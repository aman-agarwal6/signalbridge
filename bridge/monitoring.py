"""Opt-in, TLS-only, separately authenticated operational gauges.

No payloads, actor/resource identifiers, account names, notes, paths or secrets
are exported. Retained database counts are gauges: retention/restore can reduce
them. Window latency is a bounded sample, not an SLA or histogram counter.
"""

import hmac
import math
import os
import re
import shutil
import time
from datetime import timedelta

from django.conf import settings
from django.db import DatabaseError, connection, transaction
from django.db.models import Count, F, Max, Min, Q, Sum
from django.http import HttpResponse
from django.utils import timezone
from django.views.decorators.http import require_GET

from .models import Event, Integration, MetricsScrapeState, SocDelivery
from .worker_health import WORKER_STATES, worker_health

MAX_APPS = 8
SAMPLE_LIMIT = 1000
SCRAPE_INTERVAL_SECONDS = 5
MAX_RESPONSE_BYTES = 64 * 1024
COLLECTION_BUDGET_SECONDS = 4
TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,79}\Z")


class MonitoringUnavailable(ValueError):
    """Fixed diagnostic only; configuration and database values stay private."""


def app_configuration():
    raw = os.environ.get("SB_METRICS_APPS", "")
    if len(raw) > 648:
        raise MonitoringUnavailable()
    names = raw.split(",")
    if (
        not 1 <= len(names) <= MAX_APPS
        or any(SLUG.fullmatch(name) is None for name in names)
        or len(set(names)) != len(names)
    ):
        raise MonitoringUnavailable()
    return names


def claim_scrape(now):
    """One durable admission timestamp across HTTP workers; no per-client rows."""
    with transaction.atomic():
        state, created = MetricsScrapeState.objects.select_for_update().get_or_create(
            pk=1, defaults={"last_started_at": now}
        )
        if not created:
            elapsed = (now - state.last_started_at).total_seconds()
            if elapsed < 0:
                raise MonitoringUnavailable()
            if elapsed < SCRAPE_INTERVAL_SECONDS:
                return math.ceil(SCRAPE_INTERVAL_SECONDS - elapsed)
            state.last_started_at = now
            state.save(update_fields=["last_started_at"])
    return 0


class Gauges:
    """Names/help and labels are supplied only by the fixed exporter contract."""

    def __init__(self):
        self.rows = {}

    def add(self, name, help_text, value, **labels):
        if not math.isfinite(value) or value < 0:
            raise MonitoringUnavailable()
        if name not in self.rows:
            self.rows[name] = [f"# HELP {name} {help_text}", f"# TYPE {name} gauge"]
        suffix = (
            "{" + ",".join(f'{key}="{item}"' for key, item in labels.items()) + "}"
            if labels
            else ""
        )
        self.rows[name].append(f"{name}{suffix} {value:.6f}")

    def timestamp(self, name, help_text, value, now, **labels):
        if value is not None:
            if value.year < 1970 or value > now + timedelta(seconds=5):
                raise MonitoringUnavailable()
            self.add(name, help_text, value.timestamp(), **labels)

    def render(self):
        raw = ("\n".join(line for rows in self.rows.values() for line in rows) + "\n").encode()
        if len(raw) > MAX_RESPONSE_BYTES:
            raise MonitoringUnavailable()
        return raw


def collect(now, names):
    start = time.monotonic()

    def check_budget():
        if time.monotonic() - start >= COLLECTION_BUDGET_SECONDS:
            raise MonitoringUnavailable()

    apps = {app.slug: app for app in Integration.objects.filter(slug__in=names)}
    if set(apps) != set(names):
        raise MonitoringUnavailable()
    health = worker_health(now)
    if not health["configuration_valid"]:
        raise MonitoringUnavailable()
    gauges = Gauges()
    for worker in health["workers"]:
        for state in WORKER_STATES:
            gauges.add(
                "signalbridge_worker_state",
                "Configured shared worker pulse state, not per-app progress.",
                int(worker["state"] == state),
                slot=worker["slot"],
                state=state,
            )
        if worker["state"] != "clock_error":
            gauges.timestamp(
                "signalbridge_worker_last_seen_timestamp_seconds",
                "Last shared worker pulse Unix timestamp.",
                worker["seen_at"],
                now,
                slot=worker["slot"],
            )
    for index, name in enumerate(names, 1):
        check_budget()
        app, labels = apps[name], {"scope": f"app{index}"}
        events = Event.objects.filter(integration=app)
        totals = events.aggregate(
            retained=Count("pk"),
            **{
                state: Count("pk", filter=Q(state=state))
                for state in ("pending", "processed", "dead")
            },
            eligible=Count("pk", filter=Q(state="pending", available_at__lte=now)),
            oldest=Min("received_at", filter=Q(state="pending")),
            last_received=Max("received_at"),
            last_processed=Max("processed_at", filter=Q(state="processed", processed_at__lte=now)),
            committed_attempts=Sum("processing_attempts", default=0),
            committed_failures=Sum("attempts", default=0),
            invalid_processed=Count(
                "pk",
                filter=Q(state="processed")
                & (
                    Q(processed_at__isnull=True)
                    | Q(processed_at__lt=F("received_at"))
                    | Q(processed_at__gt=now)
                ),
            ),
        )
        for state in ("pending", "processed", "dead"):
            gauges.add(
                "signalbridge_retained_events",
                "Retained logical events; not a monotonic delivery counter.",
                totals[state],
                **labels,
                state=state,
            )
        for metric, key, help_text in (
            (
                "accepted_records",
                "retained",
                "Retained accepted logical records; retention and restore can reduce this gauge.",
            ),
            (
                "queue_eligible_events",
                "eligible",
                "Pending records currently eligible for processing.",
            ),
            (
                "committed_processing_attempts",
                "committed_attempts",
                "Retained committed processing attempts; excludes executions killed before commit.",
            ),
            (
                "committed_processing_failures",
                "committed_failures",
                "Retained failed attempts committed by processing; not physical process attempts.",
            ),
            (
                "invalid_processing_timestamps",
                "invalid_processed",
                "Retained processed records with missing, reversed or future completion timestamps.",
            ),
        ):
            gauges.add("signalbridge_" + metric, help_text, totals[key], **labels)
        gauges.add(
            "signalbridge_ingestion_rejections",
            "Application's retained rejection count; not classified by actor or reason.",
            app.rejected,
            **labels,
        )
        gauges.add(
            "signalbridge_ingestion_enabled",
            "Whether acceptance is enabled; not source connectivity.",
            int(app.enabled),
            **labels,
        )
        for metric, key, help_text in (
            (
                "queue_oldest_received_timestamp_seconds",
                "oldest",
                "Oldest pending record receipt time; absent for an empty queue.",
            ),
            (
                "last_received_timestamp_seconds",
                "last_received",
                "Latest accepted record time; quiet activity is not evidence of a healthy source.",
            ),
            (
                "last_processed_timestamp_seconds",
                "last_processed",
                "Latest retained successful completion time; not a worker pulse.",
            ),
        ):
            gauges.timestamp("signalbridge_" + metric, help_text, totals[key], now, **labels)
        window_start = now - timedelta(hours=1)
        check_budget()
        timings = list(
            events.filter(
                Q(processed_at__gte=F("received_at")),
                state="processed",
                processed_at__gte=window_start,
                processed_at__lte=now,
            )
            .order_by("-processed_at", "-pk")
            .values_list("received_at", "processed_at")[:SAMPLE_LIMIT]
        )
        gauges.add(
            "signalbridge_processing_sample_count",
            "Latest at most 1000 valid completions in one hour; denominator for sample latency.",
            len(timings),
            **labels,
        )
        gauges.add(
            "signalbridge_processing_sample_limit",
            "Maximum completion records loaded for the latency sample.",
            SAMPLE_LIMIT,
            **labels,
        )
        gauges.add(
            "signalbridge_processing_window_start_timestamp_seconds",
            "Start of the rolling completion window, not workload start.",
            window_start.timestamp(),
            **labels,
        )
        if timings:
            durations = sorted((end - received).total_seconds() for received, end in timings)
            gauges.add(
                "signalbridge_processing_sample_p95_seconds",
                "Nearest-rank p95 accepted-to-completed delay of the bounded one-hour sample, including retries/outages; not an SLA.",
                durations[math.ceil(0.95 * len(durations)) - 1],
                **labels,
            )
        check_budget()
        delivery = SocDelivery.objects.filter(event__integration=app).aggregate(
            staged=Count("pk", filter=Q(batch__state="staged")),
            file_appended=Count("pk", filter=Q(batch__state="file_appended")),
        )
        for state in ("staged", "file_appended"):
            gauges.add(
                "signalbridge_soc_local_delivery_records",
                "Local export stage only; does not establish native Wazuh observation or reconciliation.",
                delivery[state],
                **labels,
                stage=state,
            )
    check_budget()
    gauges.add(
        "signalbridge_workspace_filesystem_free_bytes",
        "Available bytes on the configured workspace filesystem; not Docker/VM growth or a quota.",
        shutil.disk_usage(settings.BASE_DIR / "var").free,
    )
    gauges.add(
        "signalbridge_metrics_snapshot_timestamp_seconds",
        "Exporter snapshot clock; separate queries are not an atomic database snapshot.",
        now.timestamp(),
    )
    gauges.add(
        "signalbridge_metrics_collection_seconds",
        "Elapsed collection time for this successful scrape.",
        time.monotonic() - start,
    )
    check_budget()
    return gauges.render()


def reply(text, status):
    response = HttpResponse(
        text, status=status, content_type="text/plain; version=0.0.4; charset=utf-8"
    )
    response["Cache-Control"] = "no-store, private"
    return response


@require_GET
def metrics(request):
    if os.environ.get("SB_METRICS_ENABLED") != "1":
        return reply("Not found.\n", 404)
    token = os.environ.get("SB_METRICS_TOKEN", "")
    supplied = request.headers.get("Authorization", "")
    if TOKEN.fullmatch(token) is None:
        return reply("Monitoring unavailable.\n", 503)
    if (
        not supplied.startswith("Bearer ")
        or TOKEN.fullmatch(supplied[7:]) is None
        or not hmac.compare_digest(token, supplied[7:])
    ):
        return reply("Authentication required.\n", 401)
    if not request.is_secure():
        return reply("HTTPS required.\n", 403)
    if request.META.get("QUERY_STRING") or request.body:
        return reply("Invalid metrics request.\n", 400)
    try:
        names, now = app_configuration(), timezone.now()
        retry = claim_scrape(now)
        if retry:
            response = reply("Scrape rate exceeded.\n", 429)
            response["Retry-After"] = str(retry)
            return response
        if connection.vendor == "postgresql":
            # Limit each read statement without changing the connection globally.
            # This is cooperative elapsed-time control, not a hard process kill.
            with transaction.atomic(), connection.cursor() as cursor:
                cursor.execute("SELECT set_config('statement_timeout', '2000', true)")
                raw = collect(now, names)
        else:
            # Do not open an IMMEDIATE read transaction that blocks local ingestion.
            raw = collect(now, names)
    except (MonitoringUnavailable, DatabaseError, OSError):
        # A partial/error scrape must not look like a successful empty pipeline.
        return reply("Monitoring unavailable.\n", 503)
    return reply(raw, 200)
