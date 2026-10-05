"""Read-only signals about this workspace; quiet feeds are not proof of safety."""

from datetime import timedelta

from django.db.models import Count, Max, Min, Q
from django.utils import timezone

from .models import CheckRun, Event
from .worker_health import worker_health


def event_summary(events):
    """One aggregate over an already scoped queryset; never materialize event payloads."""
    sources = [value for value, _ in Event._meta.get_field("source").choices]
    outcomes = ("allowed", "denied", "not_visible", "error")
    totals = events.aggregate(
        accepted=Count("pk"),
        **{state: Count("pk", filter=Q(state=state)) for state in ("processed", "pending", "dead")},
        **{"source_" + value: Count("pk", filter=Q(source=value)) for value in sources},
        **{"outcome_" + value: Count("pk", filter=Q(outcome=value)) for value in outcomes},
    )
    return {
        **{key: totals[key] for key in ("accepted", "processed", "pending", "dead")},
        "sources": {value: totals["source_" + value] for value in sources},
        "outcomes": {value: totals["outcome_" + value] for value in outcomes},
    }


def workspace_health(app):
    now = timezone.now()
    events = Event.objects.filter(integration=app)
    queue = events.aggregate(
        pending=Count("pk", filter=Q(state="pending")),
        eligible=Count("pk", filter=Q(state="pending", available_at__lte=now)),
        dead=Count("pk", filter=Q(state="dead")),
        oldest_pending=Min("received_at", filter=Q(state="pending")),
    )
    workers = worker_health(now)
    queue["oldest_pending_seconds"] = (
        max(0, int((now - queue["oldest_pending"]).total_seconds()))
        if queue["oldest_pending"]
        else None
    )
    queue["worker_recent"] = workers["all_recent"]
    queue["worker_seen_at"] = max(
        (item["seen_at"] for item in workers["workers"] if item["state"] in ("recent", "stale")),
        default=None,
    )
    streams = list(
        events.values("source", "environment")
        .annotate(
            total=Count("pk"),
            received_24h=Count(
                "pk", filter=Q(received_at__gte=now - timedelta(hours=24), received_at__lte=now)
            ),
            last_received=Max("received_at"),
            last_occurred=Max("occurred_at"),
            errors=Count("pk", filter=Q(outcome="error")),
        )
        .order_by("source", "environment")
    )
    labels = dict(Event._meta.get_field("source").choices)
    for stream in streams:
        stream["label"] = labels.get(stream["source"], "Unclassified source")
    latest_http = (
        CheckRun.objects.filter(integration=app, result__evidence_kind="supabase_http")
        .order_by("-created_at")
        .first()
    )
    return {
        "as_of": now,
        "collector_enabled": app.enabled,
        "queue": queue,
        "workers": workers,
        "streams": streams,
        "latest_http": latest_http,
        "attention": bool(queue["dead"] or (queue["eligible"] and not queue["worker_recent"])),
    }
