"""Bounded native-format file import with persistent recovery checkpoints.

The trusted local operator supplies files from the fixed standalone profile.
Matching native-format records are not independent runtime attestation. No
import starts Wazuh, reaches a network or marks a connector currently healthy.
"""

import hashlib
import os
import stat
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Count, Max, Q, Subquery, Sum
from django.db.models.functions import JSONObject
from django.utils import timezone

from integrations.wazuh_enterprise.contract import (
    APPS,
    LOCATIONS,
    identifier,
    require,
    segmented_location,
    validate_native_record,
    validate_observation,
    validate_signal,
)

from .contract import canonical, digest, parse_json
from .models import (
    Audit,
    Event,
    ForwardedDetection,
    Integration,
    SocDelivery,
    WazuhCursor,
    WazuhRecord,
)
from .runtime_identity import _plain_path
from .soc_delivery import _body, event_row
from .wazuh_enterprise import signal_body

MAX_SEGMENT_BYTES = 4 * 1024**2
MAX_RECORD_BYTES = 16384
MAX_IMPORT_RECORDS = 100


def file_path(app, run, kind, segment):
    require(
        app.slug in APPS
        and kind in {"archive", "alert"}
        and type(segment) is int
        and 0 <= segment <= 7
    )
    identifier(run)
    root = settings.BASE_DIR.resolve(strict=True)
    path = root / "var" / "wazuh-enterprise" / run / app.slug / f"{kind}s-{segment:03}.jsonl"
    for candidate in (path, *path.parents):
        if candidate == root:
            break
        _plain_path(candidate, directory=candidate != path)
        require(candidate.exists())
    require(path.resolve().is_relative_to(root) and path.is_file() and path.stat().st_nlink == 1)
    return path


def read_segment(path):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        info = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_SEGMENT_BYTES
        )
        raw = handle.read(info.st_size)
        require(len(raw) == info.st_size)
    return raw


def batch_location(batch, app):
    """Require the exact published segment, not merely any allowlisted file."""
    if not batch.stream.segmented_export:
        require(batch.segment_id is None)
        return LOCATIONS[batch.stream.channel]
    segment = batch.segment
    require(segment is not None and segment.stream_id == batch.stream_id)
    return segmented_location(app.slug, batch.stream.channel, segment.number)


def target(app, value, cache):
    decoded = value.get("data")
    require(isinstance(decoded, dict))
    if set(decoded) == {"signalbridge"}:
        row = decoded["signalbridge"]
        require(isinstance(row, dict))
        event_id = identifier(row.get("event_id"))
        if ("event", event_id) in cache:
            return cache[("event", event_id)]
        delivery = (
            SocDelivery.objects.select_related("event", "batch__stream", "batch__segment")
            .filter(
                event__integration=app,
                event__event_id=event_id,
                batch__state="file_appended",
                batch__stream__channel="observation",
            )
            .first()
        )
        require(delivery is not None)
        key = ("observation_batch", delivery.batch_id)
        if key not in cache:
            body = _body(delivery.batch, app)
            packets = [parse_json(line) for line in body.splitlines()]
            cache[key] = {
                packet["signalbridge"]["event_id"]: canonical(packet) for packet in packets
            }
        packet = event_row(delivery.event, app)
        validate_observation(packet)  # Enterprise v2 only; v1 pilots keep their importer.
        require(cache[key].get(event_id) == canonical(packet))
        cache[("event", event_id)] = (
            packet,
            {"event": delivery.event, "signal": None},
            batch_location(delivery.batch, app),
        )
        return cache[("event", event_id)]
    require(set(decoded) == {"signalbridge_detection"})
    row = decoded["signalbridge_detection"]
    require(isinstance(row, dict))
    signal_id = identifier(row.get("signal_id"))
    if ("signal", signal_id) in cache:
        return cache[("signal", signal_id)]
    signal = (
        ForwardedDetection.objects.select_related(
            "investigation", "batch__stream", "batch__segment"
        )
        .filter(
            pk=signal_id,
            investigation__integration=app,
            batch__state="file_appended",
            batch__stream__channel="detection",
        )
        .first()
    )
    require(signal is not None)
    key = ("detection_batch", signal.batch_id)
    if key not in cache:
        signal_body(signal.batch, app)
        cache[key] = True
    validate_signal(signal.packet)
    cache[("signal", signal_id)] = (
        signal.packet,
        {"event": None, "signal": signal},
        batch_location(signal.batch, app),
    )
    return cache[("signal", signal_id)]


@transaction.atomic(durable=True)
def import_segment(app, run, kind, segment):
    require(settings.LOCAL and app.slug in APPS)
    identifier(run)
    require(kind in {"archive", "alert"} and type(segment) is int and 0 <= segment <= 7)
    require(Integration.objects.filter(pk=app.pk, enabled=True).update(enabled=True) == 1)
    current, _ = WazuhCursor.objects.get_or_create(integration=app, collector_run=run, kind=kind)
    current = WazuhCursor.objects.select_for_update().get(pk=current.pk)
    require(segment in {current.segment, current.segment + 1})
    if segment != current.segment:
        previous = read_segment(file_path(app, run, kind, current.segment))
        require(
            len(previous) == current.offset
            and (not previous or previous.endswith(b"\n"))
            and hashlib.sha256(previous).hexdigest() == current.prefix_sha256
        )
        Audit.objects.create(
            integration=app,
            action="wazuh.import_rotated",
            object_id=str(current.pk),
            detail={
                "run_id": run,
                "kind": kind,
                "sealed_segment": current.segment,
                "bytes": current.offset,
                "sha256": current.prefix_sha256,
            },
        )
        current.segment, current.offset = segment, 0
        current.prefix_sha256 = hashlib.sha256(b"").hexdigest()
    raw = read_segment(file_path(app, run, kind, segment))
    require(
        current.offset <= len(raw)
        and hashlib.sha256(raw[: current.offset]).hexdigest() == current.prefix_sha256
    )
    offset, physical, created, duplicate = current.offset, 0, 0, 0
    cache = {}  # Current transaction/app only; at most 100 selected records.
    now = timezone.now() + timedelta(seconds=5)
    while offset < len(raw) and physical < MAX_IMPORT_RECORDS:
        end = raw.find(b"\n", offset)
        if end < 0:
            require(len(raw) - offset <= MAX_RECORD_BYTES)
            break  # An in-progress line is not consumed or called missing evidence.
        require(0 < end - offset <= MAX_RECORD_BYTES)
        value = parse_json(raw[offset:end])
        require(isinstance(value, dict))
        packet, link, location = target(app, value, cache)
        require(value.get("location") == location)
        observed = validate_native_record(value, packet, kind, now=now)
        rule = value.get("rule", {}) if kind == "alert" else {}
        fields = {
            **link,
            "occurred_at": observed,
            "packet_sha256": digest(packet),
            "record_sha256": digest(value),
            "rule_id": rule.get("id", ""),
            "rule_level": rule.get("level"),
        }
        record, added = WazuhRecord.objects.get_or_create(
            integration=app,
            collector_run=run,
            native_id=value["id"],
            kind=kind,
            defaults=fields,
        )
        require(
            all(
                getattr(record, key + "_id") == (item.pk if item else None)
                if key in {"event", "signal"}
                else getattr(record, key) == item
                for key, item in fields.items()
            )
        )
        physical += 1
        created += int(added)
        duplicate += int(not added)
        offset = end + 1
        current.last_native_at = (
            max(observed, current.last_native_at) if current.last_native_at else observed
        )
    current.offset, current.prefix_sha256 = offset, hashlib.sha256(raw[:offset]).hexdigest()
    current.physical_records += physical
    if physical:
        current.last_import_at = timezone.now()
    current.save()
    if physical:
        Audit.objects.create(
            integration=app,
            action="wazuh.records_imported",
            object_id=str(current.pk),
            detail={
                "run_id": run,
                "kind": kind,
                "segment": segment,
                "offset": offset,
                "physical_records": physical,
                "new_records": created,
                "duplicate_records": duplicate,
                "origin": "local_database_operator",
                "native_runtime_verified": False,
            },
        )
    return {
        "physical_records": physical,
        "new_records": created,
        "duplicate_records": duplicate,
        "offset": offset,
        "segment": segment,
        "native_runtime_verified": False,
    }


def status(app):
    """One statement for scoped summaries, with no event-payload hydration.

    Aggregate each ledger separately before combining results so multiple source,
    signal and cursor rows cannot multiply each other's counts. Queue counts share
    the event summary instead of adding another console request query.
    """
    records = WazuhRecord.objects.filter(integration=app)
    events = Event.objects.filter(integration=app)
    signals = ForwardedDetection.objects.filter(investigation__integration=app)
    cursors = WazuhCursor.objects.filter(integration=app)

    def summary(rows, group, **fields):
        return Subquery(
            rows.order_by()
            .values(group)
            .annotate(summary=JSONObject(**fields))
            .values("summary")[:1]
        )

    def maximum(name):
        return Subquery(
            records.order_by()
            .values("integration_id")
            .annotate(latest=Max(name))
            .values("latest")[:1]
        )

    value = (
        Integration.objects.filter(pk=app.pk)
        .annotate(
            record_summary=summary(
                records,
                "integration_id",
                native_format_records=Count("pk"),
                observed_events=Count("event", distinct=True, filter=Q(kind="archive")),
                observed_signals=Count("signal", distinct=True, filter=Q(kind="archive")),
                observation_alerts=Count("pk", filter=Q(kind="alert", event__isnull=False)),
                forwarded_alerts=Count("pk", filter=Q(kind="alert", signal__isnull=False)),
            ),
            event_summary=summary(
                events,
                "integration_id",
                pending=Count("pk", filter=Q(state="pending")),
                dead=Count("pk", filter=Q(state="dead")),
                exported_events=Count(
                    "pk",
                    filter=(
                        Q(
                            socdelivery__batch__state="file_appended",
                            socdelivery__batch__stream__channel="observation",
                        )
                        & (
                            Q(integration__slug__in={"documents", "expenses"})
                            | Q(source="instrumented_lab")
                        )
                    ),
                ),
            ),
            signal_summary=summary(
                signals,
                "investigation__integration_id",
                staged_signals=Count("pk", filter=Q(batch__state="staged")),
                exported_signals=Count("pk", filter=Q(batch__state="file_appended")),
            ),
            cursor_summary=summary(
                cursors, "integration_id", physical_import_records=Sum("physical_records")
            ),
            last_native_at=maximum("occurred_at"),
            last_import_at=maximum("imported_at"),
        )
        .values(
            "record_summary",
            "event_summary",
            "signal_summary",
            "cursor_summary",
            "last_native_at",
            "last_import_at",
        )
        .get()
    )
    counts = dict.fromkeys(
        (
            "native_format_records",
            "observed_events",
            "observed_signals",
            "observation_alerts",
            "forwarded_alerts",
            "pending",
            "dead",
            "exported_events",
            "staged_signals",
            "exported_signals",
            "physical_import_records",
        ),
        0,
    )
    for key in ("record_summary", "event_summary", "signal_summary", "cursor_summary"):
        counts.update(value[key] or {})
    counts.update(
        last_native_at=value["last_native_at"],
        last_import_at=value["last_import_at"],
        repeated_native_ids=max(
            0, counts["physical_import_records"] - counts["native_format_records"]
        ),
        unobserved_events=max(0, counts["exported_events"] - counts["observed_events"]),
        unobserved_signals=max(0, counts["exported_signals"] - counts["observed_signals"]),
        native_runtime_verified=False,
        connection_state="Native connection unverified",
    )
    return counts
