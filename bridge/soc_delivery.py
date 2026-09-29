"""Recoverable, bounded local Wazuh file outbox. No network or manager receipt.

The database commits the exact sanitized batch before any filesystem write. A
retry accepts only the previously committed prefix and an exact prefix of that
batch. SQLite/PostgreSQL transactions serialize cooperating publishers. Trusted
local administrators and power-loss behavior of the filesystem remain boundaries.
"""

import hashlib
import os
import stat

from django.conf import settings
from django.db import transaction
from django.db.models import Count, F, Q
from django.utils import timezone

from integrations.wazuh.verify_static import PreparationError, validate_export

from .contract import OPERATIONS, OUTCOMES, REASONS, canonical, parse_json
from .models import Audit, Event, Integration, SocBatch, SocDelivery, SocStream
from .runtime_identity import _plain_path

MAX_RECORDS = 100
MAX_BATCH_BYTES = 128 * 1024
MAX_STREAM_BYTES = 16 * 1024 * 1024
VALUES = {"OPERATIONS": OPERATIONS, "OUTCOMES": OUTCOMES, "REASONS": REASONS}


class DeliveryError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise DeliveryError(code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _app(app):
    require(settings.LOCAL, "local_only")
    require(app.slug in {"bettail", "netted"}, "unsupported_app")
    require(Integration.objects.filter(pk=app.pk, enabled=True).exists(), "app_disabled")


def event_row(event, app):
    row = {
        "signalbridge": {
            "export_version": 1,
            "app": app.slug,
            "environment": event.environment,
            "event_id": str(event.event_id),
            "occurred_at": event.occurred_at.isoformat(),
            "operation": event.operation,
            "outcome": event.outcome,
            "reason": event.reason,
            "source": event.source,
        }
    }
    try:
        validate_export(row, VALUES)
    except PreparationError as error:
        raise DeliveryError("invalid_export_record") from error
    require(event.integration_id == app.pk, "event_scope_mismatch")
    return row


def _locked_stream(app, *, create):
    # Hold the application row too, so a concurrent disable cannot slip between
    # eligibility validation and publication. This is also an SQLite write lock.
    require(
        Integration.objects.filter(pk=app.pk, enabled=True).update(enabled=True) == 1,
        "app_disabled",
    )
    if create:
        SocStream.objects.get_or_create(integration=app)
    # First acquire a database write lock, including on SQLite where SELECT FOR
    # UPDATE is a no-op. Contention may fail with database-locked; retry is safe.
    changed = SocStream.objects.filter(integration=app).update(revision=F("revision") + 1)
    require(changed == 1, "stream_not_staged")
    return SocStream.objects.select_for_update().get(integration=app)


def stage(app):
    """Commit at most 100 records. A late processed event cannot fall behind a cursor."""
    _app(app)
    with transaction.atomic(durable=True):
        stream = _locked_stream(app, create=True)
        existing = SocBatch.objects.filter(stream=stream, state="staged").first()
        if existing:
            return existing
        events = list(
            Event.objects.filter(
                integration=app, state="processed", socdelivery__isnull=True
            ).order_by("received_at", "id")[:MAX_RECORDS]
        )
        if not events:
            return None
        body = b"".join(canonical(event_row(event, app)) + b"\n" for event in events)
        require(len(body) <= MAX_BATCH_BYTES, "batch_capacity_reached")
        require(stream.offset + len(body) <= MAX_STREAM_BYTES, "stream_capacity_reached")
        batch = SocBatch.objects.create(
            stream=stream,
            body=body.decode("ascii"),
            body_sha256=sha256(body),
            start_offset=stream.offset,
            record_count=len(events),
        )
        SocDelivery.objects.bulk_create([SocDelivery(event=e, batch=batch) for e in events])
        Audit.objects.create(
            integration=app,
            action="soc.delivery_staged",
            object_id=str(batch.pk),
            detail={"records": len(events), "body_sha256": batch.body_sha256},
        )
        return batch


def collector_path(stream):
    try:
        return _collector_path(stream)
    except ValueError as error:
        raise DeliveryError("unsafe_collector_path") from error


def _collector_path(stream):
    """Fixed new path, separate from export_soc and all frozen pilot input paths."""
    root = settings.BASE_DIR.resolve(strict=True)
    directories = [root / "var", root / "var" / "soc-delivery"]
    for directory in directories:
        _plain_path(directory, directory=True)
        directory.mkdir(exist_ok=True)
        _plain_path(directory, directory=True)
        require(directory.resolve().is_relative_to(root), "unsafe_collector_directory")
    path = directories[-1] / f"{stream.pk}.jsonl"
    _plain_path(path, directory=False)
    if path.exists():
        require(path.stat().st_nlink == 1, "collector_hardlink")
    return path


def _body(batch, app):
    try:
        body = batch.body.encode("ascii")
    except UnicodeError as error:
        raise DeliveryError("invalid_staged_body") from error
    require(0 < len(body) <= MAX_BATCH_BYTES, "invalid_staged_size")
    require(sha256(body) == batch.body_sha256, "staged_digest_mismatch")
    lines = body.splitlines(keepends=True)
    require(0 < len(lines) == batch.record_count <= MAX_RECORDS, "staged_count_mismatch")
    ids = set()
    try:
        for line in lines:
            require(line.endswith(b"\n"), "incomplete_staged_record")
            row = parse_json(line)
            event = validate_export(row, VALUES)
            require(event["app"] == app.slug, "staged_scope_mismatch")
            require(canonical(row) + b"\n" == line, "staged_encoding_mismatch")
            require(event["event_id"] not in ids, "duplicate_staged_event")
            ids.add(event["event_id"])
    except (PreparationError, ValueError) as error:
        raise DeliveryError("invalid_staged_record") from error
    deliveries = list(
        SocDelivery.objects.filter(batch=batch).values_list(
            "event__event_id", "event__integration_id"
        )[: MAX_RECORDS + 1]
    )
    require(len(deliveries) == batch.record_count, "staged_ledger_mismatch")
    require(all(app_id == app.pk for _, app_id in deliveries), "staged_ledger_scope_mismatch")
    require({str(event_id) for event_id, _ in deliveries} == ids, "staged_ledger_mismatch")
    return body


def _append(path, stream, body):
    """Resume only this exact pending batch; never truncate or overwrite evidence."""
    require(0 <= stream.offset <= MAX_STREAM_BYTES, "invalid_stream_offset")
    require(stream.offset + len(body) <= MAX_STREAM_BYTES, "stream_capacity_reached")
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not path.exists():
        require(stream.offset == 0, "collector_missing")
        flags |= os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "r+b") as handle:
        metadata = os.fstat(handle.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, "unsafe_collector")
        require(metadata.st_size <= MAX_STREAM_BYTES, "collector_capacity_reached")
        data = handle.read(MAX_STREAM_BYTES + 1)
        require(len(data) <= MAX_STREAM_BYTES, "collector_capacity_reached")
        require(len(data) >= stream.offset, "collector_truncated")
        require(sha256(data[: stream.offset]) == stream.prefix_sha256, "collector_prefix_changed")
        tail = data[stream.offset :]
        require(len(tail) <= len(body) and body.startswith(tail), "collector_tail_conflict")
        handle.seek(0, os.SEEK_END)
        require(handle.tell() == len(data), "collector_changed_during_read")
        remaining = body[len(tail) :]
        if remaining:
            require(handle.write(remaining) == len(remaining), "collector_short_write")
        handle.flush()
        os.fsync(handle.fileno())
    return len(data) + len(remaining), sha256(data[: stream.offset] + body), len(tail)


def publish(app):
    """Append one staged batch. Completion proves local bytes only, not ingestion."""
    _app(app)
    with transaction.atomic(durable=True):
        stream = _locked_stream(app, create=False)
        batch = SocBatch.objects.filter(stream=stream, state="staged").first()
        if batch is None:
            return None
        require(batch.start_offset == stream.offset, "staged_offset_mismatch")
        body = _body(batch, app)
        path = collector_path(stream)
        offset, prefix, resumed = _append(path, stream, body)
        stream.offset, stream.prefix_sha256 = offset, prefix
        stream.save(update_fields=["offset", "prefix_sha256"])
        batch.state, batch.appended_at = "file_appended", timezone.now()
        batch.save(update_fields=["state", "appended_at"])
        Audit.objects.create(
            integration=app,
            action="soc.delivery_appended",
            object_id=str(batch.pk),
            detail={
                "records": batch.record_count,
                "recovered_bytes": resumed,
                "body_sha256": batch.body_sha256,
                "manager_observed": False,
            },
        )
        return batch


def status(app):
    """Database metadata only; a status read does not check the live collector file."""
    counts = Event.objects.filter(integration=app).aggregate(
        staged=Count("pk", filter=Q(socdelivery__batch__state="staged")),
        file_appended=Count("pk", filter=Q(socdelivery__batch__state="file_appended")),
        eligible=Count("pk", filter=Q(state="processed", socdelivery__isnull=True)),
    )
    stream = SocStream.objects.filter(integration=app).first()
    return {
        **counts,
        "stream_id": str(stream.pk) if stream else None,
        "bytes": stream.offset if stream else 0,
        "capacity_bytes": MAX_STREAM_BYTES,
        "manager_observed": None,
    }
