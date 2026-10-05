"""Long-running services inside the reviewed 24-hour reliability runner.

``worker-1``/``worker-2`` drain the console queue. ``collector`` delivers source
outbox rows to the console intake and journals every physical transport call.
``publisher`` stages processed events into the live SOC segments that Wazuh
tails. The runner starts and stops these processes (including the fixed
interruptions); each exits cleanly on SIGTERM after its current item.
"""

import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

EVIDENCE = Path("/evidence")
CLOCK = Path("/clock/reliability-clock.json")
ATTEMPTS = EVIDENCE / "reliability-collector"
ERRORS = EVIDENCE / "reliability-service-errors"
MAX_ERROR_LINES = 2000
ROLES = ("worker-1", "worker-2", "collector", "publisher")
APPS = ("documents", "expenses")


class ServiceError(ValueError):
    """Closed code only; never request bodies, keys or database content."""


def require(condition, code="service_predicate"):
    if not condition:
        raise ServiceError(code)


class Stop:
    def __init__(self):
        self.requested = False
        signal.signal(signal.SIGTERM, self.request)

    def request(self, *_):
        self.requested = True


class ErrorLog:
    """Bounded per-process diagnostics: class names and closed codes only."""

    def __init__(self, role):
        ERRORS.mkdir(exist_ok=True)
        self.path, self.count = ERRORS / f"{role}-{os.getpid()}.jsonl", 0

    def note(self, error):
        self.count += 1
        if self.count > MAX_ERROR_LINES:
            return
        closed = type(error).__name__ in ("DeliveryError", "ServiceError", "EnterpriseWazuhError")
        value = {
            "at_utc": datetime.now(timezone.utc).isoformat(),
            "error_class": type(error).__name__,
            "code": str(error)[:80] if closed else None,
        }
        with self.path.open("ab") as stream:
            stream.write(json.dumps(value, sort_keys=True).encode() + b"\n")


def origin():
    from .lab_clock import load

    return load(CLOCK)


def offset_ms(clock):
    return clock.offset_ms()


def setup(component, lab_clock=True):
    os.environ["SB_SOURCE_COMPONENT"] = component
    from .reference_native_support import configure, verify_database_identity

    configure()
    import django

    django.setup()
    from django.db import connection

    verify_database_identity(connection, component)
    if lab_clock:
        # Committed timestamps share the run's step-free timeline.
        from .lab_clock import install

        install(CLOCK)


def worker(name, stop):
    setup("console")
    from bridge.worker import drain

    errors = ErrorLog(name)
    while not stop.requested:
        try:
            drained = drain(limit=200, worker_id=name)
        except Exception as error:
            errors.note(error)
            # A transient database error must not end the worker for the day;
            # unprocessed events stay pending and the ledger shows any delay.
            drained = 0
            time.sleep(1)
        if not drained:
            time.sleep(0.25)


def attempt_result(status, raw):
    if status == 202:
        return "accepted"
    if status == 200:
        return "duplicate"
    if status in (400, 401, 403, 404, 409, 413, 422):
        return "rejected"
    return "retry"


def collector(stop):
    setup("source")
    from bridge.contract import digest
    from reference_lab.collector import NativeTransport, deliver_one

    started, transport = origin(), NativeTransport()
    ATTEMPTS.mkdir(exist_ok=True)
    path = ATTEMPTS / f"attempts-{offset_ms(started):012d}-{os.getpid()}.jsonl"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    handle = os.fdopen(os.open(path, flags, 0o600), "wb", buffering=0)

    def append(value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        require(len(raw) <= 1024 and handle.write(raw) == len(raw), "journal_write")
        os.fsync(handle.fileno())

    def observed(app, body, headers):
        payload = json.loads(body)
        key = {"app": app, "event_id": payload["event_id"], "digest": digest(payload)}
        begin = offset_ms(started)
        # The start is durable before the call: a killed collector leaves an
        # unknown attempt rather than an invisible one.
        append({"phase": "start", "start_ms": begin, **key})
        try:
            status, raw = transport(app, body, headers)
        except Exception:
            append(
                {
                    "phase": "end",
                    "start_ms": begin,
                    "end_ms": offset_ms(started),
                    "result": "retry",
                    **key,
                }
            )
            raise
        append(
            {
                "phase": "end",
                "start_ms": begin,
                "end_ms": offset_ms(started),
                "result": attempt_result(status, raw),
                **key,
            }
        )
        return status, raw

    errors = ErrorLog("collector")
    try:
        while not stop.requested:
            try:
                result = deliver_one(observed)
            except Exception as error:
                errors.note(error)
                result = "error"
                time.sleep(1)
            if result is None:
                time.sleep(0.1)
    finally:
        handle.close()


def publisher(stop):
    setup("console")
    from bridge.models import Integration
    from bridge.soc_delivery import ensure_delivery_root, publish, stage

    ensure_delivery_root()
    errors = ErrorLog("publisher")
    while not stop.requested:
        moved = False
        try:
            for app in Integration.objects.filter(slug__in=APPS).order_by("slug"):
                if stage(app) is not None:
                    moved = publish(app) is not None or moved
        except Exception as error:
            errors.note(error)
            # Staged batches are retried exactly; nothing is skipped or rewritten.
            time.sleep(2)
        if not moved:
            time.sleep(1)


def provision_streams():
    """Create the two observation streams with the identities the host bound."""
    setup("console", lab_clock=False)
    from bridge.models import Integration, SocStream

    from .reliability_wazuh import stream_id

    run = os.environ.get("SB_SOURCE_RUN", "")
    require(not SocStream.objects.exists(), "streams_not_fresh")
    created = {}
    for app in Integration.objects.filter(slug__in=APPS).order_by("slug"):
        stream = SocStream.objects.create(
            id=stream_id(run, app.slug), integration=app, channel="observation"
        )
        created[app.slug] = str(stream.pk)
    require(sorted(created) == sorted(APPS), "stream_inventory")
    return created


def export_stored():
    """Committed console rows as ledger 'stored' records, streamed in bounded order."""
    setup("console")
    from bridge.models import Event

    from .reliability_ledger import stored_row

    started = origin()
    path = EVIDENCE / "reliability-stored.jsonl"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    count = 0
    with os.fdopen(os.open(path, flags, 0o600), "wb") as handle:
        rows = (
            Event.objects.select_related("integration")
            .filter(integration__slug__in=APPS)
            .order_by("received_at", "pk")
        )
        for event in rows.iterator(chunk_size=2000):
            value = stored_row(
                {
                    "app": event.integration.slug,
                    "event_id": str(event.event_id),
                    "digest": event.digest,
                    "payload": event.payload,
                    "received_at": event.received_at,
                    "processed_at": event.processed_at,
                    "processed_by": event.processed_by,
                },
                started.origin_utc,
            )
            handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            count += 1
            require(count <= 100_000, "stored_row_limit")
        os.fsync(handle.fileno())
    return count


def main():
    require(sys.platform == "linux" and os.environ.get("SB_RELIABILITY_RUNTIME") == "1", "runtime")
    role = sys.argv[1] if len(sys.argv) == 2 else ""
    require(role in (*ROLES, "export-stored", "provision-streams"), "role")
    if role == "export-stored":
        print(json.dumps({"stored_rows": export_stored()}))
        return 0
    if role == "provision-streams":
        print(json.dumps({"streams": provision_streams()}))
        return 0
    stop = Stop()
    if role.startswith("worker-"):
        worker(role, stop)
    elif role == "collector":
        collector(stop)
    else:
        publisher(stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
