"""Paced, durable HTTP workload for the fixed enterprise reliability declaration.

This driver uses genuine source authentication/read paths when called through
``run_native``. It starts no server, container or watchdog and grants no launch
approval. Its result certifies neither delivery nor the full reliability gate.
The finite source proof and its existing short limits remain unchanged.
"""

import heapq
import json
import os
import stat
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .reference_http import RESOURCES, ClosedHTTPSClient, RequestBudget
from .reliability import APPS, DAY_MS, EXPECTED_EVENTS, FINAL_DRAIN_MS, declaration_hash, schedule

ACCOUNT = {"documents": "document_member", "expenses": "expense_member"}
RENEWAL_MS = 540_000
MAX_DRIFT_MS = 100
# Beyond these the run is genuinely stalled or its clock untrustworthy; smaller
# misses are retained as measured anomalies that fail the declared targets.
STALL_MS = 60_000
CLOCK_JUMP_MS = 5_000
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
MAX_REQUESTS = EXPECTED_EVENTS + 2 * 3 * (DAY_MS // RENEWAL_MS - 1) + 2
FILES = ("context.json", "requests.jsonl", "source.jsonl", "result.json")


class WorkloadError(ValueError):
    """Closed diagnostic codes only; never response bodies or credentials."""


class RunClock:
    def __init__(self):
        self.origin_ns = time.monotonic_ns()
        self.origin_utc = datetime.now(timezone.utc)
        self.maximum_drift_ms = 0

    def elapsed_ms(self):
        elapsed = (time.monotonic_ns() - self.origin_ns) // 1_000_000
        wall = (datetime.now(timezone.utc) - self.origin_utc).total_seconds() * 1000
        drift = abs(wall - elapsed)
        self.maximum_drift_ms = max(self.maximum_drift_ms, int(drift))
        if elapsed < 0 or drift > CLOCK_JUMP_MS:
            raise WorkloadError("clock_alignment_changed")
        return elapsed

    def wait_until(self, due_ms, stopped):
        while True:
            if stopped():
                raise WorkloadError("operator_stop")
            remaining = due_ms - self.elapsed_ms()
            if remaining <= 0:
                return
            time.sleep(min(0.25, remaining / 1000))

    def source_offset(self, occurred_at):
        if not isinstance(occurred_at, datetime) or occurred_at.utcoffset() is None:
            raise WorkloadError("invalid_source_time")
        return int((occurred_at - self.origin_utc).total_seconds() * 1000)


class WorkloadBudget:
    """One shared total; the client retains its per-request five-second deadline."""

    def __init__(self, clock):
        self.clock, self.used = clock, 0

    def consume(self):
        remaining = DAY_MS + FINAL_DRAIN_MS - self.clock.elapsed_ms()
        if self.used >= MAX_REQUESTS or remaining <= 0:
            raise WorkloadError("request_budget_exhausted")
        self.used += 1
        return time.monotonic() + min(5, remaining / 1000)


def _plain_directory(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise WorkloadError("redirected_output_directory")


class Journal:
    """Exclusive append-only execution evidence, fsynced before and after each read.

    A crash between intent and result remains an unknown physical request. This
    journal deliberately cannot resume/replay it as a fresh logical source read.
    """

    def __init__(self, directory):
        self.directory = Path(directory).absolute()
        _plain_directory(self.directory)
        if any((self.directory / name).exists() for name in FILES):
            raise WorkloadError("existing_workload_evidence")
        self.handles, self.bytes = {}, 0
        try:
            for name in FILES:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(self.directory / name, flags, 0o600)
                self.handles[name] = os.fdopen(descriptor, "wb", buffering=0)
        except BaseException:
            self.close()
            raise

    def append(self, name, value):
        if name not in self.handles:
            raise WorkloadError("invalid_journal_name")
        raw = (
            json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            + b"\n"
        )
        if len(raw) > 4096 or self.bytes + len(raw) > MAX_JOURNAL_BYTES:
            raise WorkloadError("journal_capacity_exceeded")
        handle = self.handles[name]
        if handle.write(raw) != len(raw):
            raise WorkloadError("journal_write_incomplete")
        self.bytes += len(raw)
        os.fsync(handle.fileno())

    def close(self):
        for handle in self.handles.values():
            handle.close()


def actions():
    reads = ((slot.due_ms, "read", slot) for slot in schedule())
    # Renew before the real 15-minute session expiry. These gaps avoid every
    # declared burst; no authentication change or telemetry event is fabricated.
    renewals = (
        (at + 500 + index * 500, "renew", app)
        for at in range(RENEWAL_MS, DAY_MS, RENEWAL_MS)
        for index, app in enumerate(APPS)
    )
    return heapq.merge(reads, renewals, key=lambda item: item[0])


def run_workload(*, journal, clients, passwords, lookup, stopped, clock=None):
    """Run an unchanged schedule against provided source clients.

    The caller authenticates both clients before entering the measured period.
    ``lookup`` must bind each returned identifier to its committed source outbox.
    Test doubles can exercise control flow, but cannot establish native execution.
    """
    if set(clients) != set(APPS) or set(passwords) != set(ACCOUNT.values()):
        raise WorkloadError("wrong_synthetic_identity_inventory")
    clock = RunClock() if clock is None else clock
    budget = WorkloadBudget(clock)
    for client in clients.values():
        client.budget = budget
    journal.append(
        "context.json",
        {
            "profile_sha256": declaration_hash(),
            "origin_utc": clock.origin_utc.isoformat(),
            "source_requests_expected": EXPECTED_EVENTS,
            "clock_drift_limit_ms": MAX_DRIFT_MS,
            "session_renewal_interval_ms": RENEWAL_MS,
            "transport": "fixed_reference_https_client_required_for_native_claim",
        },
    )
    completed, renewals, failure, unknown, seen = 0, 0, "", None, set()
    late_generations = off_schedule = outside_request = 0
    elapsed = 0
    try:
        for due, kind, value in actions():
            clock.wait_until(due, stopped)
            elapsed = clock.elapsed_ms()
            if elapsed - due > STALL_MS:
                raise WorkloadError("generation_schedule_missed")
            late_generations += elapsed - due > 250
            if kind == "renew":
                clients[value].sign_in(ACCOUNT[value], passwords[ACCOUNT[value]])
                renewals += 1
                journal.append(
                    "requests.jsonl", {"kind": "session_renewed", "app": value, "at_ms": elapsed}
                )
                continue
            slot = value
            unknown = slot.index
            journal.append(
                "requests.jsonl",
                {"kind": "read_started", "slot": slot.index, "app": slot.app, "at_ms": elapsed},
            )
            result = clients[slot.app].read(slot.app)
            finished = clock.elapsed_ms()
            identifier = clients[slot.app].last_event_id
            if result != {
                "http_status": 200,
                "observation": "known_content_returned",
                "known_content": True,
            }:
                raise WorkloadError("known_private_read_not_observed")
            if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier:
                raise WorkloadError("invalid_source_identifier")
            if identifier in seen:
                raise WorkloadError("repeated_source_identifier")
            checksum, occurred_at = lookup(slot.app, identifier)
            if (
                not isinstance(checksum, str)
                or len(checksum) != 64
                or any(character not in "0123456789abcdef" for character in checksum)
            ):
                raise WorkloadError("invalid_source_digest")
            observed = clock.source_offset(occurred_at)
            time_bound = elapsed - MAX_DRIFT_MS <= observed <= finished + MAX_DRIFT_MS
            on_schedule = due <= observed <= due + 250
            journal.append(
                "source.jsonl",
                {
                    "kind": "source",
                    "slot": slot.index,
                    "app": slot.app,
                    "event_id": identifier,
                    "digest": checksum,
                    "at_ms": observed,
                },
            )
            journal.append(
                "requests.jsonl",
                {
                    "kind": "read_completed",
                    "slot": slot.index,
                    "app": slot.app,
                    "at_ms": finished,
                    "source_time_bound": time_bound,
                    "on_schedule": on_schedule,
                },
            )
            seen.add(identifier)
            completed += 1
            unknown = None
            # A late known read remains evidence; it is counted, never hidden.
            outside_request += not time_bound
            off_schedule += not on_schedule
        clock.wait_until(DAY_MS, stopped)
        elapsed = clock.elapsed_ms()
        if completed != EXPECTED_EVENTS:
            raise WorkloadError("source_population_incomplete")
    except WorkloadError as error:
        failure = str(error)
    except (KeyboardInterrupt, SystemExit):
        failure = "execution_interrupted"
    except Exception:
        # A failed reply may still have committed source telemetry. No retry is
        # performed here; preserve the intent and reconcile the actual database.
        failure = "source_execution_incomplete"
    finally:
        result = {
            "status": "source_workload_incomplete" if failure else "source_workload_completed",
            "failure": failure,
            "completed_bound_reads": completed,
            "last_unknown_slot": unknown,
            "session_renewals": renewals,
            "physical_http_requests_after_start": budget.used,
            "last_checked_elapsed_ms": elapsed,
            "late_generations": late_generations,
            "off_schedule_observations": off_schedule,
            "source_time_outside_request": outside_request,
            "maximum_clock_drift_ms": getattr(clock, "maximum_drift_ms", None),
            "enterprise_gate_passed": False,
            "remaining": "native delivery, workers, tool observations, interruptions, restore and shutdown",
        }
        journal.append("result.json", result)
    return result


def native_lookup(app, identifier):
    """Read actual committed telemetry, not an event invented by the generator."""
    from django.contrib.auth import get_user_model

    from bridge.contract import digest, timestamp, validate_event
    from reference_lab.models import Outbox
    from reference_lab.seed import require_isolated_database
    from reference_lab.telemetry import pseudonym

    require_isolated_database()
    row = Outbox.objects.get(pk=identifier, app=app)
    validate_event(row.payload, app)
    account_id = get_user_model().objects.values_list("pk", flat=True).get(username=ACCOUNT[app])
    if (
        digest(row.payload) != row.digest
        or row.payload["event_id"] != identifier
        or row.payload["operation"] != "private_record.read"
        or row.payload["outcome"] != "allowed"
        or row.payload["environment"] != "lab"
        or row.payload["actor"] != pseudonym(app, "account", account_id)
        or row.payload["resource"] != pseudonym(app, "resource", RESOURCES[app])
    ):
        raise WorkloadError("source_outbox_binding_failed")
    # Match the ingestion ledger's occurrence time, not the later SQL insert.
    return row.digest, timestamp(row.payload["occurred_at"])


def run_native(clock=None):
    """Inside a separately reviewed long-lived source profile; no runtime launch.

    The current short source container cannot run this workload. Its future host
    controller must provide capacity checks, an independent watchdog, long-lived
    TLS services, workers/collectors and exact output mounts before calling this.
    """
    if (
        sys.platform != "linux"
        or os.geteuid() == 0
        or os.environ.get("SB_RELIABILITY_RUNTIME") != "1"
        or os.environ.get("SB_SOURCE_COMPONENT") != "source"
    ):
        raise WorkloadError("unreviewed_reliability_runtime")
    from .reference_native_support import configure, verify_database_identity

    value = configure()
    import django
    from django.db import connection

    django.setup()
    verify_database_identity(connection, "source")
    from reference_lab.models import BoundedFault, BoundedHeaderFault, Outbox

    if (
        Outbox.objects.exists()
        or BoundedFault.objects.filter(enabled=True).exists()
        or BoundedHeaderFault.objects.filter(enabled=True).exists()
    ):
        raise WorkloadError("source_not_clean")
    # Provisioning and source membership controls belong to the reviewed host
    # stage. This driver only logs in and reads the two fixed private records.
    passwords = {account: value["accounts"][account] for account in ACCOUNT.values()}
    clients = {}
    journal = Journal(Path("/evidence/reliability-source"))
    try:
        initial_budget = RequestBudget()
        try:
            for app in APPS:
                client = ClosedHTTPSClient("/run/secrets/lab_ca", initial_budget)
                client.sign_in(ACCOUNT[app], passwords[ACCOUNT[app]])
                clients[app] = client
        except Exception:
            result = {
                "status": "source_workload_incomplete",
                "failure": "initial_authentication_incomplete",
                "initial_http_requests": initial_budget.used,
                "enterprise_gate_passed": False,
            }
            journal.append("result.json", result)
            return result
        return run_workload(
            journal=journal,
            clients=clients,
            passwords=passwords,
            lookup=native_lookup,
            stopped=lambda: Path("/evidence/reliability-stop").exists(),
            clock=clock,
        )
    finally:
        # Cookies/passwords never enter evidence. Session expiry remains 900s;
        # stopping the whole profile is the host's separately verified duty.
        for client in clients.values():
            client.cookies.clear()
        passwords.clear()
        journal.close()
