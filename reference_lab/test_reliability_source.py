"""Driver failure controls and real outbox bindings; no native/24-hour claim."""

import json
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from integrations.enterprise.reliability import DAY_MS, EXPECTED_EVENTS, Slot
from integrations.enterprise.reliability_source import (
    ACCOUNT,
    APPS,
    FILES,
    Journal,
    RunClock,
    WorkloadError,
    actions,
    native_lookup,
    run_native,
    run_workload,
)

from .authorization import observe_resource
from .models import Outbox
from .seed import DOCUMENT_ID, seed_accounts


class VirtualClock:
    """Explicitly accelerated fixture; never a native clock certificate."""

    origin_utc = datetime(2026, 10, 3, tzinfo=timezone.utc)

    def __init__(self):
        self.ms = 0

    def elapsed_ms(self):
        return self.ms

    def wait_until(self, due, stopped):
        if stopped():
            raise WorkloadError("operator_stop")
        self.ms = max(self.ms, due)

    def source_offset(self, at):
        return int((at - self.origin_utc).total_seconds() * 1000)


class MemoryJournal:
    def __init__(self):
        self.rows = []

    def append(self, name, value):
        self.rows.append((name, value))


class ModeledClient:
    def __init__(self, clock, app):
        self.clock, self.app, self.count = clock, app, 0

    def sign_in(self, account, password):
        for _ in range(3):
            self.budget.consume()
        self.clock.ms += 15

    def read(self, app):
        self.budget.consume()
        self.clock.ms += 10
        self.count += 1
        self.last_event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{app}/{self.count}"))
        return {
            "http_status": 200,
            "observation": "known_content_returned",
            "known_content": True,
        }


class WorkloadDriverTests(SimpleTestCase):
    def setUp(self):
        self.clock, self.journal = VirtualClock(), MemoryJournal()
        self.clients = {app: ModeledClient(self.clock, app) for app in APPS}

    def run_driver(self, **overrides):
        args = {
            "journal": self.journal,
            "clients": self.clients,
            "passwords": dict.fromkeys(ACCOUNT.values(), "not-a-real-password"),
            "lookup": lambda app, identifier: (
                "a" * 64,
                self.clock.origin_utc + timedelta(milliseconds=self.clock.ms),
            ),
            "stopped": lambda: False,
            "clock": self.clock,
        }
        return run_workload(**{**args, **overrides})

    def test_full_virtual_workload_uses_declared_slots_and_real_session_expiry_cadence(self):
        result = self.run_driver()
        self.assertEqual(result["status"], "source_workload_completed")
        self.assertEqual(result["completed_bound_reads"], EXPECTED_EVENTS)
        self.assertEqual(result["session_renewals"], 318)
        self.assertEqual(result["physical_http_requests_after_start"], EXPECTED_EVENTS + 954)
        self.assertEqual(result["last_checked_elapsed_ms"], DAY_MS)
        self.assertFalse(result["enterprise_gate_passed"])
        self.assertEqual([self.clients[app].count for app in APPS], [23880, 23880])
        source = [row for name, row in self.journal.rows if name == "source.jsonl"]
        self.assertEqual(len({row["event_id"] for row in source}), EXPECTED_EVENTS)
        self.assertEqual(source[-1]["slot"], EXPECTED_EVENTS - 1)

    def test_lost_reply_retains_intent_and_does_not_retry_the_read(self):
        client = self.clients["documents"]
        client.read = Mock(side_effect=TimeoutError("secret-body-must-not-be-retained"))
        result = self.run_driver()
        self.assertEqual(result["status"], "source_workload_incomplete")
        self.assertEqual(result["last_unknown_slot"], 0)
        self.assertEqual(result["completed_bound_reads"], 0)
        client.read.assert_called_once_with("documents")
        self.assertNotIn("secret-body", json.dumps(self.journal.rows))
        self.assertTrue(
            any(
                row["kind"] == "read_started"
                for name, row in self.journal.rows
                if name == "requests.jsonl"
            )
        )

    def test_source_digest_identity_and_time_must_match_actual_read(self):
        result = self.run_driver(lookup=lambda *_: ("invalid", self.clock.origin_utc))
        self.assertEqual(result["failure"], "invalid_source_digest")
        self.assertEqual(result["last_unknown_slot"], 0)
        self.assertFalse(any(name == "source.jsonl" for name, _ in self.journal.rows))
        # A source time outside its request is retained and counted, never hidden;
        # the analyzer then reports every such row as an off-schedule anomaly.
        self.setUp()
        early = self.clock.origin_utc - timedelta(seconds=2)
        result = self.run_driver(lookup=lambda *_: ("a" * 64, early))
        self.assertEqual(result["failure"], "")
        self.assertEqual(result["source_time_outside_request"], EXPECTED_EVENTS)
        self.assertEqual(result["off_schedule_observations"], EXPECTED_EVENTS)
        source = [row for name, row in self.journal.rows if name == "source.jsonl"]
        self.assertEqual(source[0]["at_ms"], -2000)

    def test_small_lateness_is_counted_and_a_stall_is_not_compressed_into_a_burst(self):
        self.clock.ms = 251
        result = self.run_driver()
        self.assertEqual(result["failure"], "")
        self.assertEqual(result["late_generations"], 1)
        self.assertEqual(result["completed_bound_reads"], EXPECTED_EVENTS)
        self.setUp()
        self.clock.ms = 60_001
        result = self.run_driver()
        self.assertEqual(result["failure"], "generation_schedule_missed")
        self.assertEqual(self.clients["documents"].count, 0)
        self.assertFalse(any(name == "source.jsonl" for name, _ in self.journal.rows))

    def test_late_known_read_is_retained_as_evidence_before_timing_failure(self):
        client = self.clients["documents"]
        read, slowed = client.read, []

        def slow_once(app):
            result = read(app)
            if not slowed:
                slowed.append(True)
                self.clock.ms += 300
            return result

        client.read = slow_once
        result = self.run_driver()
        self.assertEqual(result["failure"], "")
        self.assertEqual(result["off_schedule_observations"], 1)
        self.assertIsNone(result["last_unknown_slot"])
        source = [row for name, row in self.journal.rows if name == "source.jsonl"]
        self.assertEqual(len(source), EXPECTED_EVENTS)
        self.assertEqual(source[0]["at_ms"], 310)

    def test_cancellation_and_interrupt_never_produce_completed_receipt(self):
        self.assertEqual(self.run_driver(stopped=lambda: True)["failure"], "operator_stop")
        self.setUp()
        self.clients["documents"].read = Mock(side_effect=KeyboardInterrupt())
        result = self.run_driver()
        self.assertEqual(result["failure"], "execution_interrupted")
        self.assertEqual(result["last_unknown_slot"], 0)
        self.assertEqual(result["status"], "source_workload_incomplete")

    def test_reduced_test_schedule_cannot_claim_a_complete_population(self):
        with patch(
            "integrations.enterprise.reliability_source.actions",
            return_value=iter([(0, "read", Slot(0, "documents", 0, "steady"))]),
        ):
            result = self.run_driver()
        self.assertEqual(result["failure"], "source_population_incomplete")

    def test_renewals_preserve_read_population_and_avoid_declared_bursts(self):
        from integrations.enterprise.reliability import BURST_STARTS

        rows = list(actions())
        renewals = [due for due, kind, _ in rows if kind == "renew"]
        self.assertEqual(len(renewals), 318)
        self.assertEqual(sum(kind == "read" for _, kind, _ in rows), EXPECTED_EVENTS)
        self.assertTrue(
            all(not any(start <= due < start + 60000 for start in BURST_STARTS) for due in renewals)
        )

    def test_wall_clock_jump_is_detected_and_unreviewed_runtime_refused(self):
        with patch("integrations.enterprise.reliability_source.time.monotonic_ns", return_value=0):
            clock = RunClock()
        # Small drift is measured and retained; a jump beyond five seconds aborts.
        with patch(
            "integrations.enterprise.reliability_source.time.monotonic_ns",
            return_value=2_000_000_000,
        ):
            clock.elapsed_ms()
        self.assertGreaterEqual(clock.maximum_drift_ms, 1900)
        with patch(
            "integrations.enterprise.reliability_source.time.monotonic_ns",
            return_value=6_000_000_000,
        ):
            with self.assertRaisesMessage(WorkloadError, "clock_alignment_changed"):
                clock.elapsed_ms()
        with patch.dict(os.environ, {"SB_RELIABILITY_RUNTIME": ""}):
            with self.assertRaisesMessage(WorkloadError, "unreviewed_reliability_runtime"):
                run_native()

    def test_existing_journal_is_preserved_and_writes_are_fsynced(self):
        parent = Path(tempfile.gettempdir()).resolve()
        directory = parent / ("sbrs-" + uuid.uuid4().hex)
        directory.mkdir()
        try:
            journal = Journal(directory)
            with patch(
                "integrations.enterprise.reliability_source.os.fsync", wraps=os.fsync
            ) as sync:
                journal.append("requests.jsonl", {"kind": "read_started", "slot": 0})
                self.assertEqual(sync.call_count, 1)
            journal.close()
            original = (Path(directory) / "requests.jsonl").read_bytes()
            with self.assertRaisesMessage(WorkloadError, "existing_workload_evidence"):
                Journal(directory)
            self.assertEqual((Path(directory) / "requests.jsonl").read_bytes(), original)
        finally:
            self.assertEqual(directory.resolve().parent, parent)
            self.assertFalse(directory.is_symlink())
            for name in FILES:
                (directory / name).unlink(missing_ok=True)
            directory.rmdir()


class WorkloadOutboxBindingTests(TestCase):
    def test_native_lookup_requires_same_app_actor_resource_and_committed_digest(self):
        with patch.dict(
            os.environ,
            {
                "SB_REF_PSEUDO_DOCUMENTS": "fixture-documents-" * 4,
                "SB_REF_PSEUDO_EXPENSES": "fixture-expenses-" * 4,
            },
        ):
            seed_accounts(
                {
                    account: "synthetic-long-password-" + account * 3
                    for account in ("operator", "document_member", "expense_member", "outsider")
                }
            )
            user = get_user_model().objects.get(username="document_member")
            _content, identifier = observe_resource("documents", DOCUMENT_ID, user.pk)
            row = Outbox.objects.get(pk=identifier)
            self.assertEqual(
                native_lookup("documents", identifier),
                (row.digest, datetime.fromisoformat(row.payload["occurred_at"])),
            )
            with self.assertRaises(Outbox.DoesNotExist):
                native_lookup("expenses", identifier)
            row.payload["actor"] = "a" * 64
            from bridge.contract import digest

            row.digest = digest(row.payload)
            row.save(update_fields=["payload", "digest"])
            with self.assertRaisesMessage(WorkloadError, "source_outbox_binding_failed"):
                native_lookup("documents", identifier)
