"""Portable queue regressions; native PostgreSQL checks are a separate gate."""

from datetime import timedelta
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import transaction
from django.test import TestCase
from django.utils import timezone

from bridge.models import Audit, Event, Integration, Investigation, WorkerHeartbeat
from bridge.worker import _relevant_events, drain, process_one
from tests.test_membership_detection import change, reading
from tests.test_processing_efficiency import observation, rows


class EnterpriseProcessingTests(TestCase):
    def setUp(self):
        self.app = Integration.objects.create(slug="processing-lab", name="Queue lab")
        self.base = timezone.now() - timedelta(minutes=10)

    def enqueue(self, count=1):
        Event.objects.bulk_create(rows(self.app, [observation(i, self.base) for i in range(count)]))

    def test_completion_has_committed_time_worker_and_attempt_count(self):
        self.enqueue()
        self.assertTrue(process_one(worker_id="enterprise-a"))
        event = Event.objects.get()
        self.assertEqual(
            (event.state, event.processed_by, event.processing_attempts),
            ("processed", "enterprise-a", 1),
        )
        self.assertLessEqual(event.received_at, event.processing_started_at)
        self.assertLessEqual(event.processing_started_at, event.processed_at)
        self.assertEqual(event.attempts, 0)
        self.assertFalse(process_one(worker_id="enterprise-b"))

    def test_failure_keeps_retry_without_committing_evidence_or_completion(self):
        self.enqueue(3)

        def broken(*args, **kwargs):
            Investigation.objects.create(integration=self.app, rule="R1", correlation="x" * 64)
            raise RuntimeError("Synthetic processing failure")

        with patch("bridge.worker.detections", broken), self.assertRaises(RuntimeError):
            process_one(worker_id="enterprise-a")
        event = Event.objects.order_by("received_at", "pk").first()
        self.assertEqual(
            (event.attempts, event.processing_attempts, event.state), (1, 1, "pending")
        )
        self.assertIsNone(event.processed_at)
        self.assertEqual(event.processed_by, "")
        self.assertEqual(event.error_code, "processing_failed")
        self.assertGreater(event.available_at, timezone.now())
        self.assertFalse(Investigation.objects.exists())
        self.assertFalse(Audit.objects.exists())
        Event.objects.filter(pk=event.pk).update(available_at=timezone.now())
        process_one(worker_id="enterprise-b")
        event.refresh_from_db()
        self.assertEqual(
            (event.attempts, event.processing_attempts, event.processed_by), (1, 2, "enterprise-b")
        )

    def test_outer_interruption_rolls_back_processing_and_case(self):
        self.enqueue(3)
        with transaction.atomic():
            drain(worker_id="enterprise-a")
            self.assertTrue(Investigation.objects.exists())
            transaction.set_rollback(True)
        self.assertEqual(Event.objects.filter(state="pending", processing_attempts=0).count(), 3)
        self.assertFalse(Investigation.objects.exists())
        self.assertEqual(drain(worker_id="enterprise-b"), 3)
        self.assertEqual(Investigation.objects.count(), 1)

    def test_delayed_retry_does_not_block_other_eligible_event(self):
        self.enqueue(2)
        delayed = Event.objects.order_by("received_at", "pk").first()
        Event.objects.filter(pk=delayed.pk).update(
            available_at=timezone.now() + timedelta(minutes=1)
        )
        self.assertEqual(drain(worker_id="enterprise-b"), 1)
        delayed.refresh_from_db()
        self.assertEqual((delayed.state, delayed.processing_attempts), ("pending", 0))

    def test_distinct_worker_heartbeats_do_not_overwrite_each_other(self):
        drain(worker_id="enterprise-a")
        drain(worker_id="enterprise-b")
        self.assertEqual(
            set(WorkerHeartbeat.objects.values_list("name", flat=True)),
            {"enterprise-a", "enterprise-b"},
        )

    def test_invalid_identity_and_limits_fail_before_processing(self):
        self.enqueue()
        for identity in ("", "x" * 41, "bad/name", "bad\nname", None):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                process_one(worker_id=identity)
        for limit in (0, -1, 10001, True, "2"):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                drain(limit=limit)
        self.assertFalse(WorkerHeartbeat.objects.exists())
        self.assertEqual(Event.objects.get().processing_attempts, 0)

    def test_command_validates_before_entering_retry_loop(self):
        with self.assertRaises(CommandError):
            call_command("work", once=True, worker_id="bad/name")
        with self.assertRaises(CommandError):
            call_command("work", once=True, batch_size=0)

    def test_subject_filter_does_not_load_unrelated_accounts_on_same_resource(self):
        app = Integration.objects.create(slug="bettail", name="Reference membership scope")
        values = [change(base=self.base), reading(base=self.base)]
        values.extend(reading(i + 2, self.base, actor=f"{i + 10:064x}") for i in range(6))
        Event.objects.bulk_create(rows(app, values))
        with patch("bridge.worker.MAX_CORRELATION_EVENTS", 2):
            self.assertTrue(process_one())
        self.assertEqual(Investigation.objects.get(rule="R3").events.count(), 2)

    def test_a_read_loads_latest_assertions_without_loading_all_prior_reads(self):
        values = [change(base=self.base), change(1, "granted", self.base)]
        values.extend(reading(i, self.base) for i in range(2, 102))
        Event.objects.bulk_create(rows(self.app, values))
        current = Event.objects.get(event_id=values[-1]["event_id"])
        with patch("bridge.worker.MAX_CORRELATION_EVENTS", 2):
            evidence = _relevant_events(current)
        self.assertEqual(
            {str(event.event_id) for event in evidence},
            {values[1]["event_id"], values[-1]["event_id"]},
        )
        self.assertTrue(process_one())
