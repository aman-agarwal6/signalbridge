"""Real separate-connection tests. Fail closed if invoked with another backend."""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch

from django.db import close_old_connections, connection, connections, transaction
from django.test import Client, TransactionTestCase, tag
from django.utils import timezone

from bridge.contract import canonical, signature
from bridge.models import Audit, Event, IngestKey, Integration, Investigation
from bridge.worker import drain, process_one
from tests.test_processing_efficiency import observation, rows


@tag("native_postgres")
class PostgresProcessingTests(TransactionTestCase):
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql", "This gate requires genuine PostgreSQL.")
        self.app = Integration.objects.create(
            slug="processing-lab", name="Disposable application A"
        )
        self.other = Integration.objects.create(slug="second-lab", name="Disposable application B")
        now = timezone.now()
        self.base = now.replace(second=0, microsecond=0) - timedelta(minutes=now.minute % 5 + 10)
        self.secret = "nonfunctional-concurrent-ingestion-fixture-" + "x" * 48
        IngestKey.objects.create(
            integration=self.app,
            key_id="pg-test-key",
            secret_env="SB_PG_TEST_KEY",
            environment="test",
        )
        self.environment = patch.dict(os.environ, {"SB_PG_TEST_KEY": self.secret})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def independent(self, operation):
        close_old_connections()
        try:
            return operation()
        finally:
            connections.close_all()

    def test_locked_application_is_skipped_while_another_application_progresses(self):
        Event.objects.bulk_create(rows(self.app, [observation(0, self.base)]))
        Event.objects.bulk_create(
            rows(self.other, [observation(1, self.base, app=self.other.slug)])
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            with transaction.atomic():
                Integration.objects.select_for_update().get(pk=self.app.pk)
                future = executor.submit(self.independent, lambda: process_one("pg-worker-b"))
                self.assertTrue(future.result(timeout=4))
                self.assertEqual(Event.objects.get(integration=self.app).state, "pending")
                self.assertEqual(
                    Event.objects.get(integration=self.other).processed_by, "pg-worker-b"
                )
        self.assertTrue(process_one("pg-worker-a"))

    def test_two_workers_commit_each_event_once_and_share_a_single_case(self):
        Event.objects.bulk_create(rows(self.app, [observation(i, self.base) for i in range(24)]))
        Event.objects.bulk_create(
            rows(
                self.other, [observation(i + 30, self.base, app=self.other.slug) for i in range(24)]
            )
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(
                    self.independent, lambda identity=identity: drain(worker_id=identity)
                )
                for identity in ("pg-worker-a", "pg-worker-b")
            ]
            for future in futures:
                future.result(timeout=20)
        # One consumer may finish its currently available apps before the other;
        # drain the remainder without asserting an invented fairness guarantee.
        drain(worker_id="pg-worker-a")
        self.assertEqual(Event.objects.filter(state="processed", processing_attempts=1).count(), 48)
        self.assertEqual(Investigation.objects.count(), 2)
        self.assertEqual(Audit.objects.filter(action="case.created").count(), 2)
        for case in Investigation.objects.all():
            self.assertEqual(case.events.count(), 24)

    def send(self, value):
        raw, at = canonical(value), timezone.now().isoformat()
        return (
            Client()
            .post(
                "/api/v1/events/processing-lab/",
                raw,
                content_type="application/json",
                HTTP_X_SB_KEY="pg-test-key",
                HTTP_X_SB_TIME=at,
                HTTP_X_SB_SIGNATURE=signature(self.secret, self.app.slug, "pg-test-key", at, raw),
            )
            .status_code
        )

    def test_concurrent_identical_ingestion_accepts_one_logical_record(self):
        value = observation(1, self.base)
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self.independent, lambda: self.send(value)) for _ in range(8)
            ]
            statuses = [future.result(timeout=10) for future in futures]
        self.assertEqual(statuses.count(202), 1)
        self.assertEqual(statuses.count(200), 7)
        self.assertEqual(Event.objects.count(), 1)

    def test_conflicting_concurrent_ingestion_has_one_winner_and_one_rejection(self):
        values = [observation(1, self.base), observation(1, self.base, resource="f" * 64)]
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(self.independent, lambda value=value: self.send(value))
                for value in values
            ]
            self.assertEqual(sorted(future.result(timeout=10) for future in futures), [202, 409])
        self.assertEqual(Event.objects.count(), 1)

    def test_aborted_outer_transaction_can_be_recovered_by_another_connection(self):
        Event.objects.bulk_create(rows(self.app, [observation(i, self.base) for i in range(3)]))
        with transaction.atomic():
            drain(worker_id="pg-worker-a")
            self.assertEqual(Investigation.objects.count(), 1)
            transaction.set_rollback(True)
        with ThreadPoolExecutor(max_workers=1) as executor:
            self.assertEqual(
                executor.submit(self.independent, lambda: drain(worker_id="pg-worker-b")).result(
                    timeout=10
                ),
                3,
            )
        self.assertEqual(Event.objects.filter(state="processed", processing_attempts=1).count(), 3)
        self.assertEqual(Investigation.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="case.created").count(), 1)
