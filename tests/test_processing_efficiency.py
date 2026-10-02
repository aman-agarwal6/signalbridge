"""Bounded synthetic processing costs and behavior, using Django's disposable test DB."""

import hashlib
import json
import os
import sqlite3
import statistics
import sys
import time
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import django
from django.db import connection, transaction
from django.db.models.query import QuerySet
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from bridge.contract import canonical, digest, signature, timestamp
from bridge.models import Audit, Event, IngestKey, Integration, Investigation
from bridge.worker import drain, process_one

PROFILE_RECORDS = 120
PROFILE_REPEATS = 3
PROFILE_DUPLICATES = 50
SYNTHETIC_KEY = "nonfunctional-processing-test-key-" + "x" * 48


def observation(index, base, **changes):
    value = {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"processing-profile/{index}")),
        "app": "processing-lab",
        "environment": "test",
        "occurred_at": (base + timedelta(seconds=index)).isoformat(),
        "actor": "a" * 64,
        "resource": f"{index:064x}",
        "episode": str(uuid.uuid5(uuid.NAMESPACE_URL, "processing-profile/episode")),
        "operation": "private_record.read",
        "outcome": "denied",
        "reason": "membership_required",
        "context": None,
    }
    value.update(changes)
    return value


def rows(app, values, source="migration_lab"):
    return [
        Event(
            integration=app,
            event_id=value["event_id"],
            occurred_at=timestamp(value["occurred_at"]),
            actor=value["actor"],
            membership_subject=value.get("membership", {}).get("subject", ""),
            resource=value["resource"],
            episode=value["episode"],
            operation=value["operation"],
            outcome=value["outcome"],
            reason=value["reason"],
            environment=value["environment"],
            source=source,
            payload=value,
            digest=digest(value),
            available_at=timezone.now(),
        )
        for value in values
    ]


def query_measurement(queries, elapsed):
    selections = [entry["sql"] for entry in queries if entry["sql"].lstrip().startswith("SELECT")]
    event_queries = [query for query in selections if 'FROM "bridge_event"' in query]
    return {
        "seconds": round(elapsed, 6),
        "sql_statements": len(queries),
        "select_statements": len(selections),
        "event_selects": len(event_queries),
        "event_selects_with_payload": sum(
            '"payload"' in query.split(" FROM ")[0] for query in event_queries
        ),
        "integration_selects": sum('FROM "bridge_integration"' in query for query in selections),
        "case_selects": sum('FROM "bridge_investigation"' in query for query in selections),
    }


class ProcessingEfficiencyTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="processing-lab", name="Synthetic processing lab")
        IngestKey.objects.create(
            integration=cls.app,
            key_id="processing-lab-key",
            secret_env="SB_PROCESSING_TEST_KEY",
            environment="test",
            source="migration_lab",
        )

    def setUp(self):
        now = timezone.now()
        self.base = now.replace(second=0, microsecond=0) - timedelta(minutes=now.minute % 5 + 10)
        self.environment = patch.dict(os.environ, {"SB_PROCESSING_TEST_KEY": SYNTHETIC_KEY})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def deliver(self, value):
        raw = canonical(value)
        at = timezone.now().isoformat()
        return self.client.post(
            "/api/v1/events/processing-lab/",
            raw,
            content_type="application/json",
            HTTP_X_SB_KEY="processing-lab-key",
            HTTP_X_SB_TIME=at,
            HTTP_X_SB_SIGNATURE=signature(
                SYNTHETIC_KEY, "processing-lab", "processing-lab-key", at, raw
            ),
        )

    def measure_worker(self, benign=False):
        values = [
            observation(
                index, self.base, **({"outcome": "allowed", "reason": "member"} if benign else {})
            )
            for index in range(PROFILE_RECORDS)
        ]
        samples = []
        for _ in range(PROFILE_REPEATS):
            with transaction.atomic():
                Event.objects.bulk_create(rows(self.app, values))
                with CaptureQueriesContext(connection) as queries:
                    started = time.perf_counter()
                    processed = drain(limit=PROFILE_RECORDS + 1)
                    elapsed = time.perf_counter() - started
                self.assertEqual(processed, PROFILE_RECORDS)
                self.assertEqual(Event.objects.filter(state="processed").count(), PROFILE_RECORDS)
                self.assertEqual(Investigation.objects.count(), 0 if benign else 1)
                if not benign:
                    case = Investigation.objects.get()
                    self.assertEqual(case.events.count(), PROFILE_RECORDS)
                    self.assertEqual(case.version, 1)
                    self.assertEqual(Audit.objects.filter(action="case.created").count(), 1)
                    self.assertEqual(Audit.objects.count(), 1)
                samples.append(query_measurement(queries.captured_queries, elapsed))
                transaction.set_rollback(True)
        return samples

    def measure_duplicates(self):
        value = observation(0, self.base)
        self.assertEqual(self.deliver(value).status_code, 202)
        with CaptureQueriesContext(connection) as queries:
            started = time.perf_counter()
            for _ in range(PROFILE_DUPLICATES):
                response = self.deliver(value)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["status"], "duplicate")
            elapsed = time.perf_counter() - started
        self.assertEqual(Event.objects.count(), 1)
        self.assertFalse(Investigation.objects.exists())
        return query_measurement(queries.captured_queries, elapsed)

    def test_fixed_processing_profile_preserves_cases_evidence_and_idempotent_delivery(self):
        emit = os.environ.get("SB_PROCESSING_PROFILE") == "1"
        if emit:
            self.assertEqual(connection.vendor, "sqlite")
            self.assertIn("memory", str(connection.settings_dict["NAME"]))
        correlated = self.measure_worker()
        benign = self.measure_worker(benign=True)
        duplicates = self.measure_duplicates()
        # These budgets protect reduced reads independently of wall-clock noise.
        # Per event, an app lock and an existing-case lookup must remain; neither
        # needs a second app/case SELECT or a payload on the queue candidate.
        for sample in correlated:
            self.assertLessEqual(sample["integration_selects"], PROFILE_RECORDS)
            self.assertLessEqual(sample["case_selects"], PROFILE_RECORDS)
            self.assertLessEqual(sample["event_selects_with_payload"], PROFILE_RECORDS * 2)
        for sample in benign:
            self.assertLessEqual(sample["event_selects_with_payload"], PROFILE_RECORDS)
        self.assertEqual(duplicates["event_selects_with_payload"], 0)
        if emit:
            root = Path(__file__).resolve().parents[1]
            report = {
                "schema_version": 1,
                "recorded_at": timezone.now().isoformat(),
                "kind": "bounded-disposable-processing-profile",
                "python": sys.version.split()[0],
                "django": django.get_version(),
                "sqlite": sqlite3.sqlite_version,
                "records_per_worker_drain": PROFILE_RECORDS,
                "worker_repeats": PROFILE_REPEATS,
                "duplicate_requests": PROFILE_DUPLICATES,
                "correlated_worker_samples": correlated,
                "benign_worker_samples": benign,
                "duplicate_requests_sample": duplicates,
                "correlated_median_seconds": statistics.median(
                    sample["seconds"] for sample in correlated
                ),
                "benign_median_seconds": statistics.median(sample["seconds"] for sample in benign),
                "source_sha256": {
                    name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                    for name in (
                        "bridge/engine.py",
                        "bridge/worker.py",
                        "bridge/ingestion.py",
                        "bridge/contract.py",
                        "tests/test_processing_efficiency.py",
                    )
                },
                "limits": [
                    "Synthetic events and an in-memory SQLite test database; no live HTTP or PostgreSQL.",
                    "Fixture creation is excluded; worker heartbeat, transaction statements and test query capture are included.",
                    "Three short serial worker trials and one duplicate-delivery trial; not sustained capacity or a production benchmark.",
                ],
            }
            print("SB_PROCESSING_PROFILE=" + json.dumps(report, sort_keys=True))

    def test_initial_case_lookup_retains_row_lock_for_new_and_existing_cases(self):
        Event.objects.bulk_create(
            rows(self.app, [observation(index, self.base) for index in range(3)])
        )
        observed_locks = []
        original_get = QuerySet.get

        def record_case_lock(queryset, *args, **kwargs):
            if queryset.model is Investigation:
                observed_locks.append(queryset.query.select_for_update)
            return original_get(queryset, *args, **kwargs)

        with patch.object(QuerySet, "get", record_case_lock):
            self.assertTrue(process_one())
            self.assertTrue(process_one())
        self.assertEqual(observed_locks, [True, True])
        self.assertEqual(Investigation.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="case.created").count(), 1)

    def test_existing_case_keeps_review_history_and_does_not_reopen_on_same_evidence(self):
        values = [observation(index, self.base) for index in range(4)]
        Event.objects.bulk_create(rows(self.app, values))
        drain()
        case = Investigation.objects.get()
        version = case.version
        case.status = "resolved"
        case.save(update_fields=["status"])
        Event.objects.update(state="pending")
        drain()
        case.refresh_from_db()
        self.assertEqual((case.status, case.version, case.events.count()), ("resolved", version, 4))
        self.assertEqual(Audit.objects.count(), 1)
        late = observation(4, self.base)
        Event.objects.bulk_create(rows(self.app, [late]))
        drain()
        case.refresh_from_db()
        self.assertEqual((case.status, case.version, case.events.count()), ("open", version + 1, 5))
        self.assertEqual(Audit.objects.filter(action="case.reopened").count(), 1)

    def test_reprocessing_r2_preserves_critical_case_and_one_audit(self):
        value = observation(0, self.base, outcome="allowed", reason="membership_removed")
        Event.objects.bulk_create(rows(self.app, [value]))
        process_one()
        case = Investigation.objects.get()
        Event.objects.update(state="pending")
        process_one()
        case.refresh_from_db()
        self.assertEqual(
            (case.rule, case.severity, case.version, case.events.count()), ("R2", "critical", 1, 1)
        )
        self.assertEqual(Audit.objects.count(), 1)

    def test_duplicate_conflict_and_disabled_key_still_fail_after_authenticated_retry(self):
        value = observation(0, self.base)
        self.assertEqual(self.deliver(value).status_code, 202)
        self.assertEqual(self.deliver(dict(value, resource="f" * 64)).status_code, 409)
        IngestKey.objects.update(active=False)
        self.assertEqual(self.deliver(value).status_code, 401)
        self.assertEqual(Event.objects.count(), 1)
