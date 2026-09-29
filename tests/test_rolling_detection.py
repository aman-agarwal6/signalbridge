"""Rolling R1 regressions against a small independent window oracle and disposable DB."""

import hashlib
import itertools
import random
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from django.db import transaction
from django.test import SimpleTestCase, TestCase
from django.utils import timezone as django_timezone

from bridge.contract import digest, timestamp
from bridge.engine import detections
from bridge.models import Audit, Event, Integration, Investigation
from bridge.worker import _relevant_events, drain, process_one

BASE = datetime(2026, 9, 24, 12, tzinfo=timezone.utc)


def event(index, seconds, **changes):
    value = {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"rolling-regression/{index}")),
        "app": "bettail",
        "environment": "test",
        "occurred_at": (BASE + timedelta(seconds=seconds)).isoformat(),
        "actor": "a" * 64,
        "resource": f"{index:064x}",
        "episode": str(uuid.uuid5(uuid.NAMESPACE_URL, "rolling-regression/episode")),
        "operation": "private_record.read",
        "outcome": "denied",
        "reason": "membership_required",
        "context": None,
    }
    value.update(changes)
    return value


def correlation(value):
    at = timestamp(value["occurred_at"])
    bucket = at.replace(second=0, microsecond=0) - timedelta(minutes=at.minute % 5)
    return digest(
        ["R1/rolling-v2", value["app"], value["environment"], value["actor"], bucket.isoformat()]
    )


def oracle(events):
    """Intentionally simple quadratic specification used only for small test inputs."""
    result = defaultdict(set)
    failures = [
        value
        for value in events
        if value["operation"] == "private_record.read"
        and value["outcome"] in ("denied", "not_visible")
    ]
    for endpoint in failures:
        at = timestamp(endpoint["occurred_at"])
        scope = tuple(endpoint[field] for field in ("app", "environment", "actor"))
        window = [
            value
            for value in failures
            if tuple(value[field] for field in ("app", "environment", "actor")) == scope
            and timedelta(0) <= at - timestamp(value["occurred_at"]) <= timedelta(seconds=300)
        ]
        if len({value["resource"] for value in window}) >= 3:
            result[correlation(endpoint)].update(value["event_id"] for value in window)
    return {key: sorted(value) for key, value in result.items()}


def observed(events, **options):
    return {
        row["correlation"]: row["event_ids"]
        for row in detections(events, **options)
        if row["rule"] == "R1"
    }


class RollingEngineTests(SimpleTestCase):
    def test_prior_boundary_miss_now_has_one_rolling_case(self):
        events = [event(index, seconds) for index, seconds in enumerate((299, 300, 301), 1)]
        self.assertEqual(observed(events), oracle(events))
        self.assertEqual(len(observed(events)), 1)

    def test_exact_five_minutes_is_inclusive_but_one_microsecond_beyond_is_not(self):
        events = [event(1, 0), event(2, 1), event(3, 300)]
        self.assertEqual(observed(events), oracle(events))
        self.assertEqual(len(observed(events)), 1)
        events[-1]["occurred_at"] = (BASE + timedelta(seconds=300, microseconds=1)).isoformat()
        self.assertEqual(observed(events), {})

    def test_rolling_window_cannot_accumulate_slow_activity_indefinitely(self):
        self.assertEqual(observed([event(1, 0), event(2, 301), event(3, 602)]), {})

    def test_same_resource_and_non_read_operations_do_not_make_a_threshold(self):
        self.assertEqual(
            observed([event(index, 299 + index, resource="b" * 64) for index in range(5)]), {}
        )
        events = [event(1, 299), event(2, 300), event(3, 301, operation="session.verify")]
        self.assertEqual(observed(events), {})

    def test_scope_boundaries_remain_separate(self):
        for change in ({"app": "netted"}, {"environment": "lab"}, {"actor": "f" * 64}):
            with self.subTest(change=change):
                self.assertEqual(
                    observed([event(1, 299), event(2, 300), event(3, 301, **change)]), {}
                )

    def test_all_input_orders_and_equivalent_timezone_representations_are_deterministic(self):
        events = [event(1, 299), event(2, 300), event(3, 301), event(4, 302)]
        events[0]["occurred_at"] = (
            (BASE + timedelta(seconds=299)).astimezone(timezone(timedelta(hours=9))).isoformat()
        )
        expected = oracle(events)
        for ordering in itertools.permutations(events):
            self.assertEqual(observed(ordering), expected)

    def test_case_evidence_unions_qualifying_windows_not_one_claimed_five_minute_span(self):
        events = [event(index, seconds) for index, seconds in enumerate((1, 2, 300, 301, 599), 1)]
        result = observed(events)
        self.assertEqual(result, oracle(events))
        self.assertEqual(len(result), 1)
        self.assertEqual(set(next(iter(result.values()))), {value["event_id"] for value in events})
        self.assertGreater(
            timestamp(events[-1]["occurred_at"]) - timestamp(events[0]["occurred_at"]),
            timedelta(seconds=300),
        )

    def test_sustained_activity_can_make_related_cases_in_adjacent_endpoint_buckets(self):
        events = [event(index, seconds) for index, seconds in enumerate((0, 1, 2, 301), 1)]
        result = observed(events)
        self.assertEqual(result, oracle(events))
        self.assertEqual(len(result), 2)
        self.assertNotIn(events[0]["event_id"], result[correlation(events[-1])])

    def test_revision_namespace_does_not_reuse_old_fixed_bucket_case_identity(self):
        events = [event(1, 1), event(2, 2), event(3, 3)]
        key = ("bettail", "test", "a" * 64, int(BASE.timestamp()) // 300)
        previous = hashlib.sha256(str(key).encode()).hexdigest()
        result = observed(events)
        self.assertNotIn(previous, result)
        self.assertEqual(list(result), [correlation(events[-1])])

    def test_endpoint_bounds_keep_lookback_context_but_only_evaluate_affected_endpoints(self):
        events = [event(index, seconds) for index, seconds in enumerate((0, 1, 2, 301), 1)]
        result = observed(
            events,
            endpoint_from=BASE + timedelta(seconds=301),
            endpoint_to=BASE + timedelta(seconds=601),
        )
        self.assertEqual(
            result,
            {
                correlation(events[-1]): [
                    value["event_id"]
                    for value in sorted(events[1:], key=lambda value: value["event_id"])
                ]
            },
        )

    def test_small_randomized_corpora_match_independent_window_oracle(self):
        generator = random.Random(20260924)
        for trial in range(12):
            events = [
                event(
                    trial * 100 + index,
                    generator.randrange(901),
                    resource=f"{generator.randrange(5):064x}",
                    app=generator.choice(("bettail", "netted")),
                    environment=generator.choice(("test", "lab")),
                    outcome=generator.choice(("denied", "not_visible", "error")),
                )
                for index in range(60)
            ]
            generator.shuffle(events)
            with self.subTest(trial=trial):
                self.assertEqual(observed(events), oracle(events))

    def test_r2_remains_a_single_event_identity(self):
        value = event(1, 299, outcome="allowed", reason="membership_removed")
        result = detections([value])
        self.assertEqual(len(result), 1)
        self.assertEqual((result[0]["rule"], result[0]["correlation"]), ("R2", value["event_id"]))


class RollingWorkerTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="bettail", name="BetTail")
        cls.other = Integration.objects.create(slug="netted", name="Netted")

    def persist(self, value, source="migration_lab"):
        return Event.objects.create(
            integration=self.app if value["app"] == "bettail" else self.other,
            event_id=value["event_id"],
            occurred_at=timestamp(value["occurred_at"]),
            actor=value["actor"],
            resource=value["resource"],
            episode=value["episode"],
            operation=value["operation"],
            outcome=value["outcome"],
            reason=value["reason"],
            environment=value["environment"],
            source=source,
            payload=value,
            digest=digest(value),
            available_at=django_timezone.now(),
        )

    def test_each_arrival_order_finds_boundary_evidence_once(self):
        values = [event(1, 299), event(2, 300), event(3, 301)]
        for ordering in itertools.permutations(values):
            with self.subTest(order=[value["event_id"] for value in ordering]):
                with transaction.atomic():
                    for value in ordering:
                        self.persist(value)
                        drain()
                    case = Investigation.objects.get()
                    expected = hashlib.sha256(
                        ("migration_lab|" + correlation(values[-1])).encode()
                    ).hexdigest()
                    self.assertEqual(case.correlation, expected)
                    self.assertEqual(case.events.count(), 3)
                    self.assertEqual(case.version, 1)
                    self.assertEqual(Audit.objects.filter(action="case.created").count(), 1)
                    transaction.set_rollback(True)

    def test_late_predecessor_reopens_existing_case_without_rekeying(self):
        for value in (event(1, 299), event(2, 300), event(3, 301)):
            self.persist(value)
        drain()
        case = Investigation.objects.get()
        old_key, old_version = case.correlation, case.version
        case.status = "resolved"
        case.save(update_fields=["status"])
        late = self.persist(event(4, 298))
        drain()
        case.refresh_from_db()
        self.assertEqual(Investigation.objects.count(), 1)
        self.assertEqual(case.correlation, old_key)
        self.assertEqual((case.status, case.version), ("open", old_version + 1))
        self.assertTrue(case.events.filter(pk=late.pk).exists())
        self.assertEqual(
            Audit.objects.filter(action="case.reopened", object_id=str(case.pk)).count(), 1
        )
        Event.objects.filter(pk=late.pk).update(state="pending")
        drain()
        case.refresh_from_db()
        self.assertEqual(case.version, old_version + 1)
        self.assertEqual(Audit.objects.filter(action="case.reopened").count(), 1)

    def test_late_predecessor_outside_five_minutes_does_not_reopen_case(self):
        for value in (event(1, 299), event(2, 300), event(3, 301)):
            self.persist(value)
        drain()
        case = Investigation.objects.get()
        case.status = "resolved"
        case.save(update_fields=["status"])
        version = case.version
        self.persist(event(4, -2))
        drain()
        case.refresh_from_db()
        self.assertEqual((case.status, case.version, case.events.count()), ("resolved", version, 3))

    def test_worker_lookaround_preserves_all_correlation_scope_dimensions(self):
        for change, source in (
            ({"app": "netted"}, "migration_lab"),
            ({"environment": "lab"}, "migration_lab"),
            ({"actor": "f" * 64}, "migration_lab"),
            ({}, "synthetic_demo"),
        ):
            with self.subTest(change=change, source=source), transaction.atomic():
                self.persist(event(1, 299))
                self.persist(event(2, 300))
                self.persist(event(3, 301, **change), source=source)
                drain()
                self.assertFalse(Investigation.objects.exists())
                transaction.set_rollback(True)

    def test_incremental_worker_orders_converge_to_complete_window_evidence(self):
        values = [event(index, seconds) for index, seconds in enumerate((0, 1, 2, 301, 302), 1)]
        expected = {
            hashlib.sha256(("migration_lab|" + key).encode()).hexdigest(): ids
            for key, ids in oracle(values).items()
        }
        orders = [values, list(reversed(values))]
        generator = random.Random(20260924)
        for _ in range(10):
            order = list(values)
            generator.shuffle(order)
            orders.append(order)
        for ordering in orders:
            with (
                self.subTest(order=[value["event_id"] for value in ordering]),
                transaction.atomic(),
            ):
                for value in ordering:
                    self.persist(value)
                    drain()
                result = {
                    case.correlation: sorted(
                        str(value) for value in case.events.values_list("event_id", flat=True)
                    )
                    for case in Investigation.objects.all()
                }
                self.assertEqual(result, expected)
                self.assertFalse(Event.objects.exclude(state="processed").exists())
                transaction.set_rollback(True)

    def test_two_qualifying_source_classes_keep_distinct_cases_and_evidence(self):
        for offset, source in ((0, "migration_lab"), (10, "synthetic_demo")):
            for index, seconds in enumerate((299, 300, 301), 1):
                self.persist(event(index + offset, seconds), source=source)
        drain()
        self.assertEqual(Investigation.objects.count(), 2)
        for case in Investigation.objects.all():
            self.assertEqual(case.events.count(), 3)
            self.assertEqual(len(set(case.events.values_list("source", flat=True))), 1)

    def test_worker_query_is_inclusive_bounded_lookaround_and_excludes_unrelated_operations(self):
        target = self.persist(event(1, 300))
        included = [target, self.persist(event(2, 0)), self.persist(event(3, 600))]
        for value in (
            event(4, -0.000001),
            event(5, 600.000001),
            event(6, 300, operation="session.verify"),
            event(7, 300, outcome="allowed"),
        ):
            self.persist(value)
        self.assertEqual({row.pk for row in _relevant_events(target)}, {row.pk for row in included})

    def test_capacity_failure_is_visible_without_truncating_to_a_clean_result(self):
        for index, seconds in enumerate((0, 299, 300, 301), 1):
            self.persist(event(index, seconds))
        row = Event.objects.get(event_id=event(2, 299)["event_id"])
        Event.objects.exclude(pk=row.pk).update(state="processed")
        Event.objects.filter(pk=row.pk).update(attempts=4)
        with patch("bridge.worker.MAX_CORRELATION_EVENTS", 3):
            with self.assertRaises(ValueError):
                process_one()
        row.refresh_from_db()
        self.assertEqual((row.state, row.error_code), ("dead", "correlation_capacity"))
        self.assertFalse(Investigation.objects.exists())

    def test_historical_fixed_bucket_case_is_preserved_with_its_existing_evidence(self):
        values = [event(1, 1), event(2, 2), event(3, 3)]
        rows = [self.persist(value) for value in values]
        old_key = hashlib.sha256(
            str(("bettail", "test", "a" * 64, int(BASE.timestamp()) // 300)).encode()
        ).hexdigest()
        old = Investigation.objects.create(
            integration=self.app,
            rule="R1",
            correlation=hashlib.sha256(("migration_lab|" + old_key).encode()).hexdigest(),
            title="Historical fixed-bucket case",
            severity="medium",
            explanation="Historical semantics",
            status="resolved",
            version=7,
        )
        old.events.add(*rows)
        drain()
        old.refresh_from_db()
        self.assertEqual(
            (old.status, old.version, old.explanation), ("resolved", 7, "Historical semantics")
        )
        self.assertEqual(old.events.count(), 3)
        self.assertEqual(Investigation.objects.count(), 2)
