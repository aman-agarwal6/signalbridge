"""Bounded extended patterns, independent small-window oracle and source isolation."""

import random
from collections import defaultdict
from datetime import timedelta

from django.test import SimpleTestCase, TestCase

from bridge.contract import digest, timestamp
from bridge.detection_catalog import RULES, explain_case
from bridge.engine import detections
from bridge.models import Event, Integration, Investigation
from bridge.worker import drain
from tests.test_processing_efficiency import rows
from tests.test_rolling_detection import BASE, event


def observed(values, rule, **bounds):
    return {
        r["correlation"]: r["event_ids"] for r in detections(values, **bounds) if r["rule"] == rule
    }


def oracle(values, rule):
    """Quadratic test specification; production uses counters and interval unions."""
    slow = rule == "R4"
    field, width = ("actor", 1800) if slow else ("resource", 600)
    unique = {
        e["event_id"]: e
        for e in values
        if e["operation"] == "private_record.read" and e["outcome"] == "denied"
    }
    result = defaultdict(set)
    for endpoint in unique.values():
        at = timestamp(endpoint["occurred_at"])
        scope = tuple(endpoint[k] for k in ("app", "environment", field))
        group = [
            e
            for e in unique.values()
            if tuple(e[k] for k in ("app", "environment", field)) == scope
            and 0 <= (at - timestamp(e["occurred_at"])).total_seconds() <= width
        ]
        meets = (
            len({e["resource"] for e in group}) >= 5
            and (at - min(timestamp(e["occurred_at"]) for e in group)).total_seconds() >= 600
            if slow
            else len(group) >= 6 and len({e["actor"] for e in group}) >= 3
        )
        if meets:
            key = digest(
                [rule + "/bounded-denials-v1", *scope, int(at.timestamp()) // width * width]
            )
            result[key].update(e["event_id"] for e in group)
    return {key: sorted(ids) for key, ids in result.items()}


class ExtendedEngineTests(SimpleTestCase):
    def test_slow_pattern_has_five_resources_and_minimum_span(self):
        values = [event(i, i * 400) for i in range(5)]
        self.assertEqual(observed(values, "R4"), oracle(values, "R4"))
        self.assertEqual(len(observed(values, "R4")), 1)
        self.assertFalse(observed(values[:-1], "R4"))
        self.assertFalse(observed([event(i, i) for i in range(5)], "R4"))
        self.assertFalse(observed([event(i, i * 400, resource="d" * 64) for i in range(5)], "R4"))

    def test_slow_inclusive_horizon_and_minimum_span_boundaries(self):
        for seconds, expected in ((599, False), (600, True), (1800, True), (1801, False)):
            values = [event(i, 0) for i in range(4)] + [event(4, seconds)]
            self.assertEqual(bool(observed(values, "R4")), expected)

    def test_distributed_requires_six_denials_three_accounts_same_resource(self):
        values = [event(i, i, actor=f"{i % 3:064x}", resource="d" * 64) for i in range(6)]
        self.assertEqual(observed(values, "R5"), oracle(values, "R5"))
        self.assertEqual(len(observed(values, "R5")), 1)
        self.assertFalse(observed(values[:-1], "R5"))
        self.assertFalse(observed([dict(e, actor="a" * 64) for e in values], "R5"))
        self.assertFalse(
            observed([dict(e, resource=f"{i:064x}") for i, e in enumerate(values)], "R5")
        )

    def test_distributed_inclusive_window_and_duplicate_delivery(self):
        values = [
            event(i, 0 if i < 5 else 600, actor=f"{i % 3:064x}", resource="d" * 64)
            for i in range(6)
        ]
        self.assertEqual(len(observed(values, "R5")), 1)
        self.assertEqual(observed(values[:-1] * 3, "R5"), {})
        values[-1] = event(5, 601, actor=f"{5 % 3:064x}", resource="d" * 64)
        self.assertFalse(observed(values, "R5"))

    def test_scope_unavailable_error_and_nonread_controls(self):
        for rule, values in (
            ("R4", [event(i, i * 400) for i in range(5)]),
            ("R5", [event(i, i, actor=f"{i % 3:064x}", resource="d" * 64) for i in range(6)]),
        ):
            for fields in (
                {"app": "netted"},
                {"environment": "lab"},
                {"outcome": "not_visible"},
                {"outcome": "error"},
                {"operation": "session.verify"},
            ):
                with self.subTest(rule=rule, fields=fields):
                    self.assertFalse(observed([*values[:-1], dict(values[-1], **fields)], rule))

    def test_small_random_corpora_match_independent_oracle_and_order(self):
        generator = random.Random(20261001)
        for trial in range(6):
            values = [
                event(
                    trial * 100 + i,
                    generator.randrange(2401),
                    actor=f"{generator.randrange(4):064x}",
                    resource=f"{generator.randrange(6):064x}",
                    app=generator.choice(("bettail", "netted")),
                    outcome=generator.choice(("denied", "denied", "not_visible")),
                )
                for i in range(60)
            ]
            generator.shuffle(values)
            for rule in ("R4", "R5"):
                self.assertEqual(observed(values, rule), oracle(values, rule))
                self.assertEqual(observed(list(reversed(values)), rule), oracle(values, rule))

    def test_endpoint_bounds_keep_context_without_unaffected_case_creation(self):
        values = [event(i, i * 400) for i in range(5)]
        self.assertTrue(
            observed(
                values,
                "R4",
                endpoint_from=BASE + timedelta(seconds=1600),
                endpoint_to=BASE + timedelta(seconds=1600),
            )
        )
        self.assertFalse(observed(values, "R4", endpoint_from=BASE + timedelta(seconds=1601)))

    def test_all_rules_have_version_and_analyst_limits(self):
        self.assertEqual(set(RULES), {"R1", "R2", "R3", "R4", "R5"})
        for rule in RULES.values():
            for field in ("version", "logic", "false_positives", "blind_spots", "validation"):
                self.assertTrue(rule[field])


class ExtendedWorkerTests(TestCase):
    def setUp(self):
        self.app = Integration.objects.create(slug="bettail", name="Synthetic extended pattern")

    def test_late_slow_input_creates_one_case_with_all_evidence(self):
        values = [event(i, i * 400) for i in range(5)]
        for value in reversed(values):
            Event.objects.bulk_create(rows(self.app, [value]))
            drain()
        case = Investigation.objects.get(rule="R4")
        self.assertEqual(case.events.count(), 5)
        self.assertTrue(explain_case(case, list(case.events.all()))["current_match"])

    def test_distributed_evidence_across_accounts_is_explainable(self):
        values = [event(i, i, actor=f"{i % 3:064x}", resource="d" * 64) for i in range(6)]
        for value in reversed(values):
            Event.objects.bulk_create(rows(self.app, [value]))
            drain()
        case = Investigation.objects.get(rule="R5")
        self.assertEqual(case.events.count(), 6)
        self.assertTrue(explain_case(case, list(case.events.all()))["current_match"])

    def test_trusted_source_classes_do_not_form_a_shared_threshold(self):
        values = [event(i, i, actor=f"{i % 3:064x}", resource="d" * 64) for i in range(6)]
        Event.objects.bulk_create(rows(self.app, values[:3], source="migration_lab"))
        Event.objects.bulk_create(rows(self.app, values[3:], source="synthetic_demo"))
        drain()
        self.assertFalse(Investigation.objects.filter(rule="R5").exists())
