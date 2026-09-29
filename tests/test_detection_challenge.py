"""Synthetic validation fixtures only; real challenge execution uses its fixed runner."""

import copy
from datetime import datetime, timezone
from unittest import TestCase

from bridge.challenge_evidence import display_rows, score_rows, validate_result
from bridge.contract import FIELDS, canonical, validate_event
from simulations.challenge_cases import (
    MAX_REQUESTS,
    PROFILE,
    catalog,
    declaration_sha256,
    deliveries,
)


def synthetic_result():
    rows = []
    for case in catalog():
        unique = sum(r.repeat is None for r in case.readings)
        rows.append(
            {
                "id": case.id,
                "observed_rules": list(case.rules),
                "case_count": case.cases,
                "accepted": unique,
                "duplicates": len(case.readings) - unique,
                "processed": unique,
            }
        )
    return {
        "schema_version": 1,
        "kind": PROFILE,
        "declaration_sha256": declaration_sha256(),
        "started_at": "2026-09-25T08:00:00+00:00",
        "finished_at": "2026-09-25T08:00:01+00:00",
        "duration_seconds": 1.0,
        "execution_status": "completed",
        "database": "disposable in-memory SQLite",
        "transport": "Django in-process test client",
        "rows": rows,
        "requests_executed": sum(r["accepted"] + r["duplicates"] for r in rows),
        "records_processed": sum(r["processed"] for r in rows),
        "summary": score_rows(rows),
    }


class ChallengeTests(TestCase):
    def test_catalog_is_bounded_and_oracle_never_enters_wire_payload(self):
        now = datetime(2026, 9, 25, 8, 0, 0, tzinfo=timezone.utc)
        count = 0
        identities = set()
        for case in catalog():
            readings = list(deliveries(case, now))
            self.assertTrue(all(0 <= r.at <= 900 for r in case.readings))
            for body, _ in readings:
                count += 1
                self.assertEqual(set(body), FIELDS)
                validate_event(body, "lab-challenge", now=now)
                wire = canonical(body).decode()
                self.assertNotIn(case.title, wire)
                self.assertNotIn(case.id, wire)
                self.assertNotIn("expected", wire)
            actors = {body["actor"] for body, _ in readings}
            self.assertFalse(identities & actors)
            identities.update(actors)
        self.assertLessEqual(count, MAX_REQUESTS)
        self.assertEqual(len(catalog()), 19)

    def test_desired_uncovered_capabilities_remain_unmet_after_successful_execution(self):
        status, report = validate_result(synthetic_result())
        self.assertEqual(status, "partial")
        self.assertEqual(
            report["summary"]["rule_contract"], {"met": 16, "total": 16, "failed_ids": []}
        )
        self.assertEqual(
            report["summary"]["capability_probes"],
            {
                "alert_observed": 0,
                "total": 3,
                "unmet_ids": ["P01", "P02", "P03"],
            },
        )
        self.assertEqual(sum(row["met"] for row in display_rows(report)), 16)

    def test_miss_and_unexpected_alert_are_both_failures_without_truncating_other_rows(self):
        report = synthetic_result()
        report["rows"][0].update(observed_rules=[], case_count=0)
        report["rows"][1].update(observed_rules=["R1"], case_count=1)
        report["summary"] = score_rows(report["rows"])
        status, result = validate_result(report)
        self.assertEqual(status, "failed")
        self.assertEqual(len(result["rows"]), 19)
        self.assertEqual(result["summary"]["rule_contract"]["failed_ids"], ["C01", "C02"])
        self.assertEqual(result["summary"]["capability_probes"]["unmet_ids"], ["P01", "P02", "P03"])

    def test_exact_case_count_catches_duplicate_or_collapsed_investigations(self):
        for index, count in ((0, 2), (15, 1)):
            report = synthetic_result()
            report["rows"][index]["case_count"] = count
            report["summary"] = score_rows(report["rows"])
            self.assertEqual(validate_result(report)[0], "failed")

    def test_missing_extra_reordered_or_unknown_rows_fail_closed(self):
        rows = synthetic_result()["rows"]
        variants = (
            rows[:-1],
            rows + [rows[0]],
            rows[1:] + rows[:1],
            [{**rows[0], "id": "other"}, *rows[1:]],
        )
        for bad in variants:
            with self.subTest(length=len(bad)), self.assertRaises(ValueError):
                score_rows(bad)

    def test_invalid_rules_counts_and_injected_labels_fail_closed(self):
        for key, value in (
            ("observed_rules", ["R3"]),
            ("observed_rules", ["R1", "R1"]),
            ("observed_rules", "R1"),
            ("accepted", True),
            ("processed", 0),
            ("duplicates", 1),
            ("case_count", 0),
            ("case_count", 151),
            ("expected_rule", "R1"),
        ):
            report = synthetic_result()
            report["rows"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate_result(report)

    def test_changed_declaration_incomplete_execution_totals_and_false_summary_are_rejected(self):
        for key, value in (
            ("schema_version", True),
            ("kind", "other"),
            ("declaration_sha256", "a" * 64),
            ("execution_status", "failed"),
            ("database", "live"),
            ("transport", "network"),
            ("requests_executed", True),
            ("records_processed", 0),
            ("duration_seconds", float("nan")),
            ("duration_seconds", 121),
            ("summary", {"passed": True}),
            ("finished_at", "2026-09-24T08:00:00+00:00"),
        ):
            report = synthetic_result()
            report[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_result(report)

    def test_scorer_does_not_mutate_the_recorded_observations(self):
        report = synthetic_result()
        before = copy.deepcopy(report)
        validate_result(report)
        display_rows(report)
        self.assertEqual(before, report)
