"""Checks for the Sigma rules. Run from the repository root:

python -m unittest discover -s detections -t . -p "test_*.py"
"""

import json
import re
import unittest
import uuid
from datetime import datetime, timedelta, timezone

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

from .compile import COMPILED, DETECTIONS, RULES, compile_all, sqlite_queries
from .replay import REPORT, ROOT, ROUND, build_report, python_rules, sigma_rules

# Technique IDs checked by hand against MITRE ATT&CK Enterprise; the README explains each choice.
ATTACK_TAGS = {"attack.collection", "attack.persistence", "attack.t1078", "attack.t1213"}
START = datetime(2026, 10, 2, 9, tzinfo=timezone.utc)


def event(second, operation, outcome, reason, actor, resource, membership=None):
    value = {
        "schema_version": 2 if membership else 1,
        "event_id": str(uuid.uuid4()),
        "app": "documents",
        "environment": "test",
        "occurred_at": (START + timedelta(seconds=second)).isoformat(),
        "actor": actor * 64,
        "resource": resource * 64,
        "episode": str(uuid.uuid4()),
        "operation": operation,
        "outcome": outcome,
        "reason": reason,
        "context": None,
    }
    if membership:
        value["membership"] = {"subject": membership[0] * 64, "state": membership[1]}
    return ("instrumented_lab", value)


class RuleFiles(unittest.TestCase):
    def test_rules_load_with_unique_ids_and_known_attack_tags(self):
        rules = SigmaCollection.load_ruleset([RULES])
        rules.resolve_rule_references()
        ids = [rule.id for rule in rules.rules]
        self.assertEqual(len(ids), len(set(ids)))
        names = {rule.name for rule in rules.rules}
        for rule_id in DETECTIONS:
            rule = next(r for r in rules.rules if r.name == f"signalbridge_{rule_id.lower()}")
            tags = {str(tag) for tag in rule.tags}
            self.assertTrue(tags, rule_id)
            self.assertLessEqual(tags, ATTACK_TAGS, rule_id)
            self.assertTrue(any(re.fullmatch(r"attack\.t\d{4}", tag) for tag in tags), rule_id)
            if isinstance(rule, SigmaCorrelationRule):
                for reference in rule.rules:
                    self.assertIn(reference.reference, names)

    def test_compiled_queries_are_current(self):
        present = {
            path.relative_to(COMPILED).as_posix(): path.read_text(encoding="utf-8")
            for path in COMPILED.rglob("*")
            if path.is_file()
        }
        self.assertEqual(present, compile_all())


class Replay(unittest.TestCase):
    def test_replays_the_round_the_evaluator_uses(self):
        # Read as text: importing the evaluator pulls in Django and the lab guards.
        source = (ROOT / "scripts/evaluate_enterprise_detection.py").read_text(encoding="utf-8")
        current = re.search(r'^DATA = ROOT / "([^"]+)"$', source, re.MULTILINE)
        self.assertIsNotNone(current, "evaluator DATA line not found")
        self.assertEqual(
            current.group(1),
            ROUND.relative_to(ROOT).as_posix(),
            "The evaluator moved to a new frozen round; point replay.ROUND at it and rerun.",
        )

    def test_report_is_current_and_python_reproduces_the_receipt(self):
        report = build_report()
        self.assertEqual(json.loads(REPORT.read_text(encoding="utf-8")), report)
        self.assertEqual(report["summary"]["python_matches_receipt"], 48)

    def test_known_gap_r3_fires_after_a_regrant(self):
        events = [
            event(
                0, "membership.change", "allowed", "membership_removed", "c", "b", ("a", "removed")
            ),
            event(2, "membership.change", "allowed", "member", "c", "b", ("a", "granted")),
            event(7, "private_record.read", "allowed", "member", "a", "b"),
        ]
        self.assertEqual(python_rules(events), [])
        self.assertEqual(sigma_rules(events, sqlite_queries()), ["R3"])

    def test_known_gap_r4_fires_on_a_fast_burst(self):
        # Five distinct denials in two minutes: R1 in both; R4 only without its 10-minute span.
        events = [
            event(30 * i, "private_record.read", "denied", "membership_required", "a", r)
            for i, r in enumerate("12345")
        ]
        self.assertEqual(python_rules(events), ["R1"])
        self.assertEqual(sigma_rules(events, sqlite_queries()), ["R1", "R4"])

    def test_r4_agrees_once_the_span_reaches_ten_minutes(self):
        events = [
            event(150 * i, "private_record.read", "denied", "membership_required", "a", r)
            for i, r in enumerate("12345")
        ]
        self.assertIn("R4", python_rules(events))
        self.assertIn("R4", sigma_rules(events, sqlite_queries()))


if __name__ == "__main__":
    unittest.main()
