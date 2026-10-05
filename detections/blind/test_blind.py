"""Blind-evaluation checks on a synthetic fixture; no author file is needed. Run from the root:

python -m unittest discover -s detections -t . -p "test_*.py"
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from ..sigma.replay import REPORT, ROOT
from . import blind

RECEIPT = ROOT / "docs/evidence/20261005-enterprise-detection-evaluation-public-release.json"


def read(actor, resource, at="0:00", outcome="allowed", reason="member"):
    return {
        "at": at,
        "actor": actor,
        "resource": resource,
        "operation": "private_record.read",
        "outcome": outcome,
        "reason": reason,
    }


def removal(admin, subject, resource, at="0:00"):
    return {
        "at": at,
        "actor": admin,
        "resource": resource,
        "operation": "membership.change",
        "outcome": "allowed",
        "reason": "membership_removed",
        "membership": {"subject": subject, "state": "removed"},
    }


def fixture():
    """20 scenarios with known outcomes: TP 6, FP 1, FN 2, TN 10, inconclusive 1."""
    plan = (
        [("benign", "Normal read", [read("alice", "doc-1")])] * 10
        + [
            (
                "suspicious",
                "Read after removal",
                [removal("carol", "bob", "doc-2"), read("bob", "doc-2", "0:07")],
            )
        ]
        * 6
        + [
            (
                "suspicious",
                "One refused read",
                [read("eve", "doc-3", outcome="denied", reason="membership_required")],
            )
        ]
        * 2
        + [("benign", "Faulty release", [read("dan", "doc-4", reason="policy_regression")])]
        + [("inconclusive", "Unclear read", [read("frank", "doc-5")])]
    )
    scenarios = [
        {
            "id": f"B{i:02d}",
            "title": title,
            "label": label,
            "rationale": "Synthetic test case.",
            "events": events,
        }
        for i, (label, title, events) in enumerate(plan, 1)
    ]
    return {"author": "anonymous", "attestation": blind.ATTESTATION, "scenarios": scenarios}


def write(directory, data, name="scenarios.yml"):
    path = Path(directory) / name
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


class Format(unittest.TestCase):
    def test_template_is_valid_once_its_examples_are_replaced(self):
        template = yaml.safe_load((Path(blind.__file__).parent / "template.yml").read_text())
        examples = template["scenarios"]
        template["scenarios"] = [
            {**copy.deepcopy(examples[i % len(examples)]), "id": f"B{i + 1:02d}"} for i in range(20)
        ]
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(len(blind.load(write(tmp, template))["scenarios"]), 20)
            template["scenarios"][0]["id"] = "EX1"
            with self.assertRaises(blind.BlindError):
                blind.load(write(tmp, template))

    def test_check_rejects_files_outside_the_contract(self):
        def change(edit):
            data = fixture()
            edit(data)
            return data

        cases = {
            "edited attestation": lambda d: d.update(attestation="I worked blind."),
            "extra top-level key": lambda d: d.update(notes="hi"),
            "too few scenarios": lambda d: d.update(scenarios=d["scenarios"][:19]),
            "duplicate id": lambda d: d["scenarios"][1].update(id="B01"),
            "email in rationale": lambda d: d["scenarios"][0].update(
                rationale="Ask bob@example.com"
            ),
            "IP in title": lambda d: d["scenarios"][0].update(title="From 10.1.2.3"),
            "unknown event field": lambda d: d["scenarios"][0]["events"][0].update(ip="x"),
            "unknown reason": lambda d: d["scenarios"][0]["events"][0].update(reason="hacked"),
            "uppercase name": lambda d: d["scenarios"][0]["events"][0].update(actor="Alice"),
            "bad time": lambda d: d["scenarios"][0]["events"][0].update(at="noon"),
            "time over 48 h": lambda d: d["scenarios"][0]["events"][0].update(at="49:00:00"),
            "removal with wrong reason": lambda d: d["scenarios"][10]["events"][0].update(
                reason="member"
            ),
            "membership on a read": lambda d: d["scenarios"][0]["events"][0].update(
                membership={"subject": "x", "state": "removed"}
            ),
        }
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(len(blind.load(write(tmp, fixture()))["scenarios"]), 20)
            for label, edit in cases.items():
                with self.subTest(label), self.assertRaises(blind.BlindError):
                    blind.load(write(tmp, change(edit)))

    def test_names_are_scoped_to_scenario_and_app(self):
        data = copy.deepcopy(fixture()["scenarios"][10])

        def actors(scenario):
            return [event for _, event in blind.convert("r1", 0, scenario)]

        events = actors(data)
        # The removed member and the later reader are the same account within a scenario.
        self.assertEqual(events[0]["membership"]["subject"], events[1]["actor"])
        # The same name in another scenario, or in the other app, is a different account.
        self.assertNotEqual(events[1]["actor"], actors({**data, "id": "B99"})[1]["actor"])
        expenses = copy.deepcopy(data)
        for event in expenses["events"]:
            event["app"] = "expenses"
        self.assertNotEqual(events[1]["actor"], actors(expenses)[1]["actor"])


class Rounds(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = patch.object(blind, "ROUNDS", Path(self.tmp.name) / "rounds")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.source = write(self.tmp.name, fixture(), "from-author.yml")

    def test_freeze_seal_score_gives_the_expected_metrics(self):
        blind.freeze("test-round")
        blind.seal("test-round", self.source)
        result = blind.score("test-round")
        metrics = result["metrics"]
        self.assertEqual([metrics[k] for k in ("tp", "fp", "fn", "tn")], [6, 1, 2, 10])
        self.assertEqual(metrics["inconclusive_scenarios"], 1)
        self.assertEqual(result["seal"]["author"], "anonymous")
        self.assertTrue(any("Author-attested" in limit for limit in result["limits"]))
        with self.assertRaises(blind.BlindError):
            blind.score("test-round")

    def test_seal_needs_a_freeze_first(self):
        with self.assertRaises(blind.BlindError):
            blind.seal("test-round", self.source)

    def test_score_refuses_a_changed_frozen_file(self):
        blind.freeze("test-round")
        blind.seal("test-round", self.source)
        path = blind.ROUNDS / "test-round" / "freeze.json"
        frozen = json.loads(path.read_text())
        frozen["files"]["bridge/engine.py"] = "0" * 64
        path.write_text(json.dumps(frozen))
        with self.assertRaises(blind.BlindError):
            blind.score("test-round")

    def test_score_refuses_a_changed_sealed_file(self):
        blind.freeze("test-round")
        blind.seal("test-round", self.source)
        sealed = blind.ROUNDS / "test-round" / "scenarios.yml"
        sealed.write_text(sealed.read_text().replace("Normal read", "Edited read", 1))
        with self.assertRaises(blind.BlindError):
            blind.score("test-round")


class Scoring(unittest.TestCase):
    def test_python_replay_scoring_reproduces_the_published_metrics(self):
        # Blind rounds alert when bridge.engine.detections() fires; on the frozen public round
        # that, with the published labels, gives exactly the published metrics.
        receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
        labels = {row["id"]: row["label"] for row in receipt["scenarios"]}
        rows = [
            {"label": labels[row["id"]], "alerted": bool(row["python_rules"])}
            for row in json.loads(REPORT.read_text(encoding="utf-8"))["scenarios"]
        ]
        self.assertEqual(blind.metrics(rows), receipt["metrics"])


if __name__ == "__main__":
    unittest.main()
