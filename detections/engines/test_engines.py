"""Checks that the committed engine receipts still describe the current queries and scenarios.

These read files only; they never need Splunk or Kusto. Run from the repository root:

python -m unittest discover -s detections -t . -p "test_*.py"
"""

import json
import unittest

from ..sigma.replay import REPORT, ROOT, frozen_round
from .run import DETECTIONS, HERE, VARIANTS, sha256


class Receipts(unittest.TestCase):
    def setUp(self):
        self.report = {r["id"]: r for r in json.loads(REPORT.read_text())["scenarios"]}
        self.round_id, scenarios, self.inputs_sha256 = frozen_round()
        self.events = sum(1 for s in scenarios for e in s["events"] if "repeat_of" not in e)

    def test_each_engine_receipt_matches_current_files_and_scenarios(self):
        for engine in VARIANTS:
            with self.subTest(engine=engine):
                receipt = json.loads((HERE / f"{engine}-run.json").read_text())
                self.assertEqual(receipt["engine"], engine)
                self.assertEqual(receipt["round_id"], self.round_id)
                self.assertEqual(receipt["inputs_sha256"], self.inputs_sha256)
                self.assertEqual(receipt["events_loaded"], self.events)
                self.assertEqual(set(receipt["variants"]), set(VARIANTS[engine]))
                for name, variant in receipt["variants"].items():
                    self.check_variant(engine, name, variant)

    def check_variant(self, engine, name, variant):
        # A changed query file means the receipt no longer describes it: rerun the engine.
        for rule, (path, origin) in VARIANTS[engine][name].items():
            entry = variant["queries"][rule]
            self.assertEqual((entry["file"], entry["origin"]), (path, origin), (name, rule))
            self.assertEqual(entry["sha256"], sha256(ROOT / path), f"{name} {rule}: rerun")
        rows = variant["scenarios"]
        self.assertEqual([r["id"] for r in rows], list(self.report))
        for row in rows:
            self.assertEqual(row["python_rules"], self.report[row["id"]]["python_rules"])
            self.assertEqual(row["agrees"], row["python_rules"] == row["engine_rules"])
        summary = variant["summary"]
        self.assertEqual(summary["matches_python"], sum(r["agrees"] for r in rows))
        failed = sorted(rule for rule, entry in variant["queries"].items() if "error" in entry)
        self.assertEqual(summary["failed_queries"], failed)
        for rule in DETECTIONS:
            pairs = [(rule in r["python_rules"], rule in r["engine_rules"]) for r in rows]
            self.assertEqual(
                summary["per_rule"][rule],
                {
                    "both": sum(p and e for p, e in pairs),
                    "python_only": sum(p and not e for p, e in pairs),
                    "engine_only": sum(e and not p for p, e in pairs),
                },
            )


if __name__ == "__main__":
    unittest.main()
