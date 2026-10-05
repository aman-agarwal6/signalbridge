"""The accuracy denominator must not silently include inconclusive or unrun cases."""

import hashlib
import json
from html.parser import HTMLParser
from unittest.mock import patch

from django.test import SimpleTestCase

from scripts.build_detection_report import RECEIPT, render
from scripts.evaluate_detection import DATA, checksums, evaluate, metrics


class EvaluationMetricsTests(SimpleTestCase):
    def test_all_four_outcomes_have_explicit_denominators(self):
        rows = [
            {"label": label, "alerted": alerted}
            for label in ("suspicious", "benign", "inconclusive")
            for alerted in (True, False)
        ]
        result = metrics(rows)
        self.assertEqual([result[k] for k in ("tp", "fp", "fn", "tn")], [1, 1, 1, 1])
        self.assertEqual(result["scored_scenarios"], 4)
        self.assertEqual(result["inconclusive_scenarios"], 2)
        for key in ("precision", "recall", "false_positive_rate"):
            self.assertEqual(result[key], {"numerator": 1, "denominator": 2, "value": 0.5})

    def test_zero_denominators_are_unknown_not_perfect(self):
        result = metrics([])
        self.assertIsNone(result["precision"]["value"])
        self.assertIsNone(result["recall"]["value"])
        self.assertIsNone(result["false_positive_rate"]["value"])

    def test_changed_implementation_fails_before_database_or_network_setup(self):
        with (
            patch("scripts.evaluate_detection.checksums", return_value={}),
            self.assertRaisesRegex(ValueError, "Frozen implementation changed"),
        ):
            evaluate()

    def test_retained_result_reconciles_to_sealed_inputs_and_frozen_implementation(self):
        report = json.loads(RECEIPT.read_text(encoding="utf8"))
        frozen = json.loads((DATA / "freeze.json").read_text(encoding="utf8"))
        self.assertEqual(report["implementation"]["files"], frozen["files"])
        # Historical receipts bind their own frozen revision. Changed current
        # code must be evaluated in a new round, never overwrite September.
        if checksums() != frozen["files"]:
            with self.assertRaisesRegex(ValueError, "Frozen implementation changed"):
                evaluate()
        self.assertEqual(report["metrics"], metrics(report["scenarios"]))
        for filename, field in (("inputs.json", "inputs_sha256"), ("labels.json", "labels_sha256")):
            self.assertEqual(
                hashlib.sha256((DATA / filename).read_bytes()).hexdigest(), report[field]
            )

    def test_readable_report_has_local_links_no_active_content_and_all_outcomes(self):
        report = json.loads(RECEIPT.read_text(encoding="utf8"))
        html = render(report)
        root = RECEIPT.parents[2]

        class Inspect(HTMLParser):
            tags = []
            links = []

            def handle_starttag(self, tag, attrs):
                self.tags.append(tag)
                for key, value in attrs:
                    if key == "href":
                        self.links.append(value)
                    if key.startswith("on"):
                        raise AssertionError("Active event handler in report")

        parser = Inspect()
        parser.feed(html)
        self.assertFalse({"script", "iframe", "form", "object"} & set(parser.tags))
        for link in parser.links:
            self.assertNotIn(":", link)
            target = (root / "portfolio" / link).resolve()
            self.assertTrue(target.is_relative_to(root.resolve()))
            self.assertTrue(target.is_file())
        self.assertEqual(parser.tags.count("tr"), len(report["scenarios"]) + 1)
        self.assertIn("False alert", html)
        self.assertIn("Missed", html)
        self.assertIn("All outcomes, including the gaps", html)
        self.assertEqual((root / "portfolio/evaluation.html").read_text(encoding="utf8"), html)
