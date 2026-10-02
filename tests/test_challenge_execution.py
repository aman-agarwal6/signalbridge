"""Fault-injection checks for measurement completeness, using disposable test storage."""

import json
import os
import shutil
import uuid
from pathlib import Path
from unittest.mock import patch

from django.test import Client, TransactionTestCase, override_settings, tag

from bridge.challenge_evidence import validate_result
from bridge.models import Investigation
from simulations import challenge_suite


@override_settings(SETTINGS_MODULE="config.simulation_settings")
@tag("offline_simulation")
class ChallengeExecutionTests(TransactionTestCase):
    def setUp(self):
        self.parent = Path(__file__).resolve().parents[1] / "var/tests"
        self.output = self.parent / ("challenge-execution-" + uuid.uuid4().hex)
        self.output.mkdir(parents=True)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        target = self.output.resolve()
        if not target.is_relative_to(self.parent.resolve()) or not target.name.startswith(
            "challenge-execution-"
        ):
            raise RuntimeError("Unsafe challenge fixture cleanup target.")
        shutil.rmtree(target)

    def run_matrix(self):
        case = challenge_suite.DetectionChallenge()
        case.client = Client()
        with (
            patch.dict(
                os.environ,
                {
                    "SB_SIMULATION_RUN_ID": "a" * 32,
                    "SB_SIMULATION_KEY": "synthetic-unit-test-key-not-for-real-ingestion",
                },
            ),
            patch.object(challenge_suite, "output_directory", return_value=self.output),
        ):
            case.test_predeclared_matrix()

    def test_detector_missing_every_alert_still_records_all_cases_and_coverage_failures(self):
        with patch("bridge.worker.detections", return_value=[]):
            self.run_matrix()
        report = json.loads((self.output / "result.json").read_text())
        status, _ = validate_result(report)
        self.assertEqual(report["execution_status"], "completed")
        self.assertEqual(status, "failed")
        self.assertEqual(len(report["rows"]), 19)
        self.assertEqual(report["summary"]["rule_contract"]["met"], 6)
        self.assertEqual(report["summary"]["capability_probes"]["alert_observed"], 0)

    def test_worker_failure_retains_incomplete_evidence_and_cannot_be_imported_as_passed(self):
        with patch.object(challenge_suite, "drain", side_effect=RuntimeError("synthetic failure")):
            with self.assertRaises(RuntimeError):
                self.run_matrix()
        report = json.loads((self.output / "result.json").read_text())
        self.assertEqual(report["execution_status"], "failed")
        self.assertGreater(report["requests_executed"], 0)
        with self.assertRaises(ValueError):
            validate_result(report)

    def test_historical_projection_completes_without_suppressing_real_new_rule_findings(self):
        self.run_matrix()
        report = json.loads((self.output / "result.json").read_text())
        status, _ = validate_result(report)
        self.assertEqual(status, "partial")
        self.assertEqual(len(report["rows"]), 19)
        self.assertEqual(report["summary"]["rule_contract"]["met"], 16)
        self.assertEqual(report["summary"]["capability_probes"]["alert_observed"], 0)
        # The live detector still records the wider correlation; this test only
        # projects the original contracts and makes no R3-R5 coverage claim.
        self.assertTrue(Investigation.objects.filter(rule="R5").exists())
        self.assertTrue(all(set(row["observed_rules"]) <= {"R1", "R2"} for row in report["rows"]))
