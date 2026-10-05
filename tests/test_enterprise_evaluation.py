"""New-round bounds and separation; historical declaration remains immutable."""

import copy
import hashlib
import json
from unittest.mock import patch

from django.test import SimpleTestCase

from scripts.ci_postgresql import hosted_job
from scripts.evaluate_detection import ROOT, metrics
from scripts.evaluate_enterprise_detection import DATA, declared, inputs


def corpus():
    return [
        {
            "id": f"Q{i:02d}",
            "events": [
                {
                    "app_scope": "documents",
                    "source_scope": "instrumented_lab",
                    "environment": "test",
                    "offset_seconds": i,
                }
            ],
        }
        for i in range(1, 41)
    ]


class EnterpriseEvaluationTests(SimpleTestCase):
    def test_minimum_scenarios_and_allocation_limits_are_required(self):
        self.assertEqual(len(inputs(json.dumps(corpus()).encode())), 40)
        for value in (corpus()[:39], corpus() + corpus(), {"rows": corpus()}):
            with self.subTest(shape=type(value)), self.assertRaises(ValueError):
                inputs(json.dumps(value).encode())
        with self.assertRaises(ValueError):
            inputs(b" " * (1024**2 + 1))

    def test_duplicate_ids_labels_in_wire_and_scope_escapes_fail_closed(self):
        original = corpus()
        for fields in (
            {"app_scope": "production"},
            {"source_scope": "client-asserted"},
            {"offset_seconds": True},
            {"offset_seconds": -1},
            {"offset_seconds": 172801},
            {"label": "benign"},
            {"app": "external"},
        ):
            value = copy.deepcopy(original)
            value[0]["events"][0].update(fields)
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                inputs(json.dumps(value).encode())
        original[1]["id"] = original[0]["id"]
        with self.assertRaises(ValueError):
            inputs(json.dumps(original).encode())

    def test_duplicate_request_cannot_replace_a_prior_observation(self):
        value = corpus()
        value[0]["events"].append({"repeat_of": 0})
        self.assertEqual(len(inputs(json.dumps(value).encode())), 40)
        for repeat in (
            {"repeat_of": 1},
            {"repeat_of": True},
            {"repeat_of": 0, "outcome": "allowed"},
        ):
            value[0]["events"][1] = repeat
            with self.subTest(repeat=repeat), self.assertRaises(ValueError):
                inputs(json.dumps(value).encode())

    def test_changed_frozen_implementation_is_rejected_before_any_execution(self):
        with (
            patch("scripts.evaluate_enterprise_detection.checksums", return_value={}),
            patch("scripts.evaluate_enterprise_detection.DATA") as directory,
        ):
            (directory / "freeze.json").read_text.return_value = '{"files":{"engine":"prior-hash"}}'
            with self.assertRaisesRegex(ValueError, "Frozen enterprise implementation changed"):
                declared()

    def test_retained_round_binds_source_inputs_labels_metrics_and_physical_requests(self):
        milestone = json.loads((ROOT / "docs/enterprise-milestone.json").read_text(encoding="utf8"))
        receipt = next(g["receipt"] for g in milestone["mandatory_gates"] if g["id"] == "detection")
        candidate = (ROOT / receipt).resolve()
        self.assertTrue(candidate.is_relative_to((ROOT / "docs/evidence").resolve()))
        self.assertEqual(candidate.suffix, ".json")
        report = json.loads(candidate.read_text(encoding="utf8"))
        frozen = json.loads((DATA / "freeze.json").read_text(encoding="utf8"))
        self.assertIn("integrations/wazuh_enterprise/contract.py", frozen["files"])
        self.assertIn("integrations/wazuh_enterprise/signalbridge_rules.xml", frozen["files"])
        declaration = json.loads((DATA / "declaration.json").read_text(encoding="utf8"))
        self.assertEqual(report["implementation"], frozen)
        self.assertEqual(report["declaration"], declaration)
        for filename, key in (("inputs.json", "inputs_sha256"), ("labels.json", "labels_sha256")):
            self.assertEqual(
                hashlib.sha256((DATA / filename).read_bytes()).hexdigest(), declaration[key]
            )
        self.assertEqual(report["metrics"], metrics(report["scenarios"]))
        self.assertEqual(len(report["scenarios"]), 48)
        for row in report["scenarios"]:
            self.assertEqual(row["physical_requests"], len(row["deliveries"]))
            self.assertEqual(row["logical_events"], len({d["event_id"] for d in row["deliveries"]}))
            self.assertEqual(
                row["duplicate_requests"], sum(d["http_status"] == 200 for d in row["deliveries"])
            )
        self.assertEqual(report["workload"]["initial_cases_for_review"], 24)
        self.assertEqual(report["workload"]["corrected_cases"], 1)
        self.assertEqual(report["workload"]["physical_requests"], 181)
        self.assertEqual(report["workload"]["logical_events"], 174)
        # Preserve deliberately indistinguishable benign observations and misses.
        by_id = {r["id"]: r for r in report["scenarios"]}
        self.assertEqual((by_id["Q31"]["label"], by_id["Q31"]["alerted"]), ("benign", True))
        self.assertEqual((by_id["Q41"]["label"], by_id["Q41"]["alerted"]), ("suspicious", False))

    def test_ci_provisioner_refuses_workstation_self_hosted_or_inherited_database_access(self):
        environment = {
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "SB_CI_POSTGRES_PROFILE": "signalbridge-enterprise-ci-v1",
            "GITHUB_WORKSPACE": str(ROOT),
        }
        hosted_job(environment, "linux", ROOT)
        for fields in (
            {"GITHUB_ACTIONS": "false"},
            {"RUNNER_ENVIRONMENT": "self-hosted"},
            {"GITHUB_WORKSPACE": str(ROOT.parent)},
            {"PGHOST": "external.example"},
        ):
            with self.subTest(fields=fields), self.assertRaises(RuntimeError):
                hosted_job({**environment, **fields}, "linux", ROOT)
        with self.assertRaises(RuntimeError):
            hosted_job(environment, "win32", ROOT)
