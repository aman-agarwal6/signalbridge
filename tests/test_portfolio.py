"""Public portfolio boundaries; synthetic receipts in a disposable repository only."""

import copy
import importlib.util
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from scripts import portfolio as p
from scripts.portfolio_integrations import RECEIPTS


class PortfolioTests(TestCase):
    def copy_integration_receipts(self):
        for name in RECEIPTS:
            shutil.copyfile(p.ROOT / "docs/evidence" / name, self.root / "docs/evidence" / name)

    def test_integration_viewer_reconciles_real_records_and_keeps_failed_scan_incomplete(self):
        self.copy_integration_receipts()
        metrics = self.build()
        evidence = metrics["integrations"]
        self.assertEqual(len(evidence["wazuh"]["records"]), 64)
        self.assertEqual(sum(bool(row["rule_id"]) for row in evidence["wazuh"]["records"]), 31)
        failed = next(run for run in evidence["zap"]["runs"] if run["failed"])
        self.assertEqual(failed["coverage"], "incomplete")
        self.assertEqual(failed["accepted"], 0)
        html = (self.root / "portfolio/index.html").read_text(encoding="utf8")
        for row in evidence["wazuh"]["records"]:
            self.assertIn(row["event_id"], html)
        self.assertIn("not a benign verdict", html)
        self.assertIn("AI assistance", html)
        self.assertNotIn("<script", html)
        self.assertNotIn("Choose an investigation", html)

    def test_missing_native_evidence_does_not_infer_execution_from_core_tests(self):
        self.assertIsNone(self.build()["integrations"])
        html = (self.root / "portfolio/index.html").read_text(encoding="utf8")
        self.assertIn("Integration evidence is not included", html)
        self.assertNotIn('id="wazuh-run"', html)

    def test_partial_or_modified_integration_snapshot_cannot_be_exported(self):
        self.copy_integration_receipts()
        name = next(iter(RECEIPTS))
        path = self.root / "docs/evidence" / name
        original = json.loads(path.read_text())
        for change in ("count", "unreviewed_text", "missing"):
            with self.subTest(change=change):
                modified = copy.deepcopy(original)
                if change == "count":
                    modified["counts"]["received"] += 1
                elif change == "unreviewed_text":
                    modified["unreviewed"] = "Private data must not reach an export"
                if change == "missing":
                    path.unlink()
                else:
                    self.write(name, modified)
                self.assert_rejected()
                self.write(name, original)

    def test_reviewed_json_survives_line_ending_conversion_with_accurate_byte_identity(self):
        import hashlib

        self.copy_integration_receipts()
        for name in RECEIPTS:
            path = self.root / "docs/evidence" / name
            parsed = json.loads(path.read_text())
            path.write_bytes(json.dumps(parsed, indent=2).replace("\n", "\r\n").encode("utf8"))
        evidence = self.build()["integrations"]
        for identity in evidence["receipts"]:
            raw = (self.root / "docs/evidence" / identity["receipt"]).read_bytes()
            self.assertEqual(identity["receipt_sha256"], hashlib.sha256(raw).hexdigest())

    def challenge(self):
        from tests.test_detection_challenge import synthetic_result

        report = copy.deepcopy(self.baseline)
        report.update(
            kind="signalbridge-detection-challenge-receipt",
            source_sha256=self.current["sha256"],
            source_file_count=self.current["file_count"],
            results=synthetic_result(),
        )
        return report

    def test_challenge_keeps_unmet_capabilities_visible_and_separate(self):
        self.write("challenge.json", self.challenge())
        metrics = p.build(root=self.root, now=self.now, challenge_receipt="challenge.json")
        self.assertEqual(metrics["detection_challenge"]["status"], "partial")
        self.assertIsNone(metrics["current_simulation"])
        html = (self.root / "portfolio/index.html").read_text(encoding="utf8")
        self.assertIn("Slow enumeration", html)
        self.assertIn("Missing revocation context", html)
        self.assertIn("Unmet", html)
        self.assertNotIn("<script", html)

    def test_challenge_missing_stale_changed_and_falsely_green_receipts_are_rejected(self):
        with self.assertRaises(p.PortfolioError):
            p.build(root=self.root, now=self.now, challenge_receipt="missing.json")
        for change in ("source", "summary", "declaration"):
            report = self.challenge()
            if change == "source":
                report["source_sha256"] = "a" * 64
            elif change == "summary":
                report["results"]["summary"]["capability_probes"]["alert_observed"] = 3
            else:
                report["results"]["declaration_sha256"] = "a" * 64
            self.write("challenge.json", report)
            with self.subTest(change=change), self.assertRaises(p.PortfolioError):
                p.build(root=self.root, now=self.now, challenge_receipt="challenge.json")
        self.assertFalse((self.root / "portfolio").exists())

    def setUp(self):
        self.parent = p.ROOT / "var/tests"
        self.root = self.parent / ("portfolio-" + uuid.uuid4().hex)
        (self.root / "docs/evidence").mkdir(parents=True)
        (self.root / "templates").mkdir()
        shutil.copyfile(p.ROOT / "templates/portfolio.html", self.root / "templates/portfolio.html")
        (self.root / "static").mkdir()
        shutil.copyfile(p.ROOT / "static/portfolio.css", self.root / "static/portfolio.css")
        self.addCleanup(self.cleanup)
        self.now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        # These copies are private test input, never purported new execution evidence.
        self.core = json.loads(
            (p.ROOT / "docs/evidence/20260924T044031191965Z-e1700389.json").read_text()
        )
        # Extend only this in-memory synthetic fixture for the current nine-group
        # contract. Retained historical receipts are never edited or reinterpreted.
        route_check = copy.deepcopy(self.core["checks"][-1])
        route_check.update(name="node-bettail-route-mock-tests", duration_seconds=0.01)
        route_check["tests"].update(tests_run=2, passed_tests=2)
        self.core["checks"].append(route_check)
        self.core["coverage_limits"] = list(p.LIMITS)
        self.baseline = json.loads((p.ROOT / "docs/evidence" / p.BASELINE).read_text())
        self.current = p.source_manifest(self.root)
        self.core["source_sha256"] = self.current["sha256"]
        self.core["source_file_count"] = self.current["file_count"]
        self.core_name = self.core["run_id"] + ".json"
        self.write(self.core_name, self.core)

    def cleanup(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.parent.resolve()) or not target.name.startswith(
            "portfolio-"
        ):
            raise RuntimeError("Unsafe portfolio test cleanup.")
        shutil.rmtree(target)

    def write(self, filename, value):
        (self.root / "docs/evidence" / filename).write_text(json.dumps(value), encoding="utf8")

    def build(self):
        return p.build(root=self.root, now=self.now)

    def assert_rejected(self):
        with self.assertRaises(p.PortfolioError):
            self.build()
        self.assertFalse((self.root / "portfolio").exists())

    def rolling(self):
        report = copy.deepcopy(self.baseline)
        report["run_id"] = "b" * 32
        report["source_sha256"] = self.current["sha256"]
        report["source_file_count"] = self.current["file_count"]
        result = report["results"]
        result["started_at"] = "2026-09-25T04:40:05.353490+00:00"
        result["finished_at"] = "2026-09-25T04:40:07.878200+00:00"
        result["execution_status"] = "completed"
        row = next(row for row in result["scenarios"] if row["id"] == "bucket_boundary_gap")
        row.update(observed_rules=["R1"], known_limitation=False, coverage_met=True)
        result["detection_quality"].update(
            true_positive_scenarios=5, false_negative_scenarios=0, recall=1.0
        )
        return report

    def test_import_does_not_setup_django_open_private_state_or_run_cli(self):
        spec = importlib.util.spec_from_file_location("portfolio_import_audit", p.__file__)
        module = importlib.util.module_from_spec(spec)
        with (
            patch("django.setup", side_effect=AssertionError("application setup")),
            patch("argparse.ArgumentParser.parse_args", side_effect=AssertionError("CLI parsed")),
            patch.object(Path, "read_text", side_effect=AssertionError("file read on import")),
        ):
            spec.loader.exec_module(module)
        self.assertTrue(callable(module.build))

    def test_receipt_reconstruction_and_rendering_do_not_write_or_initialize_application(self):
        with patch("django.setup", side_effect=AssertionError("application setup")):
            metrics = p.reconstruct_metrics(self.root, self.current, self.now)
            rendered = p.render_portfolio(self.root, metrics)
        self.assertIn("SignalBridge", rendered)
        self.assertFalse((self.root / "portfolio").exists())
        self.assertFalse((self.root / "var").exists())
        self.assertFalse((self.root / "artifacts").exists())

    def test_core_only_build_is_standalone_and_has_separate_generation_date(self):
        with patch("django.setup", side_effect=AssertionError("application setup")):
            metrics = self.build()
        self.assertEqual(metrics["generated_at"], self.now.isoformat())
        self.assertEqual(metrics["core"]["finished_at"], self.core["finished_at"])
        self.assertNotEqual(metrics["generated_at"], metrics["core"]["finished_at"])
        self.assertIsNone(metrics["current_simulation"])
        html = (self.root / "portfolio/index.html").read_text(encoding="utf8")
        self.assertIn("Not recorded", html)
        self.assertNotIn("<script", html)
        self.assertNotIn("artifacts/local", html)
        self.assertIn("default-src 'none'", html)
        self.assertFalse((self.root / "var").exists())
        self.assertFalse((self.root / "artifacts").exists())

    def test_new_route_mock_group_is_required_and_kept_separate_from_real_service_evidence(self):
        metrics = self.build()
        names = {check["name"] for check in metrics["core"]["checks"]}
        self.assertEqual(len(names), 9)
        self.assertIn("node-bettail-route-mock-tests", names)
        self.assertIn(
            "BetTail route suites use mocks", " ".join(metrics["core"]["coverage_limits"])
        )
        self.assertIn("No real Supabase auth", " ".join(metrics["core"]["coverage_limits"]))

    def test_eight_group_receipt_or_real_route_result_cannot_replace_new_mock_group(self):
        missing = copy.deepcopy(self.core)
        missing["checks"] = [
            check for check in missing["checks"] if check["name"] != "node-bettail-route-mock-tests"
        ]
        real_result = copy.deepcopy(self.core)
        real_result["checks"][-1]["name"] = "bettail-route-live-execution"
        for report in (missing, real_result):
            with self.subTest(groups=[check["name"] for check in report["checks"]]):
                self.write(self.core_name, report)
                self.assert_rejected()

    def test_historical_baseline_is_not_current_or_claimed_as_improvement(self):
        self.write(p.BASELINE, self.baseline)
        metrics = self.build()
        self.assertFalse(metrics["same_declared_scenarios"])
        self.assertFalse(metrics["historical_baseline"]["matches_current_source"])
        self.assertEqual(metrics["historical_baseline"]["results"]["coverage"]["met"], 14)
        html = (self.root / "portfolio/index.html").read_text(encoding="utf8")
        self.assertIn("Historical baseline only", html)
        self.assertNotIn("A boundary case was missed.</h3>", html)

    def test_comparison_reconciles_same_scenarios_and_preserves_source_dates(self):
        self.write(p.BASELINE, self.baseline)
        self.write(p.CURRENT, self.rolling())
        metrics = self.build()
        self.assertTrue(metrics["same_declared_scenarios"])
        self.assertEqual(metrics["current_simulation"]["results"]["coverage"]["met"], 15)
        self.assertNotEqual(
            metrics["historical_baseline"]["source_sha256"],
            metrics["current_simulation"]["source_sha256"],
        )
        self.assertEqual(
            metrics["historical_baseline"]["results"]["detection_quality"]["recall"], 0.8
        )
        self.assertEqual(
            metrics["current_simulation"]["results"]["detection_quality"]["recall"], 1.0
        )

    def test_stale_source_and_wrong_count_are_rejected(self):
        for key, value in (
            ("source_sha256", "a" * 64),
            ("source_file_count", 42),
            ("source_unchanged", False),
        ):
            with self.subTest(key=key):
                bad = {**self.core, key: value}
                self.write(self.core_name, bad)
                self.assert_rejected()

    def test_failed_skipped_missing_and_duplicate_checks_are_not_success(self):
        variants = []
        bad = copy.deepcopy(self.core)
        bad["passed"] = False
        variants.append(bad)
        bad = copy.deepcopy(self.core)
        bad["checks"][0]["tests"]["skipped"] = 1
        variants.append(bad)
        bad = copy.deepcopy(self.core)
        bad["checks"][0]["tests"]["tests_run"] = 0
        variants.append(bad)
        bad = copy.deepcopy(self.core)
        bad["checks"].pop()
        variants.append(bad)
        bad = copy.deepcopy(self.core)
        bad["checks"][-1] = copy.deepcopy(bad["checks"][0])
        variants.append(bad)
        bad = copy.deepcopy(self.core)
        bad["checks"][-1]["tests"]["passed_tests"] -= 1
        variants.append(bad)
        for index, bad in enumerate(variants):
            with self.subTest(index=index):
                self.write(self.core_name, bad)
                self.assert_rejected()

    def test_newest_matching_failure_cannot_fall_back_to_older_success(self):
        newer = copy.deepcopy(self.core)
        newer.update(run_id="20260925T044031191965Z-aaaaaaaa", passed=False)
        self.write(newer["run_id"] + ".json", newer)
        self.assert_rejected()

    def test_malformed_check_container_and_boolean_numbers_fail_closed(self):
        for field, value in (("log_sha256", ["stdout", "stderr"]), ("exit_code", False)):
            with self.subTest(field=field):
                bad = copy.deepcopy(self.core)
                bad["checks"][0][field] = value
                self.write(self.core_name, bad)
                self.assert_rejected()

    def test_future_and_naive_core_dates_are_rejected(self):
        for value in ("2035-01-01T00:00:00+00:00", "2026-09-24T04:40:50.575389"):
            with self.subTest(value=value):
                bad = copy.deepcopy(self.core)
                bad["finished_at"] = value
                self.write(self.core_name, bad)
                self.assert_rejected()

    def test_unsupported_fields_and_arbitrary_text_do_not_enter_public_artifact(self):
        bad = {**self.core, "private_token": "private-sentinel"}
        self.write(self.core_name, bad)
        with self.assertRaises(p.PortfolioError) as error:
            self.build()
        self.assertNotIn("private-sentinel", str(error.exception))
        bad = copy.deepcopy(self.core)
        bad["coverage_limits"] = ["<script>private-sentinel</script>"]
        self.write(self.core_name, bad)
        self.assert_rejected()

    def test_duplicate_nonfinite_and_overdeep_json_rejected(self):
        path = self.root / "docs/evidence" / self.core_name
        for payload in (
            '{"kind":1,"kind":2}',
            '{"value":NaN}',
            '{"value":' + "[" * 26 + "0" + "]" * 26 + "}",
        ):
            with self.subTest(payload=payload[:30]):
                path.write_text(payload, encoding="utf8")
                with self.assertRaises(p.PortfolioError):
                    p.read_public(self.root, self.core_name)

    def test_oversized_receipt_rejected(self):
        (self.root / "docs/evidence" / self.core_name).write_bytes(b" " * (p.MAX_BYTES + 1))
        self.assert_rejected()

    def test_source_changes_during_render_do_not_write_artifact(self):
        changed = {**self.current, "sha256": "f" * 64}
        with patch.object(p, "source_manifest", side_effect=[self.current, changed]):
            self.assert_rejected()

    def test_receipt_changes_during_render_do_not_write_artifact(self):
        original = p.read_public
        calls = 0

        def changed(root, name):
            nonlocal calls
            calls += 1
            value, digest = original(root, name)
            return value, ("f" * 64 if calls == 2 else digest)

        with patch.object(p, "read_public", side_effect=changed):
            self.assert_rejected()

    def test_current_simulation_must_match_source(self):
        self.write(p.CURRENT, self.baseline)
        self.assert_rejected()

    def test_explicit_core_only_omits_even_stale_simulation_without_claiming_results(self):
        self.write(p.CURRENT, self.baseline)
        metrics = p.build(self.root, now=self.now, core_only=True)
        self.assertIsNone(metrics["current_simulation"])
        self.assertIsNone(metrics["historical_baseline"])
        self.assertFalse(metrics["same_declared_scenarios"])

    def test_simulation_changed_scenario_inflated_metrics_and_reused_run_rejected(self):
        self.write(p.BASELINE, self.baseline)
        for variant in ("scenario", "metrics", "identity", "future", "failure"):
            with self.subTest(variant=variant):
                current = self.rolling()
                if variant == "scenario":
                    current["results"]["scenarios"][0]["expected_rule"] = "R1"
                elif variant == "metrics":
                    current["results"]["detection_quality"]["true_positive_scenarios"] = 6
                elif variant == "identity":
                    current["run_id"] = self.baseline["run_id"]
                elif variant == "future":
                    current["results"]["finished_at"] = "2035-01-01T00:00:00+00:00"
                else:
                    current["exit_code"] = 1
                self.write(p.CURRENT, current)
                self.assert_rejected()

    def test_safe_canonical_simulation_descriptions_omit_uncontrolled_text(self):
        current = self.rolling()
        current["limits"] = ["private-sentinel"]
        current["results"]["bounded_load"]["limits"] = "private-sentinel"
        current["results"]["not_tested"] = ["private-sentinel"]
        current["results"]["detection_quality"]["denominator"] = "private-sentinel"
        self.write(p.CURRENT, current)
        metrics = self.build()
        self.assertNotIn("private-sentinel", json.dumps(metrics))
        self.assertNotIn(
            "private-sentinel", (self.root / "portfolio/index.html").read_text(encoding="utf8")
        )

    def test_explicit_receipt_cannot_traverse_or_use_other_directory(self):
        for name in ("../secret.json", "C:\\private.json", ".env", "sub/report.json"):
            with self.subTest(name=name):
                with self.assertRaises(p.PortfolioError):
                    p.build(self.root, core_receipt=name, now=self.now)

    def test_linked_output_refused_before_existing_file_is_replaced(self):
        output = self.root / "portfolio"
        output.mkdir()
        target = output / "index.html"
        target.write_text("preserve-existing", encoding="utf8")
        original = Path.lstat

        class Linked:
            st_mode = 0
            st_file_attributes = 1024

        def fake_lstat(path, *args, **kwargs):
            return Linked() if path == target else original(path, *args, **kwargs)

        with patch.object(Path, "lstat", fake_lstat):
            with self.assertRaises(p.PortfolioError):
                self.build()
        self.assertEqual(target.read_text(encoding="utf8"), "preserve-existing")
