"""Evidence integrity and publication boundary tests; never invoke the full runner here."""

import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from scripts import record_verification as evidence


class VerificationEvidenceTests(TestCase):
    def setUp(self):
        self.test_root = evidence.ROOT / "var/tests"
        self.root = self.test_root / ("verification-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup_case)
        (self.root / "bridge").mkdir()
        (self.root / "bridge/app.py").write_text("value = 1\n")

    def cleanup_case(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.test_root.resolve()) or not target.name.startswith(
            "verification-"
        ):
            raise RuntimeError("Unsafe test cleanup target.")
        shutil.rmtree(target)

    def summary(self, output="Ran 12 tests in 0.321s\n\nOK\n"):
        return evidence.parse_django_summary(output)

    def tap_output(
        self,
        records=("ok 1 - first", "ok 2 - second"),
        tests=2,
        passed=2,
        failed=0,
        cancelled=0,
        skipped=0,
        todo=0,
    ):
        return "\n".join(
            [
                "TAP version 13",
                *records,
                f"1..{tests}",
                f"# tests {tests}",
                "# suites 0",
                f"# pass {passed}",
                f"# fail {failed}",
                f"# cancelled {cancelled}",
                f"# skipped {skipped}",
                f"# todo {todo}",
                "# duration_ms 1.25",
                "",
            ]
        )

    def check_record(self, name="django-tests"):
        return {
            "name": name,
            "argv": ["C:/private-user/secret-command"],
            "started_at": "2026-09-24T00:00:00+00:00",
            "finished_at": "2026-09-24T00:00:01+00:00",
            "duration_seconds": 1,
            "exit_code": 0,
            "passed": True,
            "tests": (
                evidence.parse_node_tap_summary(self.tap_output())
                if name in evidence.NODE_TEST_TARGETS
                else self.summary()
            ),
            "logs": {
                name: {"file": "private-sentinel.log", "sha256": "a" * 64}
                for name in ("stdout", "stderr")
            },
        }

    def test_only_executed_summary_counts(self):
        self.assertIsNone(self.summary("Found 99 test(s).\nSystem check identified no issues.\n"))
        actual = self.summary("Found 99 test(s).\nRan 12 tests in 0.321s\n\nOK\n")
        self.assertEqual(actual["tests_run"], 12)
        self.assertEqual(actual["skipped"], 0)
        self.assertTrue(actual["successful_summary"])

    def test_summary_reports_failures_and_skips(self):
        result = self.summary("Ran 9 tests in 1.5s\nFAILED (failures=2, errors=1, skipped=3)\n")
        self.assertEqual((result["failures"], result["errors"], result["skipped"]), (2, 1, 3))
        self.assertFalse(result["successful_summary"])

    def test_ambiguous_or_unrecognized_summaries_fail_closed(self):
        for output in (
            "Ran 3 tests in 1.0s\nOK\nRan 4 tests in 2.0s\nOK\n",
            "Ran 3 tests in 1.0s\nOK (unknown=1)\n",
            "Ran 3 tests in 1.0s\nOK (skipped=1, skipped=0)\n",
            "Ran 3 tests in 1.0s\n",
        ):
            with self.subTest(output=output):
                self.assertIsNone(self.summary(output))

    def test_tap_reconciles_executed_flat_results_with_plan_and_footer(self):
        text = self.tap_output().replace(
            "ok 1 - first", "# Subtest: first\nok 1 - first\n  ---\n  duration_ms: 0.1\n  ..."
        )
        summary = evidence.parse_node_tap_summary(text)
        self.assertEqual(summary["tests_run"], 2)
        self.assertEqual(summary["passed_tests"], 2)
        self.assertEqual(summary["suites"], 0)
        self.assertTrue(summary["successful_summary"])

    def test_tap_rejects_ambiguous_truncated_inconsistent_and_nested_output(self):
        valid = self.tap_output()
        for text in (
            "Found 2 tests\n",
            valid + valid,
            valid.replace("TAP version 13\n", ""),
            valid.replace("# tests 2\n", ""),
            valid.replace("# fail 0", "# fail unknown"),
            valid.replace("# tests 2", "# tests 3"),
            valid.replace("1..2", "1..3"),
            valid.replace("ok 2 - second", "ok 1 - second"),
            valid.replace("ok 2 - second", "ok 4 - second"),
            valid.replace("ok 2 - second", "ok wrong - second"),
            valid.replace("ok 2 - second", "not ok 2 - second"),
            valid.replace("ok 2 - second", "ok 2 - second # SKIP unavailable"),
            valid.replace("# pass 2", "# pass 1"),
            valid.replace("# suites 0", "# suites 1"),
            valid.replace("ok 2 - second", "  ok 2 - second"),
            valid.replace("ok 2 - second", "ok 2 - second\nBail out! interrupted"),
            valid.replace("ok 2 - second", "ok 2 - second\n# tests 2"),
            valid.replace("ok 2 - second", "ok 2 - second\n1..2"),
            valid.replace("# todo 0\n", ""),
            valid.replace("# duration_ms 1.25\n", ""),
        ):
            with self.subTest(text=text):
                self.assertIsNone(evidence.parse_node_tap_summary(text))

    def test_tap_preserves_failed_skipped_todo_and_cancelled_counts(self):
        for keyword, directive, field in (
            ("failed", "not ok 2 - second", "failures"),
            ("cancelled", "not ok 2 - second", "cancelled"),
            ("skipped", "ok 2 - second # SKIP unavailable", "skipped"),
            ("todo", "not ok 2 - second # TODO pending", "todo"),
        ):
            with self.subTest(outcome=keyword):
                text = self.tap_output(
                    records=("ok 1 - first", directive), passed=1, **{keyword: 1}
                )
                summary = evidence.parse_node_tap_summary(text)
                self.assertEqual(summary["tests_run"], 2)
                self.assertEqual(summary[field], 1)
                self.assertEqual(summary["passed_tests"], 1)
                self.assertFalse(summary["successful_summary"])

    def test_manifest_hashes_actual_uncommitted_content_and_new_files(self):
        before = evidence.source_manifest(self.root)
        (self.root / "bridge/app.py").write_text("value = 2\n")
        changed = evidence.source_manifest(self.root)
        self.assertNotEqual(before["sha256"], changed["sha256"])
        (self.root / "scripts").mkdir()
        (self.root / "scripts/local.ps1").write_text("Write-Output 'local'\n")
        after = evidence.source_manifest(self.root)
        self.assertEqual(after["file_count"], 2)
        self.assertIn("scripts/local.ps1", after["files"])

    def test_manifest_excludes_private_state_and_documentation(self):
        before = evidence.source_manifest(self.root)
        for name in (
            ".env",
            "var/secret.json",
            "private-source/secret.py",
            "artifacts/local/raw.json",
            "docs/STATUS.md",
            "bridge/.env.local",
            "bridge/__pycache__/app.pyc",
            "bridge/README.md",
        ):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("private sentinel")
        self.assertEqual(before, evidence.source_manifest(self.root))

    def test_source_link_rejected_before_reading(self):
        path = self.root / "bridge/app.py"
        original = Path.is_symlink
        with patch.object(
            Path, "is_symlink", lambda candidate: candidate == path or original(candidate)
        ):
            with self.assertRaisesRegex(ValueError, "links"):
                evidence.source_manifest(self.root)

    def test_child_environment_cannot_inherit_external_database(self):
        with patch.dict(os.environ, {"SB_DB_HOST": "remote.invalid", "SB_DB_PASSWORD": "secret"}):
            env = evidence.child_environment()
        self.assertNotIn("SB_DB_HOST", env)
        self.assertNotIn("SB_DB_PASSWORD", env)
        self.assertEqual(env["SB_MODE"], "local")

    def test_child_environment_drops_node_preloads_and_external_output_paths(self):
        names = ("NODE_OPTIONS", "NODE_PATH", "NODE_V8_COVERAGE")
        with patch.dict(os.environ, dict.fromkeys(names, "private outside path")):
            env = evidence.child_environment()
        for name in names:
            self.assertNotIn(name, env)

    def execute_fake_check(self, text, exit_code=0, name="django-tests", stream=None):
        self.check_output = self.root / ("check-" + uuid.uuid4().hex)
        self.check_output.mkdir()
        stream = stream or ("stdout" if name in evidence.NODE_TEST_TARGETS else "stderr")

        def fake_run(*args, **kwargs):
            kwargs[stream].write(text.encode())
            return subprocess.CompletedProcess(args[0], exit_code)

        with patch.object(evidence.subprocess, "run", side_effect=fake_run) as run:
            result = evidence.run_check(
                name, ["fixed-executable"], 5, self.root, self.check_output, {}
            )
        self.assertFalse(run.call_args.kwargs["shell"])
        return result

    def test_log_hashes_match_exact_saved_bytes(self):
        result = self.execute_fake_check("Found 90 test(s).\nRan 12 tests in 0.3s\nOK\n")
        self.assertTrue(result["passed"])
        self.assertEqual(result["tests"]["tests_run"], 12)
        for stream in ("stdout", "stderr"):
            log = result["logs"][stream]
            self.assertEqual(
                log["sha256"], evidence.sha256((self.check_output / log["file"]).read_bytes())
            )

    def test_zero_tests_are_not_a_pass_even_with_success_exit(self):
        self.assertFalse(self.execute_fake_check("Ran 0 tests in 0.0s\nOK\n")["passed"])

    def test_skipped_required_tests_are_not_a_pass(self):
        self.assertFalse(
            self.execute_fake_check("Ran 12 tests in 0.3s\nOK (skipped=1)\n")["passed"]
        )

    def test_success_text_cannot_override_failed_process(self):
        self.assertFalse(self.execute_fake_check("Ran 12 tests in 0.3s\nOK\n", 1)["passed"])

    def test_all_node_suites_require_executed_tap_and_zero_exit(self):
        for name in evidence.NODE_TEST_TARGETS:
            with self.subTest(name=name):
                result = self.execute_fake_check(self.tap_output(), name=name)
                self.assertTrue(result["passed"])
                self.assertEqual(result["tests"]["tests_run"], 2)
                for stream in ("stdout", "stderr"):
                    log = result["logs"][stream]
                    self.assertEqual(
                        log["sha256"],
                        evidence.sha256((self.check_output / log["file"]).read_bytes()),
                    )
                for code in (1, 2, -9):
                    self.assertFalse(
                        self.execute_fake_check(self.tap_output(), code, name=name)["passed"]
                    )

    def test_node_missing_or_stderr_only_tap_cannot_pass(self):
        for name in evidence.NODE_TEST_TARGETS:
            with self.subTest(name=name):
                self.assertFalse(self.execute_fake_check("", name=name)["passed"])
                self.assertFalse(
                    self.execute_fake_check(self.tap_output(), name=name, stream="stderr")["passed"]
                )

    def test_node_zero_skipped_todo_cancelled_or_failed_tests_cannot_pass(self):
        for text in (
            self.tap_output(records=(), tests=0, passed=0),
            self.tap_output(records=("ok 1 - first", "ok 2 - second # SKIP"), passed=1, skipped=1),
            self.tap_output(records=("ok 1 - first", "ok 2 - second # TODO"), passed=1, todo=1),
            self.tap_output(records=("ok 1 - first", "not ok 2 - second"), passed=1, cancelled=1),
            self.tap_output(records=("ok 1 - first", "not ok 2 - second"), passed=1, failed=1),
        ):
            for name in evidence.NODE_TEST_TARGETS:
                with self.subTest(name=name, text=text):
                    result = self.execute_fake_check(text, name=name)
                    self.assertIsNotNone(result["tests"])
                    self.assertFalse(result["passed"])

    def test_timeout_is_recorded_without_inventing_an_exit_code(self):
        with patch.object(
            evidence.subprocess, "run", side_effect=subprocess.TimeoutExpired("fixed", 5)
        ):
            result = evidence.run_check("ruff-check", ["fixed-ruff"], 5, self.root, self.root, {})
        self.assertFalse(result["passed"])
        self.assertIsNone(result["exit_code"])
        self.assertEqual(result["error"], "timeout")
        self.assertTrue((self.root / result["logs"]["stderr"]["file"]).exists())

    def test_source_change_during_run_invalidates_all_passed_checks(self):
        before = evidence.source_manifest(self.root)
        after = {**before, "sha256": "b" * 64}

        def fake_check(name, *_):
            return self.check_record(name)

        with (
            patch.object(evidence, "git_state", return_value={"head": "a" * 40, "dirty": True}),
            patch.object(evidence, "source_manifest", side_effect=[before, after]),
            patch.object(evidence, "capture_small", return_value="installed-version"),
            patch.object(evidence, "run_check", side_effect=fake_check),
        ):
            report, output = evidence.run_verification(self.root)
        self.assertFalse(report["passed"])
        self.assertFalse(report["source_unchanged"])
        self.assertEqual(len(report["checks"]), 9)
        self.assertEqual(json.loads((output / "report.json").read_text())["passed"], False)

    def test_node_version_is_recorded_and_required_even_when_checks_pass(self):
        def version(command, *_):
            if command == ["node", "--version"]:
                return "v24.14.1"
            return "installed-version"

        with (
            patch.object(evidence, "git_state", return_value={"head": "a" * 40, "dirty": True}),
            patch.object(evidence, "capture_small", side_effect=version),
            patch.object(
                evidence, "run_check", side_effect=lambda name, *_: self.check_record(name)
            ),
        ):
            report, output = evidence.run_verification(self.root)
        self.assertTrue(report["passed"])
        self.assertEqual(report["tool_versions"]["node"], "v24.14.1")
        self.assertEqual(
            json.loads((output / "report.json").read_text())["tool_versions"],
            report["tool_versions"],
        )

        def missing_node(command, *_):
            if command == ["node", "--version"]:
                raise OSError("not installed")
            return "installed-version"

        with (
            patch.object(evidence, "git_state", return_value={"head": "a" * 40, "dirty": True}),
            patch.object(evidence, "capture_small", side_effect=missing_node),
            patch.object(
                evidence, "run_check", side_effect=lambda name, *_: self.check_record(name)
            ),
        ):
            report, _ = evidence.run_verification(self.root)
        self.assertIsNone(report["tool_versions"]["node"])
        self.assertFalse(report["passed"])

    def test_public_receipt_allowlist_removes_private_fields(self):
        report = {
            "run_id": "run-1",
            "started_at": "2026-09-24T00:00:00+00:00",
            "finished_at": "2026-09-24T00:00:01+00:00",
            "duration_seconds": 1,
            "git_before": {"head": "a" * 40, "dirty": True, "status": "private sentinel"},
            "source_before": {"sha256": "b" * 64, "file_count": 1, "files": {"private": "secret"}},
            "source_unchanged": True,
            "passed": True,
            "checks": [
                self.check_record(),
                *(self.check_record(name) for name in evidence.NODE_TEST_TARGETS),
            ],
            "private": "private sentinel",
        }
        for check in report["checks"]:
            check["tests"]["secret"] = "private sentinel"
        receipt = evidence.public_receipt(report)
        serialized = json.dumps(receipt)
        for forbidden in (
            "private sentinel",
            "secret-command",
            "private-sentinel.log",
            '"files"',
            '"argv"',
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(receipt["checks"][0]["tests"]["tests_run"], 12)
        self.assertEqual(receipt["checks"][0]["log_sha256"]["stdout"], "a" * 64)
        for check in receipt["checks"][1:]:
            self.assertEqual(check["tests"]["passed_tests"], 2)
            self.assertEqual(check["tests"]["skipped"], 0)
        self.assertEqual(
            {check["name"] for check in receipt["checks"][1:]}, set(evidence.NODE_TEST_TARGETS)
        )
        self.assertIn("mocks", " ".join(receipt["coverage_limits"]))
        self.assertIn("BetTail route", " ".join(receipt["coverage_limits"]))

    def test_receipt_cannot_escape_or_overwrite(self):
        run_id = "run-1"
        path = evidence.receipt_path(self.root, "docs/evidence/run-1.json", run_id)
        path.parent.mkdir(parents=True)
        path.write_text("existing")
        for target in (path, "docs/evidence/../../outside.json", "var/run-1.json"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    evidence.receipt_path(self.root, target, run_id)

    def test_fixed_checks_do_not_accept_commands_or_contact_other_projects(self):
        checks = evidence.fixed_checks(self.root)
        self.assertEqual(len(checks), 9)
        self.assertEqual(
            {name for name, _, _ in checks},
            {
                "django-tests",
                "django-check",
                "migration-drift",
                "ruff-check",
                "ruff-format",
                "publication-scan",
                "node-courier-tests",
                "node-http-harness-mock-tests",
                "node-bettail-route-mock-tests",
            },
        )
        self.assertEqual(
            evidence.NODE_TEST_TARGETS,
            {
                "node-courier-tests": "integrations/sender.test.mjs",
                "node-http-harness-mock-tests": "integrations/supabase-http.test.mjs",
                "node-bettail-route-mock-tests": "integrations/bettail-routes.test.mjs",
            },
        )
        self.assertEqual(checks[0][1][1:], ["manage.py", "test", "tests", "--verbosity", "1"])
        for name, command, timeout in checks:
            if name in evidence.NODE_TEST_TARGETS:
                self.assertEqual(
                    command,
                    [
                        "node",
                        "--test",
                        "--test-isolation=none",
                        "--test-reporter=tap",
                        evidence.NODE_TEST_TARGETS[name],
                    ],
                )
                self.assertEqual(timeout, 60)
                self.assertTrue(command[-1].endswith(".test.mjs"))
            else:
                self.assertTrue(Path(command[0]).is_relative_to(self.root / ".venv"))
            self.assertNotIn("install", command)
            self.assertNotIn("--linked", command)
