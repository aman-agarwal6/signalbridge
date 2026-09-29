"""Exercise the fixed Ruff command with synthetic sources and mocked child processes.

Imports use Django's disposable test database. No scanner or service is executed.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import uuid
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from bridge.findings import import_scan
from bridge.management.commands import scan_local
from bridge.models import Audit, Finding, FindingObservation, Integration, Membership, ScanRun
from bridge.scanner_guidance import guidance

REVISION = "a" * 40


class LocalScannerCommandTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="signalbridge", name="Self", enabled=False)
        cls.users = {}
        for role in ("viewer", "analyst", "reviewer"):
            user = get_user_model().objects.create_user(username="local-scan-" + role)
            Membership.objects.create(user=user, integration=cls.app, role=role)
            cls.users[role] = user
        cls.outsider = get_user_model().objects.create_user(username="local-scan-outsider")

    def setUp(self):
        self.test_base = Path(settings.BASE_DIR).resolve() / "var" / "tests"
        self.root = self.test_base / ("local-scanner-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True, exist_ok=False)
        self.addCleanup(self.cleanup)
        self.source = self.root / "bridge" / "sample.py"
        self.source.parent.mkdir()
        self.source.write_text("# synthetic scanner input\n", encoding="utf-8")
        (self.root / "manage.py").write_text("# synthetic entry point\n", encoding="utf-8")
        excluded = self.root / "var" / "excluded.py"
        excluded.parent.mkdir()
        excluded.write_text("# outside fixed scan scope\n", encoding="utf-8")
        self.interpreter = (
            self.root
            / ".venv"
            / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        )
        self.scanner = self.interpreter.with_name("ruff.exe" if sys.platform == "win32" else "ruff")
        self.scanner.parent.mkdir(parents=True)
        self.scanner.write_bytes(b"synthetic executable placeholder; never run")
        settings_override = override_settings(BASE_DIR=self.root, LOCAL=True)
        settings_override.enable()
        self.addCleanup(settings_override.disable)
        self.mock(scan_local.sys, "executable", new=str(self.interpreter))
        self.git = self.mock(scan_local.shutil, "which", return_value="fixed-git")
        self.revision = self.mock(scan_local.subprocess, "check_output", return_value=REVISION)
        self.process = self.mock(scan_local.subprocess, "run", return_value=self.result())
        self.importer = self.mock(scan_local, "import_scan", wraps=import_scan)

    def cleanup(self):
        target = self.root.resolve()
        if target.parent != self.test_base.resolve() or not target.name.startswith(
            "local-scanner-"
        ):
            raise RuntimeError("Synthetic test cleanup escaped its intended directory.")
        shutil.rmtree(target)

    def mock(self, target, name, **options):
        patcher = patch.object(target, name, **options)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def document(self, *, findings=True, uri=None):
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Ruff", "version": "0.16.8"}},
                    "originalUriBaseIds": {"ROOT": {"uri": self.root.as_uri()}},
                    "artifacts": [{"location": {"uri": self.source.as_uri()}}],
                    "results": [
                        {
                            "ruleId": "S603",
                            "message": {"text": "private-scanner-message-sentinel"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri or self.source.as_uri()},
                                        "region": {
                                            "startLine": 1,
                                            "snippet": {"text": "private-code-sentinel"},
                                        },
                                    }
                                }
                            ],
                        }
                    ]
                    if findings
                    else [],
                }
            ],
        }

    def result(self, *, document=None, raw=None, code=1):
        return SimpleNamespace(
            returncode=code,
            stdout=raw if raw is not None else json.dumps(document or self.document()).encode(),
            stderr=b"private-tool-stderr-sentinel",
        )

    def scan(self, user=None):
        output = StringIO()
        call_command("scan_local", user=(user or self.users["analyst"]).username, stdout=output)
        return output.getvalue()

    def assert_no_evidence(self):
        self.assertEqual(ScanRun.objects.count(), 0)
        self.assertEqual(Finding.objects.count(), 0)
        self.assertEqual(FindingObservation.objects.count(), 0)
        self.assertEqual(Audit.objects.filter(action="scan.imported").count(), 0)

    def test_fixed_argv_and_real_import_preserve_exact_source_and_report_provenance(self):
        before = scan_local.source_manifest(self.root)
        raw = self.process.return_value.stdout
        output = self.scan()
        command = self.process.call_args.args[0]
        self.assertEqual(
            command,
            [
                str(self.scanner),
                "check",
                "--isolated",
                "--select",
                "S",
                "--no-cache",
                "--output-format",
                "sarif",
                *before,
            ],
        )
        options = self.process.call_args.kwargs
        self.assertFalse(options.get("shell", False))
        self.assertEqual(options["cwd"], self.root)
        self.assertEqual(options["timeout"], 60)
        self.assertTrue(options["capture_output"])
        self.assertFalse(options["check"])
        self.assertEqual(before, scan_local.source_manifest(self.root))
        self.assertEqual(set(before), {"bridge/sample.py", "manage.py"})
        run = ScanRun.objects.get()
        self.assertEqual(run.source_revision, REVISION)
        self.assertEqual(run.manifest, before)
        self.assertEqual(run.provenance, "local_execution")
        self.assertEqual(run.execution["original_digest"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(run.execution["returncode"], 1)
        normalized = self.importer.call_args.args[2]
        self.assertEqual(run.digest, hashlib.sha256(normalized).hexdigest())
        self.assertNotIn(self.root.as_uri(), normalized.decode())
        self.assertEqual(run.coverage_status, "unknown")
        self.assertEqual(run.finding_count, 1)
        self.assertEqual(Finding.objects.get().path, "bridge/sample.py")
        observation = FindingObservation.objects.get()
        saved_metadata = json.dumps(observation.snapshot)
        for sentinel in ("private-scanner-message-sentinel", "private-code-sentinel"):
            self.assertNotIn(sentinel, saved_metadata)
            self.assertNotIn(sentinel, output)
        self.assertIn(str(run.pk), output)

    def test_reviewer_can_run_and_empty_report_is_not_complete_coverage(self):
        self.process.return_value = self.result(document=self.document(findings=False), code=0)
        self.scan(self.users["reviewer"])
        run = ScanRun.objects.get()
        self.assertEqual(run.imported_by, self.users["reviewer"])
        self.assertEqual(run.finding_count, 0)
        self.assertEqual(run.coverage_status, "unknown")
        self.assertEqual(run.execution["returncode"], 0)

    def test_viewer_outsider_inactive_and_unknown_operator_never_start_a_process(self):
        inactive = self.users["analyst"]
        inactive.is_active = False
        inactive.save(update_fields=["is_active"])
        for user in (
            self.users["viewer"],
            self.outsider,
            inactive,
            SimpleNamespace(username="missing-local-scan-user"),
        ):
            with self.subTest(user=user.username), self.assertRaises(CommandError):
                self.scan(user)
        self.git.assert_not_called()
        self.revision.assert_not_called()
        self.process.assert_not_called()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_nonlocal_mode_and_enabled_or_missing_scanner_workspace_refuse_execution(self):
        with override_settings(LOCAL=False), self.assertRaises(CommandError):
            self.scan()
        Integration.objects.filter(pk=self.app.pk).update(enabled=True)
        with self.assertRaises(CommandError):
            self.scan()
        Integration.objects.filter(pk=self.app.pk).update(slug="different-workspace")
        with self.assertRaises(CommandError):
            self.scan()
        self.revision.assert_not_called()
        self.process.assert_not_called()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_missing_installed_scanner_or_git_refuses_execution(self):
        with patch.object(Path, "is_file", return_value=False), self.assertRaises(CommandError):
            self.scan()
        self.git.return_value = None
        with self.assertRaises(CommandError):
            self.scan()
        self.revision.assert_not_called()
        self.process.assert_not_called()
        self.assert_no_evidence()

    def test_timeout_or_unavailable_process_has_safe_diagnostic_and_no_import(self):
        for error in (
            subprocess.TimeoutExpired("private-command-sentinel", 60),
            OSError("private-executable-path-sentinel"),
        ):
            with self.subTest(error=type(error).__name__):
                self.process.side_effect = error
                with self.assertRaises(CommandError) as caught:
                    self.scan()
                self.assertNotIn("sentinel", str(caught.exception))
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_failed_tool_exit_and_oversized_output_never_import(self):
        for result in (
            self.result(code=2),
            self.result(raw=b" " * (2 * 1024 * 1024 + 1)),
        ):
            with self.subTest(code=result.returncode, size=len(result.stdout)):
                self.process.return_value = result
                with self.assertRaises(CommandError):
                    self.scan()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_nonbytes_output_is_rejected_before_json_or_import(self):
        self.process.return_value = SimpleNamespace(returncode=0, stdout="invalid output type")
        with self.assertRaises(CommandError):
            self.scan()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_unavailable_or_invalid_revision_prevents_scanner_execution(self):
        for error in (
            OSError("private-revision-path-sentinel"),
            subprocess.TimeoutExpired("private-revision-command-sentinel", 10),
        ):
            self.revision.side_effect = error
            with (
                self.subTest(error=type(error).__name__),
                self.assertRaises(CommandError) as caught,
            ):
                self.scan()
            self.assertNotIn("sentinel", str(caught.exception))
        self.revision.side_effect = None
        for value in ("a" * 41, "a" * 63, "not-a-commit"):
            self.revision.return_value = value
            with self.subTest(length=len(value)), self.assertRaises(CommandError):
                self.scan()
        self.process.assert_not_called()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_revision_change_even_with_identical_source_prevents_import(self):
        self.revision.side_effect = [REVISION, "b" * 40]
        with self.assertRaisesMessage(CommandError, "source changed"):
            self.scan()
        self.process.assert_called_once()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_revoked_membership_during_scanning_refuses_import_with_safe_error(self):
        def revoke(*args, **kwargs):
            Membership.objects.filter(user=self.users["analyst"], integration=self.app).delete()
            return self.result()

        self.process.side_effect = revoke
        with self.assertRaisesMessage(CommandError, "import validation failed"):
            self.scan()
        self.assert_no_evidence()

    def test_source_change_during_process_refuses_stale_manifest_import(self):
        def changed(*args, **kwargs):
            self.source.write_text("# changed during mock scan\n", encoding="utf-8")
            return self.result()

        self.process.side_effect = changed
        with self.assertRaisesMessage(CommandError, "source changed"):
            self.scan()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_malformed_json_or_shape_is_safe_and_never_becomes_a_clean_scan(self):
        for raw in (
            b"not-json-private-sentinel",
            b"null",
            b"[]",
            b'{"version":"2.1.0","runs":[]}',
            b'{"version":"2.1.0","runs":[null]}',
            b'{"version":"2.1.0","runs":[{"results":null}]}',
            b"[" * 40 + b"0" + b"]" * 40,
        ):
            with self.subTest(raw_shape=raw[:25]):
                self.process.return_value = self.result(raw=raw)
                with self.assertRaises(CommandError) as caught:
                    self.scan()
                self.assertNotIn("private-sentinel", str(caught.exception))
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_duplicate_json_keys_are_rejected_before_normalization_can_erase_them(self):
        valid = json.dumps(self.document()).encode()
        raw = valid.replace(b'"version": "2.1.0"', b'"version": "invalid", "version": "2.1.0"', 1)
        self.process.return_value = self.result(raw=raw)
        with self.assertRaises(CommandError):
            self.scan()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_exit_status_must_agree_with_findings(self):
        for code, has_findings in ((0, True), (1, False)):
            with self.subTest(code=code, has_findings=has_findings):
                self.process.return_value = self.result(
                    document=self.document(findings=has_findings), code=code
                )
                with self.assertRaises(CommandError):
                    self.scan()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_external_remote_or_unscanned_source_locations_never_import(self):
        for uri in (
            "https://remote.invalid/source.py",
            "file://remote-host/source.py",
            (self.root.parent / "outside.py").as_uri(),
            (self.root / "var" / "excluded.py").as_uri(),
            self.source.as_uri() + "?query=unexpected",
            self.source.as_uri() + "#fragment",
        ):
            with self.subTest(uri=uri):
                self.process.return_value = self.result(document=self.document(uri=uri))
                with self.assertRaises(CommandError):
                    self.scan()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_missing_finding_location_cannot_create_unbound_local_evidence(self):
        document = self.document()
        document["runs"][0]["results"][0].pop("locations")
        self.process.return_value = self.result(document=document)
        with self.assertRaisesMessage(CommandError, "scanned source file"):
            self.scan()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_ambiguous_artifact_references_cannot_be_erased_by_normalization(self):
        for field, value in (("uriBaseId", "UNRESOLVED"), ("index", 0)):
            document = self.document()
            artifact = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                "artifactLocation"
            ]
            artifact[field] = value
            self.process.return_value = self.result(document=document)
            with self.subTest(field=field), self.assertRaises(CommandError):
                self.scan()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_reported_tool_failure_or_incomplete_coverage_cannot_claim_success(self):
        for invocation in (
            {"executionSuccessful": False},
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": [{"level": "error"}],
            },
        ):
            document = self.document()
            document["runs"][0]["invocations"] = [invocation]
            self.process.return_value = self.result(document=document)
            with self.subTest(invocation=invocation), self.assertRaises(CommandError):
                self.scan()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_wrong_tool_and_invalid_metadata_fail_before_import(self):
        wrong_tool = self.document()
        wrong_tool["runs"][0]["tool"]["driver"]["name"] = "UnexpectedScanner"
        bad_region = self.document()
        bad_region["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"][
            "startLine"
        ] = -1
        for document in (wrong_tool, bad_region):
            self.process.return_value = self.result(document=document)
            with self.subTest(tool=document["runs"][0]["tool"]), self.assertRaises(CommandError):
                self.scan()
        self.importer.assert_not_called()
        self.assert_no_evidence()

    def test_s106_guidance_explains_local_risk_without_claiming_acceptance_or_exposure(self):
        advice = guidance(SimpleNamespace(tool="Ruff", rule_id="S106"))
        self.assertEqual(
            advice["url"], "https://docs.astral.sh/ruff/rules/hardcoded-password-func-arg/"
        )
        self.assertIn(
            "Loopback does not prevent other local processes", " ".join(advice["validate"])
        )
        self.assertIn("generated credentials", advice["remediation"])
        self.assertIn("production", advice["unknowns"])
        self.assertIn("not risk acceptance", advice["unknowns"])
