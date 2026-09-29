"""Fixed dependency audit scope and failure handling; all external processes are mocked."""

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

from bridge.management.commands.scan_dependencies import PUBLIC_PACKAGES
from bridge.models import Integration, Membership

MODULE = "bridge.management.commands.scan_dependencies"
PINS = {
    "django": "5.2.17",
    "psycopg": "3.3.6",
    "psycopg-binary": "3.3.6",
    "waitress": "3.0.2",
    "asgiref": "3.12.1",
    "sqlparse": "0.6.0",
    "tzdata": "2026.4",
}
REQUIREMENTS = "\n".join(
    f"{name}{'[binary]' if name == 'psycopg' else ''}=={version}" for name, version in PINS.items()
).encode()
REVISION = "a" * 40


def clean_report():
    return {
        "dependencies": [
            {"name": name, "version": version, "vulns": []} for name, version in PINS.items()
        ],
        "fixes": [],
    }


class DependencyRunnerTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(
            slug="signalbridge", name="SignalBridge", enabled=False
        )
        cls.users = {}
        for role in ("viewer", "analyst", "reviewer"):
            user = get_user_model().objects.create_user(username="dependency-" + role)
            Membership.objects.create(user=user, integration=cls.app, role=role)
            cls.users[role] = user
        cls.outsider = get_user_model().objects.create_user(username="dependency-outsider")

    def setUp(self):
        test_base = Path(settings.BASE_DIR).resolve() / "var" / "tests"
        self.root = test_base / ("dependency-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True, exist_ok=False)

        def cleanup():
            resolved = self.root.resolve()
            if resolved.parent != test_base.resolve():
                raise RuntimeError("Test directory moved outside its intended parent.")
            shutil.rmtree(resolved)

        self.addCleanup(cleanup)
        self.requirements = self.root / "requirements.txt"
        self.requirements.write_bytes(REQUIREMENTS)
        self.interpreter = (
            self.root
            / ".venv"
            / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        )
        self.interpreter.parent.mkdir(parents=True)
        self.interpreter.write_bytes(b"mock interpreter; never executed")
        settings_override = override_settings(BASE_DIR=self.root, LOCAL=True)
        settings_override.enable()
        self.addCleanup(settings_override.disable)
        self.process = self.mock(
            "subprocess.run",
            return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(clean_report()).encode(), stderr=b""
            ),
        )
        self.revision = self.mock("subprocess.check_output", return_value=REVISION)
        self.mock("shutil.which", return_value="mock-git")
        self.importer = self.mock(
            "import_scan", return_value=(SimpleNamespace(pk="recorded-run", finding_count=0), True)
        )

    def mock(self, name, **options):
        patcher = patch(f"{MODULE}.{name}", **options)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def audit(self, user=None, fetch=True):
        output = StringIO()
        call_command(
            "scan_dependencies",
            user=(user or self.users["analyst"]).username,
            fetch_advisories=fetch,
            stdout=output,
        )
        return output.getvalue()

    def test_network_requires_explicit_flag_before_any_process(self):
        with self.assertRaisesMessage(CommandError, "--fetch-advisories"):
            self.audit(fetch=False)
        self.process.assert_not_called()
        self.revision.assert_not_called()
        self.importer.assert_not_called()

    def test_only_active_authorized_scanner_members_can_run(self):
        for user in (self.users["viewer"], self.outsider):
            with self.subTest(user=user.username), self.assertRaises(CommandError):
                self.audit(user=user)
        self.users["analyst"].is_active = False
        self.users["analyst"].save()
        with self.assertRaises(CommandError):
            self.audit()
        self.process.assert_not_called()
        self.importer.assert_not_called()

    def test_runner_is_local_only_and_requires_disabled_scanner_collector(self):
        with override_settings(LOCAL=False), self.assertRaises(CommandError):
            self.audit()
        Integration.objects.filter(pk=self.app.pk).update(enabled=True)
        with self.assertRaises(CommandError):
            self.audit()
        self.process.assert_not_called()

    def test_clean_report_imports_fixed_pins_and_local_execution_provenance(self):
        output = self.audit(user=self.users["reviewer"])
        self.assertIn("7 explicit public package pins", output)
        self.assertEqual(set(PINS), PUBLIC_PACKAGES)
        args, kwargs = self.process.call_args
        command = args[0]
        self.assertEqual(command[:4], [str(self.interpreter), "-I", "-m", "pip_audit"])
        for option in ("--no-deps", "--disable-pip", "--strict"):
            self.assertIn(option, command)
        self.assertNotIn("--fix", command)
        self.assertEqual(command[command.index("-r") + 1], "requirements.txt")
        self.assertEqual(command[command.index("--format") + 1], "json")
        self.assertEqual(command[command.index("--vulnerability-service") + 1], "pypi")
        self.assertEqual(command[command.index("--progress-spinner") + 1], "off")
        self.assertEqual(
            (kwargs["cwd"], kwargs["timeout"], kwargs["check"]), (self.root, 120, False)
        )
        positional, provenance = self.importer.call_args
        self.assertEqual(positional[0], self.users["reviewer"])
        self.assertEqual(positional[1], self.app)
        self.assertEqual(positional[3], "pip-audit")
        self.assertEqual(provenance["source_revision"], REVISION)
        self.assertEqual(
            provenance["manifest"], {"requirements.txt": hashlib.sha256(REQUIREMENTS).hexdigest()}
        )
        execution = provenance["execution"]
        self.assertEqual(execution["runner"], "signalbridge-pip-audit")
        self.assertEqual(execution["returncode"], 0)
        self.assertEqual(execution["original_digest"], hashlib.sha256(positional[2]).hexdigest())
        self.assertGreaterEqual(execution["duration_ms"], 0)
        self.assertIn("+00:00", execution["started_at"])
        self.assertIn("+00:00", execution["finished_at"])

    def test_report_with_findings_and_exit_one_is_valid_execution(self):
        report = clean_report()
        report["dependencies"][0]["vulns"] = [{"id": "CVE-2099-12345", "fix_versions": []}]
        self.process.return_value = SimpleNamespace(
            returncode=1, stdout=json.dumps(report).encode()
        )
        self.audit()
        self.assertEqual(self.importer.call_args.kwargs["execution"]["returncode"], 1)

    def test_mismatched_findings_and_exit_status_are_rejected(self):
        self.process.return_value.returncode = 1
        with self.assertRaisesMessage(CommandError, "exit status and findings disagree"):
            self.audit()
        report = clean_report()
        report["dependencies"][0]["vulns"] = [{"id": "CVE-2099-12345", "fix_versions": []}]
        self.process.return_value = SimpleNamespace(
            returncode=0, stdout=json.dumps(report).encode()
        )
        with self.assertRaises(CommandError):
            self.audit()
        self.importer.assert_not_called()

    def test_timeout_process_failure_and_error_return_code_do_not_import(self):
        self.process.side_effect = subprocess.TimeoutExpired("fixed scanner", 120)
        with self.assertRaisesMessage(CommandError, "timed out"):
            self.audit()
        self.process.side_effect = OSError("private-sentinel")
        with self.assertRaises(CommandError) as caught:
            self.audit()
        self.assertNotIn("private-sentinel", str(caught.exception))
        self.process.side_effect = None
        self.process.return_value.returncode = 2
        with self.assertRaisesMessage(CommandError, "audit failed"):
            self.audit()
        self.importer.assert_not_called()

    def test_partial_skipped_malformed_and_oversized_reports_are_not_success(self):
        partial = clean_report()
        partial["dependencies"].pop()
        skipped = clean_report()
        skipped["dependencies"][0] = {"name": "django", "skip_reason": "query failure"}
        for raw in (
            json.dumps(partial).encode(),
            json.dumps(skipped).encode(),
            b'{"dependencies":[]}',
            b"query failure",
            b"x" * (2 * 1024 * 1024 + 1),
        ):
            self.process.return_value.stdout = raw
            with self.subTest(size=len(raw)), self.assertRaises(CommandError):
                self.audit()
        self.importer.assert_not_called()

    def test_reported_package_versions_must_match_exact_requested_versions(self):
        report = clean_report()
        report["dependencies"][0]["version"] = "0.1"
        self.process.return_value.stdout = json.dumps(report).encode()
        with self.assertRaisesMessage(CommandError, "exact requested dependency pins"):
            self.audit()
        self.importer.assert_not_called()

    def test_manifest_rejects_includes_urls_ranges_missing_and_unknown_packages(self):
        for addition in (
            b"\n-r other.txt",
            b"\nhttps://private.invalid/package.whl",
            b"\ndjango>=5",
            b"\nunknown-package==1.0",
            b"\ndjango==5.2.17",
        ):
            self.requirements.write_bytes(REQUIREMENTS + addition)
            with self.subTest(addition=addition), self.assertRaises(CommandError):
                self.audit()
        self.requirements.write_bytes(b"django==5.2.17")
        with self.assertRaises(CommandError):
            self.audit()
        self.requirements.unlink()
        with self.assertRaises(CommandError):
            self.audit()
        self.process.assert_not_called()
        self.importer.assert_not_called()

    def test_source_changes_during_audit_reject_import(self):
        result = self.process.return_value

        def change_source(*_args, **_kwargs):
            self.requirements.write_bytes(REQUIREMENTS + b"\n# changed while scanner ran")
            return result

        self.process.side_effect = change_source
        with self.assertRaisesMessage(CommandError, "Source changed"):
            self.audit()
        self.importer.assert_not_called()

    def test_revision_changes_or_invalid_revision_reject_import(self):
        self.revision.side_effect = [REVISION, "b" * 40]
        with self.assertRaisesMessage(CommandError, "Source changed"):
            self.audit()
        self.revision.side_effect = None
        self.revision.return_value = "short"
        with self.assertRaisesMessage(CommandError, "complete source commit hash"):
            self.audit()
        self.importer.assert_not_called()

    def test_injected_python_package_service_and_proxy_environment_is_not_forwarded(self):
        injected = {
            "PIP_AUDIT_VULNERABILITY_SERVICE": "osv",
            "PIP_INDEX_URL": "https://private.invalid",
            "PYTHONPATH": "private-module-path",
            "HTTPS_PROXY": "https://user:password@proxy.invalid",
        }
        with patch.dict("os.environ", injected):
            self.audit()
        environment = self.process.call_args.kwargs["env"]
        for name in injected:
            self.assertNotIn(name, environment)

    def test_missing_project_interpreter_fails_before_scanner_execution(self):
        self.interpreter.unlink()
        with self.assertRaisesMessage(CommandError, "project venv"):
            self.audit()
        self.process.assert_not_called()
        self.importer.assert_not_called()
