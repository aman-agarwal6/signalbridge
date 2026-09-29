"""Offline guard tests: fake sockets/processes and synthetic files, never a lab run."""

import builtins
import json
import os
import runpy
import shutil
import socket
import subprocess
import sys
import uuid
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from scripts import record_verification
from scripts import run_enterprise_lab as lab
from simulations.scenarios import build_scenarios


def forbidden(*args, **kwargs):
    raise AssertionError("A real external operation was attempted by a safety test.")


class FakeSocket:
    """No operating-system socket is ever created by this stand-in."""

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    connect = forbidden
    connect_ex = forbidden
    sendto = forbidden
    sendmsg = forbidden
    bind = forbidden
    listen = forbidden


class OfflineGuardTests(TestCase):
    @contextmanager
    def fake_external_operations(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(socket, "socket", FakeSocket))
            for name in (
                "create_connection",
                "getaddrinfo",
                "gethostbyname",
                "gethostbyname_ex",
                "gethostbyaddr",
            ):
                stack.enter_context(patch.object(socket, name, forbidden))
            stack.enter_context(patch.object(subprocess, "Popen", forbidden))
            for name in ("system", "popen", "startfile", "spawnv", "execv"):
                if hasattr(os, name):
                    stack.enter_context(patch.object(os, name, forbidden))
            yield

    def test_network_dns_listener_and_child_process_guards_fail_closed(self):
        with self.fake_external_operations(), ExitStack() as stack:
            lab.offline_guards(stack)
            lab.verify_guards()
            client = FakeSocket()
            calls = (
                lambda: client.connect(("192.0.2.1", 443)),
                lambda: client.connect_ex(("192.0.2.1", 443)),
                lambda: client.sendto(b"synthetic", ("192.0.2.1", 53)),
                lambda: client.sendmsg([b"synthetic"]),
                lambda: client.bind(("127.0.0.1", 12345)),
                lambda: client.listen(),
                lambda: socket.create_connection(("invalid.example", 443)),
                lambda: socket.gethostbyname("invalid.example"),
                lambda: socket.gethostbyname_ex("invalid.example"),
                lambda: socket.gethostbyaddr("192.0.2.1"),
                lambda: subprocess.Popen(["never-executed"]),
                lambda: os.system("never-executed"),
                lambda: os.popen("never-executed"),
                lambda: os.spawnv(0, "never-executed", []),
                lambda: os.execv("never-executed", []),
            )
            for operation in calls:
                with self.assertRaises(PermissionError):
                    operation()

    def test_guards_restore_methods_after_an_exception(self):
        with self.fake_external_operations():
            with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
                with ExitStack() as stack:
                    lab.offline_guards(stack)
                    raise RuntimeError("synthetic failure")
            self.assertIs(FakeSocket.connect, forbidden)
            self.assertIs(socket.getaddrinfo, forbidden)
            self.assertIs(subprocess.Popen, forbidden)

    def test_guard_verification_refuses_an_unblocked_operation(self):
        with self.fake_external_operations(), ExitStack() as stack:
            lab.offline_guards(stack)
            with patch.object(FakeSocket, "connect", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "did not fail closed"):
                    lab.verify_guards()

    def test_clean_environment_excludes_credentials_targets_and_interpreter_preloads(self):
        inherited = {
            "PATH": "synthetic-path",
            "SystemRoot": "synthetic-windows",
            "SB_DB_HOST": "database.invalid",
            "PGHOSTADDR": "192.0.2.1",
            "PGSERVICE": "remote",
            "SB_SECRET_KEY": "original-secret",
            "SB_SIMULATION_KEY": "original-signing-key",
            "PYTHONPATH": "untrusted-import-path",
            "PYTHONSTARTUP": "untrusted-startup.py",
            "NODE_OPTIONS": "--require=untrusted.js",
            "DJANGO_SETTINGS_MODULE": "config.settings",
            "AWS_SECRET_ACCESS_KEY": "synthetic-cloud-secret",
            "HTTP_PROXY": "http://proxy.invalid",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "untrusted-hook",
        }
        with patch.dict(os.environ, inherited, clear=True):
            before = dict(os.environ)
            first = lab.clean_environment("a" * 32)
            second = lab.clean_environment("a" * 32)
            self.assertEqual(dict(os.environ), before)
        for key in inherited:
            if key not in {
                "PATH",
                "SystemRoot",
                "SB_SECRET_KEY",
                "SB_SIMULATION_KEY",
                "DJANGO_SETTINGS_MODULE",
                "GIT_CONFIG_COUNT",
                "GIT_CONFIG_KEY_0",
                "GIT_CONFIG_VALUE_0",
            }:
                self.assertNotIn(key, first)
        self.assertEqual(first["DJANGO_SETTINGS_MODULE"], "config.simulation_settings")
        self.assertEqual(first["SB_MODE"], "local")
        self.assertEqual(first["SB_SIMULATION_RUN_ID"], "a" * 32)
        self.assertEqual(first["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertNotEqual(first["SB_SECRET_KEY"], inherited["SB_SECRET_KEY"])
        self.assertNotEqual(first["SB_SIMULATION_KEY"], inherited["SB_SIMULATION_KEY"])
        self.assertNotEqual(first["SB_SECRET_KEY"], second["SB_SECRET_KEY"])
        self.assertNotEqual(first["SB_SIMULATION_KEY"], second["SB_SIMULATION_KEY"])
        self.assertNotEqual(first.get("GIT_CONFIG_VALUE_0"), "untrusted-hook")

    def test_provenance_configuration_disables_git_hooks_and_index_refresh(self):
        environment = lab.clean_environment("a" * 32)
        self.assertEqual(environment.get("GIT_OPTIONAL_LOCKS"), "0")
        overrides = {
            environment[f"GIT_CONFIG_KEY_{index}"]: environment[f"GIT_CONFIG_VALUE_{index}"]
            for index in range(int(environment.get("GIT_CONFIG_COUNT", "0")))
        }
        self.assertEqual(overrides.get("core.fsmonitor"), "false")

    def test_standalone_settings_ignore_hosted_targets_without_reading_runtime_files(self):
        original_import = builtins.__import__

        def safe_import(name, *args, **kwargs):
            if name == "config.settings" or name.startswith("django"):
                raise AssertionError("Standalone settings imported the running application.")
            return original_import(name, *args, **kwargs)

        with (
            patch.dict(
                os.environ,
                {
                    "SB_SECRET_KEY": "synthetic-ephemeral-secret",
                    "SB_DB_HOST": "remote.invalid",
                    "PGHOSTADDR": "192.0.2.1",
                    "SB_MODE": "production",
                },
                clear=True,
            ),
            patch("builtins.__import__", side_effect=safe_import),
            patch.object(Path, "read_text", forbidden),
            patch.object(Path, "read_bytes", forbidden),
            patch.object(Path, "write_text", forbidden),
            patch.object(Path, "write_bytes", forbidden),
        ):
            values = runpy.run_path(str(lab.ROOT / "config/simulation_settings.py"))
        self.assertEqual(values["SECRET_KEY"], "synthetic-ephemeral-secret")
        self.assertTrue(values["LOCAL"])
        self.assertFalse(values["DEBUG"])
        self.assertEqual(set(values["DATABASES"]), {"default"})
        database = values["DATABASES"]["default"]
        self.assertEqual(database["ENGINE"], "django.db.backends.sqlite3")
        self.assertEqual(database["NAME"], ":memory:")
        self.assertEqual(database["TEST"]["NAME"], ":memory:")
        self.assertNotIn("HOST", database)
        self.assertIn("locmem", values["EMAIL_BACKEND"])
        self.assertIn("LocMemCache", values["CACHES"]["default"]["BACKEND"])


class ChildSafetyTests(TestCase):
    def test_challenge_selects_only_fixed_suite_after_existing_guards(self):
        with (
            self.fake_django() as (_, _, _, runner),
            patch.dict(os.environ, {"SB_SIMULATION_RUN_ID": "a" * 32}),
            patch.object(lab, "offline_guards") as guard,
            patch.object(lab, "verify_guards") as verify,
        ):
            self.assertFalse(lab.child("a" * 32, challenge=True))
            guard.assert_called_once()
            verify.assert_called_once()
            runner.run_tests.assert_called_once_with(["simulations.challenge_suite"])
            with self.assertRaises(ValueError):
                lab.child("a" * 32, challenge="arbitrary.module")

    @contextmanager
    def fake_django(self, database=None):
        operations = []
        django = ModuleType("django")
        django.setup = Mock(side_effect=lambda: operations.append("django-setup"))
        conf = ModuleType("django.conf")
        conf.settings = SimpleNamespace(
            DATABASES={
                "default": database
                or {
                    "ENGINE": "django.db.backends.sqlite3",
                    "NAME": ":memory:",
                    "TEST": {"NAME": ":memory:"},
                }
            }
        )
        runner_module = ModuleType("django.test.runner")
        runner = Mock()
        runner.run_tests.return_value = 0
        runner_module.DiscoverRunner = Mock(return_value=runner)
        with (
            patch.dict(
                sys.modules,
                {"django": django, "django.conf": conf, "django.test.runner": runner_module},
            ),
            patch.object(lab, "output_directory", return_value=Path("synthetic-output")),
        ):
            yield operations, django, runner_module.DiscoverRunner, runner

    def test_invalid_child_identity_fails_before_guards_or_django(self):
        with (
            self.fake_django() as (_, django, _, runner),
            patch.object(lab, "offline_guards") as guard,
        ):
            for run_id in ("../escape", "g" * 32, "a" * 31, "a" * 33):
                with self.subTest(run_id=run_id), self.assertRaises(ValueError):
                    lab.child(run_id)
            with patch.dict(os.environ, {"SB_SIMULATION_RUN_ID": "b" * 32}):
                with self.assertRaises(ValueError):
                    lab.child("a" * 32)
            guard.assert_not_called()
            django.setup.assert_not_called()
            runner.run_tests.assert_not_called()

    def test_failed_guard_prevents_django_setup_and_test_storage(self):
        with (
            self.fake_django() as (_, django, _, runner),
            patch.dict(os.environ, {"SB_SIMULATION_RUN_ID": "a" * 32}),
            patch.object(lab, "offline_guards"),
            patch.object(lab, "verify_guards", side_effect=RuntimeError("failed guard")),
        ):
            with self.assertRaisesRegex(RuntimeError, "failed guard"):
                lab.child("a" * 32)
            django.setup.assert_not_called()
            runner.run_tests.assert_not_called()

    def test_guards_are_verified_before_setup_and_only_fixed_suite_is_selected(self):
        with (
            self.fake_django() as (operations, _, constructor, runner),
            patch.dict(os.environ, {"SB_SIMULATION_RUN_ID": "a" * 32}),
            patch.object(
                lab, "offline_guards", side_effect=lambda stack: operations.append("install")
            ),
            patch.object(lab, "verify_guards", side_effect=lambda: operations.append("verify")),
        ):
            self.assertFalse(lab.child("a" * 32))
            self.assertEqual(operations, ["install", "verify", "django-setup"])
            constructor.assert_called_once_with(verbosity=1, interactive=False, parallel=0)
            runner.run_tests.assert_called_once_with(["simulations.enterprise_suite"])

    def test_nonmemory_or_network_database_never_reaches_runner(self):
        databases = (
            {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": "live.sqlite3",
                "TEST": {"NAME": ":memory:"},
            },
            {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
                "TEST": {"NAME": "live.sqlite3"},
            },
            {
                "ENGINE": "django.db.backends.postgresql",
                "NAME": ":memory:",
                "TEST": {"NAME": ":memory:"},
            },
        )
        for database in databases:
            with (
                self.subTest(database=database),
                self.fake_django(database) as (_, _, constructor, runner),
                patch.dict(os.environ, {"SB_SIMULATION_RUN_ID": "a" * 32}),
                patch.object(lab, "offline_guards"),
                patch.object(lab, "verify_guards"),
            ):
                with self.assertRaises(RuntimeError):
                    lab.child("a" * 32)
                constructor.assert_not_called()
                runner.run_tests.assert_not_called()

    def test_memory_database_gate_rejects_extra_connections_and_missing_test_target(self):
        memory = {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
            "TEST": {"NAME": ":memory:"},
        }
        lab.require_memory_database({"default": memory})
        invalid = (
            {},
            {"default": memory, "secondary": memory},
            {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
            {"default": dict(memory, ENGINE="django.db.backends.postgresql")},
            {"default": dict(memory, NAME="file:live.sqlite3")},
        )
        for databases in invalid:
            with self.subTest(databases=databases), self.assertRaises(RuntimeError):
                lab.require_memory_database(databases)


class ParentSafetyTests(TestCase):
    def test_malformed_result_preserves_failure_provenance(self):
        def malformed(argv, **kwargs):
            (self.output / "result.json").write_text("{broken", encoding="utf8")
            return SimpleNamespace(returncode=0)

        result, _ = self.run_parent(malformed)
        self.assertEqual(result, 1)
        self.assertFalse(self.receipt()["execution_verified"])
        self.assertIn("result_sha256", self.receipt())

    def test_changed_challenge_declaration_fails_verification(self):
        from tests.test_detection_challenge import synthetic_result

        def changed(argv, **kwargs):
            (self.output / "declaration.json").write_text("{}", encoding="utf8")
            (self.output / "result.json").write_text(
                json.dumps(synthetic_result()), encoding="utf8"
            )
            return SimpleNamespace(returncode=0)

        result, _ = self.run_parent(changed, argv=["run_enterprise_lab.py", "--challenge"])
        self.assertEqual(result, 1)
        self.assertFalse(self.receipt()["execution_verified"])

    def test_challenge_declared_before_child_and_gaps_do_not_claim_full_coverage(self):
        from tests.test_detection_challenge import synthetic_result

        def complete(argv, **kwargs):
            self.assertTrue((self.output / "declaration.json").is_file())
            (self.output / "result.json").write_text(
                json.dumps(synthetic_result()), encoding="utf8"
            )
            return SimpleNamespace(returncode=0)

        result, process = self.run_parent(complete, argv=["run_enterprise_lab.py", "--challenge"])
        self.assertEqual(result, 0)
        self.assertEqual(process.call_args.args[0][-1], "--challenge")
        self.assertTrue(self.receipt()["execution_verified"])
        self.assertEqual(self.receipt()["coverage_status"], "partial")

    def test_challenge_rejects_successful_child_with_falsely_green_summary(self):
        from tests.test_detection_challenge import synthetic_result

        def false_summary(argv, **kwargs):
            report = synthetic_result()
            report["summary"]["capability_probes"]["alert_observed"] = 3
            (self.output / "result.json").write_text(json.dumps(report), encoding="utf8")
            return SimpleNamespace(returncode=0)

        result, _ = self.run_parent(false_summary, argv=["run_enterprise_lab.py", "--challenge"])
        self.assertEqual(result, 1)
        self.assertFalse(self.receipt()["execution_verified"])

    def setUp(self):
        self.test_root = lab.ROOT / "var/tests"
        self.root = self.test_root / ("simulation-safety-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup)
        self.run_id = "a" * 32
        self.output = self.root / "artifacts/local/simulation" / self.run_id
        self.manifest = {"files": {"fixed.py": "b" * 64}, "sha256": "c" * 64, "file_count": 1}

    def cleanup(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.test_root.resolve()) or not target.name.startswith(
            "simulation-safety-"
        ):
            raise RuntimeError("Unsafe simulation safety test cleanup target.")
        shutil.rmtree(target)

    def run_parent(self, action, manifests=None, argv=None):
        with (
            patch.object(lab, "ROOT", self.root),
            patch.object(lab.uuid, "uuid4", return_value=SimpleNamespace(hex=self.run_id)),
            patch.object(sys, "argv", argv or ["run_enterprise_lab.py"]),
            patch.object(
                record_verification,
                "source_manifest",
                side_effect=manifests or [self.manifest, self.manifest],
            ),
            patch.object(
                record_verification, "git_state", return_value={"head": "d" * 40, "dirty": False}
            ),
            patch.object(lab.subprocess, "run", side_effect=action) as process,
            redirect_stdout(StringIO()),
        ):
            result = lab.main()
        return result, process

    def complete_child(self, argv, **kwargs):
        kwargs["stdout"].write(b"Synthetic mocked child output\n")
        kwargs["stderr"].write(b"Synthetic mocked child error output\n")
        (self.output / "result.json").write_text(
            json.dumps({"execution_status": "completed_with_known_coverage_gap"}), encoding="utf-8"
        )
        return SimpleNamespace(returncode=0)

    def receipt(self):
        return json.loads((self.output / "provenance.json").read_text(encoding="utf-8"))

    def test_parent_invokes_only_fixed_isolated_python_with_timeout_and_ephemeral_environment(self):
        result, process = self.run_parent(self.complete_child)
        self.assertEqual(result, 0)
        argv = process.call_args.args[0]
        options = process.call_args.kwargs
        self.assertEqual(argv[:3], [sys.executable, "-I", "-B"])
        self.assertEqual(Path(argv[3]), Path(lab.__file__).resolve())
        self.assertEqual(argv[4:], ["--child", self.run_id])
        self.assertEqual(options["timeout"], 120)
        self.assertEqual(options["cwd"], self.root)
        self.assertFalse(options.get("shell", False))
        self.assertFalse(options["check"])
        self.assertEqual(options["env"]["SB_SIMULATION_RUN_ID"], self.run_id)
        receipt = self.receipt()
        self.assertTrue(receipt["execution_verified"])
        self.assertEqual(set(receipt["logs"]), {"stdout.txt", "stderr.txt"})
        self.assertNotIn("SB_SIMULATION_KEY", json.dumps(receipt))

    def test_timeout_never_claims_verified_execution(self):
        result, process = self.run_parent(subprocess.TimeoutExpired("fixed child", 120))
        self.assertEqual(result, 1)
        process.assert_called_once()
        receipt = self.receipt()
        self.assertIsNone(receipt["exit_code"])
        self.assertFalse(receipt["execution_verified"])

    def test_successful_exit_without_report_never_claims_verified_execution(self):
        result, _ = self.run_parent(lambda *args, **kwargs: SimpleNamespace(returncode=0))
        self.assertEqual(result, 1)
        self.assertFalse(self.receipt()["execution_verified"])

    def test_nonzero_child_even_with_completed_report_fails_verification(self):
        def fail(argv, **kwargs):
            self.complete_child(argv, **kwargs)
            return SimpleNamespace(returncode=1)

        result, _ = self.run_parent(fail)
        self.assertEqual(result, 1)
        self.assertFalse(self.receipt()["execution_verified"])

    def test_source_changes_during_run_fail_verification(self):
        changed = dict(self.manifest, sha256="e" * 64)
        result, _ = self.run_parent(self.complete_child, manifests=[self.manifest, changed])
        self.assertEqual(result, 1)
        receipt = self.receipt()
        self.assertFalse(receipt["source_unchanged"])
        self.assertFalse(receipt["execution_verified"])

    def test_failed_report_even_with_zero_exit_fails_verification(self):
        def incomplete(argv, **kwargs):
            self.complete_child(argv, **kwargs)
            (self.output / "result.json").write_text(
                json.dumps({"execution_status": "failed"}), encoding="utf-8"
            )
            return SimpleNamespace(returncode=0)

        result, _ = self.run_parent(incomplete)
        self.assertEqual(result, 1)
        self.assertFalse(self.receipt()["execution_verified"])

    def test_existing_run_directory_is_never_overwritten_or_executed(self):
        self.output.mkdir(parents=True)
        sentinel = self.output / "result.json"
        sentinel.write_text("existing evidence", encoding="utf-8")
        with self.assertRaises((FileExistsError, ValueError, RuntimeError)):
            self.run_parent(forbidden)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "existing evidence")

    def test_output_ancestor_link_is_rejected_before_directory_creation_or_execution(self):
        original = Path.is_symlink
        linked = self.root / "artifacts"

        def is_link(path):
            return path == linked or original(path)

        with patch.object(Path, "is_symlink", is_link):
            with self.assertRaises((ValueError, RuntimeError)):
                self.run_parent(forbidden)
        self.assertFalse(self.output.exists())

    def test_output_helper_rejects_invalid_identity_and_existing_file(self):
        with patch.object(lab, "ROOT", self.root):
            for run_id in ("../outside", "a/" + "b" * 30, "A" * 32):
                with self.subTest(run_id=run_id), self.assertRaises((ValueError, RuntimeError)):
                    lab.output_directory(run_id, create=True)
            self.output.parent.mkdir(parents=True)
            self.output.write_text("synthetic sentinel", encoding="utf-8")
            with self.assertRaises((FileExistsError, ValueError, RuntimeError)):
                lab.output_directory(self.run_id, create=True)
            self.assertEqual(self.output.read_text(encoding="utf-8"), "synthetic sentinel")

    def test_output_helper_rechecks_ancestors_for_child_writes(self):
        self.output.mkdir(parents=True)
        original = Path.is_symlink
        linked = self.root / "artifacts/local"

        def is_link(path):
            return path == linked or original(path)

        with patch.object(lab, "ROOT", self.root), patch.object(Path, "is_symlink", is_link):
            with self.assertRaises((ValueError, RuntimeError)):
                lab.output_directory(self.run_id)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_output_helper_rejects_windows_reparse_attributes(self):
        self.output.parent.mkdir(parents=True)
        original = Path.lstat
        linked = self.root / "artifacts/local"

        def attributes(path, *args, **kwargs):
            if path == linked:
                return SimpleNamespace(st_file_attributes=1024)
            return original(path, *args, **kwargs)

        with patch.object(lab, "ROOT", self.root), patch.object(Path, "lstat", attributes):
            with self.assertRaisesRegex(ValueError, "reparse"):
                lab.output_directory(self.run_id, create=True)
        self.assertFalse(self.output.exists())

    def test_arbitrary_output_and_test_selection_arguments_are_rejected(self):
        for flag in ("--output", "--suite", "--url", "--source"):
            with self.subTest(flag=flag), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    self.run_parent(forbidden, argv=["run_enterprise_lab.py", flag, "unexpected"])
                self.assertEqual(raised.exception.code, 2)
        self.assertFalse(self.output.exists())


class ScenarioBoundaryTests(TestCase):
    def test_declared_truth_stays_outside_events_and_request_count_is_bounded(self):
        cases = build_scenarios(datetime(2026, 9, 24, tzinfo=timezone.utc))
        self.assertEqual(len(cases), 15)
        self.assertEqual(len({case["id"] for case in cases}), 15)
        self.assertLessEqual(sum(len(case["deliveries"]) for case in cases) + 603, 750)
        boundary = next(case for case in cases if case["id"] == "bucket_boundary_gap")
        self.assertFalse(boundary["known_gap"])
        self.assertEqual(boundary["expected_rule"], "R1")
        allowed_fields = {
            "schema_version",
            "event_id",
            "app",
            "environment",
            "occurred_at",
            "actor",
            "resource",
            "episode",
            "operation",
            "outcome",
            "reason",
            "context",
        }
        for case in cases:
            for delivery in case["deliveries"]:
                self.assertEqual(set(delivery), {"source", "event"})
                self.assertEqual(set(delivery["event"]), allowed_fields)
                self.assertIn(delivery["event"]["app"], {"lab-alpha", "lab-beta"})
                self.assertIn(delivery["source"], {"migration_lab", "synthetic_demo"})
