"""Portable onboarding boundaries; never install packages, run a server or open a connection."""

import importlib.util
import io
import os
import shutil
import subprocess
import uuid
from contextlib import redirect_stdout
from unittest import TestCase
from unittest.mock import call, patch

from scripts import sb


class OnboardingTests(TestCase):
    def setUp(self):
        self.test_root = sb.ROOT / "var/tests"
        self.root = self.test_root / ("onboarding-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup)
        self.root_patch = patch.object(sb, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.env_patch = patch.dict(os.environ, {}, clear=True)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def cleanup(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.test_root.resolve()) or not target.name.startswith(
            "onboarding-"
        ):
            raise RuntimeError("Unsafe onboarding test cleanup.")
        shutil.rmtree(target)

    def fixtures(self):
        directory = self.root / "fixtures"
        directory.mkdir()
        for name in ("events.json", "labels.json"):
            (directory / name).write_text("[]", encoding="utf8")

    def test_import_has_no_command_parser_process_or_working_directory_side_effect(self):
        spec = importlib.util.spec_from_file_location("sb_import_audit", sb.__file__)
        module = importlib.util.module_from_spec(spec)
        with (
            patch(
                "argparse.ArgumentParser.parse_args", side_effect=AssertionError("CLI on import")
            ),
            patch("os.chdir", side_effect=AssertionError("cwd changed")),
            patch("subprocess.run", side_effect=AssertionError("child started")),
            patch("subprocess.Popen", side_effect=AssertionError("server started")),
        ):
            spec.loader.exec_module(module)
        self.assertTrue(callable(module.main))

    def test_nonlocal_database_port_and_settings_overrides_are_rejected_before_setup(self):
        for values in (
            {"SB_MODE": "production"},
            {"SB_DB_HOST": "remote.invalid"},
            {"SB_DB_HOST": "127.0.0.1"},
            {"SB_DB_PASSWORD": "private-password-sentinel"},
            {"SB_PORT": "8742"},
            {"DJANGO_SETTINGS_MODULE": "foreign.settings"},
        ):
            with (
                self.subTest(values=values),
                patch.dict(os.environ, values),
                patch.object(sb, "manage") as manage,
            ):
                with self.assertRaises(SystemExit) as error:
                    sb.setup()
                self.assertNotIn("private-password-sentinel", str(error.exception))
                manage.assert_not_called()

    def test_child_environment_keeps_local_intent_and_drops_node_preload_output_settings(self):
        with patch.dict(
            os.environ,
            {
                "NODE_OPTIONS": "--import private.mjs",
                "NODE_PATH": "foreign",
                "NODE_V8_COVERAGE": "outside",
                "BETTAIL_REPO": "explicit-source",
            },
        ):
            child = sb.local_environment()
            self.assertIn("NODE_OPTIONS", os.environ)
        for name in ("NODE_OPTIONS", "NODE_PATH", "NODE_V8_COVERAGE"):
            self.assertNotIn(name, child)
        self.assertEqual(child["SB_MODE"], "local")
        self.assertEqual(child["DJANGO_SETTINGS_MODULE"], "config.settings")
        self.assertEqual(child["BETTAIL_REPO"], "explicit-source")

    def test_main_refuses_global_python_before_any_mutation(self):
        with (
            patch.object(sb, "project_python", return_value=False),
            patch.object(sb, "setup") as setup,
        ):
            with self.assertRaisesRegex(SystemExit, "this checkout's .venv"):
                sb.main(["setup"])
        setup.assert_not_called()

    def test_main_refuses_conflicting_configuration_even_when_target_is_mocked(self):
        with (
            patch.object(sb, "project_python", return_value=True),
            patch.object(sb, "up") as up,
            patch.dict(os.environ, {"SB_MODE": "production"}),
        ):
            with self.assertRaises(SystemExit):
                sb.main(["up"])
        up.assert_not_called()

    def test_node_version_check_rejects_old_missing_ambiguous_and_failed_process(self):
        with patch.object(sb.shutil, "which", return_value="fixed-node"):
            for output, code, expected in (
                ("v24.14.1\n", 0, True),
                ("v25.0.0\n", 0, True),
                ("v23.9.0\n", 0, False),
                ("v24.14.1\nextra", 0, False),
                ("v24.14.1", 1, False),
                ("", 0, False),
            ):
                with (
                    self.subTest(output=output, code=code),
                    patch.object(
                        sb.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess([], code, output),
                    ) as run,
                ):
                    self.assertEqual(sb.node_ready(), expected)
                    self.assertEqual(run.call_args.args[0], ["fixed-node", "--version"])
                    self.assertFalse(run.call_args.kwargs["shell"])
                    self.assertEqual(run.call_args.kwargs["timeout"], 3)
            for error in (OSError("private path"), subprocess.TimeoutExpired("fixed", 3)):
                with patch.object(sb.subprocess, "run", side_effect=error):
                    self.assertFalse(sb.node_ready())
        with (
            patch.object(sb.shutil, "which", return_value=None),
            patch.object(sb.subprocess, "run") as run,
        ):
            self.assertFalse(sb.node_ready())
            run.assert_not_called()

    def test_node_version_probe_cannot_inherit_preloaded_modules(self):
        with (
            patch.dict(os.environ, {"NODE_OPTIONS": "--import outside.mjs"}),
            patch.object(sb.shutil, "which", return_value="fixed-node"),
            patch.object(
                sb.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "v24.14.1")
            ) as run,
        ):
            self.assertTrue(sb.node_ready())
        self.assertNotIn("NODE_OPTIONS", run.call_args.kwargs["env"])

    def test_runtime_readiness_uses_exact_distribution_pins_without_installing(self):
        path = self.root / "requirements.txt"
        path.write_text("# Runtime\nDjango==5.2.17\npsycopg[binary]==3.3.6\n", encoding="utf8")
        with patch.object(
            sb.importlib.metadata,
            "version",
            side_effect={"Django": "5.2.17", "psycopg": "3.3.6"}.__getitem__,
        ):
            self.assertTrue(sb.pinned_runtime_ready())
        with patch.object(sb.importlib.metadata, "version", return_value="wrong"):
            self.assertFalse(sb.pinned_runtime_ready())
        with patch.object(
            sb.importlib.metadata, "version", side_effect=sb.importlib.metadata.PackageNotFoundError
        ):
            self.assertFalse(sb.pinned_runtime_ready())
        path.write_text("--index-url https://private.invalid\n", encoding="utf8")
        self.assertFalse(sb.pinned_runtime_ready())

    def doctor_patches(self, ready=True):
        patches = (
            patch.object(sb, "project_python", return_value=True),
            patch.object(sb, "pinned_runtime_ready", return_value=ready),
            patch.object(sb, "node_ready", return_value=False),
            patch.object(sb, "source_available", return_value=False),
            patch.object(sb.shutil, "which", return_value=None),
        )
        for mocked in patches:
            mocked.start()
            self.addCleanup(mocked.stop)

    def test_missing_optional_labs_do_not_fail_console_doctor_or_claim_full_readiness(self):
        self.doctor_patches()
        output = io.StringIO()
        with (
            redirect_stdout(output),
            patch.object(sb.subprocess, "run", side_effect=AssertionError("no external checks")),
        ):
            sb.doctor()
        text = output.getvalue()
        self.assertIn("Synthetic demo prerequisites: incomplete", text)
        self.assertIn("Offline proof prerequisites: incomplete", text)
        self.assertIn("NOT PROVIDED bettail migration inputs", text)
        self.assertIn("engine, capacity and isolation not checked", text)
        self.assertIn("does not prove a running server", text)

    def test_missing_runtime_packages_fail_doctor(self):
        self.doctor_patches(ready=False)
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as error:
            sb.doctor()
        self.assertEqual(error.exception.code, 1)

    def test_source_preflight_respects_explicit_checkout_and_rejects_empty_migrations(self):
        source = self.root / "explicit"
        migrations = source / "supabase/migrations"
        migrations.mkdir(parents=True)
        with patch.dict(os.environ, {"BETTAIL_REPO": str(source)}):
            self.assertFalse(sb.source_available("bettail"))
            (migrations / "202609240001_synthetic.sql").write_text("select 1;", encoding="utf8")
            self.assertTrue(sb.source_available("bettail"))

    def test_setup_preserves_fixed_local_accounts_and_provisions_all_three_workspace_roles(self):
        with patch.object(sb, "manage") as manage:
            sb.setup()
        self.assertEqual(
            manage.call_args_list,
            [
                call("migrate", "--noinput"),
                call("bootstrap"),
                call(
                    "setup_scanners",
                    "--grant",
                    "analyst:analyst",
                    "--grant",
                    "reviewer:reviewer",
                    "--grant",
                    "viewer:viewer",
                ),
            ],
        )

    def test_core_verification_uses_recorded_offline_checks_without_source_apps_or_server(self):
        with (
            patch.object(sb, "run") as run,
            patch.object(sb, "test_apps", side_effect=AssertionError("private source required")),
            patch.object(sb, "up", side_effect=AssertionError("server started")),
            patch.object(sb, "setup", side_effect=AssertionError("live database changed")),
        ):
            sb.verify("core")
        run.assert_called_once_with(sb.sys.executable, "scripts/record_verification.py")

    def test_m1_remains_nonzero_without_discarding_separate_http_evidence(self):
        output = io.StringIO()
        with (
            patch.object(sb, "test") as test,
            patch.object(sb, "test_apps") as apps,
            redirect_stdout(output),
            self.assertRaises(SystemExit) as error,
        ):
            sb.verify("m1")
        self.assertEqual(error.exception.code, 2)
        test.assert_called_once_with()
        apps.assert_called_once_with("bettail")
        self.assertIn("Separately recorded HTTP/Auth/Storage evidence", output.getvalue())

    def test_test_command_runs_only_the_three_fixed_mock_node_targets(self):
        with (
            patch.object(sb, "require_node"),
            patch.object(sb, "manage") as manage,
            patch.object(sb, "run") as run,
        ):
            sb.test()
        self.assertEqual(
            manage.call_args_list, [call("check"), call("test", "tests", "--verbosity", "1")]
        )
        self.assertEqual(
            run.call_args_list,
            [
                call(
                    "node",
                    "--test",
                    "--test-isolation=none",
                    "--test-reporter=tap",
                    "integrations/sender.test.mjs",
                ),
                call(
                    "node",
                    "--test",
                    "--test-isolation=none",
                    "--test-reporter=tap",
                    "integrations/supabase-http.test.mjs",
                ),
                call(
                    "node",
                    "--test",
                    "--test-isolation=none",
                    "--test-reporter=tap",
                    "integrations/bettail-routes.test.mjs",
                ),
            ],
        )

    def test_demo_preflights_node_and_fixtures_before_initializing_local_data(self):
        with patch.object(sb, "node_ready", return_value=False), patch.object(sb, "setup") as setup:
            with self.assertRaises(SystemExit):
                sb.demo_core()
            setup.assert_not_called()
        with patch.object(sb, "require_node"), patch.object(sb, "setup") as setup:
            with self.assertRaisesRegex(SystemExit, "fixture files are missing"):
                sb.demo_core()
            setup.assert_not_called()

    def test_demo_core_uses_only_explicit_synthetic_source_and_preserves_existing_data(self):
        self.fixtures()
        output = io.StringIO()
        with (
            patch.object(sb, "require_node"),
            patch.object(sb, "setup") as setup,
            patch.object(sb, "up") as up,
            patch.object(sb, "run") as run,
            patch.object(sb, "manage") as manage,
            patch.object(sb, "test_apps", side_effect=AssertionError("private repo read")),
            redirect_stdout(output),
        ):
            sb.demo_core()
        setup.assert_called_once_with()
        up.assert_called_once_with()
        run.assert_called_once_with("node", "integrations/demo-synthetic.mjs")
        self.assertEqual(
            manage.call_args_list, [call("work", "--once"), call("seed_replays"), call("evidence")]
        )
        self.assertIn("source class synthetic_demo", output.getvalue())
        self.assertIn("existing data is preserved", output.getvalue())

    def test_source_lab_preflight_refuses_missing_sources_and_arbitrary_selection(self):
        with (
            patch.object(sb, "require_node"),
            patch.object(sb, "source_available", return_value=False),
            patch.object(sb, "run") as run,
        ):
            for app in ("all", "https://untrusted.invalid", "../../other"):
                with self.subTest(app=app), self.assertRaises(SystemExit):
                    sb.test_apps(app)
            run.assert_not_called()

    def test_child_failure_is_propagated_and_uses_local_working_directory(self):
        with patch.object(
            sb.subprocess, "run", return_value=subprocess.CompletedProcess([], 9)
        ) as run:
            with self.assertRaises(SystemExit) as error:
                sb.run("fixed-command")
        self.assertEqual(error.exception.code, 9)
        self.assertEqual(run.call_args.kwargs["cwd"], self.root)
        self.assertEqual(run.call_args.kwargs["env"]["SB_MODE"], "local")
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_missing_executable_has_safe_actionable_error(self):
        with (
            patch.object(sb.subprocess, "run", side_effect=OSError("private-path-sentinel")),
            self.assertRaises(SystemExit) as error,
        ):
            sb.run("missing-command")
        self.assertIn("doctor", str(error.exception))
        self.assertNotIn("private-path-sentinel", str(error.exception))
