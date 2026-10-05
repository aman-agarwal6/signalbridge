"""Host orchestration denial paths with substitutes; no daemon, ACL changes or VM."""

import copy
import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from integrations.enterprise import reference_host_controls as host
from integrations.enterprise import verification as base
from integrations.enterprise import windows_capacity
from integrations.enterprise.reference_controls import expected_config
from integrations.enterprise.reference_host_evidence import validate_shutdown
from scripts import enterprise_reference_verify as launch

RUN, DB, RUNNER = "a" * 32, "b" * 64, "c" * 64
IMAGES = {"database": "sha256:" + "d" * 64, "runner": "sha256:" + "e" * 64}


class ReferenceHostLaunchTests(SimpleTestCase):
    def setUp(self):
        self.parent = Path(__file__).resolve().parents[1] / "var/tests"
        self.workspace = self.parent / ("reference-launch-" + uuid.uuid4().hex)
        self.directory = base.private_run_directory(self.workspace, RUN)
        (self.directory / "evidence").mkdir(parents=True)
        host.write_control(
            self.workspace, RUN, "watchdog-ready.json", {"run_id": RUN, "armed": True}
        )
        self.guard = Mock()
        self.guard.poll.return_value = None
        self.addCleanup(self.cleanup)

    def cleanup(self):
        path = self.workspace.resolve()
        if not path.is_relative_to(self.parent.resolve()) or self.workspace.is_symlink():
            raise RuntimeError("Unsafe launcher test cleanup.")
        shutil.rmtree(path)

    def test_inherited_proxy_database_preloads_and_compose_settings_are_removed(self):
        with patch.dict(
            os.environ,
            {
                "PGHOST": "outside.invalid",
                "SB_SECRET_KEY": "nonfunctional-secret",
                "HTTP_PROXY": "outside.invalid",
                "SSLKEYLOGFILE": "outside.log",
                "PYTHONPATH": "outside",
                "DOCKER_HOST": "outside.invalid",
                "COMPOSE_FILE": "outside",
            },
        ):
            environment = launch.clean_environment()
        for name in (
            "PGHOST",
            "SB_SECRET_KEY",
            "HTTP_PROXY",
            "SSLKEYLOGFILE",
            "PYTHONPATH",
            "DOCKER_HOST",
            "COMPOSE_FILE",
        ):
            self.assertNotIn(name, environment)
        self.assertEqual(environment["COMPOSE_DISABLE_ENV_FILE"], "1")

    def test_failed_or_malformed_windows_memory_probe_never_authorizes_capacity(self):
        def query(pointer):
            value = pointer._obj
            value.total_physical = 16 * base.GIB
            value.available_physical = 8 * base.GIB
            return 1

        query_mock = Mock(side_effect=query)
        library = Mock(GlobalMemoryStatusEx=query_mock)
        with (
            patch.object(windows_capacity.sys, "platform", "win32"),
            patch.object(
                windows_capacity.ctypes, "WinDLL", return_value=library, create=True
            ) as load,
        ):
            self.assertEqual(windows_capacity.available_memory(), 8 * base.GIB)
            self.assertEqual(load.call_args.kwargs["winmode"], 0x800)
            query_mock.side_effect = None
            query_mock.return_value = 0
            with self.assertRaises(base.LabControlError):
                windows_capacity.available_memory()

    def test_windows_program_data_survives_without_inheriting_private_configuration(self):
        with patch.dict(
            os.environ,
            {
                "ProgramData": r"C:\ProgramData",
                "PGPASSWORD": "nonfunctional-synthetic-value",
                "DOCKER_HOST": "tcp://outside.invalid:2375",
            },
            clear=True,
        ):
            environment = launch.clean_environment()
        self.assertEqual(
            {name.upper(): value for name, value in environment.items()}["PROGRAMDATA"],
            r"C:\ProgramData",
        )
        self.assertNotIn("PGPASSWORD", environment)
        self.assertNotIn("DOCKER_HOST", environment)

    def test_private_acl_call_has_literal_arguments_and_no_policy_bypass(self):
        result = b'{"private_acl_verified":true,"inherited_public_access_removed":true}'
        with (
            patch.object(launch.sys, "platform", "win32"),
            patch.object(launch, "invoke", return_value=result) as invoke,
        ):
            launch.private_acl(RUN, "Verify")
            arguments = [str(v) for v in invoke.call_args.args[0]]
            self.assertEqual(arguments[-4:], ["-Run", RUN, "-Mode", "Verify"])
            self.assertNotIn("-ExecutionPolicy", arguments)
            with self.assertRaises(base.LabControlError):
                launch.private_acl("../../other", "Verify")
            invoke.assert_called_once()

    def test_certificate_receipt_is_closed_and_bound_to_actual_public_files(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        directory = self.directory / "secrets"
        directory.mkdir()
        raw = b"Nonfunctional public certificate metadata test marker."
        digest = hashlib.sha256(raw).hexdigest()
        for name in ("lab-ca.pem", "source-certificate.pem", "console-certificate.pem"):
            (directory / name).write_bytes(raw)
        value = {
            "run_id": RUN,
            "authority_sha256": digest,
            "server_certificate_sha256": {"source": digest, "console": digest},
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=2)).isoformat(),
            "loopback_only": True,
            "host_trust_changed": False,
            "signing_key_persisted": False,
            "python_version": "3.12.14",
            "cryptography_version": "50.0.1",
        }
        self.assertEqual(launch.certificate_metadata(value, RUN, self.directory), value)
        for changed in (
            {"private_key": "nonfunctional-extra-field"},
            {"host_trust_changed": True},
            {"run_id": "f" * 32},
            {"authority_sha256": "f" * 64},
            {"expires_at": (now + timedelta(hours=3)).isoformat()},
        ):
            with self.subTest(fields=list(changed)), self.assertRaises(base.LabControlError):
                launch.certificate_metadata({**value, **changed}, RUN, self.directory)

    def test_source_profile_is_recorded_first_and_uses_distinct_closed_credentials(self):
        # Known test-only markers are never used by an operational source service.
        with patch.object(
            launch.secrets, "token_urlsafe", side_effect=[c * 64 for c in "abcdefghijklmn"]
        ):
            launch.prepare_credentials(self.directory)
        directory = self.directory / "secrets"
        self.assertEqual(
            {p.name for p in directory.iterdir()},
            {"source-profile", "bootstrap-password", "source-password", "console-password"},
        )
        values = launch.profile(directory / "source-profile")
        self.assertEqual(set(values), launch.FIELDS)
        self.assertEqual(set(values["accounts"]), launch.ACCOUNTS)
        with self.assertRaises(FileExistsError):
            launch.prepare_credentials(self.directory)

    def test_private_docker_configuration_only_names_the_installed_compose_plugin(self):
        resources = self.workspace / "nonfunctional-docker-resources"
        plugins = resources / "cli-plugins"
        plugins.mkdir(parents=True)
        docker = resources / "bin/docker.exe"
        with self.assertRaises(base.LabControlError):
            launch.private_docker_config(self.directory, docker)
        self.assertFalse((self.directory / "docker-config").exists())
        (plugins / "docker-compose.exe").write_bytes(b"nonfunctional marker; never executed")
        config = launch.private_docker_config(self.directory, docker)
        self.assertEqual(
            json.loads((config / "config.json").read_bytes()),
            {"cliPluginsExtraDirs": [str(plugins)]},
        )
        with self.assertRaises(FileExistsError):
            launch.private_docker_config(self.directory, docker)

    def test_guard_expiry_abort_wrong_identity_and_duplicate_fields_refuse_execution(self):
        ready = self.directory / "watchdog-ready.json"
        for variant in ("expired", "abort", "wrong", "duplicate"):
            self.guard.poll.return_value = 0 if variant == "expired" else None
            ready.write_text('{"run_id":"' + RUN + '","armed":true}', encoding="ascii")
            if variant == "abort":
                (self.directory / "watchdog-abort.json").write_text("{}", encoding="ascii")
            elif variant == "wrong":
                ready.write_text('{"run_id":"' + "f" * 32 + '","armed":true}', encoding="ascii")
            elif variant == "duplicate":
                ready.write_text(
                    '{"run_id":"' + RUN + '","armed":false,"armed":true}', encoding="ascii"
                )
            with self.subTest(variant=variant), self.assertRaises(base.LabControlError):
                launch.require_guard(self.guard, RUN, self.directory)
            abort = self.directory / "watchdog-abort.json"
            if abort.exists():
                abort.unlink()

    def test_new_foreign_running_container_needs_review_without_stopping_it(self):
        for output in ("f" * 64, DB + "\n" + DB, "short-id"):
            with patch.object(base, "docker_result", return_value=output) as daemon:
                with self.assertRaises(base.LabControlError):
                    launch.no_foreign_running("unused", {DB, RUNNER})
                daemon.assert_called_once_with("unused", ["ps", "--quiet", "--no-trunc"], timeout=5)

    def exercise(
        self,
        *,
        configuration=None,
        runtime_failure=False,
        created_running=False,
        health="running|healthy",
        exit_state="exited|0",
        abort_at_start=False,
    ):
        calls = []
        configuration = configuration or expected_config(IMAGES, RUN, self.directory)

        def invoke(arguments, *_args):
            calls.append(tuple(arguments))
            return json.dumps(configuration).encode("ascii") if "config" in arguments else b""

        def daemon(_docker, arguments, **_kwargs):
            calls.append(tuple(arguments))
            if arguments[:1] == ["start"]:
                if abort_at_start and arguments[-1] == RUNNER:
                    (self.directory / "watchdog-abort.json").write_text("{}", encoding="ascii")
                return arguments[-1]
            if arguments[:2] in (["network", "ls"], ["volume", "ls"]):
                return ""
            if arguments[:1] == ["ps"]:
                return ""
            if arguments[-1] == "{{.State.Status}}":
                return "running" if created_running else "created"
            if arguments[-1] == "{{.State.Status}}|{{.State.Health.Status}}":
                return health
            if arguments[-1] == "{{.State.Status}}|{{.State.ExitCode}}":
                return exit_state
            raise AssertionError("Unexpected substitute daemon argument.")

        with (
            patch.object(launch, "compose_command", return_value=["docker", "compose"]),
            patch.object(launch, "invoke", side_effect=invoke),
            patch.object(launch, "check_capacity"),
            patch.object(launch, "private_acl"),
            patch.object(host, "owned", return_value={}),
            patch.object(
                launch,
                "exact_components",
                side_effect=base.LabControlError("unsafe runtime") if runtime_failure else None,
                return_value={DB: "database", RUNNER: "runner"},
            ),
            patch.object(base, "docker_result", side_effect=daemon),
        ):
            try:
                result = launch.execute("docker", RUN, self.directory, IMAGES, {}, self.guard)
            except base.LabControlError:
                result = None
        return result, calls

    def test_create_verify_start_and_gate_order_with_no_pull_or_build(self):
        result, calls = self.exercise()
        self.assertTrue(result["runtime_isolation_verified"])
        self.assertIn(
            ("docker", "compose", "create", "--no-build", "--pull", "never", "--no-recreate"), calls
        )
        self.assertEqual([c for c in calls if c[0] == "start"], [("start", DB), ("start", RUNNER)])
        self.assertTrue((self.directory / "evidence/allow-source.json").is_file())
        self.assertFalse(any("up" in c or "--build" in c or "pull" == c[0] for c in calls))

    def test_changed_recipe_effective_runtime_or_unexpected_start_blocks_both_starts(self):
        changed = copy.deepcopy(expected_config(IMAGES, RUN, self.directory))
        changed["services"]["runner"]["privileged"] = True
        for settings in (
            {"configuration": changed},
            {"runtime_failure": True},
            {"created_running": True},
        ):
            with self.subTest(settings=settings):
                result, calls = self.exercise(**settings)
                self.assertIsNone(result)
                self.assertFalse(any(c[0] == "start" for c in calls))
                self.assertFalse((self.directory / "evidence/allow-source.json").exists())

    def test_database_failure_does_not_start_runner_and_guard_abort_never_writes_gate(self):
        result, calls = self.exercise(health="exited|unhealthy")
        self.assertIsNone(result)
        self.assertEqual([c for c in calls if c[0] == "start"], [("start", DB)])
        result, _ = self.exercise(abort_at_start=True)
        self.assertIsNone(result)
        self.assertFalse((self.directory / "evidence/allow-source.json").exists())

    def test_runner_failure_is_incomplete_even_after_gate_was_written(self):
        result, _ = self.exercise(exit_state="exited|1")
        self.assertIsNone(result)

    def test_independent_shutdown_requires_exact_count_identity_reason_and_time(self):
        now = datetime.now(timezone.utc)
        main = {"run_id": RUN, "shutdown_verified": True, "stopped_component_count": 2}
        independent = {**main, "reason": "launcher_finished", "stopped_at": now.isoformat()}
        self.assertTrue(
            validate_shutdown(
                main, independent, RUN, started=now - timedelta(seconds=1), finished=now
            )["independent_shutdown_verified"]
        )
        for change in (
            {"run_id": "f" * 32},
            {"reason": "deadline"},
            {"stopped_component_count": True},
            {"shutdown_verified": 1},
            {"error_class": "TimeoutError"},
            {"stopped_at": (now + timedelta(seconds=1)).isoformat()},
        ):
            with self.subTest(change=change), self.assertRaises(base.LabControlError):
                validate_shutdown(
                    main,
                    {**independent, **change},
                    RUN,
                    started=now - timedelta(seconds=1),
                    finished=now,
                )

    def test_launcher_failure_still_stops_scope_and_keeps_guard_alive(self):
        new_run = "f" * 32
        docker = self.workspace / "not-executed-docker.exe"
        docker.write_bytes(b"nonfunctional test marker")
        directory = base.private_run_directory(self.workspace, new_run)

        def wait(**_kwargs):
            host.write_control(
                self.workspace,
                new_run,
                "watchdog.json",
                {
                    "run_id": new_run,
                    "shutdown_verified": True,
                    "stopped_component_count": 2,
                    "reason": "launcher_finished",
                    "stopped_at": datetime.now(timezone.utc).isoformat(),
                },
            )

        self.guard.wait.side_effect = wait
        manifest = {"sha256": "a" * 64, "files": {}, "file_count": 0}
        with (
            patch.object(launch.sys, "platform", "win32"),
            patch.object(launch, "ROOT", self.workspace),
            patch.object(launch.uuid, "uuid4", return_value=Mock(hex=new_run)),
            patch.object(
                launch,
                "check_capacity",
                return_value={"free_disk_bytes": 70 * base.GIB, "free_memory_bytes": 8 * base.GIB},
            ),
            patch.object(launch, "certificate_runtime"),
            patch.object(launch, "invoke"),
            patch.object(base, "docker_result", return_value=""),
            patch.object(base, "inspect_local_image", return_value=IMAGES["database"]),
            patch.object(launch.cached, "inspect_python_image", return_value=IMAGES["runner"]),
            patch.object(
                launch, "prepare", return_value=(manifest, {}, {}, {"wheel_footprint": {}})
            ),
            patch.object(launch, "arm_guard", return_value=self.guard),
            patch.object(launch, "require_guard"),
            patch.object(
                launch, "execute", side_effect=RuntimeError("nonfunctional-private-diagnostic")
            ),
            patch.object(host, "stop_scope", return_value=2) as stop,
            patch.object(launch, "source_manifest", return_value=manifest),
            patch.object(
                launch, "receipt_path", return_value=self.workspace / "public-receipt.json"
            ),
            patch.object(
                launch.time,
                "sleep",
                side_effect=lambda _: host.write_control(
                    self.workspace,
                    new_run,
                    "watchdog-ready.json",
                    {"run_id": new_run, "armed": True},
                ),
            ),
        ):
            result_directory, passed = launch.launch(
                docker, "test-only-model-not-authorization", RUN, docker
            )
        self.assertEqual(result_directory, directory)
        self.assertFalse(passed)
        stop.assert_called_once_with(docker, new_run)
        self.guard.terminate.assert_not_called()
        self.guard.kill.assert_not_called()
        receipt = (directory / "receipt.json").read_text(encoding="ascii")
        self.assertNotIn("nonfunctional-private-diagnostic", receipt)
        self.assertEqual(json.loads(receipt)["error_class"], "RuntimeError")
