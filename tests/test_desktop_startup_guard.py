"""Inert startup safety regressions: every native process primitive is mocked."""

import copy
import json
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from integrations.enterprise import desktop_startup_guard as guard

RUN = "a" * 32
DIRECTORY = Path("synthetic-run")


class DesktopStartupGuardTests(unittest.TestCase):
    def setUp(self):
        # Unexpected native invocation fails the test instead of starting a
        # process. Individual tests may replace a boundary with a narrower fake.
        self.native_run = self.enterContext(
            patch.object(
                guard.subprocess,
                "run",
                side_effect=AssertionError("Native command forbidden in test"),
            )
        )
        self.native_popen = self.enterContext(
            patch.object(
                guard.subprocess,
                "Popen",
                side_effect=AssertionError("Native process forbidden in test"),
            )
        )
        for name in ("CREATE_NO_WINDOW", "DETACHED_PROCESS", "CREATE_NEW_PROCESS_GROUP"):
            self.enterContext(patch.object(guard.subprocess, name, 0, create=True))

    def clock(self):
        value = [0.0]
        self.enterContext(patch.object(guard.time, "time", side_effect=lambda: 1000 + value[0]))
        self.enterContext(patch.object(guard.time, "monotonic", side_effect=lambda: value[0]))
        self.enterContext(
            patch.object(
                guard.time, "sleep", side_effect=lambda n: value.__setitem__(0, value[0] + n)
            )
        )
        return value

    def test_missing_programdata_refuses_before_any_process(self):
        environment = {name: "C:\\synthetic" for name in guard.REQUIRED_PATHS - {"PROGRAMDATA"}}
        environment["PATH"] = "C:\\synthetic"
        environment["SYSTEMDRIVE"] = "C:"
        with (
            patch.object(guard.sys, "platform", "win32"),
            patch.object(guard, "clean_environment", return_value=environment),
            self.assertRaises(guard.LabControlError),
        ):
            guard.DesktopStartup(
                "C:\\synthetic\\docker.exe", "reviewed", 60 * guard.GIB
            ).__enter__()
        self.native_run.assert_not_called()
        self.native_popen.assert_not_called()

    def test_required_environment_has_no_synthesized_fallback(self):
        value = {name: "C:\\synthetic" for name in guard.REQUIRED_PATHS}
        value["PATH"] = "C:\\synthetic"
        value["SYSTEMDRIVE"] = "C:"
        with (
            patch.object(guard, "clean_environment", return_value=value),
            patch.object(Path, "is_absolute", return_value=True),
            patch.object(Path, "is_dir", return_value=True),
        ):
            self.assertEqual(guard.environment(), value)
        with (
            patch.object(guard, "clean_environment", return_value=value),
            patch.object(Path, "is_absolute", return_value=True),
            patch.object(Path, "is_dir", return_value=False),
            self.assertRaises(guard.LabControlError),
        ):
            guard.environment()

    def test_clean_environment_preserves_os_drive_without_private_configuration(self):
        with patch.dict(
            guard.os.environ,
            {
                "SystemDrive": "C:",
                "ProgramData": r"C:\ProgramData",
                "PGPASSWORD": "synthetic-nonfunctional",
                "DOCKER_HOST": "outside.invalid",
            },
            clear=True,
        ):
            value = {name.upper(): item for name, item in guard.clean_environment().items()}
        self.assertEqual(value["SYSTEMDRIVE"], "C:")
        self.assertEqual(value["PROGRAMDATA"], r"C:\ProgramData")
        self.assertNotIn("PGPASSWORD", value)
        self.assertNotIn("DOCKER_HOST", value)

    def test_systemdrive_required_and_validated_as_existing_absolute_root(self):
        value = {name: "C:\\synthetic" for name in guard.REQUIRED_PATHS}
        value["PATH"] = "C:\\synthetic"
        for invalid in (None, "", "C", "C:\\", "%SystemDrive%", "C:relative", "\\\\server\\share"):
            changed = dict(value)
            if invalid is not None:
                changed["SYSTEMDRIVE"] = invalid
            with (
                self.subTest(value=invalid),
                patch.object(guard, "clean_environment", return_value=changed),
                patch.object(guard.sys, "platform", "win32"),
                self.assertRaises(guard.LabControlError),
            ):
                guard.DesktopStartup(
                    "C:\\synthetic\\docker.exe", "reviewed", 60 * guard.GIB
                ).__enter__()
        self.native_run.assert_not_called()
        self.native_popen.assert_not_called()
        with (
            patch.object(guard, "clean_environment", return_value={**value, "SYSTEMDRIVE": "C:"}),
            patch.object(Path, "is_absolute", autospec=True, return_value=True) as absolute,
            patch.object(Path, "is_dir", autospec=True, return_value=True) as directory,
        ):
            guard.environment()
        self.assertEqual(absolute.call_args_list[0].args, (Path("C:\\"),))
        self.assertEqual(directory.call_args_list[0].args, (Path("C:\\"),))
        with (
            patch.object(guard, "clean_environment", return_value={**value, "SYSTEMDRIVE": "C:"}),
            patch.object(Path, "is_absolute", return_value=True),
            patch.object(Path, "is_dir", return_value=False),
            self.assertRaises(guard.LabControlError),
        ):
            guard.environment()

    def test_unavailable_inventory_still_requests_desktop_stop(self):
        self.clock()
        with (
            patch.object(guard, "inventory", return_value="unavailable"),
            patch.object(guard, "command", return_value="") as command,
            patch.object(guard, "desktop_status", return_value="stopped"),
        ):
            value = guard.shutdown_owned("docker", {}, 1120)
        self.assertTrue(value["desktop_stop_requested"])
        self.assertTrue(value["inventory_unavailable_seen"])
        self.assertTrue(value["shutdown_verified"])
        self.assertGreaterEqual(value["stopped_observation_seconds"], 30)
        self.assertFalse(value["daemon_request_settlement_verified"])
        self.assertTrue(
            all(
                call.args[1] == ["desktop", "stop", "--timeout", "15"]
                for call in command.call_args_list
            )
        )

    def test_installed_desktop_status_allows_only_observed_optional_session_id(self):
        value = {"SessionID": "6a5d7443-4da4-43bc-a454-c7a4d512fa51", "Status": "running"}
        with patch.object(guard, "command", return_value=json.dumps(value)):
            self.assertEqual(guard.desktop_status("docker", {}), "running")
        for changed in (
            {**value, "unknown": True},
            {**value, "SessionID": "malformed"},
            {**value, "status": "stopped"},
        ):
            with (
                patch.object(guard, "command", return_value=json.dumps(changed)),
                self.assertRaises(guard.LabControlError),
            ):
                guard.desktop_status("docker", {})

    def test_cli_error_requires_independent_process_and_pipe_absence(self):
        observed = {}
        with (
            patch.object(
                guard, "command", side_effect=guard.LabControlError("Synthetic nonzero CLI")
            ),
            patch.object(guard, "desktop_process_count", return_value=0),
            patch.object(guard, "engine_pipe_absent", return_value=True),
        ):
            self.assertEqual(guard.desktop_status("docker", {}, capture=observed), "stopped")
        self.assertEqual(observed["source"], "windows_process_and_pipe_absence")
        for count, absent in ((1, True), (0, False)):
            with (
                patch.object(
                    guard, "command", side_effect=guard.LabControlError("Synthetic failure")
                ),
                patch.object(guard, "desktop_process_count", return_value=count),
                patch.object(guard, "engine_pipe_absent", return_value=absent),
                self.assertRaises(guard.LabControlError),
            ):
                guard.desktop_status("docker", {})
        with (
            patch.object(guard, "command", side_effect=guard.LabControlError("Synthetic failure")),
            patch.object(
                guard, "desktop_process_count", side_effect=OSError("Synthetic inaccessible query")
            ),
            patch.object(guard, "engine_pipe_absent") as pipe,
            self.assertRaises(OSError),
        ):
            guard.desktop_status("docker", {})
        pipe.assert_not_called()

    def test_engine_pipe_access_denied_is_never_absence(self):
        kernel = MagicMock()
        kernel.WaitNamedPipeW.return_value = 0
        with (
            patch.object(guard.sys, "platform", "win32"),
            patch.object(guard.ctypes, "WinDLL", return_value=kernel, create=True),
            patch.object(guard.ctypes, "set_last_error", create=True),
            patch.object(guard.ctypes, "get_last_error", return_value=2, create=True),
        ):
            self.assertTrue(guard.engine_pipe_absent())
        with (
            patch.object(guard.sys, "platform", "win32"),
            patch.object(guard.ctypes, "WinDLL", return_value=kernel, create=True),
            patch.object(guard.ctypes, "set_last_error", create=True),
            patch.object(guard.ctypes, "get_last_error", return_value=5, create=True),
            self.assertRaises(guard.LabControlError),
        ):
            guard.engine_pipe_absent()

    def test_independent_guard_is_armed_before_desktop_start_intent(self):
        self.clock()
        written, calls = {}, []
        measured = {"within_limits": True, "free_disk_bytes": 60 * guard.GIB}
        child = MagicMock()
        child.poll.return_value = None
        starter = MagicMock(returncode=0)
        starter.poll.return_value = 0

        def popen(arguments, **_):
            calls.append(arguments)
            if "watchdog" in arguments:
                self.assertNotIn("intent", written)
                written["ready"] = {"run_id": RUN, "armed": True}
                return child
            self.assertEqual(arguments[1:], ["desktop", "start", "--timeout", "90"])
            self.assertEqual(written["intent"], {"run_id": RUN, "start_requested": True})
            return starter

        with (
            patch.object(guard.sys, "platform", "win32"),
            patch.object(guard, "environment", return_value={}),
            patch.object(guard, "sample", return_value=measured),
            patch.object(guard, "desktop_status", side_effect=["stopped", "stopped", "running"]),
            patch.object(guard, "inventory", return_value="empty"),
            patch.object(guard.uuid, "uuid4", return_value=SimpleNamespace(hex=RUN)),
            patch.object(guard, "private_run_directory", return_value=DIRECTORY),
            patch.object(guard, "private_acl"),
            patch.object(Path, "is_absolute", return_value=True),
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "is_symlink", return_value=False),
            patch.object(Path, "lstat", return_value=SimpleNamespace(st_file_attributes=0)),
            patch.object(Path, "mkdir"),
            patch.object(guard, "present", side_effect=lambda _d, name: name in written),
            patch.object(guard, "load", side_effect=lambda _d, name: written[name]),
            patch.object(
                guard,
                "control",
                side_effect=lambda _d, name, value: written.update({name: copy.deepcopy(value)}),
            ),
            patch.object(guard.subprocess, "Popen", side_effect=popen),
        ):
            instance = guard.DesktopStartup(
                "C:\\synthetic\\docker.exe", "reviewed", 60 * guard.GIB
            ).__enter__()
            instance.start()
        self.assertEqual(len(calls), 2)
        self.assertIn("watchdog", calls[0])
        self.assertEqual(written["phase"], {"run_id": RUN, "phase": "acquisition"})

    def test_reachable_foreign_workload_is_not_stopped(self):
        self.clock()
        with (
            patch.object(guard, "inventory", return_value="foreign"),
            patch.object(guard, "command") as command,
        ):
            value = guard.shutdown_owned("docker", {}, 1120)
        self.assertTrue(value["foreign_workload_preserved"])
        self.assertFalse(value["shutdown_verified"])
        command.assert_not_called()

    def test_timeout_is_not_shutdown_and_late_start_resets_observation(self):
        clock = self.clock()

        def status(*_, **__):
            return "starting" if 10 <= clock[0] < 20 else "stopped"

        with (
            patch.object(guard, "inventory", return_value="unavailable"),
            patch.object(guard, "command", side_effect=subprocess.TimeoutExpired("synthetic", 15)),
            patch.object(guard, "desktop_status", side_effect=status),
        ):
            value = guard.shutdown_owned("docker", {}, 1120)
        self.assertTrue(value["cli_timeout_seen"])
        self.assertTrue(value["shutdown_verified"])
        self.assertGreaterEqual(clock[0], 50)
        self.assertFalse(value["daemon_request_settlement_verified"])

    def test_unreachable_desktop_never_claims_shutdown(self):
        clock = self.clock()
        with (
            patch.object(guard, "inventory", return_value="unavailable"),
            patch.object(guard, "command", side_effect=subprocess.TimeoutExpired("synthetic", 15)),
            patch.object(guard, "desktop_status", side_effect=ValueError("synthetic")),
        ):
            value = guard.shutdown_owned("docker", {}, 1010)
        self.assertFalse(value["shutdown_verified"])
        self.assertLessEqual(clock[0], 10)

    def test_capacity_sampling_failure_does_not_bypass_shutdown(self):
        self.clock()
        with (
            patch.object(guard, "inventory", return_value="unavailable"),
            patch.object(guard, "command", return_value="") as command,
            patch.object(guard, "desktop_status", return_value="stopped"),
        ):
            value = guard.shutdown_owned(
                "docker", {}, 1120, MagicMock(side_effect=OSError("synthetic"))
            )
        self.assertEqual(value["last_capacity_error_class"], "OSError")
        self.assertTrue(value["shutdown_verified"])
        command.assert_called()

    def test_capacity_breach_is_retained_without_claiming_hard_quota(self):
        with (
            patch.object(
                guard.shutil, "disk_usage", return_value=SimpleNamespace(free=30 * guard.GIB)
            ),
            patch.object(guard, "available_memory", return_value=471871488),
        ):
            value = guard.sample(70 * guard.GIB)
        self.assertFalse(value["within_limits"])
        self.assertEqual(value["available_memory_bytes"], 471871488)
        self.assertEqual(value["stage_free_space_decrease_bytes"], 40 * guard.GIB)

    def test_watchdog_setup_failure_after_intent_still_shuts_down(self):
        self.clock()
        written = {}

        def load(_directory, name):
            if name == "intent":
                return {"run_id": RUN, "start_requested": True}
            raise ValueError("Synthetic malformed context")

        with (
            patch.object(guard, "private_run_directory", return_value=DIRECTORY),
            patch.object(Path, "is_dir", return_value=True),
            patch.object(guard, "environment", return_value={}),
            patch.object(guard, "private_acl"),
            patch.object(guard, "load", side_effect=load),
            patch.object(guard, "present", side_effect=lambda _d, name: name == "intent"),
            patch.object(
                guard,
                "control",
                side_effect=lambda _d, name, value: written.update({name: copy.deepcopy(value)}),
            ),
            patch.object(
                guard, "shutdown_owned", return_value={"shutdown_verified": True}
            ) as shutdown,
        ):
            value = guard.watchdog(RUN, Path("docker"), 1120)
        shutdown.assert_called_once()
        self.assertNotIn("ready", written)
        self.assertEqual(written["watchdog"], value)
        self.assertEqual(value["reason"], "guard_failure")

    def test_start_cannot_run_before_watchdog_admission(self):
        instance = guard.DesktopStartup("C:\\synthetic\\docker.exe", "reviewed", 60 * guard.GIB)
        with self.assertRaises(guard.LabControlError):
            instance.start()
        self.native_popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
