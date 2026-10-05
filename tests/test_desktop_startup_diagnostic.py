"""Startup-only diagnostic regressions; all native/service boundaries are inert."""

import copy
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from scripts import enterprise_desktop_startup_verify as driver

guard = driver.guard
STAGE_RUN, GUARD_RUN = "a" * 32, "b" * 32
STAGE, OWNED = Path("synthetic-stage"), Path("synthetic-guard")
BASELINE = 60 * guard.GIB
APPROVAL = "synthetic-reviewed-approval"


def capacity(within=True):
    return {
        "free_disk_bytes": BASELINE,
        "available_memory_bytes": 8 * guard.GIB,
        "stage_free_space_decrease_bytes": 0,
        "within_limits": within,
    }


def receipts():
    return {
        "context": {
            "run_id": GUARD_RUN,
            "approval_reference": APPROVAL,
            "deadline": 1720,
            "initial_desktop_status": "stopped",
            "stage_initial_free_disk_bytes": BASELINE,
            "capacity_before": capacity(),
        },
        "ready": {"run_id": GUARD_RUN, "armed": True},
        "intent": {"run_id": GUARD_RUN, "start_requested": True},
        "finished": {"run_id": GUARD_RUN},
        "watchdog": {
            "run_id": GUARD_RUN,
            "kind": "docker-desktop-startup-watchdog",
            "reason": "launcher_finished",
            "samples": [capacity()],
            "shutdown_verified": True,
            "shutdown": {
                "shutdown_verified": True,
                "foreign_workload_preserved": False,
                "cli_timeout_seen": False,
                "reason": "observed_stopped_during_bounded_drain",
                "last_desktop_observation": {"status": "stopped"},
                "stopped_observation_seconds": 30,
            },
        },
        "launcher": {
            "run_id": GUARD_RUN,
            "start_requested": True,
            "shutdown_verified": True,
            "guard_pending": False,
            "error_class": None,
            "samples": [capacity()],
        },
    }


class DesktopStartupDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.forbidden = []
        # Even if the driver catches the exception, tearDown fails an unexpected
        # boundary invocation. Narrow per-test substitutes never launch a process.
        for target, name in (
            (guard.subprocess, "run"),
            (guard.subprocess, "Popen"),
            (guard.ctypes, "WinDLL"),
            (guard, "command"),
            (guard, "desktop_process_count"),
            (guard, "engine_pipe_absent"),
            (guard, "available_memory"),
            (guard, "desktop_status"),
            (guard, "inventory"),
            (guard, "private_acl"),
        ):
            self.forbidden.append(
                self.enterContext(
                    patch.object(
                        target,
                        name,
                        side_effect=AssertionError("Native/service boundary forbidden in test"),
                        create=True,
                    )
                )
            )

    def tearDown(self):
        for boundary in self.forbidden:
            boundary.assert_not_called()

    def owner(self):
        return SimpleNamespace(run=GUARD_RUN, directory=OWNED, deadline=1720, env={})

    def reconcile(self, rows=None):
        rows = receipts() if rows is None else rows
        with (
            patch.object(driver, "private_run_directory", return_value=OWNED),
            patch.object(guard, "private_acl"),
            patch.object(guard, "load", side_effect=lambda _d, name: copy.deepcopy(rows[name])),
            patch.object(Path, "read_bytes", return_value=b"synthetic receipt bytes"),
        ):
            return driver.reconcile(self.owner(), BASELINE, APPROVAL)

    def stage(self):
        return {
            "run_id": STAGE_RUN,
            "guard_run_id": GUARD_RUN,
            "finished_at": "synthetic-time",
            "reviewed_file_sha256": {},
            "startup_observed": True,
            "lifecycle": self.reconcile(),
            "final_desktop_observation": {"status": "stopped"},
            "capacity_after_shutdown": capacity(),
        }

    def fake_launch(self, start_error=None, inventory="empty", samples=None, lifecycle=None):
        events, written = [], {}
        default_lifecycle = self.reconcile()
        owner = MagicMock()
        owner.run, owner.directory, owner.deadline, owner.env = GUARD_RUN, OWNED, 1720, {}
        owner.__enter__.side_effect = lambda: events.append("enter") or owner
        owner.__exit__.side_effect = lambda *_: events.append("exit") or False

        def start():
            events.append("start")
            if start_error is not None:
                raise start_error

        owner.start.side_effect = start
        owner.check.side_effect = lambda phase: events.append("check:" + phase)
        measured = iter(samples or [capacity(), capacity(), capacity()])
        observations = iter(["running", "stopped"] if start_error is None else ["stopped"])

        def status(_docker, _env, capture):
            value = next(observations)
            events.append("status:" + value)
            capture.update(status=value, source="desktop_cli_status")
            return value

        def sample(baseline, **_):
            self.assertEqual(baseline, BASELINE)
            events.append("capacity")
            return next(measured)

        def bound(*_):
            events.append("reconcile")
            if isinstance(lifecycle, Exception):
                raise lifecycle
            return lifecycle if lifecycle is not None else copy.deepcopy(default_lifecycle)

        with (
            patch.object(driver, "validate_request", return_value=driver.DOCKER),
            patch.object(guard, "environment", return_value={}),
            patch.object(driver.uuid, "uuid4", return_value=SimpleNamespace(hex=STAGE_RUN)),
            patch.object(driver, "private_run_directory", return_value=STAGE),
            patch.object(Path, "mkdir"),
            patch.object(guard, "private_acl"),
            patch.object(driver, "reviewed_hashes", return_value={}),
            patch.object(
                guard.shutil,
                "disk_usage",
                side_effect=lambda _: events.append("baseline") or SimpleNamespace(free=BASELINE),
            ),
            patch.object(guard, "sample", side_effect=sample),
            patch.object(guard, "DesktopStartup", return_value=owner) as admission,
            patch.object(guard, "desktop_status", side_effect=status),
            patch.object(guard, "inventory", return_value=inventory),
            patch.object(driver, "reconcile", side_effect=bound),
            patch.object(
                driver, "write", side_effect=lambda path, value: written.update({path: value})
            ),
            patch.object(driver, "receipt_path", return_value=Path("synthetic-public.json")),
        ):
            value = driver.launch(driver.DOCKER, APPROVAL)
        return value, events, written, owner, admission

    # The driver only runs from the reviewed checkout folder; CI checks out under the repo name.
    @patch.object(driver, "ROOT", driver.ROOT.with_name("signalbridge-public"))
    def test_validation_requires_exact_existing_absolute_unredirected_executable(self):
        with (
            patch.object(driver.sys, "platform", "win32"),
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "is_absolute", return_value=True),
            patch.object(Path, "is_symlink", return_value=False),
            patch.object(Path, "lstat", return_value=SimpleNamespace(st_file_attributes=0)),
        ):
            self.assertEqual(driver.validate_request(driver.DOCKER, APPROVAL), driver.DOCKER)
            for other in ("docker.exe", r"C:\unreviewed\docker.exe", r"\\server\share\docker.exe"):
                with self.subTest(path=other), self.assertRaises(driver.LabControlError):
                    driver.validate_request(other, APPROVAL)
            for reference in ("", "a" * 81, "$(synthetic)", "approval\nother", None):
                with self.subTest(reference=reference), self.assertRaises(driver.LabControlError):
                    driver.validate_request(driver.DOCKER, reference)
        for name, value in (("is_file", False), ("is_absolute", False), ("is_symlink", True)):
            with (
                self.subTest(check=name),
                patch.object(driver.sys, "platform", "win32"),
                patch.object(Path, "is_file", return_value=True),
                patch.object(Path, "is_absolute", return_value=True),
                patch.object(Path, "is_symlink", return_value=False),
                patch.object(Path, name, return_value=value),
                self.assertRaises(driver.LabControlError),
            ):
                driver.validate_request(driver.DOCKER, APPROVAL)
        with (
            patch.object(driver.sys, "platform", "win32"),
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "is_absolute", return_value=True),
            patch.object(Path, "is_symlink", return_value=False),
            patch.object(Path, "lstat", return_value=SimpleNamespace(st_file_attributes=0x400)),
            self.assertRaises(driver.LabControlError),
        ):
            driver.validate_request(driver.DOCKER, APPROVAL)
        with (
            patch.object(driver, "ROOT", driver.ROOT.with_name("signalbridge")),
            patch.object(driver.sys, "platform", "win32"),
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "is_absolute", return_value=True),
            patch.object(Path, "is_symlink", return_value=False),
            patch.object(Path, "lstat", return_value=SimpleNamespace(st_file_attributes=0)),
            self.assertRaises(driver.LabControlError),
        ):
            driver.validate_request(driver.DOCKER, APPROVAL)

    def test_one_start_baseline_before_admission_and_immediate_scope_exit(self):
        value, events, written, owner, admission = self.fake_launch()
        self.assertTrue(value[2])
        self.assertEqual(
            events,
            [
                "baseline",
                "capacity",
                "enter",
                "start",
                "check:startup",
                "status:running",
                "capacity",
                "check:startup",
                "exit",
                "reconcile",
                "status:stopped",
                "capacity",
            ],
        )
        admission.assert_called_once_with(driver.DOCKER, APPROVAL, BASELINE)
        owner.start.assert_called_once_with()
        owner.__exit__.assert_called_once()
        self.assertEqual(len(written), 2)
        public = written[Path("synthetic-public.json")]
        self.assertEqual(public["status"], "startup_diagnostic_passed")
        self.assertFalse(public["keycloak_or_native_integration_verified"])
        self.assertFalse(public["permanent_desktop_absence_verified"])
        self.assertFalse(public["late_start_origin_established"])

    def test_required_windows_environment_refuses_before_any_process_or_stage(self):
        environment = {name: "C:\\synthetic" for name in guard.REQUIRED_PATHS - {"PROGRAMDATA"}}
        environment.update(PATH="C:\\synthetic", SYSTEMDRIVE="C:")
        with (
            patch.object(driver, "validate_request", return_value=driver.DOCKER),
            patch.object(guard, "clean_environment", return_value=environment),
            patch.object(driver, "private_run_directory") as directory,
            self.assertRaises(driver.LabControlError),
        ):
            driver.launch(driver.DOCKER, APPROVAL)
        directory.assert_not_called()

    def test_startup_failure_exits_and_retains_class_without_error_text_or_retry(self):
        value, _, written, owner, _ = self.fake_launch(
            start_error=subprocess.TimeoutExpired("synthetic-private-command", 90)
        )
        self.assertFalse(value[2])
        owner.start.assert_called_once_with()
        owner.__exit__.assert_called_once()
        public = written[Path("synthetic-public.json")]
        self.assertEqual(public["error_class"], "TimeoutExpired")
        self.assertNotIn("synthetic-private-command", str(written))

    def test_operator_interrupt_closes_scope_and_remains_incomplete(self):
        value, _, written, owner, _ = self.fake_launch(start_error=KeyboardInterrupt())
        self.assertFalse(value[2])
        owner.__exit__.assert_called_once()
        self.assertEqual(written[Path("synthetic-public.json")]["error_class"], "KeyboardInterrupt")

    def test_preflight_failure_never_enters_or_starts(self):
        value, events, _, owner, admission = self.fake_launch(samples=[capacity(False)])
        self.assertFalse(value[2])
        self.assertEqual(events, ["baseline", "capacity"])
        admission.assert_not_called()
        owner.start.assert_not_called()

    def test_overshoot_preserved_and_scope_closed_without_retry(self):
        breached = capacity(False)
        breached.update(
            stage_free_space_decrease_bytes=40 * guard.GIB, available_memory_bytes=471871488
        )
        value, _, written, owner, _ = self.fake_launch(samples=[capacity(), breached, capacity()])
        self.assertFalse(value[2])
        stage = written[STAGE / "desktop-startup-stage.json"]
        self.assertEqual(stage["capacity_after_running"], breached)
        owner.start.assert_called_once_with()
        owner.__exit__.assert_called_once()

    def test_foreign_engine_inventory_never_passes_or_hands_off(self):
        value, _, _, owner, _ = self.fake_launch(inventory="foreign")
        self.assertFalse(value[2])
        owner.start.assert_called_once_with()
        owner.__exit__.assert_called_once()

    def test_existing_shutdown_preserves_reachable_foreign_workload(self):
        with (
            patch.object(guard, "inventory", return_value="foreign"),
            patch.object(guard, "command") as command,
            patch.object(guard.time, "time", return_value=1000),
            patch.object(guard.time, "monotonic", return_value=0),
        ):
            value = guard.shutdown_owned(driver.DOCKER, {}, 1120)
        self.assertTrue(value["foreign_workload_preserved"])
        self.assertFalse(value["shutdown_verified"])
        command.assert_not_called()

    def test_cross_run_receipts_and_changed_baseline_approval_deadline_refused(self):
        for name in driver.LIFECYCLE:
            rows = receipts()
            rows[name]["run_id"] = "c" * 32
            with self.subTest(receipt=name), self.assertRaises(driver.LabControlError):
                self.reconcile(rows)
        for name, field in (("ready", "armed"), ("intent", "start_requested")):
            rows = receipts()
            rows[name][field] = 1
            with self.subTest(marker=name), self.assertRaises(driver.LabControlError):
                self.reconcile(rows)
        for field, wrong in (
            ("stage_initial_free_disk_bytes", BASELINE + 1),
            ("stage_initial_free_disk_bytes", True),
            ("approval_reference", "other-approval"),
            ("deadline", 1721),
            ("initial_desktop_status", "running"),
        ):
            rows = receipts()
            rows["context"][field] = wrong
            with self.subTest(context=field), self.assertRaises(driver.LabControlError):
                self.reconcile(rows)

    def test_missing_receipt_remains_incomplete_with_no_extra_start(self):
        value, events, written, owner, _ = self.fake_launch(
            lifecycle=FileNotFoundError("synthetic")
        )
        self.assertFalse(value[2])
        self.assertNotIn("status:stopped", events)
        self.assertEqual(
            written[Path("synthetic-public.json")]["closure_error_class"], "FileNotFoundError"
        )
        owner.start.assert_called_once_with()

    def test_shutdown_status_capacity_and_pending_guard_each_required(self):
        for field, value in (
            ("receipts_bound", False),
            ("launcher_shutdown_verified", False),
            ("watchdog_shutdown_verified", False),
            ("stopped_observation_verified", False),
            ("watchdog_finished_normally", False),
            ("all_retained_capacity_samples_within_limits", False),
            ("guard_pending", True),
            ("foreign_workload_preserved", True),
            ("cli_timeout_seen", True),
            ("error_classes", {"last_stop_error_class": "LabControlError"}),
        ):
            stage = self.stage()
            stage["lifecycle"][field] = value
            with self.subTest(control=field):
                self.assertEqual(driver.outcome(stage)["status"], "incomplete")
        for state in ("unknown", "running", "starting", "stopping", None):
            stage = self.stage()
            stage["final_desktop_observation"] = {"status": state}
            with self.subTest(final_status=state):
                self.assertEqual(driver.outcome(stage)["status"], "incomplete")
        stage = self.stage()
        stage["capacity_after_shutdown"] = capacity(False)
        self.assertEqual(driver.outcome(stage)["status"], "incomplete")

    def test_cli_error_and_capacity_breach_retained_during_reconciliation(self):
        rows = receipts()
        rows["watchdog"]["shutdown"]["last_stop_error_class"] = "LabControlError"
        rows["watchdog"]["shutdown"]["cli_timeout_seen"] = True
        rows["watchdog"]["samples"][0] = capacity(False)
        value = self.reconcile(rows)
        self.assertEqual(value["error_classes"], {"last_stop_error_class": "LabControlError"})
        self.assertTrue(value["cli_timeout_seen"])
        self.assertFalse(value["all_retained_capacity_samples_within_limits"])

    def test_minimal_public_result_omits_private_approval_and_raw_receipts(self):
        stage = self.stage()
        stage.update(
            approval_reference="synthetic-private-reference",
            private_output="synthetic-private-data",
        )
        public = driver.outcome(stage)
        self.assertNotIn("synthetic-private-reference", str(public))
        self.assertNotIn("synthetic-private-data", str(public))
        self.assertNotIn("samples", public)
        self.assertEqual(public["downloads"], 0)
        self.assertEqual(public["containers_created"], 0)


if __name__ == "__main__":
    unittest.main()
