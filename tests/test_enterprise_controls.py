"""Offline safety controls are not a substitute for verified native shutdown."""

import json
import shutil
import uuid
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from integrations.enterprise import verification as controls

RUN = "a" * 32
CONTAINER = "b" * 64


class EnterpriseControlTests(SimpleTestCase):
    def setUp(self):
        self.test_root = Path(__file__).resolve().parents[1] / "var/tests"
        self.root = self.test_root / ("enterprise-control-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup_case)

    def cleanup_case(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.test_root.resolve()) or not target.name.startswith(
            "enterprise-control-"
        ):
            raise RuntimeError("Unsafe test cleanup target.")
        shutil.rmtree(target)

    def labels(self, **changes):
        value = {
            "org.signalbridge.enterprise.run": RUN,
            "org.signalbridge.enterprise.scope": "disposable-postgresql-verification",
            "com.docker.compose.project": controls.PROJECT_PREFIX + RUN,
        }
        value.update(changes)
        return json.dumps(value)

    def test_capacity_preserves_stage_budget_and_host_reserve(self):
        controls.check_capacity(27 * controls.GIB, 5 * controls.GIB)
        for disk, memory in (
            (26 * controls.GIB, 8 * controls.GIB),
            (30 * controls.GIB, 4 * controls.GIB),
        ):
            with (
                self.subTest(disk=disk, memory=memory),
                self.assertRaises(controls.LabControlError),
            ):
                controls.check_capacity(disk, memory)

    def test_stage_growth_includes_download_and_refuses_over_budget(self):
        controls.check_capacity(
            72 * controls.GIB, 5 * controls.GIB, 75 * controls.GIB, 5 * controls.GIB
        )
        with self.assertRaises(controls.LabControlError):
            controls.check_capacity(72 * controls.GIB, 5 * controls.GIB, 75 * controls.GIB)
        with self.assertRaises(controls.LabControlError):
            controls.check_capacity(
                72 * controls.GIB, 5 * controls.GIB, max_growth=6 * controls.GIB
            )

    def test_docker_targets_local_engine_without_inherited_overrides(self):
        with patch.dict(
            controls.os.environ, {"DOCKER_HOST": "tcp://remote:2375", "DOCKER_CONTEXT": "remote"}
        ):
            environment = controls.docker_environment()
            self.assertNotIn("DOCKER_HOST", environment)
            self.assertNotIn("DOCKER_CONTEXT", environment)
        with patch.object(controls.os, "name", "nt"):
            self.assertEqual(
                controls.docker_command("docker", ["ps"]),
                ["docker", "--host", "npipe:////./pipe/dockerDesktopLinuxEngine", "ps"],
            )

    def test_private_run_path_refuses_file_parent(self):
        (self.root / "var").write_text("unrelated")
        with self.assertRaises(controls.LabControlError):
            controls.private_run_directory(self.root, RUN)

    def test_finished_launcher_without_container_releases_watchdog(self):
        receipt = self.root / "watchdog.json"
        receipt.with_name("launcher-finished.json").write_text(json.dumps({"run_id": RUN}))
        with (
            patch.object(controls.time, "time", return_value=100),
            patch.object(controls, "owned_containers", return_value=[]),
            patch.object(controls.time, "sleep") as sleep,
        ):
            controls.await_container_watchdog(
                "docker", RUN, self.root, 120, 30 * controls.GIB, receipt
            )
        sleep.assert_not_called()
        self.assertTrue(json.loads(receipt.read_text())["shutdown_verified"])

    def test_startup_growth_failure_rechecks_scope_and_retains_shutdown(self):
        receipt = self.root / "watchdog.json"
        with (
            patch.object(controls.time, "time", return_value=100),
            patch.object(controls, "owned_containers", side_effect=[[], [CONTAINER]]),
            patch.object(controls.shutil, "disk_usage") as disk,
            patch.object(controls, "guarded_stop") as stop,
        ):
            disk.return_value.free = 27 * controls.GIB
            with self.assertRaises(controls.LabControlError):
                controls.await_container_watchdog(
                    "docker", RUN, self.root, 120, 30 * controls.GIB, receipt
                )
        stop.assert_called_once_with("docker", CONTAINER, RUN)
        proof = json.loads(receipt.read_text())
        self.assertEqual(proof["reason"], "disk_growth_before_startup")
        self.assertTrue(proof["shutdown_verified"])

    def test_invalid_run_and_container_fail_before_docker_access(self):
        with patch.object(controls, "docker_result") as docker:
            for run in ("", "../lab", "a" * 31, "A" * 32):
                with self.subTest(run=run), self.assertRaises(controls.LabControlError):
                    controls.validate_container("docker", CONTAINER, run)
            with self.assertRaises(controls.LabControlError):
                controls.validate_container("docker", "bad;command", RUN)
            docker.assert_not_called()

    def test_wrong_owner_never_receives_stop(self):
        for field in (
            "org.signalbridge.enterprise.run",
            "org.signalbridge.enterprise.scope",
            "com.docker.compose.project",
        ):
            with (
                self.subTest(field=field),
                patch.object(
                    controls, "docker_result", return_value=self.labels(**{field: "other"})
                ) as docker,
            ):
                with self.assertRaises(controls.LabControlError):
                    controls.guarded_stop("docker", CONTAINER, RUN)
                self.assertEqual(docker.call_count, 1)

    def test_shutdown_requires_ownership_and_stopped_state(self):
        with patch.object(
            controls, "docker_result", side_effect=[self.labels(), "", "false"]
        ) as docker:
            controls.guarded_stop("docker", CONTAINER, RUN)
            self.assertEqual(docker.call_args_list[1].args[1], ["stop", "--time", "10", CONTAINER])
        with patch.object(controls, "docker_result", side_effect=[self.labels(), "", "true"]):
            with self.assertRaises(controls.LabControlError):
                controls.guarded_stop("docker", CONTAINER, RUN)

    def test_only_immutable_expected_platform_image_is_accepted(self):
        with patch.object(
            controls,
            "docker_result",
            side_effect=[
                "sha256:" + "c" * 64,
                "linux|amd64",
                json.dumps([controls.IMAGE_REFERENCE]),
            ],
        ):
            self.assertEqual(controls.inspect_local_image("docker"), "sha256:" + "c" * 64)
        for values in (("postgres:latest",), ("sha256:" + "c" * 64, "linux|arm64")):
            with (
                self.subTest(values=values),
                patch.object(controls, "docker_result", side_effect=values),
                self.assertRaises(controls.LabControlError),
            ):
                controls.inspect_local_image("docker")

    def test_watchdog_capacity_failure_stops_the_exact_owned_container(self):
        with patch.object(self, "root", self.root) as temporary:
            receipt = Path(temporary) / "watchdog.json"
            with (
                patch.object(controls.time, "time", return_value=100),
                patch.object(controls.shutil, "disk_usage") as disk,
                patch.object(controls, "validate_container"),
                patch.object(controls, "guarded_stop") as stop,
            ):
                disk.return_value.free = 24 * controls.GIB
                controls.watchdog(
                    "docker", CONTAINER, RUN, temporary, 120, 30 * controls.GIB, receipt
                )
            stop.assert_called_once_with("docker", CONTAINER, RUN)
            self.assertEqual(json.loads(receipt.read_text())["reason"], "disk_reserve")

    def test_watchdog_control_failure_still_attempts_shutdown_and_retains_failure(self):
        with patch.object(self, "root", self.root) as temporary:
            receipt = Path(temporary) / "watchdog.json"
            with (
                patch.object(controls.time, "time", return_value=100),
                patch.object(controls.shutil, "disk_usage") as disk,
                patch.object(controls, "validate_container"),
                patch.object(controls, "docker_result", side_effect=controls.LabControlError),
                patch.object(controls, "guarded_stop") as stop,
            ):
                disk.return_value.free = 30 * controls.GIB
                with self.assertRaises(controls.LabControlError):
                    controls.watchdog(
                        "docker", CONTAINER, RUN, temporary, 120, 30 * controls.GIB, receipt
                    )
            stop.assert_called_once()
            evidence = json.loads(receipt.read_text())
            self.assertEqual(evidence["reason"], "control_error")
            self.assertTrue(evidence["shutdown_verified"])

    def test_watchdog_deadline_cannot_expand_runtime(self):
        with (
            patch.object(controls.time, "time", return_value=100),
            patch.object(controls, "docker_result") as docker,
        ):
            for deadline in (99, 100, 1901):
                with self.subTest(deadline=deadline), self.assertRaises(controls.LabControlError):
                    controls.watchdog(
                        "docker", CONTAINER, RUN, ".", deadline, 30 * controls.GIB, "unused"
                    )
            docker.assert_not_called()
