"""Offline hostile-profile and shutdown checks; these do not launch containers."""

import hashlib
import io
import json
import shutil
import uuid
import zipfile
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from integrations.enterprise import network_verification as controls
from integrations.enterprise import verification as base
from integrations.enterprise.native_runner import verify_kernel_mounts

RUN, DATABASE, RUNNER, IMAGE = "a" * 32, "b" * 64, "c" * 64, "sha256:" + "d" * 64


class NetworkControlTests(SimpleTestCase):
    def setUp(self):
        self.test_root = Path(__file__).resolve().parents[1] / "var/tests"
        self.root = self.test_root / ("enterprise-network-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.test_root.resolve()) or not target.name.startswith(
            "enterprise-network-"
        ):
            raise RuntimeError("Unsafe test cleanup target.")
        shutil.rmtree(target)

    def labels(self, role="runner", **changes):
        value = {
            "org.signalbridge.enterprise.run": RUN,
            "org.signalbridge.enterprise.scope": controls.SCOPE,
            "com.docker.compose.project": controls.PROJECT_PREFIX + RUN,
            "com.docker.compose.service": role,
        }
        return json.dumps({**value, **changes})

    def runtime(self):
        return {
            "image": IMAGE,
            "memory": 512 * 1024**2,
            "swap": 512 * 1024**2,
            "cpu": 10**9,
            "pids": 96,
            "readonly": True,
            "privileged": False,
            "caps": ["ALL"],
            "security": ["no-new-privileges:true"],
            "restart": "no",
            "ports": {},
            "networks": {"sb-enterprise-internal-" + RUN: {}},
            "user": "10001:10001",
            "tmpfs": {
                "/tmp": "rw,noexec,nosuid,nodev,size=64m",
                "/opt/verification-deps": "rw,exec,nosuid,nodev,size=128m,mode=0700,uid=10001,gid=10001",
            },
            "mounts": [
                {
                    "Destination": target,
                    "Source": str(self.root / name),
                    "Type": "bind",
                    "RW": writable,
                }
                for target, name, writable in (
                    ("/workspace", "source", False),
                    ("/wheels", "wheels", False),
                    ("/evidence", "evidence", True),
                    ("/run/secrets/verifier_password", "secrets/verifier-password", False),
                )
            ],
        }

    def test_reviewed_wheels_match_lock_and_download_ceiling(self):
        rows = controls.wheel_manifest()
        self.assertEqual(len(rows), 6)
        self.assertEqual(sum(row["size"] for row in rows), 14200997)

    def test_cached_wheels_are_reverified_without_network_or_source_changes(self):
        original = base.private_run_directory(self.root, RUN) / "wheels"
        original.mkdir(parents=True)
        (original / "data.whl").write_bytes(b"data")
        row = {"filename": "data.whl", "size": 4, "sha256": hashlib.sha256(b"data").hexdigest()}
        with (
            patch.object(controls, "wheel_manifest", return_value=[row]),
            patch.object(controls.urllib.request, "build_opener") as network,
        ):
            value = controls.cached_wheels(self.root, RUN, self.root / "reused")
            self.assertEqual(value["downloaded_bytes"], 0)
            self.assertEqual((original / "data.whl").read_bytes(), b"data")
            (original / "data.whl").write_bytes(b"fake")
            with self.assertRaises(base.LabControlError):
                controls.cached_wheels(self.root, RUN, self.root / "corrupt")
            network.assert_not_called()

    def test_wheel_footprint_guard_does_not_extract_and_rejects_changed_or_unsafe_archives(self):
        path = self.root / "sample.whl"
        for name in ("package/module.py", "../escape.py", "/absolute.py"):
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(name, b"pass\n")
            row = {"filename": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            with patch.object(controls, "wheel_manifest", return_value=[row]):
                if name.startswith("package/"):
                    proof = controls.wheel_expansion(self.root)
                    self.assertEqual(proof["uncompressed_bytes"], 5)
                    self.assertEqual(list(self.root.iterdir()), [path])
                    row["sha256"] = "0" * 64
                with self.assertRaises(base.LabControlError):
                    controls.wheel_expansion(self.root)

    def test_parsed_comma_separated_mount_regression_fails_before_creation(self):
        data = {
            "services": {
                "database": {
                    "image": IMAGE,
                    "tmpfs": [
                        "/tmp:rw,noexec,nosuid,size=64m",
                        "/var/run/postgresql:rw,noexec,nosuid,size=16m",
                    ],
                },
                "runner": {
                    "image": IMAGE,
                    "tmpfs": [
                        "/tmp:rw,noexec,nosuid,nodev,size=64m",
                        "/opt/verification-deps:rw,exec,nosuid,nodev,size=128m,mode=0700,uid=10001,gid=10001",
                    ],
                },
            },
            "networks": {
                "verification": {"name": "sb-enterprise-internal-" + RUN, "internal": True}
            },
        }
        controls.verify_compose_config(data, {"database": IMAGE, "runner": IMAGE}, RUN)
        data["services"]["runner"]["tmpfs"] = ["/tmp:rw", "nosuid", "size=192m"]
        with self.assertRaises(base.LabControlError):
            controls.verify_compose_config(data, {"database": IMAGE, "runner": IMAGE}, RUN)

    def test_external_redirect_or_manifest_host_cannot_become_a_download(self):
        self.assertIsNone(
            controls.NoRedirect().redirect_request(
                None, None, 302, "", {}, "https://other.invalid/"
            )
        )
        manifest = json.loads(controls.WHEEL_MANIFEST.read_text())
        manifest["wheels"][0]["url"] = "https://127.0.0.1/private.whl"
        target = self.root / "wheels.json"
        target.write_text(json.dumps(manifest))
        with (
            patch.object(controls, "WHEEL_MANIFEST", target),
            self.assertRaises(base.LabControlError),
        ):
            controls.wheel_manifest()

    def test_corrupt_wheel_is_retained_without_installation_or_success(self):
        class Reply(io.BytesIO):
            status, headers = 200, {}

            def geturl(self):
                return "https://files.pythonhosted.org/packages/aa/data.whl"

        row = {"filename": "data.whl", "url": Reply.geturl(None), "size": 4, "sha256": "0" * 64}
        with (
            patch.object(controls, "wheel_manifest", return_value=[row]),
            patch.object(controls.urllib.request, "build_opener") as opener,
        ):
            opener.return_value.open.return_value = Reply(b"data")
            with self.assertRaises(base.LabControlError):
                controls.download_wheels(self.root / "wheels")
        self.assertEqual((self.root / "wheels/data.whl").read_bytes(), b"data")

    def test_source_snapshot_rejects_private_or_changed_files(self):
        source = self.root / "source"
        source.mkdir()
        (source / "manage.py").write_bytes(b"known source")
        manifest = {
            "files": {"manage.py": hashlib.sha256(b"known source").hexdigest()},
            "sha256": "a" * 64,
        }
        result = controls.snapshot_source(source, self.root / "snapshot", manifest)
        self.assertEqual(result["file_count"], 1)
        (source / "manage.py").write_bytes(b"changed")
        with self.assertRaises(base.LabControlError):
            controls.snapshot_source(source, self.root / "changed", manifest)
        (source / ".env").write_text("private")
        manifest["files"] = {".env": hashlib.sha256(b"private").hexdigest()}
        with self.assertRaises(base.LabControlError):
            controls.snapshot_source(source, self.root / "private", manifest)

    def test_memory_budget_includes_both_containers_and_host_headroom(self):
        controls.check_capacity(75 * base.GIB, 5 * base.GIB, 75 * base.GIB)
        with self.assertRaises(base.LabControlError):
            controls.check_capacity(75 * base.GIB, int(4.75 * base.GIB), 75 * base.GIB)

    def test_revised_growth_choice_stays_explicit_and_preserves_the_reserve(self):
        with self.assertRaises(base.LabControlError):
            controls.check_capacity(66 * base.GIB, 5 * base.GIB, 75 * base.GIB)
        controls.check_capacity(66 * base.GIB, 5 * base.GIB, 75 * base.GIB, 12 * base.GIB)
        for disk, maximum in ((66, 10), (63, 12), (27, 12)):
            with self.subTest(disk=disk, maximum=maximum), self.assertRaises(base.LabControlError):
                controls.check_capacity(
                    disk * base.GIB, 5 * base.GIB, 75 * base.GIB, maximum * base.GIB
                )

    def test_wrong_scope_or_component_cannot_be_stopped(self):
        for change in (
            {"org.signalbridge.enterprise.run": "other"},
            {"com.docker.compose.service": "unrelated"},
        ):
            with (
                self.subTest(change=change),
                patch.object(base, "docker_result", return_value=self.labels(**change)) as docker,
            ):
                with self.assertRaises(base.LabControlError):
                    controls.container_role("docker", RUNNER, RUN)
                self.assertEqual(docker.call_count, 1)

    def test_effective_isolation_accepts_exact_mounts_and_limits(self):
        with patch.object(
            base, "docker_result", side_effect=[self.labels(), json.dumps(self.runtime()), "true"]
        ):
            controls.verify_runtime("docker", RUNNER, RUN, self.root, IMAGE)

    def test_effective_ports_privilege_swap_restart_or_external_network_are_rejected(self):
        for change in (
            {"ports": {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]}},
            {"privileged": True},
            {"swap": -1},
            {"readonly": False},
            {"restart": "always"},
            {"networks": {"default": {}}},
            {"caps": []},
            {"user": "root"},
        ):
            with (
                self.subTest(change=change),
                patch.object(
                    base,
                    "docker_result",
                    side_effect=[self.labels(), json.dumps({**self.runtime(), **change})],
                ),
            ):
                with self.assertRaises(base.LabControlError):
                    controls.verify_runtime("docker", RUNNER, RUN, self.root, IMAGE)
        with patch.object(
            base, "docker_result", side_effect=[self.labels(), json.dumps(self.runtime()), "false"]
        ):
            with self.assertRaises(base.LabControlError):
                controls.verify_runtime("docker", RUNNER, RUN, self.root, IMAGE)

    def test_socket_other_project_or_writable_source_mount_is_rejected(self):
        for change in ("socket", "source", "write"):
            runtime = deepcopy(self.runtime())
            if change == "socket":
                runtime["mounts"].append(
                    {
                        "Destination": "/var/run/docker.sock",
                        "Source": "/var/run/docker.sock",
                        "Type": "bind",
                        "RW": True,
                    }
                )
            elif change == "source":
                runtime["mounts"][0]["Source"] = str(self.root.parent / "other-project")
            else:
                runtime["mounts"][0]["RW"] = True
            with (
                self.subTest(change=change),
                patch.object(
                    base, "docker_result", side_effect=[self.labels(), json.dumps(runtime), "true"]
                ),
            ):
                with self.assertRaises(base.LabControlError):
                    controls.verify_runtime("docker", RUNNER, RUN, self.root, IMAGE)

    def test_unbounded_or_extra_tmpfs_is_rejected(self):
        for tmpfs in (
            {"/tmp": "rw,nosuid"},
            {"/tmp": "rw,nosuid,size=1g"},
            {"/tmp": "rw,nosuid,size=192m", "/extra": "size=1m"},
        ):
            with (
                self.subTest(tmpfs=tmpfs),
                patch.object(
                    base,
                    "docker_result",
                    side_effect=[
                        self.labels(),
                        json.dumps({**self.runtime(), "tmpfs": tmpfs}),
                        "true",
                    ],
                ),
            ):
                with self.assertRaises(base.LabControlError):
                    controls.verify_runtime("docker", RUNNER, RUN, self.root, IMAGE)

    def test_shared_libraries_get_a_separate_reviewed_mount(self):
        for target, options in (
            ("/tmp", "rw,exec,nosuid,nodev,size=64m"),
            ("/opt/verification-deps", "rw,nosuid,nodev,size=128m,mode=0700,uid=10001,gid=10001"),
            (
                "/opt/verification-deps",
                "rw,exec,noexec,nosuid,nodev,size=128m,mode=0700,uid=10001,gid=10001",
            ),
            (
                "/opt/verification-deps",
                "rw,exec,nosuid,nodev,size=128m,mode=0777,uid=10001,gid=10001",
            ),
        ):
            data = self.runtime()
            data["tmpfs"][target] = options
            with (
                self.subTest(target=target, options=options),
                patch.object(
                    base, "docker_result", side_effect=[self.labels(), json.dumps(data), "true"]
                ),
                self.assertRaises(base.LabControlError),
            ):
                controls.verify_runtime("docker", RUNNER, RUN, self.root, IMAGE)

    def test_kernel_mount_evidence_catches_hidden_noexec_and_missing_scratch_controls(self):
        scratch = "30 20 0:1 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=65536k"
        dependencies = (
            "31 20 0:2 / /opt/verification-deps rw,nosuid,nodev - tmpfs tmpfs rw,size=131072k"
        )
        self.assertEqual(
            verify_kernel_mounts(scratch + "\n" + dependencies),
            {
                "/tmp": {"filesystem": "tmpfs", "noexec": True},
                "/opt/verification-deps": {"filesystem": "tmpfs", "noexec": False},
            },
        )
        for raw in (
            scratch,
            scratch + "\n" + dependencies.replace("rw,nosuid,nodev", "rw,nosuid,nodev,noexec"),
            scratch.replace(",noexec", "") + "\n" + dependencies,
            scratch + "\n" + dependencies.replace(" - tmpfs ", " - ext4 "),
            scratch + "\n" + dependencies.replace(",nosuid", ""),
            scratch + "\n" + dependencies + "\n" + dependencies,
        ):
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                verify_kernel_mounts(raw)

    def test_cleanup_attempts_database_even_when_runner_stop_fails(self):
        def docker(_docker, command, **kwargs):
            if command[0] == "stop" and command[-1] == RUNNER:
                raise base.LabControlError("Simulated runner control failure")
            return "false" if command[-1] == "{{.State.Running}}" else ""

        with (
            patch.object(controls, "owned", return_value={DATABASE: "database", RUNNER: "runner"}),
            patch.object(controls, "container_role"),
            patch.object(base, "docker_result", side_effect=docker) as access,
        ):
            with self.assertRaises(base.LabControlError):
                controls.stop_scope("docker", RUN)
        self.assertTrue(
            any(
                call.args[1][0] == "stop" and call.args[1][-1] == DATABASE
                for call in access.call_args_list
            )
        )

    def test_created_container_does_not_release_watchdog_before_startup(self):
        receipt = self.root / "watchdog.json"
        receipt.with_name("launcher-finished.json").write_text("finished")
        with (
            patch.object(controls.time, "time", return_value=100),
            patch.object(controls.shutil, "disk_usage") as disk,
            patch.object(controls, "owned", return_value={DATABASE: "database", RUNNER: "runner"}),
            patch.object(base, "docker_result", return_value="created"),
            patch.object(controls, "stop_scope", return_value=2),
        ):
            disk.return_value.free = 75 * base.GIB
            controls.watchdog("docker", RUN, self.root, 120, 75 * base.GIB, receipt)
        value = json.loads(receipt.read_text())
        self.assertEqual(value["reason"], "launcher_finished")
        self.assertTrue(value["shutdown_verified"])

    def test_disk_limit_stops_both_exact_owned_components_and_retains_receipt(self):
        receipt = self.root / "watchdog.json"
        with (
            patch.object(controls.time, "time", return_value=100),
            patch.object(controls.shutil, "disk_usage") as disk,
            patch.object(controls, "stop_scope", return_value=2) as stop,
        ):
            disk.return_value.free = 24 * base.GIB
            controls.watchdog("docker", RUN, self.root, 120, 75 * base.GIB, receipt)
        stop.assert_called_once_with("docker", RUN)
        value = json.loads(receipt.read_text())
        self.assertEqual(value["stopped_component_count"], 2)
        self.assertEqual(value["reason"], "disk_reserve")
        self.assertTrue(value["shutdown_verified"])
