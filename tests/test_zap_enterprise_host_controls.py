"""Hostile daemon facts and modeled launch/guard paths; never invoke Docker."""

import copy
import hashlib
import json
import shutil
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from integrations.enterprise import verification as base
from integrations.zap_enterprise import scanner_host_controls as host
from integrations.zap_enterprise.scanner_contract import IMAGE, receipt_bytes
from integrations.zap_enterprise.scanner_controls import PREFIX, SCOPE, expected_config
from scripts import enterprise_zap_verify as launch
from tests.test_zap_enterprise_capture import START

RUN, CONTAINER = "a" * 32, "b" * 64
IMAGE_ID = "sha256:" + "c" * 64


def image():
    return {
        "id": IMAGE_ID,
        "os": "linux",
        "architecture": "amd64",
        "digests": [IMAGE],
        "environment": ["PATH=/usr/local/bin:/usr/bin:/bin"],
    }


def runtime(directory="/synthetic-scanner-run"):
    expected = expected_config(IMAGE_ID, RUN, directory)["services"]["scanner"]
    return {
        "image": IMAGE_ID,
        "memory": host.MEMORY,
        "swap": host.MEMORY,
        "cpu": 1500000000,
        "pids": 256,
        "readonly": True,
        "privileged": False,
        "cap_drop": ["ALL"],
        "cap_add": None,
        "devices": [],
        "device_requests": None,
        "security": ["no-new-privileges:true"],
        "restart": "no",
        "user": "1000:1000",
        "pid_mode": "",
        "ipc_mode": "private",
        "uts_mode": "",
        "cgroup_mode": "private",
        "log": {"Type": "json-file", "Config": {"max-size": "2m", "max-file": "2"}},
        "command": expected["command"],
        "entrypoint": expected["entrypoint"],
        "workdir": "/workspace",
        "network_mode": "none",
        "init": True,
        "shm": 16 * 1024**2,
        "health": {"Test": ["NONE"], "Interval": 0},
        "port_bindings": {},
        "ports": {"8080/tcp": None},
        "networks": {"none": {"IPAddress": "", "Gateway": "", "GlobalIPv6Address": ""}},
        "environment": image()["environment"]
        + [f"{k}={v}" for k, v in expected["environment"].items()],
        "tmpfs": {"/tmp": expected["tmpfs"][0].split(":", 1)[1]},
        "mounts": [
            {
                "Type": "bind",
                "Destination": m["target"],
                "Source": m["source"],
                "RW": not m.get("read_only", False),
            }
            for m in expected["volumes"]
        ],
    }


class ScannerHostControlsTests(SimpleTestCase):
    def setUp(self):
        self.parent = Path(__file__).resolve().parents[1] / "var/tests"
        self.workspace = self.parent / ("h" + uuid.uuid4().hex[:8])
        self.directory = base.private_run_directory(self.workspace, RUN)
        (self.directory / "evidence").mkdir(parents=True)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.workspace.is_symlink() or not self.workspace.resolve().is_relative_to(
            self.parent.resolve()
        ):
            raise RuntimeError("Unsafe scanner host test cleanup.")
        shutil.rmtree(self.workspace)

    def test_pinned_image_requires_linux_amd64_digest_and_unambiguous_environment(self):
        self.assertEqual(host.image_identity(image()), IMAGE_ID)
        for field, changed in (
            ("digests", ["other@sha256:" + "d" * 64]),
            ("architecture", "arm64"),
            ("id", "tag"),
            ("os", "windows"),
            ("environment", ["PATH=first", "PATH=second"]),
            ("extra", "unsupported"),
        ):
            value = image()
            value[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                host.image_identity(value)

    def test_exact_modeled_effective_runtime_passes_with_no_network_or_extra_mount(self):
        self.assertTrue(
            host.validate_runtime(runtime(), image(), RUN, "/synthetic-scanner-run")[
                "effective_runtime_verified"
            ]
        )
        value = runtime()
        value["mounts"].append({"Type": "tmpfs", "Destination": "/tmp", "RW": True})
        self.assertTrue(
            host.validate_runtime(value, image(), RUN, "/synthetic-scanner-run")[
                "effective_runtime_verified"
            ]
        )

    def test_changed_privileges_ports_namespaces_resources_or_entrypoint_fail(self):
        for field, changed in (
            ("readonly", 1),
            ("privileged", True),
            ("cap_add", ["SYS_ADMIN"]),
            ("network_mode", "host"),
            ("port_bindings", {"8080/tcp": [{}]}),
            ("ports", {"8080/tcp": [{"HostIp": "0.0.0.0"}]}),
            ("networks", {"bridge": {}}),
            ("memory", 0),
            ("swap", -1),
            ("cpu", 0),
            ("pids", 0),
            ("user", "0:0"),
            ("entrypoint", ["sh"]),
            ("command", ["arbitrary"]),
            ("init", False),
            ("shm", 1024**3),
            ("ipc_mode", "host"),
            ("health", {"Test": ["CMD", "curl"]}),
            ("extra", "unsupported"),
            ("environment", ["PATH=changed"]),
        ):
            value = runtime()
            value[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                host.validate_runtime(value, image(), RUN, "/synthetic-scanner-run")

    def test_writable_source_redirected_input_socket_and_changed_tmpfs_fail(self):
        for change in (
            "source_rw",
            "input_redirect",
            "socket",
            "duplicate",
            "scratch",
            "interface",
        ):
            value = runtime()
            if change == "source_rw":
                value["mounts"][0]["RW"] = True
            elif change == "input_redirect":
                value["mounts"][1]["Source"] = "/other-project"
            elif change == "socket":
                value["mounts"].append(
                    {
                        "Type": "bind",
                        "Destination": "/var/run/docker.sock",
                        "Source": "/var/run/docker.sock",
                        "RW": True,
                    }
                )
            elif change == "duplicate":
                value["mounts"].append(copy.deepcopy(value["mounts"][0]))
            elif change == "scratch":
                value["tmpfs"]["/tmp"] = "rw,exec,size=512m"
            else:
                value["networks"]["none"]["IPAddress"] = "192.0.2.1"
            with self.subTest(change=change), self.assertRaises(ValueError):
                host.validate_runtime(value, image(), RUN, "/synthetic-scanner-run")

    def test_owner_labels_and_exact_name_must_match_before_stop(self):
        labels = {
            "org.signalbridge.enterprise.run": RUN,
            "org.signalbridge.enterprise.scope": SCOPE,
            "com.docker.compose.project": PREFIX + RUN,
            "com.docker.compose.service": "scanner",
        }
        for change in ("scope", "run", "name", "service"):
            data = {"labels": copy.deepcopy(labels), "name": "/" + PREFIX + RUN}
            if change == "name":
                data["name"] = "/another-project"
            else:
                key = {
                    "scope": "org.signalbridge.enterprise.scope",
                    "run": "org.signalbridge.enterprise.run",
                    "service": "com.docker.compose.service",
                }[change]
                data["labels"][key] = "wrong"
            with (
                patch.object(base, "docker_result", return_value=json.dumps(data)),
                self.subTest(change=change),
                self.assertRaises(ValueError),
            ):
                host.role(Path("unused-docker"), CONTAINER, RUN)

    def test_shutdown_never_mutates_an_unverified_owner_and_checks_running_state(self):
        calls = []
        with (
            patch.object(host, "inventory", return_value=[CONTAINER]),
            patch.object(host, "role", side_effect=ValueError("wrong owner")),
            patch.object(base, "docker_result") as docker,
        ):
            with self.assertRaises(ValueError):
                host.stop_scope(Path("unused-docker"), RUN)
            docker.assert_not_called()
        with (
            patch.object(host, "inventory", return_value=[CONTAINER]),
            patch.object(host, "role", return_value="scanner") as role,
            patch.object(
                base,
                "docker_result",
                side_effect=lambda _d, args, **_kw: (
                    calls.append(args) or ("false" if args[0] == "inspect" else "")
                ),
            ),
        ):
            self.assertEqual(host.stop_scope(Path("unused-docker"), RUN), 1)
            self.assertEqual(role.call_count, 2)
            self.assertEqual(calls[0], ["stop", "--time", "10", CONTAINER])
        with (
            patch.object(host, "inventory", return_value=[CONTAINER]),
            patch.object(host, "role", return_value="scanner"),
            patch.object(base, "docker_result", return_value="true"),
            self.assertRaises(ValueError),
        ):
            host.stop_scope(Path("unused-docker"), RUN)

    def test_capacity_reuses_whole_stage_guard_with_scanner_and_host_headroom(self):
        host.check_capacity(host.INITIAL_DISK, base.MIN_FREE_MEMORY + host.MEMORY)
        for disk, memory in (
            (host.INITIAL_DISK - host.GROWTH, 10 * base.GIB),
            (24 * base.GIB, 10 * base.GIB),
            (host.INITIAL_DISK, base.MIN_FREE_MEMORY + host.MEMORY - 1),
            (True, 10 * base.GIB),
        ):
            with self.subTest(disk=disk, memory=memory), self.assertRaises(ValueError):
                host.check_capacity(disk, memory)

    def test_shutdown_requires_two_matching_receipts_one_component_and_no_abort(self):
        main = {"run_id": RUN, "shutdown_verified": True, "stopped_component_count": 1}
        independent = {
            **main,
            "reason": "launcher_finished",
            "stopped_at": (START + timedelta(seconds=1)).isoformat(),
        }
        self.assertTrue(
            host.validate_shutdown(
                main, independent, RUN, started=START, finished=START + timedelta(seconds=2)
            )["independent_shutdown_verified"]
        )
        for field, value in (
            ("reason", "disk_growth"),
            ("run_id", "e" * 32),
            ("shutdown_verified", 1),
            ("stopped_component_count", True),
            ("stopped_component_count", 0),
            ("stopped_at", (START - timedelta(seconds=1)).isoformat()),
        ):
            changed = {**independent, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                host.validate_shutdown(
                    main, changed, RUN, started=START, finished=START + timedelta(seconds=2)
                )

    def guard_model(self, *, available=10 * base.GIB, failure=False):
        tick = [0.0]

        def sleep(seconds):
            tick[0] += seconds
            if tick[0] >= 2 and not (self.directory / "launcher-finished.json").exists():
                host.write_control(self.workspace, RUN, "launcher-finished.json", {"run_id": RUN})

        with (
            patch.object(host.time, "time", return_value=1000),
            patch.object(host.time, "monotonic", side_effect=lambda: tick[0]),
            patch.object(host.time, "sleep", side_effect=sleep),
            patch.object(host.shutil, "disk_usage", return_value=Mock(free=host.INITIAL_DISK)),
            patch.object(
                host,
                "owned",
                side_effect=RuntimeError("private failure") if failure else None,
                return_value={CONTAINER: "scanner"},
            ),
            patch.object(base, "docker_result", return_value="running"),
            patch.object(host, "stop_scope", return_value=1) as stop,
        ):
            result = host.watchdog(
                Path("unused-docker"), RUN, self.workspace, 1004, lambda: available
            )
        self.assertGreaterEqual(tick[0], 2)
        return result, stop.call_count

    def test_independent_guard_waits_for_launcher_and_records_normal_shutdown(self):
        result, count = self.guard_model()
        self.assertEqual(result["reason"], "launcher_finished")
        self.assertTrue(result["shutdown_verified"])
        self.assertEqual(count, 1)
        self.assertFalse((self.directory / "watchdog-abort.json").exists())

    def test_capacity_or_control_abort_keeps_stopping_until_launcher_finishes(self):
        result, count = self.guard_model(available=0)
        self.assertEqual(result["reason"], "host_memory")
        self.assertGreaterEqual(count, 3)
        self.assertTrue((self.directory / "watchdog-abort.json").exists())

    def test_guard_control_failure_retains_class_only_and_still_attempts_shutdown(self):
        result, count = self.guard_model(failure=True)
        self.assertEqual(result["reason"], "control_error")
        self.assertGreaterEqual(count, 3)
        self.assertNotIn("private failure", json.dumps(result))

    def test_guard_rejects_nonfinite_or_unbounded_deadline_before_any_control_write(self):
        with patch.object(host, "write_control") as write:
            for deadline in (True, float("nan"), float("inf"), -1, 999999999999):
                with self.subTest(deadline=deadline), self.assertRaises(ValueError):
                    host.watchdog(Path("unused-docker"), RUN, self.workspace, deadline, Mock())
            write.assert_not_called()

    def test_foreign_workload_or_stale_source_refused_before_create(self):
        receipt_name = "docs/evidence/20261002-enterprise-offline-" + RUN + ".json"
        (self.workspace / "docs/evidence").mkdir(parents=True)
        (self.workspace / "docs/enterprise-milestone.json").write_bytes(b"{}")
        (self.workspace / receipt_name).write_bytes(b"{}")
        with (
            patch.object(base, "docker_result", return_value="f" * 64),
            self.assertRaises(ValueError),
        ):
            launch.no_foreign_running(Path("unused-docker"))
        with (
            patch.object(launch, "ROOT", self.workspace),
            patch.object(launch, "source_manifest", return_value={"sha256": "old"}),
            patch.object(
                launch,
                "read_json",
                side_effect=[
                    {"current_offline_receipt": receipt_name},
                    {"passed": True, "source_unchanged": True, "source_sha256": "changed"},
                ],
            ),
            self.assertRaises(ValueError),
        ):
            launch.verified_source()

    def execute_model(self, *, runtime_failure=False, exit_state="exited|0"):
        guard = Mock()
        guard.poll.return_value = None
        host.write_control(
            self.workspace, RUN, "watchdog-ready.json", {"run_id": RUN, "armed": True}
        )
        raw = b"synthetic-package-bytes"
        binding = {"source_run_id": "d" * 32, "source_receipt_sha256": "e" * 64}
        parsed = receipt_bytes(expected_config(IMAGE_ID, RUN, self.directory))
        order = []

        def command(_docker, args, **_kwargs):
            order.append(args[0])
            if args[0] == "start":
                gate = json.loads((self.directory / "evidence/allow-scanner.json").read_bytes())
                self.assertEqual(gate["input_sha256"], hashlib.sha256(raw).hexdigest())
                self.assertFalse((self.directory / "evidence/allow-scanner.tmp").exists())
                return ""
            return "created" if args[-1] == "{{.State.Status}}" else exit_state

        def exact(*_args):
            order.append("runtime")
            if runtime_failure:
                raise base.LabControlError("modeled runtime denial")
            return CONTAINER

        with (
            patch.object(launch, "ROOT", self.workspace),
            patch.object(launch, "compose_command", return_value=["unused-docker", "compose"]),
            patch.object(launch, "invoke", side_effect=[parsed, b""]) as invoke,
            patch.object(launch, "check_capacity"),
            patch.object(host, "owned", return_value={}),
            patch.object(launch, "no_foreign_running"),
            patch.object(launch, "exact_component", side_effect=exact),
            patch.object(launch, "private_acl"),
            patch.object(base, "docker_result", side_effect=command),
        ):
            if runtime_failure or exit_state != "exited|0":
                with self.assertRaises(ValueError):
                    launch.execute(
                        Path("unused-docker"), RUN, self.directory, image(), {}, guard, raw, binding
                    )
                result = None
            else:
                result = launch.execute(
                    Path("unused-docker"), RUN, self.directory, image(), {}, guard, raw, binding
                )
        self.assertIn("--pull", invoke.call_args_list[1].args[0])
        self.assertIn("never", invoke.call_args_list[1].args[0])
        return result, order

    def test_controller_checks_created_runtime_then_gate_then_start(self):
        result, order = self.execute_model()
        self.assertTrue(result["runtime_isolation_verified"])
        self.assertLess(order.index("runtime"), order.index("start"))
        self.assertEqual(order.count("runtime"), 3)

    def test_changed_runtime_never_releases_gate_or_starts_container(self):
        _result, order = self.execute_model(runtime_failure=True)
        self.assertNotIn("start", order)
        self.assertFalse((self.directory / "evidence/allow-scanner.json").exists())

    def test_failed_native_exit_cannot_become_complete_coverage(self):
        result, _order = self.execute_model(exit_state="exited|1")
        self.assertIsNone(result)

    def test_gate_cannot_be_reused_for_another_release(self):
        binding = {"source_run_id": "d" * 32, "source_receipt_sha256": "e" * 64}
        launch.write_gate(self.directory, RUN, b"synthetic", binding)
        with self.assertRaises(ValueError):
            launch.write_gate(self.directory, RUN, b"changed", binding)
