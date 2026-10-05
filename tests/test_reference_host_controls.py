"""Hostile runtime and independent-guard models; no real daemon or services."""

import copy
import json
import shutil
import uuid
from pathlib import Path
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from integrations.enterprise import reference_host_controls as controls
from integrations.enterprise import verification as base
from integrations.enterprise.reference_controls import PREFIX, SECRETS, expected_config

RUN, DB, RUNNER = "a" * 32, "b" * 64, "c" * 64
IMAGES = {"database": "sha256:" + "d" * 64, "runner": "sha256:" + "e" * 64}


class ReferenceHostTests(SimpleTestCase):
    def setUp(self):
        self.parent = Path(__file__).resolve().parents[1] / "var/tests"
        self.workspace = self.parent / ("reference-host-" + uuid.uuid4().hex)
        self.directory = base.private_run_directory(self.workspace, RUN)
        self.directory.mkdir(parents=True)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        path = self.workspace.resolve()
        if not path.is_relative_to(self.parent.resolve()) or self.workspace.is_symlink():
            raise RuntimeError("Unsafe host control test cleanup.")
        shutil.rmtree(path)

    def ownership(self, component="runner", **changes):
        labels = {
            "org.signalbridge.enterprise.run": RUN,
            "org.signalbridge.enterprise.scope": controls.SCOPE,
            "com.docker.compose.project": PREFIX + RUN,
            "com.docker.compose.service": component,
        }
        return {
            "labels": {**labels, **changes},
            "name": "/" + PREFIX + RUN + "-" + component + "-1",
        }

    def runtime(self, component="runner"):
        expected = expected_config(IMAGES, RUN, self.directory)["services"][component]
        mounts = [
            {
                "Destination": v["target"],
                "Source": v["source"],
                "Type": "bind",
                "RW": not v.get("read_only", False),
            }
            for v in expected["volumes"]
            if v["type"] == "bind"
        ] + [
            {
                "Destination": v["target"],
                "Source": str(self.directory / "secrets" / SECRETS[v["source"]]),
                "Type": "bind",
                "RW": False,
            }
            for v in expected["secrets"]
        ]
        if component == "database":
            mounts.append(
                {
                    "Destination": "/var/lib/postgresql/data",
                    "Type": "volume",
                    "RW": True,
                    "Name": PREFIX + RUN,
                }
            )
        return {
            "image": IMAGES[component],
            "memory": 512 * 1024**2,
            "swap": 512 * 1024**2,
            "cpu": 10**9,
            "pids": 128 if component == "database" else 96,
            "readonly": True,
            "privileged": False,
            "cap_drop": ["ALL"],
            "cap_add": None,
            "security": ["no-new-privileges:true"],
            "restart": "no",
            "ports": {"5432/tcp": None} if component == "database" else {},
            "port_bindings": {},
            "networks": {controls.NETWORK_PREFIX + RUN: {}},
            "mounts": mounts,
            "tmpfs": {v.split(":", 1)[0]: v.split(":", 1)[1] for v in expected["tmpfs"]},
            "user": "postgres" if component == "database" else "10001:10001",
            "devices": [],
            "device_requests": None,
            "pid_mode": "",
            "ipc_mode": "private",
            "uts_mode": "",
            "cgroup_mode": "private",
            "log": {"Type": "json-file", "Config": {"max-file": "2", "max-size": "5m"}},
            "command": expected["command"],
            "workdir": "/workspace" if component == "runner" else "",
            "entrypoint": ["docker-entrypoint.sh"] if component == "database" else None,
            "environment": [
                "PATH=/nonfunctional-image-test-path",
                *[f"{k}={v}" for k, v in expected["environment"].items()],
            ],
        }

    def verify_runtime(self, value, component="runner"):
        with patch.object(
            base,
            "docker_result",
            side_effect=[
                json.dumps(self.ownership(component)),
                json.dumps(value),
                json.dumps(
                    {
                        "entrypoint": ["docker-entrypoint.sh"] if component == "database" else None,
                        "environment": ["PATH=/nonfunctional-image-test-path"],
                        "workdir": "",
                    }
                ),
            ],
        ):
            return controls.verify_runtime("unused-cli", RUNNER, RUN, self.directory, IMAGES)

    def test_successful_effective_models_have_no_native_execution_claim(self):
        for component in ("database", "runner"):
            self.assertEqual(
                self.verify_runtime(self.runtime(component), component),
                {"component": component, "effective_runtime_verified": True},
            )

    def test_unsafe_resources_namespaces_logs_ports_and_types_rejected(self):
        mutations = {
            "image": "unexpected:latest",
            "entrypoint": ["unreviewed-entrypoint"],
            "environment": ["PATH=/changed", "SB_SOURCE_PROOF=1"],
            "memory": 0,
            "swap": -1,
            "cpu": True,
            "pids": True,
            "readonly": 1,
            "privileged": 1,
            "cap_add": ["NET_ADMIN"],
            "cap_drop": [],
            "security": [],
            "restart": "always",
            "user": "0",
            "pid_mode": "host",
            "ipc_mode": "host",
            "uts_mode": "host",
            "cgroup_mode": "host",
            "command": ["sh"],
            "devices": [{}],
            "device_requests": [{}],
            "port_bindings": {"80/tcp": []},
            "ports": {"80/tcp": [{"HostPort": "80"}]},
            "networks": {"default": {}},
            "tmpfs": {"/tmp": "rw,exec,size=1g"},
            "log": {"Type": "json-file", "Config": {}},
        }
        for key, value in mutations.items():
            data = self.runtime()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(base.LabControlError):
                self.verify_runtime(data)

    def test_extra_duplicate_writable_and_cross_project_mounts_rejected(self):
        for change in (
            "extra",
            "duplicate",
            "writable",
            "other_project",
            "missing",
            "prior_volume",
        ):
            component = "database" if change == "prior_volume" else "runner"
            data = self.runtime(component)
            if change == "extra":
                data["mounts"].append(
                    {
                        "Destination": "/var/run/docker.sock",
                        "Source": "/var/run/docker.sock",
                        "Type": "bind",
                        "RW": True,
                    }
                )
            elif change == "duplicate":
                data["mounts"].append(copy.deepcopy(data["mounts"][0]))
            elif change == "writable":
                data["mounts"][0]["RW"] = True
            elif change == "other_project":
                data["mounts"][0]["Source"] = "C:/other-project/source"
            elif change == "missing":
                data["mounts"].pop()
            else:
                data["mounts"][-1]["Name"] = "prior-retained-volume"
            with self.subTest(change=change), self.assertRaises(base.LabControlError):
                self.verify_runtime(data, component)

    def test_foreign_or_ambiguous_ownership_never_authorizes_a_stop(self):
        for key in (
            "org.signalbridge.enterprise.run",
            "org.signalbridge.enterprise.scope",
            "com.docker.compose.project",
            "com.docker.compose.service",
        ):
            value = self.ownership(**{key: "other-project"})
            with patch.object(base, "docker_result", return_value=json.dumps(value)) as daemon:
                with self.subTest(key=key), self.assertRaises(base.LabControlError):
                    controls.role("unused", RUNNER, RUN)
                self.assertTrue(all("stop" not in call.args[1] for call in daemon.call_args_list))
        value = self.ownership()
        value["name"] = "/other-project-runner-1"
        with patch.object(base, "docker_result", return_value=json.dumps(value)):
            with self.assertRaises(base.LabControlError):
                controls.role("unused", RUNNER, RUN)

    def test_failed_ownership_or_stop_does_not_prevent_other_verified_shutdown(self):
        for failure in ("ownership", "stop"):

            def owner(_docker, identifier, _run, case=failure):
                if case == "ownership" and identifier == DB:
                    raise base.LabControlError("Ownership changed.")
                return "runner" if identifier == RUNNER else "database"

            def daemon(_docker, args, case=failure, **kwargs):
                if case == "stop" and args[0] == "stop" and args[-1] == RUNNER:
                    raise base.LabControlError("Stop failed.")
                return "false"

            with (
                patch.object(controls, "inventory", return_value=[DB, RUNNER]),
                patch.object(controls, "role", side_effect=owner),
                patch.object(base, "docker_result", side_effect=daemon) as calls,
            ):
                with self.assertRaises(base.LabControlError):
                    controls.stop_scope("unused", RUN)
                stopped = [c.args[1][-1] for c in calls.call_args_list if c.args[1][0] == "stop"]
                self.assertIn(RUNNER if failure == "ownership" else DB, stopped)
                if failure == "ownership":
                    self.assertNotIn(DB, stopped)

    def test_network_and_volume_require_unique_scope_and_no_other_connections(self):
        labels = {
            "org.signalbridge.enterprise.run": RUN,
            "org.signalbridge.enterprise.scope": controls.SCOPE,
            "com.docker.compose.project": PREFIX + RUN,
        }
        network = {
            "name": controls.NETWORK_PREFIX + RUN,
            "internal": True,
            "driver": "bridge",
            "labels": labels,
            "containers": {DB: {}, RUNNER: {}},
            "ingress": False,
        }
        volume = {"name": PREFIX + RUN, "driver": "local", "labels": labels, "options": None}
        for change in (
            None,
            "egress",
            "foreign_connection",
            "volume_name",
            "foreign_labels",
            "remote_storage",
        ):
            n, v = copy.deepcopy(network), copy.deepcopy(volume)
            if change == "egress":
                n["internal"] = False
            elif change == "foreign_connection":
                n["containers"]["f" * 64] = {}
            elif change == "volume_name":
                v["name"] = "previous-volume"
            elif change == "foreign_labels":
                v["labels"]["org.signalbridge.enterprise.run"] = "e" * 32
            elif change == "remote_storage":
                v["options"] = {"device": "//outside/share"}
            with patch.object(base, "docker_result", side_effect=[json.dumps(n), json.dumps(v)]):
                if change is None:
                    self.assertTrue(
                        controls.verify_network_volume(
                            "unused", RUN, {DB: "database", RUNNER: "runner"}
                        )["internal_network_verified"]
                    )
                else:
                    with self.subTest(change=change), self.assertRaises(base.LabControlError):
                        controls.verify_network_volume(
                            "unused", RUN, {DB: "database", RUNNER: "runner"}
                        )

    def test_control_files_reject_duplicates_redirection_and_overwrite(self):
        controls.write_control(self.workspace, RUN, "launcher-finished.json", {"run_id": RUN})
        with self.assertRaises(base.LabControlError):
            controls.write_control(self.workspace, RUN, "launcher-finished.json", {"run_id": RUN})
        with self.assertRaises(base.LabControlError):
            controls.write_control(self.workspace, RUN, "../escape", {})
        path = self.directory / "duplicate.json"
        path.write_text('{"armed":false,"armed":true}')
        with self.assertRaises(base.LabControlError):
            controls.read_json(path)
        path.write_bytes(b"x" * 4097)
        with self.assertRaises(base.LabControlError):
            controls.read_json(path)

    def test_watchdog_abort_stays_alive_until_launcher_finishes(self):
        calls = []

        def sleep(_seconds):
            calls.append("tick")
            controls.write_control(self.workspace, RUN, "launcher-finished.json", {"run_id": RUN})

        with (
            patch.object(controls.time, "time", return_value=100),
            patch.object(controls.time, "monotonic", side_effect=[100, 100, 101, 102]),
            patch.object(controls.time, "sleep", side_effect=sleep),
            patch.object(
                controls.shutil, "disk_usage", return_value=Mock(free=controls.INITIAL_DISK)
            ),
            patch.object(controls, "owned", return_value={}),
            patch.object(controls, "stop_scope", return_value=0) as stop,
        ):
            result = controls.watchdog(
                "unused", RUN, self.workspace, 130, lambda: base.MIN_FREE_MEMORY - 1
            )
        self.assertEqual(calls, ["tick"])
        self.assertEqual(result["reason"], "host_memory")
        self.assertTrue(result["shutdown_verified"])
        self.assertEqual(stop.call_count, 3)  # Two observations plus final confirmation.
        self.assertEqual(controls.read_json(self.directory / "watchdog-abort.json")["run_id"], RUN)

    def test_watchdog_control_error_attempts_verified_shutdown_and_has_finite_deadline(self):
        with (
            patch.object(controls.time, "time", return_value=100),
            patch.object(controls.time, "monotonic", side_effect=[100, 100, 132, 133]),
            patch.object(controls.time, "sleep"),
            patch.object(
                controls.shutil, "disk_usage", return_value=Mock(free=controls.INITIAL_DISK)
            ),
            patch.object(controls, "owned", side_effect=base.LabControlError("Daemon refused.")),
            patch.object(controls, "stop_scope", return_value=1) as stop,
        ):
            result = controls.watchdog("unused", RUN, self.workspace, 130, lambda: 5 * base.GIB)
        self.assertEqual(result["reason"], "control_error")
        self.assertTrue(result["shutdown_verified"])
        self.assertEqual(stop.call_count, 2)
        with patch.object(controls.time, "time", return_value=100):
            for deadline in (True, "outside", 100, 2000, float("inf"), float("nan")):
                with self.subTest(deadline=deadline), self.assertRaises(base.LabControlError):
                    controls.watchdog("unused", RUN, self.workspace, deadline, lambda: 5 * base.GIB)
