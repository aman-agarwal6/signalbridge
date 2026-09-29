"""Synthetic Docker fixtures test the gate; these are not live isolation evidence."""

import copy
import json
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from scripts import verify_supabase_isolation as gate


def topology():
    containers = []
    for index, name in enumerate(gate.NAMES):
        relay = name == gate.RELAY
        ports = (
            {
                port: [{"HostIp": "127.0.0.1", "HostPort": value}]
                for port, value in gate.PORTS.items()
            }
            if relay
            else {}
        )
        mounts = []
        if name in gate.VOLUMES:
            mounts = [
                {
                    "Type": "volume",
                    "Name": name,
                    "Destination": gate.VOLUMES[name],
                    "Driver": "local",
                    "RW": True,
                }
            ]
        if relay:
            mounts = [
                {
                    "Type": "bind",
                    "Source": str(gate.RELAY_SOURCE),
                    "Destination": "/relay.mjs",
                    "RW": False,
                }
            ]
        containers.append(
            {
                "Name": "/" + name,
                "Id": str(index) * 64,
                "Image": "sha256:" + "a" * 64,
                "State": "running",
                "Running": True,
                "User": "65534:65534" if relay else "",
                "Networks": {
                    name: {} for name in ((gate.BACKEND, gate.EDGE) if relay else (gate.BACKEND,))
                },
                "Ports": ports,
                "Mounts": mounts,
                "HostConfig": {
                    "NetworkMode": gate.EDGE if relay else gate.BACKEND,
                    "Privileged": False,
                    "CapAdd": None,
                    "CapDrop": ["ALL"] if relay else None,
                    "PidMode": "",
                    "IpcMode": "private",
                    "Devices": [],
                    "ReadonlyRootfs": relay,
                    "SecurityOpt": ["no-new-privileges:true"] if relay else [],
                    "PortBindings": ports,
                    "PublishAllPorts": False,
                    "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                    "Memory": gate.RESOURCE_LIMITS[name][0],
                    "MemorySwap": gate.RESOURCE_LIMITS[name][0],
                    "NanoCpus": gate.RESOURCE_LIMITS[name][1],
                    "PidsLimit": gate.RESOURCE_LIMITS[name][2],
                    "CpuQuota": 0,
                    "CpuPeriod": 0,
                    "OomKillDisable": False,
                },
            }
        )
    return {
        "containers": containers,
        "networks": [
            {
                "Name": name,
                "Id": name + "-id",
                "Driver": "bridge",
                "Internal": internal,
                "EnableIPv6": False,
                "Options": {"com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"},
                "Containers": {member: {"Name": member} for member in members},
            }
            for name, internal, members in (
                (gate.BACKEND, True, gate.NAMES),
                (gate.EDGE, False, (gate.RELAY,)),
            )
        ],
        "volumes": [{"Name": name, "Driver": "local", "Options": None} for name in gate.VOLUMES],
    }


class SupabaseIsolationTests(TestCase):
    def test_configured_backend_port_is_rejected_even_without_effective_port(self):
        payload = topology()
        row = payload["containers"][0]
        self.assertFalse(row["Ports"])
        row["HostConfig"]["PortBindings"] = {"5432/tcp": [{"HostIp": "", "HostPort": "55322"}]}
        self.assertIn("backend_configured_port_binding", gate.verify_topology(payload))

    def test_missing_unbounded_and_overridden_resource_controls_are_rejected(self):
        for key, value in (
            ("Memory", 0),
            ("Memory", True),
            ("Memory", 4 * 1024**3),
            ("MemorySwap", -1),
            ("MemorySwap", 0),
            ("NanoCpus", 0),
            ("NanoCpus", 2_000_000_000),
            ("PidsLimit", -1),
            ("PidsLimit", None),
            ("CpuQuota", -1),
            ("CpuPeriod", 100000),
            ("OomKillDisable", True),
            ("PublishAllPorts", True),
            ("RestartPolicy", {"Name": "unless-stopped", "MaximumRetryCount": 0}),
        ):
            with self.subTest(field=key, variant=value):
                payload = topology()
                payload["containers"][0]["HostConfig"][key] = value
                self.assertTrue(gate.verify_topology(payload))
        for key in (
            "Memory",
            "MemorySwap",
            "NanoCpus",
            "PidsLimit",
            "RestartPolicy",
            "PublishAllPorts",
        ):
            payload = topology()
            del payload["containers"][0]["HostConfig"][key]
            self.assertTrue(gate.verify_topology(payload))

    def test_each_service_has_its_own_ceiling_and_stopped_controls_are_checkable(self):
        for row in topology()["containers"]:
            name = row["Name"].lstrip("/")
            self.assertEqual(gate.verify_startup_controls(name, row["HostConfig"]), [])
            row["HostConfig"]["Memory"] += 1
            self.assertIn(
                "configured_resource_limit", gate.verify_startup_controls(name, row["HostConfig"])
            )

    def test_expected_isolated_topology_and_runtime_pass(self):
        self.assertEqual(gate.verify_topology(topology()), [])
        canonical_docker = topology()
        canonical_docker["containers"][-1]["HostConfig"]["SecurityOpt"] = ["no-new-privileges"]
        self.assertEqual(gate.verify_topology(canonical_docker), [])
        self.assertEqual(
            gate.verify_runtime(
                {
                    "ipv4_default_route": False,
                    "ipv6_default_route": False,
                    "external_tcp": "blocked",
                    "cron_launch_active_jobs": "off",
                }
            ),
            [],
        )

    def test_backend_escape_routes_ports_namespaces_and_mounts_fail(self):
        mutations = (
            lambda row: row["Networks"].update({gate.EDGE: {}}),
            lambda row: row["Ports"].update(
                {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "55322"}]}
            ),
            lambda row: row["HostConfig"].update({"Privileged": True}),
            lambda row: row["HostConfig"].update({"CapAdd": ["NET_ADMIN"]}),
            lambda row: row["HostConfig"].update({"NetworkMode": "host"}),
            lambda row: row["HostConfig"].update({"PidMode": "host"}),
            lambda row: row["HostConfig"].update({"IpcMode": "host"}),
            lambda row: row["HostConfig"].update({"Devices": [{"PathOnHost": "/dev/sda"}]}),
            lambda row: row["Mounts"].append(
                {
                    "Type": "bind",
                    "Source": "/var/run/docker.sock",
                    "Destination": "/var/run/docker.sock",
                }
            ),
            lambda row: row["Mounts"].append(
                {"Type": "bind", "Source": "C:/original/bettail", "Destination": "/source"}
            ),
            lambda row: row.update({"Running": False}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                payload = topology()
                mutate(payload["containers"][0])
                self.assertTrue(gate.verify_topology(payload))

    def test_relay_must_have_exact_loopback_bindings_and_fixed_mount(self):
        mutations = (
            lambda row: row["Ports"]["55322/tcp"][0].update({"HostIp": "0.0.0.0"}),
            lambda row: row["Ports"].update(
                {"22/tcp": [{"HostIp": "127.0.0.1", "HostPort": "22"}]}
            ),
            lambda row: row["Mounts"][0].update({"RW": True}),
            lambda row: row["Mounts"][0].update({"Source": str(gate.ROOT.parent / "bettail")}),
            lambda row: row["HostConfig"].update({"CapDrop": []}),
            lambda row: row["HostConfig"].update({"ReadonlyRootfs": False}),
            lambda row: row["HostConfig"].update({"SecurityOpt": []}),
            lambda row: row.update({"User": "root"}),
            lambda row: row.update({"Image": "sha256:" + "b" * 64}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                payload = topology()
                mutate(payload["containers"][-1])
                self.assertTrue(gate.verify_topology(payload))

    def test_unknown_network_members_and_volume_bind_options_fail(self):
        payload = topology()
        payload["networks"][0]["Containers"]["unexpected"] = {"Name": "unrelated-proxy"}
        self.assertIn("unexpected_network_member", gate.verify_topology(payload))
        payload = topology()
        payload["networks"][0]["Internal"] = False
        self.assertIn("network_internal_flag", gate.verify_topology(payload))
        payload = topology()
        payload["volumes"][0]["Options"] = {"type": "none", "o": "bind", "device": "/host"}
        self.assertIn("volume_driver_or_options", gate.verify_topology(payload))

    def test_missing_and_duplicate_inspect_records_fail_closed(self):
        self.assertTrue(gate.verify_topology({}))
        payload = topology()
        payload["containers"].append(copy.deepcopy(payload["containers"][0]))
        self.assertIn("container_inventory", gate.verify_topology(payload))
        payload = topology()
        del payload["containers"][0]["HostConfig"]["Privileged"]
        self.assertIn("malformed_inspection", gate.verify_topology(payload))

    def test_runtime_gates_never_count_unknown_or_enabled_cron_as_passed(self):
        for value in ({}, {"cron_launch_active_jobs": "on"}, {"external_tcp": "reachable"}):
            self.assertTrue(gate.verify_runtime(value))

    def test_routes_detect_ipv4_and_ipv6_defaults_but_allow_kernel_reject(self):
        header = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
        local = "eth0 000012AC 00000000 0001 0 0 0 0000FFFF 0 0 0\n"
        reject = "0" * 32 + " 00 " + "0" * 32 + " 00 " + "0" * 32 + " ffffffff 0 0 00200200 lo\n"
        self.assertEqual(
            gate.parse_routes(header + local, reject),
            {
                "ipv4_default_route": False,
                "ipv6_default_route": False,
            },
        )
        default = "eth0 00000000 010012AC 0003 0 0 0 00000000 0 0 0\n"
        self.assertTrue(gate.parse_routes(header + local + default, "")["ipv4_default_route"])
        self.assertTrue(
            gate.parse_routes(header, reject.replace("00200200", "00000001"))["ipv6_default_route"]
        )
        with self.assertRaises(gate.VerificationError):
            gate.parse_routes("", "")

    def test_inspection_and_receipt_do_not_select_environment_or_host_paths(self):
        self.assertNotIn(".Config.Env", gate.container_template())
        self.assertNotIn("json .HostConfig}}", gate.container_template())
        payload = topology()
        payload["containers"][0]["Env"] = ["SECRET=private-sentinel"]
        result = json.dumps(gate.sanitized_topology(payload))
        self.assertNotIn("private-sentinel", result)
        self.assertNotIn("Mounts", result)
        self.assertNotIn(str(gate.ROOT), result)

    @patch.object(gate.shutil, "which", return_value="docker.exe")
    @patch.object(gate.subprocess, "run")
    def test_docker_is_always_explicit_local_pipe_and_remote_overrides_are_removed(self, run, _):
        run.return_value = SimpleNamespace(returncode=0, stdout=b"ok")
        with patch.dict(
            gate.os.environ,
            {
                "DOCKER_HOST": "tcp://remote",
                "DOCKER_CONTEXT": "cloud",
                "SUPABASE_ACCESS_TOKEN": "private-sentinel",
            },
        ):
            self.assertEqual(gate.docker(["version"]), "ok")
        args, kwargs = run.call_args
        self.assertEqual(gate.Path(args[0][0]).name, "docker.exe")
        self.assertEqual(args[0][1:3], ["--host", gate.PIPE])
        self.assertFalse(
            any(name.upper().startswith(("DOCKER_", "SUPABASE_")) for name in kwargs["env"])
        )
        self.assertTrue(kwargs["capture_output"])
        self.assertNotIn("shell", kwargs)

    @patch.object(gate, "source_hashes", return_value={"config": "a" * 64})
    @patch.object(gate, "gather_runtime")
    @patch.object(gate, "gather_topology")
    def test_changed_topology_fails_and_unsafe_topology_prevents_external_probe(
        self, gather, runtime, _
    ):
        first = topology()
        second = topology()
        second["containers"][0]["Id"] = "f" * 64
        gather.side_effect = [first, second]
        runtime.return_value = {
            "ipv4_default_route": False,
            "ipv6_default_route": False,
            "external_tcp": "blocked",
            "cron_launch_active_jobs": "off",
        }
        report = gate.run_verification()
        self.assertEqual(report["status"], "failed")
        self.assertIn("environment_changed_during_verification", report["errors"])
        first["containers"][0]["HostConfig"]["Privileged"] = True
        gather.side_effect = [first]
        runtime.reset_mock()
        report = gate.run_verification()
        self.assertEqual(report["status"], "failed")
        runtime.assert_not_called()

    @patch.object(gate, "source_hashes", return_value={"config": "a" * 64})
    @patch.object(
        gate, "gather_topology", side_effect=gate.VerificationError("docker_command_failed")
    )
    def test_runtime_failure_is_fixed_and_never_passed(self, *_):
        report = gate.run_verification()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["errors"], ["docker_command_failed"])
