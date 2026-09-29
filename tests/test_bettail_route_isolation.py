"""Offline synthetic metadata tests; never live Docker or application evidence."""

import copy
import json
import shutil
import stat
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from scripts import verify_bettail_routes as gate
from tests.test_supabase_isolation import topology as base_topology


def contract():
    return {
        "schema_version": 1,
        "profile": gate.PROFILE,
        "image_id": gate.IMAGE,
        "snapshot_digest": "a" * 64,
        "runtime_files": {"package.json": "b" * 64, "node_modules/next/package.json": "c" * 64},
        "harness_files": {name: "d" * 64 for name in gate.LAB_FILES},
    }


def topology():
    payload = base_topology()
    next_id = "e" * 64
    payload["containers"].append(
        {
            "Name": "/" + gate.NEXT,
            "Id": next_id,
            "Image": gate.IMAGE,
            "Running": True,
            "State": "running",
            "User": "65534:65534",
            "Networks": {gate.base.BACKEND: {"NetworkID": payload["networks"][0]["Id"]}},
            "Ports": {"5000/tcp": None},
            "Entrypoint": ["node"],
            "Cmd": ["/lab/runtime.mjs"],
            "WorkingDir": "/app",
            "HostConfig": {
                "NetworkMode": gate.base.BACKEND,
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "PidMode": "",
                "IpcMode": "private",
                "Devices": [],
                "ReadonlyRootfs": True,
                "SecurityOpt": ["no-new-privileges:true"],
                "PortBindings": {},
                "UTSMode": "",
                "UsernsMode": "",
                "CgroupnsMode": "private",
                "DeviceRequests": [],
                "PublishAllPorts": False,
                "ExtraHosts": [],
                "Links": [],
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "Memory": 2 * 1024**3,
                "MemorySwap": 2 * 1024**3,
                "NanoCpus": 2_000_000_000,
                "CpuQuota": 0,
                "CpuPeriod": 0,
                "PidsLimit": 256,
                "OomKillDisable": False,
                "Tmpfs": {
                    "/app/.next": "rw,nosuid,nodev,noexec,size=768m",
                    "/tmp": "rw,nosuid,nodev,noexec,size=128m",
                },
            },
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": str(gate.RUNTIME / name),
                    "Destination": "/" + name,
                    "RW": name == "evidence",
                    "Propagation": "rprivate",
                }
                for name in ("app", "lab", "evidence")
            ],
        }
    )
    payload["networks"][0]["Containers"][next_id] = {"Name": gate.NEXT}
    return payload


BASE_RUNTIME = {
    "ipv4_default_route": False,
    "ipv6_default_route": False,
    "external_tcp": "blocked",
    "cron_launch_active_jobs": "off",
}
NEXT_RUNTIME = {
    name: value for name, value in BASE_RUNTIME.items() if name != "cron_launch_active_jobs"
}


class RouteTopologyTests(TestCase):
    def test_exact_profile_passes_without_mutating_or_weakening_original_gate(self):
        value = topology()
        original = copy.deepcopy(value)
        self.assertEqual(gate.verify_topology(value), [])
        self.assertEqual(value, original)
        self.assertIn("container_inventory", gate.base.verify_topology(value))
        self.assertEqual(gate.base.verify_topology(base_topology()), [])
        self.assertTrue(gate.verify_topology(base_topology()))
        value["containers"][-1]["HostConfig"]["SecurityOpt"] = ["no-new-privileges"]
        self.assertEqual(gate.verify_topology(value), [])

    def test_projection_removes_only_verified_row_and_endpoint_and_uses_a_deep_copy(self):
        value = topology()
        with patch.object(gate.base, "verify_topology", return_value=[]) as verify:
            self.assertEqual(gate.verify_topology(value), [])
        passed = verify.call_args.args[0]
        self.assertEqual(len(passed["containers"]), 7)
        self.assertEqual(len(passed["networks"][0]["Containers"]), 7)
        passed["containers"][0]["HostConfig"]["Privileged"] = True
        self.assertFalse(value["containers"][0]["HostConfig"]["Privileged"])
        passed["networks"][0]["Containers"].clear()
        self.assertEqual(len(value["networks"][0]["Containers"]), 8)

    def test_unknown_duplicate_missing_or_misidentified_eighth_container_is_rejected(self):
        mutations = (
            lambda value: value["containers"].append(copy.deepcopy(value["containers"][-1])),
            lambda value: value["containers"].pop(),
            lambda value: value["containers"][-1].update({"Name": "/unrelated-app"}),
            lambda value: value["containers"][-1].update({"Id": "0" * 64}),
            lambda value: value["networks"][0]["Containers"].update({"unknown": {"Name": "proxy"}}),
            lambda value: value["networks"][0]["Containers"].update(
                {"unknown": {"Name": gate.NEXT}}
            ),
            lambda value: value["networks"][0]["Containers"]["e" * 64].update({"Name": "proxy"}),
            lambda value: value["containers"][-1]["Networks"][gate.base.BACKEND].update(
                {"NetworkID": "wrong"}
            ),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = topology()
                mutate(value)
                with patch.object(gate.base, "verify_topology") as verify:
                    self.assertTrue(gate.verify_topology(value))
                    verify.assert_not_called()

    def test_base_privilege_network_and_relay_failures_are_still_checked(self):
        mutations = (
            lambda value: value["containers"][0]["HostConfig"].update({"Privileged": True}),
            lambda value: value["networks"][0].update({"Internal": False}),
            lambda value: value["networks"][1]["Containers"].update({"extra": {"Name": gate.NEXT}}),
            lambda value: value["containers"][-2]["Mounts"][0].update({"RW": True}),
        )
        for mutate in mutations:
            value = topology()
            mutate(value)
            self.assertTrue(gate.verify_topology(value))

    def test_next_privileges_namespace_network_restart_and_resource_denials(self):
        changes = (
            {"Privileged": True},
            {"ReadonlyRootfs": False},
            {"CapAdd": ["NET_ADMIN"]},
            {"CapDrop": []},
            {"SecurityOpt": []},
            {"SecurityOpt": ["no-new-privileges", "seccomp=unconfined"]},
            {"PidMode": "host"},
            {"IpcMode": "host"},
            {"UTSMode": "host"},
            {"UsernsMode": "host"},
            {"CgroupnsMode": "host"},
            {"NetworkMode": "host"},
            {"Devices": [{"PathOnHost": "/dev/sda"}]},
            {"DeviceRequests": [{"Driver": "gpu"}]},
            {"ExtraHosts": ["host.docker.internal:host-gateway"]},
            {"Links": ["other:other"]},
            {"RestartPolicy": {"Name": "always", "MaximumRetryCount": 0}},
            {"Memory": 0},
            {"Memory": 3 * 1024**3},
            {"NanoCpus": 0},
            {"NanoCpus": 3_000_000_000},
            {"PidsLimit": -1},
            {"PidsLimit": 257},
            {"PidsLimit": True},
            {"MemorySwap": -1},
            {"MemorySwap": 0},
            {"MemorySwap": 4 * 1024**3},
            {"CpuQuota": -1},
            {"CpuQuota": False},
            {"CpuPeriod": None},
            {"OomKillDisable": True},
        )
        for changeset in changes:
            with self.subTest(change=changeset):
                value = topology()
                value["containers"][-1]["HostConfig"].update(changeset)
                self.assertTrue(gate.verify_topology(value))
        for change in (
            {"User": "root"},
            {"Image": "sha256:" + "f" * 64},
            {"Running": False},
            {"Entrypoint": ["sh"]},
            {"Cmd": ["/other.mjs"]},
            {"WorkingDir": "/"},
            {"Networks": {gate.base.BACKEND: {}, gate.base.EDGE: {}}},
        ):
            value = topology()
            value["containers"][-1].update(change)
            self.assertTrue(gate.verify_topology(value))

    def test_inert_image_port_metadata_is_allowed_but_configured_or_published_ports_fail(self):
        self.assertEqual(gate.verify_topology(topology()), [])
        for change in ({"PublishAllPorts": True}, {"PortBindings": {"3000/tcp": None}}):
            value = topology()
            value["containers"][-1]["HostConfig"].update(change)
            self.assertIn("route_published_port", gate.verify_topology(value))
        value = topology()
        value["containers"][-1]["Ports"]["3000/tcp"] = [{"HostIp": "127.0.0.1", "HostPort": "3000"}]
        self.assertIn("route_published_port", gate.verify_topology(value))

    def test_exact_mounts_cannot_substitute_original_source_socket_or_write_access(self):
        changes = (
            {"Source": str(gate.ROOT.parent / "bettail")},
            {"Source": "/var/run/docker.sock"},
            {"RW": True},
            {"Type": "volume"},
            {"Propagation": "rshared"},
            {"Destination": "/other"},
        )
        for changeset in changes:
            value = topology()
            value["containers"][-1]["Mounts"][0].update(changeset)
            self.assertTrue(gate.verify_topology(value))
        value = topology()
        value["containers"][-1]["Mounts"].append(
            copy.deepcopy(value["containers"][-1]["Mounts"][0])
        )
        self.assertIn("route_mount_inventory", gate.verify_topology(value))
        value = topology()
        value["containers"][-1]["Mounts"][2]["RW"] = False
        self.assertIn("route_mount_boundary", gate.verify_topology(value))

    def test_tmpfs_requires_bounded_size_safety_options_and_only_two_destinations(self):
        for options in (
            "rw,size=768m",
            "rw,nosuid,nodev,noexec,size=4g",
            "rw,nosuid,nodev,noexec",
            "rw,nosuid,nodev,noexec,size=0",
            "rw,nosuid,nodev,noexec,size=768m,exec",
            "rw,nosuid,nodev,noexec,size=128m,size=1g",
            "rw,nosuid,nodev,noexec,size=128m,uid=0",
        ):
            value = topology()
            value["containers"][-1]["HostConfig"]["Tmpfs"]["/tmp"] = options
            self.assertIn("route_tmpfs_bounds", gate.verify_topology(value))
        value = topology()
        value["containers"][-1]["HostConfig"]["Tmpfs"]["/var/run"] = "rw,size=1m"
        self.assertIn("route_tmpfs_bounds", gate.verify_topology(value))
        value = topology()
        value["containers"][-1]["Mounts"].append(
            {"Type": "tmpfs", "Source": "", "Destination": "/tmp", "RW": True}
        )
        self.assertEqual(gate.verify_topology(value), [])

    def test_missing_malformed_metadata_fails_closed(self):
        for value in ({}, {"containers": None}, {"containers": [None]}, []):
            self.assertTrue(gate.verify_topology(value))
        value = topology()
        del value["containers"][-1]["HostConfig"]["Memory"]
        self.assertEqual(gate.verify_topology(value), ["route_malformed_inspection"])


class RouteContractTests(TestCase):
    def test_contract_accepts_only_fixed_profile_hashes_and_allowlisted_paths(self):
        self.assertEqual(gate.validate_contract(contract()), contract())
        npm_inventory = contract()
        npm_inventory["runtime_files"]["node_modules/.package-lock.json"] = "e" * 64
        self.assertEqual(gate.validate_contract(npm_inventory), npm_inventory)
        changes = (
            {"target": "remote"},
            {"schema_version": True},
            {"snapshot_digest": "../source"},
            {"profile": "other"},
            {"image_id": "sha256:" + "f" * 64},
            {"harness_files": {"other.mjs": "a" * 64}},
            {"runtime_files": {".env": "a" * 64}},
            {"runtime_files": {"../source.ts": "a" * 64}},
            {"runtime_files": {"src/a.ts": "invalid"}},
            {"runtime_files": {"node_modules/.bin/next": "a" * 64}},
            {"runtime_files": {"node_modules/unexpected.json": "a" * 64}},
            {"runtime_files": {"node_modules/.unexpected": "a" * 64}},
            {"runtime_files": {"node_modules/.env": "a" * 64}},
            {"runtime_files": {"node_modules/.git/config": "a" * 64}},
            {"runtime_files": {"node_modules/pkg/.npmrc": "a" * 64}},
            {"runtime_files": {"node_modules/pkg/.env.local": "a" * 64}},
            {"runtime_files": {"src/a.ts": "a" * 64, "src/A.ts": "a" * 64}},
        )
        for changed in changes:
            with self.subTest(change=changed):
                value = contract()
                value.update(changed)
                with self.assertRaises(gate.VerificationError):
                    gate.validate_contract(value)
        with self.assertRaises(gate.VerificationError):
            json.loads(
                '{"schema_version":1,"schema_version":2}', object_pairs_hook=gate._unique_json
            )

    def test_fixed_contract_has_no_cli_configuration_argument(self):
        self.assertEqual(gate.CONTRACT, gate.ROOT / "var/labs/bettail/routes/runtime.json")
        with patch.object(gate.sys, "argv", ["verify_bettail_routes.py", "--target", "remote"]):
            with patch.object(gate, "run_verification") as run, self.assertRaises(SystemExit):
                gate.main()
            run.assert_not_called()

    def test_safe_paths_reject_reparse_files_and_linked_ancestors_without_reading_them(self):
        path = gate.RUNTIME / "app/package.json"
        with patch.object(Path, "resolve", lambda value: value):
            with patch.object(
                Path,
                "lstat",
                return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT
                ),
            ):
                with self.assertRaisesRegex(gate.VerificationError, "route_link_or_reparse_path"):
                    gate._safe(path)
            with patch.object(
                Path,
                "lstat",
                return_value=SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0),
            ):
                with self.assertRaisesRegex(gate.VerificationError, "route_link_or_reparse_path"):
                    gate._safe(path)
        with self.assertRaisesRegex(gate.VerificationError, "route_path_boundary"):
            gate._safe(gate.ROOT.parent / "bettail")

    def test_source_manifest_must_equal_verified_snapshot_before_files_are_read(self):
        with (
            patch.object(gate, "read_contract", return_value=contract()),
            patch.object(gate, "_safe"),
            patch.object(
                gate.snapshot_app,
                "verify_snapshot",
                return_value={
                    "snapshot_digest": "a" * 64,
                    "app": "bettail",
                    "files": {"package.json": "f" * 64},
                },
            ),
            patch.object(gate, "_tree") as tree,
        ):
            with self.assertRaisesRegex(
                gate.VerificationError, "route_source_differs_from_snapshot"
            ):
                gate.source_hashes()
            tree.assert_not_called()

    def test_tree_detects_extra_missing_and_changed_files_using_temporary_synthetic_bytes(self):
        parent = gate.ROOT / "var/tests"
        case = parent / ("route-gate-" + uuid.uuid4().hex)
        case.mkdir(parents=True)
        try:
            path = case / "synthetic.js"
            path.write_bytes(b"synthetic")
            manifest = {"synthetic.js": gate.base.sha256(b"synthetic")}
            self.assertEqual(gate._tree(case, manifest), manifest)
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(gate.VerificationError, "route_tree_content"):
                gate._tree(case, manifest)
            with self.assertRaisesRegex(gate.VerificationError, "route_tree_inventory"):
                gate._tree(case, {})
            with self.assertRaisesRegex(gate.VerificationError, "route_tree_inventory"):
                gate._tree(case, {"missing.js": "a" * 64})
        finally:
            resolved = case.resolve()
            if not resolved.is_relative_to(parent.resolve()) or not resolved.name.startswith(
                "route-gate-"
            ):
                raise RuntimeError("Unsafe synthetic test cleanup boundary")
            shutil.rmtree(resolved)

    def test_only_exact_two_generated_next_declaration_imports_may_change(self):
        raw = b'import "./.next/types/routes.d.ts";\nimport "./.next/types/root-params.d.ts";\n'
        expected = raw.replace(b'"./.next/types/', b'"./.next/dev/types/')
        value = contract()
        value["runtime_files"]["next-env.d.ts"] = gate.base.sha256(expected)
        original = {"package.json": "b" * 64, "next-env.d.ts": gate.base.sha256(raw)}
        with (
            patch.object(gate, "read_contract", return_value=value),
            patch.object(gate, "_safe"),
            patch.object(
                gate.snapshot_app,
                "verify_snapshot",
                return_value={
                    "snapshot_digest": "a" * 64,
                    "app": "bettail",
                    "files": original,
                },
            ),
            patch.object(gate, "_tree"),
            patch.object(gate.base, "source_hashes", return_value={}),
            patch.object(Path, "read_bytes", return_value=raw),
        ):
            result = gate.source_hashes()
            self.assertEqual(
                result["generated_declaration_adjustment"],
                {
                    "original_sha256": gate.base.sha256(raw),
                    "runtime_sha256": gate.base.sha256(expected),
                },
            )
            value["runtime_files"]["next-env.d.ts"] = gate.base.sha256(
                expected + b"unsafe extra code"
            )
            with self.assertRaisesRegex(gate.VerificationError, "route_declaration_transform"):
                gate.source_hashes()
            value["runtime_files"]["next-env.d.ts"] = gate.base.sha256(expected)
            value["runtime_files"]["package.json"] = "e" * 64
            with self.assertRaisesRegex(
                gate.VerificationError, "route_source_differs_from_snapshot"
            ):
                gate.source_hashes()

    def test_hard_links_are_not_accepted_as_copied_runtime_files(self):
        with (
            patch.object(Path, "resolve", lambda value: value),
            patch.object(
                Path,
                "lstat",
                return_value=SimpleNamespace(
                    st_mode=stat.S_IFREG,
                    st_file_attributes=0,
                    st_nlink=2,
                ),
            ),
        ):
            with self.assertRaisesRegex(gate.VerificationError, "route_hard_link"):
                gate._safe(gate.RUNTIME / "app/package.json", directory=False)


class RouteRuntimeTests(TestCase):
    def test_unknown_or_numeric_runtime_claims_are_not_passed_as_booleans(self):
        for runtime in (
            {},
            {**NEXT_RUNTIME, "ipv4_default_route": 0},
            {**NEXT_RUNTIME, "ipv6_default_route": None},
            {**NEXT_RUNTIME, "external_tcp": "reachable"},
        ):
            self.assertTrue(gate.verify_next_runtime(runtime))

    def test_next_probe_is_fixed_and_does_not_include_payload_or_remote_target_inputs(self):
        routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
        with patch.object(gate.base, "docker", side_effect=[routes, "", "blocked"]) as docker:
            self.assertEqual(gate.gather_next_runtime(), NEXT_RUNTIME)
        calls = [call.args[0] for call in docker.call_args_list]
        self.assertTrue(all(arguments[:3] == ["exec", gate.NEXT, "node"] for arguments in calls))
        self.assertIn("host:'1.1.1.1',port:443", calls[-1][-1])
        self.assertNotIn("s.write", calls[-1][-1])
        self.assertIn("3000", calls[-1][-1])

    def test_next_default_route_prevents_egress_probe(self):
        routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
        routes += "eth0 00000000 010012AC 0003 0 0 0 00000000 0 0 0\n"
        with patch.object(gate.base, "docker", side_effect=[routes, ""]) as docker:
            runtime = gate.gather_next_runtime()
        self.assertEqual(docker.call_count, 2)
        self.assertIn("route_ipv4_default_route", gate.verify_next_runtime(runtime))
        self.assertEqual(runtime["external_tcp"], "not_run_unsafe_routes")

    def test_inspection_and_receipts_exclude_environment_mount_paths_and_commands(self):
        template = gate.next_template()
        self.assertNotIn(".Config.Env", template)
        self.assertNotIn("json .HostConfig}}", template)
        value = topology()
        value["containers"][-1]["Env"] = ["SECRET=private-sentinel"]
        body = json.dumps(gate.base.sanitized_topology(value))
        for excluded in (
            "private-sentinel",
            str(gate.RUNTIME),
            "runtime.mjs",
            "Entrypoint",
            "Mounts",
        ):
            self.assertNotIn(excluded, body)

    def _run(self, before=None, after=None, hashes=None, base_runtime=None):
        with (
            patch.object(
                gate, "source_hashes", side_effect=hashes or [{"safe": "a"}, {"safe": "a"}]
            ),
            patch.object(
                gate, "gather_topology", side_effect=[before or topology(), after or topology()]
            ),
            patch.object(
                gate.base, "gather_runtime", return_value=base_runtime or BASE_RUNTIME
            ) as base_probe,
            patch.object(gate, "gather_next_runtime", return_value=NEXT_RUNTIME) as next_probe,
        ):
            report = gate.run_verification()
        return report, base_probe, next_probe

    def test_full_pass_requires_topology_sources_base_cron_and_next_egress(self):
        report, base_probe, next_probe = self._run()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["errors"], [])
        base_probe.assert_called_once()
        next_probe.assert_called_once()
        self.assertEqual(report["source_hashes"], report["source_hashes_after"])
        self.assertEqual(report["topology_sha256"], report["topology_after_sha256"])

    def test_unsafe_topology_prevents_all_runtime_probes(self):
        before = topology()
        before["containers"][-1]["HostConfig"]["Privileged"] = True
        report, base_probe, next_probe = self._run(before=before)
        self.assertEqual(report["status"], "failed")
        base_probe.assert_not_called()
        next_probe.assert_not_called()

    def test_enabled_cron_prevents_next_runtime_probe_and_cannot_pass(self):
        report, _, next_probe = self._run(
            base_runtime={**BASE_RUNTIME, "cron_launch_active_jobs": "on"}
        )
        self.assertEqual(report["status"], "failed")
        self.assertIn("cron_launch_active_jobs", report["errors"])
        next_probe.assert_not_called()

    def test_changed_topology_or_mounted_source_during_gate_cannot_pass(self):
        after = topology()
        after["containers"][0]["Id"] = "f" * 64
        for arguments in ({"after": after}, {"hashes": [{"safe": "a"}, {"safe": "b"}]}):
            report, _, _ = self._run(**arguments)
            self.assertEqual(report["status"], "failed")
            self.assertIn("route_environment_changed_during_verification", report["errors"])

    def test_unreadable_source_or_invalid_probe_is_a_fixed_failure_not_raw_output(self):
        with patch.object(gate, "source_hashes", side_effect=OSError("private-sentinel")):
            report = gate.run_verification()
        self.assertEqual(report["errors"], ["route_verification_input_or_runtime_failure"])
        self.assertNotIn("private-sentinel", json.dumps(report))
        routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
        with patch.object(gate.base, "docker", side_effect=[routes, "", "private-sentinel"]):
            with self.assertRaisesRegex(gate.VerificationError, "route_invalid_connection_probe"):
                gate.gather_next_runtime()
