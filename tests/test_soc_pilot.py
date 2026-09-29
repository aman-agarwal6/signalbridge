"""Mocked Docker metadata only: these tests do not start or inspect live services."""

import copy
import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock

from scripts import verify_soc_pilot as gate

RUN = "3c900877-8bf7-49f4-bcaa-531d1baf57d3"


def fixture(profile="zap", state="running"):
    names = gate.NAMES[profile]
    result = {"containers": [], "images": [], "networks": [], "active": []}
    members = {}
    for index, name in enumerate(names, 1):
        expected = gate.profiles(RUN)[name]
        identity, endpoint_id = str(index) * 64, str(index + 4) * 64
        image_id = "sha256:" + str(index + 2) * 64
        host = dict.fromkeys(gate.HOST_FIELDS)
        host.update(
            {
                "NetworkMode": expected["network"],
                "Privileged": False,
                "ReadonlyRootfs": expected["readonly"],
                "CapDrop": ["ALL"],
                "CapAdd": expected["capabilities"],
                "SecurityOpt": ["no-new-privileges:true"],
                "PidMode": "",
                "UTSMode": "",
                "UsernsMode": "",
                "IpcMode": "private",
                "CgroupnsMode": "private",
                "PortBindings": {},
                "PublishAllPorts": False,
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "AutoRemove": False,
                "Memory": expected["memory"],
                "MemorySwap": expected["memory"],
                "MemoryReservation": 0,
                "NanoCpus": expected["cpus"],
                "PidsLimit": expected["pids"],
                "CpuQuota": 0,
                "CpuPeriod": 0,
                "Tmpfs": expected["tmpfs"],
                "LogConfig": copy.deepcopy(gate.LOG_CONFIG),
                "MaskedPaths": ["/proc/kcore", "/proc/keys", "/proc/timer_list", "/sys/firmware"],
                "ReadonlyPaths": [
                    "/proc/bus",
                    "/proc/fs",
                    "/proc/irq",
                    "/proc/sys",
                    "/proc/sysrq-trigger",
                ],
            }
        )
        endpoint = {
            "NetworkID": "9" * 64 if state == "running" else "",
            "EndpointID": endpoint_id if state == "running" else "",
            "Gateway": "",
            "IPAddress": "" if profile == "wazuh" else f"172.28.0.{index + 1}",
            "GlobalIPv6Address": "",
            "IPv6Gateway": "",
            "Aliases": ["signalbridge-zap-target"] if name == gate.TARGET else None,
        }
        row = {
            "Name": "/" + name,
            "Id": identity,
            "Image": image_id,
            "ConfiguredImage": gate.IMAGES[name],
            "State": state,
            "Running": state == "running",
            "Entrypoint": expected["entrypoint"],
            "Cmd": expected["command"],
            "User": expected["user"],
            "WorkingDir": expected["workdir"],
            "Hostname": "signalbridge-zap-target" if name == gate.TARGET else name,
            "Healthcheck": {"Test": ["NONE"]},
            "HostConfig": host,
            "Ports": None,
            "Networks": {expected["network"]: endpoint},
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": str(source),
                    "Destination": destination,
                    "RW": writable,
                    "Propagation": "rprivate",
                }
                for destination, (source, writable) in expected["mounts"].items()
            ],
        }
        result["containers"].append(row)
        result["images"].append(
            {
                "Id": image_id,
                "RepoDigests": [gate.IMAGES[name]],
                "Architecture": "amd64",
                "Os": "linux",
            }
        )
        if state == "running":
            result["active"].append(name)
            members[identity] = {"Name": name, "EndpointID": endpoint_id}
    if profile == "zap":
        result["networks"].append(
            {
                "Name": gate.NETWORK,
                "Id": "9" * 64,
                "Driver": "bridge",
                "Internal": True,
                "EnableIPv6": False,
                "Attachable": False,
                "Ingress": False,
                "Scope": "local",
                "Options": {"com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"},
                "Containers": members,
            }
        )
    return result


class SocPilotMetadataTests(TestCase):
    def check_bad(self, mutate, diagnostic, *, profile="zap", state="running"):
        value = fixture(profile, state)
        mutate(value)
        self.assertIn(diagnostic, gate.verify_topology(value, profile, RUN, state=state))

    def test_both_fixed_profiles_accept_created_running_and_exited_mock_metadata(self):
        for profile in gate.NAMES:
            for state in gate.STATES:
                with self.subTest(profile=profile, state=state):
                    value = fixture(profile, state)
                    original = copy.deepcopy(value)
                    self.assertEqual(gate.verify_topology(value, profile, RUN, state=state), [])
                    self.assertEqual(value, original)

    def test_requests_cannot_select_other_targets_paths_or_noncanonical_ids(self):
        for run in ("../lab", RUN.upper(), str(uuid.uuid1()), "", None):
            with self.subTest(run=run), self.assertRaises(gate.VerificationError):
                gate.validate_request("zap", run, "created")
        for profile, state in (("other", "running"), ("zap", "paused")):
            self.assertTrue(gate.verify_topology({}, profile, RUN, state=state))

    def test_unknown_duplicate_missing_containers_and_rows_fail_closed(self):
        for mutate in (
            lambda value: value["containers"].append(copy.deepcopy(value["containers"][0])),
            lambda value: value["containers"].pop(),
            lambda value: value.update(extra={}),
            lambda value: value["containers"][0].pop("HostConfig"),
        ):
            value = fixture()
            mutate(value)
            self.assertTrue(gate.verify_topology(value, "zap", RUN))

    def test_active_other_project_and_underreported_active_inventory_are_rejected(self):
        for names in ([*gate.NAMES["zap"], "supabase_db_other"], [gate.ZAP], None, [["bad"]]):
            self.check_bad(
                lambda value, names=names: value.update(active=names), "soc_active_inventory"
            )
        self.check_bad(
            lambda value: value.update(active=[gate.ZAP]), "soc_active_inventory", state="created"
        )

    def test_mutable_image_tag_wrong_digest_platform_or_local_identity_rejected(self):
        mutations = (
            lambda value: value["containers"][0].update(
                ConfiguredImage="zaproxy/zap-stable:latest"
            ),
            lambda value: value["containers"][0].update(Image="sha256:" + "f" * 64),
            lambda value: value["images"][0].update(RepoDigests=["unknown@sha256:" + "a" * 64]),
            lambda value: value["images"][0].update(Architecture="arm64"),
            lambda value: value["images"][0].update(Os="windows"),
        )
        for mutation in mutations:
            self.check_bad(mutation, "soc_image_identity")

    def test_inherited_exposed_port_is_inert_but_configured_or_published_bindings_rejected(self):
        value = fixture()
        value["containers"][0]["Ports"] = {"8080/tcp": None}
        self.assertEqual(gate.verify_topology(value, "zap", RUN), [])
        self.check_bad(
            lambda value: value["containers"][0].update(
                Ports={"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}
            ),
            "soc_published_port",
        )
        for key, setting in (("PortBindings", {"8080/tcp": []}), ("PublishAllPorts", True)):
            self.check_bad(
                lambda value, key=key, setting=setting: value["containers"][0]["HostConfig"].update(
                    {key: setting}
                ),
                "soc_host_port",
            )

    def test_entrypoint_command_user_workdir_hostname_and_healthcheck_are_fixed(self):
        for key, bad in (
            ("Entrypoint", ["sh"]),
            ("Cmd", ["-c", "anything"]),
            ("User", "root"),
            ("WorkingDir", "/"),
        ):
            self.check_bad(
                lambda value, key=key, bad=bad: value["containers"][0].update({key: bad}),
                "soc_execution_contract",
            )
        self.check_bad(
            lambda value: value["containers"][0].update(Hostname="anything"),
            "soc_hostname_contract",
        )
        self.check_bad(
            lambda value: value["containers"][0].update(
                Healthcheck={"Test": ["CMD", "curl", "https://example.com"]}
            ),
            "soc_unreviewed_healthcheck",
        )

    def test_capabilities_are_exact_and_no_unconfined_security_profile(self):
        for key, bad in (
            ("CapAdd", ["SYS_ADMIN"]),
            ("CapDrop", []),
            ("SecurityOpt", ["seccomp=unconfined"]),
            ("SecurityOpt", []),
        ):
            self.check_bad(
                lambda value, key=key, bad=bad: value["containers"][0]["HostConfig"].update(
                    {key: bad}
                ),
                "soc_capability_or_security_options",
            )
        self.check_bad(
            lambda value: value["containers"][0]["HostConfig"].update(CapAdd=["SETUID", "SETGID"]),
            "soc_capability_or_security_options",
            profile="wazuh",
        )

    def test_host_namespaces_devices_dns_links_and_kernel_overrides_rejected(self):
        for key in ("PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode"):
            self.check_bad(
                lambda value, key=key: value["containers"][0]["HostConfig"].update({key: "host"}),
                "soc_namespace_boundary",
            )
        for key in (
            "Devices",
            "DeviceRequests",
            "DeviceCgroupRules",
            "ExtraHosts",
            "Links",
            "VolumesFrom",
            "Dns",
            "DnsOptions",
            "DnsSearch",
        ):
            self.check_bad(
                lambda value, key=key: value["containers"][0]["HostConfig"].update(
                    {key: ["unsafe"]}
                ),
                "soc_device_or_external_reference",
            )
        for key in ("StorageOpt", "Sysctls"):
            self.check_bad(
                lambda value, key=key: value["containers"][0]["HostConfig"].update(
                    {key: {"unsafe": "1"}}
                ),
                "soc_storage_or_kernel_override",
            )
        self.check_bad(
            lambda value: value["containers"][0]["HostConfig"].update(MaskedPaths=[]),
            "soc_kernel_path_protection",
        )

    def test_docker_canonical_cap_prefix_is_equivalent_but_duplicates_and_extra_caps_fail(self):
        value = fixture("wazuh", "created")
        value["containers"][0]["HostConfig"]["CapAdd"] = [
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SYS_CHROOT",
        ]
        self.assertEqual(gate.verify_topology(value, "wazuh", RUN, state="created"), [])
        for added in (
            ["CAP_SETGID", "CAP_SETUID", "CAP_SYS_CHROOT", "SETUID"],
            ["CAP_SETGID", "CAP_SETUID", "CAP_SYS_CHROOT", "CAP_SYS_ADMIN"],
            ["CAP_CAP_SETGID", "CAP_SETUID", "CAP_SYS_CHROOT"],
            "CAP_SETGID,CAP_SETUID,CAP_SYS_CHROOT",
        ):
            self.check_bad(
                lambda data, added=added: data["containers"][0]["HostConfig"].update(CapAdd=added),
                "soc_capability_or_security_options",
                profile="wazuh",
                state="created",
            )

    def test_resources_restart_logs_and_tmpfs_are_bounded_exactly(self):
        for key in ("Memory", "MemorySwap", "NanoCpus", "PidsLimit"):
            for bad in (0, -1, True, 99_000_000_000):
                self.check_bad(
                    lambda value, key=key, bad=bad: value["containers"][0]["HostConfig"].update(
                        {key: bad}
                    ),
                    "soc_resource_limits",
                )
        for key, bad, diagnostic in (
            ("LogConfig", {"Type": "json-file", "Config": {}}, "soc_log_limits"),
            ("RestartPolicy", {"Name": "always", "MaximumRetryCount": 0}, "soc_restart_or_removal"),
            ("AutoRemove", True, "soc_restart_or_removal"),
            ("Tmpfs", {"/tmp": "size=10g,exec"}, "soc_tmpfs_contract"),
            ("OomKillDisable", True, "soc_resource_override"),
            ("CpuQuota", -1, "soc_resource_override"),
        ):
            self.check_bad(
                lambda value, key=key, bad=bad: value["containers"][0]["HostConfig"].update(
                    {key: bad}
                ),
                diagnostic,
            )

    def test_mounts_cannot_escape_run_directory_be_writable_source_or_include_socket(self):
        for key, bad in (
            ("Source", str(gate.ROOT.parent)),
            ("RW", True),
            ("Type", "volume"),
            ("Propagation", "rshared"),
        ):
            self.check_bad(
                lambda value, key=key, bad=bad: value["containers"][0]["Mounts"][0].update(
                    {key: bad}
                ),
                "soc_mount_contract",
            )
        self.check_bad(
            lambda value: value["containers"][0]["Mounts"].append(
                {
                    "Destination": "/var/run/docker.sock",
                    "Type": "bind",
                    "Source": "/var/run/docker.sock",
                    "RW": True,
                    "Propagation": "rprivate",
                }
            ),
            "soc_mount_contract",
        )
        self.check_bad(
            lambda value: value["containers"][0]["Mounts"][1].update(
                Source=str(gate.ROOT / "var/soc/pilot" / str(uuid.uuid4()) / "zap")
            ),
            "soc_mount_contract",
        )

    def test_internal_network_rejects_external_members_edges_ipv6_or_extra_options(self):
        for key, bad in (
            ("Internal", False),
            ("Driver", "host"),
            ("EnableIPv6", True),
            ("Attachable", True),
            ("Ingress", True),
            ("Scope", "swarm"),
            ("Options", {}),
        ):
            self.check_bad(
                lambda value, key=key, bad=bad: value["networks"][0].update({key: bad}),
                "soc_network_boundary",
            )
        self.check_bad(
            lambda value: value["networks"][0]["Containers"].update({"f" * 64: {"Name": "other"}}),
            "soc_network_endpoint_inventory",
        )
        self.check_bad(
            lambda value: value["containers"][0]["Networks"].update(bridge={}),
            "soc_container_network_inventory",
        )

    def test_network_endpoint_ids_aliases_gateways_and_overrides_are_verified(self):
        for key, bad in (
            ("NetworkID", "a" * 64),
            ("EndpointID", "a" * 64),
            ("Gateway", "172.28.0.1"),
            ("GlobalIPv6Address", "fe80::1"),
        ):
            self.check_bad(
                lambda value, key=key, bad=bad: value["containers"][0]["Networks"][
                    gate.NETWORK
                ].update({key: bad}),
                "soc_network_endpoint_identity",
            )
        self.check_bad(
            lambda value: value["containers"][1]["Networks"][gate.NETWORK].update(Aliases=[]),
            "soc_network_alias_contract",
        )
        self.check_bad(
            lambda value: value["containers"][0]["Networks"][gate.NETWORK].update(
                Aliases=["another-target"]
            ),
            "soc_network_alias_contract",
        )
        self.check_bad(
            lambda value: value["containers"][0]["Networks"][gate.NETWORK].update(
                IPAMConfig={"LinkLocalIPs": ["169.254.169.254"]}
            ),
            "soc_endpoint_override",
        )

    def test_only_exact_optional_docker_ipv4_ipv6_defaults_are_allowed(self):
        for defaults in (
            {"com.docker.network.enable_ipv4": "true"},
            {"com.docker.network.enable_ipv6": "false"},
            {"com.docker.network.enable_ipv4": "true", "com.docker.network.enable_ipv6": "false"},
        ):
            value = fixture(state="created")
            value["networks"][0]["Options"].update(defaults)
            self.assertEqual(gate.verify_topology(value, "zap", RUN, state="created"), [])
        for key, bad in (
            ("com.docker.network.enable_ipv4", "false"),
            ("com.docker.network.enable_ipv6", "true"),
            ("com.docker.network.enable_ipv4", True),
            ("com.docker.network.enable_ipv6", False),
            ("com.docker.network.bridge.host_binding_ipv4", "0.0.0.0"),
            ("com.docker.network.bridge.enable_ip_masquerade", "true"),
            ("unknown", "false"),
        ):
            self.check_bad(
                lambda value, key=key, bad=bad: value["networks"][0]["Options"].update({key: bad}),
                "soc_network_boundary",
                state="created",
            )

    def test_wazuh_requires_network_none_and_zero_addresses(self):
        self.check_bad(
            lambda value: value["containers"][0]["HostConfig"].update(NetworkMode="bridge"),
            "soc_privilege_or_network_mode",
            profile="wazuh",
        )
        self.check_bad(
            lambda value: value["containers"][0]["Networks"]["none"].update(IPAddress="172.17.0.2"),
            "soc_none_network_address",
            profile="wazuh",
        )

    def test_aggregate_profile_limits_stay_inside_authorized_budget(self):
        profiles = gate.profiles(RUN)
        for names in gate.NAMES.values():
            self.assertLessEqual(sum(profiles[name]["memory"] for name in names), 3 * gate.GIB)
            self.assertLessEqual(sum(profiles[name]["cpus"] for name in names), 2_000_000_000)


class SocPilotCollectionTests(TestCase):
    def test_fixed_inspection_calls_never_include_env_or_execute_container_commands(self):
        calls = []

        def inspect(kind, names, template):
            calls.append((kind, names, template))
            self.assertNotIn(".Env", template)
            self.assertNotIn("Config}}", template)
            return []

        with (
            mock.patch.object(gate.base, "inspect_objects", side_effect=inspect),
            mock.patch.object(gate.base, "docker", return_value="") as docker,
        ):
            gate.gather_topology("zap")
        self.assertEqual(calls[0][1], gate.NAMES["zap"])
        self.assertEqual(calls[1][1], tuple(gate.IMAGES[name] for name in gate.NAMES["zap"]))
        self.assertEqual(calls[2][1], (gate.NETWORK,))
        docker.assert_called_once_with(["container", "ls", "--format", "{{json .Names}}"])

    def test_receipt_is_allowlisted_and_private_mounts_metadata_are_omitted(self):
        value = fixture()
        value["containers"][0]["private_extra"] = "NEVER_PRINT_THIS"
        with (
            mock.patch.object(
                gate, "source_hashes", return_value={"package": {"driver": "a" * 64}}
            ),
            mock.patch.object(gate, "gather_topology", return_value=value),
        ):
            result = gate.run_verification("zap", RUN)
        self.assertEqual(result["status"], "passed")
        rendered = json.dumps(result)
        for private in ("NEVER_PRINT_THIS", str(gate.ROOT), "HostConfig", "Mounts"):
            self.assertNotIn(private, rendered)

    def test_source_drift_and_failed_inspection_do_not_report_pass(self):
        with (
            mock.patch.object(gate, "source_hashes", side_effect=[{"a": 1}, {"a": 2}]),
            mock.patch.object(gate, "gather_topology", return_value=fixture()),
        ):
            result = gate.run_verification("zap", RUN)
        self.assertEqual(result["status"], "failed")
        self.assertIn("soc_source_changed_during_inspection", result["errors"])
        self.assertNotIn("containers", result)
        with mock.patch.object(
            gate, "source_hashes", side_effect=OSError("private filesystem detail")
        ):
            result = gate.run_verification("zap", RUN)
        self.assertEqual(result["errors"], ["soc_inspection_or_source_unavailable"])

    def test_source_hashing_requires_fixed_driver_and_rejects_sensitive_source_file(self):
        with (
            mock.patch.object(gate, "_tree", return_value={"fixture.py": "a" * 64}) as tree,
            mock.patch.object(gate, "_safe"),
            mock.patch.object(Path, "read_bytes", return_value=b"synthetic"),
        ):
            with self.assertRaisesRegex(gate.VerificationError, "soc_driver_missing"):
                gate.source_hashes("zap", RUN)
            tree.return_value = {"run_passive.py": "a" * 64, "fixture.py": "b" * 64}
            self.assertIn("package", gate.source_hashes("zap", RUN))
            tree.assert_any_call(gate.ROOT / "var/soc/pilot" / RUN / "zap", evidence=True)
        package = gate.ROOT / "integrations/zap"
        with (
            mock.patch.object(gate, "_safe", return_value=SimpleNamespace(st_size=16)),
            mock.patch.object(Path, "iterdir", return_value=iter([package / ".env"])),
            mock.patch.object(Path, "is_dir", return_value=False),
        ):
            with self.assertRaisesRegex(gate.VerificationError, "soc_unexpected_source_file"):
                gate._tree(package)

    def test_path_boundary_and_windows_reparse_metadata_fail_closed(self):
        with self.assertRaisesRegex(gate.VerificationError, "soc_local_path_boundary"):
            gate._safe(gate.ROOT.parent, directory=True)
        value = SimpleNamespace(
            st_mode=gate.stat.S_IFDIR, st_file_attributes=gate.stat.FILE_ATTRIBUTE_REPARSE_POINT
        )
        with (
            mock.patch.object(Path, "resolve", lambda self: self),
            mock.patch.object(Path, "lstat", return_value=value),
            self.assertRaisesRegex(gate.VerificationError, "soc_link_or_reparse_path"),
        ):
            gate._safe(gate.ROOT / "ordinary", directory=False)
