"""Preservation trust/abuse regressions; no native process, network or file contents."""

import copy
import importlib
import json
import os
import socket
import subprocess
import unittest
import urllib.request
from unittest.mock import Mock, patch

from integrations.wazuh_enterprise import preservation_profile as profile

RUN, OTHER_RUN = "a" * 32, "b" * 32
PRESERVED = [f"{number:064x}" for number in range(1, 9)]
OWNED, UNKNOWN = "c" * 64, "d" * 64
CONTEXT = "e" * 64
DIRECTORY = r"C:\synthetic\signalbridge-public\var\enterprise\runs" + "\\" + RUN
ENGINE = {"id": "synthetic-engine-1", "os_type": "linux"}


def envelope(identifier):
    return {
        "id": identifier,
        "running": True,
        "started_at": "2026-10-03T01:02:03.123456789Z",
        "restart_count": 0,
        "privileged": False,
        "pid_mode": "",
        "ipc_mode": "private",
        "uts_mode": "",
        "cgroupns_mode": "private",
        "network_mode": "accessops_default",
        "memory": 512 * 1024**2,
        "memory_swap": 1024 * 1024**2,
        "nano_cpus": 10**9,
        "pids_limit": 128,
        "networks": {"accessops_default": "f" * 64},
        "mounts": [
            {
                "Type": "volume",
                "Source": "/var/lib/docker/volumes/synthetic/_data",
                "Destination": "/var/lib/postgresql/data",
                "RW": True,
                "Name": "synthetic-volume",
                "Driver": "local",
                "Mode": "z",
                "Propagation": "",
            }
        ],
    }


class WazuhPreservationProfileTests(unittest.TestCase):
    def setUp(self):
        self.forbidden = []
        for target, name in (
            (subprocess, "run"),
            (subprocess, "Popen"),
            (os, "system"),
            (socket, "socket"),
            (socket, "create_connection"),
            (urllib.request, "urlopen"),
        ):
            self.forbidden.append(
                self.enterContext(
                    patch.object(
                        target,
                        name,
                        side_effect=AssertionError("Unexpected native process/network IO"),
                    )
                )
            )
        self.state = {
            "engine": copy.deepcopy(ENGINE),
            "running": list(PRESERVED),
            "envelopes": {identifier: envelope(identifier) for identifier in PRESERVED},
        }
        self.request = Mock(side_effect=self.reply)

    def tearDown(self):
        for boundary in self.forbidden:
            boundary.assert_not_called()

    def reply(self, arguments, *, timeout):
        self.assertIs(type(arguments), tuple)
        self.assertEqual(timeout, 3)
        if arguments == profile.INFO_ARGUMENTS:
            return json.dumps(self.state["engine"])
        if arguments == profile.workloads.RUNNING_ARGUMENTS:
            return "\n".join(self.state["running"])
        self.assertEqual(arguments[:2], ("container", "inspect"))
        self.assertEqual(arguments[3:], ("--format", profile.ENVELOPE_TEMPLATE))
        self.assertEqual(len(arguments), 5)
        self.assertIn(arguments[2], self.state["envelopes"])
        return json.dumps(self.state["envelopes"][arguments[2]])

    def capture(self):
        baseline, public = profile.capture(self.request, RUN, DIRECTORY, CONTEXT)
        return baseline, public["preservation_digest"]

    def checkpoint(self, baseline, digest, owned=(OWNED,)):
        return profile.checkpoint(
            self.request, baseline, RUN, DIRECTORY, CONTEXT, owned, expected_digest=digest
        )

    def test_import_and_adapter_creation_are_inert(self):
        importlib.reload(profile)
        with patch.object(profile.host, "request") as native:
            adapter = profile.bind_request("synthetic-docker", RUN, "synthetic-workspace")
            native.assert_not_called()
            adapter(profile.INFO_ARGUMENTS, timeout=3)
            native.assert_called_once_with(
                "synthetic-docker", RUN, "synthetic-workspace", profile.INFO_ARGUMENTS, timeout=3
            )

    def test_adapter_denies_mutation_full_inspect_image_and_unbounded_timeout(self):
        adapter = profile.bind_request("synthetic-docker", RUN, "synthetic-workspace")
        with patch.object(profile.host, "request") as native:
            for arguments in (
                ("stop", OWNED),
                ("rm", OWNED),
                ("inspect", OWNED),
                ("image", "inspect", "synthetic"),
                ("info", "--format", "{{json .}}"),
                ("container", "inspect", OWNED, "--format", "{{json .Config.Env}}"),
                (
                    "container",
                    "inspect",
                    OWNED,
                    "--format",
                    profile.ENVELOPE_TEMPLATE,
                    "--type=container",
                ),
            ):
                with (
                    self.subTest(arguments=arguments[:2]),
                    self.assertRaises(profile.LabControlError),
                ):
                    adapter(arguments, timeout=3)
            with self.assertRaises(profile.LabControlError):
                adapter(profile.INFO_ARGUMENTS, timeout=30)
            native.assert_not_called()

    def test_eight_private_envelopes_public_counts_and_digests_only(self):
        baseline, digest = self.capture()
        self.assertEqual(len(baseline["envelopes"]), 8)
        self.assertEqual(baseline["run_id"], RUN)
        self.assertEqual(baseline["profile"], profile.PROFILE)
        self.assertEqual(baseline["engine"], ENGINE)
        self.state["running"].append(OWNED)
        public = self.checkpoint(baseline, digest)
        self.assertEqual(public["preserved_count"], 8)
        self.assertEqual(public["owned_running_count"], 1)
        self.assertEqual(public["running_count"], 9)
        self.assertTrue(all(key.endswith(("count", "digest")) for key in public))
        self.assertFalse(
            any(identifier in json.dumps(public) for identifier in PRESERVED + [OWNED])
        )
        self.assertNotIn("synthetic-engine-1", json.dumps(public))
        self.assertNotIn("postgresql", json.dumps(public))
        self.assertNotIn(".Config.Env", profile.ENVELOPE_TEMPLATE)
        self.assertNotIn(".Config.Cmd", profile.ENVELOPE_TEMPLATE)
        self.assertNotIn(".Config.Labels", profile.ENVELOPE_TEMPLATE)
        self.assertEqual(len(self.request.call_args_list), 24)
        self.assertTrue(all(call.kwargs == {"timeout": 3} for call in self.request.call_args_list))

    def test_newly_created_owned_collector_may_not_yet_be_running(self):
        baseline, digest = self.capture()
        public = self.checkpoint(baseline, digest)
        self.assertEqual(public["owned_count"], 1)
        self.assertEqual(public["owned_running_count"], 0)

    def test_maximum_eight_refuses_ninth_before_foreign_inspection(self):
        self.state["running"].append(UNKNOWN)
        with self.assertRaises(profile.LabControlError):
            self.capture()
        self.assertEqual(self.request.call_count, 2)

    def test_one_owned_collector_and_preserved_overlap_fail_before_native_read(self):
        baseline, digest = self.capture()
        self.request.reset_mock()
        for owned in ((OWNED, UNKNOWN), (PRESERVED[0],)):
            with self.subTest(owned_count=len(owned)), self.assertRaises(profile.LabControlError):
                self.checkpoint(baseline, digest, owned)
        self.request.assert_not_called()

    def test_engine_must_be_linux_bounded_scalar_and_minimal(self):
        for engine in (
            {"id": "synthetic", "os_type": "windows"},
            {"id": "", "os_type": "linux"},
            {"id": "x" * 129, "os_type": "linux"},
            {"id": "synthetic\nprivate", "os_type": "linux"},
            {"id": "synthetic", "os_type": "linux", "environment": "synthetic-private"},
            {"id": True, "os_type": "linux"},
        ):
            self.state["engine"] = engine
            with (
                self.subTest(engine_fields=len(engine)),
                self.assertRaises(profile.LabControlError),
            ):
                self.capture()

    def test_engine_switch_detected_during_capture_and_checkpoint(self):
        counter = [0]
        normal = self.reply

        def switch(arguments, *, timeout):
            if arguments == profile.INFO_ARGUMENTS:
                counter[0] += 1
                if counter[0] == 2:
                    self.state["engine"]["id"] = "different-engine"
            return normal(arguments, timeout=timeout)

        self.request.side_effect = switch
        with self.assertRaisesRegex(profile.LabControlError, "engine identity changed"):
            self.capture()
        self.state["engine"] = copy.deepcopy(ENGINE)
        self.request.side_effect = self.reply
        baseline, digest = self.capture()
        self.state["engine"]["id"] = "different-engine"
        with self.assertRaisesRegex(profile.LabControlError, "engine identity changed"):
            self.checkpoint(baseline, digest)

    def test_missing_unknown_replacement_running_ids_fail_without_repair(self):
        baseline, digest = self.capture()
        for running, message in (
            (PRESERVED[:-1], "preserved running workload is missing"),
            (PRESERVED + [UNKNOWN], "unexpected running workload arrived"),
            (PRESERVED[:-1] + [UNKNOWN], "preserved running workload is missing"),
        ):
            self.state["running"] = running
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(profile.LabControlError, message),
            ):
                self.checkpoint(baseline, digest)

    def test_start_restart_resource_network_or_mount_envelope_drift_aborts(self):
        baseline, digest = self.capture()
        original = envelope(PRESERVED[0])
        for key, changed in (
            ("started_at", "2026-10-03T01:02:04.123456789Z"),
            ("restart_count", 1),
            ("memory", 1024 * 1024**2),
            ("memory_swap", -1),
            ("nano_cpus", 2 * 10**9),
            ("pids_limit", 256),
            ("network_mode", "bridge"),
            ("networks", {"accessops_default": "d" * 64}),
            ("mounts", [{**original["mounts"][0], "RW": False}]),
        ):
            self.state["envelopes"][PRESERVED[0]] = {**copy.deepcopy(original), key: changed}
            with (
                self.subTest(field=key),
                self.assertRaisesRegex(profile.LabControlError, "envelope changed"),
            ):
                self.checkpoint(baseline, digest)

    def test_privileged_host_or_shared_namespace_baseline_is_rejected(self):
        original = envelope(PRESERVED[0])
        for key, changed in (
            ("privileged", True),
            ("pid_mode", "host"),
            ("pid_mode", "container:" + OWNED),
            ("ipc_mode", "host"),
            ("uts_mode", "host"),
            ("cgroupns_mode", "host"),
            ("cgroupns_mode", ""),
            ("network_mode", "host"),
            ("network_mode", "container:" + OWNED),
        ):
            self.state["envelopes"][PRESERVED[0]] = {**copy.deepcopy(original), key: changed}
            with self.subTest(namespace=key), self.assertRaises(profile.LabControlError):
                self.capture()

    def test_required_mount_and_identity_timestamp_schema_fails_closed(self):
        original = envelope(PRESERVED[0])
        for key, changed in (
            ("id", OWNED),
            ("running", False),
            ("running", 1),
            ("privileged", 0),
            ("restart_count", True),
            ("started_at", "2026-02-31T01:02:03Z"),
            ("started_at", "0001-01-01T00:00:00Z"),
            ("mounts", None),
            ("mounts", [{"Type": "bind"}]),
            ("mounts", [{**original["mounts"][0], "Type": {}}]),
            ("mounts", original["mounts"] * 17),
            ("networks", {"synthetic": "truncated"}),
            ("memory", True),
            ("nano_cpus", -1),
        ):
            self.state["envelopes"][PRESERVED[0]] = {**copy.deepcopy(original), key: changed}
            with self.subTest(field=key), self.assertRaises(profile.LabControlError):
                self.capture()
        for removed in ("mounts", "restart_count", "started_at", "privileged"):
            altered = copy.deepcopy(original)
            del altered[removed]
            self.state["envelopes"][PRESERVED[0]] = altered
            with self.subTest(missing=removed), self.assertRaises(profile.LabControlError):
                self.capture()

    def test_control_socket_pipe_and_socket_parent_directory_mounts_rejected(self):
        for source, destination, kind in (
            ("/var/run/docker.sock", "/socket", "bind"),
            ("/run/docker.sock", "/socket", "bind"),
            ("/var/run", "/host-run", "bind"),
            ("/", "/host", "bind"),
            (r"\\.\pipe\docker_engine", "/pipe", "bind"),
            (r"\\.\pipe\dockerDesktopLinuxEngine", "/pipe", "npipe"),
            ("/safe", "/var/run/docker.sock", "bind"),
        ):
            current = envelope(PRESERVED[0])
            current["mounts"] = [
                {"Type": kind, "Source": source, "Destination": destination, "RW": False}
            ]
            self.state["envelopes"][PRESERVED[0]] = current
            with self.subTest(source=source), self.assertRaises(profile.LabControlError):
                self.capture()

    def test_bind_overlap_denied_for_ancestor_descendant_and_desktop_translation(self):
        translated = (
            "/run/desktop/mnt/host/c/synthetic/signalbridge-public/var/enterprise/runs/" + RUN
        )
        for source in (
            DIRECTORY,
            DIRECTORY + r"\evidence",
            r"C:\synthetic",
            "C:/",
            translated,
            translated + "/secrets",
            "/host_mnt/c/synthetic",
        ):
            current = envelope(PRESERVED[0])
            current["mounts"] = [
                {"Type": "bind", "Source": source, "Destination": "/data", "RW": False}
            ]
            self.state["envelopes"][PRESERVED[0]] = current
            with (
                self.subTest(source=source),
                self.assertRaisesRegex(profile.LabControlError, "overlaps"),
            ):
                self.capture()

    def test_known_windows_aliases_match_and_component_boundaries_preserve_siblings(self):
        source = r"C:\Users\Synthetic\AccessOps\data"
        current = envelope(PRESERVED[0])
        current["mounts"] = [{"Type": "bind", "Source": source, "Destination": "/data", "RW": True}]
        self.state["envelopes"][PRESERVED[0]] = current
        baseline, digest = self.capture()
        for source in (
            "/run/desktop/mnt/host/c/Users/synthetic/AccessOps/data",
            "/host_mnt/c/Users/synthetic/AccessOps/data",
            "c:/users/synthetic/accessops/data",
        ):
            self.state["envelopes"][PRESERVED[0]]["mounts"][0]["Source"] = source
            self.checkpoint(baseline, digest)
        current["mounts"][0]["Source"] = DIRECTORY + "-sibling/data"
        self.state["envelopes"][PRESERVED[0]] = current
        self.capture()

    def test_opaque_proxy_unc_device_relative_ads_and_alias_paths_refused(self):
        for source in (
            "/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/Ubuntu/opaque",
            "/mnt/c/synthetic",
            r"\\server\share\data",
            r"\\?\C:\synthetic",
            "C:relative",
            "C:/synthetic/../run",
            "C:/SHORT~1/data",
            "C:/data/file:ads",
            "C:/synthetic./data",
            "C:/synthetic /data",
            "C:/synthetic//data",
        ):
            current = envelope(PRESERVED[0])
            current["mounts"] = [
                {"Type": "bind", "Source": source, "Destination": "/data", "RW": True}
            ]
            self.state["envelopes"][PRESERVED[0]] = current
            with self.subTest(source=source), self.assertRaises(profile.LabControlError):
                self.capture()

    def test_baseline_context_engine_envelopes_and_profile_integrity_bound(self):
        baseline, digest = self.capture()
        for key, altered in (
            ("profile", "exclusive"),
            ("run_id", OTHER_RUN),
            ("private_run", baseline["private_run"] + "/other"),
            ("reviewed_context_digest", "f" * 64),
            ("engine", {**ENGINE, "id": "other-engine"}),
            ("envelopes", {}),
            ("sha256", "f" * 64),
            ("schema_version", True),
        ):
            changed = copy.deepcopy(baseline)
            changed[key] = altered
            with self.subTest(field=key), self.assertRaises(profile.LabControlError):
                profile.validate_baseline(changed, RUN, DIRECTORY, CONTEXT, expected_digest=digest)
        for run, directory, context in (
            (OTHER_RUN, DIRECTORY.replace(RUN, OTHER_RUN), CONTEXT),
            (RUN, DIRECTORY + "-other", CONTEXT),
            (RUN, DIRECTORY, "f" * 64),
        ):
            with self.subTest(run=run), self.assertRaises(profile.LabControlError):
                profile.validate_baseline(baseline, run, directory, context, expected_digest=digest)

    def test_preserved_drift_aborts_but_pure_own_cleanup_remains_admitted(self):
        baseline, digest = self.capture()
        self.state["running"] = PRESERVED[:-1] + [OWNED]
        with self.assertRaises(profile.LabControlError):
            self.checkpoint(baseline, digest)
        count = self.request.call_count
        self.assertTrue(
            profile.mutation_admitted(
                OWNED,
                RUN,
                ENGINE,
                baseline,
                RUN,
                DIRECTORY,
                CONTEXT,
                (OWNED,),
                expected_digest=digest,
            )
        )
        self.assertEqual(self.request.call_count, count)
        for candidate, observed_run, engine in (
            (PRESERVED[0], RUN, ENGINE),
            (UNKNOWN, RUN, ENGINE),
            (OWNED, OTHER_RUN, ENGINE),
            (OWNED, RUN, {**ENGINE, "id": "other-engine"}),
        ):
            with self.subTest(candidate=candidate):
                self.assertFalse(
                    profile.mutation_admitted(
                        candidate,
                        observed_run,
                        engine,
                        baseline,
                        RUN,
                        DIRECTORY,
                        CONTEXT,
                        (OWNED,),
                        expected_digest=digest,
                    )
                )

    def test_metadata_bounds_duplicates_and_errors_do_not_expose_private_output(self):
        for raw in (
            "x" * 513,
            '{"id":"synthetic","id":"other","os_type":"linux"}',
            "{",
            "\ud800",
            b"{}",
        ):
            request = Mock(return_value=raw)
            with self.subTest(type=type(raw).__name__), self.assertRaises(profile.LabControlError):
                profile.engine(request)
        request = Mock(side_effect=OSError("synthetic-private-detail"))
        with self.assertRaises(profile.LabControlError) as raised:
            profile.engine(request)
        self.assertNotIn("synthetic-private-detail", str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)
        with self.assertRaises(profile.LabControlError):
            profile.inspect(
                Mock(return_value="x" * (profile.MAX_ENVELOPE_BYTES + 1)),
                PRESERVED[0],
                "win:c:/synthetic",
            )


if __name__ == "__main__":
    unittest.main()
