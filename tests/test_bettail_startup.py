"""Pre-start configuration checks: synthetic metadata, no live services."""

import copy
import json
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from scripts import check_bettail_startup as startup
from scripts import verify_bettail_routes as route
from scripts.lab_credentials import LabCredentialError
from tests.test_bettail_route_isolation import topology


def stopped_topology():
    payload = topology()
    for row in payload["containers"]:
        row.update({"State": "exited", "Running": False, "Ports": {}})
    for network in payload["networks"]:
        network["Containers"] = {}
    return payload


class StartupTopologyTests(TestCase):
    def test_stopped_profile_keeps_running_gate_separate_and_preserves_input(self):
        payload = stopped_topology()
        before = copy.deepcopy(payload)
        self.assertEqual(route.verify_topology(payload, stopped=True), [])
        self.assertTrue(route.verify_topology(payload))
        self.assertEqual(payload, before)
        self.assertTrue(route.verify_topology(topology(), stopped=True))
        self.assertTrue(route.verify_topology(payload, stopped="yes"))
        self.assertTrue(route.base.verify_topology(payload, stopped="yes"))

    def test_stopped_mode_still_rejects_host_access_and_configured_ports(self):
        mutations = (
            lambda p: p["containers"][0]["HostConfig"].update({"Privileged": True}),
            lambda p: p["containers"][0]["HostConfig"].update(
                {"PortBindings": {"5432/tcp": [{"HostIp": "", "HostPort": "55322"}]}}
            ),
            lambda p: p["containers"][-2]["HostConfig"]["PortBindings"]["55322/tcp"][0].update(
                {"HostIp": "0.0.0.0"}
            ),
            lambda p: p["containers"][-1]["HostConfig"].update({"Memory": 0}),
            lambda p: p["containers"][-1]["Mounts"][0].update({"RW": True}),
            lambda p: p["networks"][0].update({"Internal": False}),
            lambda p: p["networks"][1]["Containers"].update({"foreign": {"Name": "foreign"}}),
            lambda p: p["containers"][0].update({"State": "paused"}),
            lambda p: p["containers"][-1].update({"State": "dead"}),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                payload = stopped_topology()
                mutate(payload)
                self.assertTrue(route.verify_topology(payload, stopped=True))

    def test_known_legacy_configuration_is_not_a_safe_stopped_profile(self):
        payload = stopped_topology()
        host = payload["containers"][0]["HostConfig"]
        host.update({"Memory": 0, "MemorySwap": 0, "NanoCpus": 0, "PidsLimit": None})
        host["RestartPolicy"] = {"Name": "unless-stopped", "MaximumRetryCount": 0}
        errors = route.verify_topology(payload, stopped=True)
        self.assertIn("configured_resource_limit", errors)
        self.assertIn("automatic_restart_policy", errors)


class StartupExecutionTests(TestCase):
    def check(self, *, payloads=None, hashes=None, running="", free=None, credential_error=None):
        with (
            patch.object(
                route, "gather_topology", side_effect=payloads or [stopped_topology()] * 3
            ),
            patch.object(
                route, "source_hashes", side_effect=hashes or [{"source": "a"}] * 2
            ) as source,
            patch.object(route.base, "docker", return_value=running) as docker,
            patch.object(
                startup.shutil,
                "disk_usage",
                return_value=SimpleNamespace(free=free if free is not None else 26 * 1024**3),
            ),
            patch.object(
                startup,
                "read_database_password",
                return_value="synthetic-private",
                side_effect=credential_error,
            ),
            patch.object(route.base, "gather_runtime") as runtime,
            patch.object(route, "gather_next_runtime") as next_runtime,
        ):
            result = startup.run_check()
        docker.assert_called_once_with(["ps", "--format", "{{.ID}}", "--no-trunc"])
        runtime.assert_not_called()
        next_runtime.assert_not_called()
        self.assertNotIn("synthetic-private", json.dumps(result))
        if result.get("source_check") == "not_run_startup_blocked":
            source.assert_not_called()
        return result

    def test_ready_means_configured_only_without_service_execution_or_password_claim(self):
        result = self.check()
        self.assertEqual(result["status"], "ready_for_live_verification")
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["running_container_count"], 0)
        self.assertTrue(result["generated_credential_present"])
        self.assertNotIn("runtime", result)

    def test_missing_credential_capacity_or_running_service_blocks(self):
        for settings, error in (
            (
                {"credential_error": LabCredentialError("private-sentinel")},
                "coordinated_credentials_required",
            ),
            ({"free": startup.FREE_FLOOR - 1}, "host_free_floor"),
            ({"running": "a" * 64}, "other_or_lab_container_running"),
        ):
            with self.subTest(error=error):
                result = self.check(**settings)
                self.assertEqual(result["status"], "blocked")
                self.assertIn(error, result["errors"])
                self.assertNotIn("private-sentinel", json.dumps(result))

    def test_source_or_topology_change_during_read_blocks(self):
        after = stopped_topology()
        after["containers"][0]["Image"] = "sha256:" + "b" * 64
        for settings in (
            {"payloads": [stopped_topology(), after]},
            {"hashes": [{"source": "a"}, {"source": "b"}]},
        ):
            result = self.check(**settings)
            self.assertEqual(result["status"], "blocked")
            self.assertIn("preflight_environment_changed", result["errors"])

    def test_read_failure_is_fixed_diagnostic_and_arbitrary_targets_are_refused(self):
        with patch.object(route, "gather_topology", side_effect=OSError("private-sentinel")):
            result = startup.run_check()
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["errors"], ["preflight_input_or_runtime_failure"])
        with patch.object(startup, "run_check") as check, self.assertRaises(SystemExit):
            startup.main(["--target", "remote"])
        check.assert_not_called()
