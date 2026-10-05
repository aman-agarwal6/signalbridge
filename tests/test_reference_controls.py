"""Hostile edits of actual offline Compose output, with private paths removed."""

import copy
import json
from pathlib import Path

from django.test import SimpleTestCase

from integrations.enterprise.reference_controls import verify_compose_config
from integrations.enterprise.verification import LabControlError

RUN = "a" * 32
DIRECTORY = "/reference-proof-profile"


class ReferenceRecipeTests(SimpleTestCase):
    def setUp(self):
        self.data = json.loads(
            (Path(__file__).parent / "fixtures/reference-compose.json").read_text()
        )
        self.images = {role: value["image"] for role, value in self.data["services"].items()}

    def verify(self, data=None):
        return verify_compose_config(data or self.data, self.images, RUN, DIRECTORY)

    def test_actual_parsed_recipe_matches_preparation_without_claiming_runtime(self):
        result = self.verify()
        self.assertTrue(result["parsed_recipe_verified"])
        self.assertFalse(result["runtime_verified"])
        self.assertEqual(result["published_ports"], 0)

    def test_extra_surfaces_ports_capabilities_and_host_mounts_are_rejected(self):
        mutations = {
            "ports": ["18842:18842"],
            "network_mode": "host",
            "privileged": True,
            "pid": "host",
            "ipc": "host",
            "cap_add": ["NET_ADMIN"],
            "devices": ["/dev/example:/dev/example"],
            "build": {"context": "."},
            "entrypoint": ["sh"],
            "user": "0",
            "read_only": False,
            "restart": "always",
            "mem_limit": "1073741824",
            "memswap_limit": "-1",
            "cpus": 2,
            "pids_limit": 1024,
            "pull_policy": "always",
            "security_opt": [],
            "cap_drop": [],
            "extra_hosts": ["outside.example:host-gateway"],
        }
        for role in ("database", "runner"):
            for key, value in mutations.items():
                data = copy.deepcopy(self.data)
                data["services"][role][key] = value
                with self.subTest(role=role, key=key), self.assertRaises(LabControlError):
                    self.verify(data)
        data = copy.deepcopy(self.data)
        data["services"]["runner"]["volumes"].append(
            {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}
        )
        with self.assertRaises(LabControlError):
            self.verify(data)

    def test_image_command_environment_and_secret_inventory_are_closed(self):
        for change in (
            "image",
            "command",
            "environment",
            "secret",
            "secret_source",
            "writable_source",
        ):
            data = copy.deepcopy(self.data)
            row = data["services"]["runner"]
            if change == "image":
                row["image"] = "unexpected:latest"
            elif change == "command":
                row["command"] = ["python", "-c", "unexpected()"]
            elif change == "environment":
                row["environment"]["HTTPS_PROXY"] = "http://outside.example"
            elif change == "secret":
                row["secrets"].append(
                    {"source": "bootstrap_password", "target": "/run/secrets/bootstrap_password"}
                )
            elif change == "secret_source":
                data["secrets"]["source_password"]["file"] = "/other-project/secret"
            else:
                row["volumes"][0]["read_only"] = False
            with self.subTest(change=change), self.assertRaises(LabControlError):
                self.verify(data)

    def test_internal_network_ownership_and_fresh_volume_identity_are_closed(self):
        for change in ("network", "extra_network", "label", "volume", "extra_service", "extra_top"):
            data = copy.deepcopy(self.data)
            if change == "network":
                data["networks"]["reference"]["internal"] = False
            elif change == "extra_network":
                data["services"]["runner"]["networks"]["default"] = None
            elif change == "label":
                data["services"]["runner"]["labels"]["org.signalbridge.enterprise.run"] = "b" * 32
            elif change == "volume":
                data["volumes"]["reference_data"]["name"] = "prior-retained-database"
            elif change == "extra_service":
                data["services"]["extra"] = copy.deepcopy(data["services"]["runner"])
            else:
                data["configs"] = {}
            with self.subTest(change=change), self.assertRaises(LabControlError):
                self.verify(data)

    def test_temporary_mount_limits_and_boolean_types_are_exact(self):
        for role in ("database", "runner"):
            for key, value in (("tmpfs", ["/tmp:rw,size=1g"]), ("read_only", 1), ("cpus", True)):
                data = copy.deepcopy(self.data)
                data["services"][role][key] = value
                with self.subTest(role=role, key=key), self.assertRaises(LabControlError):
                    self.verify(data)

    def test_malformed_profiles_and_escape_paths_fail_closed(self):
        for value in ({"services": []}, {"services": {}}, ["not", "a", "profile"]):
            with self.subTest(value=value), self.assertRaises(LabControlError):
                self.verify(value)
        data = copy.deepcopy(self.data)
        data["services"]["runner"]["volumes"][0]["source"] = DIRECTORY + "/../../other-project"
        with self.assertRaises(LabControlError):
            self.verify(data)
