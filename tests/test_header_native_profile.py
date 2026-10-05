"""Closed native source variant with modeled runtimes; no Docker or source launch."""

import copy
import json
import os
import time
from pathlib import Path
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from integrations.enterprise import reference_host_controls as host
from integrations.enterprise import reference_host_evidence as evidence
from integrations.enterprise.reference_controls import expected_config, verify_compose_config
from integrations.enterprise.verification import LabControlError
from integrations.zap_enterprise import source_runner, source_support
from scripts import enterprise_reference_verify as launch

RUN = "a" * 32
IMAGES = {"database": "sha256:" + "d" * 64, "runner": "sha256:" + "e" * 64}
DIRECTORY = Path(__file__).resolve().parents[1] / "var/enterprise/preparation/closed-header-model"


class HeaderNativeProfileTests(SimpleTestCase):
    def test_actual_offline_compose_output_matches_both_the_fixed_recipe_and_isolation(self):
        fixture = Path(__file__).resolve().parent / "fixtures/header-compose.json"
        value = json.loads(fixture.read_text(encoding="utf8"))
        images = {role: config["image"] for role, config in value["services"].items()}
        verify_compose_config(value, images, RUN, "/reference-proof-profile", profile="header")
        self.assertEqual(value["services"]["runner"]["environment"]["SB_HEADER_PROOF"], "1")
        self.assertTrue(value["networks"]["reference"]["internal"])
        self.assertTrue(all(service["read_only"] for service in value["services"].values()))
        self.assertTrue(all("ports" not in service for service in value["services"].values()))

    def test_new_recipe_variant_changes_only_fixed_runner_command_and_opt_in(self):
        original = expected_config(IMAGES, RUN, DIRECTORY)
        expected = copy.deepcopy(original)
        expected["services"]["runner"]["environment"]["SB_HEADER_PROOF"] = "1"
        expected["services"]["runner"]["command"] = [
            "python",
            "-B",
            "-m",
            "integrations.zap_enterprise.source_runner",
        ]
        header = expected_config(IMAGES, RUN, DIRECTORY, profile="header")
        self.assertEqual(header, expected)
        verify_compose_config(header, IMAGES, RUN, DIRECTORY, profile="header")
        self.assertNotIn("SB_HEADER_PROOF", original["services"]["runner"]["environment"])
        with self.assertRaises(LabControlError):
            verify_compose_config(header, IMAGES, RUN, DIRECTORY)

    def test_changed_scope_ports_mounts_and_fault_configuration_are_rejected(self):
        for change in ("command", "port", "network", "environment", "memory"):
            value = expected_config(IMAGES, RUN, DIRECTORY, profile="header")
            runner = value["services"]["runner"]
            if change == "command":
                runner["command"] = ["python", "-c", "print('arbitrary')"]
            elif change == "port":
                runner["ports"] = [{"target": 18842, "published": "18842"}]
            elif change == "network":
                value["networks"]["reference"]["internal"] = False
            elif change == "environment":
                runner["environment"]["SB_HEADER_DURATION"] = "unbounded"
            else:
                runner["mem_limit"] *= 2
            with self.subTest(change=change), self.assertRaises(LabControlError):
                verify_compose_config(value, IMAGES, RUN, DIRECTORY, profile="header")

    def test_unknown_profile_refused_before_component_creation_or_run(self):
        with patch.object(launch, "invoke") as command, patch.object(host, "owned") as owned:
            for operation in (
                lambda: launch.compose_command(
                    Path("docker.exe"), RUN, DIRECTORY, profile="arbitrary"
                ),
                lambda: launch.exact_components(
                    Path("docker.exe"), RUN, DIRECTORY, IMAGES, profile="arbitrary"
                ),
                lambda: launch.execute(
                    Path("docker.exe"), RUN, DIRECTORY, IMAGES, {}, Mock(), profile="arbitrary"
                ),
                lambda: launch.launch(
                    Path("docker.exe"), "test", RUN, Path("python.exe"), profile="arbitrary"
                ),
            ):
                with self.assertRaises(LabControlError):
                    operation()
            command.assert_not_called()
            owned.assert_not_called()
        with self.assertRaises(LabControlError):
            expected_config(IMAGES, RUN, DIRECTORY, profile="arbitrary")

    def test_variant_selects_distinct_receipts_and_does_not_substitute_access_proof(self):
        with patch(
            "integrations.zap_enterprise.source_host_evidence.validate_native",
            return_value={"native_zap_executed": False},
        ) as validator:
            self.assertFalse(
                evidence.validate_native(DIRECTORY, RUN, {}, {}, now=time.time(), profile="header")[
                    "native_zap_executed"
                ]
            )
            validator.assert_called_once()
        with self.assertRaises(LabControlError):
            evidence.validate_native(DIRECTORY, RUN, {}, {}, now=time.time(), profile="arbitrary")
        command = launch.compose_command(Path("docker.exe"), RUN, DIRECTORY, profile="header")
        self.assertTrue(str(command[-1]).endswith("compose.header.yaml"))

    def test_operator_cannot_enable_native_profile_or_read_credentials_without_opt_in(self):
        with (
            patch.dict(os.environ, {"SB_SOURCE_COMPONENT": "source"}, clear=True),
            patch.object(source_support.base, "configure") as base,
        ):
            with self.assertRaises(ValueError):
                source_support.configure()
            base.assert_not_called()
        with (
            patch.dict(
                os.environ, {"SB_HEADER_PROOF": "1", "SB_SOURCE_COMPONENT": "console"}, clear=True
            ),
            patch.object(source_support.base, "configure") as base,
        ):
            with self.assertRaises(ValueError):
                source_support.configure()
            base.assert_not_called()
        with patch.object(source_support, "configure") as configure:
            with self.assertRaises(ValueError):
                source_support.operate("arbitrary")
            configure.assert_not_called()

    def test_header_operation_scope_is_fixed_and_sensitive_failures_are_suppressed(self):
        context = {
            "SB_HEADER_PROOF": "other",
            "SB_HEADER_DURATION": "unbounded",
            "SB_SOURCE_RUN": RUN,
            "PGHOST": "outside.invalid",
            "SSLKEYLOGFILE": "unsafe.log",
        }
        result = Mock(returncode=0, stdout=b'{"enabled":false,"maximum_seconds":300}', stderr=b"")
        with patch.object(source_runner.subprocess, "run", return_value=result) as command:
            self.assertFalse(source_runner.operate(context, "header-off")["enabled"])
            self.assertEqual(command.call_args.args[0][-1], "header-off")
            environment = command.call_args.kwargs["env"]
            self.assertEqual(environment["SB_HEADER_PROOF"], "1")
            self.assertNotIn("PGHOST", environment)
            self.assertNotIn("SSLKEYLOGFILE", environment)
            self.assertNotIn("SB_HEADER_DURATION", environment)
            self.assertEqual(command.call_args.kwargs["timeout"], 15)
            with self.assertRaises(ValueError):
                source_runner.operate(context, "header-on;arbitrary")
            command.assert_called_once()
        with (
            patch.object(
                source_runner.subprocess,
                "run",
                return_value=Mock(
                    returncode=1, stdout=b"private failure", stderr=b"private failure"
                ),
            ),
            self.assertRaisesRegex(ValueError, "fixed native header operation failed"),
        ):
            source_runner.operate({}, "header-off")

    def test_header_native_entry_refuses_workstation_before_install_process_or_credentials(self):
        with (
            patch.object(source_runner.base, "runtime_gate") as gate,
            patch.object(source_runner.base, "install_dependencies") as install,
            patch.object(source_runner.subprocess, "Popen") as process,
            patch.dict(os.environ, {"SB_HEADER_PROOF": "1"}, clear=True),
        ):
            with self.assertRaises(ValueError):
                source_runner.main()
            gate.assert_not_called()
            install.assert_not_called()
            process.assert_not_called()

    def test_header_environment_is_separate_and_other_database_boundary_fails(self):
        supplied = {
            "SB_HEADER_PROOF": "wrong",
            "SB_HEADER_OTHER": "unsafe",
            "SB_REF_PRIVATE": "nonfunctional",
            "PGHOST": "outside.invalid",
        }
        actual = source_runner.environment(supplied, "source")
        self.assertEqual(supplied["SB_HEADER_PROOF"], "wrong")
        self.assertEqual(actual["SB_HEADER_PROOF"], "1")
        self.assertNotIn("SB_HEADER_OTHER", actual)
        self.assertNotIn("PGHOST", actual)
        for value in (
            {"actual_identity_verified": True},
            {
                "component": "source",
                "actual_identity_verified": 1,
                "cross_database_connect_denied": True,
                "denial_kind": "sqlstate",
                "denial_sqlstate": "42501",
            },
        ):
            with self.assertRaises(ValueError):
                source_runner.database_boundary(value, "source")
