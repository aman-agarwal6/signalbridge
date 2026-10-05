"""Modeled source archives/receipts; no claim of genuine source execution."""

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
from integrations.zap_enterprise import source_transfer as transfer
from integrations.zap_enterprise.scanner_contract import receipt_bytes, validate_input
from scripts import enterprise_zap_verify as launch
from tests.test_zap_enterprise_capture import START
from tests.test_zap_enterprise_runtime import package


class SourceTransferTests(SimpleTestCase):
    def setUp(self):
        self.parent = Path(__file__).resolve().parents[1] / "var/tests"
        self.workspace = self.parent / ("t" + uuid.uuid4().hex[:8])
        self.value = package()
        self.run = self.value["source_run_id"]
        self.directory = base.private_run_directory(self.workspace, self.run)
        (self.directory / "evidence").mkdir(parents=True)
        (self.directory / "wheels").mkdir()
        (self.directory / "wheels/modeled.whl").write_bytes(b"modeled-only")
        self.footprint = {"wheel_count": 1, "bytes": 12, "modeled": True}
        self.manifest = {"sha256": self.value["source_sha256"]}
        self.proof = {
            "native_receipts_revalidated": True,
            "source_snapshot": {
                "source_sha256": self.manifest["sha256"],
                "file_count": 1,
                "bytes": 12,
            },
        }
        self.watchdog = {
            "run_id": self.run,
            "shutdown_verified": True,
            "reason": "launcher_finished",
            "stopped_component_count": 2,
            "stopped_at": (START + timedelta(seconds=19)).isoformat(),
        }
        self.receipt = {
            "schema_version": 1,
            "kind": "signalbridge-native-authenticated-header-capture",
            "run_id": self.run,
            "status": "passed",
            "acceptance_passed": True,
            "source_unchanged": True,
            "runtime_isolation_verified": True,
            "parsed_configuration_verified": True,
            "main_shutdown_verified": True,
            "independent_shutdown_verified": True,
            "runner_exit_code": 0,
            "started_at": (START - timedelta(seconds=1)).isoformat(),
            "finished_at": (START + timedelta(seconds=20)).isoformat(),
            "source_sha256": self.manifest["sha256"],
            "source_snapshot": self.proof["source_snapshot"],
            "native_proof": self.proof,
            "preparation": {"wheel_footprint": self.footprint},
            "images": {"database": "sha256:" + "a" * 64, "runner": "sha256:" + "b" * 64},
            "main_shutdown": {
                "run_id": self.run,
                "shutdown_verified": True,
                "stopped_component_count": 2,
            },
            "independent_shutdown": self.watchdog,
        }
        self.addCleanup(self.cleanup)
        self.save()

    def cleanup(self):
        if self.workspace.is_symlink() or not self.workspace.resolve().is_relative_to(
            self.parent.resolve()
        ):
            raise RuntimeError("Unsafe transfer fixture cleanup.")
        shutil.rmtree(self.workspace)

    def save(self):
        files = {
            "receipt.json": self.receipt,
            "watchdog.json": self.watchdog,
            "evidence/header-execution.json": self.value["execution"],
            "evidence/source-captures.json": self.value["phases"],
        }
        for name, value in files.items():
            (self.directory / name).write_bytes(receipt_bytes(value))

    def load(self):
        with (
            patch.object(
                transfer, "wheel_manifest", return_value=[{"filename": "modeled.whl", "size": 12}]
            ),
            patch.object(transfer, "wheel_expansion", return_value=self.footprint),
            patch.object(transfer, "validate_native", return_value=self.proof) as native,
        ):
            result = transfer.load_completed_source(
                self.workspace, self.run, self.manifest, now=START + timedelta(minutes=1)
            )
            native.assert_called_once_with(
                self.workspace,
                self.run,
                self.manifest,
                self.footprint,
                now=START + timedelta(seconds=20),
            )
            return result

    def test_bound_package_uses_original_receipt_hash_and_only_declared_captures(self):
        with patch.object(transfer, "read_receipt", wraps=transfer.read_receipt) as read:
            value, binding = self.load()
        validate_input(value, now=START + timedelta(minutes=1))
        self.assertEqual(
            value["source_receipt_sha256"],
            hashlib.sha256((self.directory / "receipt.json").read_bytes()).hexdigest(),
        )
        self.assertEqual(value["phases"], self.value["phases"])
        self.assertTrue(binding["main_shutdown_verified"])
        self.assertTrue(binding["independent_shutdown_verified"])
        self.assertFalse(binding["native_zap_executed"])
        self.assertEqual(
            {call.args[0].relative_to(self.directory).as_posix() for call in read.call_args_list},
            {
                "receipt.json",
                "watchdog.json",
                "evidence/header-execution.json",
                "evidence/source-captures.json",
            },
        )
        self.assertNotIn("password", json.dumps(value))

    def test_access_profile_incomplete_or_numeric_boolean_receipts_are_rejected(self):
        original = copy.deepcopy(self.receipt)
        for field, value in (
            ("kind", "signalbridge-native-reference-access"),
            ("status", "incomplete"),
            ("acceptance_passed", 1),
            ("main_shutdown_verified", False),
            ("runner_exit_code", True),
            ("run_id", "f" * 32),
        ):
            self.receipt = {**copy.deepcopy(original), field: value}
            self.save()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load()

    def test_changed_source_identity_future_or_overlong_native_run_fails(self):
        original = copy.deepcopy(self.receipt)
        for field, value in (
            ("source_sha256", "f" * 64),
            ("finished_at", (START + timedelta(hours=1)).isoformat()),
            ("started_at", (START - timedelta(hours=1)).isoformat()),
            ("images", {"database": "unversioned"}),
        ):
            self.receipt = {**copy.deepcopy(original), field: value}
            self.save()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load()

    def test_raw_proof_cannot_be_replaced_by_host_success_flags(self):
        self.receipt["native_proof"] = {"native_receipts_revalidated": True}
        self.save()
        with self.assertRaises(ValueError):
            self.load()

    def test_guard_abort_or_stale_shutdown_cannot_be_transferred(self):
        original = copy.deepcopy(self.watchdog)
        for field, value in (
            ("reason", "disk_growth"),
            ("stopped_component_count", 1),
            ("stopped_at", (START - timedelta(minutes=1)).isoformat()),
        ):
            self.watchdog = {**original, field: value}
            self.receipt["independent_shutdown"] = self.watchdog
            self.save()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load()

    def test_changed_wheel_inventory_or_size_fails_before_archive_analysis(self):
        (self.directory / "wheels/modeled.whl").write_bytes(b"changed")
        with (
            patch.object(
                transfer, "wheel_manifest", return_value=[{"filename": "modeled.whl", "size": 12}]
            ),
            patch.object(transfer, "wheel_expansion") as expansion,
            self.assertRaises(ValueError),
        ):
            transfer.load_completed_source(
                self.workspace, self.run, self.manifest, now=START + timedelta(minutes=1)
            )
        expansion.assert_not_called()

    def test_missing_event_or_service_failure_capture_cannot_be_packaged(self):
        self.value["phases"]["corrected"][1]["http_status"] = 503
        self.save()
        with self.assertRaises(ValueError):
            self.load()

    def test_preparation_uses_recipe_names_and_does_not_start_or_install_anything(self):
        scanner_run = "d" * 32
        scanner = base.private_run_directory(self.workspace, scanner_run)
        scanner.mkdir()
        binding = {"source_run_id": self.run, "source_receipt_sha256": "e" * 64}
        with (
            patch.object(launch, "private_acl") as acl,
            patch.object(launch, "load_completed_source", return_value=(self.value, binding)),
            patch.object(launch, "snapshot_source", return_value={"bytes": 12}),
            patch.object(launch, "private_docker_config", return_value=scanner / "docker-config"),
            patch.object(launch, "invoke") as invoke,
            patch.object(base, "docker_result") as docker,
        ):
            raw, result, _snapshot, environment = launch.prepare(
                Path("unused-docker"), scanner_run, scanner, self.run, self.manifest
            )
        self.assertEqual(raw, (scanner / "input/source-capture.json").read_bytes())
        self.assertEqual(result, binding)
        self.assertEqual(environment["SB_SCANNER_RUN"], scanner_run)
        self.assertEqual(environment["SB_SCANNER_DIRECTORY"], str(scanner))
        self.assertIn("SB_SCANNER_IMAGE", environment)
        self.assertNotIn("SB_ZAP_SCANNER_IMAGE_ID", environment)
        self.assertEqual(acl.call_count, 2)
        invoke.assert_not_called()
        docker.assert_not_called()

    def test_missing_native_input_refused_before_daemon_or_creating_new_run(self):
        fake_docker = self.workspace / "unused-docker.exe"
        fake_docker.write_bytes(b"never-executed")
        with (
            patch.object(launch.sys, "platform", "win32"),
            patch.object(launch, "verified_source", return_value=self.manifest),
            patch.object(launch, "private_acl"),
            patch.object(launch, "load_completed_source", side_effect=ValueError("missing input")),
            patch.object(launch, "no_foreign_running") as running,
            patch.object(launch.host, "inspect_image") as image,
        ):
            with self.assertRaises(ValueError):
                launch.launch(fake_docker, "modeled-approval-only", self.run)
            running.assert_not_called()
            image.assert_not_called()
        self.assertEqual(
            {p.name for p in (self.workspace / "var/enterprise/runs").iterdir()}, {self.run}
        )

    def test_failed_phase_retains_receipt_and_attempts_both_shutdowns_without_killing_guard(self):
        fake_docker = self.workspace / "unused-docker.exe"
        fake_docker.write_bytes(b"never-executed")
        guard = Mock()
        guard.poll.return_value = None
        guard.wait.side_effect = TimeoutError("private guard detail")
        binding = {"source_run_id": self.run, "source_receipt_sha256": "e" * 64}
        image = {"id": "sha256:" + "c" * 64}

        def arm(_docker, run):
            directory = base.private_run_directory(self.workspace, run)
            (directory / "watchdog-ready.json").write_bytes(
                receipt_bytes({"run_id": run, "armed": True})
            )
            return guard

        with (
            patch.object(launch.sys, "platform", "win32"),
            patch.object(launch, "ROOT", self.workspace),
            patch.object(launch, "verified_source", return_value=self.manifest),
            patch.object(launch, "private_acl"),
            patch.object(launch, "load_completed_source", return_value=(self.value, binding)),
            patch.object(launch, "check_capacity", return_value={}),
            patch.object(launch, "no_foreign_running"),
            patch.object(launch.host, "inspect_image", return_value=image),
            patch.object(
                launch, "prepare", return_value=(b"synthetic", binding, {"bytes": 12}, {})
            ),
            patch.object(launch, "arm_guard", side_effect=arm),
            patch.object(launch, "require_guard"),
            patch.object(launch.time, "sleep"),
            patch.object(launch, "execute", side_effect=TimeoutError("private phase detail")),
            patch.object(launch.host, "stop_scope", return_value=1) as stop,
            patch.object(launch.host, "write_control") as signal,
            patch.object(launch, "source_manifest", return_value=self.manifest),
            patch.object(
                launch, "receipt_path", return_value=self.workspace / "modeled-public-receipt.json"
            ),
        ):
            directory, passed = launch.launch(fake_docker, "modeled-approval-only", self.run)
        receipt = json.loads((directory / "receipt.json").read_bytes())
        self.assertFalse(passed)
        self.assertFalse(receipt["native_zap_executed"])
        self.assertEqual(receipt["status"], "incomplete")
        self.assertTrue(receipt["watchdog_pending"])
        self.assertNotIn("private phase detail", json.dumps(receipt))
        self.assertNotIn("private guard detail", json.dumps(receipt))
        stop.assert_called_once()
        signal.assert_called_once()
        guard.kill.assert_not_called()
        guard.terminate.assert_not_called()
