"""Hostile input/kernel and modeled process lifecycles; no scanner or service runs."""

import copy
import hashlib
import io
import json
import signal
import subprocess
import threading
import time
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from integrations.enterprise.verification import LabControlError
from integrations.zap.run_passive import collect_log
from integrations.zap_enterprise import scanner_contract as contract
from integrations.zap_enterprise import scanner_controls as controls
from integrations.zap_enterprise import scanner_runner as runner
from integrations.zap_enterprise.capture import PROFILE, HeaderProfileError
from integrations.zap_enterprise.passive import MAX_CALLS, Client
from tests.test_zap_enterprise_capture import START, rows
from tests.test_zap_enterprise_passive import ModeledAPI

RUN, IMAGE = "a" * 32, "sha256:" + "b" * 64


def package():
    phases = {phase: rows(phase) for phase in ("fault", "corrected")}
    for row in phases["corrected"]:
        row["started_at"] = (START + timedelta(seconds=5 + row["ordinal"])).isoformat()
    summary = {
        "profile": PROFILE,
        "completed": True,
        "native_zap_executed": False,
        "failure": "",
        "fault_disabled": True,
        "restoration_checks": {"document_member": True, "operator": True},
        "restoration_event_ids": {
            name: str(uuid.uuid5(uuid.NAMESPACE_URL, "restore/" + name))
            for name in ("document_member", "operator")
        },
        "phase_requests": {"fault": 5, "corrected": 5},
        "phase_attempted_requests": {"fault": 5, "corrected": 5},
        "captured_at": (START + timedelta(seconds=12)).isoformat(),
        "response_digests": {
            phase: [hashlib.sha256(row["body"].encode()).hexdigest() for row in group]
            for phase, group in phases.items()
        },
    }
    return {
        "schema_version": 1,
        "profile": PROFILE,
        "source_run_id": "c" * 32,
        "source_receipt_sha256": "d" * 64,
        "source_sha256": "e" * 64,
        "capture_sha256": contract.digest(phases),
        "execution_sha256": contract.digest(summary),
        "execution": summary,
        "phases": phases,
    }


def addons():
    result = []
    for name in ("exim", "network", "pscanrules"):
        item = {field: "" for field in contract.ADDON_FIELDS}
        item.update(id=name, version="1.2.3", installationStatus="INSTALLED", mandatory="false")
        result.append(item)
    return {"installedAddons": result}


def kernel():
    status = "\n".join(
        [
            "Uid:\t1000 1000 1000 1000",
            "Gid:\t1000 1000 1000 1000",
            "Groups:\t1000",
            *[name + ":\t0000000000000000" for name in contract.STATUS if name.startswith("Cap")],
            "NoNewPrivs:\t1",
            "Seccomp:\t2",
        ]
    )
    groups = {
        "memory.max": str(contract.MEMORY),
        "memory.swap.max": "0",
        "pids.max": "256",
        "cpu.max": "150000 100000",
    }
    mounts = "\n".join(
        f"{i} 1 0:1 / {target} {options} - {filesystem} none rw"
        for i, (target, options, filesystem) in enumerate(
            [
                ("/", "ro", "overlay"),
                ("/workspace", "ro", "ext4"),
                ("/input", "ro", "ext4"),
                ("/evidence", "rw", "ext4"),
                ("/tmp", "rw,noexec,nosuid,nodev", "tmpfs"),
            ],
            2,
        )
    )
    return status, groups, mounts, ["lo"]


class OfflineScannerContractTests(SimpleTestCase):
    def test_complete_bound_capture_is_not_source_or_scanner_attestation(self):
        proof = contract.validate_input(package())
        self.assertTrue(proof["input_validated"])
        self.assertFalse(proof["source_capture_attested"])
        self.assertFalse(proof["runtime_attested"])

    def test_unknown_fields_profiles_types_future_and_changed_raw_bindings_fail(self):
        for change in (
            "extra",
            "profile",
            "schema",
            "source",
            "hash",
            "future",
            "partial",
            "native",
        ):
            value = package()
            if change == "extra":
                value["password"] = "nonfunctional-private-value"
            elif change == "profile":
                value["profile"] = "arbitrary"
            elif change == "schema":
                value["schema_version"] = True
            elif change == "source":
                value["source_run_id"] = "../other"
            elif change == "hash":
                value["capture_sha256"] = "f" * 64
            elif change == "future":
                value["execution"]["captured_at"] = "2100-01-01T00:00:00+00:00"
            elif change == "partial":
                value["execution"]["completed"] = False
            else:
                value["execution"]["native_zap_executed"] = True
            with self.subTest(change=change), self.assertRaises(HeaderProfileError):
                contract.validate_input(value)

    def test_restoration_cannot_reuse_a_capture_or_cross_its_declared_account_inventory(self):
        for change in ("duplicate", "capture", "missing", "numeric_flag", "numeric_count"):
            value = package()
            summary = value["execution"]
            if change == "duplicate":
                summary["restoration_event_ids"]["operator"] = summary["restoration_event_ids"][
                    "document_member"
                ]
            elif change == "capture":
                summary["restoration_event_ids"]["operator"] = value["phases"]["fault"][1][
                    "event_id"
                ]
            elif change == "missing":
                summary["restoration_event_ids"].pop("operator")
            elif change == "numeric_flag":
                summary["restoration_checks"]["operator"] = 1
            else:
                summary["phase_requests"]["fault"] = 5.0
            value["execution_sha256"] = contract.digest(summary)
            with self.subTest(change=change), self.assertRaises(HeaderProfileError):
                contract.validate_input(value)

    def test_gate_matches_the_exact_input_bytes_scope_and_boolean_type(self):
        value, raw = package(), b"synthetic-exact-input-file"
        gate = {
            "run_id": RUN,
            "runtime_verified": True,
            "source_run_id": value["source_run_id"],
            "source_receipt_sha256": value["source_receipt_sha256"],
            "input_sha256": hashlib.sha256(raw).hexdigest(),
        }
        contract.validate_gate(gate, RUN, value, raw)
        for field, changed in (
            ("runtime_verified", 1),
            ("run_id", "f" * 32),
            ("source_run_id", "f" * 32),
            ("input_sha256", "f" * 64),
        ):
            altered = {**gate, field: changed}
            with self.subTest(field=field), self.assertRaises(HeaderProfileError):
                contract.validate_gate(altered, RUN, value, raw)

    def test_addon_inventory_requires_real_installed_dependencies_and_unambiguous_versions(self):
        self.assertEqual(set(contract.validate_addons(addons())), {"exim", "network", "pscanrules"})
        for change in ("missing", "duplicate", "not_installed", "version", "extra", "bool"):
            value = addons()
            if change == "missing":
                value["installedAddons"].pop()
            elif change == "duplicate":
                value["installedAddons"].append(copy.deepcopy(value["installedAddons"][0]))
            elif change == "extra":
                value["installedAddons"][0]["extra"] = "unsupported"
            else:
                field, changed = {
                    "not_installed": ("installationStatus", "NOT_INSTALLED"),
                    "version": ("version", "unknown"),
                    "bool": ("mandatory", False),
                }[change]
                value["installedAddons"][0][field] = changed
            with self.subTest(change=change), self.assertRaises(HeaderProfileError):
                contract.validate_addons(value)

    def test_kernel_checks_effective_privileges_mounts_quotas_and_loopback_only(self):
        value = contract.verify_kernel(*kernel())
        self.assertEqual(value["interfaces"], ["lo"])
        self.assertEqual(value["memory_bytes"], 2560 * 1024**2)
        for change in (
            "uid",
            "cap",
            "seccomp",
            "duplicate",
            "mount",
            "tmp",
            "memory",
            "swap",
            "cpu",
            "interface",
        ):
            status, groups, mounts, interfaces = kernel()
            if change == "uid":
                status = status.replace("1000 1000 1000 1000", "0 0 0 0", 1)
            elif change == "cap":
                status = status.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001")
            elif change == "seccomp":
                status = status.replace("Seccomp:\t2", "Seccomp:\t0")
            elif change == "duplicate":
                status += "\nNoNewPrivs:\t1"
            elif change == "mount":
                mounts = mounts.replace("/input ro", "/input rw")
            elif change == "tmp":
                mounts = mounts.replace("rw,noexec,nosuid,nodev", "rw,nosuid,nodev")
            elif change == "memory":
                groups["memory.max"] = "max"
            elif change == "swap":
                groups["memory.swap.max"] = "max"
            elif change == "cpu":
                groups["cpu.max"] = "max 100000"
            else:
                interfaces.append("eth0")
            with self.subTest(change=change), self.assertRaises(HeaderProfileError):
                contract.verify_kernel(status, groups, mounts, interfaces)

    def test_transcript_records_native_response_with_body_digest_and_no_key(self):
        client = contract.TranscriptClient("1" * 64, time.monotonic() + 120)
        with patch.object(Client, "request", return_value={"Result": "OK"}) as request:
            client.request("POST", "/JSON/exim/action/importHar/", b"sanitized-capture-only")
        request.assert_called_once()
        entry = client.transcript[0]
        self.assertEqual(
            entry["body_sha256"], hashlib.sha256(b"sanitized-capture-only").hexdigest()
        )
        self.assertNotIn(client.key, json.dumps(entry))
        self.assertNotIn("sanitized-capture-only", json.dumps(entry))

    def test_unapproved_route_is_not_sent_or_retained_and_sensitive_failure_is_class_only(self):
        client = contract.TranscriptClient("2" * 64, time.monotonic() + 120)
        with patch.object(Client, "request") as request:
            with self.assertRaises(HeaderProfileError):
                client.request("GET", "/JSON/ascan/action/scan/?url=outside.invalid")
            request.assert_not_called()
            self.assertEqual(client.transcript, [])
        with patch.object(Client, "request", side_effect=TimeoutError("private-secret-message")):
            with self.assertRaises(TimeoutError):
                client.request("GET", "/JSON/core/view/version/")
        self.assertEqual(client.transcript[0]["error_class"], "TimeoutError")
        self.assertNotIn("private-secret-message", json.dumps(client.transcript))

    def test_transcript_has_an_independent_byte_bound_and_rejects_key_echo(self):
        client = contract.TranscriptClient("3" * 64, time.monotonic() + 120)
        client.transcript_bytes = contract.TRANSCRIPT_BYTES
        with patch.object(Client, "request", return_value={"version": "2.17.0"}):
            with self.assertRaises(HeaderProfileError):
                client.request("GET", "/JSON/core/view/version/")
        self.assertEqual(client.transcript, [])
        client.transcript_bytes = 0
        with patch.object(Client, "request", return_value={"echo": client.key}):
            with self.assertRaises(HeaderProfileError):
                client.request("GET", "/JSON/core/view/version/")
        self.assertEqual(client.transcript, [])

    def test_exact_recipe_and_actual_offline_parse_prohibit_egress_credentials_and_auto_mount_creation(
        self,
    ):
        path = Path(__file__).resolve().parent / "fixtures/scanner-compose.json"
        value = json.loads(path.read_text(encoding="utf8"))
        controls.verify_compose_config(value, IMAGE, RUN, "/offline-scanner-profile")
        config = value["services"]["scanner"]
        self.assertEqual(config["network_mode"], "none")
        self.assertTrue(config["healthcheck"]["disable"])
        self.assertTrue(
            all(item["bind"]["create_host_path"] is False for item in config["volumes"])
        )
        self.assertEqual(
            set(config["environment"]),
            {"SB_ZAP_RUN", "SB_ZAP_SOURCE_PROOF", "PYTHONDONTWRITEBYTECODE"},
        )
        self.assertNotIn("ports", config)

    def test_recipe_changes_cannot_add_ports_networks_secrets_privileges_or_unbounded_memory(self):
        for change in (
            "port",
            "network",
            "secret",
            "source_mount",
            "memory",
            "health",
            "privilege",
            "boolean",
            "extra_service",
        ):
            value = controls.expected_config(IMAGE, RUN, "/offline-scanner-profile")
            config = value["services"]["scanner"]
            if change == "port":
                config["ports"] = ["8080:8080"]
            elif change == "network":
                config["network_mode"] = "host"
            elif change == "secret":
                config["environment"]["API_KEY"] = "nonfunctional-private-value"
            elif change == "source_mount":
                config["volumes"][1]["source"] = "/other-project"
            elif change == "memory":
                config["mem_limit"] *= 2
            elif change == "health":
                config["healthcheck"]["disable"] = False
            elif change == "privilege":
                config["privileged"] = True
            elif change == "boolean":
                config["read_only"] = 1
            else:
                value["services"]["other"] = copy.deepcopy(config)
            with self.subTest(change=change), self.assertRaises(LabControlError):
                controls.verify_compose_config(value, IMAGE, RUN, "/offline-scanner-profile")

    def test_workstation_entry_rejected_before_input_io_or_process_creation(self):
        with (
            patch.object(runner.subprocess, "Popen") as process,
            patch.object(runner, "read_closed") as read,
        ):
            with self.assertRaises(HeaderProfileError):
                runner.main()
            process.assert_not_called()
            read.assert_not_called()

    def test_fixed_command_has_explicit_heap_private_config_loopback_silent_and_clean_environment(
        self,
    ):
        directory = runner.RUNTIME / "fault"
        argv = runner.command(directory)
        self.assertIn("-Xmx1536m", argv)
        self.assertIn("-silent", argv)
        self.assertEqual(argv[argv.index("-host") + 1], "127.0.0.1")
        self.assertEqual(argv[argv.index("-configfile") + 1], str(directory / "private.properties"))
        with self.assertRaises(HeaderProfileError):
            runner.command(Path("/arbitrary"))
        environment = runner.child_environment(directory)
        self.assertEqual(set(environment), {"PATH", "HOME", "LANG", "TZ"})
        self.assertNotIn("JAVA_TOOL_OPTIONS", environment)
        self.assertFalse(
            any("addoninstall" in argument or "api.key" in argument for argument in argv)
        )

    def test_readiness_failure_and_deadline_never_become_a_clean_scan(self):
        child, overflow = Mock(), threading.Event()
        child.poll.return_value = 1
        with self.assertRaises(HeaderProfileError):
            runner.ready(Mock(deadline=time.monotonic() + 10), child, overflow)
        client = Mock(deadline=time.monotonic() - 1)
        with self.assertRaises(ValueError):
            runner.ready(client, child, overflow)
        client.api.assert_not_called()

    def test_invalid_capture_or_unbounded_phase_deadline_is_rejected_before_files_or_processes(
        self,
    ):
        with (
            patch.object(Path, "mkdir") as directory,
            patch.object(runner.subprocess, "Popen") as process,
        ):
            with self.assertRaises(HeaderProfileError):
                runner.run_phase("fault", [], START.isoformat(), time.monotonic() + 300)
            for deadline in (float("inf"), float("nan"), time.monotonic() + 1000, True):
                with self.subTest(deadline=deadline), self.assertRaises(HeaderProfileError):
                    runner.run_phase("fault", rows(), START.isoformat(), deadline)
            directory.assert_not_called()
            process.assert_not_called()

    def test_owned_process_shutdown_checks_group_and_records_forced_cleanup(self):
        child = Mock(pid=4242, returncode=0)
        child.poll.return_value = None
        with (
            patch.object(runner.os, "getpgid", return_value=4242, create=True),
            patch.object(runner.os, "killpg", create=True) as kill,
            patch.object(runner, "group_present", return_value=False),
        ):
            result = runner.stop_child(child)
            self.assertTrue(result["stopped"])
            self.assertFalse(result["forced"])
            kill.assert_called_once_with(4242, signal.SIGTERM)
        child.wait.side_effect = [subprocess.TimeoutExpired("owned-zap", 10), None]
        with (
            patch.object(runner.os, "getpgid", return_value=4242, create=True),
            patch.object(runner.os, "killpg", create=True) as kill,
            patch.object(runner, "group_present", side_effect=[True, False, False]),
            patch.object(runner.signal, "SIGKILL", 9, create=True),
        ):
            result = runner.stop_child(child)
            self.assertTrue(result["forced"])
            self.assertTrue(result["stopped"])
            self.assertEqual(kill.call_args_list[-1].args, (4242, signal.SIGKILL))
        with (
            patch.object(runner.os, "getpgid", return_value=1111, create=True),
            patch.object(runner.os, "killpg", create=True) as kill,
        ):
            self.assertFalse(runner.stop_child(child)["stopped"])
            kill.assert_not_called()

    def test_process_log_redacts_the_ephemeral_api_key_without_writing_it_to_evidence(self):
        key, overflow = "4" * 64, threading.Event()
        with patch("integrations.zap.run_passive.private_write") as write:
            collect_log(
                io.BytesIO(("api.key=" + key).encode()),
                Path("/evidence/fault-process.log"),
                overflow,
                key,
            )
        retained = write.call_args.args[1]
        self.assertNotIn(key.encode(), retained)
        self.assertIn(b"[redacted-api-key]", retained)
        self.assertFalse(overflow.is_set())

    def exercise_phase(self, *, fail=None, forced=False, phase="fault"):
        client = ModeledAPI(phase)
        client.reads[("autoupdate", "view", "installedAddons")] = addons()
        client.transcript = []
        child, thread = Mock(), Mock()
        child.poll.return_value = None
        thread.is_alive.return_value = False
        saved = {}

        def save(name, value):
            saved[name] = copy.deepcopy(value)
            return "f" * 64

        operation = (
            patch.object(runner, "analyze_phase", side_effect=fail)
            if fail
            else patch.object(runner, "analyze_phase", wraps=runner.analyze_phase)
        )
        with (
            patch.object(Path, "mkdir"),
            patch.object(runner, "safe_directory"),
            patch.object(runner, "private_write") as write,
            patch.object(runner.subprocess, "Popen", return_value=child) as spawn,
            patch.object(runner.threading, "Thread", return_value=thread),
            patch.object(runner, "TranscriptClient", return_value=client),
            patch.object(runner, "ready", return_value=1),
            patch.object(
                runner,
                "stop_child",
                return_value={"stopped": True, "forced": forced, "exit_code": 0},
            ),
            patch.object(runner, "save", side_effect=save),
            operation,
        ):
            result = runner.run_phase(
                phase,
                rows(phase),
                (START + timedelta(seconds=12)).isoformat(),
                time.monotonic() + 540,
            )
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])
        self.assertFalse(spawn.call_args.kwargs["shell"])
        self.assertEqual(write.call_args.args[0].name, "private.properties")
        thread.join.assert_called_once_with(timeout=3)
        self.assertLessEqual(client.calls, MAX_CALLS)
        return result, saved

    def test_modeled_native_phase_retains_validated_analysis_and_independent_shutdown(self):
        result, saved = self.exercise_phase()
        self.assertTrue(result["completed"])
        self.assertEqual(len(saved["fault-analysis.json"]["findings"]), 1)
        self.assertFalse(saved["fault-analysis.json"]["runtime_attested"])
        self.assertFalse(saved["fault-analysis.json"]["source_capture_attested"])
        self.assertIn("fault-process.json", saved)
        self.assertIn("fault-api.json", saved)

    def test_api_failure_and_forced_shutdown_retain_incomplete_phase_not_clean_coverage(self):
        result, saved = self.exercise_phase(fail=TimeoutError("private-sensitive-value"))
        self.assertFalse(result["completed"])
        self.assertEqual(result["error_class"], "TimeoutError")
        self.assertTrue(result["process_shutdown"]["stopped"])
        self.assertNotIn("fault-analysis.json", saved)
        self.assertNotIn("private-sensitive-value", json.dumps(saved))
        result, saved = self.exercise_phase(forced=True)
        self.assertFalse(result["completed"])
        self.assertIn("fault-analysis.json", saved)

    def test_equivalent_corrected_phase_has_no_finding_and_uses_its_own_private_home(self):
        result, saved = self.exercise_phase(phase="corrected")
        self.assertTrue(result["completed"])
        self.assertEqual(saved["corrected-analysis.json"]["findings"], [])
        self.assertNotIn("fault-analysis.json", saved)
        self.assertNotEqual(
            runner.command(runner.RUNTIME / "fault"), runner.command(runner.RUNTIME / "corrected")
        )

    def exercise_pipeline(self, outcomes):
        value = package()
        raw = contract.receipt_bytes(value)
        gate = {
            "run_id": RUN,
            "runtime_verified": True,
            "source_run_id": value["source_run_id"],
            "source_receipt_sha256": value["source_receipt_sha256"],
            "input_sha256": hashlib.sha256(raw).hexdigest(),
        }
        saved = {}

        def save(name, result):
            saved[name] = copy.deepcopy(result)
            return "f" * 64

        with (
            patch.object(runner, "runtime_gate", return_value=RUN),
            patch.object(Path, "read_text", return_value="not-used-kernel-double"),
            patch.object(Path, "iterdir", return_value=iter([Path("/sys/class/net/lo")])),
            patch.object(Path, "mkdir"),
            patch.object(runner, "safe_directory"),
            patch.object(runner, "verify_kernel", return_value=contract.verify_kernel(*kernel())),
            patch.object(
                runner, "read_closed", side_effect=[(raw, value), (b"unused-gate-raw", gate)]
            ),
            patch.object(runner, "run_phase", side_effect=outcomes) as phases,
            patch.object(runner, "save", side_effect=save),
        ):
            code = runner.main()
        return code, phases.call_args_list, saved["scanner-runner.json"]

    def test_pipeline_uses_two_fresh_phases_and_does_not_promote_local_receipts_to_attestation(
        self,
    ):
        outcomes = [
            {"phase": phase, "completed": True, "installed_addons": {"exim": "1"}}
            for phase in ("fault", "corrected")
        ]
        code, calls, result = self.exercise_pipeline(outcomes)
        self.assertEqual(code, 0)
        self.assertEqual([call.args[0] for call in calls], ["fault", "corrected"])
        self.assertTrue(result["completed"])
        self.assertFalse(result["runtime_attested"])
        self.assertFalse(result["source_capture_attested"])

    def test_partial_first_phase_skips_retest_and_changed_addons_invalidate_equivalence(self):
        code, calls, result = self.exercise_pipeline([{"phase": "fault", "completed": False}])
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 1)
        self.assertFalse(result["completed"])
        code, calls, result = self.exercise_pipeline(
            [
                {"phase": "fault", "completed": True, "installed_addons": {"exim": "1"}},
                {"phase": "corrected", "completed": True, "installed_addons": {"exim": "2"}},
            ]
        )
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 2)
        self.assertFalse(result["completed"])
