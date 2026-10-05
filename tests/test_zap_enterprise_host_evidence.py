"""Synthetic archive tampering/recomputation checks; no native scanner proof."""

import copy
import hashlib
import shutil
import time
import uuid
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from django.test import SimpleTestCase

from integrations.enterprise.verification import LabControlError, private_run_directory
from integrations.zap_enterprise import scanner_host_evidence as host
from integrations.zap_enterprise.capture import PROFILE, HeaderProfileError
from integrations.zap_enterprise.passive import GET_ROUTES, Client, analyze_phase
from integrations.zap_enterprise.scanner_contract import receipt_bytes, verify_kernel
from integrations.zap_enterprise.scanner_runner import LIMITS
from scripts.record_verification import json_bytes
from tests.test_zap_enterprise_capture import START
from tests.test_zap_enterprise_passive import ModeledAPI
from tests.test_zap_enterprise_runtime import RUN, addons, kernel, package


class RecordedModel(Client):
    def __init__(self, value, phase):
        self.value, self.phase = value, phase
        self.model, self.calls, self.entries = ModeledAPI(phase), 0, []
        self.deadline = time.monotonic() + 120

    def request(self, method, path, body=None):
        if method == "POST":
            self.model.import_capture(
                self.value["phases"][self.phase], self.phase, self.value["execution"]["captured_at"]
            )
            response = {"Result": "OK"}
        else:
            matches = [
                route
                for route, parameters in GET_ROUTES.items()
                if path
                == "/JSON/"
                + "/".join(route)
                + "/"
                + ("?" + urlencode(parameters) if parameters else "")
            ]
            assert len(matches) == 1
            route = matches[0]
            response = (
                addons()
                if route[0] == "autoupdate"
                else self.model.api(*route, **GET_ROUTES[route])
            )
        self.calls += 1
        entry = {"method": method, "path": path, "response": response, "elapsed_seconds": 0.001}
        if body is not None:
            entry["body_sha256"] = hashlib.sha256(body).hexdigest()
        self.entries.append(copy.deepcopy(entry))
        return response


def phase_receipts(value, phase):
    client = RecordedModel(value, phase)
    client.api("core", "view", "version")
    installed = host.validate_addons(client.api("autoupdate", "view", "installedAddons"))
    analysis = analyze_phase(
        client,
        value["phases"][phase],
        phase,
        value["execution"]["captured_at"],
        pause=lambda _: None,
    )
    transcript_hash = hashlib.sha256(receipt_bytes(client.entries)).hexdigest()
    analysis_hash = hashlib.sha256(receipt_bytes(analysis)).hexdigest()
    process = {
        "phase": phase,
        "completed": True,
        "readiness_attempts": 1,
        "installed_addons": installed,
        "api_evidence_validated": True,
        "process_shutdown": {"stopped": True, "forced": False, "exit_code": -15},
        "log_overflow": False,
        "log_collector_stopped": True,
        "api_calls": client.calls,
        "duration_seconds": 4.0,
        "transcript_sha256": transcript_hash,
        "analysis_sha256": analysis_hash,
    }
    return client.entries, process, analysis


class ScannerHostEvidenceTests(SimpleTestCase):
    def setUp(self):
        self.value = package()

    @contextmanager
    def temporary_workspace(self):
        parent = Path(__file__).resolve().parents[1] / "var/tests"
        parent.mkdir(parents=True, exist_ok=True)
        # Synthetic fixtures use normal inherited permissions. Python 3.14's
        # private temp-directory ACL excludes the managed test process on Windows.
        # Native evidence still requires the separately verified private ACL.
        workspace = parent / ("z" + uuid.uuid4().hex[:8])
        workspace.mkdir()
        try:
            yield workspace
        finally:
            if not workspace.resolve().is_relative_to(parent.resolve()) or workspace.is_symlink():
                raise RuntimeError("Unsafe scanner fixture cleanup.")
            shutil.rmtree(workspace)

    def recompute(self, phase="fault", change=None):
        entries, process, analysis = phase_receipts(self.value, phase)
        if change:
            change(entries, process, analysis)
        hashes = {
            phase + "-api.json": hashlib.sha256(receipt_bytes(entries)).hexdigest(),
            phase + "-analysis.json": hashlib.sha256(receipt_bytes(analysis)).hexdigest(),
        }
        # A forger can update hashes; the parser must still reject changed content.
        process["transcript_sha256"] = hashes[phase + "-api.json"]
        process["analysis_sha256"] = hashes[phase + "-analysis.json"]
        return host.revalidate_phase(
            entries,
            process,
            analysis,
            self.value["phases"][phase],
            phase,
            self.value["execution"]["captured_at"],
            hashes,
        )

    def test_recomputed_finding_and_retest_keep_attestation_false_without_sockets(self):
        with patch("http.client.HTTPConnection") as socket:
            for phase in ("fault", "corrected"):
                result = self.recompute(phase)
                self.assertEqual(len(result["analysis"]["findings"]), 1 if phase == "fault" else 0)
                self.assertFalse(result["analysis"]["source_capture_attested"])
                self.assertFalse(result["analysis"]["runtime_attested"])
            socket.assert_not_called()

    def test_readiness_failure_prefix_is_bounded_counted_and_class_only(self):
        def change(entries, process, analysis):
            entries.insert(
                0,
                {
                    "method": "GET",
                    "path": "/JSON/core/view/version/",
                    "error_class": "ConnectionRefusedError",
                    "calls_attempted": 1,
                },
            )
            process["readiness_attempts"] += 1
            process["api_calls"] += 1
            analysis["api_calls"] += 1

        original_calls = phase_receipts(self.value, "fault")[1]["api_calls"]
        self.assertEqual(self.recompute(change=change)["analysis"]["api_calls"], original_calls + 1)
        for field, value in (
            ("calls_attempted", True),
            ("error_class", "RuntimeError"),
            ("extra", "private"),
        ):

            def altered(entries, process, analysis, field=field, value=value):
                change(entries, process, analysis)
                entries[0][field] = value

            with self.subTest(field=field), self.assertRaises(ValueError):
                self.recompute(change=altered)

    def test_success_prefix_cannot_hide_extra_calls_or_wrong_readiness_count(self):
        for mutation in ("extra", "count", "active", "changed_query", "reorder"):

            def change(entries, process, analysis, mutation=mutation):
                if mutation == "extra":
                    entries.append(copy.deepcopy(entries[0]))
                    process["api_calls"] += 1
                elif mutation == "count":
                    process["readiness_attempts"] = 2
                elif mutation == "active":
                    entries[4]["path"] = "/JSON/ascan/action/scan/"
                elif mutation == "changed_query":
                    entries[-4]["path"] += "&count=0"
                else:
                    entries[3], entries[4] = entries[4], entries[3]

            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.recompute(change=change)

    def test_wrong_har_digest_cannot_be_repaired_by_rehashing_transcript(self):
        def change(entries, _process, _analysis):
            entry = next(entry for entry in entries if entry["method"] == "POST")
            entry["body_sha256"] = "f" * 64

        with self.assertRaises(ValueError):
            self.recompute(change=change)

    def test_native_history_and_alert_binding_are_recomputed_not_trusted(self):
        for mutation in (
            "record",
            "credential",
            "message_id",
            "rule",
            "missing_alert",
            "extra_alert",
        ):

            def change(entries, _process, _analysis, mutation=mutation):
                history = next(e["response"] for e in entries if "messages" in e["response"])
                alerts = next(e["response"] for e in entries if "alerts" in e["response"])
                if mutation == "record":
                    history["messages"][1]["responseBody"] = "other-content"
                elif mutation == "credential":
                    history["messages"][1]["requestHeader"] += "Cookie: nonfunctional\r\n"
                elif mutation == "message_id":
                    alerts["alerts"][0]["messageId"] = "5"
                elif mutation == "rule":
                    alerts["alerts"][0]["pluginId"] = "999"
                elif mutation == "missing_alert":
                    alerts["alerts"].clear()
                else:
                    alerts["alerts"].append(copy.deepcopy(alerts["alerts"][0]))

            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.recompute(change=change)

    def test_saved_analysis_cannot_promote_attestation_or_change_finding(self):
        for field, value in (
            ("source_capture_attested", True),
            ("runtime_attested", True),
            ("findings", []),
            ("api_calls", 1),
            ("extra", "unsupported"),
        ):

            def change(_entries, _process, analysis, field=field, value=value):
                analysis[field] = value

            with self.subTest(field=field), self.assertRaises(ValueError):
                self.recompute(change=change)

    def test_partial_forced_or_unbounded_process_is_not_complete_coverage(self):
        for field, value in (
            ("completed", 1),
            ("api_evidence_validated", False),
            ("log_overflow", True),
            ("log_collector_stopped", False),
            ("duration_seconds", 241),
            ("duration_seconds", float("inf")),
            ("api_calls", True),
            ("process_shutdown", {"stopped": True, "forced": True, "exit_code": -9}),
            ("process_shutdown", {"stopped": True, "forced": False, "exit_code": True}),
            ("error_class", "TimeoutError"),
        ):

            def change(_entries, process, _analysis, field=field, value=value):
                process[field] = value

            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.recompute(change=change)

    def test_transcript_timing_counts_unknown_fields_and_byte_limits_are_bounded(self):
        for field, value in (
            ("elapsed_seconds", -1),
            ("elapsed_seconds", 7),
            ("elapsed_seconds", True),
            ("elapsed_seconds", float("nan")),
            ("extra", "private"),
            ("response", {"version": "2.17.0", "extra": "x" * (2 * 1024**2)}),
        ):

            def change(entries, _process, _analysis, field=field, value=value):
                entries[0][field] = value

            with self.subTest(field=field), self.assertRaises(ValueError):
                self.recompute(change=change)
        for entries in (None, {}, [], [None], [{}] * 161):
            with self.subTest(kind=type(entries).__name__), self.assertRaises(ValueError):
                host.ReplayClient(entries)

    def test_recomputed_elapsed_api_time_cannot_exceed_process_duration(self):
        def change(entries, _process, _analysis):
            for entry in entries:
                entry["elapsed_seconds"] = 1.0

        with self.assertRaises(ValueError):
            self.recompute(change=change)

    def archive(self, workspace):
        directory = private_run_directory(workspace, RUN)
        source = directory / "source"
        names = [
            "integrations/zap_enterprise/" + name + ".py"
            for name in ("scanner_runner", "scanner_contract", "passive", "capture")
        ]
        files = {}
        for name in names:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = b"# Synthetic source snapshot only; never executed.\n"
            path.write_bytes(raw)
            files[name] = hashlib.sha256(raw).hexdigest()
        manifest = {
            "files": files,
            "file_count": len(files),
            "sha256": hashlib.sha256(json_bytes(files)).hexdigest(),
        }
        value = copy.deepcopy(self.value)
        value["source_sha256"] = manifest["sha256"]
        input_raw = receipt_bytes(value)
        (directory / "input").mkdir()
        (directory / "input/source-capture.json").write_bytes(input_raw)
        evidence = directory / "evidence"
        evidence.mkdir()
        receipts = {
            "allow-scanner.json": {
                "run_id": RUN,
                "runtime_verified": True,
                "source_run_id": value["source_run_id"],
                "source_receipt_sha256": value["source_receipt_sha256"],
                "input_sha256": hashlib.sha256(input_raw).hexdigest(),
            },
            "scanner-kernel.json": verify_kernel(*kernel()),
        }
        phases = []
        for phase in ("fault", "corrected"):
            entries, process, analysis = phase_receipts(value, phase)
            receipts[phase + "-api.json"] = entries
            receipts[phase + "-process.json"] = process
            receipts[phase + "-analysis.json"] = analysis
            (evidence / (phase + "-process.log")).write_bytes(
                b"Modeled private log; no process ran.\n"
            )
            phases.append(process)
        receipts["scanner-runner.json"] = {
            "schema_version": 1,
            "profile": PROFILE,
            "run_id": RUN,
            "completed": True,
            "source_capture_attested": False,
            "runtime_attested": False,
            "started_at": (START + timedelta(seconds=15)).isoformat(),
            "finished_at": (START + timedelta(seconds=25)).isoformat(),
            "phases": phases,
            "limits": list(LIMITS),
            "kernel_sha256": hashlib.sha256(
                receipt_bytes(receipts["scanner-kernel.json"])
            ).hexdigest(),
            "input_sha256": hashlib.sha256(input_raw).hexdigest(),
            "source_run_id": value["source_run_id"],
            "source_receipt_sha256": value["source_receipt_sha256"],
            "duration_seconds": 10.0,
        }
        for name, result in receipts.items():
            (evidence / name).write_bytes(receipt_bytes(result))
        return directory, manifest, receipts

    def test_complete_file_consistency_still_is_not_source_runtime_or_shutdown_attestation(self):
        with self.temporary_workspace() as workspace:
            _directory, manifest, _receipts = self.archive(workspace)
            with (
                patch("http.client.HTTPConnection") as socket,
                patch("subprocess.Popen") as process,
            ):
                result = host.validate_receipts(
                    workspace, RUN, manifest, now=START + timedelta(minutes=1)
                )
                socket.assert_not_called()
                process.assert_not_called()
            self.assertTrue(result["scanner_receipts_revalidated"])
            for flag in (
                "source_capture_attested",
                "runtime_attested",
                "host_shutdowns_verified",
                "native_zap_executed",
            ):
                self.assertIs(result[flag], False)
            self.assertEqual(len(result["raw_receipt_sha256"]), 11)

    def test_unexpected_or_missing_files_and_changed_snapshot_fail_closed(self):
        for change in ("extra", "missing", "source"):
            with self.temporary_workspace() as workspace:
                directory, manifest, _receipts = self.archive(workspace)
                if change == "extra":
                    (directory / "evidence/extra.json").write_bytes(b"{}")
                elif change == "missing":
                    (directory / "evidence/fault-process.log").unlink()
                else:
                    (directory / "source/integrations/zap_enterprise/capture.py").write_bytes(
                        b"changed"
                    )
                with (
                    self.subTest(change=change),
                    self.assertRaises((HeaderProfileError, LabControlError)),
                ):
                    host.validate_receipts(
                        workspace, RUN, manifest, now=START + timedelta(minutes=1)
                    )

    def test_wrong_scope_snapshot_gate_future_time_and_promoted_runner_are_rejected(self):
        for change in (
            "source_run",
            "gate",
            "snapshot",
            "future",
            "clock",
            "attestation",
            "kernel",
            "extra",
        ):
            with self.temporary_workspace() as workspace:
                directory, manifest, receipts = self.archive(workspace)
                name = "scanner-runner.json"
                result = receipts[name]
                if change == "source_run":
                    result["source_run_id"] = "f" * 32
                elif change == "gate":
                    name, result = "allow-scanner.json", receipts["allow-scanner.json"]
                    result["runtime_verified"] = 1
                elif change == "snapshot":
                    name, result = "../input/source-capture.json", copy.deepcopy(self.value)
                elif change == "future":
                    result["finished_at"] = (START + timedelta(hours=2)).isoformat()
                elif change == "clock":
                    result["duration_seconds"] = 1
                elif change == "attestation":
                    result["runtime_attested"] = True
                elif change == "kernel":
                    name, result = "scanner-kernel.json", receipts["scanner-kernel.json"]
                    result["interfaces"].append("eth0")
                    receipts["scanner-runner.json"]["kernel_sha256"] = hashlib.sha256(
                        receipt_bytes(result)
                    ).hexdigest()
                    (directory / "evidence/scanner-runner.json").write_bytes(
                        receipt_bytes(receipts["scanner-runner.json"])
                    )
                else:
                    result["unsupported"] = "extra"
                (directory / "evidence" / name).write_bytes(receipt_bytes(result))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    host.validate_receipts(
                        workspace, RUN, manifest, now=START + timedelta(minutes=1)
                    )

    def test_phase_receipts_reject_runner_disagreement_changed_addons_and_missing_native_result(
        self,
    ):
        for change in ("phase", "addons", "analysis", "duplicate_json"):
            with self.temporary_workspace() as workspace:
                directory, manifest, receipts = self.archive(workspace)
                evidence = directory / "evidence"
                if change == "phase":
                    receipts["scanner-runner.json"]["phases"] = list(
                        reversed(receipts["scanner-runner.json"]["phases"])
                    )
                    (evidence / "scanner-runner.json").write_bytes(
                        receipt_bytes(receipts["scanner-runner.json"])
                    )
                elif change == "addons":
                    entries = receipts["corrected-api.json"]
                    entries[1]["response"]["installedAddons"][0]["version"] = "2.0"
                    process = receipts["corrected-process.json"]
                    process["installed_addons"]["exim"]["version"] = "2.0"
                    process["transcript_sha256"] = hashlib.sha256(
                        receipt_bytes(entries)
                    ).hexdigest()
                    for name in (
                        "corrected-api.json",
                        "corrected-process.json",
                        "scanner-runner.json",
                    ):
                        (evidence / name).write_bytes(receipt_bytes(receipts[name]))
                elif change == "analysis":
                    (evidence / "corrected-analysis.json").write_bytes(b"{}")
                else:
                    (evidence / "scanner-runner.json").write_bytes(
                        b'{"schema_version":1,"schema_version":1}'
                    )
                with self.subTest(change=change), self.assertRaises(ValueError):
                    host.validate_receipts(
                        workspace, RUN, manifest, now=START + timedelta(minutes=1)
                    )
