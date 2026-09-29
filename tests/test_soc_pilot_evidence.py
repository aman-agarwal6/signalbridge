"""Synthetic receipts and mocked Docker inspection only; no service/scanner execution."""

import copy
import io
import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase, override_settings

from bridge import soc_pilot_evidence as evidence
from bridge.models import Audit, CheckRun, Integration, ScanRun
from tests.test_zap_report import fixture as zap_fixture

RUN = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
SOURCE_FILES = (
    "run_pilot.py",
    "verify_static.py",
    "event-contract.json",
    "manager-lab.conf",
    "signalbridge_rules.xml",
    "image-lock.json",
    "fixtures/events.jsonl",
    "fixtures/expectations.json",
)


def receipt_fixture(tool):
    source = {
        "package": {
            name: evidence.digest((settings.BASE_DIR / "integrations/wazuh" / name).read_bytes())
            for name in SOURCE_FILES
        }
    }
    source_hash = evidence.gate.base.sha256(evidence.gate.base.canonical(source))
    base = Path("var/soc/pilot") / RUN
    data = {}
    states = ("created", "running", "exited")
    for minute, state in enumerate(states):
        data[base / f"{tool}-{state}.json"] = {
            "schema_version": 1,
            "profile": "soc-pilot-" + tool,
            "run_id": RUN,
            "checked_at": f"2026-09-24T10:0{minute}:00+00:00",
            "expected_state": state,
            "status": "passed",
            "errors": [],
            "limitations": ["Synthetic test gate."],
            "source_sha256": source_hash,
            "containers": [
                {
                    "name": name,
                    "id": str(index) * 64,
                    "image_id": "sha256:" + str(index + 2) * 64,
                    "image_reference": evidence.gate.IMAGES[name],
                    "state": state,
                }
                for index, name in enumerate(evidence.gate.NAMES[tool], 1)
            ],
            "networks": []
            if tool == "wazuh"
            else [{"name": evidence.gate.NETWORK, "id": "9" * 64, "internal": True}],
        }
    if tool == "wazuh":
        directory = settings.BASE_DIR / "integrations/wazuh/fixtures"
        expectations = json.loads((directory / "expectations.json").read_bytes())
        events = (directory / "events.jsonl").read_bytes()
        data[Path("integrations/wazuh/fixtures/expectations.json")] = expectations
        data[Path("integrations/wazuh/fixtures/events.jsonl")] = events
        lines = events.decode().splitlines()
        batch = [
            json.dumps(json.loads(line), separators=(",", ":"), ensure_ascii=False)
            for line, case in zip(lines, expectations["cases"], strict=True)
            if case["export_contract_valid"]
        ]
        sentinel = json.loads(lines[2])
        sentinel["signalbridge"]["event_id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
        batch.append(json.dumps(sentinel, separators=(",", ":")))
        report = {
            "schema_version": 1,
            "tool": "wazuh",
            "status": "passed",
            "scope": "isolated_synthetic_manager_pilot",
            "synthetic_only": True,
            "logtest_verified": True,
            "collection_verified": True,
            "expected_logtest_case_count": 27,
            "passed_logtest_case_count": 27,
            "owned_processes_stopped": True,
            "failure_code": None,
            "source_sha256": source["package"],
            "runtime_version": "4.14.8",
            "duration_seconds": 10.5,
            "logtest_cases": [
                {
                    "id": case["id"],
                    "status": "passed",
                    "expected_rule": case["expected_rule"],
                    "expected_level": case["expected_level"],
                    "observed_rule": case["expected_rule"],
                    "observed_level": case["expected_level"],
                    "decoder": "json",
                }
                for case in expectations["cases"]
            ],
            "collector": {
                "verified": True,
                "collector_counts_verified": True,
                "observed_event_count": 19,
                "observed_drop_count": 0,
                "state_interval_seconds": 1,
                "expected_processed_bytes": sum(len(line.encode()) + 1 for line in batch),
                "observed_processed_bytes": sum(len(line.encode()) + 1 for line in batch),
                "input_count": 19,
                "fixture_input_count": 18,
                "tail_sentinel_count": 1,
                "expected_alert_count": 12,
                "negative_control_count": 7,
                "quiet_window_seconds": 3,
                "observed_alert_count": 12,
                "duplicate_count": 0,
                "unexpected_custom_alert_count": 0,
                "batch_sha256": evidence.digest(("\n".join(batch) + "\n").encode()),
            },
        }
        runtime_path = base / tool / "result.json"
    else:
        raw_report = zap_fixture()
        alert = raw_report["site"][0]["alerts"][0]
        alert.update(pluginid="10021", alertRef="10021", count="2")
        alert["instances"] = [
            {"uri": evidence.ORIGIN + path, "method": "GET"} for path in ("/", "/login/")
        ]
        raw = json.dumps(raw_report).encode()
        data[base / tool / "zap-report.json"] = raw
        report = {
            "schema_version": 1,
            "kind": "signalbridge-zap-synthetic-pilot",
            "target_kind": "synthetic-fixture-not-signalbridge-application",
            "profile": evidence.PROFILE,
            "status": "passed",
            "started_at": "2026-09-24T10:00:10+00:00",
            "errors": [],
            "limits": [],
            "zap_version": raw_report["@version"],
            "controls": {
                "rule_id": "10021",
                "positive_paths": ["/", "/login/"],
                "negative_path": "/health/",
                "status": "passed",
            },
            "report_sha256": evidence.digest(raw),
            "passive_queue_complete": True,
            "request_count": 3,
            "redirects_followed": False,
            "safe_mode": True,
            "requests": [
                {
                    "method": "GET",
                    "path": path,
                    "status": "passed",
                    "http_status": 200,
                    "body_sha256": evidence.BODY_HASHES[path],
                }
                for path in evidence.PATHS
            ],
            "zap_exit_code": 0,
            "history_verified": True,
            "history_message_count": 6,
            "history_proxied_count": 3,
            "history_internal_count": 3,
            "history_request_paths": list(evidence.PATHS),
            "history_internal_ancestor_paths": [path.rstrip("/") for path in evidence.PATHS],
            "finished_at": "2026-09-24T10:01:30+00:00",
        }
        runtime_path = base / tool / "pilot-result.json"
    data[runtime_path] = report
    fresh = copy.deepcopy(data[base / f"{tool}-exited.json"])
    fresh["checked_at"] = "2026-09-24T11:00:00+00:00"
    return data, source, fresh, runtime_path


def bound_wazuh_fixture():
    data, source, fresh, path = receipt_fixture("wazuh")
    source["package"]["run_context.py"] = evidence.digest(
        (settings.BASE_DIR / "integrations/wazuh/run_context.py").read_bytes()
    )
    source_hash = evidence.digest(evidence.canonical(source))
    base = path.parent.parent
    for state in ("created", "running", "exited"):
        data[base / f"wazuh-{state}.json"]["source_sha256"] = source_hash
    fresh["source_sha256"] = source_hash
    context = json.dumps(
        {
            "schema_version": 1,
            "kind": "signalbridge-wazuh-run-context",
            "run_id": RUN,
            "prepared_at": "2026-09-24T09:59:00+00:00",
            "source_sha256": source_hash,
        }
    ).encode()
    data[path.parent / "run-context.json"] = context
    lines = data[Path("integrations/wazuh/fixtures/events.jsonl")].decode().splitlines()
    cases = data[Path("integrations/wazuh/fixtures/expectations.json")]["cases"]
    records, alerts = [], []
    selected = [
        (json.loads(line), case)
        for line, case in zip(lines, cases, strict=True)
        if case["export_contract_valid"]
    ]
    sentinel = json.loads(lines[2])
    sentinel["signalbridge"]["event_id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
    selected.append(
        (sentinel, {"expected_alert": True, "expected_rule": "100202", "expected_level": 5})
    )
    for record, case in selected:
        event = record["signalbridge"]
        event["event_id"] = str(
            uuid.uuid5(uuid.UUID(RUN), "signalbridge-wazuh:" + event["event_id"])
        )
        records.append(record)
        if case["expected_alert"]:
            alerts.append(
                {
                    "timestamp": "2026-09-24T10:01:00.000+0000",
                    "decoder": {"name": "json"},
                    "location": "/signalbridge/input/events.jsonl",
                    "rule": {"id": case["expected_rule"], "level": case["expected_level"]},
                    "data": record,
                }
            )
    raw = ("\n".join(json.dumps(alert) for alert in alerts) + "\n").encode()
    data[path.parent / "alerts.jsonl"] = raw
    batch = (
        "\n".join(json.dumps(record, separators=(",", ":")) for record in records) + "\n"
    ).encode()
    report = data[path]
    report.update(
        schema_version=2,
        run_id=RUN,
        context_sha256=evidence.digest(context),
        started_at="2026-09-24T10:00:10+00:00",
        finished_at="2026-09-24T10:01:30+00:00",
        duration_seconds=80,
        alerts_sha256=evidence.digest(raw),
    )
    report["collector"].update(
        batch_sha256=evidence.digest(batch),
        expected_processed_bytes=len(batch),
        observed_processed_bytes=len(batch),
    )
    return data, source, fresh, path


class SocPilotEvidenceTests(SimpleTestCase):
    def load(self, tool="zap", *, data=None, source=None, fresh=None, reader=None):
        default_data, default_source, default_fresh, _ = receipt_fixture(tool)
        data = data if data is not None else default_data
        source = source if source is not None else default_source
        fresh = fresh if fresh is not None else default_fresh

        def read(_root, path):
            value = data[path]
            return value if isinstance(value, bytes) else json.dumps(value).encode()

        with (
            patch.object(evidence, "read_private", side_effect=reader or read),
            patch.object(evidence.gate, "source_hashes", return_value=source),
            patch.object(evidence.gate, "run_verification", return_value=fresh) as verifier,
            patch.object(
                evidence.gate, "gather_topology", side_effect=AssertionError("No Docker in tests")
            ),
        ):
            result = evidence.load_soc_pilot(settings.BASE_DIR, tool, RUN)
            verifier.assert_called_once_with(tool, RUN, state="exited")
            return result

    def bound(self, change=None):
        data, source, fresh, path = bound_wazuh_fixture()
        if change:
            change(data, source, path)
        return self.load("wazuh", data=data, source=source, fresh=fresh)

    def test_bound_run_retains_twelve_exact_observations_and_hashes(self):
        result = self.bound()["result"]["pilot"]
        self.assertEqual(result["run_binding"]["run_id"], RUN)
        self.assertEqual(len(result["run_binding"]["observations"]), 12)
        self.assertEqual(
            result["run_binding"]["alerts_sha256"], result["provenance"]["receipt_sha256"]["alerts"]
        )

    def test_container_running_can_precede_entrypoint_initialization_briefly(self):
        def change(data, source, path):
            data[path.parent.parent / "wazuh-running.json"]["checked_at"] = (
                "2026-09-24T10:00:09+00:00"
            )

        self.assertEqual(self.bound(change)["status"], "passed")

        def excessive(data, source, path):
            data[path.parent.parent / "wazuh-running.json"]["checked_at"] = (
                "2026-09-24T10:00:04+00:00"
            )

        with self.assertRaises(evidence.EvidenceError):
            self.bound(excessive)

    def test_bound_run_rejects_copied_identity_time_and_hash(self):
        for field, value in (
            ("run_id", "bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb"),
            ("context_sha256", "0" * 64),
            ("alerts_sha256", "0" * 64),
            ("started_at", "2026-09-24T09:59:59+00:00"),
            ("finished_at", "2026-09-24T10:03:00+00:00"),
            ("duration_seconds", 1),
            ("started_at", "2026-09-24T10:00:10"),
        ):
            with self.subTest(field=field), self.assertRaises(evidence.EvidenceError):
                self.bound(
                    lambda data, source, path, field=field, value=value: data[path].update(
                        {field: value}
                    )
                )

    def test_bound_context_cannot_be_swapped_even_with_recomputed_digest(self):
        for key, value in (
            ("run_id", "bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb"),
            ("source_sha256", "0" * 64),
            ("prepared_at", "2026-09-23T09:59:00+00:00"),
            ("prepared_at", "2026-09-24T10:00:11+00:00"),
            ("schema_version", True),
        ):

            def change(data, source, path, key=key, value=value):
                target = path.parent / "run-context.json"
                context = json.loads(data[target])
                context[key] = value
                data[target] = json.dumps(context).encode()
                data[path]["context_sha256"] = evidence.digest(data[target])

            with self.subTest(key=key), self.assertRaises(evidence.EvidenceError):
                self.bound(change)

    def test_bound_alerts_reject_stale_duplicate_missing_changed_and_raw_content(self):
        changes = [
            lambda rows: rows.pop(),
            lambda rows: rows.append(rows[0]),
            lambda rows: rows[0]["data"]["signalbridge"].update(
                event_id="00000000-0000-4000-8000-000000000001"
            ),
            lambda rows: rows[0]["data"]["signalbridge"].update(outcome="denied"),
            lambda rows: rows[0]["data"]["signalbridge"].update(export_version=True),
            lambda rows: rows[0]["rule"].update(level=1),
            lambda rows: rows[0].update(timestamp="2026-09-24T09:00:00+00:00"),
            lambda rows: rows[0].update(location="/other/input"),
            lambda rows: rows[0].update(full_log="synthetic raw input"),
        ]
        for index, mutate in enumerate(changes):

            def change(data, source, path, mutate=mutate):
                target = path.parent / "alerts.jsonl"
                rows = [json.loads(line) for line in data[target].splitlines()]
                mutate(rows)
                data[target] = ("\n".join(json.dumps(row) for row in rows) + "\n").encode()
                data[path]["alerts_sha256"] = evidence.digest(data[target])

            with self.subTest(index=index), self.assertRaises(evidence.EvidenceError):
                self.bound(change)

    def test_bound_reports_cannot_downgrade_to_legacy_verification(self):
        def change(data, source, path):
            data[path]["schema_version"] = 1
            for key in ("run_id", "context_sha256", "alerts_sha256", "started_at", "finished_at"):
                del data[path][key]

        with self.assertRaises(evidence.EvidenceError):
            self.bound(change)

    def test_both_complete_bundles_are_scoped_synthetic_and_preserve_claim_boundary(self):
        for tool in ("wazuh", "zap"):
            checked = self.load(tool)
            result, pilot = checked["result"], checked["result"]["pilot"]
            self.assertEqual(result["app"], "signalbridge")
            self.assertEqual(result["evidence_kind"], "soc_pilot")
            self.assertEqual(pilot["scope"], "synthetic_fixture")
            self.assertFalse(pilot["source_app_assessed"])
            self.assertFalse(pilot["continuous_connection"])
            self.assertTrue(pilot["stopped_at_end"])
            self.assertNotIn("claims", json.dumps(result))
            self.assertEqual(
                pilot["counts"].get("logtest_cases", 33), 27 if tool == "wazuh" else 33
            )
            self.assertEqual(len(checked["revision"]), 64)

    def test_all_gate_stages_must_pass_match_identity_source_and_chronology(self):
        changes = [
            ("running", "status", "failed"),
            ("created", "errors", ["failure"]),
            ("exited", "source_sha256", "0" * 64),
            ("running", "run_id", "bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb"),
            ("running", "checked_at", "2026-09-24T12:00:00+00:00"),
            ("created", "schema_version", True),
        ]
        for state, key, value in changes:
            data, _, _, _ = receipt_fixture("zap")
            data[Path("var/soc/pilot") / RUN / f"zap-{state}.json"][key] = value
            with self.subTest(state=state, key=key), self.assertRaises(evidence.EvidenceError):
                self.load(data=data)

    def test_container_and_network_substitution_or_floating_image_fail(self):
        for field, value in (
            ("id", "0" * 64),
            ("image_id", "sha256:" + "0" * 64),
            ("image_reference", "zaproxy/zap-stable:latest"),
        ):
            data, _, _, _ = receipt_fixture("zap")
            data[Path("var/soc/pilot") / RUN / "zap-exited.json"]["containers"][0][field] = value
            with self.subTest(field=field), self.assertRaises(evidence.EvidenceError):
                self.load(data=data)
        data, _, _, _ = receipt_fixture("zap")
        data[Path("var/soc/pilot") / RUN / "zap-exited.json"]["networks"][0]["id"] = "0" * 64
        with self.assertRaises(evidence.EvidenceError):
            self.load(data=data)

    def test_current_source_and_fresh_stopped_gate_are_mandatory(self):
        _, source, fresh, _ = receipt_fixture("zap")
        source["package"]["run_pilot.py"] = "0" * 64
        with self.assertRaises(evidence.EvidenceError):
            self.load(source=source)
        for key, value in (
            ("status", "failed"),
            ("expected_state", "running"),
            ("source_sha256", "0" * 64),
            ("checked_at", "2026-09-23T10:00:00+00:00"),
        ):
            bad = copy.deepcopy(fresh)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(evidence.EvidenceError):
                self.load(fresh=bad)

    def test_wazuh_missing_controls_wrong_counts_or_raw_failure_never_pass(self):
        for key, value in (
            ("status", "failed"),
            ("owned_processes_stopped", False),
            ("passed_logtest_case_count", 26),
            ("failure_code", "private_payload"),
            ("duration_seconds", float("inf")),
            ("runtime_version", "9.9.9"),
        ):
            data, _, _, runtime = receipt_fixture("wazuh")
            data[runtime][key] = value
            with self.subTest(key=key), self.assertRaises(evidence.EvidenceError) as raised:
                self.load("wazuh", data=data)
            self.assertNotIn("private_payload", str(raised.exception))
        for key, value in (
            ("observed_alert_count", 11),
            ("negative_control_count", 6),
            ("duplicate_count", 1),
            ("collector_counts_verified", False),
            ("observed_event_count", 18),
            ("observed_drop_count", 1),
            ("state_interval_seconds", 60),
            ("observed_processed_bytes", 1),
            ("expected_processed_bytes", True),
            ("batch_sha256", "0" * 64),
        ):
            data, _, _, runtime = receipt_fixture("wazuh")
            data[runtime]["collector"][key] = value
            with self.subTest(key=key), self.assertRaises(evidence.EvidenceError):
                self.load("wazuh", data=data)

    def test_wazuh_observed_rules_must_match_every_fixed_case(self):
        for index in (0, 17, 26):
            data, _, _, runtime = receipt_fixture("wazuh")
            data[runtime]["logtest_cases"][index]["observed_rule"] = "100205"
            with self.subTest(index=index), self.assertRaises(evidence.EvidenceError):
                self.load("wazuh", data=data)

    def test_zap_requires_all_three_exact_requests_queue_controls_and_clean_exit(self):
        for key, value in (
            ("status", "failed"),
            ("request_count", 2),
            ("redirects_followed", True),
            ("safe_mode", False),
            ("zap_exit_code", 1),
            ("passive_queue_complete", False),
            ("requests", []),
            ("report_sha256", "0" * 64),
            ("errors", ["private_payload"]),
            ("history_verified", False),
            ("history_message_count", 3),
            ("history_message_count", "6"),
            ("history_proxied_count", 6),
            ("history_internal_count", 0),
            ("history_request_paths", ["/", "/login", "/health"]),
            ("history_internal_ancestor_paths", ["", "/login", "/unexpected"]),
        ):
            data, _, _, runtime = receipt_fixture("zap")
            data[runtime][key] = value
            with self.subTest(key=key), self.assertRaises(evidence.EvidenceError) as raised:
                self.load(data=data)
            self.assertNotIn("private_payload", str(raised.exception))

    def test_zap_report_is_strictly_parsed_and_control_claims_reconciled(self):
        for uri in (evidence.ORIGIN + "/health/", "https://external.invalid/"):
            data, _, _, runtime = receipt_fixture("zap")
            path = runtime.parent / "zap-report.json"
            report = json.loads(data[path])
            report["site"][0]["alerts"][0]["instances"][0]["uri"] = uri
            data[path] = json.dumps(report).encode()
            data[runtime]["report_sha256"] = evidence.digest(data[path])
            with self.subTest(uri=uri), self.assertRaises(evidence.EvidenceError):
                self.load(data=data)

    def test_zap_running_container_sample_can_precede_driver_initialization(self):
        for started in (
            "2026-09-24T10:00:10+00:00",
            "2026-09-24T10:01:00.129519+00:00",
        ):
            data, _, _, runtime = receipt_fixture("zap")
            data[runtime]["started_at"] = started
            with self.subTest(started=started):
                self.assertEqual(self.load(data=data)["status"], "passed")

    def test_zap_driver_must_remain_inside_outer_gates_and_overlap_running_sample(self):
        for started, finished in (
            ("2026-09-24T09:59:59+00:00", "2026-09-24T10:01:30+00:00"),
            ("2026-09-24T10:00:10+00:00", "2026-09-24T10:02:01+00:00"),
            ("2026-09-24T10:00:10+00:00", "2026-09-24T10:00:59+00:00"),
            ("2026-09-24T10:01:30+00:00", "2026-09-24T10:01:30+00:00"),
            ("2026-09-24T10:01:31+00:00", "2026-09-24T10:01:30+00:00"),
        ):
            data, _, _, runtime = receipt_fixture("zap")
            data[runtime].update(started_at=started, finished_at=finished)
            with (
                self.subTest(started=started, finished=finished),
                self.assertRaisesRegex(evidence.EvidenceError, "soc_zap_execution_interval"),
            ):
                self.load(data=data)
        data, _, _, runtime = receipt_fixture("zap")
        data[runtime]["finished_at"] = "2026-09-24T10:04:11+00:00"
        data[runtime.parent.parent / "zap-exited.json"]["checked_at"] = "2026-09-24T10:05:00+00:00"
        with self.assertRaisesRegex(evidence.EvidenceError, "soc_zap_execution_interval"):
            self.load(data=data)

    def test_ambiguous_json_and_mid_import_file_change_fail(self):
        data, _, _, runtime = receipt_fixture("zap")
        data[runtime] = b'{"status":"failed","status":"passed"}'
        with self.assertRaises(evidence.EvidenceError):
            self.load(data=data)
        data, _, _, _ = receipt_fixture("zap")
        counts = {}

        def read(_root, path):
            counts[path] = counts.get(path, 0) + 1
            value = data[path]
            raw = value if isinstance(value, bytes) else json.dumps(value).encode()
            return raw + b" " if counts[path] > 1 else raw

        with self.assertRaisesRegex(evidence.EvidenceError, "soc_evidence_changed_during_import"):
            self.load(reader=read)

    def test_private_paths_reject_traversal_reparse_links_and_oversize(self):
        with self.assertRaises(evidence.EvidenceError):
            evidence.read_private(settings.BASE_DIR, Path("../elsewhere"))
        path = settings.BASE_DIR / "var/soc/pilot" / RUN / "zap/pilot-result.json"
        for metadata in (
            SimpleNamespace(st_mode=evidence.stat.S_IFLNK, st_file_attributes=0),
            SimpleNamespace(
                st_mode=evidence.stat.S_IFREG,
                st_file_attributes=evidence.stat.FILE_ATTRIBUTE_REPARSE_POINT,
            ),
            SimpleNamespace(
                st_mode=evidence.stat.S_IFREG, st_file_attributes=0, st_nlink=2, st_size=1
            ),
            SimpleNamespace(
                st_mode=evidence.stat.S_IFREG,
                st_file_attributes=0,
                st_nlink=1,
                st_size=evidence.MAX_BYTES + 1,
            ),
        ):
            with (
                patch.object(Path, "resolve", autospec=True, side_effect=lambda obj: obj),
                patch.object(Path, "lstat", return_value=metadata),
            ):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.read_private(settings.BASE_DIR, path.relative_to(settings.BASE_DIR))

    def test_bad_uuid_or_tool_never_reads_files_or_inspects_docker(self):
        with (
            patch.object(evidence, "read_private") as reader,
            patch.object(evidence.gate, "run_verification") as verifier,
        ):
            for tool, run in (
                ("external", RUN),
                ("zap", "../escape"),
                ("zap", RUN.upper()),
                ("zap", "00000000-0000-0000-0000-000000000000"),
            ):
                with self.assertRaises(evidence.EvidenceError):
                    evidence.load_soc_pilot(settings.BASE_DIR, tool, run)
            reader.assert_not_called()
            verifier.assert_not_called()


class SocPilotImportCommandTests(TestCase):
    def setUp(self):
        self.app = Integration.objects.create(slug="signalbridge", name="SignalBridge")
        self.other = Integration.objects.create(slug="bettail", name="BetTail")
        self.checked = SocPilotEvidenceTests().load()
        self.loader = patch(
            "bridge.management.commands.import_soc_pilot.load_soc_pilot", return_value=self.checked
        )
        self.mock_loader = self.loader.start()
        self.addCleanup(self.loader.stop)

    def run_import(self, **kwargs):
        call_command("import_soc_pilot", tool="zap", run_id=RUN, stdout=io.StringIO(), **kwargs)

    def test_self_assurance_scoped_idempotent_and_audited_without_scan_provenance(self):
        self.run_import()
        self.run_import()
        run = CheckRun.objects.get()
        self.assertEqual(run.integration, self.app)
        self.assertFalse(CheckRun.objects.filter(integration=self.other).exists())
        self.assertEqual(Audit.objects.filter(action="soc_pilot.imported").count(), 1)
        self.assertFalse(ScanRun.objects.exists())

    def test_dry_run_and_nonlocal_refusal_do_not_mutate_database(self):
        self.run_import(dry_run=True)
        self.assertFalse(CheckRun.objects.exists())
        self.assertFalse(Audit.objects.exists())
        self.mock_loader.reset_mock()
        with override_settings(LOCAL=False), self.assertRaises(CommandError):
            self.run_import()
        self.mock_loader.assert_not_called()

    def test_conflict_keeps_original_history_and_missing_self_workspace_fails(self):
        self.run_import()
        old = CheckRun.objects.get().digest
        self.checked["digest"] = "0" * 64
        with self.assertRaises(CommandError):
            self.run_import()
        self.assertEqual(CheckRun.objects.get().digest, old)
        self.assertEqual(Audit.objects.count(), 1)

    def test_rejected_or_missing_evidence_never_creates_partial_record(self):
        self.mock_loader.side_effect = evidence.EvidenceError("soc_gate_not_passed")
        with self.assertRaises(CommandError):
            self.run_import()
        self.assertFalse(CheckRun.objects.exists())
        self.assertFalse(Audit.objects.exists())

    def test_missing_self_workspace_never_creates_one_implicitly(self):
        self.app.delete()
        with self.assertRaises(CommandError):
            self.run_import()
        self.assertFalse(CheckRun.objects.exists())
        self.assertFalse(Audit.objects.exists())
