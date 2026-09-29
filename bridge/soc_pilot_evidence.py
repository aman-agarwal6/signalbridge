"""Consistency-check fixed synthetic pilot receipts; never launch a scanner.

The local builder and Docker administrator remain trusted. A fresh metadata gate
checks stopped containers at import time; retained receipts are not independent
or tamper-proof attestations and do not prove continuous isolation.
"""

import hashlib
import json
import math
import os
import re
import stat
from datetime import timedelta
from pathlib import Path

from bridge.assurance import EvidenceError, require, sha, timestamp
from bridge.scanner_reports import ReportError, _load
from bridge.zap_report import parse_zap_report
from integrations.wazuh import run_context
from integrations.zap.contract import BODY_HASHES, ORIGIN, PATHS, PROFILE
from scripts import verify_soc_pilot as gate

MAX_BYTES = 2 * 1024 * 1024
LIMITATIONS = [
    "Builder-operated synthetic local pilot; not an independent or tamper-proof audit.",
    "Receipts are consistency-checked; a trusted local administrator can replace evidence.",
    "Container metadata was sampled before, during, after and again at import; not continuous monitoring.",
    "No SignalBridge, BetTail, Netted or production application security assessment was performed.",
    "A stopped one-time pilot does not establish an ongoing connection or enterprise parity.",
    "Only complete passing bundles are imported; failed raw attempts remain outside this imported history.",
    "Scanner reports remain claimed reports with unknown coverage, even when this separate pilot passes.",
]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def closed(value, keys, code):
    require(isinstance(value, dict) and set(value) == set(keys), code)
    return value


def integer(value, expected):
    return type(value) is int and value == expected


def read_private(root, relative):
    """Fixed callers only; reject symlinks, junctions, hardlinks and path escape."""
    root = Path(os.path.abspath(root))
    relative = Path(relative)
    require(not relative.is_absolute() and ".." not in relative.parts, "soc_evidence_path")
    path = root / relative
    require(root.resolve() == root and path.resolve() == path, "soc_linked_evidence_path")
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        require(
            not stat.S_ISLNK(info.st_mode)
            and not (getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT),
            "soc_linked_evidence_path",
        )
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_BYTES,
        "soc_evidence_file_bound",
    )
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        require(
            (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino) and opened.st_nlink == 1,
            "soc_evidence_file_changed",
        )
        raw = handle.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "soc_evidence_file_bound")
    return raw


def validate_gate(record, tool, run_id, state):
    closed(
        record,
        {
            "schema_version",
            "profile",
            "run_id",
            "checked_at",
            "expected_state",
            "status",
            "errors",
            "limitations",
            "source_sha256",
            "containers",
            "networks",
        },
        "soc_gate_shape",
    )
    require(
        integer(record["schema_version"], 1)
        and record["profile"] == "soc-pilot-" + tool
        and record["run_id"] == run_id
        and record["expected_state"] == state
        and record["status"] == "passed"
        and record["errors"] == []
        and sha(record["source_sha256"]),
        "soc_gate_not_passed",
    )
    require(
        isinstance(record["limitations"], list)
        and len(record["limitations"]) <= 20
        and all(isinstance(item, str) and len(item) <= 1024 for item in record["limitations"]),
        "soc_gate_limitations_shape",
    )
    containers = record["containers"]
    names = gate.NAMES[tool]
    require(isinstance(containers, list) and len(containers) == len(names), "soc_gate_inventory")
    identities = {}
    for row in containers:
        closed(row, {"name", "id", "image_id", "image_reference", "state"}, "soc_gate_container")
        name = row["name"]
        require(
            isinstance(name, str)
            and name in names
            and name not in identities
            and sha(row["id"])
            and isinstance(row["image_id"], str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", row["image_id"])
            and row["image_reference"] == gate.IMAGES[name]
            and row["state"] == state,
            "soc_gate_container_identity",
        )
        identities[name] = {key: row[key] for key in ("name", "id", "image_id", "image_reference")}
    require(
        len({row["id"] for row in identities.values()}) == len(names), "soc_duplicate_container"
    )
    networks = record["networks"]
    require(isinstance(networks, list), "soc_gate_networks")
    if tool == "wazuh":
        require(networks == [], "soc_gate_networks")
    else:
        require(len(networks) == 1, "soc_gate_networks")
        closed(networks[0], {"name", "id", "internal"}, "soc_gate_networks")
        require(
            networks[0]["name"] == gate.NETWORK
            and sha(networks[0]["id"])
            and networks[0]["internal"] is True,
            "soc_gate_networks",
        )
    return timestamp(record["checked_at"]), identities


def wazuh_result(report, source, expectations, event_lines, *, run_id=None):
    bound = type(report) is dict and integer(report.get("schema_version"), 2)
    closed(
        report,
        {
            "schema_version",
            "tool",
            "status",
            "scope",
            "synthetic_only",
            "logtest_verified",
            "collection_verified",
            "expected_logtest_case_count",
            "logtest_cases",
            "collector",
            "owned_processes_stopped",
            "failure_code",
            "source_sha256",
            "runtime_version",
            "duration_seconds",
            "passed_logtest_case_count",
            *(
                {"run_id", "context_sha256", "started_at", "finished_at", "alerts_sha256"}
                if bound
                else set()
            ),
        },
        "soc_wazuh_result_shape",
    )
    require(
        (integer(report["schema_version"], 1) or bound)
        and report["tool"] == "wazuh"
        and report["status"] == "passed"
        and report["scope"] == "isolated_synthetic_manager_pilot"
        and report["synthetic_only"] is True
        and report["logtest_verified"] is True
        and report["collection_verified"] is True
        and report["owned_processes_stopped"] is True
        and report["failure_code"] is None
        and report["runtime_version"] == "4.14.8"
        and integer(report["expected_logtest_case_count"], 27)
        and integer(report["passed_logtest_case_count"], 27),
        "soc_wazuh_not_complete",
    )
    duration = report["duration_seconds"]
    require(
        type(duration) in (int, float) and math.isfinite(duration) and 0 < duration <= 180,
        "soc_wazuh_duration",
    )
    required_sources = {
        "run_pilot.py",
        "verify_static.py",
        "event-contract.json",
        "manager-lab.conf",
        "signalbridge_rules.xml",
        "image-lock.json",
        "fixtures/events.jsonl",
        "fixtures/expectations.json",
    }
    if bound:
        required_sources.add("run_context.py")
        require(report["run_id"] == run_id, "soc_wazuh_run_mismatch")
    else:
        require("run_context.py" not in source["package"], "soc_wazuh_version_downgrade")
    require(
        report["source_sha256"] == {name: source["package"][name] for name in required_sources},
        "soc_wazuh_source_mismatch",
    )
    cases = expectations["cases"]
    rows = report["logtest_cases"]
    require(
        isinstance(cases, list) and isinstance(rows, list) and len(cases) == len(rows) == 27,
        "soc_wazuh_case_count",
    )
    custom = {str(value) for value in range(100200, 100206)}
    for expected, row in zip(cases, rows, strict=True):
        closed(
            row,
            {
                "id",
                "status",
                "expected_rule",
                "expected_level",
                "observed_rule",
                "observed_level",
                "decoder",
            },
            "soc_wazuh_case_shape",
        )
        require(
            row["id"] == expected["id"]
            and row["status"] == "passed"
            and row["expected_rule"] == expected["expected_rule"]
            and row["expected_level"] == expected["expected_level"]
            and row["decoder"] == "json",
            "soc_wazuh_case_mismatch",
        )
        rule, level = row["observed_rule"], row["observed_level"]
        require(
            (rule is None and level is None)
            or (
                isinstance(rule, str)
                and re.fullmatch(r"[0-9]{1,7}", rule)
                and type(level) is int
                and 0 <= level <= 15
            ),
            "soc_wazuh_observed_shape",
        )
        require(
            (expected["expected_rule"] is None and rule not in custom)
            or (
                expected["expected_rule"] is not None
                and (rule, level) == (expected["expected_rule"], expected["expected_level"])
            ),
            "soc_wazuh_observation_mismatch",
        )
    collector = report["collector"]
    counts = {
        "input_count": 19,
        "fixture_input_count": 18,
        "tail_sentinel_count": 1,
        "expected_alert_count": 12,
        "negative_control_count": 7,
        "quiet_window_seconds": 3,
        "observed_alert_count": 12,
        "duplicate_count": 0,
        "unexpected_custom_alert_count": 0,
        "observed_event_count": 19,
        "observed_drop_count": 0,
        "state_interval_seconds": 1,
    }
    closed(
        collector,
        {
            *counts,
            "verified",
            "batch_sha256",
            "collector_counts_verified",
            "observed_processed_bytes",
            "expected_processed_bytes",
        },
        "soc_collector_shape",
    )
    require(
        collector["verified"] is True
        and collector["collector_counts_verified"] is True
        and all(integer(collector[key], value) for key, value in counts.items()),
        "soc_collector_incomplete",
    )
    lines = event_lines.decode("utf8").splitlines()
    require(len(lines) == 27, "soc_wazuh_fixture_inventory")
    records = [
        _load(line.encode())
        for line, case in zip(lines, cases, strict=True)
        if case["export_contract_valid"]
    ]
    sentinel = _load(lines[2].encode())
    sentinel["signalbridge"]["event_id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
    records.append(sentinel)
    if bound:
        for record in records:
            event = record["signalbridge"]
            event["event_id"] = run_context.event_id(run_id, event["event_id"])
    batch = [json.dumps(record, separators=(",", ":"), ensure_ascii=False) for record in records]
    require(
        len(batch) == 19
        and collector["batch_sha256"] == digest(("\n".join(batch) + "\n").encode()),
        "soc_wazuh_collection_digest",
    )
    expected_bytes = sum(len(line.encode("utf8")) + 1 for line in batch)
    require(
        integer(collector["expected_processed_bytes"], expected_bytes)
        and integer(collector["observed_processed_bytes"], expected_bytes),
        "soc_wazuh_processed_bytes",
    )
    return "4.14.8", {
        "logtest_cases": 27,
        "collection_inputs": 19,
        "fixture_inputs": 18,
        "tail_sentinels": 1,
        "alerts": 12,
        "negative_controls": 7,
    }


def wazuh_binding(
    report, context_raw, alerts_raw, run_id, source_hash, times, expectations, events
):
    """Reconcile run identity, bounded timing and every retained custom alert."""
    context = run_context.parse(context_raw)
    require(context["run_id"] == run_id and report["run_id"] == run_id, "soc_wazuh_run_mismatch")
    require(context["source_sha256"] == source_hash, "soc_wazuh_context_source")
    require(digest(context_raw) == report["context_sha256"], "soc_wazuh_context_digest")
    prepared, start, end = (
        timestamp(value)
        for value in (context["prepared_at"], report["started_at"], report["finished_at"])
    )
    elapsed = (end - start).total_seconds()
    require(
        prepared <= times[0] <= start < end <= times[2]
        and times[1] <= end
        # Docker may be running just before its Python entrypoint initializes.
        and start <= times[1] + timedelta(seconds=5)
        and 0 <= (start - prepared).total_seconds() <= 900
        and 0 < elapsed <= 180
        and abs(elapsed - report["duration_seconds"]) <= 2,
        "soc_wazuh_runtime_window",
    )
    require(
        0 < len(alerts_raw) <= 1024 * 1024
        and alerts_raw.endswith(b"\n")
        and digest(alerts_raw) == report["alerts_sha256"],
        "soc_wazuh_alert_digest",
    )
    expected = {}
    lines = events.decode().splitlines()
    cases = expectations["cases"]
    for line, case in zip(lines, cases, strict=True):
        if case["export_contract_valid"] and case["expected_alert"]:
            event = _load(line.encode())["signalbridge"]
            event["event_id"] = run_context.event_id(run_id, event["event_id"])
            expected[event["event_id"]] = (event, case["expected_rule"], case["expected_level"])
    sentinel = _load(lines[2].encode())["signalbridge"]
    sentinel["event_id"] = run_context.event_id(run_id, "ffffffff-ffff-4fff-8fff-ffffffffffff")
    expected[sentinel["event_id"]] = (sentinel, "100202", 5)
    observed = {}
    for line in alerts_raw.splitlines():
        row = _load(line)
        require(type(row) is dict and type(row.get("rule")) is dict, "soc_wazuh_alert_shape")
        rule = row["rule"]
        if str(rule.get("id")) not in {str(n) for n in range(100200, 100206)}:
            continue
        require(
            "full_log" not in row
            and row.get("location") == "/signalbridge/input/events.jsonl"
            and row.get("decoder", {}).get("name") == "json",
            "soc_wazuh_alert_origin",
        )
        event = row["data"]["signalbridge"]
        require(type(event) is dict, "soc_wazuh_alert_event")
        identity = event.get("event_id")
        require(
            isinstance(identity, str) and identity in expected and identity not in observed,
            "soc_wazuh_alert_identity",
        )
        target, rule_id, level = expected[identity]
        # Wazuh may render a decoded JSON number as text. No other type coercion.
        normalized = dict(event)
        if normalized.get("export_version") == "1":
            normalized["export_version"] = 1
        require(
            type(normalized.get("export_version")) is int
            and normalized == target
            and str(rule.get("id")) == rule_id
            and integer(rule.get("level"), level),
            "soc_wazuh_alert_mismatch",
        )
        # This isolated profile uses UTC; naive or foreign-offset times fail.
        alert_time = run_context.utc_time(row["timestamp"])
        require(start <= alert_time <= end, "soc_wazuh_alert_time")
        observed[identity] = {
            "event_id": identity,
            "rule_id": rule_id,
            "level": level,
            "app": target["app"],
            "source": target["source"],
            "outcome": target["outcome"],
            "reason": target["reason"],
        }
    require(set(observed) == set(expected) and len(observed) == 12, "soc_wazuh_alert_incomplete")
    return {
        "version": 2,
        "run_id": run_id,
        "started_at": report["started_at"],
        "finished_at": report["finished_at"],
        "context_sha256": digest(context_raw),
        "alerts_sha256": digest(alerts_raw),
        "observations": [observed[key] for key in sorted(observed)],
    }


def zap_result(report, raw, times):
    closed(
        report,
        {
            "schema_version",
            "kind",
            "target_kind",
            "profile",
            "status",
            "started_at",
            "errors",
            "limits",
            "zap_version",
            "controls",
            "report_sha256",
            "passive_queue_complete",
            "request_count",
            "redirects_followed",
            "safe_mode",
            "requests",
            "zap_exit_code",
            "finished_at",
            "history_verified",
            "history_message_count",
            "history_proxied_count",
            "history_internal_count",
            "history_request_paths",
            "history_internal_ancestor_paths",
        },
        "soc_zap_result_shape",
    )
    require(
        integer(report["schema_version"], 1)
        and report["kind"] == "signalbridge-zap-synthetic-pilot"
        and report["target_kind"] == "synthetic-fixture-not-signalbridge-application"
        and report["profile"] == PROFILE
        and report["status"] == "passed"
        and report["errors"] == []
        and report["passive_queue_complete"] is True
        and integer(report["request_count"], 3)
        and report["redirects_followed"] is False
        and report["safe_mode"] is True
        and report["history_verified"] is True
        and integer(report["history_message_count"], 6)
        and integer(report["history_proxied_count"], 3)
        and integer(report["history_internal_count"], 3)
        and report["history_request_paths"] == list(PATHS)
        and report["history_internal_ancestor_paths"] == [path.rstrip("/") for path in PATHS]
        and report["zap_version"] == "2.17.0"
        and integer(report["zap_exit_code"], 0),
        "soc_zap_not_complete",
    )
    require(
        isinstance(report["limits"], list)
        and len(report["limits"]) <= 20
        and all(isinstance(value, str) and len(value) <= 1024 for value in report["limits"]),
        "soc_zap_limitations_shape",
    )
    started, finished = timestamp(report["started_at"]), timestamp(report["finished_at"])
    # Gate timestamps mark the start of container-metadata inspection. Docker
    # can already report running before Python initializes and records started_at.
    # Bound the driver within the outer gates; do not infer its initialization
    # order from the running-container sample.
    require(
        times[0] <= started < finished <= times[2]
        and times[1] <= finished
        and finished - started <= timedelta(seconds=240),
        "soc_zap_execution_interval",
    )
    require(
        report["requests"]
        == [
            {
                "method": "GET",
                "path": path,
                "status": "passed",
                "http_status": 200,
                "body_sha256": BODY_HASHES[path],
            }
            for path in PATHS
        ],
        "soc_zap_request_inventory",
    )
    require(
        report["controls"]
        == {
            "rule_id": "10021",
            "positive_paths": ["/", "/login/"],
            "negative_path": "/health/",
            "status": "passed",
        },
        "soc_zap_control_claim",
    )
    require(report["report_sha256"] == digest(raw), "soc_zap_report_digest")
    parsed = parse_zap_report(raw)
    require(report["zap_version"] == parsed.version, "soc_zap_version_mismatch")
    observed = set()
    data = _load(raw)
    for alert in data["site"][0]["alerts"]:
        if alert["pluginid"] == "10021":
            observed.update(row["uri"] for row in alert["instances"])
    require(observed == {ORIGIN + "/", ORIGIN + "/login/"}, "soc_zap_control_observation")
    return parsed.version, {
        "requests": 3,
        "header_positive_paths": 2,
        "header_negative_paths": 1,
        "reported_findings": len(parsed.findings),
    }


def load_soc_pilot(root, tool, run_id):
    """Read fixed private paths and invoke only the fixed read-only Docker verifier."""
    try:
        gate.validate_request(tool, run_id, "exited")
        root = Path(os.path.abspath(root))
        require(root == gate.ROOT.resolve(), "soc_workspace_mismatch")
        directory = Path("var/soc/pilot") / run_id
        retained = {}
        hashes = {}

        def read(key, path):
            raw = read_private(root, path)
            retained[path] = digest(raw)
            hashes[key] = digest(raw)
            return raw

        receipts = {
            state: _load(read(state, directory / f"{tool}-{state}.json"))
            for state in ("created", "running", "exited")
        }
        validated = [
            validate_gate(receipts[state], tool, run_id, state)
            for state in ("created", "running", "exited")
        ]
        times = [value[0] for value in validated]
        require(
            times[0] <= times[1] <= times[2] and times[2] - times[0] <= timedelta(hours=1),
            "soc_gate_chronology",
        )
        identities = validated[0][1]
        require(all(value[1] == identities for value in validated), "soc_container_changed")
        before = receipts["created"]
        require(
            all(
                value["source_sha256"] == before["source_sha256"]
                and value["networks"] == before["networks"]
                for value in receipts.values()
            ),
            "soc_gate_source_or_network_changed",
        )
        source = gate.source_hashes(tool, run_id)
        require(
            gate.base.sha256(gate.base.canonical(source)) == before["source_sha256"],
            "soc_source_no_longer_matches",
        )
        report_name = "result.json" if tool == "wazuh" else "pilot-result.json"
        report = _load(read("runtime", directory / tool / report_name))
        binding = None
        if tool == "wazuh":
            expectations = _load(
                read_private(root, Path("integrations/wazuh/fixtures/expectations.json"))
            )
            events = read_private(root, Path("integrations/wazuh/fixtures/events.jsonl"))
            version, counts = wazuh_result(report, source, expectations, events, run_id=run_id)
            if report["schema_version"] == 2:
                binding = wazuh_binding(
                    report,
                    read("run_context", directory / tool / "run-context.json"),
                    read("alerts", directory / tool / "alerts.jsonl"),
                    run_id,
                    before["source_sha256"],
                    times,
                    expectations,
                    events,
                )
        else:
            raw = read("zap_report", directory / tool / "zap-report.json")
            version, counts = zap_result(report, raw, times)
        for path, expected in retained.items():
            require(
                digest(read_private(root, path)) == expected, "soc_evidence_changed_during_import"
            )
        # This may inspect Docker, but never executes a container command or starts
        # a service. The caller cannot supply a verifier, target or Docker endpoint.
        fresh = gate.run_verification(tool, run_id, state="exited")
        fresh_time, fresh_identity = validate_gate(fresh, tool, run_id, "exited")
        require(
            fresh_time >= times[2]
            and fresh_identity == identities
            and fresh["source_sha256"] == before["source_sha256"]
            and fresh["networks"] == before["networks"],
            "soc_fresh_stopped_gate_mismatch",
        )
        result = {
            "evidence_kind": "soc_pilot",
            "tool": tool,
            "app": "signalbridge",
            "status": "passed",
            "checks": [
                {"id": "fixed_synthetic_controls", "status": "passed"},
                {"id": "matching_created_running_exited_gates", "status": "passed"},
                {"id": "fresh_stopped_metadata_gate", "status": "passed"},
            ],
            "limitations": LIMITATIONS,
            "pilot": {
                "run_id": run_id,
                "recorded_at": receipts["exited"]["checked_at"],
                "runtime_version": version,
                "scope": "synthetic_fixture",
                "source_app_assessed": False,
                "continuous_connection": False,
                "stopped_at_end": True,
                "counts": counts,
                "provenance": {
                    "verification": "builder_local_receipt_consistency_and_fresh_stopped_gate",
                    "source_sha256": before["source_sha256"],
                    "receipt_sha256": hashes,
                    "containers": [identities[name] for name in sorted(identities)],
                    "fresh_stopped_gate_required": True,
                },
            },
        }
        if binding is not None:
            result["pilot"]["run_binding"] = binding
        return {
            "digest": digest(canonical(result)),
            "revision": before["source_sha256"],
            "status": "passed",
            "result": result,
            "fresh_checked_at": fresh["checked_at"],
        }
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        IndexError,
        ReportError,
        gate.VerificationError,
    ) as error:
        if isinstance(error, EvidenceError):
            raise
        raise EvidenceError("soc_evidence_unavailable_or_invalid") from None
