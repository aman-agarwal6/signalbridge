"""Local operator import of bounded ZAP runs, including a verified failed scan.

No scan launch, target override or report upload. Retained bytes and freshly
sampled stopped metadata remain builder-operated evidence, not attestation.
"""

import math
from datetime import datetime, timezone
from pathlib import Path

from bridge.assurance import EvidenceError, require, sha, timestamp
from bridge.scanner_reports import ReportError, _load
from bridge.soc_pilot_evidence import canonical, closed, digest, integer, read_private
from scripts import run_zap_pilot as runner
from scripts import verify_soc_pilot as gate
from scripts.record_verification import json_bytes

KIND = "zap_repeat"
MODES = ("normal", "unavailable-target")
DEPENDENCIES = (
    "scripts/run_zap_pilot.py",
    "scripts/verify_soc_pilot.py",
    "scripts/verify_supabase_isolation.py",
    "bridge/soc_pilot_evidence.py",
    "bridge/zap_report.py",
    "bridge/scanner_reports.py",
    "bridge/assurance.py",
)


def identity(topology):
    return {
        "containers": [
            {key: row[key] for key in ("Id", "Image", "ConfiguredImage", "Name")}
            for row in topology["containers"]
        ],
        "network": topology["networks"][0]["Id"],
    }


def validate_result(result):
    """Closed, display-safe persisted contract; does not contact files or Docker."""
    closed(
        result,
        {
            "evidence_kind",
            "schema_version",
            "app",
            "tool",
            "run_id",
            "mode",
            "status",
            "exercise_verified",
            "coverage",
            "runtime_version",
            "started_at",
            "finished_at",
            "recorded_at",
            "duration_seconds",
            "target_accepted",
            "counts",
            "failure_code",
            "source_app_assessed",
            "continuous_connection",
            "stopped_at_end",
            "provenance",
        },
        "zap_receipt_shape",
    )
    gate.validate_request("zap-repeat", result["run_id"], "exited")
    mode = result["mode"]
    require(
        result["evidence_kind"] == KIND
        and integer(result["schema_version"], 1)
        and result["app"] == "signalbridge"
        and result["tool"] == "zap"
        and mode in MODES
        and result["exercise_verified"] is True
        and result["runtime_version"] == "2.17.0"
        and result["source_app_assessed"] is False
        and result["continuous_connection"] is False
        and result["stopped_at_end"] is True,
        "zap_receipt_scope",
    )
    start, end, recorded = map(
        timestamp,
        (
            result["started_at"],
            result["finished_at"],
            result["recorded_at"],
        ),
    )
    duration = result["duration_seconds"]
    require(
        start < end <= recorded
        and 0 < (end - start).total_seconds() <= 240
        and type(duration) in (int, float)
        and math.isfinite(duration)
        and 0 < duration <= 240,
        "zap_receipt_time",
    )
    if mode == "unavailable-target":
        require(
            result["status"] == "failed"
            and result["coverage"] == "incomplete"
            and result["counts"] is None
            and integer(result["target_accepted"], 0)
            and result["failure_code"] == "target_unavailable",
            "zap_failed_scan_contract",
        )
    else:
        counts = result["counts"]
        closed(
            counts,
            {"requests", "header_positive_paths", "header_negative_paths", "reported_findings"},
            "zap_counts_shape",
        )
        require(
            result["status"] == "passed"
            and result["coverage"] == "fixed-fixture-only"
            and result["failure_code"] is None
            and integer(result["target_accepted"], 3)
            and integer(counts["requests"], 3)
            and integer(counts["header_positive_paths"], 2)
            and integer(counts["header_negative_paths"], 1)
            and type(counts["reported_findings"]) is int
            and 2 <= counts["reported_findings"] <= 5000,
            "zap_complete_scan_contract",
        )
    proof = result["provenance"]
    closed(
        proof,
        {
            "execution_sha256",
            "package_sha256",
            "container_ids",
            "network_id",
            "receipt_sha256",
            "fresh_stopped_gate_required",
        },
        "zap_proof_shape",
    )
    require(
        sha(proof["execution_sha256"])
        and sha(proof["package_sha256"])
        and sha(proof["network_id"])
        and type(proof["container_ids"]) is list
        and len(proof["container_ids"]) == 2
        and all(sha(v) for v in proof["container_ids"])
        and len(set(proof["container_ids"])) == 2
        and proof["fresh_stopped_gate_required"] is True,
        "zap_proof_identity",
    )
    hashes = proof["receipt_sha256"]
    expected = {
        "execution-source.json",
        "source-manifest.json",
        "plan.json",
        "host-result.json",
        "created-gate.json",
        "running-gate.json",
        "exited-gate.json",
        "route-samples.json",
        "target.log",
        "zap/pilot-result.json",
    }
    expected |= {"source/" + name for name in runner.FILES}
    expected.add(
        "target-unavailable.json" if mode == "unavailable-target" else "zap/zap-report.json"
    )
    require(
        type(hashes) is dict and set(hashes) == expected and all(sha(v) for v in hashes.values()),
        "zap_receipt_hashes",
    )


def load_zap_repeat(root, run_id):
    """Reconcile fixed run bytes; fresh stopped inspection is read-only and required."""
    try:
        gate.validate_request("zap-repeat", run_id, "exited")
        directory = Path("var/soc/pilot") / run_id
        retained = {}

        def read(path):
            raw = read_private(root, path)
            retained[path] = digest(raw)
            return raw

        def value(path):
            return _load(read(path))

        execution = value(directory / "execution-source.json")
        closed(execution, {"files", "sha256", "file_count"}, "zap_execution_shape")
        inventory = execution["files"]
        require(
            type(inventory) is dict
            and 0 < len(inventory) <= 2000
            and all(type(k) is str and len(k) <= 300 and sha(v) for k, v in inventory.items())
            and integer(execution["file_count"], len(inventory))
            and execution["sha256"] == digest(json_bytes(inventory)),
            "zap_execution_digest",
        )
        files = value(directory / "source-manifest.json")
        closed(files, runner.FILES, "zap_package_shape")
        require(all(sha(v) for v in files.values()), "zap_package_hash")
        for name in sorted(runner.FILES):
            original = Path("integrations/zap") / name
            raw = read(directory / "source" / name)
            require(digest(raw) == files[name] and raw == read(original), "zap_source_changed")
            if original.suffix != ".md":
                require(files[name] == inventory[original.as_posix()], "zap_executed_source")
        for name in DEPENDENCIES:
            require(digest(read(Path(name))) == inventory[name], "zap_validator_changed")
        package_hash = digest(gate.base.canonical(files))
        plan = value(directory / "plan.json")
        closed(plan, {"run_id", "mode", "names", "network", "limits", "prepared_at"}, "zap_plan")
        names = gate.profile_names("zap-repeat", run_id)
        require(
            plan["run_id"] == run_id
            and plan["mode"] in MODES
            and plan["names"] == list(names)
            and plan["limits"] == runner.LIMITS
            and plan["network"] == gate.network_name("zap-repeat", run_id),
            "zap_plan_scope",
        )
        unavailable = plan["mode"] == "unavailable-target"
        records, times, identities = [], [], []
        for state in gate.STATES:
            record = value(directory / (state + "-gate.json"))
            closed(record, {"checked_at", "errors", "topology"}, "zap_gate_shape")
            require(
                record["errors"] == []
                and not gate.verify_topology(record["topology"], "zap-repeat", run_id, state=state),
                "zap_isolation",
            )
            records.append(record)
            times.append(timestamp(record["checked_at"]))
            identities.append(identity(record["topology"]))
        require(
            identities[0] == identities[1] == identities[2]
            and timestamp(plan["prepared_at"]) <= times[0] < times[1] < times[2]
            and (times[2] - times[0]).total_seconds() <= 240,
            "zap_gate_binding",
        )
        # The shared strict decoder accepts objects; wrap the fixed array field
        # so duplicate keys and nonfinite values still use its rejection rules.
        wrapped_routes = _load(b'{"routes":' + read(directory / "route-samples.json") + b"}")
        closed(wrapped_routes, {"routes"}, "zap_route_document")
        routes = wrapped_routes["routes"]
        require(
            canonical(routes) == canonical([{"default_ipv4": 0, "default_ipv6": 0}] * 2),
            "zap_route_sample",
        )
        host = value(directory / "host-result.json")
        closed(
            host,
            {
                "schema_version",
                "kind",
                "run_id",
                "mode",
                "failure",
                "observation",
                "containers",
                "source_sha256",
                "package_sha256",
                "duration_seconds",
                "finished_at",
                "limits",
            },
            "zap_host_shape",
        )
        closed(host["containers"], names, "zap_host_containers")
        states = [host["containers"][name]["state"] for name in names]
        for state in states:
            closed(state, {"status", "exit_code", "oom"}, "zap_exit_state")
        containers = {
            name: {"id": row["Id"], "state": state}
            for name, row, state in zip(names, identities[0]["containers"], states, strict=True)
        }
        require(
            integer(host["schema_version"], 1)
            and host["kind"] == "signalbridge-zap-repeat"
            and host["run_id"] == run_id
            and host["mode"] == plan["mode"]
            and host["failure"] is None
            and host["limits"] == runner.LIMITS
            and host["source_sha256"] == execution["sha256"]
            and host["package_sha256"] == package_hash
            and canonical(host["containers"]) == canonical(containers)
            and all(type(s["exit_code"]) is int for s in states)
            and times[2] <= timestamp(host["finished_at"]),
            "zap_host_binding",
        )
        report = value(directory / "zap/pilot-result.json")
        raw = None
        if unavailable:
            # Even an unexpected unreadable/linked report is a conflict, not absence.
            try:
                (Path(root) / directory / "zap/zap-report.json").lstat()
            except FileNotFoundError:
                pass
            else:
                raise EvidenceError("zap_failure_has_report")
            fault = value(directory / "target-unavailable.json")
            closed(fault, {"target_id", "observed_at", "state"}, "zap_fault_shape")
            require(
                fault["target_id"] == identities[0]["containers"][1]["Id"]
                and canonical(fault["state"]) == canonical(states[1])
                and times[1] <= timestamp(fault["observed_at"]) < timestamp(report["finished_at"]),
                "zap_fault_binding",
            )
            require(
                integer(report["schema_version"], 1) and integer(report["zap_exit_code"], 0),
                "zap_failure_types",
            )
        else:
            raw = read(directory / "zap/zap-report.json")
        observed = runner.classify(
            report,
            raw,
            times,
            states,
            read(directory / "target.log").decode(),
            unavailable=unavailable,
        )
        require(canonical(host["observation"]) == canonical(observed), "zap_observation_changed")
        fresh = gate.gather_topology("zap-repeat", run_id)
        require(
            not gate.verify_topology(fresh, "zap-repeat", run_id, state="exited")
            and identity(fresh) == identities[0]
            and canonical([runner.state(row["Id"]) for row in identities[0]["containers"]])
            == canonical(states),
            "zap_fresh_stopped_gate",
        )
        now = datetime.now(timezone.utc)
        require(timestamp(host["finished_at"]) <= now, "zap_future_receipt")
        for path, expected in retained.items():
            require(digest(read_private(root, path)) == expected, "zap_evidence_changed")
        result = {
            "evidence_kind": KIND,
            "schema_version": 1,
            "tool": "zap",
            "app": "signalbridge",
            "run_id": run_id,
            "mode": plan["mode"],
            "status": observed["scan_status"],
            "exercise_verified": True,
            "coverage": "incomplete" if unavailable else "fixed-fixture-only",
            "runtime_version": observed["version"],
            "started_at": report["started_at"],
            "finished_at": report["finished_at"],
            "recorded_at": host["finished_at"],
            "duration_seconds": host["duration_seconds"],
            "target_accepted": observed["target_accepted"],
            "counts": observed["counts"],
            "failure_code": "target_unavailable" if unavailable else None,
            "source_app_assessed": False,
            "continuous_connection": False,
            "stopped_at_end": True,
            "provenance": {
                "execution_sha256": execution["sha256"],
                "package_sha256": package_hash,
                "container_ids": [row["Id"] for row in identities[0]["containers"]],
                "network_id": identities[0]["network"],
                "fresh_stopped_gate_required": True,
                "receipt_sha256": {
                    p.relative_to(directory).as_posix(): h
                    for p, h in retained.items()
                    if p.is_relative_to(directory)
                },
            },
        }
        validate_result(result)
        return {
            "result": result,
            "digest": digest(canonical(result)),
            "revision": execution["sha256"],
            "status": result["status"],
            "fresh_checked_at": now.isoformat(),
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
        runner.PilotError,
    ):
        raise EvidenceError("zap_repeat_evidence_unavailable_or_invalid") from None
