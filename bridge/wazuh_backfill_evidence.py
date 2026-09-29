"""Validate a fixed historical BetTail backfill; never start or execute a container.

The builder, OS user and Docker administrator remain trusted. Hashes and sampled
metadata detect inconsistency; they are not independent execution attestation.
"""

import json
import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bridge.assurance import EvidenceError, require, sha
from bridge.scanner_reports import ReportError, _load
from bridge.soc_pilot_evidence import canonical, closed, digest, integer, read_private
from integrations.wazuh import run_context, run_pilot
from integrations.wazuh_backfill import contract
from scripts import verify_soc_pilot as gate
from scripts.run_wazuh_backfill import SOURCE_FILES

PACKAGE = {
    **{name: "integrations/wazuh/" + name for name in SOURCE_FILES},
    "run_delivery.py": "integrations/wazuh_recovery/run_delivery.py",
    "run_backfill.py": "integrations/wazuh_backfill/run_backfill.py",
    "backfill_contract.py": "integrations/wazuh_backfill/contract.py",
}
LIMITATIONS = [
    "Historical bounded replay of retained BetTail lab metadata; no continuous connection.",
    "No fresh source-app authorization test, host monitoring, indexer or dashboard.",
    "Non-alert records are not necessarily benign; legacy classification remains unknown.",
    "Three-second quiet window; no sustained-throughput, forced-crash or full-manager recovery claim.",
    "Repeated runs replay the same input into a fresh container; not end-to-end exactly-once delivery.",
    "Builder-operated evidence and sampled Docker metadata; trusted administrators can replace both.",
    "Only complete passing bundles are imported; preserved failed attempts are outside this history.",
]


def runtime(report, manifest, source):
    closed(
        report,
        {
            "alerts",
            "alerts_sha256",
            "archived_records",
            "archives_sha256",
            "collection_verified",
            "collector",
            "context_sha256",
            "duplicates",
            "duration_seconds",
            "effective_config_sha256",
            "expected_alert_count",
            "expected_logtest_case_count",
            "failure_code",
            "finished_at",
            "handoff_verified",
            "input_count",
            "input_manifest_sha256",
            "input_sha256",
            "kind",
            "logtest_cases",
            "logtest_verified",
            "nonalert_records",
            "owned_processes_stopped",
            "quiet_seconds",
            "recovery_phases",
            "run_id",
            "runtime_version",
            "schema_version",
            "scope",
            "source_counts",
            "source_sha256",
            "started_at",
            "status",
            "synthetic_only",
            "tool",
            "transport",
        },
        "backfill_runtime_shape",
    )
    require(
        integer(report["schema_version"], 2)
        and report["kind"] == "signalbridge-wazuh-ledger-backfill"
        and report["tool"] == "wazuh"
        and report["runtime_version"] == "4.14.8"
        and report["scope"] == "retained_local_lab_metadata"
        and report["synthetic_only"] is False
        and report["transport"] == "read_only_ledger_snapshot_to_fresh_collector_spool"
        and report["status"] == "passed"
        and report["failure_code"] is None
        and all(
            report[key] is True
            for key in (
                "collection_verified",
                "handoff_verified",
                "logtest_verified",
                "owned_processes_stopped",
            )
        )
        and report["collector"] == {"verified": False}
        and report["recovery_phases"] == [],
        "backfill_runtime_incomplete",
    )
    counts = {
        "input_count": len(manifest["packets"]),
        "archived_records": len(manifest["packets"]),
        "expected_alert_count": len(manifest["expected_alerts"]),
        "alerts": len(manifest["expected_alerts"]),
        "nonalert_records": len(manifest["packets"]) - len(manifest["expected_alerts"]),
        "duplicates": 0,
        "quiet_seconds": 3,
        "expected_logtest_case_count": 27,
    }
    require(all(integer(report[k], v) for k, v in counts.items()), "backfill_runtime_counts")
    require(
        report["source_counts"]
        == dict(Counter(p["signalbridge"]["source"] for p in manifest["packets"].values()))
        and all(type(n) is int for n in report["source_counts"].values())
        and report["input_sha256"] == manifest["sha256"]
        and report["source_sha256"] == {name: source[name] for name in SOURCE_FILES},
        "backfill_runtime_input",
    )
    duration = report["duration_seconds"]
    require(
        type(duration) in (int, float) and math.isfinite(duration) and 0 < duration <= 180,
        "backfill_runtime_duration",
    )


def load_backfill(root, run_id):
    """Fixed run UUID only. Freshly inspect stopped metadata; return a stable receipt."""
    try:
        gate.validate_request("wazuh-backfill", run_id, "exited")
        directory = Path("var/soc/pilot") / run_id
        output = directory / "wazuh-backfill"
        retained = {}

        def read(relative):
            raw = read_private(root, relative)
            retained[relative] = digest(raw)
            return raw

        def value(relative):
            return _load(read(relative))

        package = value(directory / "source-manifest.json")
        closed(package, {"files", "sha256"}, "backfill_package_shape")
        files = package["files"]
        require(
            type(files) is dict
            and set(files) == {*PACKAGE, "backfill-input.json"}
            and all(sha(v) for v in files.values())
            and digest(canonical(files)) == package["sha256"],
            "backfill_package_digest",
        )
        execution = value(directory / "execution-source.json")
        closed(execution, {"files", "sha256", "file_count"}, "backfill_execution_shape")
        inventory = execution["files"]
        require(
            type(inventory) is dict
            and 0 < len(inventory) <= 2048
            and integer(execution["file_count"], len(inventory))
            and all(type(k) is str and len(k) < 240 and sha(v) for k, v in inventory.items())
            and digest((json.dumps(inventory, sort_keys=True, indent=2) + "\n").encode())
            == execution["sha256"],
            "backfill_execution_digest",
        )
        for name, original in PACKAGE.items():
            raw = read(directory / "source" / name)
            require(
                digest(raw) == files[name] == inventory[original] and raw == read(Path(original)),
                "backfill_source_mismatch",
            )
        for saved, original in (
            ("executed-controller.py", "scripts/run_wazuh_backfill.py"),
            ("executed-inspection.py", "integrations/wazuh_backfill/inspect_ledger.py"),
        ):
            raw = read(directory / saved)
            require(
                digest(raw) == inventory[original] and raw == read(Path(original)),
                "backfill_controller_mismatch",
            )
        input_manifest_raw = read(directory / "source/backfill-input.json")
        require(
            digest(input_manifest_raw) == files["backfill-input.json"], "backfill_manifest_digest"
        )
        manifest = contract.load_manifest(input_manifest_raw)
        packets, expected_alerts = contract.validate_input(
            manifest, read(directory / "input/events.jsonl")
        )
        report = value(output / "backfill-result.json")
        runtime(report, manifest, files)
        require(
            report["run_id"] == run_id
            and report["input_manifest_sha256"] == digest(input_manifest_raw),
            "backfill_runtime_binding",
        )
        times, identities = [], []
        for state in gate.STATES:
            record = value(directory / (state + "-gate.json"))
            closed(
                record,
                {"state", "errors", "source_sha256", "observed_at", "topology"},
                "backfill_gate_shape",
            )
            require(
                record["state"] == state
                and record["errors"] == []
                and record["source_sha256"] == package["sha256"]
                and not gate.verify_topology(
                    record["topology"], "wazuh-backfill", run_id, state=state
                ),
                "backfill_isolation",
            )
            row = record["topology"]["containers"][0]
            identities.append({key: row[key] for key in ("Id", "Image", "ConfiguredImage", "Name")})
            times.append(run_context.utc_time(record["observed_at"]))
        require(
            identities[0] == identities[1] == identities[2] and times[0] < times[1] < times[2],
            "backfill_gate_binding",
        )
        context_raw = read(output / "run-context.json")
        context = run_context.parse(context_raw)
        require(
            context["run_id"] == run_id
            and context["source_sha256"] == package["sha256"]
            and digest(context_raw) == report["context_sha256"],
            "backfill_context",
        )
        start, end, prepared = map(
            run_context.utc_time,
            (report["started_at"], report["finished_at"], context["prepared_at"]),
        )
        elapsed = (end - start).total_seconds()
        require(
            prepared <= times[0] <= start < end <= times[2]
            and times[1] <= end
            and start <= times[1] + timedelta(seconds=5)
            and 0 <= (start - prepared).total_seconds() <= 900
            and 0 < elapsed <= 180
            and abs(elapsed - report["duration_seconds"]) <= 2,
            "backfill_runtime_window",
        )
        config = (
            read(directory / "source/manager-lab.conf")
            .replace(b"<logall_json>no</logall_json>", b"<logall_json>yes</logall_json>")
            .replace(
                b"<only-future-events>yes</only-future-events>",
                b'<only-future-events max-size="1MB">no</only-future-events>',
            )
        )
        require(
            read(output / "effective-config.xml") == config
            and digest(config) == report["effective_config_sha256"],
            "backfill_effective_config",
        )
        require(b"Wazuh v4.14.8" in read(output / "version.log"), "backfill_runtime_version")
        cases = value(directory / "source/fixtures/expectations.json")["cases"]
        require(
            type(report["logtest_cases"]) is list
            and len(report["logtest_cases"]) == len(cases) == 27,
            "backfill_logtest_count",
        )
        for index, (case, row) in enumerate(zip(cases, report["logtest_cases"], strict=True), 1):
            observed = run_pilot.parse_logtest_output(
                read(output / f"logtest-{index:02d}.log"),
                case["expected_rule"],
                case["expected_level"],
                0,
            )
            require(
                row
                == {
                    "id": case["id"],
                    "status": "passed",
                    "expected_rule": case["expected_rule"],
                    "expected_level": case["expected_level"],
                    **observed,
                },
                "backfill_logtest_mismatch",
            )
        hostname = gate.profile_names("wazuh-backfill", run_id)[0]
        archives_raw, alerts_raw = read(output / "archives.jsonl"), read(output / "alerts.jsonl")
        received = contract.observations(
            archives_raw, packets, hostname=hostname, window=(start, end)
        )
        alerts = contract.observations(
            alerts_raw, packets, alerts=True, hostname=hostname, window=(start, end)
        )
        require(
            set(received) == set(packets)
            and set(alerts) == set(expected_alerts)
            and digest(archives_raw) == report["archives_sha256"]
            and digest(alerts_raw) == report["alerts_sha256"],
            "backfill_observations_incomplete",
        )
        host = value(directory / "host-result.json")
        closed(
            host,
            {
                "run_id",
                "container_id",
                "stopped",
                "failure",
                "state",
                "free_bytes_after",
                "source_sha256",
            },
            "backfill_host_shape",
        )
        require(
            host["run_id"] == run_id
            and host["container_id"] == identities[0]["Id"]
            and host["source_sha256"] == package["sha256"]
            and host["stopped"] is True
            and host["failure"] is None
            and host["state"] == {"status": "exited", "exit_code": 0, "oom": False}
            and type(host["state"]["exit_code"]) is int
            and host["state"]["oom"] is False
            and type(host["free_bytes_after"]) is int
            and host["free_bytes_after"] >= 25 * 1024**3,
            "backfill_host_incomplete",
        )
        fresh = gate.gather_topology("wazuh-backfill", run_id)
        require(
            not gate.verify_topology(fresh, "wazuh-backfill", run_id, state="exited")
            and {key: fresh["containers"][0][key] for key in identities[0]} == identities[0],
            "backfill_fresh_stopped_gate",
        )
        fresh_time = datetime.now(timezone.utc)
        require(fresh_time >= times[2], "backfill_future_receipt")
        for relative, expected in retained.items():
            require(digest(read_private(root, relative)) == expected, "backfill_evidence_changed")
        result = {
            "evidence_kind": "wazuh_backfill",
            "schema_version": 1,
            "tool": "wazuh",
            "app": "bettail",
            "status": "passed",
            "run_id": run_id,
            "runtime_version": "4.14.8",
            "started_at": report["started_at"],
            "finished_at": report["finished_at"],
            "duration_seconds": report["duration_seconds"],
            "recorded_at": times[2].isoformat(),
            "continuous_connection": False,
            "stopped_at_end": True,
            "source_app_assessed": False,
            "stream": {key: manifest[key] for key in ("stream_id", "revision", "offset", "sha256")},
            "counts": {
                "inputs": len(packets),
                "received": len(received),
                "alerts": len(alerts),
                "nonalerts": len(packets) - len(alerts),
                "missing": 0,
                "duplicates": 0,
                "rule_cases": 27,
            },
            "source_counts": report["source_counts"],
            "observations": [
                {
                    **packets[key]["signalbridge"],
                    "rule_id": alerts.get(key),
                    "level": expected_alerts[key][1] if key in alerts else None,
                }
                for key in sorted(packets)
            ],
            "provenance": {
                "source_sha256": package["sha256"],
                "execution_sha256": execution["sha256"],
                "container_id": identities[0]["Id"],
                "image": identities[0]["ConfiguredImage"],
                "fresh_stopped_gate_required": True,
                "receipt_sha256": {
                    p.relative_to(directory).as_posix(): h
                    for p, h in retained.items()
                    if p.is_relative_to(directory)
                },
            },
            "limitations": LIMITATIONS,
        }
        return {
            "digest": digest(canonical(result)),
            "revision": package["sha256"],
            "status": "passed",
            "result": result,
            "fresh_checked_at": fresh_time.isoformat(),
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
        run_pilot.PilotFailure,
    ):
        raise EvidenceError("backfill_evidence_unavailable_or_invalid") from None
