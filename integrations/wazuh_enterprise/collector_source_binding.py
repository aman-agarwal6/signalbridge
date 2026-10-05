"""Bind a complete idle export to a revalidated genuine reference-access run.

No daemon, network, event creation or provenance reassignment. Native receipts
remain trusted local-operator evidence, not protection against an administrator.
"""

import hashlib
import os
from pathlib import Path

from bridge.contract import digest, parse_json, timestamp
from integrations.enterprise.reference_host_controls import same
from integrations.enterprise.reference_host_evidence import safe_path
from integrations.enterprise.verification import private_run_directory

from .contract import identifier, require, validate_signal
from .export_snapshot import _plain, inspect_exports
from .native_reconciliation import expected_exports


def read_bytes(path, root, bound):
    path = safe_path(path, root)
    before = _plain(path, directory=False)
    require(before.st_size <= bound, "collector_binding_file_bound")
    with os.fdopen(
        os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)), "rb"
    ) as stream:
        opened = os.fstat(stream.fileno())
        require(
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_nlink)
            == (before.st_dev, before.st_ino, before.st_size, 1),
            "collector_binding_file_race",
        )
        raw = stream.read(bound + 1)
        after = os.fstat(stream.fileno())
    final = _plain(path, directory=False)
    require(
        len(raw) == before.st_size
        and (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)
        and (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
        == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns),
        "collector_binding_file_race",
    )
    return raw


def load_snapshot(workspace, snapshot_run, *, source_directory=None):
    identifier(snapshot_run)
    if source_directory is None:
        boundary = Path(workspace)
        root = boundary / "var/wazuh-enterprise/native" / snapshot_run
    else:
        boundary = Path(source_directory) / "evidence"
        root = boundary / "wazuh-enterprise/native" / snapshot_run
    safe_path(root, boundary)
    require(
        root.is_dir()
        and {p.name for p in root.iterdir()} == {"input", "manifest.json", "snapshot.json"},
        "collector_binding_snapshot_inventory",
    )
    raw = read_bytes(root / "manifest.json", root, 32768)
    inspected = inspect_exports(root / "input", raw)
    report = parse_json(read_bytes(root / "snapshot.json", root, 32768))
    require(
        same(
            report,
            {
                **inspected,
                "run_id": snapshot_run,
                "private_host_acl_verified": False,
                "snapshot_live_after_capture": False,
            },
        ),
        "collector_binding_snapshot_changed",
    )
    return root, raw, expected_exports(root / "input", raw)


def bind_expected(expected, console, result, engine_sha256, *, now):
    """Called only after native archive validation; cannot attest a run itself."""
    require(
        type(console) is dict and set(console) == {"events", "cases"}, "collector_source_console"
    )
    observed = {}
    for event in console["events"]:
        row = event["payload"]
        require(
            event["source"] == "instrumented_lab" and event["state"] == "processed",
            "collector_source_event",
        )
        packet = {
            "signalbridge": {
                "export_version": 2,
                "app": event["app"],
                "environment": row["environment"],
                "event_id": event["event_id"],
                "occurred_at": timestamp(row["occurred_at"]).isoformat(),
                "operation": row["operation"],
                "outcome": row["outcome"],
                "reason": row["reason"],
                "source": "instrumented_lab",
            }
        }
        key = event["app"], "observation", event["event_id"]
        require(key not in observed and event["digest"] == digest(row), "collector_source_event")
        observed[key] = packet
    actual = {
        key: packet for key, (packet, _location) in expected.items() if key[1] == "observation"
    }
    require(actual == observed and len(actual) == 23, "collector_source_observations_differ")
    require(len(console["cases"]) == 1, "collector_source_cases")
    case = console["cases"][0]
    require(
        case["case_id"] == result["case_id"]
        and case["rule"] == "R3"
        and case["app"] == "documents",
        "collector_source_cases",
    )
    signals = [packet for key, (packet, _location) in expected.items() if key[1] == "detection"]
    require(len(signals) == 1, "collector_source_signal_count")
    signal = validate_signal(signals[0])
    evidence = sorted(case["evidence_event_ids"])
    events = {event["event_id"]: event for event in console["events"]}
    fingerprint = digest(
        sorted([[key, events[key]["digest"], "instrumented_lab"] for key in evidence])
    )
    require(
        signal["app"] == case["app"]
        and signal["case_id"] == case["case_id"]
        and signal["case_version"] == case["version"]
        and signal["rule_id"] == "R3"
        and signal["rule_version"] == "resource-membership-v1"
        and signal["source"] == "instrumented_lab"
        and signal["environment"] == "lab"
        and signal["evidence_sha256"] == fingerprint
        and signal["generation_source_sha256"] == engine_sha256
        and signal["evidence_count"] == 2
        and signal["evidence_complete"] == 1
        and signal["included_event_ids"].split(",") == evidence,
        "collector_source_signal_differ",
    )
    require(
        max(timestamp(events[key]["payload"]["occurred_at"]) for key in evidence)
        <= timestamp(signal["generated_at"])
        <= now,
        "collector_source_signal_time",
    )
    return {
        "native_source_run_id": result["run_id"],
        "native_source_receipt_sha256": result.get("host_receipt_sha256"),
        "native_source_selected_sha256": result.get("source_sha256"),
        "engine_source_sha256": engine_sha256,
        "logical_observations": len(actual),
        "forwarded_core_signals": 1,
        "native_case_id": case["case_id"],
        "source_inputs_match_revalidated_reference_run": True,
        "independent_wazuh_r3_rediscovery": False,
    }


def load_binding(workspace, snapshot_run, source_run, *, now):
    # The trusted Windows host initializes disposable verification settings.
    # This existing reader rechecks real native receipts, source, wheels,
    # restoration and both shutdowns. It makes no database writes or launch.
    from bridge.reference_retest import _manifest, load_native_retest

    result = load_native_retest(workspace, source_run)
    directory = private_run_directory(workspace, source_run)
    host_raw = read_bytes(directory / "receipt.json", directory, 262144)
    require(
        hashlib.sha256(host_raw).hexdigest() == result["host_receipt_sha256"],
        "collector_source_host_receipt_changed",
    )
    host = parse_json(host_raw)
    export_raw = read_bytes(directory / "evidence/wazuh-export.json", directory, 262144)
    export = parse_json(export_raw)
    require(
        export.get("run_id") == source_run and export.get("snapshot_run_id") == snapshot_run,
        "collector_source_snapshot_identity",
    )
    root, raw, expected = load_snapshot(workspace, snapshot_run, source_directory=directory)
    console_raw = read_bytes(directory / "evidence/console-events.json", directory, 262144)
    require(
        hashlib.sha256(console_raw).hexdigest()
        == host["native_proof"]["raw_receipt_sha256"]["console-events"],
        "collector_source_console_changed",
    )
    console = parse_json(console_raw)
    engine = hashlib.sha256(
        b"".join(
            read_bytes(directory / "source/bridge" / name, directory, 262144)
            for name in ("engine.py", "contract.py", "worker.py")
        )
    ).hexdigest()
    require(
        _manifest(directory / "source")["sha256"] == result["source_sha256"],
        "collector_source_code_changed",
    )
    binding = bind_expected(expected, console, result, engine, now=now)
    binding.update(
        snapshot_run_id=snapshot_run,
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
        expected_packets_sha256=digest(
            sorted([[*key, packet, location] for key, (packet, location) in expected.items()])
        ),
    )
    return root, raw, expected, binding
