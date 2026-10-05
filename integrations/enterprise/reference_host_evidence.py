"""Closed host revalidation of native source receipts, never a substitute execution.

This reads only one checked private run. Hashes are content identities, not
signatures: a local administrator remains outside the assurance boundary.
"""

import hashlib
import os
import re
from pathlib import Path

from bridge.contract import timestamp

from .network_verification import SNAPSHOT_LIMIT
from .reference_host_controls import read_json, same
from .reference_reconciliation import reconcile
from .verification import LabControlError, private_run_directory, validate_identity

HASHED_RECEIPTS = frozenset(
    (
        "kernel-mounts",
        "kernel-identity",
        "reference-execution",
        "source-outbox",
        "console-events",
        "reference-reconciliation",
        "wazuh-export",
    )
)
EVIDENCE_FILES = {name + ".json" for name in HASHED_RECEIPTS} | {
    "reference-runner.json",
    "allow-source.json",
    "install.log",
}
EVIDENCE_DIRECTORIES = {"wazuh-enterprise", "soc-delivery"}


def require(condition, code):
    if not condition:
        raise LabControlError(code)


def safe_path(path, root):
    path, root = Path(path), Path(root)
    require(path.is_relative_to(root), "Reference evidence escaped its private run.")
    for candidate in (path, *path.parents):
        require(
            candidate.exists()
            and not candidate.is_symlink()
            and not getattr(candidate.lstat(), "st_file_attributes", 0) & 0x400,
            "Reference evidence is missing or redirected.",
        )
        if candidate == root:
            break
    require(path.resolve().is_relative_to(root.resolve()), "Redirected reference evidence.")
    return path


def validate_snapshot(directory, manifest):
    """Check all copied files, including unexpected files excluded by selection."""
    root = Path(directory)
    require(
        isinstance(manifest, dict)
        and set(manifest) == {"files", "file_count", "sha256"}
        and isinstance(manifest["files"], dict)
        and type(manifest["file_count"]) is int
        and manifest["file_count"] == len(manifest["files"])
        and 0 < manifest["file_count"] <= 1500
        and isinstance(manifest["sha256"], str)
        and re.fullmatch(r"[a-f0-9]{64}", manifest["sha256"]),
        "Malformed selected source identity.",
    )
    expected_dirs, found, total = set(), {}, 0
    for name, digest in manifest["files"].items():
        require(
            isinstance(name, str)
            and "\\" not in name
            and not Path(name).drive
            and not Path(name).is_absolute()
            and ".." not in Path(name).parts
            and name == Path(name).as_posix()
            and isinstance(digest, str)
            and re.fullmatch(r"[a-f0-9]{64}", digest),
            "Malformed selected source entry.",
        )
        expected_dirs.update(p.as_posix() for p in Path(name).parents if p != Path("."))
    safe_path(root, root)
    require(root.is_dir(), "Selected source snapshot is not a directory.")

    def fail(error):
        raise LabControlError("Source snapshot could not be enumerated.") from error

    for parent, directories, filenames in os.walk(root, followlinks=False, onerror=fail):
        for name in directories:
            path = safe_path(Path(parent) / name, root)
            require(
                path.relative_to(root).as_posix() in expected_dirs, "Unexpected source directory."
            )
        for name in filenames:
            path = safe_path(Path(parent) / name, root)
            relative = path.relative_to(root).as_posix()
            require(relative in manifest["files"] and path.is_file(), "Unexpected source file.")
            size = path.stat().st_size
            total += size
            require(total <= SNAPSHOT_LIMIT, "Source snapshot byte ceiling reached.")
            raw = path.read_bytes()
            require(len(raw) == size, "Source snapshot changed during verification.")
            found[relative] = hashlib.sha256(raw).hexdigest()
    require(same(found, manifest["files"]), "Selected source snapshot no longer matches.")
    # Match the manifest writer's canonical identity, rather than trusting its hash.
    from scripts.record_verification import json_bytes

    require(
        hashlib.sha256(json_bytes(found)).hexdigest() == manifest["sha256"],
        "Selected source manifest digest changed.",
    )
    return {"source_sha256": manifest["sha256"], "file_count": len(found), "bytes": total}


def validate_native(workspace, run, manifest, footprint, *, now, profile="access"):
    if profile == "header":
        from integrations.zap_enterprise.source_host_evidence import validate_native as header

        return header(workspace, run, manifest, footprint, now=now)
    require(profile == "access", "Unknown native source evidence profile.")
    validate_identity(run)
    directory = private_run_directory(workspace, run)
    snapshot = validate_snapshot(directory / "source", manifest)
    evidence = safe_path(directory / "evidence", directory)
    require(evidence.is_dir(), "Native reference evidence is not a directory.")
    require(
        {p.name for p in evidence.iterdir()} == EVIDENCE_FILES | EVIDENCE_DIRECTORIES,
        "Incomplete native evidence inventory.",
    )
    values, hashes = {}, {}
    for name in EVIDENCE_FILES:
        path = safe_path(evidence / name, directory)
        require(
            path.is_file() and path.stat().st_size <= 262144, "Native receipt byte bound reached."
        )
        if name != "install.log":
            values[name.removesuffix(".json")] = read_json(path, 262144)
            hashes[name.removesuffix(".json")] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            hashes["install-log"] = hashlib.sha256(path.read_bytes()).hexdigest()
    require(
        same(values["allow-source"], {"run_id": run, "runtime_verified": True}),
        "Native execution gate is not this run.",
    )
    runner = values["reference-runner"]
    fields = {
        "schema_version",
        "run_id",
        "completed",
        "receipt_sha256",
        "wheel_footprint",
        "database_boundaries",
        "console_readiness_attempts",
        "tls_readiness",
        "source_http_requests",
        "collection",
        "final_fault_reset",
        "processes_stopped",
        "duration_seconds",
        "limits",
        "wazuh_export",
    }
    require(isinstance(runner, dict) and set(runner) == fields, "Incomplete native runner fields.")
    require(
        type(runner["schema_version"]) is int
        and runner["schema_version"] == 1
        and runner["run_id"] == run
        and all(
            runner[k] is True
            for k in ("completed", "tls_readiness", "final_fault_reset", "processes_stopped")
        )
        and type(runner["console_readiness_attempts"]) is int
        and 1 <= runner["console_readiness_attempts"] <= 10
        and type(runner["source_http_requests"]) is int
        and 1 <= runner["source_http_requests"] <= 80
        and type(runner["duration_seconds"]) in (int, float)
        and 0 < runner["duration_seconds"] <= 900
        and same(runner["wheel_footprint"], footprint)
        and isinstance(runner["limits"], list)
        and len(runner["limits"]) == 3
        and all(isinstance(v, str) and 1 <= len(v) <= 256 for v in runner["limits"]),
        "Native runtime, limits, restoration or process shutdown was not verified.",
    )
    require(
        same(runner["receipt_sha256"], {k: hashes[k] for k in HASHED_RECEIPTS}),
        "Native raw receipt identity changed.",
    )
    boundaries = runner["database_boundaries"]
    require(
        isinstance(boundaries, dict) and set(boundaries) == {"source", "console"},
        "Missing database boundaries.",
    )
    for component in boundaries:
        expected = {
            "component": component,
            "actual_identity_verified": True,
            "cross_database_connect_denied": True,
        }
        require(
            any(
                same(boundaries[component], {**expected, **variant})
                for variant in (
                    {"denial_kind": "sqlstate", "denial_sqlstate": "42501"},
                    {"denial_kind": "server_connect_privilege_message", "denial_sqlstate": None},
                )
            ),
            "Database identity or cross-database denial is incomplete.",
        )
    require(
        same(
            values["kernel-mounts"],
            {
                "/tmp": {"filesystem": "tmpfs", "noexec": True},
                "/opt/verification-deps": {"filesystem": "tmpfs", "noexec": False},
            },
        ),
        "Effective temporary kernel mounts changed.",
    )
    identity = {
        "uid": 10001,
        "gid": 10001,
        "all_capabilities_zero": True,
        "no_new_privileges": True,
        "seccomp_filter": True,
        "cgroup_version": 2,
        "memory_bytes": 512 * 1024**2,
        "swap_bytes": 0,
        "pids": 96,
        "cpu_quota_equals_period": True,
        "read_only_root_source_wheels_secrets": True,
        "reviewed_evidence_mount_writable": True,
    }
    require(
        any(
            same(values["kernel-identity"], {**identity, "supplementary_groups": g})
            for g in ([], [10001])
        ),
        "Effective kernel identity changed.",
    )
    proof = reconcile(
        values["reference-execution"], values["source-outbox"], values["console-events"], now=now
    )
    require(same(values["reference-reconciliation"], proof), "Recomputed source proof differs.")
    wazuh_binding = validate_wazuh_export(
        directory,
        run,
        values["wazuh-export"],
        values["console-events"],
        proof["regression_case_id"],
        now=now,
    )
    require(
        same(runner["wazuh_export"], values["wazuh-export"]),
        "Wazuh source receipt differs.",
    )
    collection = {
        "committed_claim_results": proof["committed_outbox_claims"],
        "collector_transport_invocations": proof["logical_source_events"],
        "phase_deadline_reached": False,
    }
    require(
        same(runner["collection"], collection), "Native claims and initiated transports differ."
    )
    return {
        "native_receipts_revalidated": True,
        "source_snapshot": snapshot,
        "raw_receipt_sha256": hashes,
        "reconciliation": proof,
        "wazuh_input_binding": wazuh_binding,
        "source_http_requests": runner["source_http_requests"],
        "collection": collection,
        "runner_duration_seconds": runner["duration_seconds"],
    }


def validate_wazuh_export(directory, run, summary, console, case_id, *, now):
    """Revalidate the immutable input that a later isolated Wazuh stage consumes."""
    from integrations.wazuh_enterprise.collector_source_binding import bind_expected
    from integrations.wazuh_enterprise.contract import identifier
    from integrations.wazuh_enterprise.export_snapshot import inspect_exports
    from integrations.wazuh_enterprise.native_reconciliation import expected_exports

    fields = {
        "run_id",
        "snapshot_run_id",
        "logical_observations",
        "forwarded_core_signals",
        "scope_counts",
        "manifest_sha256",
        "snapshot_verified",
    }
    require(isinstance(summary, dict) and set(summary) == fields, "Malformed Wazuh source receipt.")
    identifier(summary["snapshot_run_id"])
    require(
        summary["run_id"] == run
        and type(summary["logical_observations"]) is int
        and summary["logical_observations"] == 23
        and type(summary["forwarded_core_signals"]) is int
        and summary["forwarded_core_signals"] == 1
        and summary["snapshot_verified"] is True,
        "Wazuh source receipt is incomplete.",
    )
    evidence = safe_path(Path(directory) / "evidence", directory)
    snapshot_root = safe_path(
        evidence / "wazuh-enterprise" / "native" / summary["snapshot_run_id"], evidence
    )
    require(
        snapshot_root.is_dir()
        and {p.name for p in snapshot_root.iterdir()}
        == {"input", "manifest.json", "snapshot.json"},
        "Wazuh input snapshot inventory changed.",
    )
    manifest_path = safe_path(snapshot_root / "manifest.json", evidence)
    require(
        manifest_path.is_file() and 0 < manifest_path.stat().st_size <= 32768,
        "Wazuh manifest bound reached.",
    )
    raw = manifest_path.read_bytes()
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    inspected = inspect_exports(snapshot_root / "input", raw)
    validate_retained_exports(evidence, raw)
    report_path = safe_path(snapshot_root / "snapshot.json", evidence)
    require(
        report_path.is_file() and 0 < report_path.stat().st_size <= 32768,
        "Wazuh report bound reached.",
    )
    report = read_json(report_path, 32768)
    expected_report = {
        **inspected,
        "run_id": summary["snapshot_run_id"],
        "private_host_acl_verified": False,
        "snapshot_live_after_capture": False,
    }
    require(same(report, expected_report), "Wazuh snapshot receipt does not match its files.")
    expected_counts = {
        f"{app}/observation": sum(row.get("app") == app for row in console["events"])
        for app in ("documents", "expenses")
    }
    expected_counts.update({"documents/detection": 1, "expenses/detection": 0})
    require(
        isinstance(summary["scope_counts"], dict)
        and set(summary["scope_counts"]) == set(expected_counts)
        and all(
            type(summary["scope_counts"][key]) is int
            and summary["scope_counts"][key] == expected_counts[key]
            for key in expected_counts
        )
        and set(inspected["scope_counts"]) == set(expected_counts)
        and all(
            type(inspected["scope_counts"][key]) is int
            and inspected["scope_counts"][key] == expected_counts[key]
            for key in expected_counts
        )
        and inspected["logical_records"] == 24
        and summary["manifest_sha256"] == manifest_sha256,
        "Wazuh input counts or manifest identity differ from the reference run.",
    )
    expected = expected_exports(snapshot_root / "input", raw)
    source = safe_path(Path(directory) / "source", directory)
    engine = hashlib.sha256(
        b"".join(
            _read_bounded(source / "bridge" / name, directory, 262144)
            for name in ("engine.py", "contract.py", "worker.py")
        )
    ).hexdigest()
    require(isinstance(case_id, str), "Wazuh source case identity is incomplete.")
    binding = bind_expected(
        expected,
        console,
        {"case_id": case_id, "run_id": run},
        engine,
        now=now,
    )
    return {
        "snapshot_run_id": summary["snapshot_run_id"],
        "manifest_sha256": manifest_sha256,
        "scope_counts": inspected["scope_counts"],
        "logical_observations": binding["logical_observations"],
        "forwarded_core_signals": binding["forwarded_core_signals"],
        "source_inputs_match_revalidated_reference_run": binding[
            "source_inputs_match_revalidated_reference_run"
        ],
        "independent_wazuh_r3_rediscovery": binding["independent_wazuh_r3_rediscovery"],
    }


def validate_retained_exports(evidence, raw_manifest):
    """The live file outbox remains beside its snapshot; require the same bytes."""
    from integrations.wazuh_enterprise.export_snapshot import manifest

    value = manifest(raw_manifest)
    root = safe_path(evidence / "soc-delivery", evidence)
    files, children, total = {}, {root: set()}, 0
    for stream in value["streams"]:
        for segment in stream["segments"]:
            stem = "observations" if stream["channel"] == "observation" else "detections"
            path = (
                root
                / "enterprise"
                / stream["app"]
                / stream["channel"]
                / stream["stream_id"]
                / f"{stem}-{segment['number']:03}.jsonl"
            )
            files[path] = segment
            total += segment["bytes"]
            current = path
            while current != root:
                children.setdefault(current.parent, set()).add(current.name)
                current = current.parent
    require(total <= 131072, "Retained source export exceeds the fixed profile.")
    for parent, expected in children.items():
        safe_path(parent, evidence)
        require(parent.is_dir(), "Retained source export directory changed.")
        found = set()
        with os.scandir(parent) as entries:
            for entry in entries:
                require(len(found) < len(expected), "Unexpected retained source export entry.")
                found.add(entry.name)
        require(found == expected, "Retained source export inventory differs from snapshot.")
    for path, segment in files.items():
        safe_path(path, evidence)
        require(
            path.is_file()
            and path.stat().st_nlink == 1
            and path.stat().st_size == segment["bytes"],
            "Retained source export file changed.",
        )
        with path.open("rb") as stream:
            raw = stream.read(segment["bytes"] + 1)
        require(
            len(raw) == segment["bytes"] and hashlib.sha256(raw).hexdigest() == segment["sha256"],
            "Retained source export digest differs from snapshot.",
        )


def _read_bounded(path, root, limit):
    path = safe_path(path, root)
    require(path.is_file() and 0 < path.stat().st_size <= limit, "Wazuh source file bound reached.")
    raw = path.read_bytes()
    require(len(raw) == path.stat().st_size, "Wazuh source file changed during read.")
    return raw


def validate_shutdown(main, independent, run, *, started, finished, components=2):
    validate_identity(run)
    require(components in (2, 3), "Unreviewed source component count.")
    require(
        isinstance(main, dict)
        and same(
            main,
            {"run_id": run, "shutdown_verified": True, "stopped_component_count": components},
        ),
        "Main source shutdown is incomplete.",
    )
    require(
        isinstance(independent, dict)
        and set(independent)
        == {"run_id", "shutdown_verified", "reason", "stopped_component_count", "stopped_at"}
        and independent["run_id"] == run
        and independent["shutdown_verified"] is True
        and type(independent["stopped_component_count"]) is int
        and independent["stopped_component_count"] == components
        and independent["reason"] == "launcher_finished",
        "Independent source shutdown is incomplete or guard aborted.",
    )
    try:
        valid = started <= timestamp(independent["stopped_at"]) <= finished
    except (TypeError, ValueError):
        valid = False
    require(valid, "Independent shutdown time is outside this run.")
    return {"main_shutdown_verified": True, "independent_shutdown_verified": True}
