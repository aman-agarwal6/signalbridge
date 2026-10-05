"""Recheck finite native header receipts; runtime and host shutdown are separate gates."""

import hashlib

from integrations.enterprise.reference_host_controls import read_json, same
from integrations.enterprise.reference_host_evidence import require, safe_path, validate_snapshot
from integrations.enterprise.verification import private_run_directory, validate_identity

from .capture import PROFILE
from .source_reconciliation import reconcile
from .source_runner import database_boundary

HASHED = {
    "kernel-mounts",
    "kernel-identity",
    "header-execution",
    "source-captures",
    "source-outbox",
    "console-events",
    "header-reconciliation",
}
FILES = {name + ".json" for name in HASHED} | {
    "header-runner.json",
    "allow-source.json",
    "install.log",
}


def validate_native(workspace, run, manifest, footprint, *, now):
    validate_identity(run)
    directory = private_run_directory(workspace, run)
    require(
        isinstance(manifest, dict)
        and isinstance(manifest.get("files"), dict)
        and {
            "integrations/zap_enterprise/" + name + ".py"
            for name in (
                "source_runner",
                "source_server",
                "source_support",
                "source_settings",
                "capture",
                "source_reconciliation",
            )
        }
        <= manifest["files"].keys(),
        "The source snapshot omits the fixed header implementation.",
    )
    snapshot = validate_snapshot(directory / "source", manifest)
    evidence = safe_path(directory / "evidence", directory)
    require(
        evidence.is_dir() and {p.name for p in evidence.iterdir()} == FILES,
        "Incomplete header evidence inventory.",
    )
    values, hashes = {}, {}
    for name in FILES:
        path = safe_path(evidence / name, directory)
        require(
            path.is_file() and path.stat().st_size <= 262144, "Header receipt exceeded its bound."
        )
        label = name.removesuffix(".json")
        hashes[label] = hashlib.sha256(path.read_bytes()).hexdigest()
        if name != "install.log":
            values[label] = read_json(path, 262144)
    require(
        same(values["allow-source"], {"run_id": run, "runtime_verified": True}),
        "Wrong header execution gate.",
    )
    runner = values["header-runner"]
    fields = {
        "schema_version",
        "profile",
        "run_id",
        "completed",
        "native_zap_executed",
        "receipt_sha256",
        "wheel_footprint",
        "database_boundaries",
        "console_readiness_attempts",
        "tls_readiness",
        "source_http_requests",
        "source_readiness_requests",
        "collection",
        "final_fault_reset",
        "processes_stopped",
        "duration_seconds",
        "limits",
    }
    require(isinstance(runner, dict) and set(runner) == fields, "Incomplete header runner fields.")
    require(
        type(runner["schema_version"]) is int
        and runner["schema_version"] == 1
        and runner["profile"] == PROFILE
        and runner["run_id"] == run,
        "Wrong header run identity.",
    )
    require(
        all(
            runner[k] is True
            for k in ("completed", "tls_readiness", "final_fault_reset", "processes_stopped")
        )
        and runner["native_zap_executed"] is False,
        "Header source/reset/shutdown is incomplete.",
    )
    require(
        type(runner["console_readiness_attempts"]) is int
        and 1 <= runner["console_readiness_attempts"] <= 10,
        "Invalid console readiness count.",
    )
    require(
        type(runner["source_readiness_requests"]) is int
        and 1 <= runner["source_readiness_requests"] <= runner["console_readiness_attempts"],
        "Invalid source readiness count.",
    )
    require(
        type(runner["source_http_requests"]) is int
        and runner["source_http_requests"] == runner["source_readiness_requests"] + 18,
        "Unexpected header request count.",
    )
    require(
        type(runner["duration_seconds"]) in (int, float)
        and 0 < runner["duration_seconds"] <= 900
        and same(runner["wheel_footprint"], footprint),
        "Unexpected header duration/dependencies.",
    )
    require(
        isinstance(runner["limits"], list)
        and len(runner["limits"]) == 3
        and all(isinstance(v, str) and 1 <= len(v) <= 256 for v in runner["limits"]),
        "Missing header limits.",
    )
    require(
        same(runner["receipt_sha256"], {name: hashes[name] for name in HASHED}),
        "Header raw receipt identity changed.",
    )
    boundaries = runner["database_boundaries"]
    require(
        isinstance(boundaries, dict) and set(boundaries) == {"source", "console"},
        "Missing header database boundaries.",
    )
    for component in boundaries:
        database_boundary(boundaries[component], component)
    require(
        same(
            values["kernel-mounts"],
            {
                "/tmp": {"filesystem": "tmpfs", "noexec": True},
                "/opt/verification-deps": {"filesystem": "tmpfs", "noexec": False},
            },
        ),
        "Header kernel mounts changed.",
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
            same(values["kernel-identity"], {**identity, "supplementary_groups": groups})
            for groups in ([], [10001])
        ),
        "Header kernel identity changed.",
    )
    proof = reconcile(
        values["header-execution"],
        values["source-captures"],
        values["source-outbox"],
        values["console-events"],
        now=now,
    )
    require(same(values["header-reconciliation"], proof), "Recomputed header evidence differs.")
    require(
        proof["source_outbox_claims"] == proof["worker_committed_attempts"] == 8,
        "Unexpected header retries require review.",
    )
    collection = {
        "committed_claim_results": 8,
        "collector_transport_invocations": 8,
        "phase_deadline_reached": False,
    }
    require(same(runner["collection"], collection), "Header claims and transport calls differ.")
    return {
        "native_receipts_revalidated": True,
        "profile": PROFILE,
        "source_snapshot": snapshot,
        "raw_receipt_sha256": hashes,
        "reconciliation": proof,
        "source_http_requests": runner["source_http_requests"],
        "collection": collection,
        "runner_duration_seconds": runner["duration_seconds"],
        "native_zap_executed": False,
    }
