"""Validate retained offline fixture results without rerunning or contacting anything."""

import hashlib
import json
import math
import re
import stat
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath

RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_BYTES = 2 * 1024 * 1024
SCENARIOS = (
    ("authorized_read", None),
    ("distinct_private_failures", "R1"),
    ("same_resource_retries", None),
    ("below_threshold", None),
    ("bucket_boundary_gap", "R1"),
    ("revoked_read_allowed", "R2"),
    ("controlled_policy_fault", "R2"),
    ("successful_membership_change", None),
    ("session_errors_not_private_reads", None),
    ("dependency_errors", None),
    ("mixed_sources", None),
    ("cross_application", None),
    ("mixed_environments", None),
    ("out_of_order", "R1"),
    ("duplicate_delivery", None),
)
CONTROLS = (
    "tampered_signature_rejected_without_event",
    "duplicate_content_conflict_rejected",
    "configured_600_per_minute_limit",
)
CODE_FILES = {
    "runner_sha256": "scripts/run_enterprise_lab.py",
    "suite_sha256": "simulations/enterprise_suite.py",
    "scenario_definition_sha256": "simulations/scenarios.py",
    "simulation_settings_sha256": "config/simulation_settings.py",
    "engine_sha256": "bridge/engine.py",
    "contract_sha256": "bridge/contract.py",
    "worker_sha256": "bridge/worker.py",
    "ingestion_sha256": "bridge/ingestion.py",
}
SOURCE_DIRS = {
    "simulations",
    "bridge",
    "config",
    "integrations",
    "scripts",
    "tests",
    "templates",
    "static",
    "fixtures",
}
SOURCE_FILES = {
    ".github/workflows/checks.yml",
    "manage.py",
    "requirements.txt",
    "requirements-dev.txt",
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "compose.yaml",
    "Dockerfile",
    ".dockerignore",
    ".gitignore",
    "Makefile",
    "start-signalbridge.cmd",
    "stop-signalbridge.cmd",
}
PRIVATE_PARTS = {
    "var",
    "artifacts",
    ".git",
    ".venv",
    "node_modules",
    "private-source",
    "__pycache__",
}
NOT_TESTED = [
    "Endpoint or cloud inventory",
    "Live adversary exploitation",
    "Production traffic",
    "Multi-node availability",
    "PostgreSQL concurrency or crash durability",
    "Network HTTP latency",
    "Competitor products",
    "Independent blind holdout",
    "Automated external response",
]
DENOMINATOR = (
    "15 declared, builder-authored synthetic scenarios; not independent production prevalence"
)
LOAD_LIMIT = "Single-process SQLite harness timing includes test-client overhead; not network or production capacity."
LIMITS = [
    "Historical builder-operated fixture evidence, not an independent audit or enterprise benchmark.",
    "Source manifests identify the recorded code; the current checkout and current runtime are not compared.",
    "Known missed scenarios remain coverage failures even when the harness exits successfully.",
    "Python network/process guards are not an OS sandbox for arbitrary hostile code.",
    "Local filesystem administrators can replace results, provenance and their hashes.",
    "Only result/provenance bytes are read; recorded log hashes are not independently rehashed here.",
    "Aggregate timing is retained and checked for consistency; raw latency samples are unavailable.",
]


class SimulationEvidenceError(ValueError):
    """Safe fixed diagnostic, never raw report text or a private path."""


def require(condition, code):
    if not condition:
        raise SimulationEvidenceError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def valid_sha(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def integer(value, maximum=10000):
    return type(value) is int and 0 <= value <= maximum


def finite(value, maximum=1_000_000):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum


def json_document(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    try:
        data = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda _: require(False, "nonfinite_json_number"),
        )
        require(isinstance(data, dict), "invalid_document")
        return data
    except (ValueError, UnicodeError, RecursionError) as error:
        raise SimulationEvidenceError("invalid_json") from error


def read_fixed(root, run_id, filename):
    require(isinstance(run_id, str) and RUN_ID.fullmatch(run_id), "invalid_run_id")
    require(filename in {"result.json", "provenance.json"}, "unsupported_evidence_file")
    root = Path(root)
    target = root / "artifacts/local/simulation" / run_id / filename
    current = root
    for part in target.relative_to(root).parts:
        current /= part
        info = current.lstat()
        require(
            not stat.S_ISLNK(info.st_mode)
            and not (
                getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024)
            ),
            "linked_evidence_path",
        )
    require(target.resolve().is_relative_to(root.resolve()), "evidence_path_escape")
    require(target.is_file() and target.stat().st_size <= MAX_BYTES, "invalid_evidence_size")
    with target.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "oversized_evidence")
    return raw


def validate_manifest(manifest):
    require(set(manifest) == {"files", "sha256", "file_count"}, "invalid_source_manifest")
    files = manifest["files"]
    require(
        isinstance(files, dict)
        and 1 <= len(files) <= 2000
        and integer(manifest["file_count"])
        and manifest["file_count"] == len(files),
        "invalid_source_count",
    )
    folded = set()
    for name, checksum in files.items():
        require(
            isinstance(name, str)
            and len(name) <= 240
            and "\\" not in name
            and re.fullmatch(r"[A-Za-z0-9_./-]+", name),
            "invalid_manifest_path",
        )
        path = PurePosixPath(name)
        require(
            not path.is_absolute()
            and str(path) == name
            and ".." not in path.parts
            and all(
                part not in PRIVATE_PARTS and not part.startswith(".env") for part in path.parts
            )
            and (name in SOURCE_FILES or (len(path.parts) > 1 and path.parts[0] in SOURCE_DIRS))
            and name.casefold() not in folded
            and valid_sha(checksum),
            "invalid_manifest_entry",
        )
        folded.add(name.casefold())
    require(set(CODE_FILES.values()) <= set(files), "missing_simulation_source")
    calculated = digest((json.dumps(files, sort_keys=True, indent=2) + "\n").encode("utf8"))
    require(manifest["sha256"] == calculated, "source_manifest_digest_mismatch")
    return files


def stamp(value):
    require(isinstance(value, str) and len(value) <= 40, "invalid_timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.utcoffset() == timedelta(0), "timestamp_must_be_utc")
    return result


def validate_result(report):
    require(
        type(report["schema_version"]) is int
        and report["schema_version"] == 1
        and report["kind"] == "signalbridge-offline-capability-simulation",
        "unsupported_result",
    )
    require(
        set(report)
        == {
            "schema_version",
            "kind",
            "started_at",
            "execution_status",
            "database",
            "transport",
            "safety",
            "scenarios",
            "controls",
            "not_tested",
            "detection_quality",
            "bounded_load",
            "scenario_records_processed",
            "final_queue",
            "finished_at",
            "duration_seconds",
            "requests_executed",
        },
        "unexpected_result_fields",
    )
    require(
        report["database"] == "disposable in-memory SQLite"
        and report["transport"] == "Django in-process test client",
        "incorrect_execution_scope",
    )
    safety = report["safety"]
    require(
        set(safety)
        == {
            "synthetic_only",
            "network_guard",
            "child_process_guard",
            "production_database",
            "max_requests",
            "max_worker_records",
        }
        and all(
            safety[key] is True
            for key in ("synthetic_only", "network_guard", "child_process_guard")
        )
        and safety["production_database"] is False
        and safety["max_requests"] == 750
        and safety["max_worker_records"] == 700,
        "invalid_safety_contract",
    )
    start, end = stamp(report["started_at"]), stamp(report["finished_at"])
    duration = report["duration_seconds"]
    require(
        start <= end
        and finite(duration, 120)
        and abs((end - start).total_seconds() - duration) <= 0.1,
        "invalid_run_duration",
    )
    scenarios = report["scenarios"]
    require(
        isinstance(scenarios, list) and len(scenarios) == len(SCENARIOS), "incomplete_scenarios"
    )
    clean_scenarios = []
    counts = {
        "true_positive_scenarios": 0,
        "false_negative_scenarios": 0,
        "false_positive_scenarios": 0,
        "true_negative_scenarios": 0,
    }
    known_misses = []
    unexpected = []
    for row, (name, expected) in zip(scenarios, SCENARIOS, strict=True):
        require(
            isinstance(row, dict)
            and set(row)
            == {"id", "expected_rule", "observed_rules", "known_limitation", "coverage_met"},
            "invalid_scenario_fields",
        )
        require(row["id"] == name and row["expected_rule"] == expected, "scenario_label_mismatch")
        known = row["known_limitation"]
        require(
            type(known) is bool and (not known or name == "bucket_boundary_gap"),
            "scenario_limitation_mismatch",
        )
        observed = row["observed_rules"]
        require(
            isinstance(observed, list)
            and len(observed) <= 1
            and all(value in ("R1", "R2") for value in observed),
            "invalid_observed_rules",
        )
        covered = expected in observed if expected else not observed
        require(row["coverage_met"] is covered, "scenario_coverage_mismatch")
        category = (
            ("true_positive_scenarios" if covered else "false_negative_scenarios")
            if expected
            else ("true_negative_scenarios" if covered else "false_positive_scenarios")
        )
        counts[category] += 1
        if not covered:
            (known_misses if known else unexpected).append(name)
        clean_scenarios.append(
            {
                "id": name,
                "expected_rule": expected,
                "observed_rules": list(observed),
                "known_limitation": known,
                "coverage_met": covered,
            }
        )
    tp, fp = counts["true_positive_scenarios"], counts["false_positive_scenarios"]
    recall = tp / (tp + counts["false_negative_scenarios"])
    precision = tp / (tp + fp) if tp + fp else None
    quality = report["detection_quality"]
    require(
        set(quality) == set(counts) | {"recall", "precision", "denominator"},
        "invalid_quality_fields",
    )
    require(
        all(integer(quality[key]) and quality[key] == value for key, value in counts.items()),
        "confusion_matrix_mismatch",
    )
    require(
        finite(quality["recall"], 1) and abs(quality["recall"] - recall) <= 1e-12, "recall_mismatch"
    )
    require(
        (precision is None and quality["precision"] is None)
        or (
            precision is not None
            and finite(quality["precision"], 1)
            and abs(quality["precision"] - precision) <= 1e-12
        ),
        "precision_mismatch",
    )
    require(
        set(report["controls"]) == set(CONTROLS)
        and all(report["controls"][key] is True for key in CONTROLS),
        "incomplete_control_checks",
    )
    load = report["bounded_load"]
    require(
        set(load)
        == {
            "accepted_events",
            "processed_events",
            "source_rate_limit",
            "ingest_seconds",
            "processing_seconds",
            "in_process_requests_per_second",
            "in_process_request_p50_ms",
            "in_process_request_p95_ms",
            "alerts_from_benign_load",
            "limits",
        },
        "invalid_load_fields",
    )
    for field, expected in (
        ("accepted_events", 600),
        ("processed_events", 600),
        ("alerts_from_benign_load", 0),
    ):
        require(integer(load[field]) and load[field] == expected, "load_count_mismatch")
    require(load["source_rate_limit"] == "600 per application per minute", "load_scope_mismatch")
    ingest, processing = load["ingest_seconds"], load["processing_seconds"]
    require(
        finite(ingest, 60)
        and 0 < ingest < 60
        and finite(processing, 120)
        and ingest + processing <= duration + 0.01,
        "invalid_load_duration",
    )
    require(
        finite(load["in_process_requests_per_second"])
        and abs(load["in_process_requests_per_second"] - 600 / ingest) <= 0.02,
        "throughput_mismatch",
    )
    p50, p95 = load["in_process_request_p50_ms"], load["in_process_request_p95_ms"]
    require(finite(p50) and finite(p95) and p50 <= p95 <= ingest * 1000, "invalid_latency_summary")
    require(
        type(report["scenario_records_processed"]) is int
        and report["scenario_records_processed"] == 34
        and type(report["requests_executed"]) is int
        and report["requests_executed"] == 639,
        "request_reconciliation_failed",
    )
    queue = report["final_queue"]
    require(
        set(queue) <= {"processed", "pending", "dead"}
        and all(integer(value) for value in queue.values())
        and queue.get("processed") == 634
        and queue.get("pending", 0) == 0
        and queue.get("dead", 0) == 0,
        "queue_reconciliation_failed",
    )
    status = "failed" if unexpected else "partial" if known_misses else "passed"
    expected_status = (
        "completed_with_known_coverage_gap"
        if status == "partial"
        else ("completed_with_coverage_failures" if status == "failed" else "completed")
    )
    require(report["execution_status"] == expected_status, "execution_status_mismatch")
    normalized = {
        "schema_version": 1,
        "kind": report["kind"],
        "started_at": report["started_at"],
        "finished_at": report["finished_at"],
        "execution_status": expected_status,
        "database": report["database"],
        "transport": report["transport"],
        "safety": dict(safety),
        "scenarios": clean_scenarios,
        "controls": {key: True for key in CONTROLS},
        "not_tested": NOT_TESTED,
        "detection_quality": {
            **counts,
            "recall": recall,
            "precision": precision,
            "denominator": DENOMINATOR,
        },
        "bounded_load": {
            **{key: load[key] for key in load if key != "limits"},
            "limits": LOAD_LIMIT,
        },
        "scenario_records_processed": 34,
        "final_queue": {"processed": 634, "pending": 0, "dead": 0},
        "duration_seconds": duration,
        "requests_executed": 639,
        "coverage": {
            "met": sum(row["coverage_met"] for row in clean_scenarios),
            "total": 15,
            "known_misses": known_misses,
            "unexpected_misses_or_alerts": unexpected,
        },
    }
    return status, normalized


def validate_evidence(run_id, result_raw, provenance_raw):
    try:
        require(isinstance(run_id, str) and RUN_ID.fullmatch(run_id), "invalid_run_id")
        report, provenance = json_document(result_raw), json_document(provenance_raw)
        require(
            type(provenance["schema_version"]) is int
            and provenance["schema_version"] == 1
            and provenance["run_id"] == run_id,
            "invalid_provenance_identity",
        )
        require(
            provenance["execution_verified"] is True
            and type(provenance["exit_code"]) is int
            and provenance["exit_code"] == 0,
            "unverified_execution",
        )
        require(
            provenance["source_unchanged"] is True
            and provenance["source_before"] == provenance["source_after"],
            "source_changed",
        )
        files = validate_manifest(provenance["source_before"])
        require(provenance["result_sha256"] == digest(result_raw), "result_hash_mismatch")
        git = provenance["git"]
        require(
            isinstance(git["head"], str)
            and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", git["head"])
            and type(git["dirty"]) is bool,
            "invalid_revision",
        )
        require(
            isinstance(provenance["python"], str)
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", provenance["python"]),
            "invalid_runtime",
        )
        logs = provenance["logs"]
        require(
            set(logs) == {"stdout.txt", "stderr.txt"}
            and all(valid_sha(value) for value in logs.values()),
            "invalid_log_digests",
        )
        status, simulation = validate_result(report)
        result = {
            "evidence_kind": "offline_simulation",
            "app": "signalbridge",
            "status": status,
            "simulation": simulation,
            "executed_at": simulation["finished_at"],
            "duration_ms": round(simulation["duration_seconds"] * 1000),
            "working_tree_dirty": git["dirty"],
            "limitations": LIMITS,
            "checks": [
                {"id": row["id"], "status": "passed" if row["coverage_met"] else "failed"}
                for row in simulation["scenarios"]
            ],
            "provenance": {
                "run_id": run_id,
                "source_sha256": provenance["source_before"]["sha256"],
                "source_file_count": len(files),
                "source_unchanged": True,
                "result_sha256": digest(result_raw),
                "provenance_sha256": digest(provenance_raw),
                "python": provenance["python"],
                "execution_verified": True,
                "verification": "historical_local_artifact_consistency",
                "logs": dict(logs),
                "log_bytes_verified_by_importer": False,
                "limits": LIMITS,
                "code_hashes": {key: files[name] for key, name in CODE_FILES.items()},
            },
        }
        return {
            "digest": digest(result_raw),
            "revision": git["head"],
            "status": status,
            "result": result,
        }
    except (KeyError, TypeError, AttributeError, ValueError, IndexError, OverflowError) as error:
        if isinstance(error, SimulationEvidenceError):
            raise
        raise SimulationEvidenceError("invalid_simulation_evidence") from error


def load_simulation(root, run_id):
    try:
        result = read_fixed(root, run_id, "result.json")
        provenance = read_fixed(root, run_id, "provenance.json")
        normalized = validate_evidence(run_id, result, provenance)
        require(
            result == read_fixed(root, run_id, "result.json")
            and provenance == read_fixed(root, run_id, "provenance.json"),
            "evidence_changed_during_import",
        )
        return normalized
    except (OSError, UnicodeError) as error:
        raise SimulationEvidenceError("simulation_evidence_unavailable") from error
