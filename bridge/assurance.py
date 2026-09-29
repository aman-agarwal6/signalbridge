"""Import consistency-checked local service evidence, never credentials or live state.

The local operator and retained receipts are trusted. Hashes establish consistency,
not independent execution, continuous isolation, or an administrator-proof audit.
"""

import hashlib
import json
import re
import stat
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID

SHA = re.compile(r"[0-9a-f]{64}\Z")
REVISION = re.compile(r"[0-9a-f]{40}\Z")
MIGRATION = re.compile(r"[0-9]{12,14}_[a-z0-9_]+\.sql\Z")
ISOLATION_FILE = re.compile(r"[0-9]{8}T[0-9]{12}Z-[0-9a-f]{8}\.json\Z")
MAX_BYTES = 2 * 1024 * 1024
PROJECT = "signalbridge-bettail-lab"
RELAY = "signalbridge-bettail-relay"
EDGE = "signalbridge-bettail-edge"
CONTAINERS = tuple(
    f"supabase_{name}_{PROJECT}" for name in ("db", "kong", "auth", "rest", "storage", "inbucket")
) + (RELAY,)
FIXTURE_DIGEST = "c90cff659645a312a28804965f3dbc34061338f7234ff5d6ddb2c57e9eadec15"
LIMITATIONS = [
    "Builder-operated, consistency-checked historical local evidence; not an independent audit.",
    "The current machine state is not verified by this import; isolation samples are not continuous monitoring.",
    "Direct Auth, PostgREST and Storage HTTP only; Next application routes and SSR cookies were not tested.",
    "Administrative email confirmation does not establish delivery or ownership verification.",
    "No signed-URL revocation, committed policy fault, source-owned event delivery or outbox was tested.",
    "Full M1, production security, remote CI and release enforcement remain unverified.",
    "A trusted administrator can replace local evidence and hashes; this is not tamper-proof attestation.",
]

# Fixed semantic contract of the reviewed harness. Setup/restoration never inflate
# the assertion count. Failed checks carry no assertion-success metadata.
SPECS = []


def _spec(identifier, stage, outcome, status=None, code=None, content=False):
    SPECS.append((identifier, stage, outcome, status, code, content))


for _role in ("owner", "member", "outsider"):
    _spec(f"{_role}_auth_creation_and_password_login", "setup", "authenticated", 200)
    _spec(f"{_role}_profile_ready", "setup", "profile_completed")
_spec("synthetic_group_and_pick_seeded", "setup", "synthetic_fixture_ready")
for _role in ("owner", "member"):
    _spec(f"{_role}_exact_row_visible", "assertion", "allowed", 200)
    _spec(f"{_role}_snapshot_visible", "assertion", "allowed", 200)
_spec("outsider_exact_row_hidden", "assertion", "not_visible", 200)
_spec("outsider_snapshot_denied", "assertion", "denied", 400, "P0001")
_spec("anonymous_table_read_denied", "assertion", "denied", (401, 403), "42501")
_spec("anonymous_snapshot_denied", "assertion", "denied", (401, 403), "42501")
_spec(
    "private_image_reserved_and_uploaded",
    "setup",
    "private_object_created",
    (200, 201),
    content=True,
)
_spec("owner_draft_image_visible", "assertion", "allowed", 200, content=True)
_spec("member_unattached_draft_hidden", "assertion", "not_visible", "storage", "storage")
_spec("owner_image_attached_to_comment", "setup", "attachment_recorded")
_spec("owner_attached_image_visible", "assertion", "allowed", 200, content=True)
_spec("member_attached_image_visible", "assertion", "allowed", 200, content=True)
_spec("outsider_attached_image_hidden", "assertion", "not_visible", "storage", "storage")
_spec("member_removed", "setup", "membership_removed")
_spec("removed_member_same_jwt_still_valid", "assertion", "authenticated", 200)
_spec("removed_member_exact_row_hidden", "assertion", "not_visible", 200)
_spec("removed_member_snapshot_denied", "assertion", "denied", 400, "P0001")
_spec("removed_member_new_image_request_hidden", "assertion", "not_visible", "storage", "storage")
_spec("owner_read_survives_removal", "assertion", "allowed", 200)
_spec("membership_restored", "restoration", "membership_restored")
_spec("restored_member_exact_row_visible", "restoration", "allowed", 200)
_spec("restored_member_snapshot_visible", "restoration", "allowed", 200)
_spec("restored_member_image_visible", "restoration", "allowed", 200, content=True)
SPECS = tuple(SPECS)
HTTP_EXPORT = {
    "run_id",
    "status",
    "started_at",
    "finished_at",
    "duration_ms",
    "source",
    "runtime",
    "checks",
    "restoration",
    "limitations",
}


class EvidenceError(ValueError):
    """Fixed safe diagnostic; no file contents, tokens or local paths in exceptions."""


def require(condition, code):
    if not condition:
        raise EvidenceError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf8")


def sha(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def number(value, maximum=3_600_000):
    return type(value) is int and 0 <= value <= maximum


def timestamp(value):
    require(isinstance(value, str) and len(value) <= 40, "invalid_timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(result.utcoffset() == timedelta(0), "timestamp_must_be_utc")
        return result
    except ValueError as error:
        raise EvidenceError("invalid_timestamp") from error


def interval(value):
    start, end = timestamp(value["started_at"]), timestamp(value["finished_at"])
    require(start <= end and end - start <= timedelta(hours=1), "invalid_execution_interval")
    return start, end


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    try:
        return json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda _: require(False, "invalid_json_number"),
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise EvidenceError("invalid_evidence_json") from error


def _bounded_path(root, relative):
    path = root / relative
    require(
        not Path(relative).is_absolute() and ".." not in Path(relative).parts,
        "invalid_evidence_path",
    )
    current = root
    for part in Path(relative).parts:
        current /= part
        info = current.lstat()
        require(
            not stat.S_ISLNK(info.st_mode)
            and not (getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT),
            "linked_evidence_path",
        )
    require(path.resolve().is_relative_to(root.resolve()), "evidence_path_escape")
    return path


def _read(root, relative, retained):
    path = _bounded_path(root, relative)
    require(path.is_file() and path.stat().st_size <= MAX_BYTES, "invalid_evidence_file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "evidence_file_too_large")
    retained[str(relative)] = digest(raw)
    return raw


def _candidates(root, relative):
    directory = _bounded_path(root, relative)
    paths = sorted(directory.glob("*.json"))
    require(len(paths) <= 100, "too_many_evidence_files")
    return [path.relative_to(root) for path in paths]


def validate_checks(report):
    rows = report["checks"]
    require(isinstance(rows, list) and 1 <= len(rows) <= len(SPECS), "invalid_check_count")
    normal = [spec for spec in SPECS if spec[1] != "restoration"]
    recovery = [spec for spec in SPECS if spec[1] == "restoration"]
    counts = Counter()
    clean = []
    normal_index = recovery_index = 0
    seen_failure = recovery_failure = False
    for row in rows:
        require(isinstance(row, dict), "invalid_check")
        restoring = row.get("stage") == "restoration"
        if restoring:
            require(
                recovery_index < len(recovery) and not recovery_failure, "invalid_recovery_order"
            )
            spec = recovery[recovery_index]
            recovery_index += 1
        else:
            require(
                not recovery_index and not seen_failure and normal_index < len(normal),
                "invalid_check_order",
            )
            spec = normal[normal_index]
            normal_index += 1
        identifier, stage, outcome, http, code, content = spec
        require(
            row.get("id") == identifier and row.get("stage") == stage, "unexpected_check_identity"
        )
        require(number(row.get("duration_ms")), "invalid_check_duration")
        require(row.get("status") in {"passed", "failed"}, "invalid_check_status")
        item = {key: row[key] for key in ("id", "stage", "status", "duration_ms")}
        if row["status"] == "failed":
            require(
                set(row) == {"id", "stage", "status", "duration_ms", "error_code"},
                "invalid_failed_check",
            )
            require(
                isinstance(row["error_code"], str)
                and re.fullmatch(r"[a-z][a-z0-9_]{0,79}", row["error_code"]),
                "invalid_error_code",
            )
            # Never copy an arbitrary error string into an exported CheckRun.
            item["error_code"] = "local_http_check_failed"
            if restoring:
                recovery_failure = True
            else:
                seen_failure = True
        else:
            keys = {"id", "stage", "status", "duration_ms", "outcome"}
            require(row.get("outcome") == outcome, "unexpected_check_outcome")
            if http is not None:
                keys.add("http_status")
                require(type(row.get("http_status")) is int, "invalid_http_status")
                if http == "storage":
                    require(
                        (row["http_status"], row.get("response_code"))
                        in {
                            (400, "NoSuchKey"),
                            (404, "NoSuchKey"),
                            (403, "AccessDenied"),
                            (400, "not_found"),
                            (403, "not_found"),
                            (404, "not_found"),
                            (400, "unauthorized"),
                            (403, "unauthorized"),
                            (404, "unauthorized"),
                        },
                        "invalid_storage_negative",
                    )
                else:
                    require(
                        row["http_status"] in (http if isinstance(http, tuple) else (http,)),
                        "unexpected_http_status",
                    )
            if code:
                keys.add("response_code")
                require(
                    code == "storage" or row.get("response_code") == code,
                    "unexpected_response_code",
                )
            if content:
                keys.add("content_digest")
                require(row.get("content_digest") == FIXTURE_DIGEST, "unexpected_file_digest")
            require(set(row) == keys, "unexpected_check_metadata")
            item.update({key: row[key] for key in keys - set(item)})
        counts[stage] += 1
        clean.append(item)
    restoration = report["restoration"]
    require(set(restoration) == {"required", "attempted", "status"}, "invalid_restoration")
    require(
        type(restoration["required"]) is bool and type(restoration["attempted"]) is bool,
        "invalid_restoration",
    )
    mutation_attempted = any(row["id"] == "member_removed" for row in rows)
    require(restoration["required"] == mutation_attempted, "restoration_requirement_mismatch")
    if mutation_attempted:
        require(restoration["attempted"] and recovery_index > 0, "missing_required_restoration")
        complete = recovery_index == 4 and not recovery_failure
        require(
            restoration["status"] == ("restored_and_retested" if complete else "failed"),
            "restoration_result_mismatch",
        )
    else:
        require(
            not restoration["attempted"]
            and not recovery_index
            and restoration["status"] == "not_needed",
            "unexpected_restoration",
        )
    if report["status"] == "passed":
        require(
            len(rows) == 32 and not seen_failure and not recovery_failure, "incomplete_passed_run"
        )
    else:
        require(
            report["status"] == "failed" and (seen_failure or recovery_failure),
            "unsupported_failed_run",
        )
    return clean, {stage: counts[stage] for stage in ("setup", "assertion", "restoration")}


def validate_isolation(record):
    require(
        record["schema_version"] == 1
        and record["project"] == PROJECT
        and record["status"] == "passed"
        and record["errors"] == [],
        "isolation_not_passed",
    )
    require(
        record["runtime"]
        == {
            "ipv4_default_route": False,
            "ipv6_default_route": False,
            "external_tcp": "blocked",
            "cron_launch_active_jobs": "off",
        },
        "isolation_runtime_mismatch",
    )
    require(sha(record["topology_sha256"]), "invalid_topology_digest")
    require(
        set(record["source_hashes"])
        == {"lab_config_sha256", "relay_source_sha256", "verifier_source_sha256"}
        and all(sha(value) for value in record["source_hashes"].values()),
        "invalid_isolation_source",
    )
    containers = record["topology"]["containers"]
    require(
        len(containers) == 7 and {row["name"] for row in containers} == set(CONTAINERS),
        "isolation_container_inventory",
    )
    for row in containers:
        require(
            sha(row["id"]) and re.fullmatch(r"sha256:[0-9a-f]{64}", row["image_id"]),
            "invalid_container_identity",
        )
        relay = row["name"] == RELAY
        require(
            set(row["networks"]) == ({PROJECT, EDGE} if relay else {PROJECT}),
            "isolation_network_membership",
        )
        effective = {port: binds for port, binds in (row["ports"] or {}).items() if binds}
        require(
            effective
            == (
                {
                    f"{port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]
                    for port in (55321, 55322, 55324)
                }
                if relay
                else {}
            ),
            "isolation_port_mismatch",
        )
    networks = record["topology"]["networks"]
    require(
        len(networks) == 2
        and {row["name"] for row in networks} == {PROJECT, EDGE}
        and all(row["internal"] is (row["name"] == PROJECT) and sha(row["id"]) for row in networks),
        "isolation_network_inventory",
    )
    return interval(record)


def validate_bundle(bundle):
    """Pure validator; bundle.raw_hashes originate from exact retained local bytes."""
    try:
        receipt, report, state, migration = (
            bundle[key] for key in ("receipt", "http", "state", "migration")
        )
        hashes = bundle["raw_hashes"]
        require(
            receipt["schema_version"] == 1
            and receipt["kind"] == "signalbridge-isolated-supabase-receipt"
            and receipt["app"] == "bettail",
            "invalid_receipt",
        )
        require(
            report["schema_version"] == 1
            and report["app"] == "bettail"
            and report["environment"] == "isolated_supabase_http",
            "invalid_http_source",
        )
        require(
            set(report)
            <= HTTP_EXPORT | {"schema_version", "app", "environment", "identities", "error_code"},
            "unexpected_report_metadata",
        )
        UUID(report["run_id"])
        identities = report.get("identities", {})
        require(
            isinstance(identities, dict)
            and set(identities) <= {"owner", "member", "outsider"}
            and all(sha(value) for value in identities.values()),
            "invalid_identity_metadata",
        )
        require(
            set(receipt["http"]) == HTTP_EXPORT
            and all(receipt["http"][key] == report[key] for key in HTTP_EXPORT),
            "receipt_http_mismatch",
        )
        require(
            receipt["http_report_sha256"] == hashes["http"]
            and receipt["migration_report_sha256"] == hashes["migration"],
            "report_checksum_mismatch",
        )
        source = report["source"]
        require(
            set(source)
            == {
                "migration_digest",
                "harness_sha256",
                "lab_state_sha256",
                "harness_unchanged",
                "lab_state_unchanged",
            },
            "missing_execution_provenance",
        )
        require(
            source["harness_unchanged"] is True and source["lab_state_unchanged"] is True,
            "execution_source_changed",
        )
        require(
            source["harness_sha256"] == hashes["harness"]
            and source["lab_state_sha256"] == hashes["state"],
            "stale_execution_source",
        )
        require(
            set(report["runtime"]) == {"node_version"}
            and re.fullmatch(
                r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?", report["runtime"]["node_version"]
            ),
            "invalid_runtime",
        )
        start, end = interval(report)
        require(
            number(report["duration_ms"])
            and abs(report["duration_ms"] - (end - start).total_seconds() * 1000) <= 1000,
            "invalid_report_duration",
        )
        require(
            state["schema_version"] == 1
            and state["app"] == "bettail"
            and state["isolation_verified"] is True,
            "invalid_readiness",
        )
        manifest = state["migrations"]
        files = manifest["files"]
        require(
            manifest["status"] == "passed"
            and type(manifest["count"]) is int
            and 1 <= manifest["count"] == len(files) <= 1000,
            "invalid_migration_count",
        )
        require(
            all(
                set(row) == {"file", "sha256"}
                and MIGRATION.fullmatch(row["file"])
                and sha(row["sha256"])
                for row in files
            ),
            "invalid_migration_manifest",
        )
        require(
            [row["file"] for row in files] == sorted({row["file"] for row in files}),
            "migration_order_or_duplicate",
        )
        ordered = [{"file": row["file"], "sha256": row["sha256"]} for row in files]
        require(
            source["migration_digest"] == manifest["digest"] == digest(json_bytes(ordered)),
            "migration_digest_mismatch",
        )
        require(
            REVISION.fullmatch(manifest["source_revision"])
            and type(migration["source_dirty"]) is bool
            and sha(state["snapshot_digest"]),
            "invalid_source_identity",
        )
        require(
            migration["schema_version"] == 1
            and migration["app"] == "bettail"
            and migration["status"] == "passed"
            and migration["files"] == ordered
            and migration["applied"] == ordered
            and migration["source_revision"] == manifest["source_revision"]
            and migration["snapshot_digest"] == state["snapshot_digest"],
            "migration_reconciliation_failed",
        )
        require(
            receipt["migration_count"] == len(files)
            and receipt["migrations"]
            == {
                key: migration[key]
                for key in (
                    "status",
                    "started_at",
                    "finished_at",
                    "snapshot_digest",
                    "source_revision",
                    "source_dirty",
                )
            },
            "receipt_migration_mismatch",
        )
        require(interval(migration)[1] <= start, "migration_after_http")
        clean, counts = validate_checks(report)
        require(receipt["check_stage_counts"] == counts, "stage_count_mismatch")
        before, after = bundle["before"], bundle["after"]
        before_start, before_end = validate_isolation(before)
        after_start, after_end = validate_isolation(after)
        require(
            before_end <= start <= end <= after_start
            and start - before_end <= timedelta(minutes=15)
            and after_start - end <= timedelta(minutes=15),
            "isolation_does_not_bracket_run",
        )
        require(
            before["topology_sha256"] == after["topology_sha256"]
            and before["topology"] == after["topology"]
            and before["source_hashes"] == after["source_hashes"],
            "isolation_changed",
        )
        for side, record in (("before", before), ("after", after)):
            reference = receipt["isolation"][side + "_http"]
            require(
                reference["sha256"] == hashes[side]
                and all(
                    reference[key] == record[key]
                    for key in (
                        "started_at",
                        "finished_at",
                        "status",
                        "source_hashes",
                        "topology_sha256",
                        "runtime",
                    )
                ),
                "isolation_receipt_mismatch",
            )
        images = [
            {"container": row["name"], "image_id": row["image_id"]}
            for row in before["topology"]["containers"]
        ]
        require(receipt["images"] == images, "receipt_image_mismatch")
        for key in ("lab_config_sha256", "relay_source_sha256", "verifier_source_sha256"):
            require(before["source_hashes"][key] == hashes[key], "stale_isolation_source")
        result = {
            "evidence_kind": "supabase_http",
            "app": "bettail",
            "status": report["status"],
            "executed_at": report["finished_at"],
            "started_at": report["started_at"],
            "duration_ms": report["duration_ms"],
            "working_tree_dirty": migration["source_dirty"],
            "checks": [row for row in clean if row["stage"] == "assertion"],
            "setup_checks": [row for row in clean if row["stage"] == "setup"],
            "restoration_checks": [row for row in clean if row["stage"] == "restoration"],
            "stage_counts": counts,
            "migration_hashes": ordered,
            "limitations": LIMITATIONS,
            "restoration": dict(report["restoration"]),
            "full_m1_complete": False,
            "provenance": {
                "run_id": report["run_id"],
                "verification": "local_artifact_consistency",
                "http_report_sha256": hashes["http"],
                "receipt_sha256": hashes["receipt"],
                "migration_report_sha256": hashes["migration"],
                "migration_digest": manifest["digest"],
                "snapshot_digest": state["snapshot_digest"],
                "source_revision": manifest["source_revision"],
                "harness_sha256": hashes["harness"],
                "lab_state_sha256": hashes["state"],
                "isolation_before_sha256": hashes["before"],
                "isolation_after_sha256": hashes["after"],
                "topology_sha256": before["topology_sha256"],
                "images": images,
                "runtime": dict(report["runtime"]),
                "isolation_sampled_from": before_start.isoformat(),
                "isolation_sampled_to": after_end.isoformat(),
            },
        }
        return {
            "digest": hashes["http"],
            "revision": manifest["source_revision"],
            "status": report["status"],
            "result": result,
        }
    except (KeyError, TypeError, AttributeError, ValueError, IndexError, OverflowError) as error:
        if isinstance(error, EvidenceError):
            raise
        raise EvidenceError("invalid_assurance_evidence") from error


def load_assurance(root, run_id):
    """No network, process execution, private actor files, alternative app or external path."""
    try:
        require(str(UUID(run_id)) == run_id, "invalid_run_id")
        root = Path(root)
        retained = {}
        receipts = []
        for path in _candidates(root, Path("docs/evidence")):
            raw = _read(root, path, retained)
            data = _json(raw)
            if (
                isinstance(data, dict)
                and data.get("kind") == "signalbridge-isolated-supabase-receipt"
                and data.get("http", {}).get("run_id") == run_id
            ):
                receipts.append((data, digest(raw)))
        require(len(receipts) == 1, "missing_or_conflicting_receipt")
        receipt, receipt_hash = receipts[0]
        bundle = {"receipt": receipt, "raw_hashes": {"receipt": receipt_hash}}
        base = Path("var/labs/bettail")
        inputs = {
            "http": base / "http-runs" / f"{run_id}.json",
            "state": base / "lab-state.json",
            "harness": Path("integrations/supabase-http.mjs"),
            "lab_config_sha256": base / "supabase/config.toml",
            "relay_source_sha256": Path("integrations/supabase/loopback-relay.mjs"),
            "verifier_source_sha256": Path("scripts/verify_supabase_isolation.py"),
        }
        for side in ("before", "after"):
            name = receipt["isolation"][side + "_http"]["receipt"]
            require(
                isinstance(name, str) and ISOLATION_FILE.fullmatch(name),
                "invalid_isolation_filename",
            )
            inputs[side] = Path("artifacts/local/isolation") / name
        for key, path in inputs.items():
            raw = _read(root, path, retained)
            bundle["raw_hashes"][key] = digest(raw)
            if key in {"http", "state", "before", "after"}:
                bundle[key] = _json(raw)
            if key in {"before", "after"}:
                checksum = (
                    _read(root, path.with_suffix(".sha256"), retained).decode("ascii").strip()
                )
                require(checksum == digest(raw), "isolation_checksum_mismatch")
        migrations = []
        for path in _candidates(root, base / "migration-runs"):
            raw = _read(root, path, retained)
            if digest(raw) == receipt["migration_report_sha256"]:
                migrations.append(raw)
        require(len(migrations) == 1, "missing_or_conflicting_migration_report")
        bundle["migration"] = _json(migrations[0])
        bundle["raw_hashes"]["migration"] = digest(migrations[0])
        result = validate_bundle(bundle)
        for relative, expected in list(retained.items()):
            require(
                digest(_read(root, Path(relative), {})) == expected,
                "evidence_changed_during_import",
            )
        return result
    except (OSError, UnicodeError, TypeError, AttributeError, KeyError, ValueError) as error:
        if isinstance(error, EvidenceError):
            raise
        raise EvidenceError("assurance_evidence_unavailable") from error
