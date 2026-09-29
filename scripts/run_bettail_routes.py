"""Run the fixed prepared BetTail route lab; never install or start/stop services.

Keys enter the child through stdin only. Every failure produces no success claim;
a timed-out child is deliberately not killed while it may be restoring membership.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import verify_bettail_routes as gate

LAB = ROOT / "var/labs/bettail"
STATE = LAB / "lab-state.json"
ENV = LAB / ".env"
EVIDENCE = gate.RUNTIME / "evidence"
EXECUTIONS = gate.RUNTIME / "executions"
LOCK = gate.RUNTIME / "execution.lock"
RUN_ID_PATTERN = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
MAX_EVIDENCE_FILES = 1000
MAX_JSON = 2 * 1024 * 1024
MAX_LOG = 1024 * 1024
CHILD_TIMEOUT = 210
HARNESS = {
    "bettail-routes.mjs": ROOT / "integrations/bettail-routes.mjs",
    "supabase-http.mjs": ROOT / "integrations/supabase-http.mjs",
    "runtime.mjs": ROOT / "integrations/bettail-route-runtime.mjs",
}
ROUTE_STEPS = {
    **{
        f"{actor}_sdk_cookie_session_verified": "setup" for actor in ("owner", "member", "outsider")
    },
    **{
        f"{actor}_next_exact_{kind}_visible": "assertion"
        for actor in ("owner", "member")
        for kind in ("state", "image")
    },
    **{
        name: "assertion"
        for name in (
            "outsider_next_state_denied",
            "outsider_next_image_hidden",
            "anonymous_next_state_denied",
            "anonymous_next_image_denied",
            "invalid_next_state_filter_rejected",
            "invalid_next_image_id_rejected",
            "invalid_next_image_scope_rejected",
            "removed_member_same_session_still_auth_valid",
            "removed_member_same_cookie_next_state_denied",
            "removed_member_same_cookie_next_image_hidden",
            "owner_next_state_survives_removal",
            "owner_next_image_survives_removal",
        )
    },
    "route_member_removed": "setup",
    **{
        name: "restoration"
        for name in (
            "route_membership_restored",
            "restored_member_next_state_visible",
            "restored_member_next_image_visible",
        )
    },
}
SERVICE_STEPS = {
    **{
        f"{actor}_{name}": "setup"
        for actor in ("owner", "member", "outsider")
        for name in (
            "auth_creation_and_password_login",
            "profile_ready",
        )
    },
    **{
        name: "setup"
        for name in (
            "synthetic_group_and_pick_seeded",
            "private_image_reserved_and_uploaded",
            "owner_image_attached_to_comment",
            "member_removed",
        )
    },
    **{
        f"{actor}_{name}": "assertion"
        for actor in ("owner", "member")
        for name in (
            "exact_row_visible",
            "snapshot_visible",
            "attached_image_visible",
        )
    },
    **{
        name: "assertion"
        for name in (
            "outsider_exact_row_hidden",
            "outsider_snapshot_denied",
            "anonymous_table_read_denied",
            "anonymous_snapshot_denied",
            "owner_draft_image_visible",
            "member_unattached_draft_hidden",
            "outsider_attached_image_hidden",
            "removed_member_same_jwt_still_valid",
            "removed_member_exact_row_hidden",
            "removed_member_snapshot_denied",
            "removed_member_new_image_request_hidden",
            "owner_read_survives_removal",
        )
    },
    **{
        name: "restoration"
        for name in (
            "membership_restored",
            "restored_member_exact_row_visible",
            "restored_member_snapshot_visible",
            "restored_member_image_visible",
        )
    },
}
LIMITS = [
    "Builder-operated local evidence, not independent audit or enterprise-platform parity.",
    "Only two development Next GET routes and synthetic official-SDK password sessions are covered.",
    "No interactive OTP/OAuth flow, production cookie/refresh proof, signed URL, policy fault or source-owned event delivery.",
    "Synthetic identities and objects are retained privately; membership restoration is checked separately.",
    "Isolation is checked before and after, not monitored continuously; the host/Docker administrator is trusted.",
    "Timeout requires manual recovery review; the runner never kills a possibly restoring child or stops services.",
    "Request counts cover harness-issued requests only, excluding Next upstream calls, warmup and isolation probes.",
    "Exclusive files and atomic recovery updates do not establish fsync-backed host-crash durability.",
]


class RunError(Exception):
    """Fixed diagnostic only; never include private values or subprocess output."""


def require(condition, code):
    if not condition:
        raise RunError(code)


def read_bytes(path, maximum=MAX_JSON):
    require(gate._safe(path, directory=False).st_size <= maximum, "input_size_limit")
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    require(len(raw) <= maximum, "input_size_limit")
    return raw


def read_json(path):
    raw = read_bytes(path)
    return json.loads(raw, object_pairs_hook=gate._unique_json), gate.base.sha256(raw)


def verify_inputs():
    """Prove the stored migration binding and reviewed mounted code before reading keys."""
    state, state_hash = read_json(STATE)
    contract = gate.read_contract()
    require(
        isinstance(state, dict)
        and set(state)
        == {
            "schema_version",
            "app",
            "isolation_verified",
            "snapshot_digest",
            "migrations",
        },
        "lab_state_schema",
    )
    require(
        type(state["schema_version"]) is int
        and state["schema_version"] == 1
        and state["app"] == "bettail"
        and state["isolation_verified"] is True
        and state["snapshot_digest"] == contract["snapshot_digest"],
        "lab_state_identity",
    )
    snapshot = ROOT / "private-source/bettail" / contract["snapshot_digest"]
    metadata = gate.snapshot_app.verify_snapshot(snapshot, workspace=ROOT)
    migrations = state["migrations"]
    require(
        isinstance(migrations, dict)
        and set(migrations)
        == {
            "status",
            "count",
            "files",
            "source_revision",
            "digest",
        },
        "migration_state_schema",
    )
    files = [
        {"file": name.removeprefix("supabase/migrations/"), "sha256": digest}
        for name, digest in sorted(metadata["files"].items())
        if name.startswith("supabase/migrations/")
    ]
    require(
        files and all(re.fullmatch(r"\d+_[A-Za-z0-9_]+\.sql", row["file"]) for row in files),
        "migration_manifest_shape",
    )
    expected_digest = gate.base.sha256(json.dumps(files, separators=(",", ":")).encode())
    require(
        migrations["status"] == "passed"
        and type(migrations["count"]) is int
        and migrations["count"] == len(files)
        and migrations["files"] == files
        and migrations["source_revision"] == metadata["source_revision"]
        and re.fullmatch(r"[0-9a-f]{40}", metadata["source_revision"])
        and migrations["digest"] == expected_digest,
        "migration_source_mismatch",
    )
    reviewed = {}
    for name, source in HARNESS.items():
        expected = gate.base.sha256(read_bytes(source))
        require(
            contract["harness_files"][name] == expected
            and gate.base.sha256(read_bytes(gate.RUNTIME / "lab" / name)) == expected,
            "mounted_harness_differs_from_reviewed_source",
        )
        reviewed[name] = expected
    return {
        "provenance": {
            "migration_digest": expected_digest,
            "snapshot_digest": metadata["snapshot_digest"],
            "source_revision": metadata["source_revision"],
        },
        "source_dirty": metadata["source_dirty"],
        "migration_count": len(files),
        "lab_state_sha256": state_hash,
        "reviewed_harness_sha256": reviewed,
        "runtime_contract_sha256": gate.base.sha256(gate.base.canonical(contract)),
        "runner_sha256": gate.base.sha256(read_bytes(Path(__file__))),
    }


def parse_keys(raw):
    require(isinstance(raw, bytes) and len(raw) <= 65536, "lab_key_file_invalid")
    text = raw.decode("utf-8-sig")
    names = {
        "SUPABASE_AUTH_PUBLISHABLE_KEY": "publishableKey",
        "SUPABASE_AUTH_SECRET_KEY": "secretKey",
    }
    result = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*", line)
        if not match:
            require(not any(name in line for name in names), "lab_key_line_invalid")
            continue
        name, value = match.groups()
        if name not in names:
            continue
        require(names[name] not in result, "duplicate_lab_key")
        if len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
            value = value[1:-1]
        prefix = "publishable" if names[name] == "publishableKey" else "secret"
        require(
            re.fullmatch(rf"sb_{prefix}_[A-Za-z0-9_-]{{20,200}}", value), "lab_key_value_invalid"
        )
        result[names[name]] = value
    require(set(result) == set(names.values()), "lab_keys_missing")
    return result


WARMUP = """(async()=>{
const end=Date.now()+120000;const results=[];
for(const path of ['/api/state','/api/chat-image?comment_id=00000000-0000-4000-8000-000000000001']){
 let status=0;
 for(let attempt=0;attempt<4&&Date.now()<end;attempt++){
  try{const response=await fetch('http://127.0.0.1:3101'+path,{method:'GET',redirect:'error',signal:AbortSignal.timeout(Math.max(1,Math.min(60000,end-Date.now())))});
   status=response.status;await response.body?.cancel();if(status===401)break;
  }catch{status=0;}if(Date.now()<end)await new Promise(resolve=>setTimeout(resolve,250));
 }results.push(status);if(status!==401)break;
}process.stdout.write(JSON.stringify({statuses:results}));if(results.length!==2||results.some(status=>status!==401))process.exitCode=1;
})().catch(()=>{process.stderr.write('warmup_failed');process.exitCode=1});"""


def warmup():
    output = gate.base.docker(["exec", gate.NEXT, "node", "-e", WARMUP], timeout=130)
    require(json.loads(output) == {"statuses": [401, 401]}, "anonymous_warmup_failed")
    return {"status": "passed", "anonymous_route_statuses": [401, 401], "maximum_seconds": 120}


def docker_command():
    installed = (
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/DockerDesktop/resources/bin/docker.exe"
    )
    executable = str(installed) if installed.is_file() else shutil.which("docker")
    require(executable, "docker_executable_missing")
    return [
        executable,
        "--host",
        gate.base.PIPE,
        "exec",
        "-i",
        gate.NEXT,
        "node",
        "/lab/bettail-routes.mjs",
    ]


def run_child(payload, directory):
    """Keep bounded private logs, and never terminate a child on the restoration deadline."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LOCALAPPDATA"}
    }
    paths = {name: directory / name for name in ("stdout.txt", "stderr.txt")}
    handles = {name: path.open("xb") for name, path in paths.items()}
    process = None
    overflow = threading.Event()
    failure = threading.Event()

    def drain(stream, handle):
        size = 0
        try:
            while chunk := stream.read(8192):
                remaining = max(0, MAX_LOG - size)
                handle.write(chunk[:remaining])
                handle.flush()
                size += len(chunk)
                if size > MAX_LOG:
                    overflow.set()
        except (OSError, ValueError):
            failure.set()
        finally:
            handle.close()
            stream.close()

    try:
        process = subprocess.Popen(
            docker_command(),
            cwd=ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        threads = [
            threading.Thread(target=drain, args=(stream, handles[name]), daemon=True)
            for name, stream in (("stdout.txt", process.stdout), ("stderr.txt", process.stderr))
        ]
        for thread in threads:
            thread.start()
        # The fixed key formats and small provenance record keep stdin below a pipe buffer.
        body = gate.base.canonical(payload)
        require(len(body) <= 2048, "child_input_size")
        process.stdin.write(body)
        process.stdin.close()
        try:
            code = process.wait(timeout=CHILD_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {
                "exit_code": None,
                "timed_out": True,
                "logs_complete": False,
                "log_overflow": overflow.is_set(),
            }
        for thread in threads:
            thread.join(timeout=3)
        return {
            "exit_code": code,
            "timed_out": False,
            "logs_complete": not failure.is_set()
            and not any(thread.is_alive() for thread in threads),
            "log_overflow": overflow.is_set(),
        }
    except (OSError, ValueError):
        raise RunError("child_launch_or_stream_failure") from None
    finally:
        if process is None:
            for handle in handles.values():
                handle.close()


def validate_report(report, *, run_id, provenance, stages, environment):
    require(
        isinstance(report, dict)
        and type(report.get("schema_version")) is int
        and report["schema_version"] == 1
        and report.get("app") == "bettail"
        and report.get("run_id") == run_id
        and report.get("environment") == environment,
        "child_report_identity",
    )
    require(report.get("status") == "passed", "child_report_failed")
    source = report.get("source")
    require(
        isinstance(source, dict)
        and all(source.get(name) == value for name, value in provenance.items()),
        "child_report_source",
    )
    checks = report.get("checks")
    require(isinstance(checks, list) and len(checks) == len(stages), "child_report_check_count")
    require(
        all(
            isinstance(row, dict)
            and row.get("id") in stages
            and row.get("stage") == stages[row["id"]]
            and row.get("status") == "passed"
            and type(row.get("duration_ms")) is int
            and 0 <= row["duration_ms"] <= 150000
            for row in checks
        )
        and len({row["id"] for row in checks}) == len(stages),
        "child_report_check_inventory",
    )
    require(
        report.get("restoration")
        == {"required": True, "attempted": True, "status": "restored_and_retested"},
        "child_report_restoration",
    )
    return {
        "executed": len(checks),
        "passed": len(checks),
        "stages": dict(Counter(stages.values())),
    }


def read_results(run_id, inputs):
    route, route_hash = read_json(EVIDENCE / (run_id + ".json"))
    service, service_hash = read_json(EVIDENCE / (run_id + ".service.json"))
    private, _ = read_json(EVIDENCE / (run_id + ".private.json"))
    require(
        isinstance(private, dict)
        and private.get("run_id") == run_id
        and private.get("restore_required") is False
        and private.get("route_restore_required") is False
        and isinstance(private.get("service"), dict)
        and private["service"].get("run_id") == run_id
        and private["service"].get("restore_required") is False,
        "recovery_state_not_verified",
    )
    route_counts = validate_report(
        route,
        run_id=run_id,
        provenance=inputs["provenance"],
        stages=ROUTE_STEPS,
        environment="isolated_next_routes",
    )
    service_counts = validate_report(
        service,
        run_id=run_id,
        provenance={"migration_digest": inputs["provenance"]["migration_digest"]},
        stages=SERVICE_STEPS,
        environment="isolated_supabase_http",
    )
    source = route["source"]
    for field, name in (
        ("harness_sha256", "bettail-routes.mjs"),
        ("service_harness_sha256", "supabase-http.mjs"),
    ):
        require(
            source.get(field) == inputs["reviewed_harness_sha256"][name]
            and source.get(field + "_unchanged") is True,
            "child_harness_source",
        )
    require(
        route.get("runtime")
        == {
            "node_version": "v24.20.0",
            "supabase_ssr_version": "0.12.7",
            "next_mode": "development",
        },
        "child_runtime_identity",
    )
    require(
        type(route.get("request_count")) is int and 1 <= route["request_count"] <= 160,
        "child_request_bound",
    )
    require(
        route.get("service_setup")
        == {
            "status": "passed",
            "executed": 32,
            "passed": 32,
            "restoration": "restored_and_retested",
        },
        "service_summary_mismatch",
    )
    return {
        "route": route_counts,
        "service": service_counts,
        "request_count": route["request_count"],
        "route_report_sha256": route_hash,
        "service_report_sha256": service_hash,
        "restoration": "restored_and_retested",
        "runtime": dict(route["runtime"]),
    }


def verify_run_inventory(run_id):
    """A replacement in progress invalidates even an older explicit false marker."""
    require(re.fullmatch(RUN_ID_PATTERN, run_id) is not None, "recovery_run_identity")
    gate._safe(EVIDENCE, directory=True)
    expected = {run_id + suffix for suffix in (".json", ".private.json", ".service.json")}
    found = set()
    with os.scandir(EVIDENCE) as entries:
        for count, entry in enumerate(entries, 1):
            require(count <= MAX_EVIDENCE_FILES, "recovery_inventory_limit")
            path = Path(entry.path)
            if path.name.casefold().startswith(run_id + "."):
                gate._safe(path, directory=False)
                require(path.name in expected, "recovery_replacement_pending_or_unknown")
                found.add(path.name)
    require(found == expected, "recovery_evidence_incomplete")


def recovery_clear(run_id):
    """Only final matching reports and explicit false recovery markers permit another run."""
    verify_run_inventory(run_id)
    private, _ = read_json(EVIDENCE / (run_id + ".private.json"))
    require(
        isinstance(private, dict)
        and type(private.get("schema_version")) is int
        and private.get("schema_version") == 1
        and private.get("run_id") == run_id
        and "state" not in private
        and private.get("restore_required") is False
        and private.get("route_restore_required") is False
        and isinstance(private.get("service"), dict)
        and private["service"].get("run_id") == run_id
        and private["service"].get("restore_required") is False,
        "prior_recovery_unresolved",
    )
    for suffix, environment in (
        (".json", "isolated_next_routes"),
        (".service.json", "isolated_supabase_http"),
    ):
        report, _ = read_json(EVIDENCE / (run_id + suffix))
        require(
            isinstance(report, dict)
            and type(report.get("schema_version")) is int
            and report.get("schema_version") == 1
            and report.get("run_id") == run_id
            and report.get("environment") == environment
            and report.get("status") in {"passed", "failed"},
            "prior_recovery_unresolved",
        )
        restoration = report.get("restoration")
        require(
            restoration
            in (
                {"required": False, "attempted": False, "status": "not_needed"},
                {"required": True, "attempted": True, "status": "restored_and_retested"},
            ),
            "prior_recovery_unresolved",
        )
    verify_run_inventory(run_id)
    return True


def recovery_preflight():
    gate._safe(EVIDENCE, directory=True)
    runs, files = set(), set()
    with os.scandir(EVIDENCE) as entries:
        for entry in entries:
            require(len(files) < MAX_EVIDENCE_FILES, "prior_evidence_inventory_limit")
            path = Path(entry.path)
            gate._safe(path, directory=False)
            match = re.fullmatch(
                rf"({RUN_ID_PATTERN})(\.private\.json|\.service\.json|\.json)", path.name
            )
            require(match is not None, "prior_evidence_pending_or_unknown")
            files.add(path.name)
            runs.add(match[1])
    for run_id in sorted(runs):
        require(
            {run_id + suffix for suffix in (".json", ".private.json", ".service.json")}.issubset(
                files
            ),
            "prior_evidence_incomplete",
        )
        recovery_clear(run_id)
    return {"prior_runs_checked": len(runs), "unresolved": 0}


def acquire_lock(run_id):
    gate._safe(LOCK.parent, directory=True)
    body = gate.base.canonical(
        {
            "schema_version": 1,
            "run_id": run_id,
            "warning": "Do not remove until the scoped child and recovery evidence are reviewed.",
        }
    )
    try:
        with LOCK.open("xb") as handle:
            handle.write(body)
    except FileExistsError:
        raise RunError("route_execution_locked_recovery_review_required") from None
    gate._safe(LOCK, directory=False)
    return body


def verify_lock(body):
    require(read_bytes(LOCK, 2048) == body, "execution_lock_changed")


def release_lock(body):
    verify_lock(body)
    # Exactly this fixed, checked ordinary file, never a recursive cleanup.
    LOCK.unlink()


def mkdir_private(path):
    current = ROOT
    for part in path.relative_to(ROOT).parts:
        current = current / part
        if not current.exists():
            gate._safe(current.parent, directory=True)
            current.mkdir()
        gate._safe(current, directory=True)


def write_receipt(directory, name, value):
    gate._safe(directory, directory=True)
    body = json.dumps(value, indent=2).encode() + b"\n"
    with (directory / name).open("xb") as handle:
        handle.write(body)
    with (directory / (name + ".sha256")).open("x", encoding="ascii") as handle:
        handle.write(gate.base.sha256(body) + "\n")
    return gate.base.sha256(body)


def run():
    run_id = str(uuid.uuid4())
    directory = EXECUTIONS / run_id
    mkdir_private(EXECUTIONS)
    directory.mkdir()  # Exclusive UUID directory; never overwrite an earlier execution.
    gate._safe(directory, directory=True)
    report = {
        "schema_version": 1,
        "kind": "signalbridge-bettail-route-execution",
        "run_id": run_id,
        "started_at": datetime.now(UTC).isoformat(),
        "status": "failed",
        "errors": [],
        "restore_required": False,
        "coverage_limits": LIMITS,
    }
    before = None
    gate_attempted = False
    child_started = False
    isolation_before = None
    lock = None
    try:
        lock = acquire_lock(run_id)
        report["restore_required"] = True
        report["recovery_preflight"] = recovery_preflight()
        report["restore_required"] = False
        before = verify_inputs()
        report["source_before"] = before
        gate_attempted = True
        isolation = gate.run_verification()
        report["isolation_before_sha256"] = write_receipt(
            directory, "isolation-before.json", isolation
        )
        require(
            isolation.get("status") == "passed" and isolation.get("errors") == [],
            "isolation_before_failed",
        )
        require(
            gate._digest(isolation.get("topology_sha256"))
            and isinstance(isolation.get("source_hashes"), dict),
            "isolation_before_identity",
        )
        isolation_before = {
            "topology_sha256": isolation["topology_sha256"],
            "source_hashes": isolation["source_hashes"],
        }
        report["warmup"] = warmup()
        require(verify_inputs() == before, "source_changed_during_warmup")
        verify_lock(lock)
        keys = parse_keys(read_bytes(ENV, 65536))
        report["restore_required"] = True
        child_started = True
        child = run_child({**keys, "provenance": before["provenance"], "runId": run_id}, directory)
        del keys
        report["child"] = child
        require(not child["timed_out"], "child_timeout_recovery_required")
        require(child["logs_complete"] and not child["log_overflow"], "child_log_capture_failed")
        report["results"] = read_results(run_id, before)
        report["restore_required"] = False
        require(child["exit_code"] == 0, "child_exit_failed")
    except RunError as error:
        report["errors"].append(str(error))
        if str(error) == "route_execution_locked_recovery_review_required":
            report["restore_required"] = True
    except (gate.VerificationError, OSError, ValueError, KeyError, TypeError, AttributeError):
        report["errors"].append("route_execution_input_or_runtime_failure")
    finally:
        if gate_attempted:
            try:
                isolation = gate.run_verification()
                report["isolation_after_sha256"] = write_receipt(
                    directory, "isolation-after.json", isolation
                )
                require(
                    isolation.get("status") == "passed" and isolation.get("errors") == [],
                    "isolation_after_failed",
                )
                if isolation_before is not None:
                    require(
                        isolation_before
                        == {
                            "topology_sha256": isolation.get("topology_sha256"),
                            "source_hashes": isolation.get("source_hashes"),
                        },
                        "lab_changed_during_execution",
                    )
            except RunError as error:
                report["errors"].append(str(error))
            except (
                gate.VerificationError,
                OSError,
                ValueError,
                KeyError,
                TypeError,
                AttributeError,
            ):
                report["errors"].append("isolation_after_unavailable")
        if before is not None:
            try:
                after = verify_inputs()
                report["source_after"] = after
                require(after == before, "execution_source_changed")
            except RunError as error:
                report["errors"].append(str(error))
            except (
                gate.VerificationError,
                OSError,
                ValueError,
                KeyError,
                TypeError,
                AttributeError,
            ):
                report["errors"].append("source_after_unavailable")
        if child_started and report.get("child", {}).get("timed_out") is False:
            try:
                report["restore_required"] = not recovery_clear(run_id)
            except (
                RunError,
                gate.VerificationError,
                OSError,
                ValueError,
                KeyError,
                TypeError,
                AttributeError,
            ):
                report["restore_required"] = True
                report["errors"].append("recovery_review_required")
        report["lock_retained"] = lock is not None or (
            "route_execution_locked_recovery_review_required" in report["errors"]
        )
        if lock is not None and not report["restore_required"]:
            try:
                release_lock(lock)
                report["lock_retained"] = False
            except (RunError, gate.VerificationError, OSError, ValueError):
                report["errors"].append("execution_lock_release_failed")
        report["child_started"] = child_started
        if not report["errors"] and "results" in report and not report["restore_required"]:
            report["status"] = "passed"
        report["finished_at"] = datetime.now(UTC).isoformat()
        write_receipt(directory, "execution.json", report)
    return report, directory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)  # No alternate target, command, input, or service lifecycle option.
    try:
        report, directory = run()
    except (RunError, gate.VerificationError, OSError, ValueError):
        print("Route runner could not preserve its private execution record. No success claimed.")
        return 1
    print(
        f"BetTail route execution: {report['status']}. Private record: {directory.relative_to(ROOT)}/execution.json"
    )
    if report["restore_required"]:
        print(
            "Recovery evidence needs review before another run. Membership restoration may or may not be needed; a timed-out child may still be running. No process was killed."
        )
    if report["errors"]:
        print("Checks requiring attention: " + ", ".join(report["errors"]))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
