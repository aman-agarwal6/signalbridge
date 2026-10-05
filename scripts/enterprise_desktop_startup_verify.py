"""One separately authorized Docker Desktop startup diagnostic; no acquisition.

Approval references record permission, never grant it. Import is inert. The
unchanged acquisition guard owns one startup and shutdown; its legacy phase
marker does not permit downloads, images, containers or a native integration.
"""

import argparse
import hashlib
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrations.enterprise import desktop_startup_guard as guard
from integrations.enterprise.verification import LabControlError, private_run_directory
from scripts.record_verification import receipt_path

DOCKER = Path(r"C:\Users\agarw\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe")
PLAN = "integrations/enterprise/desktop-startup-stage-plan.json"
REVIEWED_FILES = (
    "scripts/enterprise_desktop_startup_verify.py",
    PLAN,
    "integrations/enterprise/desktop_startup_guard.py",
    "integrations/enterprise/windows_capacity.py",
    "scripts/enterprise_reference_verify.py",
    "integrations/enterprise/reference-private-acl.ps1",
)
LIFECYCLE = ("context", "ready", "intent", "finished", "watchdog", "launcher")


def require(condition):
    if not condition:
        raise LabControlError("Startup diagnostic refused an unsafe or unknown state.")


def validate_request(docker, approval):
    """Use one supplied installed executable; no PATH search or replacement."""
    docker = Path(docker)
    require(sys.platform == "win32" and ROOT.name == "signalbridge-public")
    require((ROOT / "manage.py").is_file())
    require(docker == DOCKER and docker.is_absolute() and docker.is_file())
    for path in (docker, *docker.parents):
        require(
            not path.is_symlink() and not getattr(path.lstat(), "st_file_attributes", 0) & 0x400
        )
    require(isinstance(approval, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", approval))
    return docker


def write(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("ascii")
    require(len(raw) <= 262144 and not path.exists() and not path.is_symlink())
    with path.open("xb") as stream:
        stream.write(raw)


def reviewed_hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in REVIEWED_FILES}


def reconcile(owner, baseline, approval):
    """A receipt from another run, baseline or deadline cannot prove closure."""
    require(private_run_directory(ROOT, owner.run) == owner.directory)
    guard.private_acl(owner.run, "Verify")
    rows = {name: guard.load(owner.directory, name) for name in LIFECYCLE}
    require(all(type(row) is dict and row.get("run_id") == owner.run for row in rows.values()))
    context, watchdog, launcher = rows["context"], rows["watchdog"], rows["launcher"]
    require(
        context.get("approval_reference") == approval
        and type(context.get("stage_initial_free_disk_bytes")) is int
        and context["stage_initial_free_disk_bytes"] == baseline
        and type(context.get("deadline")) in (int, float)
        and context["deadline"] == owner.deadline
        and context.get("initial_desktop_status") == "stopped"
        and rows["ready"] == {"run_id": owner.run, "armed": True}
        and rows["ready"].get("armed") is True
        and rows["intent"] == {"run_id": owner.run, "start_requested": True}
        and rows["intent"].get("start_requested") is True
        and rows["finished"] == {"run_id": owner.run}
        and watchdog.get("kind") == "docker-desktop-startup-watchdog"
        and launcher.get("start_requested") is True
    )
    shutdown = watchdog.get("shutdown", {})
    require(type(shutdown) is dict)
    samples = [context.get("capacity_before", {})]
    for row in (watchdog, launcher):
        require(type(row.get("samples")) is list and len(row["samples"]) <= 800)
        samples.extend(row["samples"])
    require(all(type(sample) is dict for sample in samples))
    errors = {
        key: value
        for row in (watchdog, launcher, shutdown)
        for key, value in row.items()
        if key.endswith("error_class") and value is not None
    }
    observation = shutdown.get("last_desktop_observation", {})
    return {
        "receipts_bound": True,
        "launcher_shutdown_verified": launcher.get("shutdown_verified") is True,
        "watchdog_shutdown_verified": (
            watchdog.get("shutdown_verified") is True and shutdown.get("shutdown_verified") is True
        ),
        "guard_pending": launcher.get("guard_pending") is not False,
        "foreign_workload_preserved": shutdown.get("foreign_workload_preserved") is True,
        "cli_timeout_seen": shutdown.get("cli_timeout_seen") is True,
        "error_classes": errors,
        "watchdog_finished_normally": watchdog.get("reason") == "launcher_finished",
        "stopped_observation_verified": (
            type(observation) is dict
            and observation.get("status") == "stopped"
            and shutdown.get("reason") == "observed_stopped_during_bounded_drain"
            and type(shutdown.get("stopped_observation_seconds")) in (int, float)
            and guard.STABLE_SECONDS
            <= shutdown["stopped_observation_seconds"]
            <= guard.CLEANUP_SECONDS
        ),
        "all_retained_capacity_samples_within_limits": (
            len(samples) >= 3 and all(sample.get("within_limits") is True for sample in samples)
        ),
        "samples": samples,
        "receipt_sha256": {
            name: hashlib.sha256(
                (owner.directory / f"desktop-{name}.json").read_bytes()
            ).hexdigest()
            for name in LIFECYCLE
        },
    }


def outcome(stage):
    lifecycle = stage.get("lifecycle", {})
    passed = bool(
        stage.get("startup_observed") is True
        and "error_class" not in stage
        and "closure_error_class" not in stage
        and lifecycle.get("receipts_bound") is True
        and lifecycle.get("launcher_shutdown_verified") is True
        and lifecycle.get("watchdog_shutdown_verified") is True
        and lifecycle.get("stopped_observation_verified") is True
        and lifecycle.get("watchdog_finished_normally") is True
        and lifecycle.get("all_retained_capacity_samples_within_limits") is True
        and lifecycle.get("guard_pending") is False
        and lifecycle.get("foreign_workload_preserved") is False
        and lifecycle.get("cli_timeout_seen") is False
        and lifecycle.get("error_classes") == {}
        and stage.get("final_desktop_observation", {}).get("status") == "stopped"
        and stage.get("capacity_after_shutdown", {}).get("within_limits") is True
    )
    return {
        "schema_version": 1,
        "kind": "signalbridge-desktop-startup-diagnostic",
        "run_id": stage["run_id"],
        "guard_run_id": stage.get("guard_run_id"),
        "recorded_at": stage["finished_at"],
        "status": "startup_diagnostic_passed" if passed else "incomplete",
        "startup_observed": stage.get("startup_observed") is True,
        "receipts_bound": lifecycle.get("receipts_bound") is True,
        "shutdown_verified": bool(
            lifecycle.get("launcher_shutdown_verified") is True
            and lifecycle.get("watchdog_shutdown_verified") is True
            and lifecycle.get("stopped_observation_verified") is True
        ),
        "final_stopped_status_verified": (
            stage.get("final_desktop_observation", {}).get("status") == "stopped"
        ),
        "final_stopped_status_source": stage.get("final_desktop_observation", {}).get("source"),
        "error_class": stage.get("error_class"),
        "closure_error_class": stage.get("closure_error_class"),
        "cli_errors_retained": bool(
            lifecycle.get("error_classes") or lifecycle.get("cli_timeout_seen")
        ),
        "foreign_workload_preserved": lifecycle.get("foreign_workload_preserved") is True,
        "reviewed_file_sha256": stage["reviewed_file_sha256"],
        "guard_receipt_sha256": lifecycle.get("receipt_sha256", {}),
        "downloads": 0,
        "containers_created": 0,
        "keycloak_or_native_integration_verified": False,
        "sampled_guards_are_hard_quotas": False,
        "late_start_origin_established": False,
        "daemon_request_settlement_verified": False,
        "permanent_desktop_absence_verified": False,
    }


def launch(docker, approval_reference):
    """Exactly one guarded start; no retry, acquisition or native handoff."""
    docker = validate_request(docker, approval_reference)
    guard.environment()  # Required OS paths must pass before even the private ACL child.
    run = uuid.uuid4().hex
    directory = private_run_directory(ROOT, run)
    directory.mkdir(parents=True, exist_ok=False)
    guard.private_acl(run, "SecureEmpty")
    stage = {
        "run_id": run,
        "kind": "desktop-startup-only-stage",
        "approval_reference": approval_reference,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "reviewed_file_sha256": reviewed_hashes(),
        "startup_observed": False,
    }
    owner = None
    try:
        # This is measured locally now; an operator cannot supply a stale baseline.
        baseline = guard.shutil.disk_usage(ROOT).free
        require(type(baseline) is int and baseline > 0)
        stage["stage_initial_free_disk_bytes"] = baseline
        stage["capacity_before"] = guard.sample(baseline, before_start=True)
        require(stage["capacity_before"]["within_limits"] is True)
        owner = guard.DesktopStartup(docker, approval_reference, baseline)
        with owner:
            stage["guard_run_id"] = owner.run
            owner.start()
            owner.check("startup")
            observation = {}
            require(guard.desktop_status(docker, owner.env, capture=observation) == "running")
            stage["running_desktop_observation"] = observation
            stage["running_engine_inventory"] = guard.inventory(docker, owner.env)
            stage["capacity_after_running"] = guard.sample(baseline)
            require(stage["running_engine_inventory"] == "empty")
            require(stage["capacity_after_running"]["within_limits"] is True)
            owner.check("startup")
            stage["startup_observed"] = True
            # Immediate scope exit invokes the existing independent shutdown.
    except BaseException as error:
        stage["error_class"] = type(error).__name__
    finally:
        if owner is not None and hasattr(owner, "run"):
            stage["guard_run_id"] = owner.run
            try:
                stage["lifecycle"] = reconcile(owner, baseline, approval_reference)
                final = {}
                guard.desktop_status(docker, owner.env, capture=final)
                stage["final_desktop_observation"] = final
                stage["capacity_after_shutdown"] = guard.sample(baseline)
            except Exception as error:
                stage["closure_error_class"] = type(error).__name__
        stage["finished_at"] = datetime.now(timezone.utc).isoformat()
        public = outcome(stage)
        stage["public_result"] = public
        guard.private_acl(run, "Verify")
        write(directory / "desktop-startup-stage.json", stage)
        identity = datetime.now(timezone.utc).strftime("%Y%m%d") + "-desktop-startup-" + run
        public_path = receipt_path(ROOT, "docs/evidence/" + identity + ".json", identity)
        write(public_path, public)
    return directory, public_path, public["status"] == "startup_diagnostic_passed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["launch"])
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--approval-reference", required=True)
    options = parser.parse_args()
    _, public, passed = launch(options.docker, options.approval_reference)
    print("Startup-only result retained: " + str(public))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
