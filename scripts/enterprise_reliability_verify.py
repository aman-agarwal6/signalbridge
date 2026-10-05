"""Reviewed paced 24-hour reliability stage, or its explicitly shortened rehearsal.

Runs the reference source, console, courier, two workers and live SOC export on
the unchanged 47,760-read schedule with the fixed interruptions, then measures
the retained ledger with the declared analyzer. A rehearsal stops early, scales
the windows and is never presented as the 24-hour result. It reuses the
reference stage's preparation, independent watchdog and shutdown checks. Never
pulls images, deletes data or exposes ports. Windows is asked to stay awake.
"""

import argparse
import ctypes
import json
import re
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrations.enterprise import network_verification as cached
from integrations.enterprise import reference_host_controls as host
from integrations.enterprise import reliability_wazuh as wazuh
from integrations.enterprise import verification as base
from integrations.enterprise.reference_controls import (
    reliability_subnet,
    verify_compose_config,
)
from integrations.enterprise.reference_host_evidence import validate_shutdown
from integrations.enterprise.reliability import DAY_MS, FINAL_DRAIN_MS
from integrations.enterprise.reliability_measure import evaluate
from scripts import enterprise_reference_verify as reference
from scripts.record_verification import receipt_path, source_manifest

PROFILE = "reliability"
# A rehearsal plus setup must fit inside the short two-hour certificate lifetime.
REHEARSAL_RANGE_MINUTES = (5, 90)
CERTIFICATE_HOURS = 26
ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001


def keep_awake(enabled):
    """Ask Windows not to sleep while this process runs; no setting is changed."""
    flags = ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if enabled else 0)
    return bool(ctypes.windll.kernel32.SetThreadExecutionState(flags))


ROLES = ["database", "runner", "wazuh"]


def no_foreign_running(docker, targets=()):
    """Only this run's three exact components may run; others need a new review."""
    raw = base.docker_result(docker, ["ps", "--quiet", "--no-trunc"], timeout=5)
    identifiers = raw.splitlines() if raw else []
    if (
        len(identifiers) > len(ROLES)
        or len(identifiers) != len(set(identifiers))
        or any(not re.fullmatch(r"[a-f0-9]{64}", identifier) for identifier in identifiers)
        or not set(identifiers).issubset(targets)
    ):
        raise base.LabControlError("Other running containers require a revised launch review.")


def exact_components(docker, run, directory, images, rehearsal_ms):
    targets = host.owned(docker, run)
    if sorted(targets.values()) != ROLES:
        raise base.LabControlError("The exact reliability components were not verified.")
    for identifier in targets:
        host.verify_runtime(
            docker, identifier, run, directory, images, profile=PROFILE, rehearsal_ms=rehearsal_ms
        )
    host.verify_network_volume(docker, run, targets)
    return targets


def subnet_free(docker, subnet):
    """Refuse a run-derived subnet that any existing network already uses."""
    names = base.docker_result(docker, ["network", "ls", "--format", "{{.Name}}"], timeout=10)
    for name in names.splitlines():
        raw = base.docker_result(
            docker,
            ["network", "inspect", name, "--format", "{{json .IPAM.Config}}"],
            timeout=5,
        )
        if subnet in raw:
            raise base.LabControlError("The run-derived lab subnet is already in use.")
    return subnet


LAUNCH_FREE_DISK = None


def check_capacity():
    """Launch-relative growth (owner-approved) with the unchanged 25 GiB free floor."""
    global LAUNCH_FREE_DISK
    disk, memory = shutil.disk_usage(ROOT).free, reference.available_memory()
    if LAUNCH_FREE_DISK is None:
        LAUNCH_FREE_DISK = disk
    cached.check_capacity(disk, memory, LAUNCH_FREE_DISK, host.RELIABILITY_GROWTH)
    return {"free_disk_bytes": disk, "free_memory_bytes": memory}


def status(docker, identifier, template):
    return base.docker_result(docker, ["inspect", identifier, "--format", template], timeout=5)


def start_checked(docker, run, directory, images, rehearsal_ms, guard, targets, identifier):
    exact_components(docker, run, directory, images, rehearsal_ms)
    no_foreign_running(docker, targets)
    check_capacity()
    reference.require_guard(guard, run, directory)
    base.docker_result(docker, ["start", identifier], timeout=20)
    exact_components(docker, run, directory, images, rehearsal_ms)
    reference.require_guard(guard, run, directory)


def execute(docker, run, directory, images, environment, guard, rehearsal_ms):
    """Create without startup, verify isolation, start exact IDs, supervise the day."""
    command = reference.compose_command(docker, run, directory, profile=PROFILE)
    reference.require_guard(guard, run, directory)
    raw = reference.invoke([*command, "config", "--format", "json"], environment, 20)
    from bridge.contract import parse_json

    verify_compose_config(
        parse_json(raw), images, run, directory, profile=PROFILE, rehearsal_ms=rehearsal_ms
    )
    check_capacity()
    if host.owned(docker, run):
        raise base.LabControlError("A reliability run identity cannot be reused.")
    for kind, name in (
        ("network", host.NETWORK_PREFIX + run),
        ("volume", reference.PREFIX + run),
    ):
        names = base.docker_result(docker, [kind, "ls", "--format", "{{.Name}}"], timeout=5)
        if name in names.splitlines():
            raise base.LabControlError("Reliability network or volume identity already exists.")
    reference.require_guard(guard, run, directory)
    no_foreign_running(docker)
    reference.invoke(
        [*command, "create", "--no-build", "--pull", "never", "--no-recreate"], environment, 60
    )
    targets = exact_components(docker, run, directory, images, rehearsal_ms)
    for identifier in targets:
        if status(docker, identifier, "{{.State.Status}}") != "created":
            raise base.LabControlError("Reliability creation unexpectedly started a component.")
    reference.private_acl(run, "Verify")
    ids = {component: identifier for identifier, component in targets.items()}
    reference.require_guard(guard, run, directory)
    check_capacity()
    base.docker_result(docker, ["start", ids["database"]], timeout=20)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        reference.require_guard(guard, run, directory)
        health = status(docker, ids["database"], "{{.State.Status}}|{{.State.Health.Status}}")
        if health == "running|healthy":
            break
        if health not in ("running|starting", "created|starting"):
            raise base.LabControlError("Reliability database did not become healthy.")
        time.sleep(0.5)
    else:
        raise base.LabControlError("Reliability database readiness deadline exceeded.")
    # The manager refuses a context older than fifteen minutes, so write it now.
    scale = rehearsal_ms / DAY_MS if rehearsal_ms else 1.0
    manager = wazuh.prepare_evidence(directory, run, scale=scale)
    start_checked(docker, run, directory, images, rehearsal_ms, guard, targets, ids["wazuh"])
    deadline = time.monotonic() + 120
    heartbeat = directory.joinpath(*wazuh.EVIDENCE, "heartbeat.json")
    while not heartbeat.exists():
        reference.require_guard(guard, run, directory)
        if not status(docker, ids["wazuh"], "{{.State.Status}}").startswith("running"):
            raise base.LabControlError("Reliability manager stopped before collecting.")
        if time.monotonic() > deadline:
            raise base.LabControlError("Reliability manager readiness deadline exceeded.")
        time.sleep(1)
    start_checked(docker, run, directory, images, rehearsal_ms, guard, targets, ids["runner"])
    gate = directory / "evidence/allow-source.json"
    with gate.with_suffix(".tmp").open("x", encoding="ascii") as stream:
        stream.write(json.dumps({"run_id": run, "runtime_verified": True}) + chr(10))
    if gate.exists() or gate.is_symlink():
        raise base.LabControlError("Reliability execution gate was already used.")
    gate.with_suffix(".tmp").replace(gate)
    period = rehearsal_ms or DAY_MS
    # Schedule + drain + dependency install, export, capture sealing and stop margin.
    deadline = time.monotonic() + (period + FINAL_DRAIN_MS) / 1000 + 3000
    checked, exits = 0.0, {}
    while time.monotonic() < deadline:
        reference.require_guard(guard, run, directory)
        for role in ("runner", "wazuh"):
            state = status(docker, ids[role], "{{.State.Status}}|{{.State.ExitCode}}")
            if state.startswith("exited|"):
                exits.setdefault(role, int(state.split("|", 1)[1]))
            elif not state.startswith("running|"):
                raise base.LabControlError("A reliability component stopped incompletely.")
        if len(exits) == 2:
            exact_components(docker, run, directory, images, rehearsal_ms)
            return {
                "parsed_configuration_verified": True,
                "runtime_isolation_verified": True,
                "runner_exit_code": exits["runner"],
                "manager_exit_code": exits["wazuh"],
                "manager_preparation": manager,
            }
        # Re-verify effective isolation and foreign containers every five minutes.
        if time.monotonic() - checked >= 300:
            no_foreign_running(docker, targets)
            exact_components(docker, run, directory, images, rehearsal_ms)
            check_capacity()
            checked = time.monotonic()
        time.sleep(2)
    raise base.LabControlError("Reliability execution deadline exceeded.")


def launch(docker, approval_reference, wheel_cache_run, certificate_python, rehearsal_minutes):
    if sys.platform != "win32" or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", approval_reference):
        raise base.LabControlError("A separately reviewed Windows reliability launch is required.")
    low, high = REHEARSAL_RANGE_MINUTES
    if rehearsal_minutes is not None and not low <= rehearsal_minutes <= high:
        raise base.LabControlError("Rehearsal length escaped its reviewed bound.")
    rehearsal_ms = 0 if rehearsal_minutes is None else rehearsal_minutes * 60_000
    base.validate_identity(wheel_cache_run)
    if not Path(docker).is_absolute() or not Path(docker).is_file() or Path(docker).is_symlink():
        raise base.LabControlError("The reviewed existing Docker executable is required.")
    capacity = check_capacity()
    no_foreign_running(docker)
    images = {
        "database": base.inspect_local_image(docker),
        "runner": cached.inspect_python_image(docker),
        "wazuh": wazuh.inspect_image(docker),
    }
    reference.certificate_runtime(certificate_python)
    reference.invoke(
        [sys.executable, "-B", "scripts/check_publication.py"], reference.clean_environment(), 60
    )
    run = uuid.uuid4().hex
    directory = base.private_run_directory(ROOT, run)
    directory.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc)
    receipt = {
        "schema_version": 1,
        "kind": "signalbridge-native-reliability-rehearsal"
        if rehearsal_ms
        else "signalbridge-native-reliability-24h",
        "run_id": run,
        "approval_reference": approval_reference,
        "rehearsal_ms": rehearsal_ms,
        "status": "incomplete",
        "acceptance_passed": False,
        "started_at": started.isoformat(),
        "capacity_before": capacity,
        "images": images,
        "stage_initial_free_disk_bytes": LAUNCH_FREE_DISK,
        "stage_growth_ceiling_bytes": host.RELIABILITY_GROWTH,
        "disk_guard": "launch_relative_owner_approved_2026-10-04",
        "limits": [
            "Fixed two-application synthetic workload on one PC; not a production load test.",
            "A rehearsal is shortened and scaled and is never the 24-hour result.",
            "Wazuh-side windows and tool observations are measured only when the separate "
            "continuous Wazuh driver ran beside this stage; otherwise tool targets fail.",
            "Hashes identify recorded bytes; local administrator tampering is outside this evidence.",
        ],
    }
    guard, source, awake = None, None, keep_awake(True)
    receipt["keep_awake_requested"] = awake
    try:
        source, snapshot, environment, preparation = reference.prepare(
            run,
            directory,
            images,
            certificate_python,
            wheel_cache_run,
            docker,
            hours=2 if rehearsal_ms else CERTIFICATE_HOURS,
        )
        environment["SB_RELIABILITY_REHEARSAL_MS"] = str(rehearsal_ms)
        environment["SB_WAZUH_IMAGE"] = images["wazuh"]
        environment["SB_RELIABILITY_SUBNET"] = subnet_free(docker, reliability_subnet(run))
        environment.update(wazuh.compose_environment(run))
        for folder in wazuh.host_directories(directory, run):
            folder.mkdir(parents=True, exist_ok=False)
        for path in wazuh.segment_files(directory, run):
            path.open("xb").close()
        receipt.update(
            preparation=preparation, source_sha256=source["sha256"], source_snapshot=snapshot
        )
        guard = reference.arm_guard(docker, run, directory, reliability=True)
        for _ in range(20):
            if guard.poll() is not None:
                raise base.LabControlError("Reliability watchdog exited before arming.")
            if (directory / "watchdog-ready.json").exists():
                reference.require_guard(guard, run, directory)
                break
            time.sleep(0.25)
        else:
            raise base.LabControlError("Reliability watchdog readiness expired.")
        receipt.update(execute(docker, run, directory, images, environment, guard, rehearsal_ms))
        receipt["status"] = "executed_pending_measurement"
    except Exception as error:
        receipt["error_class"] = type(error).__name__
        if isinstance(error, base.LabControlError):
            receipt["error_code"] = str(error)
    finally:
        main = {"run_id": run, "shutdown_verified": False}
        try:
            main["stopped_component_count"] = host.stop_scope(docker, run)
            main["shutdown_verified"] = True
        except Exception as error:
            main["shutdown_error_class"] = type(error).__name__
        receipt["main_shutdown"] = main
        if guard is not None:
            try:
                host.write_control(ROOT, run, "launcher-finished.json", {"run_id": run})
                guard.wait(timeout=55)
                independent = host.read_json(directory / "watchdog.json")
                receipt["independent_shutdown"] = independent
                receipt.update(
                    validate_shutdown(
                        main,
                        independent,
                        run,
                        started=started,
                        finished=datetime.now(timezone.utc),
                        components=len(ROLES),
                    )
                )
            except Exception as error:
                receipt["independent_shutdown_error_class"] = type(error).__name__
                receipt["watchdog_pending"] = guard.poll() is None
        try:
            measured = evaluate(directory, rehearsal_ms=rehearsal_ms)
            receipt["measurement"] = measured["measurement"]
            receipt["ledger_counts"] = measured["ledger_counts"]
            receipt["runner"] = measured["runner"]
        except Exception as error:
            receipt["measurement_error_class"] = type(error).__name__
        keep_awake(False)
        receipt.update(
            finished_at=datetime.now(timezone.utc).isoformat(),
            free_disk_after_bytes=shutil.disk_usage(ROOT).free,
        )
        try:
            receipt["source_unchanged"] = source is not None and host.same(
                source, source_manifest(ROOT)
            )
        except Exception:
            receipt["source_unchanged"] = False
        targets_met = receipt.get("measurement", {}).get("status") == "ledger_targets_met"
        receipt["acceptance_passed"] = bool(
            not rehearsal_ms
            and receipt["status"] == "executed_pending_measurement"
            and receipt.get("runner_exit_code") == 0
            and receipt.get("manager_exit_code") == 0
            and targets_met
            and receipt.get("source_unchanged")
            and receipt.get("main_shutdown_verified")
            and receipt.get("independent_shutdown_verified")
        )
        receipt["status"] = (
            "passed"
            if receipt["acceptance_passed"]
            else "rehearsal_finished"
            if rehearsal_ms and receipt.get("independent_shutdown_verified")
            else "incomplete"
        )
        raw = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("ascii")
        with (directory / "receipt.json").open("xb") as stream:
            stream.write(raw)
        public_id = (
            started.strftime("%Y%m%d")
            + ("-reliability-rehearsal-" if rehearsal_ms else "-reliability-24h-")
            + run
        )
        public = receipt_path(ROOT, "docs/evidence/" + public_id + ".json", public_id)
        with public.open("xb") as stream:
            stream.write(raw)
    return directory, receipt["acceptance_passed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--approval-reference", required=True)
    parser.add_argument("--wheel-cache-run", required=True)
    parser.add_argument("--certificate-python", type=Path, required=True)
    parser.add_argument("--rehearsal-minutes", type=int)
    options = parser.parse_args()
    directory, passed = launch(
        options.docker,
        options.approval_reference,
        options.wheel_cache_run,
        options.certificate_python,
        options.rehearsal_minutes,
    )
    print("Reliability receipt retained: " + str(directory))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
