"""Explicit reviewed native stage: cached images, six wheels, nine fixed PG checks.

Never starts Docker Desktop, pulls images, installs host packages or prunes data.
An operator approval reference records authorization; it cannot grant permission.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrations.enterprise import network_verification as controls
from integrations.enterprise import verification as base
from scripts.enterprise_verify import available_memory
from scripts.record_verification import parse_django_summary, receipt_path, source_manifest

COMPOSE = ROOT / "integrations/enterprise/compose.in-network.yaml"


def launch(docker, approval_reference, initial_free_disk, wheel_cache_run=None, max_growth_gib=8):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", approval_reference):
        raise base.LabControlError("A reviewed operator approval reference is required.")
    free_disk, free_memory = shutil.disk_usage(ROOT).free, available_memory()
    max_growth = max_growth_gib * base.GIB
    controls.check_capacity(free_disk, free_memory, initial_free_disk, max_growth)
    if base.docker_result(docker, ["ps", "-q"]):
        raise base.LabControlError("Other running containers require a revised resource review.")
    images = {
        "database": base.inspect_local_image(docker),
        "runner": controls.inspect_python_image(docker),
    }
    controls.wheel_manifest()
    environment = base.docker_environment()
    for name in list(environment):
        if name.startswith(("PG", "SB_", "PYTHON")):
            environment.pop(name)
    scan = subprocess.run(
        [sys.executable, "-B", "scripts/check_publication.py"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
    )
    if scan.returncode:
        raise base.LabControlError(
            "Publication safety scan failed; no source snapshot or launch allowed."
        )
    run_id = uuid.uuid4().hex
    directory = base.private_run_directory(ROOT, run_id)
    directory.mkdir(parents=True, exist_ok=False)
    secret_directory = directory / "secrets"
    secret_directory.mkdir()
    (directory / "evidence").mkdir()
    for name in ("bootstrap-password", "verifier-password"):
        (secret_directory / name).write_text(secrets.token_urlsafe(48), encoding="ascii")
    source = source_manifest(ROOT)
    snapshot = controls.snapshot_source(ROOT, directory / "source", source)
    environment.update(
        SB_VERIFY_IMAGE=images["database"],
        SB_VERIFY_PYTHON_IMAGE=images["runner"],
        SB_VERIFY_RUN=run_id,
        SB_VERIFY_RUN_DIR=str(directory),
        PYTHONDONTWRITEBYTECODE="1",
    )
    compose = base.docker_command(
        docker,
        ["compose", "--project-name", controls.PROJECT_PREFIX + run_id, "--file", str(COMPOSE)],
    )
    receipt = {
        "schema_version": 1,
        "kind": "signalbridge-native-in-network-postgresql",
        "run_id": run_id,
        "approval_reference": approval_reference,
        "status": "prepared",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "images": images,
        "source_sha256": source["sha256"],
        "source_snapshot": snapshot,
        "initial_free_disk_bytes": initial_free_disk,
        "free_disk_before_bytes": free_disk,
        "free_memory_before_bytes": free_memory,
        "stage_growth_ceiling_bytes": max_growth,
        "limits": [
            "Component concurrency and killed-process transaction checks only; no source HTTP, enterprise TLS, identity, security-tool or 24-hour proof.",
            "Two internal containers, one GiB combined memory, no published ports or external runtime network.",
            "Wheel files are installed into disposable bounded container tmpfs; no host installation or new built image.",
            "Host storage monitoring detects limits; it is not a hard quota or an allocation guarantee.",
        ],
    }
    started, guard = time.monotonic(), None
    try:
        deadline = time.time() + base.MAX_RUNTIME_SECONDS
        guard = subprocess.Popen(
            [
                sys.executable,
                "-B",
                str(Path(__file__).resolve()),
                "watchdog",
                "--docker",
                str(docker),
                "--run",
                run_id,
                "--deadline",
                str(deadline),
                "--initial-free-disk",
                str(initial_free_disk),
                "--max-growth-gib",
                str(max_growth_gib),
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        ready = directory / "watchdog-ready.json"
        for _ in range(10):
            if guard.poll() is not None:
                raise base.LabControlError("Independent shutdown watchdog did not arm.")
            if ready.exists() and json.loads(ready.read_text()) == {
                "run_id": run_id,
                "armed": True,
            }:
                break
            time.sleep(0.5)
        else:
            raise base.LabControlError("Independent watchdog readiness expired.")
        receipt["download"] = (
            controls.cached_wheels(ROOT, wheel_cache_run, directory / "wheels")
            if wheel_cache_run
            else controls.download_wheels(directory / "wheels")
        )
        receipt["wheel_footprint"] = controls.wheel_expansion(directory / "wheels")
        configuration = subprocess.run(
            [*compose, "config", "--format", "json"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            timeout=20,
            stdin=subprocess.DEVNULL,
        )
        if configuration.returncode:
            raise base.LabControlError("Native configuration did not parse; creation refused.")
        controls.verify_compose_config(json.loads(configuration.stdout), images, run_id)
        receipt["parsed_configuration_verified"] = True
        controls.check_capacity(
            shutil.disk_usage(ROOT).free, available_memory(), initial_free_disk, max_growth
        )
        if guard.poll() is not None:
            raise base.LabControlError("Shutdown watchdog exited before startup.")
        result = subprocess.run(
            [*compose, "up", "--detach", "--no-build", "--pull", "never"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            timeout=90,
            stdin=subprocess.DEVNULL,
        )
        diagnostic = result.stdout + result.stderr
        for name in ("bootstrap-password", "verifier-password"):
            diagnostic = diagnostic.replace((secret_directory / name).read_bytes(), b"[REDACTED]")
        (directory / "compose-startup.log").write_bytes(diagnostic)
        receipt["startup_log_sha256"] = hashlib.sha256(diagnostic).hexdigest()
        if result.returncode:
            raise base.LabControlError("Internal native startup failed.")
        targets = controls.owned(docker, run_id)
        if sorted(targets.values()) != ["database", "runner"]:
            raise base.LabControlError("The exact two native components were not verified.")
        for identifier, role in targets.items():
            controls.verify_runtime(docker, identifier, run_id, directory, images[role])
        receipt["runtime_isolation_verified"] = True
        gate = directory / "evidence/allow-tests.json"
        temporary = gate.with_suffix(".tmp")
        temporary.write_text(
            json.dumps({"run_id": run_id, "runtime_verified": True}), encoding="utf8"
        )
        temporary.replace(gate)
        runner = next(identifier for identifier, role in targets.items() if role == "runner")
        wait_deadline = time.monotonic() + 390
        while time.monotonic() < wait_deadline:
            state = base.docker_result(docker, ["inspect", runner, "--format", "{{.State.Status}}"])
            if state in ("exited", "dead"):
                break
            if guard.poll() is not None:
                raise base.LabControlError("Independent watchdog ended an incomplete native stage.")
            time.sleep(1)
        else:
            raise base.LabControlError("Native verification execution deadline exceeded.")
        proof_path, log_path = (
            directory / "evidence/runner.json",
            directory / "evidence/postgres-tests.log",
        )
        if (
            not proof_path.is_file()
            or not log_path.is_file()
            or log_path.stat().st_size > 2 * 1024**2
        ):
            raise base.LabControlError("Native runner did not retain its complete bounded proof.")
        proof, raw = json.loads(proof_path.read_text()), log_path.read_bytes()
        summary = parse_django_summary(raw.decode("utf8", errors="replace"))
        passed = bool(
            proof.get("test_exit_code") == 0
            and proof.get("log_sha256") == hashlib.sha256(raw).hexdigest()
            and summary
            and summary["tests_run"] == 14
            and summary["successful_summary"]
            and not any(
                summary[key]
                for key in (
                    "skipped",
                    "failures",
                    "errors",
                    "expected_failures",
                    "unexpected_successes",
                )
            )
        )
        receipt.update(
            status="passed" if passed else "failed",
            tests=summary,
            test_log_sha256=hashlib.sha256(raw).hexdigest(),
            python_version=proof.get("python_version"),
        )
    except Exception as error:
        receipt.update(status="incomplete", error_class=type(error).__name__)
        if isinstance(error, base.LabControlError):
            receipt["error_code"] = str(error)
    finally:
        if receipt["status"] != "passed":
            try:
                diagnostic = bytearray()
                for target in controls.owned(docker, run_id):
                    log = subprocess.run(
                        base.docker_command(docker, ["logs", "--tail", "60", target]),
                        capture_output=True,
                        timeout=5,
                        stdin=subprocess.DEVNULL,
                        env=base.docker_environment(),
                    )
                    diagnostic.extend(log.stdout + log.stderr)
                for name in ("bootstrap-password", "verifier-password"):
                    diagnostic = diagnostic.replace(
                        (secret_directory / name).read_bytes(), b"[REDACTED]"
                    )
                if len(diagnostic) <= 2 * 1024**2:
                    (directory / "runtime-diagnostic.log").write_bytes(diagnostic)
                    receipt["diagnostic_log_sha256"] = hashlib.sha256(diagnostic).hexdigest()
            except Exception as error:
                receipt["diagnostic_error_class"] = type(error).__name__
        try:
            receipt["stopped_component_count"] = controls.stop_scope(docker, run_id)
            receipt["shutdown_verified"] = True
        except Exception as error:
            receipt.update(shutdown_verified=False, shutdown_error_class=type(error).__name__)
        if guard:
            (directory / "launcher-finished.json").write_text(
                json.dumps({"run_id": run_id}), encoding="utf8"
            )
            try:
                guard.wait(timeout=50)
            except subprocess.TimeoutExpired:
                receipt["watchdog_pending"] = True
            watchdog = directory / "watchdog.json"
            receipt["independent_shutdown_verified"] = bool(
                watchdog.exists() and json.loads(watchdog.read_text()).get("shutdown_verified")
            )
        receipt.update(
            finished_at=datetime.now(timezone.utc).isoformat(),
            duration_seconds=round(time.monotonic() - started, 3),
            free_disk_after_bytes=shutil.disk_usage(ROOT).free,
            source_unchanged=source == source_manifest(ROOT),
        )
        receipt["acceptance_passed"] = bool(
            receipt["status"] == "passed"
            and receipt.get("runtime_isolation_verified")
            and receipt.get("shutdown_verified")
            and receipt.get("independent_shutdown_verified")
            and receipt["source_unchanged"]
        )
        (directory / "receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf8"
        )
        public_id = "20261001-postgresql-in-network-" + run_id
        public = receipt_path(ROOT, "docs/evidence/" + public_id + ".json", public_id)
        with public.open("x", encoding="utf8") as output:
            output.write(json.dumps(receipt, indent=2) + "\n")
    return directory, receipt["acceptance_passed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("launch")
    start.add_argument("--docker", required=True, type=Path)
    start.add_argument("--approval-reference", required=True)
    start.add_argument("--stage-initial-free-disk", required=True, type=int)
    start.add_argument("--max-growth-gib", choices=(8, 12), type=int, default=8)
    start.add_argument(
        "--wheel-cache-run", help="Exact retained run; verify all six wheels without downloading."
    )
    guard = commands.add_parser("watchdog")
    guard.add_argument("--docker", required=True, type=Path)
    guard.add_argument("--run", required=True)
    guard.add_argument("--deadline", required=True, type=float)
    guard.add_argument("--initial-free-disk", required=True, type=int)
    guard.add_argument("--max-growth-gib", choices=(8, 12), type=int, default=8)
    options = parser.parse_args()
    if options.command == "watchdog":
        controls.watchdog(
            options.docker,
            options.run,
            ROOT,
            options.deadline,
            options.initial_free_disk,
            base.private_run_directory(ROOT, options.run) / "watchdog.json",
            max_growth=options.max_growth_gib * base.GIB,
        )
        return 0
    directory, passed = launch(
        options.docker,
        options.approval_reference,
        options.stage_initial_free_disk,
        options.wheel_cache_run,
        options.max_growth_gib,
    )
    print("Native receipt retained: " + str(directory))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
