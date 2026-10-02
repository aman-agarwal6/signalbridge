"""Explicit operator launch for a 30-minute disposable PostgreSQL verification.

Uses only an already installed inspected image. No downloads or unrelated stops.
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

from integrations.enterprise.verification import (
    MAX_RUNTIME_SECONDS,
    PROJECT_PREFIX,
    LabControlError,
    await_container_watchdog,
    check_capacity,
    check_port,
    docker_command,
    docker_result,
    guarded_stop,
    inspect_local_image,
    owned_containers,
    private_run_directory,
    validate_identity,
    watchdog,
)
from scripts.record_verification import parse_django_summary, source_manifest

COMPOSE = ROOT / "integrations/enterprise/compose.verify.yaml"


def available_memory():
    command = "(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).FreePhysicalMemory * 1024"
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=10,
        stdin=subprocess.DEVNULL,
        shell=False,
    )
    if result.returncode or not result.stdout.strip().isdigit():
        raise LabControlError("Available host memory could not be verified; launch refused.")
    return int(result.stdout.strip())


def launch(docker, approval_reference, initial_free_disk=None, max_growth_gib=2):
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", approval_reference):
        raise LabControlError("Record a valid operator approval reference before launch.")
    free_disk = shutil.disk_usage(ROOT).free
    free_memory = available_memory()
    max_growth = max_growth_gib * 1024**3
    initial_free_disk = free_disk if initial_free_disk is None else initial_free_disk
    check_capacity(free_disk, free_memory, initial_free_disk, max_growth)
    check_port()
    # Starting Docker Desktop is a separate reviewed action. This never starts it.
    running = docker_result(docker, ["ps", "-q"])
    if running:
        raise LabControlError("Other containers are running; review their memory budget first.")
    image = inspect_local_image(docker)
    run_id = uuid.uuid4().hex
    run_dir = private_run_directory(ROOT, run_id)
    run_dir.mkdir(parents=True, exist_ok=False)
    secret_dir = run_dir / "secrets"
    secret_dir.mkdir()
    bootstrap, verifier = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
    (secret_dir / "bootstrap-password").write_text(bootstrap, encoding="ascii")
    (secret_dir / "verifier-password").write_text(verifier, encoding="ascii")
    environment = os.environ.copy()
    # Neither libpq nor Django's live DB configuration is inherited.
    for name in list(environment):
        if name.startswith(("PG", "SB_DB_", "SB_ENTERPRISE_", "DOCKER_")) or name in (
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONINSPECT",
            "PYTHONSTARTUP",
        ):
            environment.pop(name)
    environment.update(
        SB_VERIFY_IMAGE=image,
        SB_VERIFY_RUN=run_id,
        SB_VERIFY_SECRET_DIR=str(secret_dir),
        SB_DISPOSABLE_PG="1",
        SB_ENTERPRISE_VERIFY_PASSWORD=verifier,
        SB_SECRET_KEY=secrets.token_urlsafe(64),
        PYTHONDONTWRITEBYTECODE="1",
        DJANGO_SETTINGS_MODULE="config.postgres_verification_settings",
    )
    compose = docker_command(
        docker,
        [
            "compose",
            "--project-name",
            PROJECT_PREFIX + run_id,
            "--file",
            str(COMPOSE),
        ],
    )
    receipt = {
        "run_id": run_id,
        "approval_reference": approval_reference,
        "status": "prepared",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "image_id": image,
        "free_disk_bytes": free_disk,
        "free_memory_bytes": free_memory,
        "stage_initial_free_disk_bytes": initial_free_disk,
        "stage_max_growth_bytes": max_growth,
        "prelaunch_stage_growth_bytes": max(0, initial_free_disk - free_disk),
        "source_before": source_manifest(ROOT),
        "limits": [
            "Disposable PostgreSQL concurrency only; not 24-hour, HTTP, SSO or source-app coverage.",
            "An aborted SQL transaction is recovery evidence, not an operating-system process crash.",
        ],
    }
    container = None
    guard = None
    started = time.monotonic()
    try:
        deadline = time.time() + MAX_RUNTIME_SECONDS
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
                "--receipt",
                str(run_dir / "watchdog.json"),
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        for _ in range(10):
            if guard.poll() is not None:
                raise LabControlError("Independent shutdown watchdog did not arm.")
            ready = run_dir / "watchdog-ready.json"
            if ready.exists() and json.loads(ready.read_text()) == {
                "run_id": run_id,
                "armed": True,
            }:
                break
            time.sleep(0.5)
        else:
            raise LabControlError("Independent shutdown watchdog readiness deadline exceeded.")
        result = subprocess.run(
            [*compose, "up", "--detach", "--no-build", "--pull", "never"],
            env=environment,
            cwd=ROOT,
            capture_output=True,
            timeout=90,
            shell=False,
        )
        if result.returncode:
            raise LabControlError("Disposable database startup failed.")
        targets = owned_containers(docker, run_id)
        if len(targets) != 1:
            raise LabControlError("Exact database container identity was not verified.")
        container = targets[0]
        for _ in range(45):
            if guard.poll() is not None:
                raise LabControlError("Independent shutdown watchdog exited before readiness.")
            state = docker_result(
                docker, ["inspect", container, "--format", "{{.State.Health.Status}}"]
            )
            if state == "healthy":
                break
            if state not in ("starting", "unhealthy"):
                raise LabControlError("Unrecognized database health state.")
            time.sleep(2)
        else:
            raise LabControlError("Database readiness deadline exceeded.")
        command = [
            sys.executable,
            "-B",
            "manage.py",
            "test",
            "tests.test_postgres_processing",
            "--settings",
            "config.postgres_verification_settings",
            "--noinput",
            "--verbosity",
            "1",
        ]
        check = subprocess.run(
            command, env=environment, cwd=ROOT, capture_output=True, timeout=180, shell=False
        )
        output = (check.stdout + check.stderr).decode("utf8", errors="replace")
        for secret in (bootstrap, verifier, environment["SB_SECRET_KEY"]):
            output = output.replace(secret, "[REDACTED]")
        log = run_dir / "postgres-tests.txt"
        log.write_text(output, encoding="utf8")
        summary = parse_django_summary(output)
        passed = bool(
            check.returncode == 0
            and summary
            and summary["tests_run"] == 5
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
            test_exit_code=check.returncode,
            test_log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),
        )
    except Exception as error:
        receipt.update(status="incomplete", error_class=type(error).__name__)
        if isinstance(error, LabControlError):
            receipt["error_code"] = str(error)
        raise
    finally:
        try:
            targets = owned_containers(docker, run_id)
            for target in targets:
                guarded_stop(docker, target, run_id)
            receipt["shutdown_verified"] = True
        except Exception as error:
            receipt.update(shutdown_verified=False, shutdown_error_class=type(error).__name__)
        if guard:
            (run_dir / "launcher-finished.json").write_text(
                json.dumps({"run_id": run_id}) + "\n", encoding="utf8"
            )
            try:
                guard.wait(timeout=25)
            except subprocess.TimeoutExpired:
                receipt["watchdog_pending"] = True
            proof = run_dir / "watchdog.json"
            receipt["watchdog_shutdown_verified"] = bool(
                proof.exists() and json.loads(proof.read_text()).get("shutdown_verified")
            )
        receipt.update(
            duration_seconds=round(time.monotonic() - started, 3),
            final_free_disk_bytes=shutil.disk_usage(ROOT).free,
            finished_at=datetime.now(timezone.utc).isoformat(),
            source_after=source_manifest(ROOT),
        )
        receipt["source_unchanged"] = receipt["source_before"] == receipt["source_after"]
        (run_dir / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf8")
    if (
        receipt["status"] != "passed"
        or not receipt.get("shutdown_verified")
        or not receipt.get("watchdog_shutdown_verified")
        or not receipt["source_unchanged"]
    ):
        raise LabControlError(
            "Native acceptance gate did not pass; retained receipt requires review."
        )
    return run_dir


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("launch")
    start.add_argument("--docker", required=True, type=Path)
    start.add_argument("--approval-reference", required=True)
    start.add_argument("--stage-initial-free-disk", type=int)
    start.add_argument("--max-growth-gib", type=int, choices=(2, 5, 8), default=2)
    guard = commands.add_parser("watchdog")
    guard.add_argument("--docker", required=True, type=Path)
    guard.add_argument("--container")
    guard.add_argument("--run", required=True)
    guard.add_argument("--deadline", required=True, type=float)
    guard.add_argument("--initial-free-disk", required=True, type=int)
    guard.add_argument("--max-growth-gib", type=int, choices=(2, 5, 8), default=2)
    guard.add_argument("--receipt", required=True, type=Path)
    options = parser.parse_args()
    if options.command == "watchdog":
        validate_identity(options.run)
        expected = (private_run_directory(ROOT, options.run) / "watchdog.json").resolve()
        if options.receipt.resolve() != expected:
            raise LabControlError("Watchdog receipt must belong to its exact private run.")
        if options.container:
            watchdog(
                options.docker,
                options.container,
                options.run,
                ROOT,
                options.deadline,
                options.initial_free_disk,
                options.receipt,
                max_growth=options.max_growth_gib * 1024**3,
            )
        else:
            await_container_watchdog(
                options.docker,
                options.run,
                ROOT,
                options.deadline,
                options.initial_free_disk,
                options.receipt,
                max_growth=options.max_growth_gib * 1024**3,
            )
    else:
        print(
            "Native receipt: "
            + str(
                launch(
                    options.docker,
                    options.approval_reference,
                    options.stage_initial_free_disk,
                    options.max_growth_gib,
                )
            )
        )


if __name__ == "__main__":
    main()
