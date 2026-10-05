"""Explicit reviewed restoration stage: copy, back up and restore one retained console.

The retained native console volume is copied by a read-only helper, backed up
with pg_dump from that copy, and restored into a separate fresh PostgreSQL
instance where the current application migrates and runs the operator import
and case workflows. Never starts Docker Desktop, pulls images, deletes volumes
or writes the original volume. An approval reference records authorization.
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

from bridge.contract import parse_json
from integrations.enterprise import network_verification as network
from integrations.enterprise import restoration_controls as controls
from integrations.enterprise import verification as base
from integrations.enterprise.reference_host_controls import read_json, same
from integrations.enterprise.windows_capacity import available_memory
from scripts.enterprise_reference_verify import (
    clean_environment,
    invoke,
    private_acl,
    private_docker_config,
    require_guard,
)
from scripts.enterprise_zap_verify import verified_source
from scripts.record_verification import receipt_path, source_manifest

COMPOSE = ROOT / "integrations/enterprise/compose.restoration.yaml"
require = controls.require


def no_foreign_running(docker, targets=()):
    raw = base.docker_result(docker, ["ps", "--quiet", "--no-trunc"], timeout=5)
    identifiers = raw.splitlines() if raw else []
    require(
        len(identifiers) <= 2
        and all(re.fullmatch(r"[a-f0-9]{64}", value) for value in identifiers)
        and set(identifiers).issubset(targets),
        "Other running containers require a revised launch review.",
    )


def retained_receipt(run, kind):
    directory = base.private_run_directory(ROOT, run)
    value = read_json(directory / "receipt.json", 262144)
    shutdown = value.get("main_shutdown_verified", value.get("shutdown_verified"))
    require(
        value.get("run_id") == run
        and value.get("kind") == kind
        and value.get("status") == "passed"
        and value.get("acceptance_passed") is True
        and shutdown is True
        and value.get("independent_shutdown_verified") is True,
        "The retained run is not a completed native receipt of the expected kind.",
    )
    return directory, value


def tool_binding(profile, source_run, tool_run):
    """The tool run must have been produced from this exact retained source run."""
    directory = base.private_run_directory(ROOT, tool_run)
    value = read_json(directory / "receipt.json", 262144)
    require(value.get("run_id") == tool_run and value.get("status") == "passed")
    if profile == "header":
        require(
            value.get("kind") == "signalbridge-native-authenticated-zap-offline"
            and value.get("source_run_id") == source_run
            and value.get("acceptance_passed") is True,
            "The scanner run was not produced from this source capture.",
        )
    else:
        binding = value.get("source_binding") or {}
        require(
            value.get("kind") == "signalbridge-native-wazuh-ready-publication"
            and binding.get("native_source_run_id") == source_run,
            "The Wazuh run was not produced from this source run.",
        )
    return directory


def host_wazuh_scope(tool_run):
    """Run the full Wazuh review loader here, where published inputs keep the
    Windows file identity it verifies; the runner imports only this exact scope."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.verification_settings")
    os.environ.setdefault("SB_SECRET_KEY", secrets.token_urlsafe(48))
    import django

    django.setup()
    from bridge.contract import canonical
    from bridge.wazuh_native_review import load_native_review

    return canonical(load_native_review(ROOT, tool_run)["documents"])


def write_gate(directory, run):
    gate = directory / "evidence/allow-restoration.json"
    require(not gate.exists() and not gate.is_symlink())
    temporary = directory / "evidence/allow-restoration.tmp"
    with temporary.open("x", encoding="ascii") as output:
        output.write(json.dumps({"run_id": run, "runtime_verified": True, "restored": True}))
    temporary.replace(gate)


def arm_guard(docker, run, initial):
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen(
        [
            sys.executable,
            "-B",
            str(Path(__file__).resolve()),
            "watchdog",
            "--docker",
            str(docker),
            "--run",
            run,
            "--deadline",
            str(time.time() + controls.MAX_SECONDS),
            "--initial-free-disk",
            str(initial),
        ],
        cwd=ROOT,
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
        shell=False,
    )


def single(docker, run, role):
    found = [i for i, r in controls.owned(docker, run).items() if r == role]
    require(len(found) == 1, "The exact restoration component was not found.")
    return found[0]


def postgres(docker, identifier, *arguments, timeout=60):
    """Run a fixed PostgreSQL client as the container's peer-authenticated owner."""
    return base.docker_result(
        docker, ["exec", "--user", "postgres", identifier, *arguments], timeout=timeout
    )


def ready(docker, identifier, socket_only):
    target = ["-h", "/var/run/postgresql"] if socket_only else ["-h", "127.0.0.1"]
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            postgres(docker, identifier, "pg_isready", *target, "-d", "postgres", timeout=10)
            return
        except Exception:
            time.sleep(1)
    raise base.LabControlError("The restoration database did not become ready.")


def execute(docker, run, directory, images, environment, guard, plan, archive, initial):
    check = lambda: require_guard(guard, run, directory)  # noqa: E731
    result = {}
    # 1. Read-only copy of the retained volume into a new labelled volume.
    base.docker_result(
        docker,
        [
            "volume",
            "create",
            *[a for k, v in controls.labels(run, "copy").items() for a in ("--label", k + "=" + v)],
            controls.copy_volume(run),
        ],
    )
    check()
    base.docker_result(
        docker, controls.copy_arguments(run, plan["source_run"], images["database"]), timeout=120
    )
    identifier = single(docker, run, "copy")
    controls.verify_runtime(docker, identifier, run, directory, images["database"], "copy")
    require(controls.wait_exit(docker, identifier, 30, check) == 0, "Volume copy failed.")
    result["copy_verified"] = True
    # 2. Logical backup from the copy only, over a private Unix socket.
    check()
    base.docker_result(docker, controls.backup_arguments(run, directory, images["database"]))
    identifier = single(docker, run, "backup")
    controls.verify_runtime(docker, identifier, run, directory, images["database"], "backup")
    ready(docker, identifier, socket_only=True)
    source_counts = postgres(
        docker,
        identifier,
        "psql",
        "-h",
        "/var/run/postgresql",
        "-d",
        "sb_enterprise_access",
        "--no-psqlrc",
        "-At",
        "-c",
        "SELECT (SELECT count(*) FROM bridge_event)::text || ',' || "
        "(SELECT count(*) FROM bridge_investigation)::text",
    )
    require(
        source_counts == f"{len(archive['events'])},{len(archive['cases'])}",
        "The retained console copy differs from its archived inventory.",
    )
    postgres(
        docker,
        identifier,
        "pg_dump",
        "-h",
        "/var/run/postgresql",
        "--format=custom",
        "--no-owner",
        "--no-privileges",
        "--file=/backup/console.dump",
        "sb_enterprise_access",
        timeout=120,
    )
    base.docker_result(docker, ["stop", "--time", "10", identifier], timeout=20)
    require(
        base.docker_result(docker, ["inspect", identifier, "--format", "{{.State.Running}}"])
        == "false"
    )
    dump = directory / "backup/console.dump"
    require(dump.is_file() and 0 < dump.stat().st_size <= 64 * 1024**2, "Backup size unexpected.")
    result["backup"] = {
        "format": "pg_dump_custom",
        "bytes": dump.stat().st_size,
        "sha256": hashlib.sha256(dump.read_bytes()).hexdigest(),
        "source_rows": {"events": len(archive["events"]), "cases": len(archive["cases"])},
    }
    # 3. Separate fresh database, restored from the backup file.
    command = base.docker_command(
        docker,
        [
            "compose",
            "--project-directory",
            str(directory),
            "--project-name",
            controls.PREFIX + run,
            "--file",
            str(COMPOSE),
        ],
    )
    parsed = invoke([*command, "config", "--format", "json"], environment, 20)
    controls.verify_compose_config(parse_json(parsed), images, run, directory)
    result["parsed_configuration_verified"] = True
    controls.check_capacity(shutil.disk_usage(ROOT).free, available_memory(), initial)
    check()
    invoke([*command, "up", "--detach", "--no-build", "--pull", "never"], environment, 120)
    database, runner = single(docker, run, "database"), single(docker, run, "runner")
    controls.verify_runtime(docker, database, run, directory, images["database"], "database")
    controls.verify_runtime(docker, runner, run, directory, images["runner"], "runner")
    no_foreign_running(docker, [database, runner])
    ready(docker, database, socket_only=False)
    postgres(
        docker,
        database,
        "pg_restore",
        "--exit-on-error",
        "--single-transaction",
        "--no-owner",
        "--no-privileges",
        "--role=sb_restored_console",
        "--dbname=sb_enterprise_access",
        "/backup/console.dump",
        timeout=120,
    )
    result["restored_into_separate_database"] = True
    result["runtime_isolation_verified"] = True
    check()
    write_gate(directory, run)
    exit_code = controls.wait_exit(docker, runner, controls.RUNNER_SECONDS, check)
    result["runner_exit_code"] = exit_code
    value = read_json(directory / "evidence/restoration-runner.json", 65536)
    result["runner"] = value
    require(exit_code == 0, "The restored-console runner did not pass.")
    controls.validate_runner(value, plan, archive)
    return result


def launch(docker, approval_reference, profile, source_run, tool_run, wheel_cache_run, initial):
    require(
        sys.platform == "win32"
        and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", approval_reference) is not None
        and profile in controls.PROFILES
    )
    for value in (source_run, tool_run, wheel_cache_run):
        base.validate_identity(value)
    docker = Path(docker)
    require(docker.is_absolute() and docker.is_file() and not docker.is_symlink())
    manifest = verified_source()
    private_acl(source_run, "Verify")
    source_directory, source_receipt = retained_receipt(source_run, controls.PROFILES[profile])
    private_acl(tool_run, "Verify")
    tool_directory = tool_binding(profile, source_run, tool_run)
    archive_raw = (source_directory / "evidence/console-events.json").read_bytes()
    archive = parse_json(archive_raw)
    require(set(archive) == {"events", "cases"} and archive["events"])
    capacity = {"free_disk_bytes": shutil.disk_usage(ROOT).free}
    capacity["available_host_memory_bytes"] = available_memory()
    controls.check_capacity(
        capacity["free_disk_bytes"], capacity["available_host_memory_bytes"], initial
    )
    no_foreign_running(docker)
    images = {"database": base.inspect_local_image(docker)}
    images["runner"] = network.inspect_python_image(docker)
    require(images["database"] == source_receipt["images"]["database"])
    volume = controls.verify_source_volume(docker, source_run)
    run, started = uuid.uuid4().hex, datetime.now(timezone.utc)
    directory = base.private_run_directory(ROOT, run)
    directory.mkdir(parents=True, exist_ok=False)
    scope_raw = host_wazuh_scope(tool_run) if profile == "access" else b"null"
    plan = {
        "run_id": run,
        "profile": profile,
        "source_run": source_run,
        "tool_run": tool_run,
        "console_events_sha256": hashlib.sha256(archive_raw).hexdigest(),
        "tool_scope_sha256": (
            hashlib.sha256(scope_raw).hexdigest() if profile == "access" else None
        ),
    }
    receipt = {
        "schema_version": 1,
        "kind": "signalbridge-native-console-restoration",
        "run_id": run,
        "profile": profile,
        "source_run_id": source_run,
        "tool_run_id": tool_run,
        "approval_reference": approval_reference,
        "status": "incomplete",
        "acceptance_passed": False,
        "started_at": started.isoformat(),
        "capacity_before": capacity,
        "stage_initial_free_disk_bytes": initial,
        "stage_growth_ceiling_bytes": controls.GROWTH,
        "source_sha256": manifest["sha256"],
        "images": images,
        "source_volume": volume,
        "console_events_sha256": plan["console_events_sha256"],
        "tool_scope_sha256": plan["tool_scope_sha256"],
        "limits": [
            "Restores one retained native console into a separate local PostgreSQL instance; not production backup tooling or point-in-time recovery.",
            "Synthetic operator accounts exist only in the restored database; the original volume is copied read-only and never written.",
            "Imports and workflows reuse retained native tool receipts; no tool, source app or provider runs here.",
            "The Wazuh review is revalidated on the Windows host (its file-identity checks need the original files); the restored console imports that exact hash-pinned scope.",
            "Capacity readings are detection guards, not physical quotas. Containers, volumes and the backup are retained, not deleted.",
        ],
    }
    guard = None
    try:
        private_acl(run, "SecureEmpty")
        for name in ("evidence", "secrets", "backup"):
            (directory / name).mkdir()
        for name in ("bootstrap-password", "console-password"):
            (directory / "secrets" / name).write_text(secrets.token_urlsafe(48), encoding="ascii")
        with (directory / "secrets/tool-scope.json").open("xb") as output:
            output.write(scope_raw)
        (directory / "secrets/restoration-plan.json").write_text(
            json.dumps(plan, sort_keys=True), encoding="ascii"
        )
        receipt["source_snapshot"] = network.snapshot_source(ROOT, directory / "source", manifest)
        receipt["retained_copies"] = {}
        for mounted, original, short in (
            (source_run, source_directory, "s"),
            (tool_run, tool_directory, "t"),
        ):
            (directory / "source/var/enterprise/runs" / mounted).mkdir(parents=True)
            receipt["retained_copies"][mounted] = controls.copy_retained(
                original, directory / "r" / short
            )
        receipt["download"] = network.cached_wheels(ROOT, wheel_cache_run, directory / "wheels")
        environment = clean_environment()
        environment.update(
            SB_RESTORE_DB_IMAGE=images["database"],
            SB_RESTORE_PYTHON_IMAGE=images["runner"],
            SB_RESTORE_RUN=run,
            SB_RESTORE_RUN_DIR=str(directory),
            SB_RESTORE_SOURCE_RUN=source_run,
            SB_RESTORE_SOURCE_RUN_DIR=str(directory / "r/s"),
            SB_RESTORE_TOOL_RUN=tool_run,
            SB_RESTORE_TOOL_RUN_DIR=str(directory / "r/t"),
            DOCKER_CONFIG=str(private_docker_config(directory, docker)),
        )
        private_acl(run, "Verify")
        guard = arm_guard(docker, run, initial)
        for _ in range(20):
            require(guard.poll() is None)
            if (directory / "watchdog-ready.json").exists():
                require_guard(guard, run, directory)
                break
            time.sleep(0.25)
        else:
            raise base.LabControlError("Restoration watchdog readiness expired.")
        receipt.update(
            execute(docker, run, directory, images, environment, guard, plan, archive, initial)
        )
        receipt["status"] = "passed_execution_pending_shutdown"
    except Exception as error:
        receipt["error_class"] = type(error).__name__
        if isinstance(error, base.LabControlError):
            receipt["error_code"] = str(error)
    finally:
        main = {"run_id": run, "shutdown_verified": False}
        try:
            main.update(
                stopped_component_count=controls.stop_scope(docker, run), shutdown_verified=True
            )
        except Exception as error:
            main["shutdown_error_class"] = type(error).__name__
        receipt["main_shutdown"] = main
        receipt["main_shutdown_verified"] = main["shutdown_verified"]
        receipt["independent_shutdown_verified"] = False
        if guard is not None:
            try:
                (directory / "launcher-finished.json").write_text(
                    json.dumps({"run_id": run}), encoding="utf8"
                )
                guard.wait(timeout=55)
                independent = read_json(directory / "watchdog.json")
                receipt["independent_shutdown"] = independent
                receipt["independent_shutdown_verified"] = bool(
                    independent.get("run_id") == run and independent.get("shutdown_verified")
                )
            except Exception as error:
                receipt["independent_shutdown_error_class"] = type(error).__name__
        receipt.update(
            finished_at=datetime.now(timezone.utc).isoformat(),
            free_disk_after_bytes=shutil.disk_usage(ROOT).free,
        )
        try:
            receipt["source_unchanged"] = same(manifest, source_manifest(ROOT))
            receipt["source_archive_unchanged"] = (
                hashlib.sha256(
                    (source_directory / "evidence/console-events.json").read_bytes()
                ).hexdigest()
                == plan["console_events_sha256"]
            )
        except Exception:
            receipt["source_unchanged"] = receipt["source_archive_unchanged"] = False
        passed = bool(
            receipt["status"] == "passed_execution_pending_shutdown"
            and receipt["source_unchanged"]
            and receipt["source_archive_unchanged"]
            and receipt["main_shutdown_verified"]
            and receipt["independent_shutdown_verified"]
        )
        receipt.update(acceptance_passed=passed, status="passed" if passed else "incomplete")
        raw = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("ascii")
        with (directory / "receipt.json").open("xb") as output:
            output.write(raw)
        public_id = started.strftime("%Y%m%d") + "-console-restoration-" + run
        public = receipt_path(ROOT, "docs/evidence/" + public_id + ".json", public_id)
        with public.open("xb") as output:
            output.write(raw)
    return directory, passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("launch")
    start.add_argument("--docker", type=Path, required=True)
    start.add_argument("--approval-reference", required=True)
    start.add_argument("--profile", choices=tuple(controls.PROFILES), required=True)
    start.add_argument("--source-run", required=True)
    start.add_argument("--tool-run", required=True)
    start.add_argument("--wheel-cache-run", required=True)
    start.add_argument("--stage-initial-free-disk", type=int, required=True)
    guard = commands.add_parser("watchdog")
    guard.add_argument("--docker", type=Path, required=True)
    guard.add_argument("--run", required=True)
    guard.add_argument("--deadline", type=float, required=True)
    guard.add_argument("--initial-free-disk", type=int, required=True)
    options = parser.parse_args()
    if options.command == "watchdog":
        controls.watchdog(
            options.docker,
            options.run,
            ROOT,
            options.deadline,
            options.initial_free_disk,
            base.private_run_directory(ROOT, options.run) / "watchdog.json",
        )
        return 0
    directory, passed = launch(
        options.docker,
        options.approval_reference,
        options.profile,
        options.source_run,
        options.tool_run,
        options.wheel_cache_run,
        options.stage_initial_free_disk,
    )
    print("Restoration receipt retained: " + str(directory))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
