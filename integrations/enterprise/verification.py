"""Offline preparation and independent shutdown for the first native DB gate.

No image pulls, application startup, migrations, VM changes or unrelated shutdowns.
The operator must separately authorize and invoke a native launch.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

GIB = 1024**3
MIN_FREE_DISK = 25 * GIB
MAX_STAGE_GROWTH = 2 * GIB
MIN_FREE_MEMORY = 4 * GIB
MAX_RUNTIME_SECONDS = 1800
IMAGE_TAG = "postgres:17.11"
IMAGE_DIGEST = "sha256:e31e3d5327d1806f6177827c9710643e4f35f7ab3f14d26d05332753d3e95ee0"
IMAGE_REFERENCE = "postgres@" + IMAGE_DIGEST
PROJECT_PREFIX = "sb-enterprise-verify-"


class LabControlError(ValueError):
    pass


def validate_identity(run_id):
    if not isinstance(run_id, str) or not re.fullmatch(r"[a-f0-9]{32}", run_id):
        raise LabControlError("Invalid verification run identity.")
    return run_id


def check_capacity(free_disk, free_memory, initial_free_disk=None, max_growth=MAX_STAGE_GROWTH):
    if max_growth not in (2 * GIB, 5 * GIB, 8 * GIB):
        raise LabControlError("Unreviewed stage growth limit.")
    initial_free_disk = free_disk if initial_free_disk is None else initial_free_disk
    growth = max(0, initial_free_disk - free_disk)
    if growth >= max_growth:
        raise LabControlError("Stage disk-growth ceiling already reached; launch refused.")
    if free_disk < MIN_FREE_DISK + max_growth - growth:
        raise LabControlError("Insufficient disk reserve for this bounded stage.")
    if free_memory < MIN_FREE_MEMORY + 512 * 1024**2:
        raise LabControlError("Insufficient available memory and host headroom.")


def private_run_directory(workspace, run_id):
    """Reject redirected directories before creating secret-bearing run files."""
    validate_identity(run_id)
    workspace = Path(workspace).absolute()
    target = workspace / "var/enterprise/runs" / run_id
    for path in (workspace, workspace / "var", workspace / "var/enterprise", target.parent, target):
        if path.exists() or path.is_symlink():
            attributes = getattr(path.lstat(), "st_file_attributes", 0)
            if path.is_symlink() or attributes & 0x400 or not path.is_dir():
                raise LabControlError("Private run directory must not be redirected or a file.")
    if not target.resolve().is_relative_to(workspace.resolve()):
        raise LabControlError("Private run directory escaped the workspace.")
    return target


def check_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 15432))


def docker_environment():
    return {name: value for name, value in os.environ.items() if not name.startswith("DOCKER_")}


def docker_command(docker, arguments):
    if os.name != "nt":
        raise LabControlError(
            "This native verification launcher targets Windows Docker Desktop only."
        )
    return [str(docker), "--host", "npipe:////./pipe/dockerDesktopLinuxEngine", *arguments]


def docker_result(docker, arguments, timeout=15):
    result = subprocess.run(
        docker_command(docker, arguments),
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        shell=False,
        env=docker_environment(),
    )
    if result.returncode:
        # Docker diagnostics can contain secret-bearing configuration. Preserve
        # a fixed control error, never copy stderr into public receipts.
        raise LabControlError("Docker control failed; review private runtime state.")
    return result.stdout.strip()


def inspect_local_image(docker):
    image_id = docker_result(docker, ["image", "inspect", IMAGE_REFERENCE, "--format", "{{.Id}}"])
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
        raise LabControlError("An immutable installed PostgreSQL image is unavailable.")
    version = docker_result(
        docker, ["image", "inspect", IMAGE_REFERENCE, "--format", "{{.Os}}|{{.Architecture}}"]
    )
    if version != "linux|amd64":
        raise LabControlError("Unexpected database image platform.")
    digests = json.loads(
        docker_result(
            docker, ["image", "inspect", IMAGE_REFERENCE, "--format", "{{json .RepoDigests}}"]
        )
    )
    if not isinstance(digests, list) or not any(
        value in (IMAGE_REFERENCE, "docker.io/library/" + IMAGE_REFERENCE) for value in digests
    ):
        raise LabControlError("Installed image does not match the reviewed official digest.")
    return image_id


def validate_container(docker, container_id, run_id):
    validate_identity(run_id)
    if not re.fullmatch(r"[a-f0-9]{64}", container_id):
        raise LabControlError("Invalid container identity.")
    labels = json.loads(
        docker_result(docker, ["inspect", container_id, "--format", "{{json .Config.Labels}}"])
    )
    if (
        labels.get("org.signalbridge.enterprise.run") != run_id
        or labels.get("org.signalbridge.enterprise.scope") != "disposable-postgresql-verification"
        or labels.get("com.docker.compose.project") != PROJECT_PREFIX + run_id
    ):
        raise LabControlError("Container ownership does not match this isolated run.")


def guarded_stop(docker, container_id, run_id):
    validate_container(docker, container_id, run_id)
    docker_result(docker, ["stop", "--time", "10", container_id], timeout=20)
    running = docker_result(docker, ["inspect", container_id, "--format", "{{.State.Running}}"])
    if running != "false":
        raise LabControlError("Bounded shutdown was not verified.")


def owned_containers(docker, run_id):
    validate_identity(run_id)
    output = docker_result(
        docker,
        [
            "ps",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            "label=org.signalbridge.enterprise.run=" + run_id,
            "--filter",
            "label=org.signalbridge.enterprise.scope=disposable-postgresql-verification",
            "--filter",
            "label=com.docker.compose.project=" + PROJECT_PREFIX + run_id,
        ],
    )
    containers = output.splitlines() if output else []
    for container in containers:
        validate_container(docker, container, run_id)
    return containers


def await_container_watchdog(
    docker, run_id, workspace, deadline, initial_free_disk, receipt, max_growth=MAX_STAGE_GROWTH
):
    """Arm before startup, so losing the launcher does not leave an unguarded DB."""
    validate_identity(run_id)
    if not 0 < deadline - time.time() <= MAX_RUNTIME_SECONDS:
        raise LabControlError("Watchdog deadline is outside the bounded stage.")
    Path(receipt).with_name("watchdog-ready.json").write_text(
        json.dumps({"run_id": run_id, "armed": True}) + "\n", encoding="utf8"
    )
    handed_off = False
    result = {"run_id": run_id, "reason": "no_container_started", "shutdown_verified": False}
    try:
        while time.time() < deadline:
            containers = owned_containers(docker, run_id)
            if len(containers) > 1:
                raise LabControlError("Unexpected additional containers in the verification scope.")
            if containers:
                handed_off = True
                return watchdog(
                    docker,
                    containers[0],
                    run_id,
                    workspace,
                    deadline,
                    initial_free_disk,
                    receipt,
                    max_growth=max_growth,
                )
            if Path(receipt).with_name("launcher-finished.json").exists():
                break
            free = shutil.disk_usage(workspace).free
            if free < MIN_FREE_DISK:
                result["reason"] = "disk_reserve_before_startup"
                raise LabControlError("Disk reserve failed before startup.")
            if initial_free_disk - free >= max_growth:
                result["reason"] = "disk_growth_before_startup"
                raise LabControlError("Stage growth limit reached before startup.")
            time.sleep(min(2, max(0, deadline - time.time())))
    except Exception as error:
        result["error_class"] = type(error).__name__
        raise
    finally:
        if not handed_off:
            # Startup can race an error in this process: re-inventory the exact
            # owned scope and stop it before retaining an early-failure receipt.
            try:
                for container in owned_containers(docker, run_id):
                    guarded_stop(docker, container, run_id)
                result["shutdown_verified"] = True
            except Exception as error:
                result["shutdown_error_class"] = type(error).__name__
            result["stopped_at"] = datetime.now(timezone.utc).isoformat()
            Path(receipt).write_text(json.dumps(result, indent=2) + "\n", encoding="utf8")


def watchdog(
    docker,
    container_id,
    run_id,
    workspace,
    deadline,
    initial_free_disk,
    receipt,
    max_growth=MAX_STAGE_GROWTH,
):
    """Independent process: finite deadline + capacity floor, exact owned target."""
    validate_identity(run_id)
    remaining = deadline - time.time()
    if not 0 < remaining <= MAX_RUNTIME_SECONDS:
        raise LabControlError("Watchdog deadline is outside the bounded stage.")
    validate_container(docker, container_id, run_id)
    result = {"run_id": run_id, "reason": "deadline", "shutdown_verified": False}
    try:
        while time.time() < deadline:
            free = shutil.disk_usage(workspace).free
            if free < MIN_FREE_DISK:
                result["reason"] = "disk_reserve"
                break
            if initial_free_disk - free >= max_growth:
                result["reason"] = "disk_growth"
                break
            running = docker_result(
                docker, ["inspect", container_id, "--format", "{{.State.Running}}"]
            )
            if running == "false":
                result["reason"] = "already_stopped"
                break
            if running != "true":
                raise LabControlError("Unrecognized container state.")
            time.sleep(min(2, max(0, deadline - time.time())))
    except Exception as error:
        result.update(reason="control_error", error_class=type(error).__name__)
        raise
    finally:
        try:
            guarded_stop(docker, container_id, run_id)
            result["shutdown_verified"] = True
        except Exception as error:
            result["shutdown_error_class"] = type(error).__name__
        result["stopped_at"] = datetime.now(timezone.utc).isoformat()
        Path(receipt).write_text(json.dumps(result, indent=2) + "\n", encoding="utf8")
    if not result["shutdown_verified"]:
        raise LabControlError("Independent watchdog could not verify shutdown.")
