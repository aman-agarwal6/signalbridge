"""Host controls for the separate console restoration stage; no import-time I/O.

The retained source volume is only ever mounted read-only into a copy helper.
Every created container, volume and network carries this run and scope label;
nothing is deleted. Shutdown is verified per exact owned container.
"""

import hashlib
import json
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from . import verification as base
from .network_verification import host_path

SCOPE = "console-restoration-verification"
PREFIX = "sb-enterprise-restoration-"
SOURCE_SCOPE = "reference-access-verification"
ROLES = ("copy", "backup", "database", "runner")
MAX_SECONDS = 1500
GROWTH = 8 * base.GIB
PROFILES = {
    "access": "signalbridge-native-reference-access",
    "header": "signalbridge-native-authenticated-header-capture",
}
RUNNER_SECONDS = 390
EXCLUDED = ["docker-config", "secrets"]
SECRETS = {
    "database": {"bootstrap_password", "console_password"},
    "runner": {"console_password", "restoration_plan", "tool_scope"},
}


def require(condition, message="Restoration control predicate failed."):
    if not condition:
        raise base.LabControlError(message)


def labels(run, role):
    base.validate_identity(run)
    require(role in ROLES)
    return {
        "org.signalbridge.enterprise.run": run,
        "org.signalbridge.enterprise.scope": SCOPE,
        "org.signalbridge.enterprise.role": role,
    }


def label_arguments(run, role):
    return [
        argument
        for key, value in labels(run, role).items()
        for argument in ("--label", key + "=" + value)
    ]


def source_volume(source_run):
    base.validate_identity(source_run)
    return "sb-enterprise-reference-" + source_run


def copy_volume(run):
    base.validate_identity(run)
    return PREFIX + "copy-" + run


def check_capacity(disk, memory, initial):
    require(all(type(value) is int and value > 0 for value in (disk, memory, initial)))
    growth = max(0, initial - disk)
    require(growth < GROWTH, "The restoration growth guard is already reached.")
    require(disk >= base.MIN_FREE_DISK + GROWTH - growth, "Insufficient disk reserve.")
    require(memory >= base.MIN_FREE_MEMORY + base.GIB, "Insufficient host memory headroom.")


def verify_source_volume(docker, source_run):
    """The retained volume belongs to its exact source run and nothing runs on it."""
    name = source_volume(source_run)
    value = json.loads(
        base.docker_result(docker, ["volume", "inspect", name, "--format", "{{json .}}"])
    )
    require(
        value.get("Name") == name
        and value.get("Driver") == "local"
        and value.get("Scope") == "local"
        and (value.get("Labels") or {}).get("org.signalbridge.enterprise.run") == source_run
        and (value.get("Labels") or {}).get("org.signalbridge.enterprise.scope") == SOURCE_SCOPE,
        "The retained source volume identity differs from its native run.",
    )
    running = base.docker_result(
        docker, ["ps", "--quiet", "--no-trunc", "--filter", "volume=" + name], timeout=5
    )
    require(not running, "The retained source volume is in use.")
    return {"name": name, "labels_verified": True, "in_use": False}


def copy_arguments(run, source_run, image):
    """A read-only, network-less helper copies files; the original is never written."""
    return [
        "run",
        "--name",
        PREFIX + run + "-copy",
        *label_arguments(run, "copy"),
        "--network",
        "none",
        "--read-only",
        "--user",
        "postgres",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "256m",
        "--memory-swap",
        "256m",
        "--pids-limit",
        "32",
        "--log-driver",
        "none",
        "--mount",
        "type=volume,src=" + source_volume(source_run) + ",dst=/from,readonly",
        "--mount",
        "type=volume,src=" + copy_volume(run) + ",dst=/var/lib/postgresql/data",
        "--entrypoint",
        "/bin/cp",
        image,
        "-a",
        "/from/.",
        "/var/lib/postgresql/data/",
    ]


def backup_arguments(run, directory, image):
    """Start the copy without TCP; pg_dump runs over its private Unix socket."""
    return [
        "run",
        "--detach",
        "--name",
        PREFIX + run + "-backup",
        *label_arguments(run, "backup"),
        "--network",
        "none",
        "--read-only",
        "--user",
        "postgres",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "512m",
        "--memory-swap",
        "512m",
        "--pids-limit",
        "128",
        "--shm-size",
        "64m",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--tmpfs",
        "/var/run/postgresql:rw,noexec,nosuid,nodev,size=16m",
        "--mount",
        "type=volume,src=" + copy_volume(run) + ",dst=/var/lib/postgresql/data",
        "--mount",
        "type=bind,src=" + str(Path(directory) / "backup") + ",dst=/backup",
        image,
        "postgres",
        "-c",
        "listen_addresses=",
        "-c",
        "log_statement=none",
    ]


def copy_retained(source, destination):
    """Byte-exact copy of one retained run, without its private credentials.

    Container-written files keep restrictive owner modes through the Desktop
    bind mount; the unprivileged runner reads this verified copy instead.
    """
    source, destination = Path(source), Path(destination)
    require(not destination.exists(), "Retained copy destination already exists.")
    files, total, tree = 0, 0, hashlib.sha256()
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        info = path.lstat()
        require(
            not path.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400,
            "Retained runs must not contain redirected paths.",
        )
        if relative.parts[0] in EXCLUDED:
            continue
        target = destination / relative
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        raw = path.read_bytes()
        files, total = files + 1, total + len(raw)
        require(files <= 20000 and total <= 512 * 1024**2, "Retained run copy exceeds its bound.")
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(raw)
        checksum = hashlib.sha256(raw).hexdigest()
        require(hashlib.sha256(target.read_bytes()).hexdigest() == checksum)
        tree.update(relative.as_posix().encode() + b"\x00" + checksum.encode() + b"\n")
    return {"files": files, "bytes": total, "tree_sha256": tree.hexdigest(), "excluded": EXCLUDED}


def verify_compose_config(data, images, run, directory):
    services = data.get("services", {})
    require(set(services) == {"database", "runner"}, "Unexpected restoration services.")
    for role in ("database", "runner"):
        service = services[role]
        require(
            service.get("image") == images[role]
            and not service.get("ports")
            and service.get("read_only") is True
            and service.get("cap_drop") == ["ALL"]
            and service.get("privileged") in (None, False)
            and service.get("labels", {}).get("org.signalbridge.enterprise.run") == run
            and service.get("labels", {}).get("org.signalbridge.enterprise.scope") == SCOPE,
            "Parsed restoration service differs from the reviewed profile.",
        )
    network = data.get("networks", {}).get("restoration", {})
    require(
        network.get("internal") is True
        and network.get("name") == PREFIX + "internal-" + run
        and data.get("volumes", {}).get("restored_data", {}).get("name") == PREFIX + run,
        "Parsed restoration isolation differs from the reviewed profile.",
    )


def role_of(docker, identifier, run):
    require(re.fullmatch(r"[a-f0-9]{64}", identifier) is not None)
    value = json.loads(
        base.docker_result(docker, ["inspect", identifier, "--format", "{{json .Config.Labels}}"])
    )
    role = value.get("org.signalbridge.enterprise.role") or value.get("com.docker.compose.service")
    require(
        value.get("org.signalbridge.enterprise.run") == run
        and value.get("org.signalbridge.enterprise.scope") == SCOPE
        and role in ROLES,
        "Container does not belong to this restoration run.",
    )
    return role


def owned(docker, run):
    base.validate_identity(run)
    output = base.docker_result(
        docker,
        [
            "ps",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            "label=org.signalbridge.enterprise.run=" + run,
            "--filter",
            "label=org.signalbridge.enterprise.scope=" + SCOPE,
        ],
    )
    result = {line: role_of(docker, line, run) for line in output.splitlines() if line}
    require(len(result) <= len(ROLES) and len(set(result.values())) == len(result))
    return result


def stop_scope(docker, run):
    """Stop every exact owned component; keep containers, volumes and backup files."""
    errors = []
    targets = owned(docker, run)
    for identifier, _role in sorted(targets.items(), key=lambda row: row[1] == "database"):
        try:
            role_of(docker, identifier, run)
            base.docker_result(docker, ["stop", "--time", "10", identifier], timeout=20)
            state = base.docker_result(
                docker, ["inspect", identifier, "--format", "{{.State.Running}}"]
            )
            require(state == "false", "Component shutdown was not verified.")
        except Exception as error:
            errors.append(type(error).__name__)
    require(not errors, "One or more restoration components could not be verified stopped.")
    return len(targets)


def verify_runtime(docker, identifier, run, directory, image, role):
    require(role_of(docker, identifier, run) == role)
    fields = (
        '{"image":{{json .Image}},"memory":{{.HostConfig.Memory}},"pids":{{.HostConfig.PidsLimit}},'
        '"readonly":{{.HostConfig.ReadonlyRootfs}},"privileged":{{.HostConfig.Privileged}},'
        '"caps":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},'
        '"ports":{{json .HostConfig.PortBindings}},"networks":{{json .NetworkSettings.Networks}},'
        '"network_mode":{{json .HostConfig.NetworkMode}},"mounts":{{json .Mounts}},'
        '"user":{{json .Config.User}}}'
    )
    data = json.loads(base.docker_result(docker, ["inspect", identifier, "--format", fields]))
    require(
        data["image"] == image
        and data["readonly"] is True
        and data["privileged"] is False
        and data["caps"] == ["ALL"]
        and any(item.startswith("no-new-privileges") for item in data["security"] or [])
        and not data["ports"]
        and data["memory"] == (256 if role == "copy" else 512) * 1024**2,
        "Effective restoration container isolation differs from the reviewed profile.",
    )
    if role in ("copy", "backup"):
        require(data["network_mode"] == "none" and set(data["networks"] or {}) <= {"none"})
    else:
        network = PREFIX + "internal-" + run
        require(set(data["networks"] or {}) == {network})
        internal = base.docker_result(
            docker, ["network", "inspect", network, "--format", "{{.Internal}}"]
        )
        require(internal == "true", "The restoration network is not internal.")
    directory = Path(directory)
    expected = {
        "copy": {"/from": False, "/var/lib/postgresql/data": True},
        "backup": {"/var/lib/postgresql/data": True, "/backup": True},
        "database": {
            "/var/lib/postgresql/data": True,
            "/docker-entrypoint-initdb.d/10-restoration.sh": False,
            "/backup": False,
        },
        "runner": {
            "/workspace": False,
            "/wheels": False,
            "/evidence": True,
        },
    }[role]
    mounts = {row["Destination"]: row for row in data["mounts"]}
    retained = {k: v for k, v in mounts.items() if k.startswith("/workspace/var/enterprise/runs/")}
    # Compose delivers file secrets as read-only binds from this run's secrets folder.
    secrets = {k: v for k, v in mounts.items() if k.startswith("/run/secrets/")}
    require(
        {k.rsplit("/", 1)[1] for k in secrets} == SECRETS.get(role, set())
        and all(
            row["RW"] is False
            and host_path(row["Source"]).startswith(host_path(directory / "secrets") + "/")
            for row in secrets.values()
        ),
        "Unexpected restoration secret mounts.",
    )
    require(
        set(mounts) - set(retained) - set(secrets) == set(expected),
        "Unexpected restoration mounts.",
    )
    for destination, writable in expected.items():
        require(mounts[destination]["RW"] is writable, "Restoration mount access changed.")
    if role == "runner":
        require(len(retained) == 2 and all(not row["RW"] for row in retained.values()))
        # Short copy names keep nested retained paths under the Windows limit.
        copies = {host_path(directory / "r" / name) for name in ("s", "t")}
        require(
            {host_path(row["Source"]) for row in retained.values()} == copies,
            "Retained mounts are not the verified copies.",
        )
        sources = {
            "/workspace": directory / "source",
            "/wheels": directory / "wheels",
            "/evidence": directory / "evidence",
        }
        for destination, source in sources.items():
            require(host_path(mounts[destination]["Source"]) == host_path(source))
    else:
        require(not retained)
    require(data["user"] in ("postgres", "10001:10001"))
    return True


def wait_exit(docker, identifier, seconds, guard=None):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if guard is not None:
            guard()
        state = base.docker_result(
            docker,
            ["inspect", identifier, "--format", "{{.State.Status}}|{{.State.ExitCode}}"],
            timeout=5,
        )
        if state.startswith("exited|"):
            return int(state.split("|", 1)[1])
        require(state.startswith(("running|", "created|")), "Unexpected component state.")
        time.sleep(0.5)
    raise base.LabControlError("Restoration component deadline expired.")


def validate_runner(value, plan, archive):
    """Accept only the fixed passed shape with the exact restored archive counts."""
    require(
        type(value) is dict and value.get("passed") is True and value.get("phase") == "complete"
    )
    require(value.get("run_id") == plan["run_id"] and value.get("profile") == plan["profile"])
    require(
        value.get("restored")
        == {
            "events": len(archive["events"]),
            "cases": len(archive["cases"]),
            "archive_sha256": plan["console_events_sha256"],
        },
        "Restored rows do not match the retained archive.",
    )
    pending = value.get("pending_migrations")
    require(type(pending) is list and len(pending) <= 64)
    require(all(isinstance(row, str) and re.fullmatch(r"\w+\.\w+", row) for row in pending))
    workflow = value.get("workflow")
    require(type(workflow) is dict)
    if plan["profile"] == "access":
        require(
            workflow.get("retest_check_runs") == 1
            and workflow.get("self_review_denied") is True
            and workflow.get("independent_review") == "approved"
            and workflow.get("task_status") == "verified"
            and workflow.get("wazuh_case_linked") is True
            and workflow.get("case_page_status") == 200
        )
    else:
        require(
            workflow.get("scoped_check_runs") == 2
            and workflow.get("documents_finding_plugin") == "10021"
            and workflow.get("expenses_finding") is None
            and workflow.get("event_bindings") == {"documents": 6, "expenses": 2}
        )
    return value


def watchdog(docker, run, workspace, deadline, initial_disk, receipt):
    base.validate_identity(run)
    require(0 < deadline - time.time() <= MAX_SECONDS, "Watchdog deadline outside the stage.")
    receipt = Path(receipt)
    temporary = receipt.with_name("watchdog-ready.tmp")
    temporary.write_text(json.dumps({"run_id": run, "armed": True}), encoding="utf8")
    temporary.replace(receipt.with_name("watchdog-ready.json"))
    result = {"run_id": run, "reason": "deadline", "shutdown_verified": False}
    try:
        while time.time() < deadline:
            free = shutil.disk_usage(workspace).free
            if free < base.MIN_FREE_DISK or initial_disk - free >= GROWTH:
                result["reason"] = "disk_reserve" if free < base.MIN_FREE_DISK else "disk_growth"
                break
            owned(docker, run)
            if receipt.with_name("launcher-finished.json").exists():
                result["reason"] = "launcher_finished"
                break
            time.sleep(min(2, max(0, deadline - time.time())))
    except Exception as error:
        result.update(reason="control_error", error_class=type(error).__name__)
    finally:
        try:
            result["stopped_component_count"] = stop_scope(docker, run)
            result["shutdown_verified"] = True
        except Exception as error:
            result["shutdown_error_class"] = type(error).__name__
        result["stopped_at"] = datetime.now(timezone.utc).isoformat()
        receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf8")
    return result
