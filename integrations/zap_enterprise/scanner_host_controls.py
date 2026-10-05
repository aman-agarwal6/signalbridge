"""Exact scanner ownership/isolation and a separate finite host shutdown guard.

Imports perform no IO. Daemon access is only through explicitly invoked reviewed
launch/guard calls. The only mutation is stopping this run's verified scanner;
there is no pull, prune, volume removal, socket mount or source connection.
"""

import math
import re
import shutil
import time
from datetime import datetime, timezone

from bridge.contract import parse_json, timestamp
from integrations.enterprise import verification as base
from integrations.enterprise.network_verification import host_path
from integrations.enterprise.reference_host_controls import (
    GROWTH,
    INITIAL_DISK,
    read_json,
    runtime_fields,
    same,
    write_control,
)

from .scanner_contract import IMAGE, MEMORY, hex_value
from .scanner_controls import PREFIX, SCOPE, expected_config

MAX_GUARD_SECONDS = 900


def require(condition):
    if not condition:
        raise base.LabControlError(
            "The closed offline scanner runtime or shutdown boundary changed."
        )


def image_identity(data):
    require(
        isinstance(data, dict)
        and set(data) == {"id", "os", "architecture", "digests", "environment"}
    )
    require(isinstance(data["id"], str) and re.fullmatch(r"sha256:[a-f0-9]{64}", data["id"]))
    require(data["os"] == "linux" and data["architecture"] == "amd64")
    require(isinstance(data["digests"], list) and 1 <= len(data["digests"]) <= 16)
    require(all(isinstance(v, str) and len(v) <= 256 for v in data["digests"]))
    require(any(item in (IMAGE, "docker.io/" + IMAGE) for item in data["digests"]))
    environment(data["environment"])
    return data["id"]


def inspect_image(docker):
    raw = base.docker_result(
        docker,
        [
            "image",
            "inspect",
            IMAGE,
            "--format",
            '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},"digests":{{json .RepoDigests}},"environment":{{json .Config.Env}}}',
        ],
        timeout=5,
    )
    require(len(raw.encode()) <= 65536)
    data = parse_json(raw.encode())
    image_identity(data)
    return data


def environment(rows):
    require(isinstance(rows, list) and 1 <= len(rows) <= 64)
    result = {}
    for row in rows:
        require(isinstance(row, str) and 1 <= len(row) <= 4096 and "=" in row)
        name, value = row.split("=", 1)
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) and name not in result)
        result[name] = value
    return result


def role(docker, identifier, run):
    base.validate_identity(run)
    hex_value(identifier)
    raw = base.docker_result(
        docker,
        [
            "inspect",
            identifier,
            "--format",
            '{"labels":{{json .Config.Labels}},"name":{{json .Name}}}',
        ],
        timeout=5,
    )
    data = parse_json(raw.encode())
    require(isinstance(data, dict) and set(data) == {"labels", "name"})
    labels = data["labels"]
    require(isinstance(labels, dict) and data["name"] == "/" + PREFIX + run)
    expected = {
        "org.signalbridge.enterprise.run": run,
        "org.signalbridge.enterprise.scope": SCOPE,
        "com.docker.compose.project": PREFIX + run,
        "com.docker.compose.service": "scanner",
    }
    require(all(labels.get(key) == value for key, value in expected.items()))
    return "scanner"


def inventory(docker, run):
    base.validate_identity(run)
    raw = base.docker_result(
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
            "--filter",
            "label=com.docker.compose.project=" + PREFIX + run,
        ],
        timeout=5,
    )
    items = raw.splitlines() if raw else []
    require(len(items) <= 4 and len(items) == len(set(items)))
    require(all(re.fullmatch(r"[a-f0-9]{64}", item) for item in items))
    return items


def owned(docker, run):
    return {identifier: role(docker, identifier, run) for identifier in inventory(docker, run)}


def stop_scope(docker, run):
    errors, targets = [], []
    for identifier in inventory(docker, run):
        try:
            role(docker, identifier, run)
            targets.append(identifier)
        except Exception:
            errors.append("ownership")
    for identifier in targets:
        try:
            role(docker, identifier, run)
            base.docker_result(docker, ["stop", "--time", "10", identifier], timeout=20)
            require(
                base.docker_result(
                    docker, ["inspect", identifier, "--format", "{{.State.Running}}"], timeout=5
                )
                == "false"
            )
        except Exception:
            errors.append("shutdown")
    require(not errors)
    return len(targets)


def runtime_template():
    extra = {
        "network_mode": ".HostConfig.NetworkMode",
        "init": ".HostConfig.Init",
        "shm": ".HostConfig.ShmSize",
        "health": ".Config.Healthcheck",
    }
    return (
        runtime_fields()[:-1]
        + ","
        + ",".join('"' + k + '":{{json ' + v + "}}" for k, v in extra.items())
        + "}"
    )


def validate_runtime(data, image, run, directory):
    identity = image_identity(image)
    require(isinstance(data, dict))
    expected = expected_config(identity, run, directory)["services"]["scanner"]
    fixed = {
        "image": identity,
        "memory": MEMORY,
        "swap": MEMORY,
        "cpu": 1500000000,
        "pids": 256,
        "readonly": True,
        "privileged": False,
        "cap_drop": ["ALL"],
        "security": ["no-new-privileges:true"],
        "restart": "no",
        "user": "1000:1000",
        "pid_mode": "",
        "ipc_mode": "private",
        "uts_mode": "",
        "cgroup_mode": "private",
        "log": {"Type": "json-file", "Config": {"max-size": "2m", "max-file": "2"}},
        "command": expected["command"],
        "entrypoint": expected["entrypoint"],
        "workdir": "/workspace",
        "network_mode": "none",
        "init": True,
        "shm": 16 * 1024**2,
    }
    fields = set(fixed) | {
        "cap_add",
        "devices",
        "device_requests",
        "port_bindings",
        "ports",
        "health",
        "networks",
        "environment",
        "tmpfs",
        "mounts",
    }
    require(set(data) == fields and all(same(data[key], value) for key, value in fixed.items()))
    require(
        all(
            data[k] in (None, [], {})
            for k in ("cap_add", "devices", "device_requests", "port_bindings")
        )
    )
    require(
        data["ports"] is None
        or (isinstance(data["ports"], dict) and all(v is None for v in data["ports"].values()))
    )
    require(isinstance(data["health"], dict) and data["health"].get("Test") == ["NONE"])
    require(
        set(data["health"])
        <= {"Test", "Interval", "Timeout", "StartPeriod", "StartInterval", "Retries"}
    )
    require(
        same(
            environment(data["environment"]),
            {**environment(image["environment"]), **expected["environment"]},
        )
    )
    require(data["networks"] is None or isinstance(data["networks"], dict))
    networks = data["networks"] or {}
    require(set(networks) <= {"none"})
    for endpoint in networks.values():
        require(
            isinstance(endpoint, dict)
            and all(
                endpoint.get(k, "") == ""
                for k in ("IPAddress", "GlobalIPv6Address", "Gateway", "IPv6Gateway", "MacAddress")
            )
        )
    temporary = {item.split(":", 1)[0]: item.split(":", 1)[1] for item in expected["tmpfs"]}
    require(same(data["tmpfs"], temporary))
    mounts = data["mounts"]
    require(isinstance(mounts, list) and len(mounts) <= 4)
    require(all(isinstance(m, dict) and m.get("Type") in ("bind", "tmpfs") for m in mounts))
    actual = {}
    for mount in mounts:
        destination = mount.get("Destination")
        require(isinstance(destination, str) and destination not in actual)
        actual[destination] = mount
    if "/tmp" in actual:
        require(actual["/tmp"]["Type"] == "tmpfs" and actual["/tmp"].get("RW") is True)
        actual.pop("/tmp")
    require(set(actual) == {"/workspace", "/input", "/evidence"})
    for mount in expected["volumes"]:
        observed = actual[mount["target"]]
        require(
            observed["Type"] == "bind" and observed.get("RW") is (not mount.get("read_only", False))
        )
        require(
            isinstance(observed.get("Source"), str)
            and host_path(observed["Source"]) == host_path(mount["source"])
        )
    return {"component": "scanner", "effective_runtime_verified": True, "network_mode": "none"}


def verify_runtime(docker, identifier, run, directory, image):
    role(docker, identifier, run)
    raw = base.docker_result(
        docker, ["inspect", identifier, "--format", runtime_template()], timeout=5
    )
    require(len(raw.encode()) <= 131072)
    return validate_runtime(parse_json(raw.encode()), image, run, directory)


def check_capacity(free_disk, free_memory):
    require(type(free_disk) is int and type(free_memory) is int)
    growth = max(0, INITIAL_DISK - free_disk)
    require(growth < GROWTH and free_disk >= base.MIN_FREE_DISK + GROWTH - growth)
    require(free_memory >= base.MIN_FREE_MEMORY + MEMORY)


def validate_shutdown(main, independent, run, *, started, finished):
    base.validate_identity(run)
    require(same(main, {"run_id": run, "shutdown_verified": True, "stopped_component_count": 1}))
    require(
        isinstance(independent, dict)
        and set(independent)
        == {"run_id", "shutdown_verified", "reason", "stopped_component_count", "stopped_at"}
    )
    require(independent["run_id"] == run and independent["shutdown_verified"] is True)
    require(
        type(independent["stopped_component_count"]) is int
        and independent["stopped_component_count"] == 1
    )
    require(
        independent["reason"] == "launcher_finished"
        and started <= timestamp(independent["stopped_at"]) <= finished
    )
    return {"main_shutdown_verified": True, "independent_shutdown_verified": True}


def watchdog(docker, run, workspace, deadline, memory_probe):
    base.validate_identity(run)
    require(type(deadline) in (int, float) and math.isfinite(deadline))
    remaining = deadline - time.time()
    require(0 < remaining <= MAX_GUARD_SECONDS)
    directory = base.private_run_directory(workspace, run)
    stop_at = time.monotonic() + remaining
    write_control(workspace, run, "watchdog-ready.json", {"run_id": run, "armed": True})
    result = {"run_id": run, "shutdown_verified": False, "reason": "deadline"}
    abort = None
    try:
        while time.monotonic() < stop_at:
            try:
                free = shutil.disk_usage(workspace).free
                if free < base.MIN_FREE_DISK:
                    abort = abort or "disk_reserve"
                elif INITIAL_DISK - free >= GROWTH:
                    abort = abort or "disk_growth"
                elif memory_probe() < base.MIN_FREE_MEMORY:
                    abort = abort or "host_memory"
                targets = owned(docker, run)
                if len(targets) > 1:
                    abort = abort or "unexpected_components"
                for identifier in targets:
                    state = base.docker_result(
                        docker, ["inspect", identifier, "--format", "{{.State.Status}}"], timeout=5
                    )
                    if state not in ("created", "running", "exited", "dead"):
                        abort = abort or "component_state"
                if abort:
                    if not (directory / "watchdog-abort.json").exists():
                        write_control(
                            workspace, run, "watchdog-abort.json", {"run_id": run, "reason": abort}
                        )
                    stop_scope(docker, run)
                finished = directory / "launcher-finished.json"
                if finished.exists():
                    require(same(read_json(finished), {"run_id": run}))
                    result["reason"] = abort or "launcher_finished"
                    break
            except Exception as error:
                abort = abort or "control_error"
                result["control_error_class"] = type(error).__name__
                if not (directory / "watchdog-abort.json").exists():
                    write_control(
                        workspace, run, "watchdog-abort.json", {"run_id": run, "reason": abort}
                    )
                try:
                    stop_scope(docker, run)
                except Exception as stop_error:
                    result["last_shutdown_error_class"] = type(stop_error).__name__
            time.sleep(min(2, max(0, stop_at - time.monotonic())))
    finally:
        try:
            result["stopped_component_count"] = stop_scope(docker, run)
            result["shutdown_verified"] = True
        except Exception as error:
            result["shutdown_error_class"] = type(error).__name__
        result["reason"] = abort or result["reason"]
        result["stopped_at"] = datetime.now(timezone.utc).isoformat()
        write_control(workspace, run, "watchdog.json", result)
    return result
