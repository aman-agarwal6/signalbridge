"""Ownership, effective isolation and independent shutdown for the source proof.

No import performs IO. Functions that control Docker are invoked only by the
separately reviewed host launch. Tests substitute the daemon and host probes.
"""

import json
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from . import verification as base
from .network_verification import host_path
from .reference_controls import PREFIX, SCOPE, SECRETS, expected_config

# Cumulative whole-host free-space loss since the milestone baseline. Matches
# the 30 GiB milestone ceiling used by the Wazuh, identity and monitoring
# stages; the 25 GiB free-disk reserve is enforced separately.
GROWTH = 30 * base.GIB
# 24 h schedule + 10 min drain + setup, teardown and analysis margin.
RELIABILITY_SECONDS = 26 * 3600
# Owner-approved 2026-10-04: the day-long run measures its own growth from launch
# (an existing reviewed 12 GiB ceiling) instead of the cumulative milestone baseline.
RELIABILITY_GROWTH = 12 * base.GIB
INITIAL_DISK = 80498424546
NETWORK_PREFIX = "sb-enterprise-reference-internal-"
CONTROL_FILES = {
    "watchdog-ready.json",
    "watchdog-abort.json",
    "launcher-finished.json",
    "watchdog.json",
}


def same(actual, expected):
    # Python's True == 1 must never accept malformed security controls.
    return json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True)


def read_json(path, limit=4096):
    path = Path(path)
    if (
        not path.is_file()
        or path.is_symlink()
        or getattr(path.lstat(), "st_file_attributes", 0) & 0x400
        or not 0 < path.stat().st_size <= limit
    ):
        raise base.LabControlError("Bounded control receipt is missing or redirected.")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise base.LabControlError("Duplicate control field.")
            result[key] = value
        return result

    try:
        return json.loads(path.read_bytes(), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError):
        raise base.LabControlError("Malformed control receipt.") from None


def write_control(workspace, run, name, value):
    directory = base.private_run_directory(workspace, run)
    if name not in CONTROL_FILES or not directory.is_dir():
        raise base.LabControlError("Control output escaped the source run.")
    path, temporary = directory / name, directory / (name + ".tmp")
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")
    if len(raw) > 4096 or path.exists() or path.is_symlink():
        raise base.LabControlError("Control output already exists or exceeded its bound.")
    with temporary.open("xb") as stream:
        stream.write(raw)
    temporary.replace(path)


def role(docker, identifier, run):
    base.validate_identity(run)
    if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{64}", identifier):
        raise base.LabControlError("Invalid source container identity.")
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
    try:
        data = json.loads(raw)
        labels = data["labels"]
        component = labels["com.docker.compose.service"]
        if (
            labels.get("org.signalbridge.enterprise.run") != run
            or labels.get("org.signalbridge.enterprise.scope") != SCOPE
            or labels.get("com.docker.compose.project") != PREFIX + run
            or component not in ("database", "runner", "wazuh")
            or data["name"] != "/" + PREFIX + run + "-" + component + "-1"
        ):
            raise base.LabControlError("Source container ownership changed.")
    except (TypeError, KeyError, json.JSONDecodeError):
        raise base.LabControlError("Malformed source container ownership.") from None
    return component


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
    if (
        len(items) > 8
        or len(set(items)) != len(items)
        or any(not re.fullmatch(r"[a-f0-9]{64}", item) for item in items)
    ):
        raise base.LabControlError("Source container inventory escaped its bound.")
    return items


def owned(docker, run):
    return {identifier: role(docker, identifier, run) for identifier in inventory(docker, run)}


def stop_scope(docker, run):
    """Try every verified target even if another owner or stop check fails."""
    errors, targets = [], []
    for identifier in inventory(docker, run):
        try:
            targets.append((identifier, role(docker, identifier, run)))
        except Exception:
            errors.append("ownership")
    for identifier, _component in sorted(targets, key=lambda item: item[1] == "database"):
        try:
            role(docker, identifier, run)  # Revalidate immediately before mutation.
            base.docker_result(docker, ["stop", "--time", "10", identifier], timeout=20)
            if (
                base.docker_result(
                    docker, ["inspect", identifier, "--format", "{{.State.Running}}"], timeout=5
                )
                != "false"
            ):
                raise base.LabControlError("Source component still running.")
        except Exception:
            errors.append("shutdown")
    if errors:
        raise base.LabControlError("Not every source component was verified stopped.")
    return len(targets)


def runtime_fields():
    rows = {
        "image": ".Image",
        "memory": ".HostConfig.Memory",
        "swap": ".HostConfig.MemorySwap",
        "cpu": ".HostConfig.NanoCpus",
        "pids": ".HostConfig.PidsLimit",
        "readonly": ".HostConfig.ReadonlyRootfs",
        "privileged": ".HostConfig.Privileged",
        "cap_drop": ".HostConfig.CapDrop",
        "cap_add": ".HostConfig.CapAdd",
        "security": ".HostConfig.SecurityOpt",
        "restart": ".HostConfig.RestartPolicy.Name",
        "ports": ".NetworkSettings.Ports",
        "port_bindings": ".HostConfig.PortBindings",
        "networks": ".NetworkSettings.Networks",
        "mounts": ".Mounts",
        "tmpfs": ".HostConfig.Tmpfs",
        "user": ".Config.User",
        "devices": ".HostConfig.Devices",
        "device_requests": ".HostConfig.DeviceRequests",
        "pid_mode": ".HostConfig.PidMode",
        "ipc_mode": ".HostConfig.IpcMode",
        "uts_mode": ".HostConfig.UTSMode",
        "cgroup_mode": ".HostConfig.CgroupnsMode",
        "log": ".HostConfig.LogConfig",
        "command": ".Config.Cmd",
        "workdir": ".Config.WorkingDir",
        "entrypoint": ".Config.Entrypoint",
        "environment": ".Config.Env",
    }
    return (
        "{" + ",".join('"' + key + '":{{json ' + value + "}}" for key, value in rows.items()) + "}"
    )


def verify_runtime(docker, identifier, run, directory, images, *, profile="access", rehearsal_ms=0):
    component = role(docker, identifier, run)
    if component == "wazuh":
        # Only the reliability profile has a manager; it has its own closed checks.
        if profile != "reliability":
            raise base.LabControlError("A manager component escaped the reliability profile.")
        from .reliability_wazuh import effective_template, verify_effective

        raw = base.docker_result(
            docker, ["inspect", identifier, "--format", effective_template()], timeout=5
        )
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise base.LabControlError("Malformed reliability manager inspection.") from None
        return verify_effective(data, images, run, directory, host_path)
    expected = expected_config(images, run, directory, profile=profile, rehearsal_ms=rehearsal_ms)[
        "services"
    ][component]
    try:
        data = json.loads(
            base.docker_result(
                docker, ["inspect", identifier, "--format", runtime_fields()], timeout=5
            )
        )
        defaults = json.loads(
            base.docker_result(
                docker,
                [
                    "image",
                    "inspect",
                    images[component],
                    "--format",
                    '{"entrypoint":{{json .Config.Entrypoint}},"environment":{{json .Config.Env}},"workdir":{{json .Config.WorkingDir}}}',
                ],
                timeout=5,
            )
        )

        def environment(value):
            if not isinstance(value, list) or not 1 <= len(value) <= 64:
                raise base.LabControlError("Malformed effective source environment.")
            result = {}
            for item in value:
                if not isinstance(item, str) or not 1 <= len(item) <= 4096 or "=" not in item:
                    raise base.LabControlError("Malformed effective source environment.")
                key, body = item.split("=", 1)
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or key in result:
                    raise base.LabControlError("Ambiguous effective source environment.")
                result[key] = body
            return result

        merged = {**environment(defaults["environment"]), **expected["environment"]}
        if (
            not same(data["entrypoint"], defaults["entrypoint"])
            or not same(environment(data["environment"]), merged)
            or (component == "database" and data["workdir"] != defaults["workdir"])
        ):
            raise base.LabControlError("Effective source entrypoint or environment changed.")
        fixed = {
            "image": images[component],
            "memory": int(expected["mem_limit"]),
            "swap": int(expected["memswap_limit"]),
            "cpu": int(expected["cpus"] * 10**9),
            "pids": expected["pids_limit"],
            "readonly": True,
            "privileged": False,
            "cap_drop": ["ALL"],
            "security": ["no-new-privileges:true"],
            "restart": "no",
            "user": expected["user"],
            "pid_mode": "",
            "ipc_mode": "private",
            "uts_mode": "",
            "cgroup_mode": "private",
            "command": expected["command"],
            "log": {"Type": "json-file", "Config": {"max-file": "2", "max-size": "5m"}},
        }
        if (
            not all(same(data[key], value) for key, value in fixed.items())
            or any(
                data[key] not in (None, [], {})
                for key in ("cap_add", "devices", "device_requests", "port_bindings")
            )
            or any(value is not None for value in (data["ports"] or {}).values())
        ):
            raise base.LabControlError("Effective source resources or privileges changed.")
        if component == "runner" and data["workdir"] != "/workspace":
            raise base.LabControlError("Source runner working directory changed.")
        if set(data["networks"] or {}) != {NETWORK_PREFIX + run}:
            raise base.LabControlError("Source component has an unreviewed network.")
        temporary = {item.split(":", 1)[0]: item.split(":", 1)[1] for item in expected["tmpfs"]}
        if not same(data["tmpfs"], temporary):
            raise base.LabControlError("Effective source temporary mounts changed.")
        mounts = data["mounts"]
        if not isinstance(mounts, list) or len({m["Destination"] for m in mounts}) != len(mounts):
            raise base.LabControlError("Duplicate or malformed source mounts.")
        actual = {m["Destination"]: m for m in mounts if m["Type"] != "tmpfs"}
        volume = actual.pop("/var/lib/postgresql/data", None) if component == "database" else None
        if component == "database" and (
            not volume
            or volume["Type"] != "volume"
            or volume["RW"] is not True
            or volume.get("Name") != PREFIX + run
        ):
            raise base.LabControlError("Fresh source database volume binding changed.")
        required = {
            item["target"]: (item["source"], item.get("read_only", False) is not True)
            for item in expected["volumes"]
            if item["type"] == "bind"
        }
        required.update(
            {
                item["target"]: (str(Path(directory) / "secrets" / SECRETS[item["source"]]), False)
                for item in expected["secrets"]
            }
        )
        if set(actual) != set(required) or any(
            actual[target]["Type"] != "bind"
            or actual[target]["RW"] is not writable
            or host_path(actual[target]["Source"]) != host_path(source)
            for target, (source, writable) in required.items()
        ):
            raise base.LabControlError("Effective source mount scope changed.")
    except (TypeError, KeyError, AttributeError, json.JSONDecodeError):
        raise base.LabControlError("Malformed effective source configuration.") from None
    return {"component": component, "effective_runtime_verified": True}


def verify_network_volume(docker, run, targets):
    labels = {
        "org.signalbridge.enterprise.run": run,
        "org.signalbridge.enterprise.scope": SCOPE,
        "com.docker.compose.project": PREFIX + run,
    }
    try:
        network = json.loads(
            base.docker_result(
                docker,
                [
                    "network",
                    "inspect",
                    NETWORK_PREFIX + run,
                    "--format",
                    '{"name":{{json .Name}},"internal":{{json .Internal}},"driver":{{json .Driver}},"labels":{{json .Labels}},"containers":{{json .Containers}},"ingress":{{json .Ingress}}}',
                ],
                timeout=5,
            )
        )
        volume = json.loads(
            base.docker_result(
                docker,
                [
                    "volume",
                    "inspect",
                    PREFIX + run,
                    "--format",
                    '{"name":{{json .Name}},"driver":{{json .Driver}},"labels":{{json .Labels}},"options":{{json .Options}}}',
                ],
                timeout=5,
            )
        )
        if (
            network["name"] != NETWORK_PREFIX + run
            or network["internal"] is not True
            or network["driver"] != "bridge"
            or network["ingress"] is not False
            or not set(network["containers"] or {}).issubset(targets)
            or volume["name"] != PREFIX + run
            or volume["driver"] != "local"
            or volume["options"] not in (None, {})
            or any(
                any(item["labels"].get(k) != v for k, v in labels.items())
                for item in (network, volume)
            )
        ):
            raise base.LabControlError("Source network or volume ownership/isolation changed.")
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError):
        raise base.LabControlError("Malformed source network or volume.") from None
    return {"internal_network_verified": True, "fresh_volume_ownership_verified": True}


def watchdog(docker, run, workspace, deadline, memory_probe, maximum=None):
    """Independent finite guard; abort does not exit while startup could continue.

    Once a capacity/control problem is seen, request abort and keep stopping exact
    owned targets until the launcher finishes or the original deadline expires.
    This prevents a slow startup from creating a running component after one stop.
    """
    base.validate_identity(run)
    if type(deadline) not in (int, float):
        raise base.LabControlError("Source watchdog deadline escaped its reviewed bound.")
    remaining = deadline - time.time()
    # Only the reviewed reliability profile may pass its longer fixed ceiling.
    if maximum not in (None, RELIABILITY_SECONDS):
        raise base.LabControlError("Source watchdog ceiling escaped its reviewed bound.")
    if not 0 < remaining <= (maximum or base.MAX_RUNTIME_SECONDS):
        raise base.LabControlError("Source watchdog deadline escaped its reviewed bound.")
    directory = base.private_run_directory(workspace, run)
    stop_at = time.monotonic() + remaining
    initial_disk, growth_limit = (
        (shutil.disk_usage(workspace).free, RELIABILITY_GROWTH)
        if maximum == RELIABILITY_SECONDS
        else (INITIAL_DISK, GROWTH)
    )
    write_control(workspace, run, "watchdog-ready.json", {"run_id": run, "armed": True})
    result = {"run_id": run, "shutdown_verified": False, "reason": "deadline"}
    abort = None
    try:
        while time.monotonic() < stop_at:
            try:
                free = shutil.disk_usage(workspace).free
                if free < base.MIN_FREE_DISK:
                    abort = abort or "disk_reserve"
                elif initial_disk - free >= growth_limit:
                    abort = abort or "disk_growth"
                elif memory_probe() < base.MIN_FREE_MEMORY:
                    abort = abort or "host_memory"
                targets = owned(docker, run)
                # The reliability profile alone adds its networkless manager.
                allowed = 3 if maximum == RELIABILITY_SECONDS else 2
                if len(targets) > allowed or len(set(targets.values())) != len(targets):
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
                    if not same(read_json(finished), {"run_id": run}):
                        raise base.LabControlError("Invalid source launcher completion signal.")
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
