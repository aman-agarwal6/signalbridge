"""Closed Windows Docker controls. Importing this module performs no IO."""

import math
import re
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from bridge.contract import parse_json
from integrations.enterprise import verification as base
from integrations.enterprise.network_verification import host_path
from integrations.enterprise.reference_host_controls import (
    INITIAL_DISK,
    read_json,
    runtime_fields,
    same,
    write_control,
)

from .collector_profile import APPS, CHANNELS, IMAGE, recipe
from .contract import require

PREFIX, SCOPE = "sb-enterprise-wazuh-", "wazuh-reference-bootstrap"
GROWTH = 12 * 1024**3
REVIEWED_CAPACITY_GROWTH = 30 * 1024**3
MEMORY = 1536 * 1024**2


def profile(publication=False):
    """Two closed profiles; the default retains the historical snapshot contract."""
    require(type(publication) is bool, "collector_profile")
    conf = recipe()
    if publication:
        conf["native_driver_arguments"] = [
            "-B",
            "-m",
            "integrations.wazuh_enterprise.native_live_collector",
        ]
    return conf, "wazuh-ready-publication" if publication else SCOPE


def request(docker, run, workspace, arguments, timeout=5):
    base.validate_identity(run)
    config = base.private_run_directory(workspace, run) / "docker-config"
    return base.docker_result(docker, ["--config", str(config), *arguments], timeout=timeout)


def environment(rows):
    require(type(rows) is list and 1 <= len(rows) <= 64, "collector_image_environment")
    result = {}
    for row in rows:
        require(
            type(row) is str and 0 < len(row) <= 4096 and "=" in row, "collector_image_environment"
        )
        name, value = row.split("=", 1)
        require(
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) and name not in result,
            "collector_image_environment",
        )
        require(
            name not in {"PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_AUDIT"},
            "collector_image_preload",
        )
        result[name] = value
    return result


def image_identity(value):
    require(
        type(value) is dict
        and set(value) == {"id", "os", "architecture", "digests", "environment", "volumes"},
        "collector_image_fields",
    )
    require(
        type(value["id"]) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", value["id"]),
        "collector_image_identity",
    )
    require(value["os"] == "linux" and value["architecture"] == "amd64", "collector_image_platform")
    require(
        type(value["digests"]) is list
        and 1 <= len(value["digests"]) <= 16
        and all(type(v) is str and len(v) <= 256 for v in value["digests"]),
        "collector_image_digests",
    )
    require(
        any(v in (IMAGE, "docker.io/" + IMAGE) for v in value["digests"]), "collector_image_digest"
    )
    require(value["volumes"] in (None, {}), "collector_image_implicit_volumes")
    environment(value["environment"])
    return value["id"]


def inspect_image(docker, run, workspace):
    # Docker omits Volumes when an image declares none. Direct field access in
    # a composite template errors on that absent map key; index returns null.
    # Nonempty declared volumes are still rejected by image_identity below.
    template = '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},"digests":{{json .RepoDigests}},"environment":{{json .Config.Env}},"volumes":{{json (index .Config "Volumes")}}}'
    raw = request(docker, run, workspace, ["image", "inspect", IMAGE, "--format", template])
    require(len(raw.encode()) <= 65536, "collector_image_size")
    value = parse_json(raw.encode())
    image_identity(value)
    return value


def mounts(directory):
    root = Path(directory)
    return {
        "/workspace": (root / "source", True),
        "/evidence": (root / "evidence", False),
        **{
            f"/signalbridge/input/{app}/{channel}": (root / "input" / app / channel, True)
            for app in APPS
            for channel in CHANNELS
        },
    }


def create_arguments(image, run, directory, *, publication=False):
    """One closed argument array; no shell, pull, build, arbitrary volumes or stock init."""
    base.validate_identity(run)
    identity = image_identity(image)
    directory = Path(directory)
    require(directory.is_absolute(), "collector_directory")
    conf, scope = profile(publication)
    rows = [
        "create",
        "--pull=never",
        "--name",
        PREFIX + run,
        "--hostname",
        "sb-wazuh-lab",
        "--label",
        "org.signalbridge.enterprise.run=" + run,
        "--label",
        "org.signalbridge.enterprise.scope=" + scope,
        "--label",
        "org.signalbridge.enterprise.component=collector",
        "--network",
        "none",
        "--restart",
        "no",
        "--user",
        "0:0",
        "--init",
        "--ipc",
        "private",
        "--cgroupns",
        "private",
        "--shm-size",
        "16777216",
        "--memory",
        str(MEMORY),
        "--memory-swap",
        str(MEMORY),
        "--cpus",
        "1",
        "--pids-limit",
        "256",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--no-healthcheck",
        "--log-driver",
        "json-file",
        "--log-opt",
        "max-size=2m",
        "--log-opt",
        "max-file=2",
        "--workdir",
        "/workspace",
        "--entrypoint",
        conf["native_driver_entrypoint"],
    ]
    for capability in conf["container"]["cap_add"]:
        rows += ["--cap-add", capability]
    for name, value in {
        "SB_WAZUH_ENTERPRISE_RUN": str(uuid.UUID(run)),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
    }.items():
        rows += ["--env", name + "=" + value]
    for target, (source, readonly) in mounts(directory).items():
        text = str(source)
        require(not any(c in text for c in (",", "\x00", "\r", "\n", '"')), "collector_mount_path")
        rows += [
            "--mount",
            "type=bind,source=" + text + ",target=" + target + (",readonly" if readonly else ""),
        ]
    return [*rows, identity, *conf["native_driver_arguments"]]


def owned(docker, run, workspace, *, publication=False):
    _, scope = profile(publication)
    raw = request(
        docker,
        run,
        workspace,
        [
            "ps",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            "label=org.signalbridge.enterprise.run=" + run,
            "--filter",
            "label=org.signalbridge.enterprise.scope=" + scope,
        ],
    )
    items = raw.splitlines() if raw else []
    require(
        len(items) <= 2
        and len(items) == len(set(items))
        and all(re.fullmatch(r"[a-f0-9]{64}", v) for v in items),
        "collector_inventory",
    )
    for identifier in items:
        role(docker, identifier, run, workspace, publication=publication)
    return items


def role(docker, identifier, run, workspace, *, publication=False):
    _, scope = profile(publication)
    require(
        type(identifier) is str and re.fullmatch(r"[a-f0-9]{64}", identifier),
        "collector_container_identity",
    )
    raw = request(
        docker,
        run,
        workspace,
        [
            "inspect",
            identifier,
            "--format",
            '{"labels":{{json .Config.Labels}},"name":{{json .Name}}}',
        ],
    )
    require(len(raw.encode()) <= 16384, "collector_container_identity_size")
    value = parse_json(raw.encode())
    expected = {
        "org.signalbridge.enterprise.run": run,
        "org.signalbridge.enterprise.scope": scope,
        "org.signalbridge.enterprise.component": "collector",
    }
    require(
        type(value) is dict
        and set(value) == {"labels", "name"}
        and type(value["labels"]) is dict
        and len(value["labels"]) <= 64
        and all(value["labels"].get(k) == v for k, v in expected.items())
        and value["name"] == "/" + PREFIX + run,
        "collector_container_ownership",
    )


def runtime_template():
    extra = {
        "network_mode": ".HostConfig.NetworkMode",
        "init": ".HostConfig.Init",
        "shm": ".HostConfig.ShmSize",
        "health": ".Config.Healthcheck",
    }
    return (
        # No tmpfs is requested by this profile; Docker omits that optional
        # map entry. Preserve null for the existing no-extra-mounts check.
        runtime_fields().replace("json .HostConfig.Tmpfs", 'json (index .HostConfig "Tmpfs")')[:-1]
        + ","
        + ",".join('"' + k + '":{{json ' + v + "}}" for k, v in extra.items())
        + "}"
    )


def validate_runtime(value, image, run, directory, *, publication=False):
    base.validate_identity(run)
    conf, _ = profile(publication)
    fixed = {
        "image": image_identity(image),
        "memory": MEMORY,
        "swap": MEMORY,
        "cpu": 1000000000,
        "pids": 256,
        "readonly": False,
        "privileged": False,
        "cap_drop": ["ALL"],
        "security": ["no-new-privileges:true"],
        "restart": "no",
        "user": "0:0",
        "pid_mode": "",
        "ipc_mode": "private",
        "uts_mode": "",
        "cgroup_mode": "private",
        "log": {"Type": "json-file", "Config": {"max-size": "2m", "max-file": "2"}},
        "command": conf["native_driver_arguments"],
        "entrypoint": [conf["native_driver_entrypoint"]],
        "workdir": "/workspace",
        "network_mode": "none",
        "init": True,
        "shm": 16777216,
    }
    other = {
        "cap_add",
        "devices",
        "device_requests",
        "port_bindings",
        "ports",
        "networks",
        "environment",
        "tmpfs",
        "mounts",
        "health",
    }
    require(
        type(value) is dict
        and set(value) == set(fixed) | other
        and all(same(value[k], v) for k, v in fixed.items()),
        "collector_runtime_controls",
    )
    require(
        type(value["cap_add"]) is list
        and all(type(capability) is str for capability in value["cap_add"])
        and sorted(capability.removeprefix("CAP_") for capability in value["cap_add"])
        == sorted(conf["container"]["cap_add"]),
        "collector_runtime_capabilities",
    )
    require(
        all(
            value[k] in (None, [], {})
            for k in ("devices", "device_requests", "port_bindings", "tmpfs")
        ),
        "collector_runtime_devices",
    )
    require(
        value["ports"] is None
        or (type(value["ports"]) is dict and all(v is None for v in value["ports"].values())),
        "collector_runtime_ports",
    )
    require(same(value["health"], {"Test": ["NONE"]}), "collector_runtime_health")
    require(
        same(
            environment(value["environment"]),
            {
                **environment(image["environment"]),
                "SB_WAZUH_ENTERPRISE_RUN": str(uuid.UUID(run)),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUTF8": "1",
            },
        ),
        "collector_runtime_environment",
    )
    require(
        value["networks"] is None or type(value["networks"]) is dict, "collector_runtime_network"
    )
    for key, endpoint in (value["networks"] or {}).items():
        require(
            key == "none"
            and type(endpoint) is dict
            and all(
                endpoint.get(k, "") == ""
                for k in ("IPAddress", "GlobalIPv6Address", "Gateway", "IPv6Gateway", "MacAddress")
            ),
            "collector_runtime_network",
        )
    expected, actual = mounts(directory), {}
    require(
        type(value["mounts"]) is list and len(value["mounts"]) == len(expected),
        "collector_runtime_mounts",
    )
    for observed in value["mounts"]:
        require(
            type(observed) is dict
            and observed.get("Destination") in expected
            and observed["Destination"] not in actual,
            "collector_runtime_mounts",
        )
        target = observed["Destination"]
        source, readonly = expected[target]
        require(
            observed.get("Type") == "bind"
            and observed.get("RW") is (not readonly)
            and observed.get("Propagation") == "rprivate"
            and type(observed.get("Source")) is str
            and host_path(observed["Source"]) == host_path(str(source)),
            "collector_runtime_mounts",
        )
        actual[target] = observed
    return {"effective_runtime_verified": True, "component": "collector", "network_mode": "none"}


def verify_runtime(docker, identifier, run, workspace, image, *, publication=False):
    role(docker, identifier, run, workspace, publication=publication)
    raw = request(docker, run, workspace, ["inspect", identifier, "--format", runtime_template()])
    require(len(raw.encode()) <= 131072, "collector_runtime_size")
    return validate_runtime(
        parse_json(raw.encode()),
        image,
        run,
        base.private_run_directory(workspace, run),
        publication=publication,
    )


def check_capacity(disk, memory, *, launching=False, growth_ceiling=GROWTH):
    require(type(disk) is int and type(memory) is int, "collector_capacity_types")
    require(
        type(launching) is bool
        and type(growth_ceiling) is int
        and growth_ceiling in (GROWTH, REVIEWED_CAPACITY_GROWTH),
        "collector_capacity_profile",
    )
    growth = max(0, INITIAL_DISK - disk)
    require(
        growth < growth_ceiling and disk >= base.MIN_FREE_DISK + growth_ceiling - growth,
        "collector_disk_budget",
    )
    require(memory >= base.MIN_FREE_MEMORY + (MEMORY if launching else 0), "collector_host_memory")


def stop_scope(docker, run, workspace, *, publication=False, admit_stop=None):
    targets = owned(docker, run, workspace, publication=publication)
    errors = []
    for identifier in targets:
        try:
            role(docker, identifier, run, workspace, publication=publication)
            if admit_stop is not None:
                require(admit_stop(identifier) is True, "collector_cleanup_admission")
            request(docker, run, workspace, ["stop", "--time", "10", identifier], timeout=20)
            require(
                request(
                    docker,
                    run,
                    workspace,
                    ["inspect", identifier, "--format", "{{.State.Running}}"],
                )
                == "false",
                "collector_shutdown",
            )
        except Exception:
            errors.append("shutdown")
    require(not errors, "collector_shutdown")
    return len(targets)


def watchdog(
    docker, run, workspace, deadline, memory_probe, *, publication=False, preservation=None
):
    base.validate_identity(run)
    require(type(deadline) in (int, float) and math.isfinite(deadline), "collector_guard_deadline")
    remaining = deadline - time.time()
    require(0 < remaining <= 900, "collector_guard_deadline")
    stop_at = time.monotonic() + remaining
    directory = base.private_run_directory(workspace, run)
    image = read_json(directory / "image.json", 65536)
    image_identity(image)
    write_control(workspace, run, "watchdog-ready.json", {"run_id": run, "armed": True})
    result, abort = {"run_id": run, "shutdown_verified": False, "reason": "deadline"}, None
    preservation_failed = False
    try:
        while time.monotonic() < stop_at:
            try:
                check_capacity(
                    shutil.disk_usage(workspace).free,
                    memory_probe(),
                    growth_ceiling=preservation.growth_ceiling if preservation else GROWTH,
                )
                targets = owned(docker, run, workspace, publication=publication)
                require(len(targets) <= 1, "collector_guard_components")
                if preservation is not None:
                    try:
                        preservation.checkpoint(targets)
                    except Exception:
                        preservation_failed = True
                        raise
                for identifier in targets:
                    verify_runtime(
                        docker, identifier, run, workspace, image, publication=publication
                    )
                    require(
                        request(
                            docker,
                            run,
                            workspace,
                            ["inspect", identifier, "--format", "{{.State.Status}}"],
                        )
                        in ("created", "running", "exited", "dead"),
                        "collector_guard_state",
                    )
                if (directory / "launcher-finished.json").exists():
                    require(
                        same(read_json(directory / "launcher-finished.json"), {"run_id": run}),
                        "collector_guard_finished",
                    )
                    result["reason"] = "launcher_finished"
                    break
            except Exception as error:
                abort = "control_error"
                result["control_error_class"] = type(error).__name__
                if not (directory / "watchdog-abort.json").exists():
                    write_control(
                        workspace, run, "watchdog-abort.json", {"run_id": run, "reason": abort}
                    )
                try:
                    stop_scope(
                        docker,
                        run,
                        workspace,
                        publication=publication,
                        **({"admit_stop": preservation.admit_stop} if preservation else {}),
                    )
                except Exception as stop_error:
                    result["last_shutdown_error_class"] = type(stop_error).__name__
                if (directory / "launcher-finished.json").exists():
                    break
            time.sleep(min(2, max(0, stop_at - time.monotonic())))
    finally:
        if publication:
            # A timed-out native request may finish after the launcher returns.
            # Inspect and stop the exact run for a fixed additional minute.
            # This is a bounded observation window, not indefinite settlement.
            drain_started = time.monotonic()
            drain_until = drain_started + 60
            drain_complete = True
            while time.monotonic() < drain_until:
                try:
                    stop_scope(
                        docker,
                        run,
                        workspace,
                        publication=publication,
                        **({"admit_stop": preservation.admit_stop} if preservation else {}),
                    )
                except Exception as error:
                    drain_complete = False
                    result["drain_error_class"] = type(error).__name__
                if preservation is not None:
                    try:
                        preservation.checkpoint(owned(docker, run, workspace, publication=True))
                    except Exception as error:
                        abort = "preservation_error"
                        preservation_failed = True
                        result["preservation_error_class"] = type(error).__name__
                time.sleep(min(2, max(0, drain_until - time.monotonic())))
            result.update(
                late_operation_drain_seconds=60,
                late_operation_drain_elapsed_ms=int((time.monotonic() - drain_started) * 1000),
                late_operation_drain_verified=drain_complete,
            )
        try:
            result.update(
                stopped_component_count=stop_scope(
                    docker,
                    run,
                    workspace,
                    publication=publication,
                    **({"admit_stop": preservation.admit_stop} if preservation else {}),
                ),
                shutdown_verified=True,
            )
            if publication and not result["late_operation_drain_verified"]:
                result["shutdown_verified"] = False
        except Exception as error:
            result["shutdown_error_class"] = type(error).__name__
            result["shutdown_verified"] = False
        if preservation is not None:
            try:
                final = preservation.checkpoint(owned(docker, run, workspace, publication=True))
                result["preservation_final"] = final
            except Exception as error:
                preservation_failed = True
                result["preservation_error_class"] = type(error).__name__
            result["preservation_verified"] = not preservation_failed
        result.update(
            reason=abort or result["reason"], stopped_at=datetime.now(timezone.utc).isoformat()
        )
        write_control(workspace, run, "watchdog.json", result)
    return result
