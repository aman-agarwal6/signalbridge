"""Closed Wazuh manager service for the paced 24-hour reliability profile.

The manager runs beside the runner in the same reviewed recipe with no network,
the existing reviewed manager image, capabilities, limits and configuration.
It tails the console's live SOC observation segments through read-only binds of
the two deterministic stream directories. No import performs IO; the reviewed
launcher calls these functions. A recipe is never launch authorization.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from integrations.wazuh_enterprise.collector_profile import APPS, CHANNELS, IMAGE, recipe

from .verification import LabControlError, validate_identity

ROLE = "wazuh"
STREAM_NAMESPACE = uuid.UUID("5f0c8f62-8a7e-5d55-9d3a-6c1b2b9a4e10")
CONTINUOUS_MODULE = "integrations.wazuh_enterprise.native_continuous_collector"
EVIDENCE = ("wazuh", "evidence")
CLOCK = "clock"


def stream_id(run, app):
    """Deterministic observation stream identity, recomputed by host and console."""
    validate_identity(run)
    if app not in APPS:
        raise LabControlError("Unknown reliability stream application.")
    return str(uuid.uuid5(STREAM_NAMESPACE, run + "/" + app + "/observation"))


def input_sources(directory, run):
    """Host directories bound read-only at the reviewed manager input mounts."""
    root = Path(directory)
    rows = {}
    for app in APPS:
        for channel in CHANNELS:
            if channel == "observation":
                source = (
                    root / "evidence/soc-delivery/enterprise" / app / channel / stream_id(run, app)
                )
            else:
                # This workload forwards no detections; the reviewed profile still
                # watches the channel, so it gets an empty run-owned directory.
                source = root / "wazuh/idle" / app / channel
            rows["/signalbridge/input/" + app + "/" + channel] = source
    return rows


def segment_files(directory, run):
    """Every monitored segment, created empty before the manager starts.

    The native log collector stops retrying files that are absent when it
    starts, so the reviewed empty-file publication pattern is reused: the
    console later appends to these exact files (it accepts an empty one).
    """
    names = {"observation": "observations", "detection": "detections"}
    return [
        source / f"{names[target.rsplit('/', 1)[1]]}-{number:03}.jsonl"
        for target, source in input_sources(directory, run).items()
        for number in range(8)
    ]


def host_directories(directory, run):
    root = Path(directory)
    return [
        root / CLOCK,
        root.joinpath(*EVIDENCE),
        *input_sources(directory, run).values(),
    ]


def service(images, run, directory):
    """The expected parsed Compose service for the manager role."""
    validate_identity(run)
    container = recipe()["container"]
    root = Path(directory).as_posix()
    volumes = [
        {
            "type": "bind",
            "source": root + "/source",
            "target": "/workspace",
            "read_only": True,
            "bind": {},
        },
        {
            "type": "bind",
            "source": root + "/" + "/".join(EVIDENCE),
            "target": "/evidence",
            "bind": {},
        },
        {
            "type": "bind",
            "source": root + "/" + CLOCK,
            "target": "/signalbridge/clock",
            "read_only": True,
            "bind": {},
        },
    ]
    for target, source in input_sources(directory, run).items():
        volumes.append(
            {
                "type": "bind",
                "source": Path(source).as_posix(),
                "target": target,
                "read_only": True,
                "bind": {},
            }
        )
    return {
        "image": images[ROLE],
        "pull_policy": "never",
        "restart": "no",
        "user": container["user"],
        "init": True,
        "mem_limit": str(container["memory_bytes"]),
        "memswap_limit": str(container["memory_swap_bytes"]),
        "cpus": container["cpus"],
        "pids_limit": container["pids"],
        "shm_size": str(container["shm_bytes"]),
        "ipc": "private",
        "cgroup": "private",
        "network_mode": "none",
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["ALL"],
        "cap_add": list(container["cap_add"]),
        "hostname": "sb-wazuh-lab",
        "labels": {
            "org.signalbridge.enterprise.run": run,
            "org.signalbridge.enterprise.scope": "reference-access-verification",
        },
        "entrypoint": [recipe()["native_driver_entrypoint"]],
        "command": ["-B", "-m", CONTINUOUS_MODULE],
        "working_dir": "/workspace",
        "environment": {
            "SB_WAZUH_ENTERPRISE_RUN": str(uuid.UUID(run)),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
        },
        "logging": {"driver": "json-file", "options": {"max-file": "2", "max-size": "2m"}},
        "volumes": volumes,
    }


def window_plan(run, scale=1.0):
    from .reliability_ledger import wazuh_plan

    return wazuh_plan(str(uuid.UUID(run)), scale)


def prepare_evidence(directory, run, scale=1.0, now=None):
    """Fresh manager evidence: context, pinned source digests and the window plan.

    The manager refuses a context older than fifteen minutes, so the launcher
    writes this immediately before starting the manager container.
    """
    from bridge.contract import canonical
    from integrations.wazuh_enterprise.native_continuous_collector import SOURCE_FILES

    evidence = Path(directory).joinpath(*EVIDENCE)
    if any(evidence.iterdir()):
        raise LabControlError("Reliability manager evidence must start empty.")
    files = {
        name: hashlib.sha256((Path(directory) / "source" / name).read_bytes()).hexdigest()
        for name in SOURCE_FILES
    }
    plan = canonical(window_plan(run, scale)) + b"\n"
    context = {
        "context_version": 1,
        "run_id": str(uuid.UUID(run)),
        "prepared_at": (now or datetime.now(timezone.utc)).isoformat(),
        "source_sha256": hashlib.sha256(canonical(files)).hexdigest(),
        "manifest_sha256": hashlib.sha256(plan).hexdigest(),
    }
    for name, raw in (
        ("source-manifest.json", canonical({"files": files}) + b"\n"),
        ("manifest.json", plan),
        ("run-context.json", canonical(context) + b"\n"),
    ):
        with (evidence / name).open("xb") as stream:
            stream.write(raw)
    return {"source_sha256": context["source_sha256"], "plan_sha256": context["manifest_sha256"]}


def effective_template():
    rows = {
        "image": ".Image",
        "memory": ".HostConfig.Memory",
        "swap": ".HostConfig.MemorySwap",
        "cpu": ".HostConfig.NanoCpus",
        "pids": ".HostConfig.PidsLimit",
        "shm": ".HostConfig.ShmSize",
        "init": ".HostConfig.Init",
        "readonly": ".HostConfig.ReadonlyRootfs",
        "privileged": ".HostConfig.Privileged",
        "cap_drop": ".HostConfig.CapDrop",
        "cap_add": ".HostConfig.CapAdd",
        "security": ".HostConfig.SecurityOpt",
        "restart": ".HostConfig.RestartPolicy.Name",
        "network_mode": ".HostConfig.NetworkMode",
        "networks": ".NetworkSettings.Networks",
        "port_bindings": ".HostConfig.PortBindings",
        "mounts": ".Mounts",
        "user": ".Config.User",
        "devices": ".HostConfig.Devices",
        "pid_mode": ".HostConfig.PidMode",
        "ipc_mode": ".HostConfig.IpcMode",
        "cgroup_mode": ".HostConfig.CgroupnsMode",
        "entrypoint": ".Config.Entrypoint",
        "command": ".Config.Cmd",
        "workdir": ".Config.WorkingDir",
        "environment": ".Config.Env",
    }
    return "{" + ",".join('"' + k + '":{{json ' + v + "}}" for k, v in rows.items()) + "}"


def verify_effective(data, images, run, directory, host_path):
    """Compare one inspected manager container with the closed expected service."""
    expected = service(images, run, directory)
    container = recipe()["container"]
    try:
        environment = dict(item.split("=", 1) for item in data["environment"])
        fixed = {
            "image": images[ROLE],
            "memory": container["memory_bytes"],
            "swap": container["memory_swap_bytes"],
            "cpu": container["cpus"] * 10**9,
            "pids": container["pids"],
            "shm": container["shm_bytes"],
            "init": True,
            "readonly": False,
            "privileged": False,
            "cap_drop": ["ALL"],
            "security": ["no-new-privileges:true"],
            "restart": "no",
            "network_mode": "none",
            "user": container["user"],
            "pid_mode": "",
            "ipc_mode": "private",
            "cgroup_mode": "private",
            "entrypoint": expected["entrypoint"],
            "command": expected["command"],
            "workdir": "/workspace",
        }
        # Docker may report capabilities with or without the CAP_ prefix.
        added = sorted(c.removeprefix("CAP_") for c in data["cap_add"] or [])
        if (
            any(json.dumps(data[k]) != json.dumps(v) for k, v in fixed.items())
            or added != sorted(container["cap_add"])
            or set(data["networks"] or {}) not in (set(), {"none"})
            or data["port_bindings"] not in (None, {})
            or data["devices"] not in (None, [])
            or any(environment.get(k) != v for k, v in expected["environment"].items())
        ):
            raise LabControlError("Reliability manager resources or privileges changed.")
        mounts = data["mounts"]
        if not isinstance(mounts, list) or len({m["Destination"] for m in mounts}) != len(mounts):
            raise LabControlError("Duplicate or malformed reliability manager mounts.")
        actual = {m["Destination"]: m for m in mounts}
        required = {
            item["target"]: (item["source"], item.get("read_only", False) is not True)
            for item in expected["volumes"]
        }
        if set(actual) != set(required) or any(
            actual[target]["Type"] != "bind"
            or actual[target]["RW"] is not writable
            or host_path(actual[target]["Source"]) != host_path(source)
            for target, (source, writable) in required.items()
        ):
            raise LabControlError("Reliability manager mount scope changed.")
    except (TypeError, KeyError, AttributeError, ValueError) as error:
        if isinstance(error, LabControlError):
            raise
        raise LabControlError("Malformed reliability manager configuration.") from None
    return {"component": ROLE, "effective_runtime_verified": True, "network": "none"}


def inspect_image(docker):
    """The installed reviewed manager image; never pulls. Returns its local ID."""
    from integrations.wazuh_enterprise.collector_host_controls import image_identity

    from .verification import docker_result

    template = (
        '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},'
        '"digests":{{json .RepoDigests}},"environment":{{json .Config.Env}},'
        '"volumes":{{json (index .Config "Volumes")}}}'
    )
    raw = docker_result(docker, ["image", "inspect", IMAGE, "--format", template], timeout=5)
    if len(raw.encode()) > 65536:
        raise LabControlError("Reliability manager image inspection exceeded its bound.")
    try:
        return image_identity(json.loads(raw))
    except (ValueError, TypeError) as error:
        raise LabControlError("The reviewed manager image is unavailable or changed.") from error


def compose_environment(run):
    return {
        "SB_WAZUH_RUN": str(uuid.UUID(run)),
        "SB_RELIABILITY_DOCUMENTS_STREAM": stream_id(run, "documents"),
        "SB_RELIABILITY_EXPENSES_STREAM": stream_id(run, "expenses"),
    }
