"""Opt-in Wazuh preservation profile; import and cleanup admission are inert.

Only injected, engine-bound requests may read fixed minimal metadata. Keep all
baseline paths, engine/container IDs and envelopes private; public results contain
counts/digests. The caller secures a fresh private run and retains the expected
digest separately, binds the adapter to the reviewed engine, and authorizes this
profile separately. This module neither grants authorization nor mutates Docker.

Snapshots establish only the sampled envelope. They cannot prove application
health, uninterrupted service, all configuration, filesystem aliases, or absence
of administrator/race/resource interference. Recheck engine identity and the
native host's label/name/image/runtime ownership immediately before own cleanup.
Preserved drift must abort the stage, never prevent scoped own cleanup or trigger
repair of preserved workloads.
"""

import hashlib
import hmac
import json
import re
from datetime import datetime

from integrations.enterprise import preserved_workloads as workloads
from integrations.enterprise.verification import LabControlError, validate_identity

from . import collector_host_controls as host

PROFILE = "wazuh-preserve-baseline-v1"
MAX_PRESERVED, MAX_MOUNTS, MAX_NETWORKS = 8, 16, 8
MAX_ENVELOPE_BYTES, MAX_BASELINE_BYTES, MAX_PATH = 32768, 262144, 1024
INFO_TEMPLATE = '{"id":{{json .ID}},"os_type":{{json .OSType}}}'
INFO_ARGUMENTS = ("info", "--format", INFO_TEMPLATE)
ENVELOPE_FIELDS = {
    "id": ".Id",
    "running": ".State.Running",
    "started_at": ".State.StartedAt",
    "restart_count": ".RestartCount",
    "mounts": ".Mounts",
    "privileged": ".HostConfig.Privileged",
    "pid_mode": ".HostConfig.PidMode",
    "ipc_mode": ".HostConfig.IpcMode",
    "uts_mode": ".HostConfig.UTSMode",
    "cgroupns_mode": ".HostConfig.CgroupnsMode",
    "network_mode": ".HostConfig.NetworkMode",
    "memory": ".HostConfig.Memory",
    "memory_swap": ".HostConfig.MemorySwap",
    "nano_cpus": ".HostConfig.NanoCpus",
    "pids_limit": ".HostConfig.PidsLimit",
}
ENVELOPE_TEMPLATE = (
    "{"
    + ",".join('"' + key + '":{{json ' + value + "}}" for key, value in ENVELOPE_FIELDS.items())
    + ',"networks":{'
    + '{{$sep := ""}}{{range $name, $network := .NetworkSettings.Networks}}'
    + '{{$sep}}{{json $name}}:{{json $network.NetworkID}}{{$sep = ","}}{{end}}}}'
)
BASELINE_FIELDS = {
    "schema_version",
    "profile",
    "run_id",
    "private_run",
    "reviewed_context_digest",
    "engine",
    "running_baseline",
    "envelopes",
    "sha256",
}
MOUNT_REQUIRED = {"Type", "Source", "Destination", "RW"}
MOUNT_FIELDS = MOUNT_REQUIRED | {"Name", "Driver", "Mode", "Propagation"}


def require(condition, message="Wazuh preservation rejected an invalid or unknown state."):
    if not condition:
        raise LabControlError(message)


def scalar(value, maximum=128):
    require(type(value) is str and 0 < len(value) <= maximum)
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", value))
    return value


def digest(value):
    return hashlib.sha256(workloads.canonical(value)).hexdigest()


def json_value(raw, limit):
    require(type(raw) is str)
    try:
        require(len(raw.encode("utf8")) <= limit)
    except UnicodeError:
        raise LabControlError("Wazuh preservation metadata is malformed.") from None

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, RecursionError):
        raise LabControlError("Wazuh preservation metadata is malformed.") from None


def read(request, arguments, limit):
    require(callable(request))
    try:
        raw = request(tuple(arguments), timeout=3)
    except Exception:
        raise LabControlError("Wazuh preservation metadata is unavailable.") from None
    return json_value(raw, limit)


def allowed_arguments(arguments):
    return arguments in (INFO_ARGUMENTS, workloads.RUNNING_ARGUMENTS) or (
        type(arguments) is tuple
        and len(arguments) == 5
        and arguments[:2] == ("container", "inspect")
        and type(arguments[2]) is str
        and re.fullmatch(r"[a-f0-9]{64}", arguments[2])
        and arguments[3:] == ("--format", ENVELOPE_TEMPLATE)
    )


def bind_request(docker, run_id, workspace):
    """Create an inert adapter; calling it permits only these fixed read operations."""
    validate_identity(run_id)

    def request(arguments, *, timeout):
        require(type(arguments) is tuple and allowed_arguments(arguments) and timeout == 3)
        return host.request(docker, run_id, workspace, arguments, timeout=3)

    return request


def engine_value(value):
    require(type(value) is dict and set(value) == {"id", "os_type"})
    scalar(value["id"])
    require(value["os_type"] == "linux")
    return dict(value)


def engine(request):
    return engine_value(read(request, INFO_ARGUMENTS, 512))


def normalized_path(value):
    """Lexical identity only; reject opaque WSL/proxy, UNC/device and alias paths."""
    require(type(value) is str and 0 < len(value) <= MAX_PATH)
    require(not any(ord(character) < 32 or ord(character) == 127 for character in value))
    require(not any(character in value for character in ("%", "~", "\x00")))
    path = value.replace("\\", "/")
    require(not path.startswith("//") and "//" not in path)
    for prefix in ("/run/desktop/mnt/host/", "/host_mnt/"):
        if path.startswith(prefix):
            tail = path[len(prefix) :]
            require(re.fullmatch(r"[A-Za-z](?:/.*)?", tail))
            path = tail[0] + ":/" + tail[2:]
            break
    else:
        require(not path.startswith(("/run/desktop/mnt", "/host_mnt", "/mnt/")))
    windows = bool(re.match(r"^[A-Za-z]:/", path))
    require(windows or path.startswith("/"))
    root, remainder = ("win:" + path[:2].lower(), path[3:]) if windows else ("posix:", path[1:])
    components = remainder.rstrip("/").split("/") if remainder.rstrip("/") else []
    require(
        all(part not in ("", ".", "..") and not part.endswith((".", " ")) for part in components)
    )
    require(not windows or all(":" not in part for part in components))
    if windows:
        require(
            all(
                not re.fullmatch(r"(?i)(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part)
                for part in components
            )
        )
        components = [part.casefold() for part in components]
    return root + "/" + "/".join(components)


def overlaps(first, second):
    return (
        first == second
        or first.startswith(second.rstrip("/") + "/")
        or second.startswith(first.rstrip("/") + "/")
    )


def control_mount(path):
    lowered = path.casefold().replace("\\", "/")
    if "pipe/" in lowered or re.search(
        r"(?:^|/)(?:docker[^/]*\.sock|docker_engine|dockerdesktoplinuxengine|dockerdesktopwindowsengine)(?:/|$)",
        lowered,
    ):
        return True
    normalized = normalized_path(path)
    return any(
        overlaps(normalized, "posix:" + endpoint)
        for endpoint in ("/run/docker.sock", "/var/run/docker.sock")
    )


def mount_value(value, private_run):
    require(type(value) is dict and MOUNT_REQUIRED <= set(value) <= MOUNT_FIELDS)
    require(
        type(value["Type"]) is str
        and value["Type"] in {"bind", "volume", "tmpfs"}
        and type(value["RW"]) is bool
    )
    require(type(value["Source"]) is str and type(value["Destination"]) is str)
    require(value["Destination"].startswith("/") and not control_mount(value["Destination"]))
    result = dict(value)
    result["Destination"] = normalized_path(value["Destination"])
    if value["Source"]:
        require(not control_mount(value["Source"]))
        result["Source"] = normalized_path(value["Source"])
        if value["Type"] == "bind":
            require(
                not overlaps(result["Source"], private_run),
                "Preserved bind source overlaps the private run.",
            )
    else:
        require(value["Type"] == "tmpfs")
    for key in set(value) - MOUNT_REQUIRED:
        require(
            type(value[key]) is str
            and len(value[key]) <= 128
            and not any(ord(c) < 32 for c in value[key])
        )
    return result


def envelope_value(value, identifier, private_run):
    workloads.identifiers((identifier,))
    require(type(value) is dict and set(value) == set(ENVELOPE_FIELDS) | {"networks"})
    require(value["id"] == identifier and value["running"] is True and value["privileged"] is False)
    started = value["started_at"]
    require(
        type(started) is str
        and re.fullmatch(
            r"[1-9][0-9]{3}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", started
        )
    )
    try:
        require(datetime.fromisoformat(started.replace("Z", "+00:00")).year >= 2000)
    except ValueError:
        raise LabControlError("Preserved start timestamp is invalid.") from None
    require(type(value["restart_count"]) is int and 0 <= value["restart_count"] <= 1000000)
    for key, allowed in (
        ("pid_mode", {"", "private"}),
        ("ipc_mode", {"", "private", "shareable"}),
        ("uts_mode", {"", "private"}),
        ("cgroupns_mode", {"private"}),
    ):
        require(type(value[key]) is str and value[key] in allowed)
    scalar(value["network_mode"])
    require(value["network_mode"] != "host" and ":" not in value["network_mode"])
    for key in ("memory", "nano_cpus"):
        require(type(value[key]) is int and 0 <= value[key] <= 2**50)
    require(type(value["memory_swap"]) is int and -1 <= value["memory_swap"] <= 2**50)
    require(
        value["pids_limit"] is None
        or (type(value["pids_limit"]) is int and -1 <= value["pids_limit"] <= 2**32)
    )
    require(type(value["networks"]) is dict and len(value["networks"]) <= MAX_NETWORKS)
    for name, network_id in value["networks"].items():
        scalar(name)
        workloads.identifiers((network_id,))
    require(type(value["mounts"]) is list and len(value["mounts"]) <= MAX_MOUNTS)
    mounts = [mount_value(mount, private_run) for mount in value["mounts"]]
    require(len({mount["Destination"] for mount in mounts}) == len(mounts))
    return {**value, "mounts": sorted(mounts, key=lambda mount: mount["Destination"])}


def inspect(request, identifier, private_run):
    arguments = ("container", "inspect", identifier, "--format", ENVELOPE_TEMPLATE)
    return envelope_value(read(request, arguments, MAX_ENVELOPE_BYTES), identifier, private_run)


def context(run_id, private_directory, reviewed_context_digest):
    validate_identity(run_id)
    workloads.identifiers((reviewed_context_digest,))
    private_run = normalized_path(str(private_directory))
    require(
        private_run.startswith("win:") and private_run.endswith("/var/enterprise/runs/" + run_id)
    )
    return private_run


def validate_baseline(
    baseline, run_id, private_directory, reviewed_context_digest, *, expected_digest
):
    private_run = context(run_id, private_directory, reviewed_context_digest)
    workloads.identifiers((expected_digest,))
    require(type(baseline) is dict and set(baseline) == BASELINE_FIELDS)
    require(type(baseline["schema_version"]) is int and baseline["schema_version"] == 1)
    require(baseline["profile"] == PROFILE and baseline["run_id"] == run_id)
    require(
        baseline["private_run"] == private_run
        and baseline["reviewed_context_digest"] == reviewed_context_digest
    )
    engine_value(baseline["engine"])
    running = baseline["running_baseline"]
    require(type(running) is dict and running.get("profile") == "preserve-baseline")
    preserved = workloads.validate_baseline(running, run_id, running.get("sha256"))
    require(
        len(preserved) <= MAX_PRESERVED
        and type(baseline["envelopes"]) is dict
        and set(baseline["envelopes"]) == set(preserved)
    )
    for identifier in preserved:
        # Stored envelopes retain raw mount metadata; normalization is performed
        # for comparison, not stored as a second interpretation of host paths.
        envelope_value(baseline["envelopes"][identifier], identifier, private_run)
    workloads.identifiers((baseline["sha256"],))
    payload = {key: value for key, value in baseline.items() if key != "sha256"}
    require(len(workloads.canonical(baseline)) <= MAX_BASELINE_BYTES)
    require(
        hmac.compare_digest(digest(payload), expected_digest)
        and hmac.compare_digest(baseline["sha256"], expected_digest)
    )
    return private_run, preserved


def capture(request, run_id, private_directory, reviewed_context_digest):
    private_run = context(run_id, private_directory, reviewed_context_digest)
    initial_engine = engine(request)
    running, _ = workloads.capture(request, run_id, profile="preserve-baseline")
    preserved = workloads.validate_baseline(running, run_id, running["sha256"])
    require(len(preserved) <= MAX_PRESERVED)
    envelopes = {}
    for identifier in preserved:
        arguments = ("container", "inspect", identifier, "--format", ENVELOPE_TEMPLATE)
        raw = read(request, arguments, MAX_ENVELOPE_BYTES)
        envelope_value(raw, identifier, private_run)
        envelopes[identifier] = raw
    workloads.compare(request, running, run_id, expected_digest=running["sha256"])
    require(engine(request) == initial_engine, "Preservation engine identity changed.")
    baseline = {
        "schema_version": 1,
        "profile": PROFILE,
        "run_id": run_id,
        "private_run": private_run,
        "reviewed_context_digest": reviewed_context_digest,
        "engine": initial_engine,
        "running_baseline": running,
        "envelopes": envelopes,
    }
    baseline["sha256"] = digest(baseline)
    require(len(workloads.canonical(baseline)) <= MAX_BASELINE_BYTES)
    return baseline, {
        "preserved_count": len(preserved),
        "preservation_digest": baseline["sha256"],
        "engine_digest": digest(initial_engine),
    }


def checkpoint(
    request,
    baseline,
    run_id,
    private_directory,
    reviewed_context_digest,
    owned_ids=(),
    *,
    expected_digest,
):
    private_run, preserved = validate_baseline(
        baseline,
        run_id,
        private_directory,
        reviewed_context_digest,
        expected_digest=expected_digest,
    )
    require(len(workloads.identifiers(owned_ids)) <= 1)
    workloads.admitted_sets(
        baseline["running_baseline"], run_id, owned_ids, baseline["running_baseline"]["sha256"]
    )
    require(engine(request) == baseline["engine"], "Preservation engine identity changed.")
    running = baseline["running_baseline"]
    public = workloads.compare(
        request, running, run_id, owned_ids, expected_digest=running["sha256"]
    )
    for identifier in preserved:
        current = inspect(request, identifier, private_run)
        original = envelope_value(baseline["envelopes"][identifier], identifier, private_run)
        require(
            workloads.canonical(current) == workloads.canonical(original),
            "Preserved workload envelope changed.",
        )
    require(engine(request) == baseline["engine"], "Preservation engine identity changed.")
    public = workloads.compare(
        request, running, run_id, owned_ids, expected_digest=running["sha256"]
    )
    return {
        **public,
        "preservation_digest": expected_digest,
        "engine_digest": digest(baseline["engine"]),
    }


def mutation_admitted(
    candidate,
    observed_run_id,
    observed_engine,
    baseline,
    run_id,
    private_directory,
    reviewed_context_digest,
    owned_ids,
    *,
    expected_digest,
):
    """Pure own-cleanup admission; current preserved health is deliberately unused."""
    try:
        validate_baseline(
            baseline,
            run_id,
            private_directory,
            reviewed_context_digest,
            expected_digest=expected_digest,
        )
        require(len(workloads.identifiers(owned_ids)) == 1)
        require(engine_value(observed_engine) == baseline["engine"])
        running = baseline["running_baseline"]
        return workloads.mutation_admitted(
            candidate,
            observed_run_id,
            running,
            run_id,
            owned_ids,
            expected_digest=running["sha256"],
        )
    except LabControlError:
        return False
