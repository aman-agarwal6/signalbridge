"""Read-only isolation gate for the fixed, disposable BetTail Supabase lab.

Never starts containers, changes PostgreSQL, reads environment values, or writes readiness.
The sole external probe opens a TCP connection without sending application data.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "signalbridge-bettail-lab"
BACKEND = PROJECT
EDGE = "signalbridge-bettail-edge"
RELAY = "signalbridge-bettail-relay"
CORE = tuple(
    f"supabase_{service}_{PROJECT}"
    for service in ("db", "kong", "auth", "rest", "storage", "inbucket")
)
DB = CORE[0]
NAMES = (*CORE, RELAY)
PIPE = "npipe:////./pipe/dockerDesktopLinuxEngine"
VOLUMES = {DB: "/var/lib/postgresql/data", f"supabase_storage_{PROJECT}": "/mnt"}
PORTS = {"55321/tcp": "55321", "55322/tcp": "55322", "55324/tcp": "55324"}
RELAY_SOURCE = ROOT / "integrations/supabase/loopback-relay.mjs"
CONFIG_SOURCE = ROOT / "var/labs/bettail/supabase/config.toml"
CONTAINER_FIELDS = {
    "Name": ".Name",
    "Id": ".Id",
    "Image": ".Image",
    "State": ".State.Status",
    "Running": ".State.Running",
    "User": ".Config.User",
    "HostConfig": ".HostConfig",
    "Networks": ".NetworkSettings.Networks",
    "Ports": ".NetworkSettings.Ports",
    "Mounts": ".Mounts",
}
# HostConfig includes mount options, but never Config.Env. Restrict its output further below.
HOST_FIELDS = (
    "NetworkMode",
    "Privileged",
    "CapAdd",
    "CapDrop",
    "PidMode",
    "IpcMode",
    "Devices",
    "ReadonlyRootfs",
    "SecurityOpt",
    "PortBindings",
    "PublishAllPorts",
    "RestartPolicy",
    "Memory",
    "MemorySwap",
    "NanoCpus",
    "CpuQuota",
    "CpuPeriod",
    "PidsLimit",
    "OomKillDisable",
)
# These are ceilings for the seven services, not a throughput promise. The
# separate copied-Next gate adds at most 2 GiB RAM and two CPUs.
RESOURCE_LIMITS = {
    DB: (1024 * 1024**2, 1_000_000_000, 256),
    CORE[1]: (256 * 1024**2, 500_000_000, 128),
    CORE[2]: (256 * 1024**2, 500_000_000, 128),
    CORE[3]: (128 * 1024**2, 500_000_000, 128),
    CORE[4]: (384 * 1024**2, 500_000_000, 128),
    CORE[5]: (64 * 1024**2, 250_000_000, 64),
    RELAY: (96 * 1024**2, 500_000_000, 64),
}
LIMITS = [
    "A point-in-time local configuration and connection check, not a hostile-host audit.",
    "The operating system user and Docker administrator remain trusted.",
    "One failed external TCP probe is corroboration; topology and routes enforce the boundary.",
    "No source migration, user authorization, HTTP or storage assertion is established here.",
    "No proof against an administrator modifying the report or environment after this run.",
]


class VerificationError(Exception):
    """Fixed diagnostic only; never expose subprocess output or private configuration."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def template(fields):
    return "{" + ",".join(f'"{key}":{{{{json {value}}}}}' for key, value in fields.items()) + "}"


def container_template():
    fields = dict(CONTAINER_FIELDS)
    del fields["HostConfig"]
    result = template(fields)
    host = template({key: ".HostConfig." + key for key in HOST_FIELDS})
    return result[:-1] + ',"HostConfig":' + host + "}"


def docker(args, *, timeout=20):
    installed = Path(os.environ.get("LOCALAPPDATA", "")) / (
        "Programs/DockerDesktop/resources/bin/docker.exe"
    )
    executable = str(installed) if installed.is_file() else shutil.which("docker")
    if not executable:
        raise VerificationError("docker_executable_missing")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(("DOCKER_", "SUPABASE_"))
    }
    try:
        result = subprocess.run(
            [executable, "--host", PIPE, *args],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError("docker_unavailable_or_timeout") from error
    if result.returncode or len(result.stdout) > 2_000_000:
        raise VerificationError("docker_command_failed")
    return result.stdout.decode("utf-8", errors="strict").strip()


def inspect_objects(kind, names, fields):
    output = docker([kind, "inspect", "--format", fields, *names])
    try:
        rows = [json.loads(line) for line in output.splitlines()]
    except (ValueError, TypeError) as error:
        raise VerificationError("invalid_inspection_output") from error
    if len(rows) != len(names):
        raise VerificationError("inspection_count_mismatch")
    return rows


def gather_topology():
    containers = inspect_objects("container", NAMES, container_template())
    networks = inspect_objects(
        "network",
        (BACKEND, EDGE),
        template(
            {
                "Name": ".Name",
                "Id": ".Id",
                "Driver": ".Driver",
                "Internal": ".Internal",
                "EnableIPv6": ".EnableIPv6",
                "Options": ".Options",
                "Containers": ".Containers",
            }
        ),
    )
    volumes = inspect_objects(
        "volume",
        tuple(VOLUMES),
        template(
            {
                "Name": ".Name",
                "Driver": ".Driver",
                "Options": ".Options",
            }
        ),
    )
    return {"containers": containers, "networks": networks, "volumes": volumes}


def normalized_path(value):
    return str(value).replace("\\", "/").rstrip("/").casefold()


def verify_startup_controls(name, host):
    """Check configured limits and port requests even while a container is stopped."""
    if name not in RESOURCE_LIMITS or not isinstance(host, dict):
        return ["startup_control_inventory"]
    errors = []
    limits = RESOURCE_LIMITS[name]
    for key, maximum in zip(("Memory", "NanoCpus", "PidsLimit"), limits, strict=True):
        if type(host.get(key)) is not int or not 0 < host[key] <= maximum:
            errors.append("configured_resource_limit")
    memory = host.get("Memory")
    if (
        type(memory) is not int
        or memory <= 0
        or type(host.get("MemorySwap")) is not int
        or host["MemorySwap"] != memory
        or type(host.get("CpuQuota")) is not int
        or host["CpuQuota"] != 0
        or type(host.get("CpuPeriod")) is not int
        or host["CpuPeriod"] != 0
        or host.get("OomKillDisable") is True
    ):
        errors.append("resource_override_or_swap")
    if host.get("RestartPolicy") != {"Name": "no", "MaximumRetryCount": 0}:
        errors.append("automatic_restart_policy")
    if host.get("PublishAllPorts") is not False:
        errors.append("automatic_port_publication")
    if name != RELAY and host.get("PortBindings"):
        errors.append("backend_configured_port_binding")
    return sorted(set(errors))


def verify_topology(payload, *, stopped=False):
    """Evaluate synthetic or gathered Docker metadata; fail closed on unexpected shapes."""
    if type(stopped) is not bool:
        return ["invalid_topology_phase"]
    errors = []
    try:
        containers = {row["Name"].lstrip("/"): row for row in payload["containers"]}
        networks = {row["Name"]: row for row in payload["networks"]}
        volumes = {row["Name"]: row for row in payload["volumes"]}
        if set(containers) != set(NAMES) or len(payload["containers"]) != len(NAMES):
            errors.append("container_inventory")
        if set(networks) != {BACKEND, EDGE} or len(payload["networks"]) != 2:
            errors.append("network_inventory")
        if set(volumes) != set(VOLUMES) or len(payload["volumes"]) != 2:
            errors.append("volume_inventory")
        for name, network in networks.items():
            if network["Driver"] != "bridge" or network["EnableIPv6"] is not False:
                errors.append("network_driver_or_ipv6")
            if network["Internal"] is not (name == BACKEND):
                errors.append("network_internal_flag")
            if (network.get("Options") or {}).get(
                "com.docker.network.bridge.host_binding_ipv4"
            ) != "127.0.0.1":
                errors.append("network_default_binding")
            endpoints = {row["Name"] for row in (network["Containers"] or {}).values()}
            expected_endpoints = set() if stopped else (set(NAMES) if name == BACKEND else {RELAY})
            if endpoints != expected_endpoints:
                errors.append("unexpected_network_member")
        for volume in volumes.values():
            if volume["Driver"] != "local" or volume["Options"]:
                errors.append("volume_driver_or_options")
        for name, row in containers.items():
            relay = name == RELAY
            host = row["HostConfig"]
            errors.extend(verify_startup_controls(name, host))
            if stopped and (
                row["Running"] is not False or row["State"] not in {"created", "exited"}
            ):
                errors.append("container_not_stopped")
            elif not stopped and (row["Running"] is not True or row["State"] != "running"):
                errors.append("container_not_running")
            expected_networks = {BACKEND, EDGE} if relay else {BACKEND}
            if set(row["Networks"]) != expected_networks:
                errors.append("container_network_membership")
            if host["NetworkMode"] not in expected_networks:
                errors.append("unsafe_network_mode")
            if (
                host["Privileged"] is not False
                or host["CapAdd"]
                or host["PidMode"]
                or host["IpcMode"] == "host"
                or host["Devices"]
            ):
                errors.append("privilege_or_host_namespace")
            actual_ports = {
                port: bindings for port, bindings in (row["Ports"] or {}).items() if bindings
            }
            if relay:
                expected_ports = {
                    port: [{"HostIp": "127.0.0.1", "HostPort": value}]
                    for port, value in PORTS.items()
                }
                if (
                    actual_ports != ({} if stopped else expected_ports)
                    or host["PortBindings"] != expected_ports
                ):
                    errors.append("relay_port_bindings")
                if (
                    row["User"] != "65534:65534"
                    or host["ReadonlyRootfs"] is not True
                    or host["CapDrop"] != ["ALL"]
                    or not {"no-new-privileges", "no-new-privileges:true"}.intersection(
                        host["SecurityOpt"] or []
                    )
                ):
                    errors.append("relay_privileges")
                mounts = row["Mounts"]
                if len(mounts) != 1 or not (
                    mounts[0]["Type"] == "bind"
                    and mounts[0]["Destination"] == "/relay.mjs"
                    and mounts[0]["RW"] is False
                    and normalized_path(mounts[0]["Source"]) == normalized_path(RELAY_SOURCE)
                ):
                    errors.append("relay_mount")
            else:
                if actual_ports:
                    errors.append("backend_published_port")
                mounts = row["Mounts"]
                expected_mounts = 1 if name in VOLUMES else 0
                if len(mounts) != expected_mounts:
                    errors.append("backend_mount_count")
                for mount in mounts:
                    if not (
                        mount["Type"] == "volume"
                        and mount["Name"] == name
                        and mount["Destination"] == VOLUMES.get(name)
                        and mount["Driver"] == "local"
                    ):
                        errors.append("backend_mount")
            if not row["Image"].startswith("sha256:") or len(row["Image"]) != 71:
                errors.append("image_identity")
        if containers[RELAY]["Image"] != containers[f"supabase_storage_{PROJECT}"]["Image"]:
            errors.append("relay_image_identity")
    except (KeyError, TypeError, AttributeError, IndexError):
        errors.append("malformed_inspection")
    return sorted(set(errors))


def parse_routes(ipv4, ipv6):
    lines = ipv4.splitlines()
    if not lines or "Destination" not in lines[0] or "Mask" not in lines[0]:
        raise VerificationError("invalid_ipv4_routes")
    v4_default = False
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 8:
            raise VerificationError("invalid_ipv4_routes")
        v4_default |= fields[1] == "00000000" and fields[7] == "00000000"
    v6_default = False
    for line in ipv6.splitlines():
        fields = line.split()
        if len(fields) != 10:
            raise VerificationError("invalid_ipv6_routes")
        try:
            flags = int(fields[8], 16)
        except ValueError as error:
            raise VerificationError("invalid_ipv6_routes") from error
        v6_default |= (
            fields[0] == "0" * 32
            and fields[1] == "00"
            and bool(flags & 1)
            and not bool(flags & 0x200)
        )
    return {"ipv4_default_route": v4_default, "ipv6_default_route": v6_default}


def gather_runtime():
    routes = parse_routes(
        docker(["exec", DB, "cat", "/proc/net/route"]),
        docker(["exec", DB, "cat", "/proc/net/ipv6_route"]),
    )
    # This fixed connection probe sends no application payload, does not use DNS,
    # and distinguishes missing probe tools from an expected connection failure.
    probe = (
        "command -v timeout >/dev/null || exit 20; command -v bash >/dev/null || exit 21; "
        "timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' >/dev/null 2>&1; result=$?; "
        "case $result in 0) printf reachable;; 1|124) printf blocked;; *) exit 22;; esac"
    )
    connection = docker(["exec", DB, "/bin/bash", "-c", probe], timeout=10)
    if connection not in {"reachable", "blocked"}:
        raise VerificationError("invalid_connection_probe")
    cron = docker(
        [
            "exec",
            DB,
            "psql",
            "-X",
            "-U",
            "postgres",
            "-d",
            "postgres",
            "-At",
            "-c",
            "SELECT current_setting('cron.launch_active_jobs', true)",
        ]
    )
    return {
        **routes,
        "external_tcp": connection,
        "cron_launch_active_jobs": "off" if cron == "off" else "not_verified_off",
    }


def verify_runtime(runtime):
    return [
        name
        for name, expected in {
            "ipv4_default_route": False,
            "ipv6_default_route": False,
            "external_tcp": "blocked",
            "cron_launch_active_jobs": "off",
        }.items()
        if runtime.get(name) != expected
    ]


def sanitized_topology(payload):
    """Receipt allowlist excludes raw environment, mount paths, commands and host identity."""
    return {
        "containers": [
            {
                "name": row["Name"].lstrip("/"),
                "id": row["Id"],
                "image_id": row["Image"],
                "networks": sorted(row["Networks"]),
                "ports": row["Ports"],
            }
            for row in payload["containers"]
        ],
        "networks": [
            {"name": row["Name"], "id": row["Id"], "internal": row["Internal"]}
            for row in payload["networks"]
        ],
    }


def source_hashes():
    return {
        "lab_config_sha256": sha256(CONFIG_SOURCE.read_bytes()),
        "relay_source_sha256": sha256(RELAY_SOURCE.read_bytes()),
        "verifier_source_sha256": sha256(Path(__file__).read_bytes()),
    }


def run_verification():
    report = {
        "schema_version": 1,
        "project": PROJECT,
        "started_at": datetime.now(UTC).isoformat(),
        "status": "failed",
        "errors": [],
        "coverage_limits": LIMITS,
    }
    try:
        before_sources = source_hashes()
        before = gather_topology()
        report["source_hashes"] = before_sources
        report["topology_sha256"] = sha256(canonical(before))
        report["errors"] = verify_topology(before)
        report["topology"] = sanitized_topology(before)
        if not report["errors"]:
            runtime = gather_runtime()
            report["runtime"] = runtime
            report["errors"].extend(verify_runtime(runtime))
            after = gather_topology()
            report["errors"].extend(verify_topology(after))
            if canonical(before) != canonical(after) or before_sources != source_hashes():
                report["errors"].append("environment_changed_during_verification")
        if not report["errors"]:
            report["status"] = "passed"
    except VerificationError as error:
        report["errors"].append(str(error))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        report["errors"].append("verification_input_or_runtime_failure")
    report["finished_at"] = datetime.now(UTC).isoformat()
    return report


def main():
    if len(sys.argv) != 1:
        raise SystemExit("No target, command or configuration arguments are accepted.")
    report = run_verification()
    directory = ROOT / "artifacts/local/isolation"
    directory.mkdir(parents=True, exist_ok=True)
    if not directory.resolve().is_relative_to((ROOT / "artifacts/local").resolve()):
        raise SystemExit("Private evidence boundary failed.")
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8]
    path = directory / (run_id + ".json")
    body = json.dumps(report, indent=2).encode() + b"\n"
    with path.open("xb") as handle:
        handle.write(body)
    with path.with_suffix(".sha256").open("x", encoding="ascii") as handle:
        handle.write(sha256(body) + "\n")
    print(f"Isolation gate: {report['status']}. Private report: {path.relative_to(ROOT)}")
    if report["errors"]:
        print("Checks requiring attention: " + ", ".join(report["errors"]))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
