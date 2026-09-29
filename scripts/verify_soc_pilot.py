"""Read-only Docker metadata gate for the two fixed, synthetic SOC pilot profiles.

Never starts, stops, installs, executes a container command, or reads Config.Env.
Image digests, mounts and resource ceilings are code-owned, not caller supplied.
Create all containers and verify ``created`` before starting the reviewed drivers.
"""

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import verify_supabase_isolation as base

VerificationError = base.VerificationError
WAZUH = "signalbridge-soc-wazuh-pilot"
ZAP = "signalbridge-soc-zap-pilot"
TARGET = "signalbridge-soc-zap-target"
NETWORK = ZAP
IMAGES = {
    WAZUH: "wazuh/wazuh-manager@sha256:f74021c1275393aa094b6f6bb57f9bac240cba7ddb35f2a841e430341f5fc6a0",
    ZAP: "zaproxy/zap-stable@sha256:71db37cd5b75663b35758d10aaec05bf6fbac23f5020e3046c70e628a5f84efa",
    TARGET: "python@sha256:7bf6c3111fe094f8ee1a1cbcdc63c4cfb345b0e3df42d5aa9a90b3b4b022ab6d",
}
NAMES = {"wazuh": (WAZUH,), "zap": (ZAP, TARGET)}
STATES = ("created", "running", "exited")
MIB = 1024 * 1024
GIB = 1024 * MIB
LOG_CONFIG = {"Type": "json-file", "Config": {"max-size": "2m", "max-file": "2"}}
NETWORK_OPTIONS = {
    "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1",
    "com.docker.network.enable_ipv4": "true",
    "com.docker.network.enable_ipv6": "false",
}
HOST_FIELDS = (
    "NetworkMode",
    "Privileged",
    "CapAdd",
    "CapDrop",
    "PidMode",
    "IpcMode",
    "UTSMode",
    "UsernsMode",
    "CgroupnsMode",
    "Devices",
    "DeviceRequests",
    "DeviceCgroupRules",
    "ReadonlyRootfs",
    "SecurityOpt",
    "PortBindings",
    "PublishAllPorts",
    "RestartPolicy",
    "Memory",
    "MemorySwap",
    "MemoryReservation",
    "NanoCpus",
    "CpuQuota",
    "CpuPeriod",
    "PidsLimit",
    "Tmpfs",
    "ExtraHosts",
    "Links",
    "VolumesFrom",
    "Dns",
    "DnsOptions",
    "DnsSearch",
    "OomKillDisable",
    "LogConfig",
    "AutoRemove",
    "StorageOpt",
    "Sysctls",
    "MaskedPaths",
    "ReadonlyPaths",
)
LIMITATIONS = [
    "Point-in-time Docker metadata and local source check; no hostile-host security proof.",
    "No container command or network probe is executed by this verifier.",
    "The OS user and Docker administrator remain trusted; metadata can change afterward.",
    "Wazuh uses a writable disposable root layer and three reviewed identity/chroot capabilities.",
    "Timeouts and disk monitoring bound the pilot operationally; this is not a hard disk quota.",
    "A passed gate establishes no detector, scanner, target-authorization or enterprise-parity result.",
]


def validate_request(profile, run_id, state):
    if profile not in {*NAMES, "wazuh-backfill", "zap-repeat"} or state not in STATES:
        raise VerificationError("soc_request_scope")
    try:
        value = uuid.UUID(run_id)
    except (ValueError, TypeError, AttributeError) as error:
        raise VerificationError("soc_run_identity") from error
    if value.version != 4 or str(value) != run_id:
        raise VerificationError("soc_run_identity")


def profile_names(profile, run_id=None):
    if profile == "zap-repeat":
        validate_request(profile, run_id, "created")
        return ("signalbridge-zap-" + run_id[:8], "signalbridge-zap-target-" + run_id[:8])
    if profile == "wazuh-backfill":
        validate_request(profile, run_id, "created")
        return ("signalbridge-wazuh-backfill-" + run_id[:8],)
    if profile not in NAMES:
        raise VerificationError("soc_request_scope")
    return NAMES[profile]


def image_references(profile, run_id=None):
    names = profile_names(profile, run_id)
    if profile == "zap-repeat":
        return dict(zip(names, (IMAGES[ZAP], IMAGES[TARGET]), strict=True))
    return {name: IMAGES[WAZUH] if profile == "wazuh-backfill" else IMAGES[name] for name in names}


def network_name(profile, run_id=None):
    if profile == "zap-repeat":
        return profile_names(profile, run_id)[0]
    return NETWORK


def profiles(run_id):
    """Fixed runtime contract. Neither a target nor a mount path is an input."""
    directory = ROOT / "var/soc/pilot" / run_id
    result = {
        profile_names("wazuh-backfill", run_id)[0]: {
            "entrypoint": ["/var/ossec/framework/python/bin/python3"],
            "command": ["/pilot/run_backfill.py"],
            "user": "0:0",
            "workdir": "/pilot",
            "network": "none",
            "readonly": False,
            "capabilities": ["SETUID", "SETGID", "SYS_CHROOT"],
            "memory": 1536 * MIB,
            "cpus": 1_000_000_000,
            "pids": 256,
            "tmpfs": {},
            "mounts": {
                "/pilot": (directory / "source", False),
                "/evidence": (directory / "wazuh-backfill", True),
                "/handoff/events.jsonl": (directory / "input/events.jsonl", False),
            },
        },
        WAZUH: {
            "entrypoint": ["/var/ossec/framework/python/bin/python3"],
            "command": ["/pilot/run_pilot.py"],
            "user": "0:0",
            "workdir": "/pilot",
            "network": "none",
            "readonly": False,
            "capabilities": ["SETUID", "SETGID", "SYS_CHROOT"],
            "memory": 1536 * MIB,
            "cpus": 1_000_000_000,
            "pids": 256,
            "tmpfs": {},
            "mounts": {
                "/pilot": (ROOT / "integrations/wazuh", False),
                "/evidence": (directory / "wazuh", True),
            },
        },
        ZAP: {
            "entrypoint": ["python3"],
            "command": ["-I", "-B", "/pilot/run_passive.py"],
            "user": "1000:1000",
            "workdir": "/pilot",
            "network": NETWORK,
            "readonly": True,
            "capabilities": [],
            "memory": 2560 * MIB,
            "cpus": 1_500_000_000,
            "pids": 256,
            "tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=512m,uid=1000,gid=1000,mode=700"},
            "mounts": {
                "/pilot": (ROOT / "integrations/zap", False),
                "/evidence": (directory / "zap", True),
            },
        },
        TARGET: {
            "entrypoint": ["python3"],
            "command": ["-I", "-B", "/pilot/fixture.py"],
            "user": "1000:1000",
            "workdir": "/pilot",
            "network": NETWORK,
            "readonly": True,
            "capabilities": [],
            "memory": 256 * MIB,
            "cpus": 500_000_000,
            "pids": 64,
            "tmpfs": {"/tmp": "rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000,mode=700"},
            "mounts": {"/pilot": (ROOT / "integrations/zap", False)},
        },
    }
    for original, name in zip((ZAP, TARGET), profile_names("zap-repeat", run_id), strict=True):
        value = copy.deepcopy(result[original])
        value["network"] = network_name("zap-repeat", run_id)
        value["mounts"]["/pilot"] = (directory / "source", False)
        if original == ZAP:
            value["mounts"]["/evidence"] = (directory / "zap", True)
        result[name] = value
    return result


def container_template():
    fields = {
        "Name": ".Name",
        "Id": ".Id",
        "Image": ".Image",
        "State": ".State.Status",
        "Running": ".State.Running",
        "User": ".Config.User",
        "Entrypoint": ".Config.Entrypoint",
        "Cmd": ".Config.Cmd",
        "WorkingDir": ".Config.WorkingDir",
        "ConfiguredImage": ".Config.Image",
        "Networks": ".NetworkSettings.Networks",
        "Ports": ".NetworkSettings.Ports",
        "Mounts": ".Mounts",
        "Healthcheck": ".Config.Healthcheck",
        "Hostname": ".Config.Hostname",
    }
    fields["Healthcheck"] = '(index .Config "Healthcheck")'
    host = base.template({key: '(index .HostConfig "' + key + '")' for key in HOST_FIELDS})
    return base.template(fields)[:-1] + ',"HostConfig":' + host + "}"


def gather_topology(profile, run_id=None):
    """Inspect fixed resources through the explicit local Docker Desktop pipe."""
    names = profile_names(profile, run_id)
    references = image_references(profile, run_id)
    containers = base.inspect_objects("container", names, container_template())
    images = base.inspect_objects(
        "image",
        tuple(references[name] for name in names),
        base.template(
            {
                "Id": ".Id",
                "RepoDigests": ".RepoDigests",
                "Architecture": ".Architecture",
                "Os": ".Os",
            }
        ),
    )
    networks = (
        []
        if profile in {"wazuh", "wazuh-backfill"}
        else base.inspect_objects(
            "network",
            (network_name(profile, run_id),),
            base.template(
                {
                    "Name": ".Name",
                    "Id": ".Id",
                    "Driver": ".Driver",
                    "Internal": ".Internal",
                    "EnableIPv6": ".EnableIPv6",
                    "Options": ".Options",
                    "Containers": ".Containers",
                    "Attachable": ".Attachable",
                    "Ingress": ".Ingress",
                    "Scope": ".Scope",
                }
            ),
        )
    )
    output = base.docker(["container", "ls", "--format", "{{json .Names}}"])
    try:
        active = [json.loads(line) for line in output.splitlines()]
    except (ValueError, TypeError) as error:
        raise VerificationError("soc_active_inventory") from error
    return {"containers": containers, "images": images, "networks": networks, "active": active}


def _id(value, *, image=False):
    pattern = r"sha256:[0-9a-f]{64}" if image else r"[0-9a-f]{64}"
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _unique_rows(rows, key):
    if not isinstance(rows, list):
        raise VerificationError("soc_metadata_shape")
    result = {row[key]: row for row in rows}
    if len(result) != len(rows):
        raise VerificationError("soc_duplicate_metadata")
    return result


def _check_mounts(row, profile):
    mounts = _unique_rows(row["Mounts"], "Destination")
    if set(mounts) != set(profile["mounts"]):
        return False
    for destination, (source, writable) in profile["mounts"].items():
        actual = mounts[destination]
        if (
            actual["Type"] != "bind"
            or actual["RW"] is not writable
            or base.normalized_path(actual["Source"]) != base.normalized_path(source)
            or actual["Propagation"] != "rprivate"
        ):
            return False
    return True


def _check_host(host, expected):
    errors = []
    added = host["CapAdd"] or []
    normalized_caps = (
        [value.removeprefix("CAP_") for value in added]
        if isinstance(added, list) and all(isinstance(value, str) for value in added)
        else ["INVALID"]
    )
    if (
        host["NetworkMode"] != expected["network"]
        or host["Privileged"] is not False
        or host["ReadonlyRootfs"] is not expected["readonly"]
    ):
        errors.append("soc_privilege_or_network_mode")
    if (
        sorted(host["CapDrop"] or []) != ["ALL"]
        or sorted(normalized_caps) != sorted(expected["capabilities"])
        or host["SecurityOpt"] != ["no-new-privileges:true"]
    ):
        errors.append("soc_capability_or_security_options")
    if (
        host["PidMode"] != ""
        or host["UTSMode"] != ""
        or host["UsernsMode"] != ""
        or host["IpcMode"] != "private"
        or host["CgroupnsMode"] != "private"
    ):
        errors.append("soc_namespace_boundary")
    for key in (
        "Devices",
        "DeviceRequests",
        "DeviceCgroupRules",
        "ExtraHosts",
        "Links",
        "VolumesFrom",
        "Dns",
        "DnsOptions",
        "DnsSearch",
    ):
        if host[key] not in (None, []):
            errors.append("soc_device_or_external_reference")
    if host["PortBindings"] not in (None, {}) or host["PublishAllPorts"] is not False:
        errors.append("soc_host_port")
    if (
        host["RestartPolicy"] != {"Name": "no", "MaximumRetryCount": 0}
        or host["AutoRemove"] is not False
    ):
        errors.append("soc_restart_or_removal")
    for key, exact in (
        ("Memory", expected["memory"]),
        ("MemorySwap", expected["memory"]),
        ("NanoCpus", expected["cpus"]),
        ("PidsLimit", expected["pids"]),
    ):
        if type(host[key]) is not int or host[key] != exact:
            errors.append("soc_resource_limits")
    if (
        host["CpuQuota"] != 0
        or host["CpuPeriod"] != 0
        or host["MemoryReservation"] != 0
        or host["OomKillDisable"] not in (None, False)
    ):
        errors.append("soc_resource_override")
    if (host["Tmpfs"] or {}) != expected["tmpfs"]:
        errors.append("soc_tmpfs_contract")
    if host["LogConfig"] != LOG_CONFIG:
        errors.append("soc_log_limits")
    if host["StorageOpt"] not in (None, {}) or host["Sysctls"] not in (None, {}):
        errors.append("soc_storage_or_kernel_override")
    if not {"/proc/kcore", "/proc/keys", "/proc/timer_list", "/sys/firmware"}.issubset(
        host["MaskedPaths"]
    ) or not {"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}.issubset(
        host["ReadonlyPaths"]
    ):
        errors.append("soc_kernel_path_protection")
    return errors


def verify_topology(payload, profile, run_id, *, state="running"):
    """Pure inspection evaluator. Returns fixed diagnostics without private metadata."""
    errors = []
    try:
        validate_request(profile, run_id, state)
        if set(payload) != {"containers", "images", "networks", "active"}:
            raise VerificationError("soc_metadata_shape")
        names = profile_names(profile, run_id)
        network_id_name = network_name(profile, run_id)
        target_name = names[1] if profile in {"zap", "zap-repeat"} else None
        references = image_references(profile, run_id)
        containers = _unique_rows(payload["containers"], "Name")
        if set(containers) != {"/" + name for name in names}:
            raise VerificationError("soc_container_inventory")
        if len(payload["images"]) != len(names):
            raise VerificationError("soc_image_inventory")
        active = payload["active"]
        if (
            not isinstance(active, list)
            or not all(isinstance(name, str) for name in active)
            or len(active) != len(set(active))
            or set(active) != (set(names) if state == "running" else set())
        ):
            errors.append("soc_active_inventory")
        expected_profiles = profiles(run_id)
        ids = set()
        for name, image in zip(names, payload["images"], strict=True):
            row, expected = containers["/" + name], expected_profiles[name]
            if (
                not _id(image["Id"], image=True)
                or image["Architecture"] != "amd64"
                or image["Os"] != "linux"
                or not isinstance(image["RepoDigests"], list)
                or references[name] not in image["RepoDigests"]
                or row["Image"] != image["Id"]
                or row["ConfiguredImage"] != references[name]
            ):
                errors.append("soc_image_identity")
            if not _id(row["Id"]) or row["Id"] in ids:
                errors.append("soc_container_identity")
            ids.add(row["Id"])
            if row["State"] != state or row["Running"] is not (state == "running"):
                errors.append("soc_container_state")
            if (
                row["Entrypoint"] != expected["entrypoint"]
                or row["Cmd"] != expected["command"]
                or row["User"] != expected["user"]
                or row["WorkingDir"] != expected["workdir"]
            ):
                errors.append("soc_execution_contract")
            if row["Hostname"] != ("signalbridge-zap-target" if name == target_name else name):
                errors.append("soc_hostname_contract")
            if row["Healthcheck"] not in (None, {"Test": ["NONE"]}):
                errors.append("soc_unreviewed_healthcheck")
            if not isinstance(row["Ports"], (dict, type(None))) or any(
                bindings is not None for bindings in (row["Ports"] or {}).values()
            ):
                errors.append("soc_published_port")
            errors.extend(_check_host(row["HostConfig"], expected))
            if not _check_mounts(row, expected):
                errors.append("soc_mount_contract")
            if set(row["Networks"]) != {expected["network"]}:
                errors.append("soc_container_network_inventory")
            for endpoint in row["Networks"].values():
                if any(endpoint.get(key) for key in ("IPAMConfig", "Links", "DriverOpts")):
                    errors.append("soc_endpoint_override")
                aliases = endpoint.get("Aliases") or []
                allowed_aliases = {name}
                if name == target_name:
                    allowed_aliases.add("signalbridge-zap-target")
                if (
                    not isinstance(aliases, list)
                    or not all(isinstance(item, str) for item in aliases)
                    or len(aliases) != len(set(aliases))
                    or not set(aliases).issubset(allowed_aliases)
                    or (name == target_name and "signalbridge-zap-target" not in aliases)
                ):
                    errors.append("soc_network_alias_contract")
        networks = _unique_rows(payload["networks"], "Name")
        if profile in {"wazuh", "wazuh-backfill"}:
            if networks:
                errors.append("soc_network_inventory")
            endpoint = containers["/" + names[0]]["Networks"]["none"]
            if any(
                endpoint.get(key)
                for key in ("Gateway", "IPv6Gateway", "IPAddress", "GlobalIPv6Address")
            ):
                errors.append("soc_none_network_address")
        else:
            if set(networks) != {network_id_name}:
                raise VerificationError("soc_network_inventory")
            network = networks[network_id_name]
            options = network["Options"] or {}
            if (
                not _id(network["Id"])
                or network["Driver"] != "bridge"
                or network["Internal"] is not True
                or network["EnableIPv6"] is not False
                or network["Attachable"] is not False
                or network["Ingress"] is not False
                or network["Scope"] != "local"
                or not isinstance(options, dict)
                or options.get("com.docker.network.bridge.host_binding_ipv4") != "127.0.0.1"
                or any(
                    key not in NETWORK_OPTIONS or value != NETWORK_OPTIONS[key]
                    for key, value in options.items()
                )
            ):
                errors.append("soc_network_boundary")
            members = network["Containers"] or {}
            expected_members = ids if state == "running" else set()
            if set(members) != expected_members:
                errors.append("soc_network_endpoint_inventory")
            for name in names:
                row = containers["/" + name]
                endpoint = row["Networks"][network_id_name]
                if state == "running":
                    member = members[row["Id"]]
                    if (
                        endpoint["NetworkID"] != network["Id"]
                        or not _id(endpoint["EndpointID"])
                        or member["Name"] != name
                        or member["EndpointID"] != endpoint["EndpointID"]
                        or endpoint["GlobalIPv6Address"]
                        or endpoint["IPv6Gateway"]
                        or endpoint["Gateway"]
                    ):
                        errors.append("soc_network_endpoint_identity")
                elif endpoint["NetworkID"] not in ("", network["Id"]) or endpoint["EndpointID"]:
                    errors.append("soc_inactive_endpoint")
    except VerificationError as error:
        errors.append(str(error))
    except (KeyError, TypeError, ValueError, AttributeError):
        errors.append("soc_metadata_shape")
    return sorted(set(errors))


def _safe(path, *, directory):
    absolute, workspace = Path(os.path.abspath(path)), Path(os.path.abspath(ROOT))
    if not absolute.is_relative_to(workspace) or absolute.resolve() != absolute:
        raise VerificationError("soc_local_path_boundary")
    for current in (*reversed(absolute.parents), absolute):
        info = current.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise VerificationError("soc_link_or_reparse_path")
    if directory is not stat.S_ISDIR(info.st_mode) or (
        not directory and not stat.S_ISREG(info.st_mode)
    ):
        raise VerificationError("soc_file_type")
    if not directory and getattr(info, "st_nlink", 1) != 1:
        raise VerificationError("soc_hard_link")
    return info


def _tree(directory, *, evidence=False):
    _safe(directory, directory=True)
    pending, found, total, directories = [directory], {}, 0, 0
    while pending:
        current = pending.pop()
        directories += 1
        if directories > 32:
            raise VerificationError("soc_directory_bound")
        for child in current.iterdir():
            info = _safe(child, directory=child.is_dir())
            if child.is_dir():
                pending.append(child)
                if len(pending) > 32:
                    raise VerificationError("soc_directory_bound")
                continue
            total += info.st_size
            if len(found) >= 256 or info.st_size > 16 * MIB or total > 64 * MIB:
                raise VerificationError("soc_file_bound")
            relative = child.relative_to(directory).as_posix()
            if not evidence and any(
                part.casefold().startswith((".env", ".git"))
                for part in child.relative_to(directory).parts
            ):
                raise VerificationError("soc_unexpected_source_file")
            if evidence:
                found[relative] = info.st_size  # Do not read private output contents.
            else:
                with child.open("rb") as handle:
                    found[relative] = hashlib.file_digest(handle, "sha256").hexdigest()
    return found


def source_hashes(profile, run_id):
    validate_request(profile, run_id, "created")
    if profile not in NAMES:
        raise VerificationError("soc_separate_backfill_receipt_required")
    package = ROOT / "integrations" / profile
    result = {"package": _tree(package)}
    if ("run_pilot.py" if profile == "wazuh" else "run_passive.py") not in result["package"]:
        raise VerificationError("soc_driver_missing")
    if profile == "zap" and "fixture.py" not in result["package"]:
        raise VerificationError("soc_fixture_missing")
    _tree(ROOT / "var/soc/pilot" / run_id / profile, evidence=True)
    for name in ("verify_soc_pilot.py", "verify_supabase_isolation.py"):
        path = ROOT / "scripts" / name
        _safe(path, directory=False)
        result[name] = base.sha256(path.read_bytes())
    return result


def run_verification(profile, run_id, *, state="running"):
    """Return only allowlisted evidence; caller persists it in its private run receipt."""
    validate_request(profile, run_id, state)
    result = {
        "schema_version": 1,
        "profile": "soc-pilot-" + profile,
        "run_id": run_id,
        "checked_at": datetime.now(UTC).isoformat(),
        "expected_state": state,
        "status": "failed",
        "errors": [],
        "limitations": LIMITATIONS,
    }
    try:
        before = source_hashes(profile, run_id)
        topology = gather_topology(profile)
        errors = verify_topology(topology, profile, run_id, state=state)
        after = source_hashes(profile, run_id)
        if before != after:
            errors.append("soc_source_changed_during_inspection")
        result["source_sha256"] = base.sha256(base.canonical(before))
        if not errors:
            result["containers"] = [
                {
                    "name": row["Name"].lstrip("/"),
                    "id": row["Id"],
                    "image_id": row["Image"],
                    "image_reference": row["ConfiguredImage"],
                    "state": row["State"],
                }
                for row in topology["containers"]
            ]
            result["networks"] = [
                {"name": row["Name"], "id": row["Id"], "internal": row["Internal"]}
                for row in topology["networks"]
            ]
        result["errors"] = sorted(set(errors))
    except VerificationError as error:
        result["errors"] = [str(error)]
    except (OSError, ValueError, TypeError, UnicodeError):
        result["errors"] = ["soc_inspection_or_source_unavailable"]
    if not result["errors"]:
        result["status"] = "passed"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=tuple(NAMES), required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--state", choices=STATES, default="running")
    args = parser.parse_args()
    try:
        result = run_verification(args.profile, args.run_id, state=args.state)
    except VerificationError as error:
        result = {"status": "failed", "errors": [str(error)]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
