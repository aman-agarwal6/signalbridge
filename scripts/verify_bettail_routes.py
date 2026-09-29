"""Strict, read-only isolation gate for the fixed eight-container BetTail route lab.

This profile does not relax the original seven-container Supabase gate. It verifies
the one additional container and endpoint before projecting a deep copy onto that
gate. It starts no service and accepts no alternate target or configuration path.
"""

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

from scripts import snapshot_app
from scripts import verify_supabase_isolation as base

NEXT = "signalbridge-bettail-next"
IMAGE = "sha256:105a2584129c9600aebed6f5ac49ca4371c92b996ecd1af7179750333e9e2120"
PROFILE = "bettail-next-routes"
RUNTIME = ROOT / "var/labs/bettail/routes"
CONTRACT = RUNTIME / "runtime.json"
LAB_FILES = frozenset({"bettail-routes.mjs", "supabase-http.mjs", "runtime.mjs"})
CONTRACT_KEYS = frozenset(
    {"schema_version", "profile", "image_id", "snapshot_digest", "runtime_files", "harness_files"}
)
MAX_CONTRACT_BYTES = 32 * 1024 * 1024
MAX_FILES = 100_000
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
TMPFS_LIMITS = {"/app/.next": 1024 * 1024 * 1024, "/tmp": 256 * 1024 * 1024}
NEXT_HOST_FIELDS = (
    *base.HOST_FIELDS,
    "UTSMode",
    "UsernsMode",
    "CgroupnsMode",
    "DeviceRequests",
    "Tmpfs",
    "ExtraHosts",
    "Links",
)
LIMITS = [
    *base.LIMITS,
    "The extra application is a copied, hash-verified source snapshot with copied dependencies.",
    "Dependency content is pinned locally; this gate is not a dependency vulnerability audit.",
    "No application authorization or route assertion is established by the isolation check.",
    "The writable evidence directory may contain synthetic credentials and recovery state; public receipts exclude these private values.",
    "Inherited image port declarations with no binding do not publish a host port.",
    "Only two generated Next development declaration import paths may differ from the snapshot.",
]
VerificationError = base.VerificationError


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _relative(value):
    return (
        isinstance(value, str)
        and len(value) <= 500
        and "\\" not in value
        and ":" not in value
        and not any(ord(char) < 32 for char in value)
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def validate_contract(value):
    """Only hashes and the fixed profile are configurable; paths are derived locally."""
    if not isinstance(value, dict) or set(value) != CONTRACT_KEYS:
        raise VerificationError("route_contract_schema")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["profile"] != PROFILE
        or value["image_id"] != IMAGE
        or not _digest(value["snapshot_digest"])
    ):
        raise VerificationError("route_contract_identity")
    for key in ("runtime_files", "harness_files"):
        rows = value[key]
        if not isinstance(rows, dict) or not 1 <= len(rows) <= MAX_FILES:
            raise VerificationError("route_contract_file_manifest")
        if any(not _relative(name) or not _digest(digest) for name, digest in rows.items()):
            raise VerificationError("route_contract_file_manifest")
        if len({name.casefold() for name in rows}) != len(rows):
            raise VerificationError("route_contract_ambiguous_path")
    if set(value["harness_files"]) != LAB_FILES:
        raise VerificationError("route_contract_harness_inventory")
    for name in value["runtime_files"]:
        if name == "node_modules/.package-lock.json":
            continue  # npm's generated dependency inventory is a pinned ordinary file.
        if name.startswith("node_modules/"):
            parts = name.split("/")
            if (
                len(parts) < 3
                or ".bin" in parts
                or any(
                    part.casefold().startswith(".env") or part.casefold() in {".git", ".npmrc"}
                    for part in parts
                )
            ):
                raise VerificationError("route_contract_dependency_path")
        elif not snapshot_app._allowed_relative(name):
            raise VerificationError("route_contract_source_path")
    return value


def _safe(path, *, directory=None):
    """Reject linked/reparse ancestors before opening a fixed local path."""
    absolute = Path(os.path.abspath(path))
    workspace = Path(os.path.abspath(ROOT))
    if not absolute.is_relative_to(workspace) or absolute.resolve() != absolute:
        raise VerificationError("route_path_boundary")
    for current in (*reversed(absolute.parents), absolute):
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise VerificationError("route_link_or_reparse_path")
    if directory is True and not stat.S_ISDIR(info.st_mode):
        raise VerificationError("route_expected_directory")
    if directory is False and not stat.S_ISREG(info.st_mode):
        raise VerificationError("route_expected_regular_file")
    if stat.S_ISREG(info.st_mode) and getattr(info, "st_nlink", 1) != 1:
        raise VerificationError("route_hard_link")
    return info


def _unique_json(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise VerificationError("route_contract_duplicate_key")
        value[key] = item
    return value


def read_contract():
    if _safe(CONTRACT, directory=False).st_size > MAX_CONTRACT_BYTES:
        raise VerificationError("route_contract_size")
    with CONTRACT.open("rb") as handle:
        raw = handle.read(MAX_CONTRACT_BYTES + 1)
    if len(raw) > MAX_CONTRACT_BYTES:
        raise VerificationError("route_contract_size")
    return validate_contract(json.loads(raw, object_pairs_hook=_unique_json))


def _tree(directory, expected=None):
    """Bound traversal, reject special files and hash files without loading large binaries."""
    _safe(directory, directory=True)
    pending, found, total, visited = [directory], {}, 0, 0
    while pending:
        parent = pending.pop()
        _safe(parent, directory=True)
        with os.scandir(parent) as entries:
            for entry in entries:
                visited += 1
                if visited > MAX_FILES * 2:
                    raise VerificationError("route_tree_size")
                path = Path(entry.path)
                info = _safe(path)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise VerificationError("route_tree_special_file")
                name = path.relative_to(directory).as_posix()
                if expected is not None and name not in expected:
                    raise VerificationError("route_tree_inventory")
                if info.st_size > MAX_FILE_BYTES:
                    raise VerificationError("route_tree_size")
                total += info.st_size
                if total > MAX_TOTAL_BYTES or len(found) >= MAX_FILES:
                    raise VerificationError("route_tree_size")
                if expected is not None:
                    digest, size = hashlib.sha256(), 0
                    with path.open("rb") as handle:
                        while chunk := handle.read(1024 * 1024):
                            size += len(chunk)
                            if size > info.st_size or size > MAX_FILE_BYTES:
                                raise VerificationError("route_file_changed_during_hash")
                            digest.update(chunk)
                    if size != info.st_size or digest.hexdigest() != expected[name]:
                        raise VerificationError("route_tree_content")
                    found[name] = digest.hexdigest()
                else:
                    # Evidence can change during a run, but no links/special mounts are allowed.
                    found[name] = None
    if expected is not None and found != expected:
        raise VerificationError("route_tree_inventory")
    return found


def source_hashes():
    """Re-read the exact contract and all mounted code; never report host paths or values."""
    contract = read_contract()
    digest = contract["snapshot_digest"]
    snapshot = ROOT / "private-source/bettail" / digest
    _safe(snapshot, directory=True)
    metadata = snapshot_app.verify_snapshot(snapshot, workspace=ROOT)
    if metadata["snapshot_digest"] != digest or metadata["app"] != "bettail":
        raise VerificationError("route_snapshot_identity")
    source_files = {
        name: value
        for name, value in contract["runtime_files"].items()
        if not name.startswith("node_modules/")
    }
    original = metadata["files"]
    declaration = None
    if source_files != original:
        changed = {
            name
            for name in set(source_files) | set(original)
            if source_files.get(name) != original.get(name)
        }
        if changed != {"next-env.d.ts"} or "next-env.d.ts" not in original:
            raise VerificationError("route_source_differs_from_snapshot")
        raw = (snapshot / "next-env.d.ts").read_bytes()
        expected = raw
        for filename in ("routes.d.ts", "root-params.d.ts"):
            before = f'"./.next/types/{filename}"'.encode()
            after = f'"./.next/dev/types/{filename}"'.encode()
            if expected.count(before) != 1:
                raise VerificationError("route_declaration_transform")
            expected = expected.replace(before, after)
        transformed_hash = base.sha256(expected)
        if base.sha256(raw) != original["next-env.d.ts"] or (
            source_files["next-env.d.ts"] != transformed_hash
        ):
            raise VerificationError("route_declaration_transform")
        declaration = {
            "original_sha256": original["next-env.d.ts"],
            "runtime_sha256": transformed_hash,
        }
    if not any(name.startswith("node_modules/") for name in contract["runtime_files"]):
        raise VerificationError("route_dependencies_missing")
    _tree(RUNTIME / "app", contract["runtime_files"])
    _tree(RUNTIME / "lab", contract["harness_files"])
    _tree(RUNTIME / "evidence")
    return {
        **base.source_hashes(),
        "route_verifier_sha256": base.sha256(Path(__file__).read_bytes()),
        "runtime_contract_sha256": base.sha256(base.canonical(contract)),
        "snapshot_digest": digest,
        "runtime_files_sha256": base.sha256(base.canonical(contract["runtime_files"])),
        "harness_files_sha256": base.sha256(base.canonical(contract["harness_files"])),
        "generated_declaration_adjustment": declaration,
    }


def next_template():
    fields = dict(base.CONTAINER_FIELDS)
    del fields["HostConfig"]
    fields.update(
        {
            "Entrypoint": ".Config.Entrypoint",
            "Cmd": ".Config.Cmd",
            "WorkingDir": ".Config.WorkingDir",
        }
    )
    body = base.template(fields)
    host = base.template({key: ".HostConfig." + key for key in NEXT_HOST_FIELDS})
    return body[:-1] + ',"HostConfig":' + host + "}"


def gather_topology():
    result = base.gather_topology()
    result["containers"].extend(base.inspect_objects("container", (NEXT,), next_template()))
    return result


def _tmpfs_options(value, maximum):
    if not isinstance(value, str):
        return False
    flags, options = set(), {}
    for item in value.split(","):
        if "=" in item:
            key, val = item.split("=", 1)
            if key in options:
                return False
            options[key] = val
        else:
            if item in flags:
                return False
            flags.add(item)
    if not {"rw", "nosuid", "nodev", "noexec"}.issubset(flags):
        return False
    if flags - {"rw", "nosuid", "nodev", "noexec"} or set(options) - {"size", "mode", "uid", "gid"}:
        return False
    matched = re.fullmatch(r"([1-9][0-9]*)([kmg]?)", options.get("size", "").lower())
    if not matched:
        return False
    size = int(matched[1]) * {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}[matched[2]]
    return (
        size <= maximum
        and options.get("uid", "65534") == "65534"
        and options.get("gid", "65534") == "65534"
        and options.get("mode", "1777") in {"700", "0700", "1777"}
    )


def _verify_mounts(row):
    mounts = row["Mounts"]
    if not isinstance(mounts, list):
        return ["route_mount_inventory"]
    mapped = {item["Destination"]: item for item in mounts}
    # Docker versions may omit tmpfs from Mounts; HostConfig.Tmpfs is mandatory either way.
    binds = {"/app": ("app", False), "/lab": ("lab", False), "/evidence": ("evidence", True)}
    if (
        len(mapped) != len(mounts)
        or not set(binds).issubset(mapped)
        or (set(mapped) - set(binds) - set(TMPFS_LIMITS))
    ):
        return ["route_mount_inventory"]
    for destination, (name, writable) in binds.items():
        mount = mapped[destination]
        if (
            mount["Type"] != "bind"
            or mount["RW"] is not writable
            or mount.get("Propagation") != "rprivate"
            or base.normalized_path(mount["Source"]) != base.normalized_path(RUNTIME / name)
        ):
            return ["route_mount_boundary"]
    for destination in set(mapped) - set(binds):
        mount = mapped[destination]
        if mount["Type"] != "tmpfs" or mount["RW"] is not True or mount.get("Source"):
            return ["route_tmpfs_mount"]
    return []


def verify_topology(payload, *, stopped=False):
    """Validate exactly one extra member before passing a deep copy to the base gate."""
    if type(stopped) is not bool:
        return ["route_invalid_topology_phase"]
    errors = []
    try:
        rows = payload["containers"]
        if (
            len(rows) != 8
            or len({row["Name"] for row in rows}) != 8
            or {row["Name"].lstrip("/") for row in rows} != {*base.NAMES, NEXT}
        ):
            return ["route_container_inventory"]
        matches = [row for row in rows if row["Name"] == "/" + NEXT]
        if len(matches) != 1:
            return ["route_container_inventory"]
        row = matches[0]
        if not _digest(row["Id"]):
            return ["route_container_identity"]
        networks = payload["networks"]
        if len(networks) != 2 or {item["Name"] for item in networks} != {base.BACKEND, base.EDGE}:
            return ["route_network_inventory"]
        backend = next(item for item in networks if item["Name"] == base.BACKEND)
        endpoints = backend["Containers"]
        if (
            not isinstance(endpoints, dict)
            or len(endpoints) != (0 if stopped else 8)
            or {endpoint["Name"] for endpoint in endpoints.values()}
            != (set() if stopped else {*base.NAMES, NEXT})
        ):
            return ["route_network_members"]
        if not stopped and (
            endpoints.get(row["Id"], {}).get("Name") != NEXT
            or sum(item["Name"] == NEXT for item in endpoints.values()) != 1
        ):
            return ["route_endpoint_identity"]
        if set(row["Networks"]) != {base.BACKEND} or (
            row["Networks"][base.BACKEND]["NetworkID"] != backend["Id"]
        ):
            errors.append("route_network_membership")
        host = row["HostConfig"]
        if stopped and (row["Running"] is not False or row["State"] not in {"created", "exited"}):
            errors.append("route_container_not_stopped")
        elif not stopped and (row["Running"] is not True or row["State"] != "running"):
            errors.append("route_container_not_running")
        if row["Image"] != IMAGE:
            errors.append("route_image_identity")
        if (
            row["Entrypoint"] != ["node"]
            or row["Cmd"] != ["/lab/runtime.mjs"]
            or row["WorkingDir"] != "/app"
        ):
            errors.append("route_runtime_command")
        if (
            row["User"] != "65534:65534"
            or host["ReadonlyRootfs"] is not True
            or host["CapDrop"] != ["ALL"]
            or not {"no-new-privileges", "no-new-privileges:true"}.intersection(
                host["SecurityOpt"] or []
            )
            or set(host["SecurityOpt"] or []) - {"no-new-privileges", "no-new-privileges:true"}
        ):
            errors.append("route_privileges")
        if (
            host["NetworkMode"] != base.BACKEND
            or host["Privileged"] is not False
            or host["CapAdd"]
            or host["Devices"]
            or host["DeviceRequests"]
            or host["PidMode"]
            or host["UTSMode"]
            or host["UsernsMode"]
            or host["IpcMode"] not in {"private", "none"}
            or host["CgroupnsMode"] not in {"private", ""}
            or host["ExtraHosts"]
            or host["Links"]
        ):
            errors.append("route_host_access")
        if (
            host["PublishAllPorts"] is not False
            or host["PortBindings"]
            or any(bindings for bindings in (row["Ports"] or {}).values())
        ):
            errors.append("route_published_port")
        if host["RestartPolicy"] != {"Name": "no", "MaximumRetryCount": 0}:
            errors.append("route_restart_policy")
        for key, maximum in (
            ("Memory", 2 * 1024**3),
            ("NanoCpus", 2_000_000_000),
            ("PidsLimit", 256),
        ):
            if type(host[key]) is not int or not 0 < host[key] <= maximum:
                errors.append("route_resource_limit")
        if (
            type(host["MemorySwap"]) is not int
            or host["MemorySwap"] != host["Memory"]
            or type(host["CpuQuota"]) is not int
            or host["CpuQuota"] != 0
            or type(host["CpuPeriod"]) is not int
            or host["CpuPeriod"] != 0
            or host["OomKillDisable"] is True
        ):
            errors.append("route_resource_override")
        if set(host["Tmpfs"] or {}) != set(TMPFS_LIMITS) or any(
            not _tmpfs_options(host["Tmpfs"][name], maximum)
            for name, maximum in TMPFS_LIMITS.items()
        ):
            errors.append("route_tmpfs_bounds")
        errors.extend(_verify_mounts(row))
        if errors:
            return sorted(set(errors))
        projected = copy.deepcopy(payload)
        projected["containers"] = [
            item for item in projected["containers"] if item["Name"] != "/" + NEXT
        ]
        projected_backend = next(
            item for item in projected["networks"] if item["Name"] == base.BACKEND
        )
        if not stopped:
            del projected_backend["Containers"][row["Id"]]
        return base.verify_topology(projected, stopped=stopped)
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return ["route_malformed_inspection"]


def gather_next_runtime():
    routes = base.parse_routes(
        base.docker(
            [
                "exec",
                NEXT,
                "node",
                "-e",
                "process.stdout.write(require('node:fs').readFileSync('/proc/net/route','utf8'))",
            ]
        ),
        base.docker(
            [
                "exec",
                NEXT,
                "node",
                "-e",
                "process.stdout.write(require('node:fs').readFileSync('/proc/net/ipv6_route','utf8'))",
            ]
        ),
    )
    if any(routes.values()):
        return {**routes, "external_tcp": "not_run_unsafe_routes"}
    probe = (
        "const net=require('node:net');let done=false;"
        "const finish=v=>{if(done)return;done=true;process.stdout.write(v);s.destroy()};"
        "const s=net.createConnection({host:'1.1.1.1',port:443});"
        "s.setTimeout(3000,()=>finish('blocked'));s.on('connect',()=>finish('reachable'));"
        "s.on('error',e=>finish(['ENETUNREACH','EHOSTUNREACH','ECONNREFUSED','ETIMEDOUT']"
        ".includes(e.code)?'blocked':'invalid'));"
    )
    connection = base.docker(["exec", NEXT, "node", "-e", probe], timeout=10)
    if connection not in {"blocked", "reachable"}:
        raise VerificationError("route_invalid_connection_probe")
    return {**routes, "external_tcp": connection}


def verify_next_runtime(runtime):
    return [
        "route_" + name
        for name, expected in {
            "ipv4_default_route": False,
            "ipv6_default_route": False,
            "external_tcp": "blocked",
        }.items()
        if (
            runtime.get(name) is not expected
            if type(expected) is bool
            else runtime.get(name) != expected
        )
    ]


def run_verification():
    report = {
        "schema_version": 1,
        "project": base.PROJECT,
        "profile": PROFILE,
        "started_at": datetime.now(UTC).isoformat(),
        "status": "failed",
        "errors": [],
        "coverage_limits": LIMITS,
    }
    try:
        before_sources = source_hashes()
        before = gather_topology()
        report["source_hashes"] = before_sources
        report["topology_sha256"] = base.sha256(base.canonical(before))
        report["errors"] = verify_topology(before)
        if not report["errors"]:
            report["topology"] = base.sanitized_topology(before)
            runtime = base.gather_runtime()
            report["base_runtime"] = runtime
            report["errors"].extend(base.verify_runtime(runtime))
            if not report["errors"]:
                next_runtime = gather_next_runtime()
                report["route_runtime"] = next_runtime
                report["errors"].extend(verify_next_runtime(next_runtime))
            after = gather_topology()
            after_sources = source_hashes()
            report["errors"].extend(verify_topology(after))
            report["topology_after_sha256"] = base.sha256(base.canonical(after))
            report["source_hashes_after"] = after_sources
            if base.canonical(before) != base.canonical(after) or before_sources != after_sources:
                report["errors"].append("route_environment_changed_during_verification")
        if not report["errors"]:
            report["status"] = "passed"
    except VerificationError as error:
        report["errors"].append(str(error))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        report["errors"].append("route_verification_input_or_runtime_failure")
    report["errors"] = sorted(set(report["errors"]))
    report["finished_at"] = datetime.now(UTC).isoformat()
    return report


def main():
    if len(sys.argv) != 1:
        raise SystemExit("No target, command or configuration arguments are accepted.")
    report = run_verification()
    directory = ROOT / "artifacts/local/route-isolation"
    # Check existing parents before creating only the fixed private evidence directory.
    parent = ROOT
    for part in directory.relative_to(ROOT).parts:
        parent = parent / part
        if not parent.exists():
            _safe(parent.parent, directory=True)
            parent.mkdir()
        _safe(parent, directory=True)
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8]
    path = directory / (run_id + ".json")
    body = json.dumps(report, indent=2).encode() + b"\n"
    with path.open("xb") as handle:
        handle.write(body)
    with path.with_suffix(".sha256").open("x", encoding="ascii") as handle:
        handle.write(base.sha256(body) + "\n")
    print(f"Route isolation gate: {report['status']}. Private report: {path.relative_to(ROOT)}")
    if report["errors"]:
        print("Checks requiring attention: " + ", ".join(report["errors"]))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
