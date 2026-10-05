"""Reviewed two-component verification controls; imports never launch anything."""

import hashlib
import json
import re
import shutil
import ssl
import stat
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import verification as base

SCOPE = "in-network-postgresql-verification"
PROJECT_PREFIX = "sb-enterprise-network-"
PYTHON_REFERENCE = "python@sha256:7bf6c3111fe094f8ee1a1cbcdc63c4cfb345b0e3df42d5aa9a90b3b4b022ab6d"
DOWNLOAD_LIMIT = 20 * 1024**2
SNAPSHOT_LIMIT = 20 * 1024**2
WHEEL_MANIFEST = Path(__file__).with_name("runner-wheels.json")
REQUIREMENTS = Path(__file__).with_name("runner-requirements.lock")


def wheel_manifest():
    value = json.loads(WHEEL_MANIFEST.read_text(encoding="utf8"))
    rows = value.get("wheels", [])
    if len(rows) != 6 or value.get("maximum_download_bytes") != DOWNLOAD_LIMIT:
        raise base.LabControlError("Unexpected reviewed wheel inventory.")
    expected = {"Django", "psycopg", "psycopg-binary", "asgiref", "sqlparse", "tzdata"}
    if {row.get("package") for row in rows} != expected:
        raise base.LabControlError("Unexpected wheel packages.")
    lock = []
    for row in rows:
        if set(row) != {"package", "version", "filename", "size", "sha256", "url"} or (
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,160}\.whl", row["filename"])
            or not re.fullmatch(r"[a-f0-9]{64}", row["sha256"])
            or type(row["size"]) is not int
            or not 0 < row["size"] <= DOWNLOAD_LIMIT
            or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", row["version"])
            or not re.fullmatch(
                r"https://files\.pythonhosted\.org/packages/[a-f0-9/]+/"
                + re.escape(row["filename"]),
                row["url"],
            )
        ):
            raise base.LabControlError("A wheel escaped the closed reviewed profile.")
        lock.append(f"{row['package']}=={row['version']} --hash=sha256:{row['sha256']}")
    actual = [
        line for line in REQUIREMENTS.read_text().splitlines() if line and not line.startswith("#")
    ]
    if actual != lock or sum(row["size"] for row in rows) > DOWNLOAD_LIMIT:
        raise base.LabControlError("Wheel metadata and install lock disagree.")
    return rows


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def download_wheels(destination):
    """Download data only; no host package install, hooks, unpacking or execution."""
    rows = wheel_manifest()
    destination = Path(destination)
    destination.mkdir(exist_ok=False)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    total = 0
    deadline = time.monotonic() + 120
    for row in rows:
        path = destination / row["filename"]
        digest, size = hashlib.sha256(), 0
        with opener.open(row["url"], timeout=5) as reply, path.open("xb") as output:
            if reply.status != 200 or reply.geturl() != row["url"]:
                raise base.LabControlError("Wheel response changed destination or status.")
            declared = reply.headers.get("Content-Length")
            if declared is not None and declared != str(row["size"]):
                raise base.LabControlError("Wheel declared size changed.")
            while True:
                if time.monotonic() >= deadline:
                    raise base.LabControlError("Wheel-download total time limit reached.")
                chunk = reply.read(64 * 1024)
                if not chunk:
                    break
                size, total = size + len(chunk), total + len(chunk)
                if size > row["size"] or total > DOWNLOAD_LIMIT:
                    raise base.LabControlError("Wheel-download byte limit reached.")
                digest.update(chunk)
                output.write(chunk)
        if size != row["size"] or digest.hexdigest() != row["sha256"]:
            raise base.LabControlError(
                "Downloaded wheel identity does not match the reviewed lock."
            )
    return {"wheel_count": len(rows), "downloaded_bytes": total}


def cached_wheels(workspace, run_id, destination):
    """Reuse only a retained exact run's verified bytes; never fall back to a download."""
    original = base.private_run_directory(workspace, run_id) / "wheels"
    if (
        not original.is_dir()
        or original.is_symlink()
        or (hasattr(original, "is_junction") and original.is_junction())
    ):
        raise base.LabControlError("Retained wheel directory is unavailable or redirected.")
    rows = wheel_manifest()
    if {path.name for path in original.iterdir()} != {row["filename"] for row in rows}:
        raise base.LabControlError("Retained wheel inventory changed.")
    destination = Path(destination)
    destination.mkdir(exist_ok=False)
    total = 0
    for row in rows:
        path = original / row["filename"]
        if (
            path.is_symlink()
            or getattr(path.lstat(), "st_file_attributes", 0) & 0x400
            or not path.is_file()
            or path.stat().st_size != row["size"]
        ):
            raise base.LabControlError("Retained wheel file changed or became redirected.")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise base.LabControlError("Retained wheel hash changed.")
        with (destination / row["filename"]).open("xb") as output:
            output.write(raw)
        total += len(raw)
    return {
        "wheel_count": len(rows),
        "downloaded_bytes": 0,
        "reused_bytes": total,
        "cache_run": run_id,
    }


def wheel_expansion(directory):
    """Inspect verified archive metadata without extraction or package execution."""
    size, files, allocation = 0, 0, 0
    for row in wheel_manifest():
        path = Path(directory) / row["filename"]
        if (
            path.is_symlink()
            or not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]
        ):
            raise base.LabControlError("Wheel identity changed before footprint inspection.")
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                name = PurePosixPath(item.filename)
                if (
                    name.is_absolute()
                    or ".." in name.parts
                    or "\\" in item.filename
                    or stat.S_ISLNK(item.external_attr >> 16)
                    or item.flag_bits & 1
                ):
                    raise base.LabControlError("Wheel archive paths or file types are unsafe.")
                files += 1
                size += item.file_size
                allocation += ((item.file_size + 4095) // 4096) * 4096 + 512
                if files > 5000 or allocation > 96 * 1024**2:
                    raise base.LabControlError(
                        "Offline dependencies exceed their temporary footprint bound."
                    )
    return {
        "uncompressed_bytes": size,
        "archive_entries": files,
        "estimated_allocation_bytes": allocation,
        "claim": "Metadata estimate with 4 KiB rounding and inode allowance; not a native peak-memory measurement. Optional bytecode generation is disabled.",
    }


def verify_compose_config(data, images, run_id):
    """Reject malformed YAML interpretation before any Docker create/start action."""
    services = data.get("services", {})
    if set(services) != {"database", "runner"}:
        raise base.LabControlError("Parsed configuration contains unexpected services.")
    expected = {
        "runner": [
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "/opt/verification-deps:rw,exec,nosuid,nodev,size=128m,mode=0700,uid=10001,gid=10001",
        ],
        "database": [
            "/tmp:rw,noexec,nosuid,size=64m",
            "/var/run/postgresql:rw,noexec,nosuid,size=16m",
        ],
    }
    for role, temporary in expected.items():
        service = services[role]
        if (
            service.get("tmpfs") != temporary
            or service.get("image") != images[role]
            or service.get("ports")
        ):
            raise base.LabControlError(
                "Parsed native mounts, image or exposure differ from the reviewed profile."
            )
    network = data.get("networks", {}).get("verification", {})
    if (
        network.get("internal") is not True
        or network.get("name") != "sb-enterprise-internal-" + run_id
    ):
        raise base.LabControlError("Parsed network isolation differs from the reviewed profile.")


def snapshot_source(root, destination, manifest):
    """Copy only the prevalidated source inventory; never mount a live checkout."""
    from scripts.record_verification import safe_file

    root, destination = Path(root), Path(destination)
    files = manifest["files"]
    if not 0 < len(files) <= 1500:
        raise base.LabControlError("Source snapshot file ceiling exceeded.")
    # Inventory generation excludes secrets/runtime state and refuses redirected paths.
    destination.mkdir(exist_ok=False)
    total = 0
    for name, expected in files.items():
        relative = Path(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not re.fullmatch(r"[a-f0-9]{64}", expected)
        ):
            raise base.LabControlError("Invalid selected source identity.")
        original = root / relative
        if not safe_file(root, original):
            raise base.LabControlError("Selected source file is no longer safe.")
        raw = original.read_bytes()
        total += len(raw)
        if total > SNAPSHOT_LIMIT or hashlib.sha256(raw).hexdigest() != expected:
            raise base.LabControlError("Source snapshot changed or exceeded its byte ceiling.")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(raw)
    return {"source_sha256": manifest["sha256"], "file_count": len(files), "bytes": total}


def inspect_python_image(docker):
    identity = base.docker_result(
        docker, ["image", "inspect", PYTHON_REFERENCE, "--format", "{{.Id}}"]
    )
    platform = base.docker_result(
        docker, ["image", "inspect", PYTHON_REFERENCE, "--format", "{{.Os}}|{{.Architecture}}"]
    )
    digests = json.loads(
        base.docker_result(
            docker, ["image", "inspect", PYTHON_REFERENCE, "--format", "{{json .RepoDigests}}"]
        )
    )
    if (
        not re.fullmatch(r"sha256:[a-f0-9]{64}", identity)
        or platform != "linux|amd64"
        or not any(
            item in (PYTHON_REFERENCE, "docker.io/library/" + PYTHON_REFERENCE) for item in digests
        )
    ):
        raise base.LabControlError(
            "The reviewed installed Python image is unavailable or incompatible."
        )
    return identity


def check_capacity(disk, memory, initial, max_growth=8 * base.GIB):
    if max_growth not in (8 * base.GIB, 12 * base.GIB, 30 * base.GIB):
        raise base.LabControlError("Unreviewed internal-stage growth ceiling.")
    growth = max(0, initial - disk)
    if growth >= max_growth:
        raise base.LabControlError("The whole-stage growth guard is already reached.")
    if disk < base.MIN_FREE_DISK + max_growth - growth:
        raise base.LabControlError("Insufficient disk reserve for this reviewed stage.")
    if memory < base.MIN_FREE_MEMORY + base.GIB:
        raise base.LabControlError(
            "Two containers require one GiB plus four GiB available host headroom."
        )


def container_role(docker, identifier, run_id):
    base.validate_identity(run_id)
    if not re.fullmatch(r"[a-f0-9]{64}", identifier):
        raise base.LabControlError("Invalid verification container identity.")
    labels = json.loads(
        base.docker_result(docker, ["inspect", identifier, "--format", "{{json .Config.Labels}}"])
    )
    role = labels.get("com.docker.compose.service")
    if labels.get("org.signalbridge.enterprise.run") != run_id or (
        labels.get("org.signalbridge.enterprise.scope") != SCOPE
        or labels.get("com.docker.compose.project") != PROJECT_PREFIX + run_id
        or role not in ("database", "runner")
    ):
        raise base.LabControlError(
            "Container does not belong to this exact two-component verification."
        )
    return role


def owned(docker, run_id):
    base.validate_identity(run_id)
    output = base.docker_result(
        docker,
        [
            "ps",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            "label=org.signalbridge.enterprise.run=" + run_id,
            "--filter",
            "label=org.signalbridge.enterprise.scope=" + SCOPE,
            "--filter",
            "label=com.docker.compose.project=" + PROJECT_PREFIX + run_id,
        ],
    )
    return {
        identifier: container_role(docker, identifier, run_id)
        for identifier in output.splitlines()
        if identifier
    }


def stop_scope(docker, run_id):
    """Try every exact owned component even if another component's shutdown fails."""
    errors = []
    targets = owned(docker, run_id)
    for identifier, _role in sorted(targets.items(), key=lambda row: row[1] == "database"):
        try:
            container_role(docker, identifier, run_id)
            base.docker_result(docker, ["stop", "--time", "10", identifier], timeout=20)
            if (
                base.docker_result(
                    docker, ["inspect", identifier, "--format", "{{.State.Running}}"]
                )
                != "false"
            ):
                raise base.LabControlError("Component shutdown was not verified.")
        except Exception as error:
            errors.append(type(error).__name__)
    if errors:
        raise base.LabControlError("One or more owned components could not be verified stopped.")
    return len(targets)


def host_path(value):
    value = str(value).replace("\\", "/").lower().rstrip("/")
    prefix = "/run/desktop/mnt/host/"
    if value.startswith(prefix) and re.match(r"[a-z]/", value[len(prefix) :]):
        value = value[len(prefix)] + ":/" + value[len(prefix) + 2 :]
    return value


def verify_runtime(docker, identifier, run_id, run_dir, expected_image):
    role = container_role(docker, identifier, run_id)
    fields = '{"image":{{json .Image}},"memory":{{.HostConfig.Memory}},"swap":{{.HostConfig.MemorySwap}},"cpu":{{.HostConfig.NanoCpus}},"pids":{{.HostConfig.PidsLimit}},"readonly":{{.HostConfig.ReadonlyRootfs}},"privileged":{{.HostConfig.Privileged}},"caps":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"restart":{{json .HostConfig.RestartPolicy.Name}},"ports":{{json .NetworkSettings.Ports}},"networks":{{json .NetworkSettings.Networks}},"mounts":{{json .Mounts}},"tmpfs":{{json .HostConfig.Tmpfs}},"user":{{json .Config.User}}}'
    data = json.loads(base.docker_result(docker, ["inspect", identifier, "--format", fields]))
    network = "sb-enterprise-internal-" + run_id
    if (
        data["image"] != expected_image
        or data["memory"] != 512 * 1024**2
        or (
            data["swap"] != data["memory"]
            or data["cpu"] != 10**9
            or data["pids"] != (128 if role == "database" else 96)
            or not data["readonly"]
            or data["privileged"]
            or data["caps"] != ["ALL"]
            or "no-new-privileges:true" not in data["security"]
            or data["restart"] != "no"
            or set(data["networks"] or {}) != {network}
            or any(value is not None for value in (data["ports"] or {}).values())
            or data["user"] != ("postgres" if role == "database" else "10001:10001")
        )
    ):
        raise base.LabControlError("Effective native limits differ from the reviewed profile.")
    if (
        base.docker_result(docker, ["network", "inspect", network, "--format", "{{.Internal}}"])
        != "true"
    ):
        raise base.LabControlError("Verification network is not internal.")
    directory = Path(run_dir)
    expected_tmpfs = (
        {"/tmp": 64 * 1024**2, "/opt/verification-deps": 128 * 1024**2}
        if role == "runner"
        else {
            "/tmp": 64 * 1024**2,
            "/var/run/postgresql": 16 * 1024**2,
        }
    )
    if set(data["tmpfs"] or {}) != set(expected_tmpfs):
        raise base.LabControlError("Unexpected temporary filesystem mounts.")
    for target, maximum in expected_tmpfs.items():
        options = data["tmpfs"][target].lower().split(",")
        sizes = [value[5:] for value in options if value.startswith("size=")]
        if len(sizes) != 1 or not re.fullmatch(r"[1-9][0-9]*[kmg]?", sizes[0]):
            raise base.LabControlError("A temporary filesystem has no verified finite size.")
        suffix = sizes[0][-1]
        size = (
            int(sizes[0][:-1]) * {"k": 1024, "m": 1024**2, "g": 1024**3}[suffix]
            if suffix in "kmg"
            else int(sizes[0])
        )
        if (
            size > maximum
            or not {"rw", "nosuid"}.issubset(options)
            or (target != "/opt/verification-deps" and "noexec" not in options)
            or (
                role == "runner"
                and (
                    "nodev" not in options
                    or (
                        target == "/opt/verification-deps"
                        and (
                            not {"exec", "mode=0700", "uid=10001", "gid=10001"}.issubset(options)
                            or "noexec" in options
                        )
                    )
                )
            )
        ):
            raise base.LabControlError(
                "Temporary filesystem limits differ from the reviewed profile."
            )
    mounts = {
        "/run/secrets/verifier_password": (directory / "secrets/verifier-password", False),
    }
    if role == "runner":
        mounts.update(
            {
                "/workspace": (directory / "source", False),
                "/wheels": (directory / "wheels", False),
                "/evidence": (directory / "evidence", True),
            }
        )
    else:
        mounts.update(
            {
                "/run/secrets/bootstrap_password": (
                    directory / "secrets/bootstrap-password",
                    False,
                ),
                "/docker-entrypoint-initdb.d/10-verification.sh": (
                    directory / "source/integrations/enterprise/init-verification.sh",
                    False,
                ),
            }
        )
    actual = {item["Destination"]: item for item in data["mounts"] if item["Type"] != "tmpfs"}
    volume = actual.pop("/var/lib/postgresql/data", None) if role == "database" else None
    if role == "database" and (
        not volume
        or volume["Type"] != "volume"
        or not volume["RW"]
        or volume.get("Name") != "sb-enterprise-in-network-" + run_id
    ):
        raise base.LabControlError("Disposable database volume binding changed.")
    if set(actual) != set(mounts):
        raise base.LabControlError(
            "An unreviewed native mount is present or required mount is absent."
        )
    for name, (source, writable) in mounts.items():
        item = actual[name]
        if (
            item["Type"] != "bind"
            or item["RW"] != writable
            or host_path(item["Source"]) != host_path(source)
        ):
            raise base.LabControlError("An effective bind mount differs from the private run.")


def watchdog(docker, run_id, workspace, deadline, initial_disk, receipt, max_growth=8 * base.GIB):
    base.validate_identity(run_id)
    if not 0 < deadline - time.time() <= base.MAX_RUNTIME_SECONDS:
        raise base.LabControlError("Independent watchdog deadline is outside the approved stage.")
    if max_growth not in (8 * base.GIB, 12 * base.GIB):
        raise base.LabControlError("Unreviewed independent-watchdog growth ceiling.")
    receipt = Path(receipt)
    temporary = receipt.with_name("watchdog-ready.tmp")
    temporary.write_text(json.dumps({"run_id": run_id, "armed": True}), encoding="utf8")
    temporary.replace(receipt.with_name("watchdog-ready.json"))
    result = {"run_id": run_id, "reason": "deadline", "shutdown_verified": False}
    try:
        while time.time() < deadline:
            free = shutil.disk_usage(workspace).free
            if free < base.MIN_FREE_DISK or initial_disk - free >= max_growth:
                result["reason"] = "disk_reserve" if free < base.MIN_FREE_DISK else "disk_growth"
                break
            targets = owned(docker, run_id)
            if len(targets) > 2 or len(set(targets.values())) != len(targets):
                raise base.LabControlError("Unexpected additional verification component.")
            for identifier, role in targets.items():
                state = base.docker_result(
                    docker, ["inspect", identifier, "--format", "{{.State.Status}}"]
                )
                if state in ("exited", "dead"):
                    result["reason"] = role + "_finished"
                    return result
                if state not in ("created", "running"):
                    raise base.LabControlError("Unrecognized component state.")
            if receipt.with_name("launcher-finished.json").exists():
                result["reason"] = "launcher_finished"
                break
            time.sleep(min(2, max(0, deadline - time.time())))
    except Exception as error:
        result.update(reason="control_error", error_class=type(error).__name__)
        raise
    finally:
        try:
            result["stopped_component_count"] = stop_scope(docker, run_id)
            result["shutdown_verified"] = True
        except Exception as error:
            result["shutdown_error_class"] = type(error).__name__
        result["stopped_at"] = datetime.now(timezone.utc).isoformat()
        receipt.write_text(json.dumps(result, indent=2) + "\n", encoding="utf8")
    return result
