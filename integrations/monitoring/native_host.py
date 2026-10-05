"""Finite cached-only monitoring controller and independent shutdown process.

No native operation is performed at import. CLI execution requires a new,
separately approved command and reviewed source digest. An approval reference
records authorization, never grants it. No pulls, builds, shared-engine mode,
published ports, host trust changes or removal of retained resources exist.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from bridge.contract import parse_json, timestamp
from integrations.enterprise import verification as base
from integrations.enterprise.network_verification import host_path, snapshot_source
from integrations.enterprise.reference_host_controls import read_json, runtime_fields, same
from integrations.enterprise.reference_host_evidence import safe_path, validate_snapshot
from integrations.enterprise.windows_capacity import available_memory

from .native_profile import (
    DRAIN_SECONDS,
    HERE,
    PREFIX,
    ROLES,
    SCOPE,
    SECONDS,
    capacity,
    failure_category,
    image_lock,
    labels,
    require,
    specifications,
)

ROOT = HERE.parents[1]
HEX_ID = re.compile(r"[a-f0-9]{64}\Z")


def call(docker, arguments, timeout=5):
    value = base.docker_result(docker, arguments, timeout=timeout)
    require(type(value) is str and len(value.encode("utf8")) <= 262144)
    return value


def listing(docker, *, all_containers=False, run=None):
    arguments = ["ps", "--no-trunc", "--quiet"]
    if all_containers:
        arguments.append("--all")
    if run is not None:
        base.validate_identity(run)
        arguments.extend(
            [
                "--filter",
                "label=org.signalbridge.enterprise.run=" + run,
                "--filter",
                "label=org.signalbridge.enterprise.scope=" + SCOPE,
            ]
        )
    value = call(docker, arguments)
    rows = value.splitlines() if value else []
    require(
        len(rows) <= 256 and len(set(rows)) == len(rows) and all(HEX_ID.fullmatch(v) for v in rows)
    )
    return rows


def role(docker, identifier, run):
    require(type(identifier) is str and HEX_ID.fullmatch(identifier))
    value = parse_json(
        call(
            docker,
            [
                "inspect",
                identifier,
                "--format",
                '{"labels":{{json .Config.Labels}},"name":{{json .Name}}}',
            ],
        )
    )
    require(type(value["labels"]) is dict)
    component = value["labels"].get("com.docker.compose.service")
    require(
        component in ROLES
        and all(value["labels"].get(k) == v for k, v in labels(run, component).items())
    )
    require(value["name"] == "/" + PREFIX + run + "-" + component)
    return component


def owned(docker, run):
    rows = {}
    for identifier in listing(docker, all_containers=True, run=run):
        component = role(docker, identifier, run)
        require(component not in rows)
        rows[component] = identifier
    require(len(rows) <= 3)
    return rows


def stop_scope(docker, run):
    """Revalidate each target immediately; a foreign component is never mutated."""
    failed, targets = False, []
    for identifier in listing(docker, all_containers=True, run=run):
        try:
            targets.append((role(docker, identifier, run), identifier))
        except Exception:
            failed = True
    for component, identifier in sorted(targets, key=lambda row: row[0] == "runner"):
        try:
            require(role(docker, identifier, run) == component)
            call(docker, ["stop", "--time", "5", identifier], timeout=10)
            require(
                call(docker, ["inspect", identifier, "--format", "{{.State.Running}}"]) == "false"
            )
        except Exception:
            failed = True
    require(not failed)
    return len(targets)


def image_identities(row):
    # Classic store: config digest. Containerd store: the pinned target digest.
    return {row["config_digest"], "sha256:" + row["reference"].rsplit("@sha256:", 1)[1]}


def inspect_images(docker):
    images = {}
    for component, row in image_lock()["images"].items():
        value = parse_json(
            call(
                docker,
                [
                    "image",
                    "inspect",
                    row["reference"],
                    "--format",
                    # The containerd store omits empty config keys; index yields null.
                    '{"id":{{json .Id}},"os":{{json .Os}},"arch":{{json .Architecture}},"digests":{{json .RepoDigests}},"environment":{{json (index .Config "Env")}},"labels":{{json (index .Config "Labels")}}}',
                ],
            )
        )
        acceptable = {row["reference"], "docker.io/" + row["reference"]}
        if component == "runner":
            acceptable.add("docker.io/library/" + row["reference"])
        require(
            value["id"] in image_identities(row)
            and value["os"] == "linux"
            and value["arch"] == "amd64"
        )
        require(type(value["digests"]) is list and bool(acceptable.intersection(value["digests"])))
        require(type(value["environment"]) is list and len(value["environment"]) <= 64)
        require(
            value["labels"] is None or type(value["labels"]) is dict and len(value["labels"]) <= 64
        )
        images[component] = value
    return images


def create_arguments(run, directory, component, image, anchor=None):
    row = specifications(run, directory, anchor)[component]
    require(component == "runner" or type(anchor) is str and HEX_ID.fullmatch(anchor))
    args = [
        "create",
        "--pull=never",
        "--name",
        row["name"],
        "--network",
        row["network_mode"],
        "--memory",
        str(row["memory"]),
        "--memory-swap",
        str(row["swap"]),
        "--cpus",
        "1",
        "--pids-limit",
        str(row["pids"]),
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--restart",
        "no",
        "--user",
        row["user"],
        "--ipc",
        "private",
        "--cgroupns",
        "private",
        "--log-driver",
        "json-file",
        "--log-opt",
        "max-size=5m",
        "--log-opt",
        "max-file=2",
        "--workdir",
        row["workdir"],
        "--entrypoint",
        row["entrypoint"],
    ]
    for key, value in row["labels"].items():
        args.extend(["--label", key + "=" + value])
    for key, value in row["environment"].items():
        args.extend(["--env", key + "=" + value])
    for target, source in row["binds"].items():
        require(source.is_absolute() and "," not in str(source))
        args.extend(["--mount", "type=bind,readonly,source=" + str(source) + ",target=" + target])
    for target, options in row["tmpfs"].items():
        args.extend(["--tmpfs", target + ":" + options])
    require(image in image_identities(image_lock()["images"][component]))
    return [*args, image, *row["command"]]


def environment(rows):
    require(type(rows) is list and len(rows) <= 64)
    result = {}
    for value in rows:
        require(type(value) is str and "=" in value and len(value) <= 4096)
        key, text = value.split("=", 1)
        require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) and key not in result)
        result[key] = text
    return result


def verify_runtime(docker, identifier, run, directory, images, anchor, *, running=False):
    component = role(docker, identifier, run)
    row = specifications(run, directory, anchor)[component]
    data = parse_json(
        call(
            docker,
            [
                "inspect",
                identifier,
                "--format",
                runtime_fields()[:-1]
                + ',"network_mode":{{json .HostConfig.NetworkMode}},"running":{{json .State.Running}},"labels":{{json .Config.Labels}}}',
            ],
        )
    )
    fixed = {
        key: row[key]
        for key in (
            "memory",
            "swap",
            "cpu",
            "pids",
            "readonly",
            "privileged",
            "cap_drop",
            "security",
            "restart",
            "user",
            "log",
            "workdir",
            "command",
        )
    }
    fixed.update(
        image=images[component]["id"],
        entrypoint=[row["entrypoint"]],
        network_mode=row["network_mode"],
        pid_mode="",
        ipc_mode="private",
        uts_mode="",
        cgroup_mode="private",
    )
    require(all(same(data.get(key), value) for key, value in fixed.items()))
    require(same(data["labels"], {**(images[component].get("labels") or {}), **row["labels"]}))
    require(not running or data["running"] is True)
    require(
        not any(data.get(k) for k in ("cap_add", "devices", "device_requests", "port_bindings"))
    )
    require(all(v is None for v in (data.get("ports") or {}).values()))
    require(same(data["tmpfs"], row["tmpfs"]))
    require(
        environment(data["environment"])
        == {**environment(images[component]["environment"]), **row["environment"]}
    )
    require(set(data["networks"] or {}) == ({"none"} if component == "runner" else set()))
    observed = {}
    for mount in data["mounts"]:
        target = mount.get("Destination")
        require(target not in observed)
        if mount["Type"] == "tmpfs":
            require(target in row["tmpfs"] and not mount.get("Source"))
            continue
        require(mount["Type"] == "bind" and mount["RW"] is False)
        observed[target] = host_path(mount["Source"])
    require(observed == {target: host_path(path) for target, path in row["binds"].items()})


def guard_runtime(docker, run, directory, images, seen, *, committed=False):
    current = owned(docker, run)
    require(all(current.get(component) == identifier for component, identifier in seen.items()))
    require(not committed or set(current) == set(ROLES))
    seen.update(current)
    for identifier in listing(docker):
        require(identifier in current.values())  # Exclusive engine; never stop peers.
    anchor = current.get("runner")
    require(anchor is not None or not current)
    # Include stopped foreign attachments; no network namespace membership is inferred from ps alone.
    for identifier in listing(docker, all_containers=True):
        if identifier not in current.values() and anchor is not None:
            mode = call(docker, ["inspect", identifier, "--format", "{{.HostConfig.NetworkMode}}"])
            require(mode not in ("container:" + anchor, "container:" + PREFIX + run + "-runner"))
    for identifier in current.values():
        verify_runtime(docker, identifier, run, directory, images, anchor, running=committed)
    return current


def file_identity(directory, names):
    result = {}
    for name in names:
        path = safe_path(directory / name, directory)
        require(path.is_file() and 0 < path.stat().st_size <= 16 * 1024**2)
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def write_json(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")
    require(len(raw) <= 262144 and not path.exists() and not path.is_symlink())
    with path.open("xb") as stream:
        stream.write(raw)


def inputs(directory, plan):
    validate_snapshot(directory / "source", plan["source"])
    found = set()
    for name in (*ROLES, "wheels"):
        for parent, directories, filenames in os.walk(directory / name, followlinks=False):
            for child in directories:
                safe_path(Path(parent) / child, directory)
            for child in filenames:
                path = safe_path(Path(parent) / child, directory)
                found.add(path.relative_to(directory).as_posix())
                require(len(found) <= 64)
    require(found == set(plan["files"]) - {"certificate-validity.json"})
    require(file_identity(directory, plan["files"]) == plan["files"])


def wheels(directory=None):
    value = read_json(HERE / "wheels.json", 4096)
    rows = value["wheels"]
    require({row["name"] for row in rows} == {"Django", "asgiref", "sqlparse"} and len(rows) == 3)
    result = []
    for row in rows:
        path = safe_path(ROOT / value["cache_directory"] / row["filename"], ROOT)
        require(path.is_file() and path.stat().st_size == row["size"])
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == row["sha256"])
        result.append(row)
        if directory is not None:
            with (directory / row["filename"]).open("xb") as stream:
                stream.write(raw)
    return result


def sample_capacity(stage_initial, *, before_launch=False):
    disk, memory = shutil.disk_usage(ROOT).free, available_memory()
    capacity(disk, memory, stage_initial, before_launch=before_launch)
    return {"free_disk_bytes": disk, "available_memory_bytes": memory}


def watchdog(docker, run):
    directory = base.private_run_directory(ROOT, run)
    plan = read_json(directory / "monitoring-plan.json", 262144)
    require(plan["run_id"] == run and 0 < plan["deadline"] - time.time() <= SECONDS)
    inputs(directory, plan)
    result = {"run_id": run, "shutdown_verified": False, "reason": "deadline"}
    seen, committed = {}, False
    write_json(directory / "monitoring-watchdog-ready.json", {"run_id": run, "armed": True})
    try:
        while time.time() < plan["deadline"]:
            require(same(read_json(directory / "monitoring-plan.json", 262144), plan))
            inputs(directory, plan)
            sample_capacity(plan["stage_initial"])
            marker = directory / "monitoring-started.json"
            require(not committed or marker.exists())
            if marker.exists():
                started = read_json(marker)
                require(started["run_id"] == run and set(started["containers"]) == set(ROLES))
                require(all(started["containers"].get(k) == v for k, v in seen.items()))
                seen.update(started["containers"])
                committed = True
            require(committed or time.time() - plan["created_at_epoch"] < 120)
            if (directory / "monitoring-finished.json").exists():
                require(read_json(directory / "monitoring-finished.json") == {"run_id": run})
                result["reason"] = "launcher_finished"
                break
            guard_runtime(docker, run, directory, plan["images"], seen, committed=committed)
            time.sleep(2)
    except Exception as error:
        result.update(reason="control_error", error_category=failure_category(error))
    finally:
        write_json(directory / "monitoring-abort.json", {"run_id": run, "abort": True})
        # A bounded late-create drain covers a create request already in flight.
        drain = time.monotonic() + DRAIN_SECONDS
        clean, latest = True, {}
        while time.monotonic() < drain:
            try:
                stop_scope(docker, run)
                latest = owned(docker, run)
                require(not any(v in listing(docker) for v in latest.values()))
            except Exception as error:
                clean = False
                result["shutdown_error_category"] = failure_category(error)
            time.sleep(min(2, max(0, drain - time.monotonic())))
        result.update(shutdown_verified=clean, verified_container_count=len(latest))
        write_json(directory / "monitoring-watchdog.json", result)
    return result


def executable(value):
    """The separately reviewed invocation supplies this path; never guess or search PATH."""
    require(type(value) is str and 0 < len(value) <= 512)
    path = Path(value)
    require(path.is_absolute() and path.name.lower() == "docker.exe")
    safe_path(path, Path(path.anchor))
    require(path.is_file())
    return path


def fresh_directory(run):
    directory = base.private_run_directory(ROOT, run)
    require(not directory.exists() and not directory.is_symlink())
    directory.parent.mkdir(parents=True, exist_ok=True)
    directory.mkdir(exist_ok=False)
    return directory


def execute(run, reviewed_digest, approval_reference, docker_path, certificate_python):
    """Actual native entry point, NEVER invoked by offline preparation/tests."""
    from scripts.enterprise_reference_verify import (
        certificate_runtime,
        clean_environment,
        invoke,
        private_acl,
    )
    from scripts.record_verification import source_manifest

    base.validate_identity(run)
    require(
        sys.platform == "win32"
        and type(reviewed_digest) is str
        and HEX_ID.fullmatch(reviewed_digest)
    )
    require(
        type(approval_reference) is str
        and re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", approval_reference)
    )
    docker = executable(docker_path)
    source = source_manifest(ROOT)
    require(source["sha256"] == reviewed_digest)
    stage_initial = shutil.disk_usage(ROOT).free
    sample_capacity(stage_initial, before_launch=True)
    require(not listing(docker))  # No preservation/shared-engine launch path.
    images = inspect_images(docker)  # Missing images fail; never acquire here.
    wheels()
    # Same separately supplied, version-checked runtime as the other launchers.
    certificate_python = Path(certificate_python)
    certificate_runtime(certificate_python)
    directory = fresh_directory(run)
    private_acl(run, "SecureEmpty")
    snapshot_source(ROOT, directory / "source", source)
    (directory / "wheels").mkdir()
    wheels(directory / "wheels")
    invoke(
        [certificate_python, "-B", "-m", "integrations.monitoring.native_material", directory],
        clean_environment(),
        30,
        1024,
    )
    private_acl(run, "Verify")
    created = time.time()
    deadline = created + SECONDS
    require(
        timestamp(read_json(directory / "certificate-validity.json")["expires_at"]).timestamp()
        > deadline + DRAIN_SECONDS
    )
    (directory / "runner/secrets/stop-at").write_text(str(deadline), encoding="ascii")
    names = [
        p.relative_to(directory).as_posix()
        for role_name in ROLES
        for p in (directory / role_name).rglob("*")
        if p.is_file()
    ]
    names.extend("wheels/" + row["filename"] for row in read_json(HERE / "wheels.json")["wheels"])
    names.append("certificate-validity.json")
    plan = {
        "run_id": run,
        "created_at_epoch": created,
        "deadline": deadline,
        "stage_initial": stage_initial,
        "source": source,
        "images": images,
        "files": file_identity(directory, names),
        "approval_reference": approval_reference,
    }
    write_json(directory / "monitoring-plan.json", plan)
    result = {"run_id": run, "status": "failed", "shutdown_verified": False}
    watcher = subprocess.Popen(
        [
            sys.executable,
            "-B",
            "-m",
            "integrations.monitoring.native_host",
            "watchdog",
            "--run",
            run,
            "--docker-reviewed-path",
            str(docker),
        ],
        cwd=ROOT,
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    seen = {}

    def guard():
        require(
            watcher.poll() is None
            and time.time() < deadline
            and not (directory / "monitoring-abort.json").exists()
        )
        require(
            read_json(directory / "monitoring-watchdog-ready.json")
            == {"run_id": run, "armed": True}
        )
        inputs(directory, plan)
        sample_capacity(stage_initial)
        guard_runtime(docker, run, directory, images, seen)

    try:
        arm_deadline = time.monotonic() + 15
        while not (directory / "monitoring-watchdog-ready.json").exists():
            require(watcher.poll() is None and time.monotonic() < arm_deadline)
            time.sleep(0.2)
        for component in ROLES:
            guard()
            identifier = call(
                docker,
                create_arguments(
                    run, directory, component, images[component]["id"], seen.get("runner")
                ),
                timeout=15,
            )
            require(HEX_ID.fullmatch(identifier))
            seen[component] = identifier
            guard()
            call(docker, ["start", identifier], timeout=10)
        guard()
        write_json(directory / "monitoring-started.json", {"run_id": run, "containers": seen})
        while time.time() < deadline:
            guard()
            guard_runtime(docker, run, directory, images, seen, committed=True)
            raw = call(
                docker,
                [
                    "exec",
                    seen["runner"],
                    "/usr/local/bin/python3",
                    "-I",
                    "-c",
                    "from pathlib import Path;p=Path('/state/proof.json');print(p.read_text() if p.is_file() else '{}')",
                ],
            )
            proof = parse_json(raw)
            if proof:
                from .native_runtime import validate_partial, validate_proof

                if proof.get("status") == "partial":
                    validate_partial(proof)
                    result.update(status="failed", proof=proof)
                else:
                    validate_proof(proof)
                    result.update(status="passed", proof=proof)
                break
            time.sleep(5)
    except Exception as error:
        result["error_category"] = failure_category(error)
    finally:
        write_json(directory / "monitoring-finished.json", {"run_id": run})
        finish_deadline = time.monotonic() + 5
        while (
            watcher.poll() is None
            and time.monotonic() < finish_deadline
            and not (directory / "monitoring-abort.json").exists()
        ):
            time.sleep(0.2)
        try:
            stop_scope(docker, run)
            result["launcher_shutdown_verified"] = True
        except Exception as error:
            result["shutdown_error_category"] = failure_category(error)
        try:
            watcher.wait(timeout=DRAIN_SECONDS + 90)
            receipt = read_json(directory / "monitoring-watchdog.json")
            require(
                receipt["run_id"] == run
                and receipt["shutdown_verified"] is True
                and receipt["verified_container_count"] == len(seen) == 3
            )
            require(receipt["reason"] == "launcher_finished" and "error_category" not in receipt)
            result["shutdown_verified"] = result.get("launcher_shutdown_verified") is True
        except Exception as error:
            result["watchdog_error_category"] = failure_category(error)
        if not result["shutdown_verified"]:
            result["status"] = "failed"
        write_json(directory / "monitoring-execution.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("execute", "watchdog"))
    parser.add_argument("--run", required=True)
    parser.add_argument("--docker-reviewed-path", required=True)
    parser.add_argument("--reviewed-source-sha256")
    parser.add_argument("--approval-reference")
    parser.add_argument("--certificate-python")
    args = parser.parse_args()
    try:
        result = (
            watchdog(executable(args.docker_reviewed_path), args.run)
            if args.mode == "watchdog"
            else execute(
                args.run,
                args.reviewed_source_sha256,
                args.approval_reference,
                args.docker_reviewed_path,
                args.certificate_python,
            )
        )
        return (
            0
            if result.get("shutdown_verified") is True
            and result.get("status", "passed") == "passed"
            else 1
        )
    except Exception:
        # Never dump Docker diagnostics, credentials or native exception values.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
