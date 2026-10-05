"""One separately approved offline native scanner run over genuine source captures.

Uses one inspected cached image; never starts Docker Desktop, builds/pulls images,
changes host trust, reads source credentials, deletes resources or changes other
projects. An approval reference records authorization; it cannot grant it.
"""

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.contract import parse_json
from integrations.enterprise import verification as base
from integrations.enterprise.network_verification import snapshot_source
from integrations.enterprise.reference_host_controls import read_json, same
from integrations.enterprise.reference_host_evidence import safe_path
from integrations.enterprise.windows_capacity import available_memory
from integrations.zap_enterprise import scanner_host_controls as host
from integrations.zap_enterprise.scanner_contract import receipt_bytes
from integrations.zap_enterprise.scanner_controls import PREFIX, verify_compose_config
from integrations.zap_enterprise.scanner_host_evidence import validate_receipts
from integrations.zap_enterprise.scanner_runner import TOTAL_SECONDS
from integrations.zap_enterprise.source_transfer import load_completed_source
from scripts.enterprise_reference_verify import (
    clean_environment,
    invoke,
    private_acl,
    private_docker_config,
    require_guard,
)
from scripts.record_verification import receipt_path, source_manifest


def check_capacity():
    disk, memory = shutil.disk_usage(ROOT).free, available_memory()
    host.check_capacity(disk, memory)
    return {"free_disk_bytes": disk, "available_host_memory_bytes": memory}


def no_foreign_running(docker, targets=()):
    raw = base.docker_result(docker, ["ps", "--quiet", "--no-trunc"], timeout=5)
    identifiers = raw.splitlines() if raw else []
    host.require(len(identifiers) <= 1 and len(identifiers) == len(set(identifiers)))
    host.require(all(re.fullmatch(r"[a-f0-9]{64}", identifier) for identifier in identifiers))
    host.require(set(identifiers).issubset(targets))


def verified_source():
    manifest = source_manifest(ROOT)
    milestone = read_json(safe_path(ROOT / "docs/enterprise-milestone.json", ROOT), 262144)
    reference = milestone.get("current_offline_receipt")
    host.require(
        isinstance(reference, str)
        and re.fullmatch(r"docs/evidence/[0-9]{8}-enterprise-offline-[a-f0-9]{32}\.json", reference)
    )
    receipt = read_json(safe_path(ROOT / reference, ROOT), 262144)
    host.require(receipt.get("passed") is True and receipt.get("source_unchanged") is True)
    host.require(receipt.get("source_sha256") == manifest["sha256"])
    return manifest


def prepare(docker, run, directory, source_run, manifest):
    private_acl(run, "SecureEmpty")
    value, binding = load_completed_source(
        ROOT, source_run, manifest, now=datetime.now(timezone.utc)
    )
    (directory / "input").mkdir()
    (directory / "evidence").mkdir()
    raw = receipt_bytes(value)
    with (directory / "input/source-capture.json").open("xb") as output:
        output.write(raw)
    snapshot = snapshot_source(ROOT, directory / "source", manifest)
    environment = clean_environment()
    environment.update(
        SB_SCANNER_RUN=run,
        SB_SCANNER_DIRECTORY=str(directory),
        SB_SCANNER_IMAGE="not_assigned_until_inspection",
        DOCKER_CONFIG=str(private_docker_config(directory, docker)),
    )
    private_acl(run, "Verify")
    return raw, binding, snapshot, environment


def compose_command(docker, run, directory):
    base.validate_identity(run)
    host.require(directory == base.private_run_directory(ROOT, run))
    return base.docker_command(
        docker,
        [
            "compose",
            "--project-directory",
            str(directory),
            "--project-name",
            PREFIX + run,
            "--file",
            str(ROOT / "integrations/zap_enterprise/compose.scanner.yaml"),
        ],
    )


def exact_component(docker, run, directory, image):
    targets = host.owned(docker, run)
    host.require(len(targets) == 1 and list(targets.values()) == ["scanner"])
    identifier = next(iter(targets))
    host.verify_runtime(docker, identifier, run, directory, image)
    return identifier


def write_gate(directory, run, raw, binding):
    gate = directory / "evidence/allow-scanner.json"
    host.require(not gate.exists() and not gate.is_symlink())
    value = {
        "run_id": run,
        "runtime_verified": True,
        "source_run_id": binding["source_run_id"],
        "source_receipt_sha256": binding["source_receipt_sha256"],
        "input_sha256": hashlib.sha256(raw).hexdigest(),
    }
    temporary = directory / "evidence/allow-scanner.tmp"
    with temporary.open("xb") as output:
        output.write(receipt_bytes(value))
    temporary.replace(gate)


def execute(docker, run, directory, image, environment, guard, raw, binding):
    command = compose_command(docker, run, directory)
    require_guard(guard, run, directory)
    parsed = invoke([*command, "config", "--format", "json"], environment, 20)
    verify_compose_config(parse_json(parsed), image["id"], run, directory)
    check_capacity()
    host.require(not host.owned(docker, run))
    no_foreign_running(docker)
    require_guard(guard, run, directory)
    invoke([*command, "create", "--no-build", "--pull", "never", "--no-recreate"], environment, 60)
    identifier = exact_component(docker, run, directory, image)
    host.require(
        base.docker_result(
            docker, ["inspect", identifier, "--format", "{{.State.Status}}"], timeout=5
        )
        == "created"
    )
    private_acl(run, "Verify")
    require_guard(guard, run, directory)
    no_foreign_running(docker)
    check_capacity()
    # The entry point requires this gate at startup. Release it only after the
    # created/stopped exact runtime is checked; never race a running entry point.
    write_gate(directory, run, raw, binding)
    private_acl(run, "Verify")
    require_guard(guard, run, directory)
    base.docker_result(docker, ["start", identifier], timeout=20)
    exact_component(docker, run, directory, image)
    deadline = time.monotonic() + TOTAL_SECONDS + 30
    while time.monotonic() < deadline:
        require_guard(guard, run, directory)
        no_foreign_running(docker, [identifier])
        state = base.docker_result(
            docker,
            ["inspect", identifier, "--format", "{{.State.Status}}|{{.State.ExitCode}}"],
            timeout=5,
        )
        if state == "exited|0":
            exact_component(docker, run, directory, image)
            private_acl(run, "Verify")
            return {
                "parsed_configuration_verified": True,
                "runtime_isolation_verified": True,
                "runner_exit_code": 0,
                "owned_container_id": identifier,
            }
        host.require(state.startswith("running|"))
        time.sleep(0.5)
    raise base.LabControlError("The offline native scanner execution deadline expired.")


def arm_guard(docker, run):
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen(
        [
            sys.executable,
            "-B",
            str(Path(__file__).resolve()),
            "watchdog",
            "--docker",
            str(docker),
            "--run",
            run,
            "--deadline",
            str(time.time() + host.MAX_GUARD_SECONDS),
        ],
        cwd=ROOT,
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
        shell=False,
    )


def launch(docker, approval_reference, source_run):
    host.require(
        sys.platform == "win32"
        and isinstance(approval_reference, str)
        and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", approval_reference)
    )
    base.validate_identity(source_run)
    docker = Path(docker)
    host.require(docker.is_absolute() and docker.is_file() and not docker.is_symlink())
    manifest = verified_source()
    # Reject missing/stale/incomplete native input before any daemon request.
    private_acl(source_run, "Verify")
    _, expected_binding = load_completed_source(
        ROOT, source_run, manifest, now=datetime.now(timezone.utc)
    )
    capacity = check_capacity()
    no_foreign_running(docker)
    image = host.inspect_image(docker)
    run, started = uuid.uuid4().hex, datetime.now(timezone.utc)
    directory = base.private_run_directory(ROOT, run)
    directory.mkdir(parents=True, exist_ok=False)
    receipt = {
        "schema_version": 1,
        "kind": "signalbridge-native-authenticated-zap-offline",
        "run_id": run,
        "source_run_id": source_run,
        "approval_reference": approval_reference,
        "status": "incomplete",
        "acceptance_passed": False,
        "native_zap_executed": False,
        "started_at": started.isoformat(),
        "capacity_before": capacity,
        "source_sha256": manifest["sha256"],
        "source_binding": expected_binding,
        "image_id": image["id"],
        "image_reference": host.IMAGE,
        "stage_initial_free_disk_bytes": host.INITIAL_DISK,
        "stage_growth_ceiling_bytes": host.GROWTH,
        "limits": [
            "Two fresh native passive analyses of credential-free captures; only header rule 10021.",
            "Genuine source authentication is verified separately; no ZAP login, crawling, active requests or source changes.",
            "Hashes and trusted operator receipts are not independent attestation against an administrator.",
            "Capacity readings are detection guards, not physical quotas. Retained containers/images are not removed.",
        ],
    }
    guard = None
    try:
        raw, binding, snapshot, environment = prepare(docker, run, directory, source_run, manifest)
        host.require(same(binding, expected_binding))
        receipt["source_snapshot"] = snapshot
        receipt["input_sha256"] = hashlib.sha256(raw).hexdigest()
        environment["SB_SCANNER_IMAGE"] = image["id"]
        guard = arm_guard(docker, run)
        for _ in range(20):
            host.require(guard.poll() is None)
            if (directory / "watchdog-ready.json").exists():
                require_guard(guard, run, directory)
                break
            time.sleep(0.25)
        else:
            raise base.LabControlError("Offline scanner watchdog readiness expired.")
        receipt.update(execute(docker, run, directory, image, environment, guard, raw, binding))
        receipt["scanner_proof"] = validate_receipts(
            ROOT, run, manifest, now=datetime.now(timezone.utc)
        )
        _, final_binding = load_completed_source(
            ROOT, source_run, manifest, now=datetime.now(timezone.utc)
        )
        host.require(same(binding, final_binding))
        receipt["source_archive_unchanged"] = True
        receipt["status"] = "passed_execution_pending_shutdown"
    except Exception as error:
        receipt["error_class"] = type(error).__name__
        # Arbitrary exceptions can contain sensitive runtime details. Retain only
        # their class publicly; fixed control codes have a constant message.
    finally:
        main = {"run_id": run, "shutdown_verified": False}
        try:
            main.update(
                stopped_component_count=host.stop_scope(docker, run), shutdown_verified=True
            )
        except Exception as error:
            main["shutdown_error_class"] = type(error).__name__
        receipt["main_shutdown"] = main
        if guard is not None:
            try:
                host.write_control(ROOT, run, "launcher-finished.json", {"run_id": run})
                guard.wait(timeout=55)
                independent = read_json(directory / "watchdog.json")
                receipt["independent_shutdown"] = independent
                receipt.update(
                    host.validate_shutdown(
                        main, independent, run, started=started, finished=datetime.now(timezone.utc)
                    )
                )
            except Exception as error:
                receipt["independent_shutdown_error_class"] = type(error).__name__
                receipt["watchdog_pending"] = guard.poll() is None
        receipt.update(
            finished_at=datetime.now(timezone.utc).isoformat(),
            free_disk_after_bytes=shutil.disk_usage(ROOT).free,
        )
        try:
            receipt["source_unchanged"] = same(manifest, source_manifest(ROOT))
        except Exception:
            receipt["source_unchanged"] = False
        passed = bool(
            receipt["status"] == "passed_execution_pending_shutdown"
            and receipt["source_unchanged"]
            and receipt.get("main_shutdown_verified")
            and receipt.get("independent_shutdown_verified")
        )
        receipt.update(
            acceptance_passed=passed,
            native_zap_executed=passed,
            status="passed" if passed else "incomplete",
        )
        raw_receipt = receipt_bytes(receipt)
        with (directory / "receipt.json").open("xb") as output:
            output.write(raw_receipt)
        public_id = started.strftime("%Y%m%d") + "-authenticated-zap-offline-" + run
        public = receipt_path(ROOT, "docs/evidence/" + public_id + ".json", public_id)
        with public.open("xb") as output:
            output.write(raw_receipt)
    return directory, passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("launch")
    start.add_argument("--docker", type=Path, required=True)
    start.add_argument("--approval-reference", required=True)
    start.add_argument("--source-run", required=True)
    guard = commands.add_parser("watchdog")
    guard.add_argument("--docker", type=Path, required=True)
    guard.add_argument("--run", required=True)
    guard.add_argument("--deadline", type=float, required=True)
    options = parser.parse_args()
    host.require(sys.platform == "win32")
    if options.command == "watchdog":
        result = host.watchdog(
            options.docker, options.run, ROOT, options.deadline, available_memory
        )
        return 0 if result["shutdown_verified"] else 1
    directory, passed = launch(options.docker, options.approval_reference, options.source_run)
    print("Offline scanner receipt retained: " + str(directory))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
