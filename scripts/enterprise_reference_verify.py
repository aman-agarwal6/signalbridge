"""One separately reviewed Windows source-proof run; cached components only.

This never starts Docker Desktop, pulls/builds images, downloads dependencies,
changes host trust, updates other projects or removes retained resources. An
approval reference records the user's authorization; it cannot grant permission.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrations.enterprise import network_verification as cached
from integrations.enterprise import reference_host_controls as host
from integrations.enterprise import verification as base
from integrations.enterprise.private_acl_diagnostics import MODES
from integrations.enterprise.private_acl_diagnostics import failure as acl_failure
from integrations.enterprise.reference_controls import PREFIX, SECRETS, verify_compose_config
from integrations.enterprise.reference_host_evidence import validate_native, validate_shutdown
from integrations.enterprise.reference_native_support import ACCOUNTS, FIELDS, profile
from integrations.enterprise.windows_capacity import available_memory
from scripts.record_verification import receipt_path, source_manifest

POWERSHELL = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
ACL = ROOT / "integrations/enterprise/reference-private-acl.ps1"


def clean_environment():
    # No inherited DB, proxy, preload, key-log or Compose override inputs.
    environment = {
        k: v
        for k, v in os.environ.items()
        if k.upper()
        in {
            "SYSTEMROOT",
            "WINDIR",
            "PATH",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
            # Docker Desktop's Windows settings loader requires this OS path.
            # Omitting it caused a native startup crash before daemon readiness.
            "PROGRAMDATA",
            # Windows expands this drive prefix in Desktop/system cache paths.
            # Keep the OS-provided value; do not invent a replacement drive.
            "SYSTEMDRIVE",
        }
    }
    environment.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", COMPOSE_DISABLE_ENV_FILE="1")
    return environment


def invoke(arguments, environment, timeout, limit=262144, *, acl_mode=None):
    if acl_mode is not None and (type(acl_mode) is not str or acl_mode not in MODES):
        raise base.LabControlError("Invalid private ACL helper mode.")
    result = subprocess.run(
        [str(a) for a in arguments],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        shell=False,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    if acl_mode is not None:
        # The private helper has a separate closed protocol. Preserve useful
        # branch metadata only on its exact failure channel; never native text.
        if (
            type(result.returncode) is int
            and result.returncode == 1
            and not result.stdout
            and len(result.stderr) <= limit
        ):
            diagnostic = acl_failure(result.stderr, acl_mode)
            if diagnostic is not None:
                raise diagnostic
        if result.stderr:
            raise base.LabControlError("A fixed private ACL helper phase failed.")
    if result.returncode or len(result.stdout) > limit or len(result.stderr) > limit:
        raise base.LabControlError("A fixed source preparation or runtime phase failed.")
    return result.stdout


def private_acl(run, mode):
    if sys.platform != "win32" or mode not in ("SecureEmpty", "Verify"):
        raise base.LabControlError("Private ACL controls require the reviewed Windows profile.")
    base.validate_identity(run)
    raw = invoke(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            ACL,
            "-Workspace",
            ROOT,
            "-Run",
            run,
            "-Mode",
            mode,
        ],
        clean_environment(),
        30,
        1024,
        acl_mode=mode,
    )
    from bridge.contract import parse_json

    value = parse_json(raw)
    if not host.same(
        value, {"private_acl_verified": True, "inherited_public_access_removed": True}
    ):
        raise base.LabControlError("Private source ACL was not verified.")
    return value


def check_capacity():
    disk, memory = shutil.disk_usage(ROOT).free, available_memory()
    cached.check_capacity(disk, memory, host.INITIAL_DISK, host.GROWTH)
    return {"free_disk_bytes": disk, "free_memory_bytes": memory}


def certificate_runtime(python):
    python = Path(python)
    if not python.is_absolute() or not python.is_file() or python.is_symlink():
        raise base.LabControlError("The existing reviewed certificate interpreter is unavailable.")
    raw = invoke(
        [
            python,
            "-I",
            "-c",
            "import cryptography,json,sys;print(json.dumps({'python':sys.version.split()[0],'cryptography':cryptography.__version__}))",
        ],
        clean_environment(),
        15,
        1024,
    )
    from bridge.contract import parse_json

    if not host.same(parse_json(raw), {"python": "3.12.14", "cryptography": "50.0.1"}):
        raise base.LabControlError(
            "The existing certificate runtime differs from the reviewed version."
        )


def prepare_credentials(directory):
    secret_directory = directory / "secrets"
    secret_directory.mkdir(exist_ok=False)
    values = {
        name: {account: secrets.token_urlsafe(48) for account in sorted(ACCOUNTS)}
        if name == "accounts"
        else secrets.token_urlsafe(48)
        for name in sorted(FIELDS)
    }
    # Record the recognized profile first so interrupted preparation remains
    # publication-scannable. Partial preparation never authorizes execution.
    with (secret_directory / "source-profile").open("x", encoding="ascii") as stream:
        stream.write(json.dumps(values, sort_keys=True) + "\n")
    tokens = [*values["accounts"].values(), *(v for k, v in values.items() if k != "accounts")]
    for name in ("bootstrap-password", "source-password", "console-password"):
        value = secrets.token_urlsafe(48)
        tokens.append(value)
        with (secret_directory / name).open("x", encoding="ascii") as stream:
            stream.write(value)
    if len(set(tokens)) != len(tokens):
        raise base.LabControlError("Fresh source credentials must be distinct.")


def certificate_metadata(value, run, directory, hours=2):
    from bridge.contract import timestamp

    fields = {
        "run_id",
        "authority_sha256",
        "server_certificate_sha256",
        "created_at",
        "expires_at",
        "loopback_only",
        "host_trust_changed",
        "signing_key_persisted",
        "python_version",
        "cryptography_version",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value["run_id"] != run
        or value["loopback_only"] is not True
        or value["host_trust_changed"] is not False
        or value["signing_key_persisted"] is not False
        or value["python_version"] != "3.12.14"
        or value["cryptography_version"] != "50.0.1"
        or not isinstance(value["server_certificate_sha256"], dict)
        or set(value["server_certificate_sha256"]) != {"source", "console"}
    ):
        raise base.LabControlError("Temporary certificate metadata is outside the fixed profile.")
    now = datetime.now(timezone.utc)
    created, expiry = timestamp(value["created_at"]), timestamp(value["expires_at"])
    if (
        hours not in (2, 26)
        or not 0 <= (now - created).total_seconds() <= 60
        or (expiry - created).total_seconds() != hours * 3600
    ):
        raise base.LabControlError("Temporary certificate validity differs from preparation.")
    for filename, digest in (
        ("lab-ca.pem", value["authority_sha256"]),
        *[
            (c + "-certificate.pem", value["server_certificate_sha256"][c])
            for c in ("source", "console")
        ],
    ):
        path = directory / "secrets" / filename
        if (
            not isinstance(digest, str)
            or not re.fullmatch(r"[a-f0-9]{64}", digest)
            or not path.is_file()
            or path.is_symlink()
            or path.stat().st_size > 4096
            or hashlib.sha256(path.read_bytes()).hexdigest() != digest
        ):
            raise base.LabControlError("Temporary public certificate identity changed.")
    return value


def private_docker_config(directory, docker):
    plugins = Path(docker).parent.parent / "cli-plugins"
    compose = plugins / "docker-compose.exe"
    if not compose.is_file() or any(
        p.is_symlink() or getattr(p.lstat(), "st_file_attributes", 0) & 0x400
        for p in (plugins, compose)
    ):
        raise base.LabControlError("The installed reviewed Compose plugin is unavailable.")
    config = directory / "docker-config"
    config.mkdir(exist_ok=False)
    with (config / "config.json").open("x", encoding="ascii") as stream:
        stream.write(json.dumps({"cliPluginsExtraDirs": [str(plugins)]}) + "\n")
    return config


def prepare(run, directory, images, certificate_python, wheel_cache_run, docker, hours=2):
    private_acl(run, "SecureEmpty")
    (directory / "evidence").mkdir()
    prepare_credentials(directory)
    environment = clean_environment()
    certificate = invoke(
        [
            certificate_python,
            "-B",
            "-m",
            "integrations.enterprise.reference_certificates",
            "--workspace",
            ROOT,
            "--run",
            run,
            "--hours",
            str(hours),
        ],
        environment,
        30,
        16384,
    )
    from bridge.contract import parse_json

    certificate = certificate_metadata(parse_json(certificate), run, directory, hours)
    inventory = directory / "secrets"
    if {p.name for p in inventory.iterdir()} != set(SECRETS.values()):
        raise base.LabControlError("The native source secret inventory is incomplete.")
    profile(inventory / "source-profile")
    private_acl(run, "Verify")
    reused = cached.cached_wheels(ROOT, wheel_cache_run, directory / "wheels")
    footprint = cached.wheel_expansion(directory / "wheels")
    source = source_manifest(ROOT)
    snapshot = cached.snapshot_source(ROOT, directory / "source", source)
    (directory / "empty.env").write_bytes(b"")
    docker_config = private_docker_config(directory, docker)
    environment.update(
        SB_SOURCE_RUN=run,
        SB_SOURCE_RUN_DIR=str(directory),
        SB_SOURCE_DB_IMAGE=images["database"],
        SB_SOURCE_PYTHON_IMAGE=images["runner"],
        DOCKER_CONFIG=str(docker_config),
    )
    private_acl(run, "Verify")
    return (
        source,
        snapshot,
        environment,
        {"certificates": certificate, "cached_wheels": reused, "wheel_footprint": footprint},
    )


def compose_command(docker, run, directory, *, profile="access"):
    recipes = {
        "access": "compose.reference.yaml",
        "header": "compose.header.yaml",
        "reliability": "compose.reliability.yaml",
    }
    if profile not in recipes:
        raise base.LabControlError("Unknown source recipe profile.")
    recipe = recipes[profile]
    return base.docker_command(
        docker,
        [
            "compose",
            "--project-name",
            PREFIX + run,
            "--env-file",
            str(directory / "empty.env"),
            "--file",
            str(directory / "source/integrations/enterprise" / recipe),
        ],
    )


def require_guard(guard, run, directory):
    if guard.poll() is not None or (directory / "watchdog-abort.json").exists():
        raise base.LabControlError("The independent source guard exited or requested abort.")
    if not host.same(
        host.read_json(directory / "watchdog-ready.json"), {"run_id": run, "armed": True}
    ):
        raise base.LabControlError("The independent source guard is not armed for this run.")


def no_foreign_running(docker, targets=()):
    raw = base.docker_result(docker, ["ps", "--quiet", "--no-trunc"], timeout=5)
    identifiers = raw.splitlines() if raw else []
    if (
        len(identifiers) > 2
        or len(identifiers) != len(set(identifiers))
        or any(not re.fullmatch(r"[a-f0-9]{64}", identifier) for identifier in identifiers)
        or not set(identifiers).issubset(targets)
    ):
        raise base.LabControlError("Other running containers require a revised launch review.")


def arm_guard(docker, run, directory, *, reliability=False):
    seconds = host.RELIABILITY_SECONDS if reliability else base.MAX_RUNTIME_SECONDS
    deadline = time.time() + seconds
    flags = (
        (subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
        if os.name == "nt"
        else 0
    )
    guard = subprocess.Popen(
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
            str(deadline),
            *(["--reliability"] if reliability else []),
        ],
        cwd=ROOT,
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )
    return guard


def exact_components(docker, run, directory, images, *, profile="access"):
    if profile not in ("access", "header"):
        raise base.LabControlError("Unknown exact component profile.")
    targets = host.owned(docker, run)
    if sorted(targets.values()) != ["database", "runner"]:
        raise base.LabControlError("The exact source component pair was not verified.")
    for identifier in targets:
        host.verify_runtime(
            docker,
            identifier,
            run,
            directory,
            images,
            **({"profile": "header"} if profile == "header" else {}),
        )
    host.verify_network_volume(docker, run, targets)
    return targets


def execute(docker, run, directory, images, environment, guard, *, profile="access"):
    """Create without startup, verify effective isolation, then start exact IDs."""
    if profile not in ("access", "header"):
        raise base.LabControlError("Unknown native source launch profile.")
    variant = {"profile": "header"} if profile == "header" else {}
    command = compose_command(docker, run, directory, **variant)
    require_guard(guard, run, directory)
    raw = invoke([*command, "config", "--format", "json"], environment, 20)
    from bridge.contract import parse_json

    verify_compose_config(parse_json(raw), images, run, directory, **variant)
    check_capacity()
    if host.owned(docker, run):
        raise base.LabControlError("A source run identity cannot be reused.")
    for kind, name in (("network", host.NETWORK_PREFIX + run), ("volume", PREFIX + run)):
        names = base.docker_result(docker, [kind, "ls", "--format", "{{.Name}}"], timeout=5)
        if name in names.splitlines():
            raise base.LabControlError("Source network or volume identity already exists.")
    require_guard(guard, run, directory)
    no_foreign_running(docker)
    invoke([*command, "create", "--no-build", "--pull", "never", "--no-recreate"], environment, 60)
    targets = exact_components(docker, run, directory, images, **variant)
    for identifier in targets:
        if (
            base.docker_result(
                docker, ["inspect", identifier, "--format", "{{.State.Status}}"], timeout=5
            )
            != "created"
        ):
            raise base.LabControlError("Source creation unexpectedly started a component.")
    private_acl(run, "Verify")
    ids = {component: identifier for identifier, component in targets.items()}
    require_guard(guard, run, directory)
    check_capacity()
    base.docker_result(docker, ["start", ids["database"]], timeout=20)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        require_guard(guard, run, directory)
        health = base.docker_result(
            docker,
            ["inspect", ids["database"], "--format", "{{.State.Status}}|{{.State.Health.Status}}"],
            timeout=5,
        )
        if health == "running|healthy":
            break
        if health not in ("running|starting", "created|starting"):
            raise base.LabControlError("Source database initialization did not become healthy.")
        time.sleep(0.5)
    else:
        raise base.LabControlError("Source database readiness deadline exceeded.")
    exact_components(docker, run, directory, images, **variant)
    no_foreign_running(docker, targets)
    check_capacity()
    require_guard(guard, run, directory)
    base.docker_result(docker, ["start", ids["runner"]], timeout=20)
    exact_components(docker, run, directory, images, **variant)
    require_guard(guard, run, directory)
    gate = directory / "evidence/allow-source.json"
    with gate.with_suffix(".tmp").open("x", encoding="ascii") as stream:
        stream.write(json.dumps({"run_id": run, "runtime_verified": True}) + "\n")
    if gate.exists() or gate.is_symlink():
        raise base.LabControlError("Native source execution gate was already used.")
    gate.with_suffix(".tmp").replace(gate)
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        require_guard(guard, run, directory)
        no_foreign_running(docker, targets)
        state = base.docker_result(
            docker,
            ["inspect", ids["runner"], "--format", "{{.State.Status}}|{{.State.ExitCode}}"],
            timeout=5,
        )
        if state == "exited|0":
            exact_components(docker, run, directory, images, **variant)
            return {
                "parsed_configuration_verified": True,
                "runtime_isolation_verified": True,
                "runner_exit_code": 0,
            }
        if not state.startswith("running|"):
            raise base.LabControlError("Native source runner failed or stopped incompletely.")
        time.sleep(0.5)
    raise base.LabControlError("Native source execution deadline exceeded.")


def launch(docker, approval_reference, wheel_cache_run, certificate_python, *, profile="access"):
    if profile not in ("access", "header"):
        raise base.LabControlError("Unknown source launch profile.")
    variant = {"profile": "header"} if profile == "header" else {}
    if sys.platform != "win32" or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", approval_reference):
        raise base.LabControlError("A separately reviewed Windows source launch is required.")
    base.validate_identity(wheel_cache_run)
    if not Path(docker).is_absolute() or not Path(docker).is_file() or Path(docker).is_symlink():
        raise base.LabControlError("The reviewed existing Docker executable is required.")
    capacity = check_capacity()
    no_foreign_running(docker)
    images = {
        "database": base.inspect_local_image(docker),
        "runner": cached.inspect_python_image(docker),
    }
    certificate_runtime(certificate_python)
    invoke([sys.executable, "-B", "scripts/check_publication.py"], clean_environment(), 60)
    run = uuid.uuid4().hex
    directory = base.private_run_directory(ROOT, run)
    directory.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc)
    receipt = {
        "schema_version": 1,
        "kind": "signalbridge-native-reference-access"
        if profile == "access"
        else "signalbridge-native-authenticated-header-capture",
        "run_id": run,
        "approval_reference": approval_reference,
        "status": "incomplete",
        "acceptance_passed": False,
        "started_at": started.isoformat(),
        "capacity_before": capacity,
        "images": images,
        "stage_initial_free_disk_bytes": host.INITIAL_DISK,
        "stage_growth_ceiling_bytes": host.GROWTH,
        "limits": [
            "Fixed two-application synthetic source proof; not SSO, security-tool, restoration or 24-hour acceptance.",
            "Source/console processes share one uid; database roles are not independent OS security boundaries.",
            "Hashes identify recorded bytes; local administrator tampering is outside this evidence boundary.",
            "Capacity readings are detection guards, not hard quotas. No images, volumes or other projects are removed.",
        ],
    }
    guard, source = None, None
    try:
        source, snapshot, environment, preparation = prepare(
            run, directory, images, certificate_python, wheel_cache_run, docker
        )
        receipt.update(
            preparation=preparation, source_sha256=source["sha256"], source_snapshot=snapshot
        )
        guard = arm_guard(docker, run, directory)
        for _ in range(20):
            if guard.poll() is not None:
                raise base.LabControlError("Source watchdog exited before arming.")
            if (directory / "watchdog-ready.json").exists():
                require_guard(guard, run, directory)
                break
            time.sleep(0.25)
        else:
            raise base.LabControlError("Source watchdog readiness expired.")
        receipt.update(execute(docker, run, directory, images, environment, guard, **variant))
        receipt["native_proof"] = validate_native(
            ROOT,
            run,
            source,
            preparation["wheel_footprint"],
            now=datetime.now(timezone.utc),
            **variant,
        )
        receipt["status"] = "passed_execution_pending_shutdown"
    except Exception as error:
        receipt["error_class"] = type(error).__name__
        # Fixed control codes may be public. Arbitrary runtime exceptions may
        # contain credentials and are represented only by their class.
        if isinstance(error, base.LabControlError):
            receipt["error_code"] = str(error)
    finally:
        main = {"run_id": run, "shutdown_verified": False}
        try:
            main["stopped_component_count"] = host.stop_scope(docker, run)
            main["shutdown_verified"] = True
        except Exception as error:
            main["shutdown_error_class"] = type(error).__name__
        receipt["main_shutdown"] = main
        if guard is not None:
            try:
                host.write_control(ROOT, run, "launcher-finished.json", {"run_id": run})
                guard.wait(timeout=55)
                independent = host.read_json(directory / "watchdog.json")
                receipt["independent_shutdown"] = independent
                receipt.update(
                    validate_shutdown(
                        main, independent, run, started=started, finished=datetime.now(timezone.utc)
                    )
                )
            except Exception as error:
                # Keep a live guard running; never terminate the safety process.
                receipt["independent_shutdown_error_class"] = type(error).__name__
                receipt["watchdog_pending"] = guard.poll() is None
        receipt.update(
            finished_at=datetime.now(timezone.utc).isoformat(),
            free_disk_after_bytes=shutil.disk_usage(ROOT).free,
        )
        try:
            receipt["source_unchanged"] = source is not None and host.same(
                source, source_manifest(ROOT)
            )
        except Exception:
            receipt["source_unchanged"] = False
        receipt["acceptance_passed"] = bool(
            receipt["status"] == "passed_execution_pending_shutdown"
            and receipt.get("source_unchanged")
            and receipt.get("main_shutdown_verified")
            and receipt.get("independent_shutdown_verified")
        )
        receipt["status"] = "passed" if receipt["acceptance_passed"] else "incomplete"
        raw = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("ascii")
        with (directory / "receipt.json").open("xb") as stream:
            stream.write(raw)
        public_id = (
            started.strftime("%Y%m%d")
            + ("-reference-access-" if profile == "access" else "-reference-header-")
            + run
        )
        public = receipt_path(ROOT, "docs/evidence/" + public_id + ".json", public_id)
        with public.open("xb") as stream:
            stream.write(raw)
    return directory, receipt["acceptance_passed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("launch")
    start.add_argument("--docker", type=Path, required=True)
    start.add_argument("--approval-reference", required=True)
    start.add_argument("--wheel-cache-run", required=True)
    start.add_argument("--certificate-python", type=Path, required=True)
    start.add_argument("--profile", choices=("access", "header"), default="access")
    guard = commands.add_parser("watchdog")
    guard.add_argument("--docker", type=Path, required=True)
    guard.add_argument("--run", required=True)
    guard.add_argument("--deadline", type=float, required=True)
    guard.add_argument("--reliability", action="store_true")
    options = parser.parse_args()
    if options.command == "watchdog":
        result = host.watchdog(
            options.docker,
            options.run,
            ROOT,
            options.deadline,
            available_memory,
            maximum=host.RELIABILITY_SECONDS if options.reliability else None,
        )
        return 0 if result["shutdown_verified"] else 1
    directory, passed = launch(
        options.docker,
        options.approval_reference,
        options.wheel_cache_run,
        options.certificate_python,
        **({"profile": "header"} if options.profile == "header" else {}),
    )
    print("Source proof receipt retained: " + str(directory))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
