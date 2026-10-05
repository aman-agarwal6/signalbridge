"""Finite cached-only native Keycloak host command; separately reviewed launch only.

Approval references record authorization, never grant it. This never
starts Docker Desktop, downloads, installs host packages, alters host trust,
publishes ports, removes retained resources or operates another project's lab.
"""

import argparse
import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# ruff: noqa: E402

from integrations.enterprise import verification as base
from integrations.enterprise.network_verification import snapshot_source
from integrations.enterprise.reference_host_controls import (
    INITIAL_DISK,
    read_json,
    same,
    write_control,
)
from integrations.enterprise.reference_host_evidence import safe_path
from integrations.enterprise.windows_capacity import available_memory
from integrations.identity import native_host as host
from integrations.identity.native_profile import material
from scripts.enterprise_reference_verify import (
    certificate_runtime,
    clean_environment,
    invoke,
    private_acl,
    require_guard,
)
from scripts.enterprise_zap_verify import verified_source
from scripts.record_verification import source_manifest

SECONDS, GROWTH = 1800, 4 * 1024**3
MILESTONE_GROWTH, DRAIN_SECONDS = 30 * 1024**3, 60
RESOURCE_COMMIT_SECONDS = 90
CONTROLS = {
    "callback_wrong_state_rejected",
    "callback_replay_rejected",
    "malformed_logout_token_rejected",
    "viewer_note_write_denied",
    "csrf_missing_write_denied",
    "analyst_note_write_persisted",
    "analyst_reviewer_action_denied",
    "analyst_cross_app_write_denied",
    "viewer_cross_app_write_denied",
    "reviewer_cross_app_write_denied",
    "wrong_password_rejected",
    "provider_disabled_login_rejected",
    "password_alone_not_admitted",
    "wrong_totp_rejected",
    "expiry_native_mfa_login",
    "analyst_native_mfa_login",
    "viewer_native_mfa_login",
    "reviewer_native_mfa_login",
    "local_disabled_local_admission_denied",
    "unmapped_local_admission_denied",
    "analyst_application_boundary",
    "viewer_application_boundary",
    "reviewer_application_boundary",
    "permission_withdrawal_immediate",
    "native_backchannel_logout_revoked_session",
    "provider_signing_key_rotation_admitted",
    "http_cookie_and_header_policy",
    "real_session_expiry_denied",
}
BROWSER_CONTROLS = (
    "browser_keyboard_mfa_login",
    "browser_cookie_attributes_enforced",
    "browser_csp_blocks_inline_script",
    "browser_framing_blocked",
    "browser_logout_ends_session",
)
BROWSER_LOCK = "integrations/identity/browser-requirements.lock"
BROWSER_CACHE = "var/enterprise/browser-wheels"


def write(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")
    host.require(len(raw) <= 262144 and not path.exists() and not path.is_symlink())
    with path.open("xb") as stream:
        stream.write(raw)


def capacity(baseline=None, before_launch=False):
    disk, memory = shutil.disk_usage(ROOT).free, available_memory()
    host.require(disk >= 25 * base.GIB and memory >= (7 if before_launch else 4) * base.GIB)
    host.require(INITIAL_DISK - disk < MILESTONE_GROWTH)
    if baseline is not None:
        host.require(type(baseline) is int and baseline > 0 and baseline - disk < GROWTH)
        if before_launch:
            host.require(disk >= 25 * base.GIB + GROWTH - max(0, baseline - disk))
    return {"free_disk_bytes": disk, "available_memory_bytes": memory}


def publication_preflight(directory=None):
    """Inspect only this run's credentials; never collect another lab's secrets."""
    from scripts.check_publication import (
        collect_identity_credentials,
        publication_files,
        scan_publishable,
    )

    known = set()
    files = publication_files(ROOT)
    try:
        if directory is not None:
            collect_identity_credentials(list((directory / "secrets").iterdir()), ROOT, known)
        host.require(not scan_publishable(ROOT, files, known))
    finally:
        known.clear()


def wheel_inputs(directory=None):
    """Check every exact cached input before preparing or starting the native lab."""
    rows = read_json(ROOT / "integrations/identity/linux-wheels.json", 65536)["wheels"]
    host.require(type(rows) is list and len(rows) == 16)
    seen, expanded, checked = set(), 0, []
    for row in rows:
        filename = row["filename"]
        host.require(isinstance(filename, str) and re.fullmatch(r"[A-Za-z0-9_.-]+\.whl", filename))
        host.require(filename not in seen)
        seen.add(filename)
        relative = row.get(
            "cache_relative_path", "var/enterprise/identity/native-wheel-cache/" + filename
        )
        path = safe_path(ROOT / relative, ROOT)
        host.require(
            path.is_file() and path.name == filename and path.stat().st_size == row["size"]
        )
        raw = path.read_bytes()
        host.require(hashlib.sha256(raw).hexdigest() == row["sha256"])
        with zipfile.ZipFile(path) as archive:
            entries, names = archive.infolist(), set()
            host.require(len(entries) <= 15000)
            for entry in entries:
                part = PurePosixPath(entry.filename)
                host.require(
                    not part.is_absolute()
                    and ".." not in part.parts
                    and "\\" not in entry.filename
                    and ":" not in entry.filename
                )
                host.require(
                    not stat.S_ISLNK(entry.external_attr >> 16) and not entry.flag_bits & 1
                )
                host.require(
                    part.suffix != ".pth"
                    and part.name not in {"sitecustomize.py", "usercustomize.py"}
                )
                host.require(entry.filename.casefold() not in names)
                names.add(entry.filename.casefold())
                expanded += entry.file_size
                host.require(expanded <= 100 * 1024**2)
        checked.append({"filename": filename, "sha256": row["sha256"], "size": len(raw)})
        if directory is not None:
            with (directory / filename).open("xb") as stream:
                stream.write(raw)
    return {"files": checked, "expanded_bytes": expanded, "downloads": False}


def browser_wheel_inputs(directory=None):
    """The real-browser client: exactly the four PyPI wheels pinned in the lock."""
    pins = {}
    for line in (ROOT / BROWSER_LOCK).read_text(encoding="ascii").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([0-9.]+) --hash=sha256:([0-9a-f]{64})", line)
        host.require(match is not None and match[1] not in pins)
        pins[match[1]] = match[3]
    host.require(len(pins) == 4 and len(set(pins.values())) == 4)
    cache = safe_path(ROOT / BROWSER_CACHE, ROOT)
    files = sorted(cache.glob("*.whl"))
    host.require(len(files) == 4)
    expected, checked = set(pins.values()), []
    for path in files:
        host.require(
            path.is_file() and not path.is_symlink() and path.stat().st_size <= 64 * 1024**2
        )
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        host.require(digest in expected)
        expected.discard(digest)
        checked.append({"filename": path.name, "sha256": digest, "size": len(raw)})
        if directory is not None:
            with (directory / path.name).open("xb") as stream:
                stream.write(raw)
    host.require(not expected)
    return {"files": checked, "downloads": False}


def browser_receipt(directory, run, recorded):
    """Closed browser result, bound to the digest the runner recorded."""
    path = safe_path(directory / "evidence/identity-browser.json", directory)
    raw = path.read_bytes()
    host.require(len(raw) <= 65536)
    host.require(
        type(recorded) is dict
        and recorded.get("passed") is True
        and recorded.get("sha256") == hashlib.sha256(raw).hexdigest()
    )
    value = json.loads(raw)
    host.require(
        value.get("run_id") == run
        and value.get("passed") is True
        and value.get("browser_engine") == "chromium"
        and isinstance(value.get("browser_version"), str)
    )
    rows = value.get("controls")
    host.require(
        type(rows) is list
        and [row.get("control") for row in rows] == list(BROWSER_CONTROLS)
        and all(row.get("passed") is True for row in rows)
    )
    login, cookies = rows[0], rows[1]
    host.require(
        login.get("keyboard_activation") is True
        and login.get("typed_credentials") is True
        and login.get("tls_verified_by_spki_pin") is True
        and login.get("factors") == ["password", "totp"]
    )
    host.require(
        cookies.get("cookies", {}).get("session")
        == {"secure": True, "http_only": True, "same_site": "None"}
        and cookies["cookies"].get("csrf", {}).get("same_site") == "Strict"
        and cookies.get("session_hidden_from_script") is True
    )
    return value


def prepare(run, directory, manifest, certificate_python):
    for name in ("secrets", "evidence", "state", "wheels", "browser-wheels"):
        (directory / name).mkdir(exist_ok=False)
    snapshot = snapshot_source(ROOT, directory / "source", manifest)
    # The writable state bind targets /workspace/var inside the read-only source
    # bind; Docker cannot create that mountpoint at start, so provide it empty.
    (directory / "source" / "var").mkdir(exist_ok=False)
    wheels = wheel_inputs(directory / "wheels")
    browser_wheels = browser_wheel_inputs(directory / "browser-wheels")
    realm = read_json(directory / "source/integrations/identity/realm.json", 65536)
    prepared, profile = material(realm, run)
    write(directory / "secrets/identity-profile.json", profile)
    write(directory / "secrets/signalbridge-realm.json", prepared)
    for name, field in (
        ("bootstrap-password", "bootstrap_database_password"),
        ("console-password", "database_password"),
        ("keycloak-password", "keycloak_database_password"),
    ):
        with (directory / "secrets" / name).open("xb") as stream:
            stream.write(profile[field].encode("ascii"))
    plan = read_json(directory / "source/integrations/identity/native-stage-plan.json", 32768)
    config = dict(plan["required_keycloak_config"])
    config.update(
        {
            "db-password": profile["keycloak_database_password"],
            "bootstrap-admin-username": profile["operator_username"],
            "bootstrap-admin-password": profile["operator_password"],
        }
    )
    host.require(
        all(
            isinstance(value, str) and not any(c in value for c in "\r\n\x00")
            for value in config.values()
        )
    )
    with (directory / "secrets/keycloak.conf").open("xb") as stream:
        stream.write(
            "".join(key + "=" + value + "\n" for key, value in sorted(config.items())).encode(
                "ascii"
            )
        )
    private_acl(run, "Verify")
    certificate_runtime(certificate_python)
    raw = invoke(
        [
            certificate_python,
            "-B",
            "-m",
            "integrations.identity.native_certificates",
            "--workspace",
            ROOT,
            "--run",
            run,
        ],
        clean_environment(),
        30,
        16384,
    )
    certificates = json.loads(raw)
    host.require(
        certificates.get("run_id") == run
        and certificates.get("host_trust_changed") is False
        and certificates.get("ca_private_key_persisted") is False
    )
    host.require(
        certificates.get("server_addresses") == {"console": "127.0.0.1", "provider": "127.0.0.2"}
    )
    created, expiry = (
        datetime.fromisoformat(certificates[name]) for name in ("created_at", "expires_at")
    )
    host.require(
        0 <= (datetime.now(timezone.utc) - created).total_seconds() <= 60
        and (expiry - created).total_seconds() == 7200
    )
    expected = {"lab-ca.pem", "provider-certificate.pem", "console-certificate.pem"}
    host.require(set(certificates["public_file_sha256"]) == expected)
    for name, digest in certificates["public_file_sha256"].items():
        path = safe_path(directory / "secrets" / name, directory)
        host.require(
            path.stat().st_size <= 4096 and hashlib.sha256(path.read_bytes()).hexdigest() == digest
        )
    private_acl(run, "Verify")
    host.require(same(manifest, source_manifest(ROOT)))
    publication_preflight(directory)
    return {
        "source_snapshot": snapshot,
        "wheels": wheels,
        "browser_wheels": browser_wheels,
        "certificates": certificates,
    }


def state(docker, run, identifier):
    raw = host.request(
        docker,
        run,
        ROOT,
        [
            "inspect",
            identifier,
            "--format",
            '{"status":{{json .State.Status}},"exit_code":{{json .State.ExitCode}}}',
        ],
    )
    host.require(len(raw) <= 1024)
    return json.loads(raw)


def resource_binding(directory, run, expected=None, *, allow_precommit=False):
    path = directory / "identity-resource-binding.json"
    if not path.exists() and not path.is_symlink():
        host.require(allow_precommit and expected is None)
        return None
    safe_path(path, directory)
    value = read_json(path, 4096)
    host.require(type(value) is dict and set(value) == {"run_id", "resources"})
    host.require(value["run_id"] == run)
    binding = host.validate_resource_binding(value["resources"], run)
    host.require(expected is None or same(binding, expected))
    return binding


def runtime(docker, run, images, expected=None, *, binding=None, allow_precommit=False):
    targets = host.owned(docker, run, ROOT)
    host.require(expected is None or same(targets, expected))
    host.no_foreign_running(docker, run, ROOT, targets)
    bound = resource_binding(
        base.private_run_directory(ROOT, run), run, binding, allow_precommit=allow_precommit
    )
    if bound is None:
        # The independent guard is armed before resource creation. No workload
        # is admitted until both fresh resources have an atomic identity commit.
        host.require(not targets)
        return targets
    host.resources(docker, run, ROOT, targets, binding=bound)
    host.verify_runtime(docker, run, ROOT, images, targets, binding=bound)
    return targets


def runtime_snapshot(docker, run, directory, images, targets, phase, *, binding=None):
    host.require(phase in {"created", "running"})
    binding = resource_binding(directory, run, binding)
    value = {"run_id": run, "phase": phase, "components": {}, "resources": {}}
    host.resources(docker, run, ROOT, targets, capture=value["resources"], binding=binding)
    host.verify_runtime(
        docker, run, ROOT, images, targets, capture=value["components"], binding=binding
    )
    path = directory / "evidence" / ("identity-runtime-" + phase + ".json")
    write(path, value)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_resources(docker, run):
    # Fresh random identities, never adoption of an existing network or volume.
    directory = base.private_run_directory(ROOT, run)
    committed = directory / "identity-resource-binding.json"
    temporary = committed.with_suffix(".tmp")
    host.require(not committed.exists() and not committed.is_symlink())
    host.require(not temporary.exists() and not temporary.is_symlink())
    started, created = time.time(), {}
    for kind, name in (("network", host.NETWORK + run), ("volume", host.PREFIX + run)):
        existing = host.request(
            docker, run, ROOT, [kind, "ls", "--filter", "name=" + name, "--format", "{{.Name}}"]
        )
        host.require(not existing)
        arguments = [kind, "create"]
        if kind == "network":
            arguments += ["--internal", "--driver", "bridge"]
        for key, value in host.labels(run).items():
            arguments += ["--label", key + "=" + value]
        created[kind] = host.request(docker, run, ROOT, [*arguments, name], timeout=15)
    binding = host.resources(docker, run, ROOT, {})
    host.require(created["network"] == binding["network"]["id"])
    host.require(created["volume"] == binding["volume"]["name"])
    finished = time.time()
    host.require(0 <= finished - started < RESOURCE_COMMIT_SECONDS)
    host.require(
        all(
            started - 5 <= host.resource_time(row["created"]) <= finished + 5
            for row in binding.values()
        )
    )
    write(temporary, {"run_id": run, "resources": binding})
    host.require(not committed.exists() and not committed.is_symlink())
    temporary.replace(committed)
    # Commit remains mandatory even when the initial container inventory is empty.
    resource_binding(directory, run, binding)
    return binding


def native_receipt(directory, run):
    kernel = read_json(directory / "evidence/identity-kernel.json", 196608)
    kernel_proof = host.verify_kernel(kernel)
    value = read_json(directory / "evidence/identity-native.json", 65536)
    host.require(
        value.get("run_id") == run
        and value.get("passed") is True
        and value.get("native_keycloak") is True
        and value.get("server_stopped") is True
        and value.get("phase") == "complete"
    )
    execution = value.get("execution", {})
    host.require(execution.get("passed") is True and execution.get("native_keycloak") is True)
    host.require(
        execution.get("case_evidence_source") == "synthetic_demo"
        and execution.get("remediation_verification_exercised") is False
    )
    host.require(
        all(
            execution.get(key) is False
            for key in ("browser_automation", "mocked_token_responses", "host_trust_changed")
        )
    )
    host.require(type(execution.get("requests")) is int and 0 < execution["requests"] <= 200)
    rows = execution.get("controls", [])
    host.require(
        type(rows) is list
        and len(rows) == len(CONTROLS)
        and {row.get("control") for row in rows} == CONTROLS
    )
    host.require(all(row.get("passed") is True for row in rows))
    expiry = next(row for row in rows if row["control"] == "real_session_expiry_denied")
    host.require(
        type(expiry.get("lifetime_seconds")) in (int, float)
        and 0 < expiry["lifetime_seconds"] <= 900
        and expiry.get("clock_or_database_time_changed") is False
    )
    rotation = next(r for r in rows if r["control"] == "provider_signing_key_rotation_admitted")
    host.require(
        rotation.get("provider_component_status") == 201
        and all(
            rotation.get(key) is True
            for key in (
                "new_signing_key_active",
                "new_key_absent_from_startup_jwks",
                "bounded_jwks_refresh_required",
            )
        )
    )
    policy = next(r for r in rows if r["control"] == "http_cookie_and_header_policy")
    host.require(
        policy.get("session_cookie") == {"secure": True, "http_only": True, "same_site": "None"}
        and isinstance(policy.get("csrf_cookie"), dict)
        and policy["csrf_cookie"].get("secure") is True
        and policy["csrf_cookie"].get("same_site") == "Strict"
        and policy.get("browser_engine") is False
    )
    return {**value, "runner_kernel": kernel_proof}


def arm_guard(docker, run, deadline):
    # DETACHED_PROCESS ensures shutdown survives the initiating console closing.
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
            str(deadline),
        ],
        cwd=ROOT,
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        shell=False,
    )


def execute(docker, run, directory, images, guard, baseline):
    require_guard(guard, run, directory)
    host.require(not host.owned(docker, run, ROOT))
    host.no_foreign_running(docker, run, ROOT)
    binding = create_resources(docker, run)
    targets, identifiers = {}, {}
    for component in ("database", "keycloak", "runner"):
        require_guard(guard, run, directory)
        capacity(baseline, before_launch=True)
        identifier = host.request(
            docker,
            run,
            ROOT,
            host.create_arguments(
                component, images[component], run, directory, identifiers.get("keycloak")
            ),
            timeout=30,
        )
        host.require(re.fullmatch(r"[a-f0-9]{64}", identifier))
        targets[identifier], identifiers[component] = component, identifier
        runtime(docker, run, images, targets, binding=binding)
        host.require(state(docker, run, identifier)["status"] == "created")
    snapshots = {
        "created_sha256": runtime_snapshot(
            docker, run, directory, images, targets, "created", binding=binding
        )
    }
    private_acl(run, "Verify")
    for component in ("database", "keycloak", "runner"):
        require_guard(guard, run, directory)
        capacity(baseline)
        runtime(docker, run, images, targets, binding=binding)
        host.request(docker, run, ROOT, ["start", identifiers[component]], timeout=20)
        if component == "database":
            deadline, ready = time.monotonic() + 90, False
            while time.monotonic() < deadline:
                require_guard(guard, run, directory)
                capacity(baseline)
                try:
                    host.request(
                        docker,
                        run,
                        ROOT,
                        [
                            "exec",
                            identifiers[component],
                            "pg_isready",
                            "-h",
                            "127.0.0.1",
                            "-U",
                            "postgres",
                            "-d",
                            "postgres",
                        ],
                        timeout=5,
                    )
                    ready = True
                    break
                except base.LabControlError:
                    host.require(state(docker, run, identifiers[component])["status"] == "running")
                    time.sleep(1)
            host.require(ready)
    # Runner startup waits at its own finite gate. Check its actual kernel state
    # before permitting dependency installation or any native identity traffic.
    require_guard(guard, run, directory)
    snapshots["running_sha256"] = runtime_snapshot(
        docker, run, directory, images, targets, "running", binding=binding
    )
    kernel, _ = host.inspect_kernel(docker, run, ROOT, identifiers["runner"])
    write(directory / "evidence/identity-kernel.json", kernel)
    snapshots["runner_kernel_sha256"] = hashlib.sha256(
        (directory / "evidence/identity-kernel.json").read_bytes()
    ).hexdigest()
    require_guard(guard, run, directory)
    gate = directory / "evidence/allow-identity.json"
    host.require(not (directory / "evidence/identity-abort.json").exists())
    write(gate.with_suffix(".tmp"), {"run_id": run, "runtime_verified": True})
    gate.with_suffix(".tmp").replace(gate)
    ready = directory / "evidence/identity-browser-ready.json"
    deadline = time.monotonic() + 1560
    while time.monotonic() < deadline:
        require_guard(guard, run, directory)
        capacity(baseline)
        runtime(docker, run, images, targets, binding=binding)
        if "browser" not in identifiers and ready.exists():
            # Start the pinned browser only after the protocol controls finished.
            host.require(
                same(read_json(ready), {"run_id": run, "ready": True, "account": "reviewer"})
            )
            identifier = host.request(
                docker,
                run,
                ROOT,
                host.create_arguments(
                    "browser", images["browser"], run, directory, identifiers["keycloak"]
                ),
                timeout=30,
            )
            host.require(re.fullmatch(r"[a-f0-9]{64}", identifier))
            targets[identifier], identifiers["browser"] = "browser", identifier
            runtime(docker, run, images, targets, binding=binding)
            host.require(state(docker, run, identifier)["status"] == "created")
            private_acl(run, "Verify")
            host.request(docker, run, ROOT, ["start", identifier], timeout=20)
        if "browser" in identifiers:
            browser = state(docker, run, identifiers["browser"])
            host.require(
                browser["status"] == "running"
                or browser["status"] == "exited"
                and browser["exit_code"] == 0
            )
        current = state(docker, run, identifiers["runner"])
        if current["status"] == "exited":
            host.require(current["exit_code"] == 0 and "browser" in identifiers)
            private_acl(run, "Verify")
            value = native_receipt(directory, run)
            value["browser_result"] = browser_receipt(directory, run, value.get("browser"))
            return {**value, "retained_runtime": snapshots}
        host.require(current["status"] == "running")
        host.require(
            all(
                state(docker, run, identifiers[key])["status"] == "running"
                for key in ("database", "keycloak")
            )
        )
        time.sleep(2)
    raise base.LabControlError("The finite native identity execution deadline expired.")


def revoke_gate(directory, run):
    """Invalidate a late runner before every bounded stop attempt."""
    evidence = directory / "evidence"
    if not evidence.exists():
        return
    safe_path(evidence, directory)
    marker = evidence / "identity-abort.json"
    if not marker.exists():
        temporary = marker.with_suffix(".tmp")
        write(temporary, {"run_id": run, "abort": True})
        temporary.replace(marker)
    else:
        host.require(same(read_json(marker), {"run_id": run, "abort": True}))
    gate = evidence / "allow-identity.json"
    if gate.exists() or gate.is_symlink():
        safe_path(gate, directory)
        host.require(same(read_json(gate), {"run_id": run, "runtime_verified": True}))
        gate.unlink()


def watchdog(docker, run, deadline):
    directory = base.private_run_directory(ROOT, run)
    receipt = {
        "run_id": run,
        "shutdown_verified": False,
        "reason": "deadline",
        "drain_completed": False,
    }
    stop_at, acknowledged_at, context = time.monotonic(), None, None
    failed, bound = False, None
    resource_deadline = time.monotonic() + RESOURCE_COMMIT_SECONDS
    try:
        host.require(type(deadline) in (int, float) and 0 < deadline - time.time() <= SECONDS)
        stop_at = time.monotonic() + (deadline - time.time())
        try:
            # All setup failures still enter scoped stop/recheck. The absolute
            # deadline is passed separately, so corrupt context cannot extend it.
            private_acl(run, "Verify")
            context = read_json(directory / "identity-host-context.json", 65536)
            host.require(context.get("run_id") == run and context.get("deadline") == deadline)
            write_control(ROOT, run, "watchdog-ready.json", {"run_id": run, "armed": True})
        except Exception as error:
            failed = True
            receipt.update(reason="guard_failure", error_class=type(error).__name__)
        while time.time() < deadline and time.monotonic() < stop_at:
            try:
                if (directory / "launcher-finished.json").exists():
                    host.require(
                        same(read_json(directory / "launcher-finished.json"), {"run_id": run})
                    )
                    if acknowledged_at is None:
                        acknowledged_at = time.monotonic()
                    if not failed:
                        receipt["reason"] = "launcher_finished"
                if failed or acknowledged_at is not None:
                    revoke_gate(directory, run)
                    if failed and not (directory / "watchdog-abort.json").exists():
                        write_control(
                            ROOT,
                            run,
                            "watchdog-abort.json",
                            {"run_id": run, "reason": "guard_failure"},
                        )
                    host.stop_scope(docker, run, ROOT)
                    if (
                        acknowledged_at is not None
                        and time.monotonic() - acknowledged_at >= DRAIN_SECONDS
                    ):
                        receipt["drain_completed"] = True
                        break
                else:
                    capacity(context["baseline_free_disk"])
                    bound = resource_binding(directory, run, bound, allow_precommit=True)
                    host.require(bound is not None or time.monotonic() < resource_deadline)
                    runtime(
                        docker, run, context["images"], binding=bound, allow_precommit=bound is None
                    )
            except Exception as error:
                failed = True
                receipt.update(reason="guard_failure", error_class=type(error).__name__)
                # Try scope shutdown even if marker IO or inspection failed.
                try:
                    revoke_gate(directory, run)
                except Exception as marker_error:
                    receipt["abort_marker_error_class"] = type(marker_error).__name__
                try:
                    host.stop_scope(docker, run, ROOT)
                except Exception as stop_error:
                    receipt["last_shutdown_error_class"] = type(stop_error).__name__
            time.sleep(min(1, max(0, stop_at - time.monotonic())))
    except Exception as error:
        receipt.update(reason="guard_failure", error_class=type(error).__name__)
    finally:
        try:
            revoke_gate(directory, run)
        except Exception as error:
            receipt["abort_marker_error_class"] = type(error).__name__
        try:
            receipt["stopped_components"] = host.stop_scope(docker, run, ROOT)
            # One empty inventory is not proof a timed-out daemon request settled.
            receipt["shutdown_verified"] = receipt["drain_completed"]
        except Exception as error:
            receipt["shutdown_error_class"] = type(error).__name__
        receipt["stopped_at"] = datetime.now(timezone.utc).isoformat()
        receipt["deadline_exhausted"] = not receipt["drain_completed"]
        write_control(ROOT, run, "watchdog.json", receipt)
    return receipt


def launch(docker, certificate_python, approval_reference, stage_initial_free_disk_bytes):
    host.require(
        sys.platform == "win32" and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", approval_reference)
    )
    host.require(docker.is_absolute() and docker.is_file() and not docker.is_symlink())
    manifest = verified_source()
    initial = capacity(stage_initial_free_disk_bytes, before_launch=True)
    host.require(
        type(stage_initial_free_disk_bytes) is int
        and stage_initial_free_disk_bytes >= initial["free_disk_bytes"]
    )
    publication_preflight()
    wheel_inputs()  # Cache failure precedes native create/start and credential generation.
    browser_wheel_inputs()
    certificate_runtime(certificate_python)
    run, started = uuid.uuid4().hex, datetime.now(timezone.utc)
    directory = base.private_run_directory(ROOT, run)
    directory.mkdir(parents=True, exist_ok=False)
    private_acl(run, "SecureEmpty")
    (directory / "docker-config").mkdir()
    write(directory / "docker-config/config.json", {})
    receipt = {
        "schema_version": 1,
        "kind": "signalbridge-native-keycloak-host",
        "run_id": run,
        "approval_reference": approval_reference,
        "started_at": started.isoformat(),
        "source_sha256": manifest["sha256"],
        "capacity_before": initial,
        "stage_growth_ceiling_bytes": GROWTH,
        "stage_initial_free_disk_bytes": stage_initial_free_disk_bytes,
        "milestone_initial_free_disk_bytes": INITIAL_DISK,
        "milestone_growth_ceiling_bytes": MILESTONE_GROWTH,
        "native_profile_passed": False,
        "entire_identity_gate_passed": False,
        "status": "incomplete",
        "phase": "image_preflight",
        "limits": [
            "A real headless Chromium walkthrough checks login, cookies, CSP, framing and keyboard paths; it is not a full accessibility (WCAG) audit.",
            "Selected native role-write and callback controls do not establish all browser/protocol attack defenses.",
            "PostgreSQL is plaintext inside the isolated component network.",
            "Private synthetic credentials and volumes are retained; no cleanup or download occurs.",
            "Host capacity readings are guards, not physical filesystem quotas.",
            "Disk guards measure whole-host free-space decreases, not attributable SignalBridge usage.",
            "Runner kernel controls are measured; database/Keycloak controls use Docker metadata.",
            "One launch only; no retry or previous stage authorization is implied.",
            "An unreachable daemon or exhausted drain period leaves shutdown unverified.",
        ],
    }
    guard = None
    try:
        host.no_foreign_running(docker, run, ROOT)
        images = host.inspect_images(docker, run, ROOT)
        receipt["images"] = {
            key: {"reference": host.IMAGES[key], "id": value["id"]} for key, value in images.items()
        }
        receipt["phase"] = "private_preparation"
        receipt["preparation"] = prepare(run, directory, manifest, certificate_python)
        deadline = time.time() + SECONDS
        write(
            directory / "identity-host-context.json",
            {
                "run_id": run,
                "baseline_free_disk": stage_initial_free_disk_bytes,
                "deadline": deadline,
                "images": images,
            },
        )
        guard = arm_guard(docker, run, deadline)
        for _ in range(160):
            host.require(guard.poll() is None)
            if (directory / "watchdog-ready.json").exists():
                require_guard(guard, run, directory)
                break
            time.sleep(0.25)
        else:
            raise base.LabControlError("Native identity watchdog readiness expired.")
        receipt["phase"] = "native_execution"
        receipt["native_receipt"] = execute(
            docker, run, directory, images, guard, stage_initial_free_disk_bytes
        )
        receipt["status"] = "passed_execution_pending_shutdown"
    except Exception as error:
        receipt["error_class"] = type(error).__name__
    finally:
        try:
            revoke_gate(directory, run)
        except Exception as error:
            receipt["main_abort_marker_error_class"] = type(error).__name__
        try:
            receipt["main_shutdown"] = {
                "run_id": run,
                "stopped_components": host.stop_scope(docker, run, ROOT),
                "shutdown_verified": True,
            }
        except Exception as error:
            receipt["main_shutdown"] = {
                "run_id": run,
                "shutdown_verified": False,
                "error_class": type(error).__name__,
            }
        if guard is not None:
            try:
                write_control(ROOT, run, "launcher-finished.json", {"run_id": run})
                guard.wait(timeout=90)
                receipt["independent_shutdown"] = read_json(directory / "watchdog.json")
            except Exception as error:
                receipt["independent_shutdown_error_class"] = type(error).__name__
        receipt["finished_at"] = datetime.now(timezone.utc).isoformat()
        try:
            receipt["source_unchanged"] = same(manifest, source_manifest(ROOT))
        except Exception:
            receipt["source_unchanged"] = False
        independent = receipt.get("independent_shutdown", {})
        passed = bool(
            receipt["status"] == "passed_execution_pending_shutdown"
            and receipt["source_unchanged"]
            and receipt["main_shutdown"]["shutdown_verified"]
            and independent.get("run_id") == run
            and independent.get("shutdown_verified") is True
            and independent.get("reason") == "launcher_finished"
            and independent.get("drain_completed") is True
            and set(receipt["main_shutdown"].get("stopped_components", [])) == set(host.ROLES)
            and set(independent.get("stopped_components", [])) == set(host.ROLES)
        )
        browser_passed = bool(
            passed and receipt.get("native_receipt", {}).get("browser_result", {}).get("passed")
        )
        receipt.update(
            native_profile_passed=passed,
            real_browser_passed=browser_passed,
            entire_identity_gate_passed=browser_passed,
            status="passed_native_profile" if passed else "incomplete",
        )
        # Public promotion is a separate reviewed evidence step; partial receipts
        # and source snapshots remain in this private run either way.
        write(directory / "receipt.json", receipt)
    return directory, passed


def main():
    host.require(
        sys.platform == "win32"
        and (ROOT / "manage.py").is_file()
        and ROOT.name == "signalbridge-public"
    )
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("launch")
    start.add_argument("--docker", type=Path, required=True)
    start.add_argument("--certificate-python", type=Path, required=True)
    start.add_argument("--approval-reference", required=True)
    start.add_argument("--stage-initial-free-disk-bytes", type=int, required=True)
    guard = commands.add_parser("watchdog")
    guard.add_argument("--docker", type=Path, required=True)
    guard.add_argument("--run", required=True)
    guard.add_argument("--deadline", type=float, required=True)
    options = parser.parse_args()
    if options.command == "watchdog":
        return (
            0 if watchdog(options.docker, options.run, options.deadline)["shutdown_verified"] else 1
        )
    directory, passed = launch(
        options.docker,
        options.certificate_python,
        options.approval_reference,
        options.stage_initial_free_disk_bytes,
    )
    print("Native identity receipt retained: " + str(directory))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
