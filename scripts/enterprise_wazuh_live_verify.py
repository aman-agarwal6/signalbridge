"""Separately reviewed, finite native Wazuh empty-file publication stage.

Never starts Desktop, pulls images, changes networks or removes resources.
An approval reference records prior authorization; it cannot grant permission.
The retired snapshot launcher stays retired. This is not a continuous collector.
"""

import argparse
import hashlib
import os
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

from bridge.contract import canonical, digest, parse_json
from integrations.enterprise import verification as base
from integrations.enterprise.private_acl_diagnostics import PrivateACLFailure
from integrations.enterprise.reference_host_controls import read_json, same, write_control
from integrations.enterprise.windows_capacity import available_memory
from integrations.wazuh_enterprise import collector_host_controls as host
from integrations.wazuh_enterprise import execution_policy as policy
from integrations.wazuh_enterprise import ready_publisher as publisher
from integrations.wazuh_enterprise.collector_kernel import verify_kernel
from integrations.wazuh_enterprise.collector_source_binding import load_binding, read_bytes
from integrations.wazuh_enterprise.contract import EnterpriseWazuhError, require
from integrations.wazuh_enterprise.native_live_collector import SOURCE_FILES
from integrations.wazuh_enterprise.native_reconciliation import expected_exports
from integrations.wazuh_enterprise.ready_contract import verify_delivery_configuration
from scripts.enterprise_reference_verify import clean_environment, private_acl, require_guard
from scripts.enterprise_wazuh_verify import validate_output
from scripts.enterprise_zap_verify import no_foreign_running

FAILURE_PHASES = {
    "preparation": None,
    "prepare_private_acl": "SecureEmpty",
    "prepare_inputs": None,
    "prepare_private_acl_verify": "Verify",
    "preservation_capture": None,
    "image_inspection": None,
    "watchdog_start": None,
    "watchdog_readiness": None,
    "execution": None,
    "execute_private_acl_before_create": "Verify",
    "execute_preflight_before_create": None,
    "collector_create": None,
    "collector_created_validation": None,
    "execute_private_acl_before_start": "Verify",
    "execute_preflight_before_start": None,
    "collector_start": None,
    "collector_monitor": None,
    "publication": None,
    "execute_private_acl_after_exit": "Verify",
    "output_validation": None,
    "source_revalidation": None,
    "main_shutdown": None,
    "watchdog_completion": None,
    "watchdog_validation": None,
    "preservation_final": None,
}


class PhaseDiagnostics:
    """Only fixed phase/code/mode labels; never exception or native output."""

    def __init__(self):
        self.phase = "preparation"

    def enter(self, phase):
        require(type(phase) is str and phase in FAILURE_PHASES, "collector_diagnostic_phase")
        self.phase = phase

    def snapshot(self, error=None):
        require(self.phase in FAILURE_PHASES, "collector_diagnostic_phase")
        mode = FAILURE_PHASES[self.phase]
        result = {
            "phase": self.phase,
            "code": "collector_private_acl_failed" if mode else "collector_phase_failed",
            **({"acl_mode": mode} if mode else {}),
        }
        if mode and type(error) is PrivateACLFailure:
            helper = error.metadata(mode)
            if helper is not None:
                result["helper"] = helper
        return result


def diagnostic_error_class(error):
    # Even a custom exception class name may contain private input. Retain
    # only fixed categories, without reading the exception's text or args.
    for kind, label in (
        (base.LabControlError, "LabControlError"),
        (EnterpriseWazuhError, "EnterpriseWazuhError"),
        (subprocess.TimeoutExpired, "TimeoutExpired"),
        (OSError, "OSError"),
        (ValueError, "ValueError"),
        (TypeError, "TypeError"),
        (RuntimeError, "RuntimeError"),
    ):
        if isinstance(error, kind):
            return label
    return "Exception"


def save(path, raw):
    with path.open("xb") as output:
        require(output.write(raw) == len(raw), "collector_host_short_write")
        output.flush()
        os.fsync(output.fileno())


def check_capacity(*, launching=False, growth_ceiling=host.GROWTH):
    disk, memory = shutil.disk_usage(ROOT).free, available_memory()
    host.check_capacity(disk, memory, launching=launching, growth_ceiling=growth_ceiling)
    return {"free_disk_bytes": disk, "available_host_memory_bytes": memory}


def prepare(
    run, directory, snapshot_root, raw_manifest, expected, *, diagnostics=None, recovery=False
):
    diagnostics = diagnostics if diagnostics is not None else PhaseDiagnostics()
    diagnostics.enter("prepare_private_acl")
    private_acl(run, "SecureEmpty")
    diagnostics.enter("prepare_inputs")
    for name in ("source", "frozen-input", "evidence", "docker-config"):
        (directory / name).mkdir()
    save(directory / "docker-config/config.json", b"{}\n")
    # Keep expectation bytes in a separate, unmonitored read-only source tree.
    for app in ("documents", "expenses"):
        for channel in ("observation", "detection"):
            for parent in (directory / "frozen-input", directory / "source/delivery/frozen-input"):
                (parent / app / channel).mkdir(parents=True)
    for stream in parse_json(raw_manifest)["streams"]:
        stem = "observations" if stream["channel"] == "observation" else "detections"
        for segment in stream["segments"]:
            relative = f"{stream['app']}/{stream['channel']}/{stem}-{segment['number']:03}.jsonl"
            raw = read_bytes(snapshot_root / "input" / relative, snapshot_root, publisher.MAX_BYTES)
            for parent in (directory / "frozen-input", directory / "source/delivery/frozen-input"):
                save(parent / relative, raw)
    for path in (directory / "frozen-input", directory / "source/delivery/frozen-input"):
        require(expected_exports(path, raw_manifest) == expected, "collector_host_frozen_changed")
    plan = publisher.prepare(ROOT, run, raw_manifest, recovery=recovery)
    # Four reviewed RO mounts remain present even when a channel has no packets.
    for app in ("documents", "expenses"):
        for channel in ("observation", "detection"):
            (directory / "input" / app / channel).mkdir(parents=True, exist_ok=True)
    generated = {
        "delivery/plan.json": canonical(plan) + b"\n",
        "delivery/manager-lab.conf": publisher.delivery_configuration(plan),
    }
    sources = {}
    for name in SOURCE_FILES:
        raw = generated[name] if name in generated else read_bytes(ROOT / name, ROOT, 262144)
        path = directory / "source" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        save(path, raw)
        sources[name] = hashlib.sha256(raw).hexdigest()
    context = {
        "context_version": 1,
        "run_id": str(uuid.UUID(run)),
        "prepared_at": datetime.now(timezone.utc).isoformat(),
        "source_sha256": digest(sources),
        "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
    }
    for name, raw in (
        ("run-context.json", canonical(context) + b"\n"),
        ("source-manifest.json", canonical({"files": sources}) + b"\n"),
        ("manifest.json", raw_manifest),
    ):
        save(directory / "evidence" / name, raw)
    diagnostics.enter("prepare_private_acl_verify")
    private_acl(run, "Verify")
    return context, plan


def arm_guard(docker, run, preservation=None):
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
            str(time.time() + (840 if preservation else 900)),
            *(
                [
                    "--preservation-digest",
                    preservation.digest,
                    "--reviewed-plan-sha256",
                    preservation.plan_digest,
                    "--stage-plan",
                    preservation.plan_name,
                ]
                if preservation
                else []
            ),
        ],
        cwd=ROOT,
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
        creationflags=subprocess.DETACHED_PROCESS
        | subprocess.CREATE_NEW_PROCESS_GROUP
        | subprocess.CREATE_NO_WINDOW,
    )


def publish_ready(run, directory, plan):
    """Called only while the verified owned runner and independent guard live."""
    evidence = directory / "evidence"
    verify_kernel(parse_json(read_bytes(evidence / "kernel-observed.json", directory, 262144)))
    verify_delivery_configuration(
        plan,
        read_bytes(evidence / "effective-config.xml", directory, 32768),
        read_bytes(evidence / "effective-internal-options.conf", directory, 4096),
    )
    ready = parse_json(read_bytes(evidence / "collector-ready.json", directory, 32768))
    raw = read_bytes(evidence / "collector-ready-state.json", directory, publisher.MAX_BYTES)
    # publish revalidates plan, freshness, exact empty inputs and kernel file IDs.
    result = publisher.publish(ROOT, run, ready, raw)
    completed = read_bytes(directory / "publisher/publication-finished.json", directory, 32768)
    # Native reader sees only the complete fsynced acknowledgement.
    temporary = evidence / "publication-next.json"
    save(temporary, completed)
    require(not (evidence / "publication-complete.json").exists(), "collector_publication_repeated")
    os.rename(temporary, evidence / "publication-complete.json")
    return result


def _hand_over(evidence, name, raw):
    """Native reader sees only a complete fsynced record, published by rename."""
    temporary = evidence / (name.removesuffix(".json") + "-next.json")
    save(temporary, raw)
    require(not (evidence / name).exists(), "collector_publication_repeated")
    os.rename(temporary, evidence / name)


def _checked_runtime_evidence(directory, plan):
    evidence = directory / "evidence"
    verify_kernel(parse_json(read_bytes(evidence / "kernel-observed.json", directory, 262144)))
    verify_delivery_configuration(
        plan,
        read_bytes(evidence / "effective-config.xml", directory, 32768),
        read_bytes(evidence / "effective-internal-options.conf", directory, 4096),
    )
    return evidence


def publish_initial(run, directory, plan):
    """Recovery profile phase one, while the verified collector runs."""
    evidence = _checked_runtime_evidence(directory, plan)
    ready = parse_json(read_bytes(evidence / "collector-ready.json", directory, 32768))
    raw = read_bytes(evidence / "collector-ready-state.json", directory, publisher.MAX_BYTES)
    result = publisher.publish_initial(ROOT, run, ready, raw)
    _hand_over(
        evidence,
        "publication-initial.json",
        read_bytes(directory / "publisher/publication-initial.json", directory, 32768),
    )
    return result


def publish_backlog(run, directory, plan):
    """Recovery profile phase two: rotate and append only after the native stop record."""
    evidence = _checked_runtime_evidence(directory, plan)
    stopped = parse_json(read_bytes(evidence / "collector-stopped.json", directory, 32768))
    result = publisher.publish_backlog(ROOT, run, stopped)
    _hand_over(
        evidence,
        "publication-complete.json",
        read_bytes(directory / "publisher/publication-finished.json", directory, 32768),
    )
    return result


def admission(docker, run, preservation=None):
    if preservation is None:
        no_foreign_running(docker, host.owned(docker, run, ROOT, publication=True))
    else:
        preservation.checkpoint(host.owned(docker, run, ROOT, publication=True))


def await_guard(guard):
    """Allow bounded serial cleanup requests without a single long blocking wait."""
    deadline = time.monotonic() + 240
    while True:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "collector_guard_completion_timeout")
        try:
            guard.wait(timeout=min(10, remaining))
            return
        except subprocess.TimeoutExpired:
            continue


def execute(
    docker,
    run,
    directory,
    image,
    guard,
    plan,
    *,
    preservation=None,
    diagnostics=None,
    recovery=False,
):
    diagnostics = diagnostics if diagnostics is not None else PhaseDiagnostics()
    growth_ceiling = preservation.growth_ceiling if preservation else host.GROWTH
    diagnostics.enter("execute_private_acl_before_create")
    private_acl(run, "Verify")
    diagnostics.enter("execute_preflight_before_create")
    check_capacity(launching=True, growth_ceiling=growth_ceiling)
    require_guard(guard, run, directory)
    admission(docker, run, preservation)
    require(host.owned(docker, run, ROOT, publication=True) == [], "collector_existing_run")
    diagnostics.enter("collector_create")
    identifier = host.request(
        docker,
        run,
        ROOT,
        host.create_arguments(image, run, directory, publication=True),
        timeout=60,
    )
    diagnostics.enter("collector_created_validation")
    require(
        host.owned(docker, run, ROOT, publication=True) == [identifier],
        "collector_created_identity",
    )
    host.verify_runtime(docker, identifier, run, ROOT, image, publication=True)
    require(
        host.request(docker, run, ROOT, ["inspect", identifier, "--format", "{{.State.Status}}"])
        == "created",
        "collector_not_stopped_before_validation",
    )
    diagnostics.enter("execute_private_acl_before_start")
    private_acl(run, "Verify")
    diagnostics.enter("execute_preflight_before_start")
    require_guard(guard, run, directory)
    check_capacity(launching=True, growth_ceiling=growth_ceiling)
    admission(docker, run, preservation)
    diagnostics.enter("collector_start")
    host.request(docker, run, ROOT, ["start", identifier], timeout=20)
    deadline, publication, initial = time.monotonic() + 720, None, None
    while time.monotonic() < deadline:
        diagnostics.enter("collector_monitor")
        require_guard(guard, run, directory)
        admission(docker, run, preservation)
        check_capacity(growth_ceiling=growth_ceiling)
        host.verify_runtime(docker, identifier, run, ROOT, image, publication=True)
        state = host.request(
            docker,
            run,
            ROOT,
            ["inspect", identifier, "--format", "{{.State.Status}}|{{.State.ExitCode}}"],
        )
        if state == "exited|0":
            require(publication is not None, "collector_exited_without_publication")
            diagnostics.enter("execute_private_acl_after_exit")
            private_acl(run, "Verify")
            return {
                "runtime_isolation_verified": True,
                "runner_exit_code": 0,
                "owned_container_id": identifier,
                "publication": publication,
            }
        require(state.startswith("running|"), "collector_driver_incomplete")
        evidence = directory / "evidence"
        if recovery:
            if initial is None and (evidence / "collector-ready.json").exists():
                diagnostics.enter("publication")
                initial = publish_initial(run, directory, plan)
            elif (
                initial is not None
                and publication is None
                and (evidence / "collector-stopped.json").exists()
            ):
                diagnostics.enter("publication")
                publication = publish_backlog(run, directory, plan)
        elif publication is None and (evidence / "collector-ready.json").exists():
            diagnostics.enter("publication")
            publication = publish_ready(run, directory, plan)
        time.sleep(2 if preservation else 0.25)
    diagnostics.enter("collector_monitor")
    raise base.LabControlError("Native ready-publication execution deadline expired.")


def launch(
    docker,
    approval_reference,
    snapshot_run,
    source_run,
    *,
    execution_policy="exclusive",
    reviewed_plan_sha256=None,
    stage_plan=policy.PLAN,
    recovery=False,
):
    require(type(recovery) is bool, "collector_recovery_profile")
    require(
        sys.platform == "win32"
        and isinstance(approval_reference, str)
        and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", approval_reference),
        "collector_launch_review",
    )
    base.validate_identity(source_run)
    require(execution_policy in ("exclusive", policy.POLICY), "collector_execution_policy_unknown")
    require(
        (
            execution_policy == "exclusive"
            and reviewed_plan_sha256 is None
            and stage_plan == policy.PLAN
        )
        or (
            execution_policy == policy.POLICY
            and type(reviewed_plan_sha256) is str
            and re.fullmatch(r"[a-f0-9]{64}", reviewed_plan_sha256)
        ),
        "collector_reviewed_policy_required",
    )
    if execution_policy == policy.POLICY:
        reviewed_plan, _ = policy.read_plan(ROOT, reviewed_plan_sha256, plan_name=stage_plan)
        growth_ceiling = reviewed_plan["controls"]["cumulative_disk_growth_guard_bytes"]
    else:
        growth_ceiling = host.GROWTH
    docker = Path(docker)
    require(
        docker.is_absolute() and docker.is_file() and not docker.is_symlink(),
        "collector_docker_path",
    )
    if execution_policy == policy.POLICY:
        require(
            docker.resolve()
            == (
                Path.home() / "AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe"
            ).resolve(),
            "collector_reviewed_docker_installation",
        )
    private_acl(source_run, "Verify")
    snapshot, raw, expected, binding = load_binding(
        ROOT, snapshot_run, source_run, now=datetime.now(timezone.utc)
    )
    if execution_policy == policy.POLICY:
        require(
            all(same(binding.get(key), value) for key, value in policy.SOURCE_BINDING.items()),
            "collector_reviewed_source_changed",
        )
    capacity = check_capacity(growth_ceiling=growth_ceiling)
    if execution_policy == "exclusive":
        no_foreign_running(docker)
    run, started = uuid.uuid4().hex, datetime.now(timezone.utc)
    directory = base.private_run_directory(ROOT, run)
    directory.mkdir(parents=True, exist_ok=False)
    receipt = {
        "schema_version": 1,
        "kind": "signalbridge-native-wazuh-ready-publication",
        "run_id": run,
        "approval_reference": approval_reference,
        "status": "incomplete",
        "acceptance_passed": False,
        "native_runtime_execution_verified": False,
        "continuous_delivery_verified": False,
        "started_at": started.isoformat(),
        "capacity_before": capacity,
        "source_binding": binding,
        "stage_growth_ceiling_bytes": growth_ceiling,
        "limits": [
            "Finite replay of fixed source-bound packets; not continuous delivery or recovery proof.",
            "The R3 signal is forwarded from SignalBridge, not rediscovered independently by Wazuh.",
            "Trusted local-operator evidence; not attestation against a local administrator.",
        ],
    }
    if recovery:
        receipt["profile"] = "recovery_rotation"
        receipt["limits"][0] = (
            "Finite source-bound replay with one deliberate logcollector stop/restart and one"
            " same-path input rotation; not continuous delivery, crash recovery or Wazuh"
            " output-file rotation."
        )
    guard, preservation = None, None
    diagnostics = PhaseDiagnostics()
    try:
        context, plan = prepare(
            run, directory, snapshot, raw, expected, diagnostics=diagnostics, recovery=recovery
        )
        if execution_policy == policy.POLICY:
            diagnostics.enter("preservation_capture")
            preservation = policy.capture(
                docker, run, ROOT, reviewed_plan_sha256, plan_name=stage_plan
            )
            receipt.update(preservation.public_binding())
            receipt["limits"].append(
                "Preservation verifies sampled nonsecret envelopes, not uninterrupted application health."
            )
        diagnostics.enter("image_inspection")
        image = host.inspect_image(docker, run, ROOT)
        save(directory / "image.json", canonical(image) + b"\n")
        receipt.update(image_id=image["id"], image_reference=host.IMAGE, plan_sha256=digest(plan))
        diagnostics.enter("watchdog_start")
        guard = arm_guard(docker, run, preservation) if preservation else arm_guard(docker, run)
        diagnostics.enter("watchdog_readiness")
        for _ in range(20):
            require(guard.poll() is None, "collector_guard_exited")
            if (directory / "watchdog-ready.json").exists():
                require_guard(guard, run, directory)
                break
            time.sleep(0.25)
        else:
            raise base.LabControlError("Native publication watchdog readiness expired.")
        diagnostics.enter("execution")
        receipt.update(
            execute(
                docker,
                run,
                directory,
                image,
                guard,
                plan,
                diagnostics=diagnostics,
                recovery=recovery,
                **({"preservation": preservation} if preservation else {}),
            )
        )
        diagnostics.enter("output_validation")
        receipt["native_proof"] = validate_output(
            directory, context, now=datetime.now(timezone.utc), publication_plan=plan
        )
        diagnostics.enter("source_revalidation")
        _, _, _, final = load_binding(
            ROOT, snapshot_run, source_run, now=datetime.now(timezone.utc)
        )
        require(same(binding, final), "collector_source_archive_changed")
        receipt["status"] = "passed_execution_pending_shutdown"
    except Exception as error:
        receipt["error_class"] = diagnostic_error_class(error)
        receipt["failure_diagnostic"] = diagnostics.snapshot(error)
        # Never publish arbitrary exception text containing filesystem/private inputs.
    finally:
        main = {"run_id": run, "shutdown_verified": False}
        try:
            diagnostics.enter("main_shutdown")
            main.update(
                stopped_component_count=host.stop_scope(
                    docker,
                    run,
                    ROOT,
                    publication=True,
                    **({"admit_stop": preservation.admit_stop} if preservation else {}),
                ),
                shutdown_verified=True,
            )
        except Exception as error:
            main["shutdown_error_class"] = diagnostic_error_class(error)
            receipt["main_shutdown_failure_diagnostic"] = diagnostics.snapshot()
        receipt["main_shutdown"] = main
        if guard is not None:
            try:
                diagnostics.enter("watchdog_completion")
                write_control(ROOT, run, "launcher-finished.json", {"run_id": run})
                await_guard(guard)
                independent = read_json(directory / "watchdog.json")
                receipt["independent_shutdown"] = independent
                diagnostics.enter("watchdog_validation")
                receipt.update(
                    policy.publication_shutdown(
                        main,
                        independent,
                        run,
                        started=started,
                        finished=datetime.now(timezone.utc),
                        shared=preservation is not None,
                    )
                )
                require(
                    independent.get("late_operation_drain_verified") is True
                    and independent.get("late_operation_drain_seconds") == 60,
                    "collector_late_drain_incomplete",
                )
                if preservation is not None:
                    diagnostics.enter("preservation_final")
                    receipt["preservation_final"] = preservation.checkpoint(
                        host.owned(docker, run, ROOT, publication=True)
                    )
                    receipt["preservation_verified"] = (
                        not preservation.failed and independent.get("preservation_verified") is True
                    )
                    policy.verify_recorded(directory, receipt, independent)
            except Exception as error:
                receipt["independent_shutdown_error_class"] = diagnostic_error_class(error)
                receipt["independent_shutdown_failure_diagnostic"] = diagnostics.snapshot()
                receipt["watchdog_pending"] = guard.poll() is None
        passed = bool(
            receipt["status"] == "passed_execution_pending_shutdown"
            and receipt.get("main_shutdown_verified")
            and receipt.get("independent_shutdown_verified")
            and not receipt.get("independent_shutdown_error_class")
            and (preservation is None or receipt.get("preservation_verified") is True)
        )
        receipt.update(
            status="passed" if passed else "incomplete",
            acceptance_passed=passed,
            native_runtime_execution_verified=passed,
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        save(directory / "receipt.json", canonical(receipt) + b"\n")
    return directory, passed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("launch")
    start.add_argument("--docker", type=Path, required=True)
    start.add_argument("--approval-reference", required=True)
    start.add_argument("--snapshot-run", required=True)
    start.add_argument("--source-run", required=True)
    start.add_argument(
        "--execution-policy", choices=("exclusive", policy.POLICY), default="exclusive"
    )
    start.add_argument("--reviewed-plan-sha256")
    start.add_argument("--stage-plan", choices=policy.PLAN_NAMES, default=policy.PLAN)
    start.add_argument("--profile", choices=("ready", "recovery"), default="ready")
    guard = commands.add_parser("watchdog")
    guard.add_argument("--docker", type=Path, required=True)
    guard.add_argument("--run", required=True)
    guard.add_argument("--deadline", type=float, required=True)
    guard.add_argument("--preservation-digest")
    guard.add_argument("--reviewed-plan-sha256")
    guard.add_argument("--stage-plan", choices=policy.PLAN_NAMES, default=policy.PLAN)
    options = parser.parse_args()
    require(sys.platform == "win32", "collector_windows_host_required")
    if options.command == "watchdog":
        require(
            bool(options.preservation_digest) == bool(options.reviewed_plan_sha256),
            "collector_guard_policy_binding",
        )
        require(
            bool(options.preservation_digest) or options.stage_plan == policy.PLAN,
            "collector_guard_policy_binding",
        )
        preservation = (
            policy.load(
                options.docker,
                options.run,
                ROOT,
                options.preservation_digest,
                options.reviewed_plan_sha256,
                plan_name=options.stage_plan,
            )
            if options.preservation_digest
            else None
        )
        result = host.watchdog(
            options.docker,
            options.run,
            ROOT,
            options.deadline,
            available_memory,
            publication=True,
            preservation=preservation,
        )
        return 0 if result["shutdown_verified"] else 1
    # Receipt readers use models, but disposable settings avoid the console's
    # credentials/database. No database queries or migrations are performed.
    os.environ["DJANGO_SETTINGS_MODULE"] = "config.verification_settings"
    os.environ["SB_SECRET_KEY"] = "offline-receipt-reader-not-a-console-secret"
    import django

    django.setup()
    directory, passed = launch(
        options.docker,
        options.approval_reference,
        options.snapshot_run,
        options.source_run,
        execution_policy=options.execution_policy,
        reviewed_plan_sha256=options.reviewed_plan_sha256,
        stage_plan=options.stage_plan,
        recovery=options.profile == "recovery",
    )
    print("Native ready-publication receipt retained: " + str(directory))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
