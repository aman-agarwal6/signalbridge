"""Retained Wazuh snapshot validation and scoped shutdown controls.

The preloaded-snapshot launch path is retired. Historical execution source and
receipts remain in their retained run directories; no executable launch copy is
kept here. The replacement publisher requires its own reviewed supervisor.
"""

import argparse
import hashlib
import math
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.contract import canonical, parse_json, timestamp
from integrations.enterprise import verification as base
from integrations.enterprise.reference_host_controls import same
from integrations.enterprise.windows_capacity import available_memory
from integrations.wazuh_enterprise import collector_host_controls as host
from integrations.wazuh_enterprise.capture_journal import CaptureJournal
from integrations.wazuh_enterprise.collector_kernel import verify_kernel
from integrations.wazuh_enterprise.collector_profile import verify_configuration
from integrations.wazuh_enterprise.collector_source_binding import read_bytes
from integrations.wazuh_enterprise.contract import require
from integrations.wazuh_enterprise.native_collector import SOURCE_FILES
from integrations.wazuh_enterprise.native_reconciliation import expected_exports, reconcile
from scripts.enterprise_reference_verify import clean_environment, private_acl, require_guard
from scripts.enterprise_zap_verify import no_foreign_running


def check_capacity(*, launching=False):
    disk, memory = shutil.disk_usage(ROOT).free, available_memory()
    host.check_capacity(disk, memory, launching=launching)
    return {"free_disk_bytes": disk, "available_host_memory_bytes": memory}


def save(path, raw):
    with path.open("xb") as output:
        require(output.write(raw) == len(raw), "collector_host_short_write")


def prepare(run, directory, snapshot_root, raw_manifest, expected):
    private_acl(run, "SecureEmpty")
    for name in ("source", "input", "evidence", "docker-config"):
        (directory / name).mkdir()
    save(directory / "docker-config/config.json", b"{}\n")
    sources = {}
    for name in SOURCE_FILES:
        raw = read_bytes(ROOT / name, ROOT, 262144)
        destination = directory / "source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        save(destination, raw)
        sources[name] = hashlib.sha256(raw).hexdigest()
    for app in ("documents", "expenses"):
        for channel in ("observation", "detection"):
            (directory / "input" / app / channel).mkdir(parents=True)
    manifest = parse_json(raw_manifest)
    for stream in manifest["streams"]:
        stem = "observations" if stream["channel"] == "observation" else "detections"
        for segment in stream["segments"]:
            relative = f"{stream['app']}/{stream['channel']}/{stem}-{segment['number']:03}.jsonl"
            save(
                directory / "input" / relative,
                read_bytes(snapshot_root / "input" / relative, snapshot_root, 2 * 1024**2),
            )
    require(
        expected_exports(directory / "input", raw_manifest) == expected,
        "collector_host_input_changed",
    )
    context = {
        "context_version": 1,
        "run_id": str(uuid.UUID(run)),
        "prepared_at": datetime.now(timezone.utc).isoformat(),
        "source_sha256": hashlib.sha256(canonical(sources)).hexdigest(),
        "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
    }
    for name, raw in (
        ("run-context.json", canonical(context) + b"\n"),
        ("source-manifest.json", canonical({"files": sources}) + b"\n"),
        ("manifest.json", raw_manifest),
    ):
        save(directory / "evidence" / name, raw)
    private_acl(run, "Verify")
    return context


def arm_guard(docker, run):
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
            str(time.time() + 900),
        ],
        cwd=ROOT,
        env=clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.DETACHED_PROCESS
        | subprocess.CREATE_NEW_PROCESS_GROUP
        | subprocess.CREATE_NO_WINDOW,
        shell=False,
    )


def execute(docker, run, directory, image, guard):
    private_acl(run, "Verify")
    check_capacity(launching=True)
    require_guard(guard, run, directory)
    no_foreign_running(docker)
    require(host.owned(docker, run, ROOT) == [], "collector_existing_run")
    identifier = host.request(
        docker, run, ROOT, host.create_arguments(image, run, directory), timeout=60
    )
    require(host.owned(docker, run, ROOT) == [identifier], "collector_created_identity")
    host.verify_runtime(docker, identifier, run, ROOT, image)
    require(
        host.request(docker, run, ROOT, ["inspect", identifier, "--format", "{{.State.Status}}"])
        == "created",
        "collector_not_stopped_before_validation",
    )
    private_acl(run, "Verify")
    require_guard(guard, run, directory)
    check_capacity(launching=True)
    no_foreign_running(docker)
    host.request(docker, run, ROOT, ["start", identifier], timeout=20)
    deadline = time.monotonic() + 720
    while time.monotonic() < deadline:
        require_guard(guard, run, directory)
        no_foreign_running(docker, [identifier])
        check_capacity()
        host.verify_runtime(docker, identifier, run, ROOT, image)
        state = host.request(
            docker,
            run,
            ROOT,
            ["inspect", identifier, "--format", "{{.State.Status}}|{{.State.ExitCode}}"],
        )
        if state == "exited|0":
            private_acl(run, "Verify")
            return {
                "runtime_isolation_verified": True,
                "runner_exit_code": 0,
                "owned_container_id": identifier,
            }
        require(state.startswith("running|"), "collector_driver_incomplete")
        time.sleep(1)
    raise base.LabControlError("The native collector execution deadline expired.")


def validate_output(directory, context, *, now, publication_plan=None):
    # The retired CLI cannot select this alternative. Its separate controller
    # supplies the frozen plan and independently verifies the native handshake.
    source_files = SOURCE_FILES
    report_kind = "signalbridge-wazuh-native-bootstrap-v1"
    if publication_plan is not None:
        from integrations.wazuh_enterprise.native_live_collector import (
            KIND,
        )
        from integrations.wazuh_enterprise.native_live_collector import (
            SOURCE_FILES as LIVE_FILES,
        )

        source_files, report_kind = LIVE_FILES, KIND
    recovery = publication_plan is not None and "recovery" in publication_plan
    if recovery:
        from integrations.wazuh_enterprise.native_live_collector import RECOVERY_KIND

        report_kind = RECOVERY_KIND
    evidence = directory / "evidence"
    logs = {"analysisd-config.log", "wazuh-db.log", "wazuh-analysisd.log", "wazuh-logcollector.log"}
    if recovery:
        logs.add("wazuh-logcollector-restart.log")
    names = logs | {
        "run-context.json",
        "source-manifest.json",
        "manifest.json",
        "kernel-observed.json",
        "effective-config.xml",
        "effective-internal-options.conf",
        "heartbeat.json",
        "native-archives.jsonl",
        "native-alerts.jsonl",
        "native-report.json",
        "capture.sqlite3",
    }
    if publication_plan is not None:
        names |= {"collector-ready-state.json", "collector-ready.json", "publication-complete.json"}
    if recovery:
        names |= {"publication-initial.json", "collector-stopped.json"}
    require({p.name for p in evidence.iterdir()} == names, "collector_native_evidence_inventory")
    values, hashes = {}, {}
    for name in names:
        bound = (
            16 * 1024**2
            if name == "capture.sqlite3"
            else 4 * 1024**2
            if name.endswith(".jsonl")
            else 1024**2
            if name in logs
            else 262144
        )
        raw = read_bytes(evidence / name, directory, bound)
        values[name], hashes[name] = raw, hashlib.sha256(raw).hexdigest()
    require(
        same(parse_json(values["run-context.json"]), context), "collector_native_context_changed"
    )
    sources = parse_json(values["source-manifest.json"])
    require(
        type(sources) is dict
        and set(sources) == {"files"}
        and set(sources["files"]) == set(source_files),
        "collector_native_source_manifest",
    )
    actual = {
        name: hashlib.sha256(read_bytes(directory / "source" / name, directory, 262144)).hexdigest()
        for name in source_files
    }
    require(
        same(sources["files"], actual)
        and hashlib.sha256(canonical(actual)).hexdigest() == context["source_sha256"],
        "collector_native_source_changed",
    )
    require(
        hashes["manifest.json"] == context["manifest_sha256"], "collector_native_manifest_changed"
    )
    kernel = verify_kernel(parse_json(values["kernel-observed.json"]))
    if publication_plan is None:
        config = verify_configuration(
            values["effective-config.xml"], values["effective-internal-options.conf"]
        )
    else:
        from integrations.wazuh_enterprise.ready_contract import verify_delivery_configuration

        config = verify_delivery_configuration(
            publication_plan,
            values["effective-config.xml"],
            values["effective-internal-options.conf"],
        )
    # A recovery run rotates one live input aside; its exact bytes are checked
    # against the frozen copy by validate_recorded_recovery below.
    expected = expected_exports(
        directory / ("frozen-input" if recovery else "input"), values["manifest.json"]
    )
    counts = reconcile(
        values["native-archives.jsonl"],
        values["native-alerts.jsonl"],
        expected,
        now=now,
        final=True,
    )
    require(counts["bootstrap_counts_match"], "collector_native_counts_incomplete")
    if recovery:
        # Interruption and rotation must neither lose nor re-read a record.
        require(
            counts["extra_archive_copies"] == 0 and counts["extra_alert_copies"] == 0,
            "collector_native_recovery_duplicates",
        )
    captured = CaptureJournal(evidence, context["run_id"], readonly=True)
    try:
        require(
            captured.db.execute("SELECT COUNT(*) FROM sources WHERE sealed=0").fetchone()[0] == 0,
            "collector_native_capture_unsealed",
        )
        for kind in ("archive", "alert"):
            require(
                captured.captured(kind, limit=4 * 1024**2) == values[f"native-{kind}s.jsonl"],
                "collector_native_capture_mismatch",
            )
    finally:
        captured.close()
    report = parse_json(values["native-report.json"])
    fields = {
        "kind",
        "status",
        "failure_code",
        "owned_processes_stopped",
        "native_runtime_execution_verified",
        "genuine_source_execution_verified",
        "continuous_delivery_verified",
        "run_id",
        "context_sha256",
        "source_sha256",
        "manifest_sha256",
        "kernel_sha256",
        "kernel_controls",
        "configuration_sha256",
        "internal_options_sha256",
        "coverage",
        "finished_at",
        "duration_seconds",
    }
    if publication_plan is not None:
        fields |= {"readiness_sha256", "publication_sha256"}
    if recovery:
        fields.add("recovery_sha256")
    require(type(report) is dict and set(report) == fields, "collector_native_report_fields")
    require(
        report["kind"] == report_kind
        and report["status"] == "counts_matched_pending_host_verification"
        and report["failure_code"] is None
        and report["owned_processes_stopped"] is True
        and all(
            report[k] is False
            for k in (
                "native_runtime_execution_verified",
                "genuine_source_execution_verified",
                "continuous_delivery_verified",
            )
        ),
        "collector_native_report_incomplete",
    )
    expected_report = {
        "run_id": context["run_id"],
        "context_sha256": hashes["run-context.json"],
        "source_sha256": context["source_sha256"],
        "manifest_sha256": context["manifest_sha256"],
        "kernel_sha256": hashes["kernel-observed.json"],
        "kernel_controls": kernel,
        "configuration_sha256": config["configuration_sha256"],
        "internal_options_sha256": config["internal_options_sha256"],
        "coverage": counts,
    }
    if publication_plan is not None:
        from integrations.wazuh_enterprise.ready_publisher import validate_recorded_publication

        require(
            same(
                parse_json(read_bytes(directory / "source/delivery/plan.json", directory, 32768)),
                publication_plan,
            ),
            "collector_native_publication_plan_changed",
        )
        expected_report.update(validate_recorded_publication(directory, publication_plan))
    require(
        all(same(report[k], v) for k, v in expected_report.items()),
        "collector_native_report_changed",
    )
    prepared, finished = timestamp(context["prepared_at"]), timestamp(report["finished_at"])
    require(
        prepared < finished <= now
        and type(report["duration_seconds"]) in (int, float)
        and math.isfinite(report["duration_seconds"])
        and 0 < report["duration_seconds"] <= 700,
        "collector_native_duration",
    )
    if publication_plan is not None:
        ready = parse_json(values["collector-ready.json"])
        require(
            prepared <= timestamp(ready["observed_at"]) <= finished,
            "collector_native_readiness_time",
        )
        require(
            expected_exports(directory / "source/delivery/frozen-input", values["manifest.json"])
            == expected,
            "collector_native_frozen_inputs_changed",
        )
    heartbeat = parse_json(values["heartbeat.json"])
    require(
        type(heartbeat) is dict
        and set(heartbeat)
        == {
            "run_id",
            "sequence",
            "observed_at",
            "supervisor_children_alive",
            "coverage",
            "native_runtime_execution_verified",
        }
        and heartbeat["run_id"] == context["run_id"]
        and type(heartbeat["sequence"]) is int
        and 1 <= heartbeat["sequence"] <= 1000
        and heartbeat["supervisor_children_alive"] is True
        and heartbeat["native_runtime_execution_verified"] is False
        and prepared <= timestamp(heartbeat["observed_at"]) <= finished,
        "collector_native_heartbeat",
    )
    return {
        "native_raw_receipts_revalidated": True,
        "raw_receipt_sha256": hashes,
        "kernel_controls": kernel,
        "coverage": counts,
        "owned_daemons_stopped": True,
        "durable_capture_revalidated": True,
        "native_runtime_execution_verified": False,
        "continuous_delivery_verified": False,
    }


def launch(docker, approval_reference, snapshot_run, source_run):
    # Retired after the final authorized attempt on 2026-10-03: a first-start
    # logcollector seeks EOF in preloaded files without saved offsets. Preserve
    # validation/import helpers for auditing; do not spend another native retry
    # on this snapshot-startup design. A separately reviewed publisher profile
    # must wait for empty-file readiness before appending the frozen packets.
    raise base.LabControlError(
        "This preloaded-snapshot launcher is retired. Use a separately reviewed publication profile."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("launch")
    start.add_argument("--docker", type=Path, required=True)
    start.add_argument("--approval-reference", required=True)
    start.add_argument("--snapshot-run", required=True)
    start.add_argument("--source-run", required=True)
    guard = commands.add_parser("watchdog")
    guard.add_argument("--docker", type=Path, required=True)
    guard.add_argument("--run", required=True)
    guard.add_argument("--deadline", type=float, required=True)
    options = parser.parse_args()
    require(sys.platform == "win32", "collector_windows_host_required")
    if options.command == "watchdog":
        result = host.watchdog(
            options.docker, options.run, ROOT, options.deadline, available_memory
        )
        return 0 if result["shutdown_verified"] else 1
    parser.error("This snapshot launcher is retired; no new execution was started.")


if __name__ == "__main__":
    raise SystemExit(main())
