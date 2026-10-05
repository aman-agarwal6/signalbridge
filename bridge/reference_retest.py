"""Import one retained native reference proof, never execute a lab or invent events.

Local database/filesystem operators remain trusted. Receipt hashes establish
consistency, not independent attestation. Generic green CheckRuns cannot verify a fix.
"""

import hashlib
import os
import re
from datetime import timedelta
from pathlib import Path

from django.db import transaction
from django.utils import timezone

from integrations.enterprise.network_verification import (
    SNAPSHOT_LIMIT,
    wheel_expansion,
    wheel_manifest,
)
from integrations.enterprise.reference_host_controls import read_json, same
from integrations.enterprise.reference_host_evidence import (
    safe_path,
    validate_native,
    validate_shutdown,
)
from integrations.enterprise.verification import LabControlError, private_run_directory
from scripts.record_verification import source_manifest

from .case_provenance import _consistent
from .case_workflow import evidence_binding
from .contract import digest, timestamp, validate_event
from .models import Audit, CheckRun, Event, Investigation
from .native_receipts import matches_result
from .services import WorkflowError

PROFILE = "reference-access-v2"
SUITE = "Native reference access correction"
STEPS = {
    "removal": "documents_permission_removed",
    "failure": "bounded_regression_known_content",
    "denial": "regression_reset_denied",
    "owner_control": "documents_reset_owner_control",
}
FIELDS = {
    "schema_version",
    "evidence_kind",
    "profile",
    "run_id",
    "app",
    "case_id",
    "case_evidence_sha256",
    "source_sha256",
    "host_receipt_sha256",
    "finished_at",
    "bindings",
}


def require(condition):
    if not condition:
        raise WorkflowError("Matching native retest evidence is incomplete, stale or inconsistent.")


def _manifest(root):
    """Bound all archive bytes before the existing manifest reader consumes them."""
    total, count, directory_count = 0, 0, 0

    def failed(_):
        raise LabControlError("Reference snapshot enumeration failed.")

    safe_path(root, root)
    for parent, directories, files in os.walk(root, followlinks=False, onerror=failed):
        for name in directories:
            safe_path(Path(parent) / name, root)
            directory_count += 1
            require(directory_count <= 3000)
        for name in files:
            path = safe_path(Path(parent) / name, root)
            require(path.is_file())
            total += path.stat().st_size
            count += 1
            require(total <= SNAPSHOT_LIMIT and count <= 1500)
    return source_manifest(root)


def load_native_retest(workspace, run_id):
    """Read only a fixed retained run; no supplied path, subprocess, network or secrets."""
    directory = private_run_directory(workspace, run_id)
    receipt_path = safe_path(directory / "receipt.json", directory)
    receipt = read_json(receipt_path, 262144)
    require(isinstance(receipt, dict))
    require(
        receipt.get("schema_version") == 1
        and type(receipt.get("schema_version")) is int
        and receipt.get("kind") == "signalbridge-native-reference-access"
        and receipt.get("run_id") == run_id
        and receipt.get("status") == "passed"
        and all(
            receipt.get(key) is True
            for key in (
                "acceptance_passed",
                "source_unchanged",
                "runtime_isolation_verified",
                "parsed_configuration_verified",
                "main_shutdown_verified",
                "independent_shutdown_verified",
            )
        )
        and type(receipt.get("runner_exit_code")) is int
        and receipt["runner_exit_code"] == 0
    )
    started, finished = timestamp(receipt.get("started_at")), timestamp(receipt.get("finished_at"))
    require(started < finished <= timezone.now() + timedelta(seconds=5))
    require(finished - started <= timedelta(minutes=30))
    manifest = _manifest(safe_path(directory / "source", directory))
    wheels = safe_path(directory / "wheels", directory)
    rows = wheel_manifest()
    require({p.name for p in wheels.iterdir()} == {row["filename"] for row in rows})
    for row in rows:
        path = safe_path(wheels / row["filename"], directory)
        require(path.is_file() and path.stat().st_size == row["size"])
    footprint = wheel_expansion(wheels)
    proof = validate_native(workspace, run_id, manifest, footprint, now=finished)
    require(same(proof, receipt.get("native_proof")))
    require(same(proof["source_snapshot"], receipt.get("source_snapshot")))
    require(receipt.get("source_sha256") == manifest["sha256"])
    preparation = receipt.get("preparation")
    require(isinstance(preparation, dict) and same(preparation.get("wheel_footprint"), footprint))
    watchdog = read_json(safe_path(directory / "watchdog.json", directory))
    require(same(watchdog, receipt.get("independent_shutdown")))
    validate_shutdown(
        receipt.get("main_shutdown"), watchdog, run_id, started=started, finished=finished
    )
    require(proof["reconciliation"]["profile"] == PROFILE)
    execution = read_json(
        safe_path(directory / "evidence/reference-execution.json", directory), 262144
    )
    console = read_json(safe_path(directory / "evidence/console-events.json", directory), 262144)
    steps = {row["step"]: row for row in execution["steps"]}
    events = {row["event_id"]: row for row in console["events"]}
    bindings = {}
    for name, step in STEPS.items():
        event_id = steps[step]["event_id"]
        bindings[name] = {"event_id": event_id, "digest": events[event_id]["digest"]}
    return {
        "schema_version": 1,
        "evidence_kind": "native_reference_access",
        "profile": PROFILE,
        "run_id": run_id,
        "app": "documents",
        "case_id": proof["reconciliation"]["regression_case_id"],
        "case_evidence_sha256": None,  # Assigned only against existing matching database rows.
        "source_sha256": manifest["sha256"],
        "host_receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        "finished_at": finished.isoformat(),
        "bindings": bindings,
    }


def validate_result(case, result):
    """Require exact original evidence plus corrected denial and surviving owner access."""
    require(isinstance(result, dict) and set(result) == FIELDS)
    require(
        type(result["schema_version"]) is int
        and result["schema_version"] == 1
        and result["evidence_kind"] == "native_reference_access"
        and result["profile"] == PROFILE
        and case.rule == "R3"
        and case.integration.slug == "documents"
        and result["app"] == case.integration.slug
        and result["case_id"] == str(case.pk)
        and isinstance(result["run_id"], str)
        and re.fullmatch(r"[a-f0-9]{32}", result["run_id"])
    )
    for key in ("case_evidence_sha256", "source_sha256", "host_receipt_sha256"):
        require(isinstance(result[key], str) and re.fullmatch(r"[a-f0-9]{64}", result[key]))
    require(result["case_evidence_sha256"] == evidence_binding(case))
    finished = timestamp(result["finished_at"])
    require(finished <= timezone.now() + timedelta(seconds=5))
    bindings = result["bindings"]
    require(isinstance(bindings, dict) and set(bindings) == set(STEPS))
    events = {}
    for key, row in bindings.items():
        require(isinstance(row, dict) and set(row) == {"event_id", "digest"})
        require(isinstance(row["event_id"], str) and isinstance(row["digest"], str))
        event = Event.objects.filter(event_id=row["event_id"], integration=case.integration).first()
        require(
            event is not None
            and event.digest == row["digest"]
            and event.source == "instrumented_lab"
            and event.state == "processed"
            and _consistent(case, event)
            and event.processed_at is not None
            and event.processed_at <= finished
            and event.processed_by == "native-reference-proof"
        )
        validate_event(event.payload, case.integration.slug, now=finished)
        events[key] = event
    require(len({event.event_id for event in events.values()}) == 4)
    require(
        set(case.events.values_list("event_id", flat=True))
        == {
            events["removal"].event_id,
            events["failure"].event_id,
        }
    )
    removal, failure, denial, owner = (events[key].payload for key in STEPS)
    require(
        removal["schema_version"] == 2
        and removal["operation"] == "membership.change"
        and removal["membership"]["state"] == "removed"
        and failure["schema_version"] == denial["schema_version"] == owner["schema_version"] == 1
        and all(p["operation"] == "private_record.read" for p in (failure, denial, owner))
        and failure["outcome"] == "allowed"
        and failure["reason"] == "member"
        and denial["outcome"] == "denied"
        and denial["reason"] == "membership_required"
        and owner["outcome"] == "allowed"
        and owner["reason"] == "owner"
        and removal["membership"]["subject"] == failure["actor"] == denial["actor"]
        and events["removal"].membership_subject == removal["membership"]["subject"]
        and removal["actor"] == owner["actor"]
        and owner["actor"] != failure["actor"]
        and len({p["resource"] for p in (removal, failure, denial, owner)}) == 1
        and len({p["episode"] for p in (removal, failure, denial, owner)}) == 1
        and all(p["environment"] == "lab" for p in (removal, failure, denial, owner))
        and timestamp(removal["occurred_at"])
        < timestamp(failure["occurred_at"])
        < timestamp(denial["occurred_at"])
        < timestamp(owner["occurred_at"])
        <= finished
    )
    return events


def validate_check_run(case, run):
    require(isinstance(run.result, dict))
    require(
        matches_result(
            run,
            case.integration_id,
            SUITE,
            run.result.get("source_sha256"),
            run.result,
            checksum=digest(run.result),
        )
    )
    events = validate_result(case, run.result)
    marker = {
        "digest": run.digest,
        "profile": PROFILE,
        "run_id": run.result["run_id"],
        "origin": "local_database_operator",
    }
    require(
        Audit.objects.filter(
            integration=case.integration,
            actor__isnull=True,
            action="retest.imported",
            object_id=str(run.pk),
            detail=marker,
        ).exists()
    )
    return events


@transaction.atomic
def import_retest(result, *, dry_run=False):
    """Do not fabricate a native case/event in the receiving application database."""
    case = (
        Investigation.objects.select_for_update()
        .select_related("integration")
        .get(pk=result["case_id"])
    )
    result = {**result, "case_evidence_sha256": evidence_binding(case)}
    validate_result(case, result)
    identity = digest(result)
    existing = CheckRun.objects.filter(
        integration=case.integration, result__run_id=result["run_id"]
    ).first()
    require(existing is None or (existing.digest == identity and same(existing.result, result)))
    if dry_run:
        return None, False
    run, created = CheckRun.objects.get_or_create(
        digest=identity,
        defaults={
            "integration": case.integration,
            "suite": SUITE,
            "revision": result["source_sha256"],
            "result": result,
            "status": "passed",
        },
    )
    require(run.integration_id == case.integration_id and same(run.result, result))
    if created:
        Audit.objects.create(
            integration=case.integration,
            action="retest.imported",
            object_id=str(run.pk),
            detail={
                "digest": identity,
                "profile": PROFILE,
                "run_id": result["run_id"],
                "origin": "local_database_operator",
            },
        )
    validate_check_run(case, run)
    return run, created
