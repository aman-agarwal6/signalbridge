"""Matching retest submission and independent, current-role review.

This never changes source permissions, closes a case or asserts current health.
Only a revalidated, imported native reference-access-v2 run is supported today.
"""

from django.core.exceptions import ValidationError
from django.utils import timezone

from .models import CaseTask, CaseVerification, CheckRun
from .reference_retest import require, validate_check_run
from .services import WorkflowError, write_membership


def _task(case, identifier, fingerprint):
    task = CaseTask.objects.select_for_update().get(pk=identifier, investigation=case)
    require(
        task.kind == "remediation"
        and task.status == "awaiting_retest"
        and task.created_by_id is not None
        and task.evidence_sha256 == fingerprint
    )
    return task


def submit(case, user, values, fingerprint):
    task = _task(case, values.get("task_id"), fingerprint)
    if task.verifications.filter(status="pending", case_version=case.version).exists():
        raise WorkflowError("This task already has a retest awaiting independent review.")
    run = CheckRun.objects.select_for_update().get(
        pk=values.get("check_run_id"), integration=case.integration
    )
    validate_check_run(case, run)
    require(task.verifications.count() < 20)
    verification = CaseVerification.objects.create(
        task=task,
        check_run=run,
        case_version=case.version + 1,
        evidence_sha256=fingerprint,
        check_digest=run.digest,
        submitted_by=user,
    )
    return {
        "verification_id": str(verification.pk),
        "task_id": str(task.pk),
        "check_run_id": str(run.pk),
    }


def decide(case, user, values, fingerprint):
    write_membership(user, case.integration, ("reviewer",))
    verification = CaseVerification.objects.select_for_update().get(
        pk=values.get("verification_id"),
        task__investigation=case,
    )
    task = _task(case, verification.task_id, fingerprint)
    require(
        verification.status == "pending"
        and verification.case_version == case.version
        and verification.evidence_sha256 == fingerprint
    )
    involved = {verification.submitted_by_id, task.created_by_id}
    if task.assignee_id:
        involved.add(task.assignee.user_id)
    if case.assignee_id:
        involved.add(case.assignee.user_id)
    if user.pk in involved:
        raise WorkflowError("A reviewer independent of task ownership and submission is required.")
    run = CheckRun.objects.select_for_update().get(pk=verification.check_run_id)
    require(run.digest == verification.check_digest)
    validate_check_run(case, run)
    decision, rationale = values.get("decision"), values.get("rationale", "")
    require(isinstance(rationale, str))
    rationale = rationale.strip()
    require(decision in ("approved", "rejected") and 10 <= len(rationale) <= 1000)
    verification.status, verification.reviewer = decision, user
    verification.rationale, verification.decided_at = rationale, timezone.now()
    verification.save(update_fields=["status", "reviewer", "rationale", "decided_at"])
    if decision == "approved":
        task.status = "verified"
        task.save(update_fields=["status", "updated_at"])
    return {"verification_id": str(verification.pk), "task_id": str(task.pk), "decision": decision}


def presentation(case, verification, fingerprint, valid_runs=None):
    """A prior decision is historical; changed evidence cannot keep a verified badge."""
    try:
        require(
            verification.task.kind == "remediation"
            and verification.task.status
            == ("verified" if verification.status == "approved" else "awaiting_retest")
            and verification.evidence_sha256 == fingerprint == verification.task.evidence_sha256
            and verification.check_digest == verification.check_run.digest
        )
        if valid_runs is None or verification.check_run_id not in valid_runs:
            validate_check_run(case, verification.check_run)
            if valid_runs is not None:
                valid_runs.add(verification.check_run_id)
        if verification.status == "pending":
            require(verification.case_version == case.version)
            return "Awaiting independent review", True
        if verification.status == "approved":
            return "Verified within recorded lab scope", False
        return "Reviewer rejected verification", False
    except (WorkflowError, ValueError, TypeError, ValidationError):
        return "Evidence or work state changed; review again", False


def console_context(case):
    from django.db.models import Prefetch

    from .case_workflow import evidence_binding

    tasks = list(
        case.tasks.select_related("assignee__user")
        .prefetch_related(
            Prefetch(
                "verifications",
                queryset=CaseVerification.objects.select_related(
                    "task", "check_run", "submitted_by", "reviewer"
                ).order_by("-submitted_at", "pk")[:1],
                to_attr="latest_verification",
            )
        )
        .order_by("-created_at", "pk")[:50]
    )
    try:
        fingerprint = evidence_binding(case)
    except WorkflowError:
        fingerprint = None
    candidates, valid_runs = [], set()
    runs = CheckRun.objects.filter(
        integration=case.integration,
        result__case_id=str(case.pk),
        result__profile="reference-access-v2",
        status="passed",
    ).order_by("-created_at", "pk")[:20]
    for run in runs:
        try:
            validate_check_run(case, run)
            valid_runs.add(run.pk)
            candidates.append(run)
        except (WorkflowError, ValueError, TypeError, ValidationError):
            continue
    for task in tasks:
        task.work_label = task.get_status_display()
        task.verification = task.latest_verification[0] if task.latest_verification else None
        if task.verification:
            task.verification_label, task.verification_reviewable = presentation(
                case,
                task.verification,
                fingerprint,
                valid_runs,
            )
        if task.status == "verified" and (
            task.verification is None
            or task.verification_label != "Verified within recorded lab scope"
        ):
            task.work_label = "Verification needs review"
        task.can_submit_retest = bool(
            candidates
            and task.kind == "remediation"
            and task.status == "awaiting_retest"
            and task.evidence_sha256 == fingerprint
            and not (task.verification and task.verification_reviewable)
        )
    return {"case_tasks": tasks, "matching_retests": candidates}
