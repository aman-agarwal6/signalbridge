"""Current app-role checks, optimistic versions and accountable case operations."""

from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from .case_provenance import _consistent, evidence_fingerprint
from .models import Audit, CaseTask, Investigation, Membership, Note
from .services import WorkflowError, write_membership


def evidence_binding(case):
    if case.events.exclude(integration_id=case.integration_id).exists():
        raise WorkflowError("Case evidence crosses the application boundary.")
    events = list(
        case.events.filter(integration_id=case.integration_id).order_by("event_id")[:1001]
    )
    if len(events) > 1000:
        raise WorkflowError("This operation exceeds its 1,000-event evidence bound.")
    if not events:
        raise WorkflowError("This case has no retained evidence to bind.")
    if any(not _consistent(case, event) for event in events):
        raise WorkflowError("Stored evidence consistency needs review.")
    return evidence_fingerprint([(event.event_id, event.digest, event.source) for event in events])


@transaction.atomic
def operate(user, case_id, version, operation, values):
    initial = Investigation.objects.only("integration_id").get(pk=case_id)
    write_membership(user, initial.integration)
    case = Investigation.objects.select_for_update().get(
        pk=case_id, integration_id=initial.integration_id
    )
    if type(version) is not int or version < 1 or case.version != version:
        raise WorkflowError("Case changed. Reload before saving.")
    detail = {}
    fields = ["version"]
    if operation == "acknowledge":
        if case.acknowledged_at is not None:
            raise WorkflowError("This case is already acknowledged.")
        case.acknowledged_at, case.acknowledged_by = timezone.now(), user
        fields += ["acknowledged_at", "acknowledged_by"]
        detail = {"acknowledged": True}
    elif operation == "assign":
        identifier = values.get("assignee", "")
        member = None
        if identifier:
            member = (
                Membership.objects.select_related("user")
                .filter(
                    pk=identifier,
                    integration_id=case.integration_id,
                    user__is_active=True,
                    role__in=("analyst", "reviewer"),
                )
                .first()
            )
            if member is None:
                raise WorkflowError("Choose a current analyst or reviewer for this application.")
        case.assignee = member
        fields += ["assignee"]
        detail = {"assigned_membership": member.pk if member else None}
    elif operation == "due":
        try:
            days = int(values.get("due_days", ""))
        except (ValueError, TypeError):
            raise WorkflowError("Choose a deadline between 1 and 90 days.") from None
        if not 1 <= days <= 90:
            raise WorkflowError("Choose a deadline between 1 and 90 days.")
        case.due_at = timezone.now() + timedelta(days=days)
        fields += ["due_at"]
        detail = {"due_at": case.due_at.isoformat()}
    elif operation == "structured_note":
        kind, text = values.get("kind"), values.get("note", "").strip()
        if kind not in dict(Note._meta.get_field("kind").choices) or not 1 <= len(text) <= 2000:
            raise WorkflowError("Choose a note category and write 1 to 2,000 characters.")
        Note.objects.create(investigation=case, author=user, kind=kind, text=text)
        detail = {"note_kind": kind}
    elif operation == "task":
        kind, title = values.get("kind"), values.get("title", "").strip()
        if kind not in ("review", "remediation") or not 10 <= len(title) <= 160:
            raise WorkflowError("Choose a task kind and a 10 to 160 character title.")
        task = CaseTask.objects.create(
            investigation=case,
            kind=kind,
            title=title,
            assignee=case.assignee,
            created_by=user,
            case_version=case.version + 1,
            evidence_sha256=evidence_binding(case),
        )
        detail = {"task_id": str(task.pk), "task_kind": kind}
    elif operation == "task_state":
        task = (
            CaseTask.objects.select_for_update()
            .filter(
                pk=values.get("task_id"),
                investigation=case,
            )
            .first()
        )
        state = values.get("status")
        if task is None or state not in ("open", "in_progress", "awaiting_retest"):
            raise WorkflowError("Choose a current task and a valid work state.")
        task.status = state
        task.save(update_fields=["status", "updated_at"])
        detail = {"task_id": str(task.pk), "task_status": state}
    elif operation in ("submit_retest", "review_retest"):
        from .case_verification import decide, submit

        action = submit if operation == "submit_retest" else decide
        detail = action(case, user, values, evidence_binding(case))
    else:
        raise WorkflowError("Invalid case operation.")
    case.version += 1
    case.save(update_fields=fields)
    Audit.objects.create(
        integration_id=case.integration_id,
        actor=user,
        action="case." + operation,
        object_id=str(case.pk),
        detail={**detail, "case_version": case.version},
    )
    return case
