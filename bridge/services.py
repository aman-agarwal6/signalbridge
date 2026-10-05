from django.db import transaction
from django.utils import timezone

from .evaluation import evaluate
from .federation import check_write_admission
from .models import Audit, Membership, Replay


class WorkflowError(ValueError):
    pass


def allowed(user, integration, roles=("viewer", "analyst", "reviewer")):
    return (
        user.is_authenticated
        and user.is_active
        and Membership.objects.filter(
            user=user, user__is_active=True, integration=integration, role__in=roles
        ).exists()
    )


def write_membership(user, integration, roles=("analyst", "reviewer")):
    """Check current account/role within the caller's write transaction.

    PostgreSQL locks the selected membership and joined account until commit.
    SQLite has no row locks; its transaction/write-conflict behavior remains
    separate. A cached request's role or is_active flag cannot authorize a write.
    """
    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Write authorization requires a transaction.")
    if not user.is_authenticated or not user.is_active:
        raise PermissionError("Your current role does not allow this action.")
    membership = (
        Membership.objects.select_related("user")
        .only("user_id", "integration_id", "role", "user__is_active")
        .select_for_update()
        .filter(user=user, user__is_active=True, integration=integration, role__in=roles)
        .first()
    )
    if membership is None:
        raise PermissionError("Your current role does not allow this action.")
    check_write_admission(user)
    return membership


def create_replay(user, integration, policy):
    if not allowed(user, integration, ("analyst", "reviewer")):
        raise PermissionError()
    data_hash, engine_hash, result = evaluate(policy, integration.slug)
    with transaction.atomic():
        write_membership(user, integration)
        replay = Replay.objects.create(
            integration=integration,
            author=user,
            policy=policy,
            dataset_hash=data_hash,
            engine_hash=engine_hash,
            result=result,
        )
        Audit.objects.create(
            integration=integration,
            actor=user,
            action="replay.created",
            object_id=str(replay.pk),
            detail={"policy": policy, "dataset_hash": data_hash},
        )
    return replay


def decide_replay(user, replay_id, decision, version):
    with transaction.atomic():
        replay = Replay.objects.select_related("integration").get(pk=replay_id)
        write_membership(user, replay.integration, ("reviewer",))
        replay = (
            Replay.objects.select_for_update()
            .filter(pk=replay_id, integration_id=replay.integration_id)
            .first()
        )
        if replay is None:
            raise PermissionError()
        if replay.author_id == user.id:
            raise WorkflowError("A second person must review this proposal.")
        if replay.status != "pending" or replay.version != version:
            raise WorkflowError("This proposal changed. Reload before reviewing.")
        if decision not in ("approved", "rejected"):
            raise WorkflowError("Invalid decision.")
        data_hash, engine_hash, result = evaluate(replay.policy, replay.integration.slug)
        if (
            data_hash != replay.dataset_hash
            or engine_hash != replay.engine_hash
            or result != replay.result
        ):
            raise WorkflowError("Evidence changed. Run a fresh comparison.")
        if decision == "approved" and not result["safe"]:
            raise WorkflowError(
                "Approval blocked: a required suspicious episode would leave review."
            )
        updated = Replay.objects.filter(pk=replay.pk, status="pending", version=version).update(
            status=decision,
            version=version + 1,
            reviewer=user,
            decided_at=timezone.now(),
        )
        if updated != 1:
            raise WorkflowError("Another reviewer already decided.")
        Audit.objects.create(
            integration=replay.integration,
            actor=user,
            action="replay." + decision,
            object_id=str(replay.pk),
            detail={
                "dataset_hash": data_hash,
                "engine_hash": engine_hash,
                "version": version + 1,
            },
        )
    return replay
