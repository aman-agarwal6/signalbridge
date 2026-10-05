"""Source authorization, membership change and telemetry share a resource lock."""

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone

from .models import BoundedFault, Grant, Resource
from .telemetry import emit


def effective_access(resource, user):
    return user.is_active and (
        resource.owner_id == user.pk or Grant.objects.filter(resource=resource, user=user).exists()
    )


@transaction.atomic
def observe_resource(app, resource_id, user_id):
    """Return content and the exact committed observation, never a latest-row guess."""
    resource = Resource.objects.select_for_update().get(app=app, pk=resource_id)
    user = get_user_model().objects.get(pk=user_id)
    if not user.is_active:
        raise PermissionDenied("Account is disabled.")
    legitimate = effective_access(resource, user)
    injected = (
        not legitimate
        and BoundedFault.objects.filter(
            resource=resource,
            user=user,
            enabled=True,
            started_at__lte=timezone.now(),
            expires_at__gt=timezone.now(),
        ).exists()
    )
    allowed = legitimate or injected
    reason = (
        "owner" if resource.owner_id == user.pk else "member" if allowed else "membership_required"
    )
    # The result has been determined by the actual policy path. Failure to retain
    # its observation aborts this transaction before any content is returned.
    event = emit(resource, user, "allowed" if allowed else "denied", reason)
    return resource.synthetic_content if allowed else None, str(event.pk)


def read_resource(app, resource_id, user_id):
    return observe_resource(app, resource_id, user_id)[0]


@transaction.atomic
def observe_permission_change(app, resource_id, operator_id, subject_id, kind, granted):
    if kind not in ("group", "direct") or type(granted) is not bool:
        raise ValueError("Invalid permission change.")
    resource = Resource.objects.select_for_update().get(app=app, pk=resource_id)
    operator = get_user_model().objects.get(pk=operator_id)
    subject = get_user_model().objects.get(pk=subject_id)
    if not operator.is_active or resource.owner_id != operator.pk:
        raise PermissionDenied("Only the active business owner may change this resource.")
    before = effective_access(resource, subject)
    if granted:
        Grant.objects.get_or_create(resource=resource, user=subject, kind=kind)
    else:
        Grant.objects.filter(resource=resource, user=subject, kind=kind).delete()
    after = effective_access(resource, subject)
    event = None
    if before != after:
        event = emit(
            resource,
            operator,
            "allowed",
            "member" if after else "membership_removed",
            (subject, "granted" if after else "removed"),
        )
    return (
        {"effective_access": after, "effective_access_changed": before != after},
        str(event.pk) if event else None,
    )


def change_permission(app, resource_id, operator_id, subject_id, kind, granted):
    return observe_permission_change(app, resource_id, operator_id, subject_id, kind, granted)[0]
