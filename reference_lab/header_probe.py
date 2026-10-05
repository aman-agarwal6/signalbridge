"""Operator-only header control for the isolated, fixed synthetic reference app."""

from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.utils import timezone

from bridge.contract import parse_json

from .authorization import effective_access
from .models import BoundedFault, BoundedHeaderFault, Resource
from .seed import CONTENT, DOCUMENT_ID, require_isolated_database

PROFILE = "signalbridge-reference-authenticated-headers-v1"
PATH = f"/apps/documents/resources/{DOCUMENT_ID}/"


def require_profile():
    require_isolated_database()
    if getattr(settings, "REFERENCE_HEADER_PROFILE", None) != PROFILE:
        raise ImproperlyConfigured("The dedicated header profile is not enabled.")


@transaction.atomic
def set_header_fault(enabled, duration_seconds=300):
    """Fixed document/member pair only; no browser route or arbitrary target."""
    require_profile()
    if (
        type(enabled) is not bool
        or type(duration_seconds) is not int
        or not 1 <= duration_seconds <= 600
    ):
        raise ValueError("The fixed header fault requires a 1-600 second bound.")
    resource = Resource.objects.select_for_update().get(pk=DOCUMENT_ID, app="documents")
    if not enabled:
        # Withdrawal must still work after permission or account changes. It
        # cannot introduce a fault, and it preserves the original expiry record.
        BoundedHeaderFault.objects.filter(resource=resource).update(enabled=False)
        return {"enabled": False, "scope": "fixed synthetic document header only"}
    user = get_user_model().objects.get(username="document_member", is_active=True)
    if resource.synthetic_content != CONTENT["documents"] or not effective_access(resource, user):
        raise ValueError(
            "The header control requires the known synthetic record and legitimate access."
        )
    now = timezone.now()
    if BoundedFault.objects.filter(enabled=True, expires_at__gt=now).exists():
        raise ValueError("Do not combine this header profile with an authorization bypass.")
    BoundedHeaderFault.objects.update_or_create(
        resource=resource,
        user=user,
        defaults={
            "enabled": enabled,
            "started_at": now,
            "expires_at": now + timedelta(seconds=duration_seconds),
        },
    )
    return {
        "enabled": enabled,
        "scope": "fixed synthetic document/member header only",
        "expires_at": now + timedelta(seconds=duration_seconds),
    }


class HeaderProbe:
    """Opt-in outer middleware: remove only a header from a verified allowed read.

    This must wrap SecurityMiddleware so secure headers remain the ordinary
    default. Expired faults, other users/paths and denied results keep nosniff.
    No request can create or extend a fault. Database failures stop the response.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if getattr(settings, "REFERENCE_HEADER_PROFILE", None) != PROFILE:
            return response
        if request.method != "GET" or request.path != PATH or response.status_code != 200:
            return response
        require_profile()
        if (
            not request.is_secure()
            or not request.user.is_authenticated
            or request.user.username != "document_member"
        ):
            return response
        # Recheck the fixed data and actual access. A header omission must never
        # hide a denied result or turn an injected authorization bypass into this
        # profile's successful member control.
        with transaction.atomic():
            resource = Resource.objects.select_for_update().get(pk=DOCUMENT_ID, app="documents")
            user = get_user_model().objects.get(pk=request.user.pk, is_active=True)
            now = timezone.now()
            fault = BoundedHeaderFault.objects.filter(
                resource=resource,
                user=user,
                enabled=True,
                started_at__lte=now,
                expires_at__gt=now,
            ).first()
            if fault is None:
                return response
            if resource.synthetic_content != CONTENT["documents"] or not effective_access(
                resource, user
            ):
                raise ValueError("Header profile access/data integrity changed.")
            if BoundedFault.objects.filter(enabled=True, expires_at__gt=now).exists():
                raise ValueError("Overlapping authorization fault is outside this profile.")
            if response.get("Content-Type") != "application/json" or parse_json(
                response.content
            ) != {
                "app": "documents",
                "record_id": str(DOCUMENT_ID),
                "synthetic_content": CONTENT["documents"],
            }:
                raise ValueError("The fixed header response is not the known synthetic record.")
            if response.get("X-Content-Type-Options") != "nosniff":
                raise ValueError(
                    "The default secure header is missing before the controlled omission."
                )
            del response["X-Content-Type-Options"]
        return response
