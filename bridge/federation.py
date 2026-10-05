"""Local policy AFTER OIDC validation; this module does not validate provider tokens.

The separate optional OIDC client must verify signature, issuer, audience, nonce,
PKCE, state and MFA before calling admit_verified_identity. Local policy tests
alone do not establish genuine SSO. Provisioning trusts the local DB operator.
"""

import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.db import transaction
from django.http import HttpResponse
from django.utils import timezone
from django.utils.crypto import salted_hmac

from .models import FederatedIdentity, FederatedSession, IdentityAudit

SESSION_KEY = "_sb_federated_binding"
MAX_LIFETIME = timedelta(minutes=15)
MAX_AUTH_AGE = timedelta(minutes=5)
MAX_CLOCK_SKEW = timedelta(seconds=5)
GENERIC_DENIAL = "Federated access is unavailable. Sign in again or contact the local operator."


class FederationDenied(PermissionError):
    def __init__(self):
        super().__init__(GENERIC_DENIAL)


@dataclass(frozen=True)
class VerifiedIdentity:
    """Internal adapter contract, NOT proof of signature validation on its own."""

    issuer: str
    subject: str
    provider_session: str
    issued_at: datetime
    authenticated_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class Admission:
    session_id: uuid.UUID
    binding_digest: str


def _identifier(value):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 255
        or value != value.strip()
        or any(ord(char) < 33 or ord(char) == 127 for char in value)
    ):
        raise FederationDenied()
    return value


def validate_link(issuer, subject):
    _identifier(issuer)
    _identifier(subject)
    try:
        URLValidator(schemes=["https"])(issuer)
        parsed = urlsplit(issuer)
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not parsed.hostname
            or parsed.port == 0
            or "\\" in issuer
            or "%" in parsed.netloc
        ):
            raise ValueError()
    except (ValidationError, ValueError):
        raise FederationDenied() from None


def _digest(namespace, value):
    return salted_hmac(
        "signalbridge.federation." + namespace, value, algorithm="sha256"
    ).hexdigest()


def _audit(identity, action, origin, *, actor=None, session=None):
    IdentityAudit.objects.create(
        identity=identity,
        actor=actor,
        session_id=session.pk if session is not None else None,
        action=action,
        origin=origin,
        identity_version=identity.version,
    )


def provision_identity(*, issuer, subject, user_id):
    """Explicit local-operator link to an existing account; never assigns a role.

    Access to this Python/management interface assumes trusted host/database
    operation. No remotely supplied operator name is accepted as authentication.
    """
    validate_link(issuer, subject)
    with transaction.atomic():
        user = (
            get_user_model().objects.select_for_update().filter(pk=user_id, is_active=True).first()
        )
        if user is None:
            raise FederationDenied()
        existing = FederatedIdentity.objects.filter(issuer=issuer, subject=subject).first()
        if existing is not None:
            if existing.user_id != user.pk:
                raise FederationDenied()
            return existing, False
        if FederatedIdentity.objects.filter(user=user).count() >= 8:
            raise FederationDenied()
        identity = FederatedIdentity.objects.create(issuer=issuer, subject=subject, user=user)
        _audit(identity, "link.provisioned", "local_operator")
        return identity, True


def set_identity_enabled(identity_id, *, enabled):
    """Version changes invalidate old sessions, including after re-enablement."""
    if type(enabled) is not bool:
        raise FederationDenied()
    with transaction.atomic():
        stub = FederatedIdentity.objects.filter(pk=identity_id).first()
        if stub is None:
            raise FederationDenied()
        get_user_model().objects.select_for_update().get(pk=stub.user_id)
        identity = FederatedIdentity.objects.select_for_update().get(pk=identity_id)
        if identity.user_id != stub.user_id:
            raise FederationDenied()
        if identity.enabled == enabled:
            return identity, False
        identity.enabled = enabled
        identity.version += 1
        identity.save(update_fields=["enabled", "version"])
        FederatedSession.objects.filter(identity=identity, revoked_at=None).update(
            revoked_at=timezone.now()
        )
        _audit(identity, "link.enabled" if enabled else "link.disabled", "local_operator")
        return identity, True


def _aware(value):
    if not isinstance(value, datetime) or timezone.is_naive(value):
        raise FederationDenied()
    return value


def admit_verified_identity(request, evidence):
    """Apply local account policy to an already cryptographically verified identity.

    The optional OIDC HTTP adapter cannot use this policy as a replacement for
    actual provider validation. Provider execution is a separate acceptance gate.
    """
    if not settings.FEDERATED_AUTH_ENABLED or not request.is_secure():
        raise FederationDenied()
    if not isinstance(evidence, VerifiedIdentity):
        raise FederationDenied()
    validate_link(evidence.issuer, evidence.subject)
    _identifier(evidence.provider_session)
    now = timezone.now()
    issued, authenticated, expiry = (
        _aware(evidence.issued_at),
        _aware(evidence.authenticated_at),
        _aware(evidence.expires_at),
    )
    if (
        authenticated > now + MAX_CLOCK_SKEW
        or issued > now + MAX_CLOCK_SKEW
        or authenticated > issued + MAX_CLOCK_SKEW
        or now - authenticated > MAX_AUTH_AGE
        or issued < now - MAX_AUTH_AGE
        or expiry <= now
        or expiry <= issued
    ):
        raise FederationDenied()
    stub = FederatedIdentity.objects.filter(
        issuer=evidence.issuer, subject=evidence.subject
    ).first()
    if stub is None:
        raise FederationDenied()
    with transaction.atomic():
        from .oidc_state import assert_provider_session_active, lock_provider_admissions

        lock_provider_admissions()
        user = get_user_model().objects.select_for_update().get(pk=stub.user_id)
        identity = FederatedIdentity.objects.select_for_update().get(pk=stub.pk)
        if not user.is_active or not identity.enabled or identity.user_id != user.pk:
            raise FederationDenied()
        # The provider may log out while an earlier authorization-code reply is
        # in flight. Serialize with logout, then reject that session's return.
        assert_provider_session_active(evidence)
        if request.user.is_authenticated and request.user.pk != user.pk:
            raise FederationDenied()
        prior_marker = request.session.get(SESSION_KEY)
        if prior_marker is not None:
            # Reauthentication replaces this browser's old admission atomically.
            revoke_browser_session(user, prior_marker)
        if (
            FederatedSession.objects.filter(
                identity__user=user, revoked_at=None, expires_at__gt=now
            ).count()
            >= 8
        ):
            raise FederationDenied()
        binding = secrets.token_urlsafe(32)
        session = FederatedSession.objects.create(
            identity=identity,
            identity_version=identity.version,
            binding_digest=_digest("browser", binding),
            provider_session_digest=_digest("provider-session", evidence.provider_session),
            created_at=now,
            authenticated_at=authenticated,
            expires_at=min(now + MAX_LIFETIME, expiry),
        )
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        # Django may retain the key when reauthenticating the same logged-in user.
        # Rotate on every admission so a previously copied cookie cannot inherit it.
        request.session.cycle_key()
        request.session[SESSION_KEY] = {"id": str(session.pk), "binding": binding}
        request.session.set_expiry(session.expires_at)
        request.session.save()
        _audit(identity, "session.issued", "validated_oidc", actor=user, session=session)
        request.user._sb_federated_admission = Admission(session.pk, session.binding_digest)
    return session


def parse_marker(marker):
    if not isinstance(marker, dict) or set(marker) != {"id", "binding"}:
        raise FederationDenied()
    if (
        not isinstance(marker["id"], str)
        or not isinstance(marker["binding"], str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", marker["binding"])
    ):
        raise FederationDenied()
    try:
        identity = uuid.UUID(marker["id"])
    except ValueError:
        raise FederationDenied() from None
    if str(identity) != marker["id"]:
        raise FederationDenied()
    return Admission(identity, _digest("browser", marker["binding"]))


def _current(user, admission, *, lock=False):
    if (
        not settings.FEDERATED_AUTH_ENABLED
        or not user.is_authenticated
        or not isinstance(admission, Admission)
    ):
        raise FederationDenied()
    query = FederatedSession.objects.select_related("identity", "identity__user")
    if lock:
        query = query.select_for_update()
    session = query.filter(
        pk=admission.session_id,
        binding_digest=admission.binding_digest,
        identity__user_id=user.pk,
        identity__user__is_active=True,
        identity__enabled=True,
        revoked_at=None,
    ).first()
    now = timezone.now()
    if (
        session is None
        or session.identity_version != session.identity.version
        or session.created_at > now + MAX_CLOCK_SKEW
        or session.expires_at <= now
        or session.expires_at > session.created_at + MAX_LIFETIME
    ):
        raise FederationDenied()
    return session


def check_browser_admission(user, marker):
    admission = parse_marker(marker)
    _current(user, admission)
    return admission


def check_write_admission(user):
    """Recheck and lock local SSO policy within the existing case write transaction."""
    admission = getattr(user, "_sb_federated_admission", None)
    if admission is not None:
        if not transaction.get_connection().in_atomic_block:
            raise RuntimeError("Federated write authorization requires a transaction.")
        _current(user, admission, lock=True)


def revoke_browser_session(user, marker):
    admission = parse_marker(marker)
    with transaction.atomic():
        get_user_model().objects.select_for_update().get(pk=user.pk)
        session = (
            FederatedSession.objects.select_related("identity")
            .select_for_update()
            .filter(
                pk=admission.session_id,
                binding_digest=admission.binding_digest,
                identity__user_id=user.pk,
            )
            .first()
        )
        if session is None:
            raise FederationDenied()
        if session.revoked_at is None:
            session.revoked_at = timezone.now()
            session.save(update_fields=["revoked_at"])
            _audit(
                session.identity, "session.revoked", "local_session", actor=user, session=session
            )


def unavailable_response():
    return HttpResponse(GENERIC_DENIAL, status=503, content_type="text/plain")
