"""Durable OIDC flow controls, separate from signature verification and HTTP.

The optional established client must validate tokens before calling logout.
The optional HTTP adapter cannot treat a dataclass alone as cryptographic
evidence. Local SQL tests do not establish native SSO or MFA.
"""

import re
import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone

from integrations.identity.protocol import VerifiedLogout

from .federation import (
    MAX_CLOCK_SKEW,
    MAX_LIFETIME,
    FederationDenied,
    _audit,
    _aware,
    _digest,
    _identifier,
    validate_link,
)
from .models import (
    FederatedExchange,
    FederatedFlowWindow,
    FederatedIdentity,
    FederatedLogoutNotice,
    FederatedSession,
)

BROWSER_KEY = "_sb_oidc_browser"
FLOW_LIFETIME = timedelta(minutes=5)


def _require(condition):
    if not condition:
        raise FederationDenied()


def _opaque(value):
    _require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", value))
    return value


def _browser(request, *, create):
    _require(settings.FEDERATED_AUTH_ENABLED and request.is_secure())
    _require(settings.SESSION_ENGINE == "django.contrib.sessions.backends.db")
    value = request.session.get(BROWSER_KEY)
    if value is None and create:
        value = secrets.token_urlsafe(32)
        request.session[BROWSER_KEY] = value
        request.session.save()
    return _digest("oidc-browser", _opaque(value))


def _lock_window(operation, now):
    _require(transaction.get_connection().in_atomic_block)
    _require(operation in {"login", "logout", "protocol"})
    FederatedFlowWindow.objects.get_or_create(operation=operation, defaults={"window_start": now})
    # The update locks in SQLite too; PostgreSQL locks this same fixed row.
    FederatedFlowWindow.objects.filter(pk=operation).update(operation=operation)
    return FederatedFlowWindow.objects.select_for_update().get(pk=operation)


def lock_provider_admissions():
    """Serialize admission/logout before user locks, including unknown subjects.

    This fixed-row lock deliberately serializes the bounded lab's SSO admissions,
    not ordinary console requests. It also covers logout arriving just before an
    operator provisions a previously unknown subject. Native races need separate
    PostgreSQL verification; SQLite tests establish only the sequential policy.
    """
    _lock_window("logout", timezone.now())


def _reserve(operation, now):
    slot = _lock_window(operation, now)
    _require(slot.window_start <= now + MAX_CLOCK_SKEW)
    if slot.window_start <= now - timedelta(minutes=1):
        slot.window_start, slot.requests = now, 0
    _require(slot.requests < (20 if operation == "login" else 60))
    slot.requests += 1
    slot.save(update_fields=["window_start", "requests"])


def reserve_protocol_request():
    """Persist failures too: signature/HTTP processing occurs after this commit."""
    with transaction.atomic():
        _reserve("protocol", timezone.now())


def begin_exchange(request, issuer):
    """Return state for Authlib; PKCE/nonce stay in its DB-backed session data."""
    validate_link(issuer, "oidc-exchange")
    browser = _browser(request, create=True)
    now, state = timezone.now(), secrets.token_urlsafe(32)
    with transaction.atomic():
        _reserve("login", now)
        _require(
            FederatedExchange.objects.filter(
                browser_digest=browser, consumed_at=None, expires_at__gt=now
            ).count()
            < 4
        )
        FederatedExchange.objects.create(
            state_digest=_digest("oidc-state", state),
            browser_digest=browser,
            issuer_digest=_digest("oidc-issuer", issuer),
            created_at=now,
            expires_at=now + FLOW_LIFETIME,
        )
    return state


def consume_exchange(request, issuer, state):
    """Claim before the token exchange; failure needs a new login, never replay."""
    validate_link(issuer, "oidc-exchange")
    browser, now = _browser(request, create=False), timezone.now()
    # One conditional SQL write prevents concurrent callbacks using one state.
    changed = FederatedExchange.objects.filter(
        state_digest=_digest("oidc-state", _opaque(state)),
        browser_digest=browser,
        issuer_digest=_digest("oidc-issuer", issuer),
        consumed_at=None,
        created_at__lte=now + MAX_CLOCK_SKEW,
        expires_at__gt=now,
    ).update(consumed_at=now)
    _require(changed == 1)


def _logout_scope(issuer, subject, provider_session):
    validate_link(issuer, subject)
    _identifier(provider_session)
    return _digest("provider-logout-scope", "\0".join((issuer, subject, provider_session)))


def assert_provider_session_active(evidence):
    _require(transaction.get_connection().in_atomic_block)
    scope = _logout_scope(evidence.issuer, evidence.subject, evidence.provider_session)
    _require(
        not FederatedLogoutNotice.objects.filter(
            scope_digest=scope, block_until__gt=timezone.now()
        ).exists()
    )


def consume_verified_logout(evidence):
    """Revoke this issuer/subject/session and block an in-flight re-admission."""
    _require(settings.FEDERATED_AUTH_ENABLED and isinstance(evidence, VerifiedLogout))
    now = timezone.now()
    issued, expiry = _aware(evidence.issued_at), _aware(evidence.expires_at)
    _require(now - FLOW_LIFETIME <= issued <= now + MAX_CLOCK_SKEW)
    _require(now < expiry <= issued + FLOW_LIFETIME)
    scope = _logout_scope(evidence.issuer, evidence.subject, evidence.provider_session)
    token = _digest(
        "provider-logout-token", evidence.issuer + "\0" + _identifier(evidence.token_id)
    )
    with transaction.atomic():
        _reserve("logout", now)
        stub = FederatedIdentity.objects.filter(
            issuer=evidence.issuer, subject=evidence.subject
        ).first()
        identity = None
        if stub is not None:
            get_user_model().objects.select_for_update().get(pk=stub.user_id)
            identity = FederatedIdentity.objects.select_for_update().get(pk=stub.pk)
            _require(identity.user_id == stub.user_id)
        try:
            with transaction.atomic():
                FederatedLogoutNotice.objects.create(
                    token_digest=token,
                    scope_digest=scope,
                    received_at=now,
                    block_until=now + MAX_LIFETIME + MAX_CLOCK_SKEW,
                )
        except IntegrityError:
            raise FederationDenied() from None
        if identity is None:
            return 0
        sessions = list(
            FederatedSession.objects.select_for_update()
            .filter(
                identity=identity,
                provider_session_digest=_digest("provider-session", evidence.provider_session),
                revoked_at=None,
                expires_at__gt=now,
            )
            .order_by("pk")[:9]
        )
        _require(len(sessions) <= 8)
        for session in sessions:
            session.revoked_at = now
            session.save(update_fields=["revoked_at"])
            _audit(identity, "session.revoked", "provider_logout", session=session)
        return len(sessions)
