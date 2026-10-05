"""Trusted local operator operations; never exposed through a browser or API."""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.views.decorators.debug import sensitive_variables

from .federation import FederationDenied, _audit
from .models import (
    FederatedExchange,
    FederatedIdentity,
    FederatedLogoutNotice,
    FederatedSession,
)
from .oidc_state import lock_provider_admissions


@sensitive_variables("password")
def recover_local_account(identity_id, password):
    """Reset one linked, active account, disabling all its provider links.

    Host/database operator authority is assumed, not proved by a caller-supplied
    actor. Existing roles and activation flags remain unchanged. Django's session
    auth hash invalidates prior password sessions; registry sessions are explicitly
    revoked. Links require a later explicit operator enable after IdP recovery.
    """
    if not isinstance(password, str) or not 14 <= len(password) <= 128:
        raise FederationDenied()
    if any(ord(char) < 32 or ord(char) == 127 for char in password):
        raise FederationDenied()
    with transaction.atomic():
        lock_provider_admissions()
        stub = FederatedIdentity.objects.filter(pk=identity_id).first()
        if stub is None:
            raise FederationDenied()
        user = get_user_model().objects.select_for_update().get(pk=stub.user_id)
        if not user.is_active:
            raise FederationDenied()
        identities = list(
            FederatedIdentity.objects.select_for_update().filter(user=user).order_by("pk")[:9]
        )
        if not 1 <= len(identities) <= 8 or stub.pk not in {item.pk for item in identities}:
            raise FederationDenied()
        try:
            validate_password(password, user=user)
        except ValidationError:
            raise FederationDenied() from None
        if user.check_password(password):
            raise FederationDenied()
        user.set_password(password)
        user.save(update_fields=["password"])
        now = timezone.now()
        for identity in identities:
            identity.enabled = False
            identity.version += 1
            identity.save(update_fields=["enabled", "version"])
            FederatedSession.objects.filter(identity=identity, revoked_at=None).update(
                revoked_at=now
            )
            _audit(identity, "account.recovered", "local_operator")
    return len(identities)


def prune_expired_runtime(*, apply=False, limit=200):
    """One bounded batch per ephemeral table, with a one-day forensic buffer.

    Never deletes identities, account data, audit history or unexpired barriers.
    This is manual maintenance, not evidence of an operational scheduler. Logout
    tokens and login admission timestamps expire long before this cutoff.
    """
    if type(apply) is not bool or type(limit) is not int or not 1 <= limit <= 200:
        raise FederationDenied()
    cutoff = timezone.now() - timedelta(days=1)
    counts = {}
    with transaction.atomic():
        for label, model, expiry_field in (
            ("login_states", FederatedExchange, "expires_at"),
            ("logout_notices", FederatedLogoutNotice, "block_until"),
            ("registry_sessions", FederatedSession, "expires_at"),
        ):
            eligible = model.objects.filter(**{expiry_field + "__lte": cutoff})
            keys = list(eligible.order_by(expiry_field, "pk").values_list("pk", flat=True)[:limit])
            counts[label] = len(keys)
            if apply:
                # Recheck expiry in the deletion itself; never trust just an old key list.
                deleted, _ = eligible.filter(pk__in=keys).delete()
                counts[label] = deleted
    return counts
