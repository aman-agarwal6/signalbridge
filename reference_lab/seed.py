"""Fixed lab inventory and one narrowly scoped, finite regression mechanism."""

import uuid
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db import connection, transaction
from django.utils import timezone

from .models import BoundedFault, Grant, Resource

ACCOUNTS = ("operator", "document_member", "expense_member", "outsider")
DOCUMENT_ID = uuid.uuid5(uuid.NAMESPACE_URL, "signalbridge-reference/private-document")
EXPENSE_ID = uuid.uuid5(uuid.NAMESPACE_URL, "signalbridge-reference/private-expense")
CONTENT = {
    "documents": "SYNTHETIC-ONLY: Board briefing reference document 2026-10.",
    "expenses": "SYNTHETIC-ONLY: Expense record EXP-LAB-001, amount 42.00.",
}


def require_isolated_database():
    if (
        "reference_lab" not in settings.INSTALLED_APPS
        or settings.ROOT_URLCONF != "reference_lab.urls"
    ):
        raise ImproperlyConfigured(
            "Reference controls require the isolated source application profile."
        )
    name = str(connection.settings_dict["NAME"])
    allowed = (
        name in ("sb_reference", "test_sb_reference")
        if connection.vendor == "postgresql"
        else "memory" in name
    )
    if not allowed:
        raise ImproperlyConfigured(
            "Reference controls refuse non-disposable or unrelated databases."
        )


@transaction.atomic
def seed_accounts(passwords):
    require_isolated_database()
    if set(passwords) != set(ACCOUNTS) or any(
        not isinstance(value, str) or len(value) < 32 for value in passwords.values()
    ):
        raise ValueError("Separate long credentials are required for the four synthetic accounts.")
    User = get_user_model()
    if User.objects.exists() or Resource.objects.exists():
        raise ValueError(
            "Provisioning requires an empty dedicated source database; it never overwrites accounts."
        )
    users = {
        name: User.objects.create_user(username=name, password=passwords[name]) for name in ACCOUNTS
    }
    for app, identifier, member in (
        ("documents", DOCUMENT_ID, "document_member"),
        ("expenses", EXPENSE_ID, "expense_member"),
    ):
        resource = Resource.objects.create(
            id=identifier,
            app=app,
            owner=users["operator"],
            label="Synthetic " + app,
            synthetic_content=CONTENT[app],
        )
        Grant.objects.create(resource=resource, user=users[member], kind="group")
    return users


@transaction.atomic
def set_regression(enabled, duration_seconds=300):
    """Only the known document/member pair; no arbitrary account/record targets."""
    require_isolated_database()
    if (
        type(enabled) is not bool
        or type(duration_seconds) is not int
        or not 1 <= duration_seconds <= 600
    ):
        raise ValueError("The fixed fault must have a 1–600 second bound.")
    resource = Resource.objects.select_for_update().get(pk=DOCUMENT_ID, app="documents")
    user = get_user_model().objects.get(username="document_member")
    now = timezone.now()
    BoundedFault.objects.update_or_create(
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
        "expires_at": now + timedelta(seconds=duration_seconds),
        "scope": "fixed synthetic document/member pair",
    }
