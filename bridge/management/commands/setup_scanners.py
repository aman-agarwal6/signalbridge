"""Explicit membership provisioning for the local self-assurance workspace."""

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from bridge.models import Audit, Integration, Membership


class Command(BaseCommand):
    help = "Create a local scanner workspace; explicitly grant existing users access."

    def add_arguments(self, parser):
        parser.add_argument("--grant", action="append", required=True, metavar="USERNAME:ROLE")

    @transaction.atomic
    def handle(self, *args, **options):
        if not settings.LOCAL:
            raise CommandError("Scanner workspace setup is local-only.")
        grants = []
        for value in options["grant"]:
            username, separator, role = value.rpartition(":")
            if not separator or role not in ("viewer", "analyst", "reviewer"):
                raise CommandError("Each grant must be USERNAME:viewer, analyst, or reviewer.")
            try:
                user = get_user_model().objects.get(username=username, is_active=True)
            except get_user_model().DoesNotExist as error:
                raise CommandError("Grant requires an existing active user.") from error
            grants.append((user, role))
        app, created = Integration.objects.get_or_create(
            slug="signalbridge",
            defaults={
                "name": "SignalBridge",
                "enabled": False,
                "coverage": "Local scanner reports for SignalBridge itself. No source-app event collector or Supabase checks.",
            },
        )
        if app.enabled:
            raise CommandError(
                "Existing SignalBridge workspace has an event collector; inspect before provisioning."
            )
        for user, role in grants:
            membership, added = Membership.objects.get_or_create(
                user=user, integration=app, defaults={"role": role}
            )
            if membership.role != role:
                raise CommandError(
                    "An existing membership has a different role; no changes were applied."
                )
            if added:
                Audit.objects.create(
                    integration=app,
                    actor=user,
                    action="scanner.access_granted",
                    object_id=str(user.pk),
                    detail={"role": role, "via": "local_operator"},
                )
        self.stdout.write(
            f"Scanner workspace ready; {len(grants)} explicit memberships checked. Credentials preserved."
        )
