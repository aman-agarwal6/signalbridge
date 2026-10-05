"""Explicit identity linking by the trusted local database operator, never a web API."""

import sys
import uuid

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError
from django.views.decorators.debug import sensitive_variables

from bridge.federation import FederationDenied, provision_identity, set_identity_enabled
from bridge.federation_operator import prune_expired_runtime, recover_local_account


class Command(BaseCommand):
    help = "Manage explicit identity links, recover linked accounts or prune expired runtime rows."

    def add_arguments(self, parser):
        parser.add_argument(
            "action", choices=["provision", "disable", "enable", "recover", "prune"]
        )
        parser.add_argument("--local-database-operator", action="store_true")
        parser.add_argument("--issuer")
        parser.add_argument("--username")
        parser.add_argument("--identity-id")
        parser.add_argument(
            "--apply", action="store_true", help="Delete one expired runtime batch."
        )

    @sensitive_variables("data")
    def handle(self, *args, **options):
        if not options["local_database_operator"]:
            raise CommandError("This operation requires explicit trusted local database operation.")
        try:
            if options["action"] == "prune":
                if options["issuer"] or options["username"] or options["identity_id"]:
                    raise FederationDenied()
                counts = prune_expired_runtime(apply=options["apply"])
                mode = "Deleted" if options["apply"] else "Eligible; preview only"
                self.stdout.write(mode + ": " + ", ".join(f"{k}={v}" for k, v in counts.items()))
                return
            if options["apply"]:
                raise FederationDenied()
            if options["action"] == "recover":
                if options["issuer"] or options["username"] or not options["identity_id"]:
                    raise FederationDenied()
                if sys.stdin.isatty():
                    raise CommandError("Provide the new password through private redirected input.")
                data = sys.stdin.read(131)
                if data.endswith("\r\n"):
                    data = data[:-2]
                elif data.endswith("\n"):
                    data = data[:-1]
                links = recover_local_account(uuid.UUID(options["identity_id"]), data)
                self.stdout.write(
                    f"Local recovery recorded; {links} provider links disabled. "
                    "Existing roles retained. Re-enable links only after provider recovery."
                )
                return
            if options["action"] == "provision":
                if options["identity_id"] or not options["issuer"] or not options["username"]:
                    raise FederationDenied()
                # The subject is private account metadata; keep it out of process arguments.
                if sys.stdin.isatty():
                    raise CommandError(
                        "Provide one subject through private redirected standard input."
                    )
                data = sys.stdin.read(258)
                if data.endswith("\r\n"):
                    data = data[:-2]
                elif data.endswith("\n"):
                    data = data[:-1]
                if "\r" in data or "\n" in data:
                    raise FederationDenied()
                user = get_user_model().objects.filter(username=options["username"]).first()
                if user is None:
                    raise FederationDenied()
                identity, changed = provision_identity(
                    issuer=options["issuer"], subject=data, user_id=user.pk
                )
            else:
                if options["issuer"] or options["username"] or not options["identity_id"]:
                    raise FederationDenied()
                identity_id = uuid.UUID(options["identity_id"])
                identity, changed = set_identity_enabled(
                    identity_id, enabled=options["action"] == "enable"
                )
        except (FederationDenied, IntegrityError, ValueError):
            raise CommandError(
                "Identity operation rejected; no provider claims or account data printed."
            ) from None
        self.stdout.write(
            f"Identity {identity.pk}: {'changed' if changed else 'already configured'}."
        )
