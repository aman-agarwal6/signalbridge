import json
import secrets

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from bridge.models import IngestKey, Integration, Membership


def ensure_synthetic_keys():
    path = settings.VAR_DIR / "synthetic-keys.json"
    if not path.exists():
        with path.open("x") as handle:
            json.dump({app: secrets.token_hex(32) for app in ("bettail", "netted")}, handle)
    for app in Integration.objects.filter(slug__in=("bettail", "netted")):
        IngestKey.objects.get_or_create(
            key_id=app.slug + "-synthetic-v1",
            defaults={
                "integration": app,
                "secret_env": "SB_" + app.slug.upper() + "_SYNTH_KEY",
                "source": "synthetic_demo",
                "environment": "lab",
            },
        )


class Command(BaseCommand):
    help = "Create local lab accounts and keys once; never resets existing credentials."

    def handle(self, *args, **options):
        if not settings.LOCAL:
            raise CommandError("Bootstrap is local-only.")
        access = settings.VAR_DIR / "local-access.txt"
        if access.exists():
            ensure_synthetic_keys()
            self.stdout.write("Local access already exists; credentials preserved.")
            return
        users = get_user_model()
        if users.objects.filter(username__in=["analyst", "reviewer", "viewer"]).exists():
            raise CommandError(
                "Existing demo username found; provision accounts explicitly instead of replacing it."
            )
        lines = [
            "SignalBridge local lab access — private, do not publish.",
            "URL: http://127.0.0.1:8741/",
            "",
        ]
        with transaction.atomic():
            apps = []
            for slug, name in [("bettail", "BetTail"), ("netted", "Netted")]:
                app, _ = Integration.objects.get_or_create(
                    slug=slug,
                    defaults={
                        "name": name,
                        "coverage": "Local test-runner telemetry and migration checks only; hosted app not connected.",
                    },
                )
                apps.append(app)
                env = "SB_" + slug.upper() + "_LAB_KEY"
                IngestKey.objects.get_or_create(
                    key_id=slug + "-lab-v1",
                    defaults={"integration": app, "secret_env": env},
                )
            for role in ("analyst", "reviewer", "viewer"):
                password = secrets.token_urlsafe(20)
                user = users.objects.create_user(username=role, password=password)
                for app in apps:
                    Membership.objects.create(user=user, integration=app, role=role)
                lines.append(role + ": " + password)
            keys = {a.slug: secrets.token_hex(32) for a in apps}
            with (settings.VAR_DIR / "lab-keys.json").open("x") as handle:
                json.dump(keys, handle)
            with access.open("x") as handle:
                handle.write("\n".join(lines) + "\n")
        ensure_synthetic_keys()
        self.stdout.write(
            "Created local accounts. Credentials: var/local-access.txt (ignored by Git)."
        )
