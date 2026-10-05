"""Import one scoped retained execution; no manager launch or event creation."""

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.core.management.base import BaseCommand, CommandError

from bridge.wazuh_native_review import (
    APPS,
    PUBLICATION_PROFILE,
    import_native_review,
    load_native_review,
)


class Command(BaseCommand):
    help = "Revalidate and import a historical native Wazuh receipt for one authorized app."

    def add_arguments(self, parser):
        parser.add_argument("--run-id", required=True)
        parser.add_argument("--app", choices=APPS, required=True)
        parser.add_argument("--user-id", type=int, required=True)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        if not settings.LOCAL:
            raise CommandError("Native Wazuh import is a local operator procedure.")
        try:
            user = get_user_model().objects.get(pk=options["user_id"])
            scopes = load_native_review(settings.BASE_DIR, options["run_id"])
            _, created, links = import_native_review(
                user, scopes[options["app"]], dry_run=options["dry_run"]
            )
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
            ObjectDoesNotExist,
        ):
            raise CommandError(
                "Native Wazuh evidence rejected; preserve the retained archive for review."
            ) from None
        self.stdout.write(
            "Historical native receipt validated; no database writes."
            if options["dry_run"]
            else "Historical native receipt imported; shutdown was verified at the end of that run."
            if created
            else "Historical native receipt already imported; no duplicate created."
        )
        if scopes[options["app"]]["profile"] == PUBLICATION_PROFILE:
            self.stdout.write(
                "Recorded replay after native empty-file readiness; current connectivity and continuous delivery remain unverified."
            )
        self.stdout.write(
            f"Local event links: {links['matched_events']} matched; {links['unmatched_events']} unmatched. No source events or cases were created."
        )
