"""Read a fixed completed native header run; never launch or fabricate evidence."""

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from bridge.zap_enterprise_review import import_native_review, load_native_review


class Command(BaseCommand):
    help = "Import a completed native authenticated header review for existing documents/expenses events."

    def add_arguments(self, parser):
        parser.add_argument("--run-id", required=True)
        parser.add_argument("--user-id", required=True, type=int)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        if not settings.LOCAL:
            raise CommandError("Native header import is an isolated local operator procedure.")
        try:
            user = get_user_model().objects.get(pk=options["user_id"])
            evidence = load_native_review(settings.BASE_DIR, options["run_id"])
            _, created = import_native_review(user, evidence, dry_run=options["dry_run"])
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
            PermissionError,
            get_user_model().DoesNotExist,
        ):
            raise CommandError(
                "Native header evidence rejected; preserve the archive for inspection."
            ) from None
        if options["dry_run"]:
            self.stdout.write("Native header review matched; no database writes.")
        else:
            self.stdout.write(
                "Historical native header review imported."
                if created
                else "Native header review already imported; no duplicate created."
            )
