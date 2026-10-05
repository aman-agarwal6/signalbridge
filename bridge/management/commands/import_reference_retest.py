"""Trusted local operator imports one retained native proof, with no lab startup."""

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from bridge.models import Investigation
from bridge.reference_retest import import_retest, load_native_retest
from bridge.services import WorkflowError
from integrations.enterprise.verification import LabControlError


class Command(BaseCommand):
    help = "Revalidate a native source archive and attach its retest to an existing matching case."

    def add_arguments(self, parser):
        parser.add_argument("--run-id", required=True)
        parser.add_argument("--local-database-operator", action="store_true", required=True)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        if not settings.LOCAL or not options["local_database_operator"]:
            raise CommandError("Only the trusted local database operator may import this evidence.")
        try:
            result = load_native_retest(settings.BASE_DIR, options["run_id"])
            _, created = import_retest(result, dry_run=options["dry_run"])
        except (
            LabControlError,
            WorkflowError,
            ValueError,
            TypeError,
            KeyError,
            OSError,
            ValidationError,
            Investigation.DoesNotExist,
        ):
            raise CommandError(
                "Native retest import rejected; review the retained archive and matching case."
            ) from None
        self.stdout.write(
            "Matching retest validated; no writes."
            if options["dry_run"]
            else "Native retest imported."
            if created
            else "Already imported; no duplicate."
        )
