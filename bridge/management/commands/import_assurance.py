"""Local operator import of verified service evidence; no network or Docker access."""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from bridge.assurance import EvidenceError, load_assurance
from bridge.models import Audit, CheckRun, Integration


class Command(BaseCommand):
    help = "Validate and import a retained BetTail HTTP run with linked local evidence."

    def add_arguments(self, parser):
        parser.add_argument("--run-id", required=True, help="UUID of the fixed local HTTP report")
        parser.add_argument(
            "--dry-run", action="store_true", help="Validate without database writes"
        )

    def handle(self, *args, **options):
        if not settings.LOCAL:
            raise CommandError("Assurance evidence import is local-only.")
        try:
            evidence = load_assurance(settings.BASE_DIR, options["run_id"])
        except EvidenceError as error:
            raise CommandError(f"Assurance import rejected: {error}") from error
        if options["dry_run"]:
            self.stdout.write("Linked local evidence is consistent; no database writes performed.")
            return
        with transaction.atomic():
            try:
                app = Integration.objects.select_for_update().get(slug="bettail")
            except Integration.DoesNotExist as error:
                raise CommandError(
                    "Create the BetTail integration before importing its evidence."
                ) from error
            existing = CheckRun.objects.filter(
                integration=app, result__provenance__run_id=options["run_id"]
            ).first()
            if existing and (
                existing.digest != evidence["digest"] or existing.result != evidence["result"]
            ):
                raise CommandError("Conflicting evidence for an already imported run.")
            run, created = CheckRun.objects.get_or_create(
                digest=evidence["digest"],
                defaults={
                    "integration": app,
                    "suite": "Local Supabase Auth, REST and Storage",
                    "revision": evidence["revision"],
                    "result": evidence["result"],
                    "status": evidence["status"],
                },
            )
            if (
                run.integration_id != app.pk
                or run.result != evidence["result"]
                or run.status != evidence["status"]
                or run.revision != evidence["revision"]
            ):
                raise CommandError("Conflicting evidence digest; no existing record was changed.")
            if created:
                Audit.objects.create(
                    integration=app,
                    action="assurance.imported",
                    object_id=str(run.pk),
                    detail={
                        "digest": evidence["digest"],
                        "status": evidence["status"],
                        "evidence_kind": "supabase_http",
                    },
                )
        self.stdout.write(
            "Imported historical local service evidence."
            if created
            else "Evidence already imported; no duplicate created."
        )
