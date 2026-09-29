"""Import retained fixture evidence into the self-assurance scope, never source-app telemetry."""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from bridge.models import Audit, CheckRun, Integration
from bridge.simulation_evidence import SimulationEvidenceError, load_simulation


class Command(BaseCommand):
    help = "Validate and import an existing fixed offline lab run for SignalBridge itself."

    def add_arguments(self, parser):
        parser.add_argument(
            "--run-id", required=True, help="32-character lowercase hexadecimal run ID"
        )
        parser.add_argument(
            "--dry-run", action="store_true", help="Validate without database changes"
        )

    def handle(self, *args, **options):
        if not settings.LOCAL:
            raise CommandError("Simulation evidence import is local-only.")
        try:
            evidence = load_simulation(settings.BASE_DIR, options["run_id"])
        except SimulationEvidenceError as error:
            raise CommandError(f"Simulation import rejected: {error}") from error
        if options["dry_run"]:
            self.stdout.write(
                f"Historical fixture evidence is consistent; coverage {evidence['status']}. No database changes."
            )
            return
        with transaction.atomic():
            try:
                app = Integration.objects.select_for_update().get(slug="signalbridge")
            except Integration.DoesNotExist as error:
                raise CommandError(
                    "Create the SignalBridge self-assurance workspace first."
                ) from error
            existing = CheckRun.objects.filter(
                integration=app,
                result__evidence_kind="offline_simulation",
                result__provenance__run_id=options["run_id"],
            ).first()
            if existing and (
                existing.digest != evidence["digest"] or existing.result != evidence["result"]
            ):
                raise CommandError("Conflicting evidence for an already imported simulation.")
            run, created = CheckRun.objects.get_or_create(
                digest=evidence["digest"],
                defaults={
                    "integration": app,
                    "suite": "Offline detection and bounded-load lab",
                    "revision": evidence["revision"],
                    "status": evidence["status"],
                    "result": evidence["result"],
                },
            )
            if (
                run.integration_id != app.pk
                or run.result != evidence["result"]
                or run.status != evidence["status"]
                or run.revision != evidence["revision"]
            ):
                raise CommandError(
                    "Conflicting simulation digest or workspace; no history was changed."
                )
            if created:
                Audit.objects.create(
                    integration=app,
                    action="simulation.imported",
                    object_id=str(run.pk),
                    detail={
                        "digest": run.digest,
                        "status": run.status,
                        "evidence_kind": "offline_simulation",
                    },
                )
        self.stdout.write(
            "Imported historical offline fixture evidence."
            if created
            else "Simulation already imported; no duplicate created."
        )
