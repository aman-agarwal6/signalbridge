"""Import only complete, stopped, consistency-checked local synthetic SOC pilots."""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from bridge.models import Audit, CheckRun, Integration
from bridge.soc_pilot_evidence import EvidenceError, load_soc_pilot


class Command(BaseCommand):
    help = (
        "Import a fixed local synthetic Wazuh or ZAP receipt; freshly inspect stopped containers."
    )

    def add_arguments(self, parser):
        parser.add_argument("--tool", required=True, choices=("wazuh", "zap"))
        parser.add_argument("--run-id", required=True)
        parser.add_argument(
            "--dry-run", action="store_true", help="Validate without database writes"
        )

    def handle(self, *args, **options):
        if not settings.LOCAL:
            raise CommandError("SOC pilot import is local-only.")
        try:
            evidence = load_soc_pilot(settings.BASE_DIR, options["tool"], options["run_id"])
        except EvidenceError as error:
            raise CommandError(f"SOC pilot import rejected: {error}") from None
        if options["dry_run"]:
            self.stdout.write(
                "Synthetic receipts and fresh stopped gate passed; no database writes."
            )
            return
        with transaction.atomic():
            try:
                app = Integration.objects.select_for_update().get(slug="signalbridge")
            except Integration.DoesNotExist:
                raise CommandError(
                    "Create the SignalBridge integration before importing its pilot."
                ) from None
            existing = CheckRun.objects.filter(
                integration=app,
                result__evidence_kind="soc_pilot",
                result__tool=options["tool"],
                result__pilot__run_id=options["run_id"],
            ).first()
            if existing and (
                existing.digest != evidence["digest"] or existing.result != evidence["result"]
            ):
                raise CommandError("Conflicting pilot evidence; retained history was not changed.")
            run, created = CheckRun.objects.get_or_create(
                digest=evidence["digest"],
                defaults={
                    "integration": app,
                    "suite": f"{options['tool'].upper()} synthetic local pilot",
                    "revision": evidence["revision"],
                    "result": evidence["result"],
                    "status": "passed",
                },
            )
            if (
                run.integration_id != app.pk
                or run.result != evidence["result"]
                or run.status != "passed"
                or run.revision != evidence["revision"]
            ):
                raise CommandError("Conflicting pilot digest; retained history was not changed.")
            if created:
                Audit.objects.create(
                    integration=app,
                    action="soc_pilot.imported",
                    object_id=str(run.pk),
                    detail={
                        "digest": evidence["digest"],
                        "tool": options["tool"],
                        "status": "passed",
                        "evidence_kind": "soc_pilot",
                        "fresh_stopped_gate_at": evidence["fresh_checked_at"],
                    },
                )
        self.stdout.write(
            "Imported builder-operated synthetic pilot receipt; no application assessment or ongoing connection."
            if created
            else "Pilot receipt already imported; no duplicate created."
        )
