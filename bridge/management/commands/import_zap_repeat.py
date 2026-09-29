"""Import fixed bounded ZAP execution evidence; no scanner launch or finding writes."""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from bridge.models import Audit, CheckRun, Integration
from bridge.zap_repeat_evidence import KIND, EvidenceError, load_zap_repeat


class Command(BaseCommand):
    help = "Import a historical three-GET ZAP run or verified target-outage exercise."

    def add_arguments(self, parser):
        parser.add_argument("--run-id", required=True)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        if not settings.LOCAL:
            raise CommandError("ZAP repeat import is local-only.")
        try:
            evidence = load_zap_repeat(settings.BASE_DIR, options["run_id"])
        except EvidenceError:
            raise CommandError("ZAP evidence rejected; preserve the run for inspection.") from None
        if options["dry_run"]:
            self.stdout.write(
                "ZAP evidence reconciled and stopped state checked; no database writes."
            )
            return
        with transaction.atomic():
            try:
                # This internal scanner workspace deliberately disables event
                # ingestion. Importing evidence must never enable that endpoint.
                app = Integration.objects.select_for_update().get(
                    slug="signalbridge", enabled=False
                )
            except Integration.DoesNotExist:
                raise CommandError(
                    "The SignalBridge workspace with ingestion disabled is required."
                ) from None
            existing = CheckRun.objects.filter(
                integration=app,
                result__evidence_kind=KIND,
                result__run_id=options["run_id"],
            ).first()
            if existing and (
                existing.digest != evidence["digest"] or existing.result != evidence["result"]
            ):
                raise CommandError("Conflicting ZAP run; existing evidence preserved.")
            run, created = CheckRun.objects.get_or_create(
                digest=evidence["digest"],
                defaults={
                    "integration": app,
                    "suite": "ZAP bounded synthetic execution",
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
                raise CommandError("Conflicting ZAP digest; existing evidence preserved.")
            if created:
                Audit.objects.create(
                    integration=app,
                    action="zap_repeat.imported",
                    object_id=str(run.pk),
                    detail={
                        "digest": evidence["digest"],
                        "run_id": options["run_id"],
                        "scan_status": evidence["status"],
                        "fresh_stopped_gate_at": evidence["fresh_checked_at"],
                    },
                )
        self.stdout.write(
            "Historical ZAP evidence imported; scan status: " + evidence["status"] + "."
            if created
            else "ZAP evidence already imported; no duplicate created."
        )
