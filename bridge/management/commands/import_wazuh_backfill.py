"""Operator-only import of a bounded, historical BetTail ledger replay."""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from bridge.models import Audit, CheckRun, Integration
from bridge.wazuh_backfill_evidence import EvidenceError, load_backfill


class Command(BaseCommand):
    help = "Validate a fixed BetTail backfill and freshly inspect its stopped container."

    def add_arguments(self, parser):
        parser.add_argument("--run-id", required=True)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        if not settings.LOCAL:
            raise CommandError("Backfill import is local-only.")
        try:
            evidence = load_backfill(settings.BASE_DIR, options["run_id"])
        except EvidenceError:
            raise CommandError(
                "Backfill evidence rejected; preserve the run for inspection."
            ) from None
        if options["dry_run"]:
            self.stdout.write(
                "Backfill reconciled and stopped container verified; no database writes."
            )
            return
        with transaction.atomic():
            try:
                app = Integration.objects.select_for_update().get(slug="bettail", enabled=True)
            except Integration.DoesNotExist:
                raise CommandError("An enabled BetTail workspace is required.") from None
            existing = CheckRun.objects.filter(
                integration=app,
                result__evidence_kind="wazuh_backfill",
                result__run_id=options["run_id"],
            ).first()
            if existing and (
                existing.digest != evidence["digest"] or existing.result != evidence["result"]
            ):
                raise CommandError("Conflicting backfill receipt; existing evidence preserved.")
            run, created = CheckRun.objects.get_or_create(
                digest=evidence["digest"],
                defaults={
                    "integration": app,
                    "suite": "Wazuh retained lab metadata backfill",
                    "revision": evidence["revision"],
                    "status": "passed",
                    "result": evidence["result"],
                },
            )
            if (
                run.integration_id != app.pk
                or run.result != evidence["result"]
                or run.status != "passed"
                or run.revision != evidence["revision"]
            ):
                raise CommandError("Conflicting backfill digest; existing evidence preserved.")
            if created:
                Audit.objects.create(
                    integration=app,
                    action="wazuh_backfill.imported",
                    object_id=str(run.pk),
                    detail={
                        "digest": evidence["digest"],
                        "run_id": options["run_id"],
                        "fresh_stopped_gate_at": evidence["fresh_checked_at"],
                    },
                )
        self.stdout.write(
            "Historical BetTail backfill imported; no continuous connection."
            if created
            else "Backfill already imported; no duplicate created."
        )
