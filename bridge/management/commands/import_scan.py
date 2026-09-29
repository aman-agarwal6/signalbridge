from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from bridge.findings import MAX_REPORT_BYTES, import_scan
from bridge.models import Integration


class Command(BaseCommand):
    help = "Import local SARIF, pip-audit or fixed-lab ZAP JSON as unverified scanner claims."

    def add_arguments(self, parser):
        parser.add_argument("app", help="Existing app slug")
        parser.add_argument("file", type=Path)
        parser.add_argument("--format", required=True, choices=["sarif", "pip-audit", "zap"])
        parser.add_argument("--user", required=True, help="Existing analyst/reviewer username")

    def handle(self, *args, **options):
        try:
            app = Integration.objects.get(slug=options["app"])
            user = get_user_model().objects.get(username=options["user"])
        except (Integration.DoesNotExist, get_user_model().DoesNotExist):
            raise CommandError("Use an existing app and authorized local account.") from None
        try:
            with options["file"].open("rb") as handle:
                raw = handle.read(MAX_REPORT_BYTES + 1)
            run, created = import_scan(user, app, raw, options["format"])
        except PermissionError:
            raise CommandError("This account cannot import reports for this app.") from None
        except (OSError, ValueError):
            raise CommandError(
                "Report could not be imported: invalid, oversized or unreadable input."
            ) from None
        self.stdout.write(
            f"{'Imported' if created else 'Already imported'} report {run.pk}; "
            f"{run.finding_count} findings; coverage {run.coverage_status}. "
            "Report claims do not establish scanner execution."
        )
