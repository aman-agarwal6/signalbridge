import json

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from bridge.contract import digest
from bridge.models import Audit, CheckRun, Integration


class Command(BaseCommand):
    help = "Import this workspace's local app-check evidence. No remote artifact upload."

    def handle(self, *args, **options):
        path = settings.BASE_DIR / "artifacts/local/app-checks.json"
        if not path.exists():
            raise CommandError("Run the actual app checks first.")
        data = json.loads(path.read_text())
        if data.get("environment") != "ephemeral-pglite" or not data.get("apps"):
            raise CommandError("Invalid evidence source.")
        with transaction.atomic():
            for row in data["apps"]:
                app = Integration.objects.get(slug=row["app"])
                if not row.get("checks") or not row.get("migration_hashes"):
                    raise CommandError("Empty check run cannot establish evidence.")
                key = digest({"executed_at": data["executed_at"], "row": row})
                run, created = CheckRun.objects.get_or_create(
                    digest=key,
                    defaults={
                        "integration": app,
                        "suite": "Repository PostgreSQL authorization checks",
                        "revision": row["revision"],
                        "result": dict(
                            row,
                            executed_at=data["executed_at"],
                            limitations=data["limitations"],
                        ),
                        "status": row["status"],
                    },
                )
                if created:
                    Audit.objects.create(
                        integration=app,
                        action="checks.imported",
                        object_id=str(run.pk),
                        detail={"digest": key, "status": row["status"]},
                    )
        self.stdout.write(
            "Imported actual local check results, including source hashes and limitations."
        )
