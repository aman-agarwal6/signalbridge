import json

from django.conf import settings
from django.core.management.base import BaseCommand

from bridge.models import Audit, Event, Integration


class Command(BaseCommand):
    help = "Produce a sanitized local Wazuh collector file. Does not contact or install Wazuh."

    def add_arguments(self, parser):
        parser.add_argument("app", choices=["bettail", "netted"])

    def handle(self, *args, **options):
        app = Integration.objects.get(slug=options["app"])
        path = settings.VAR_DIR / (app.slug + "-wazuh.jsonl")
        count = 0
        with path.open("w", encoding="utf8", newline="\n") as handle:
            for e in Event.objects.filter(integration=app, state="processed").iterator():
                row = {
                    "signalbridge": {
                        "export_version": 1,
                        "app": app.slug,
                        "environment": e.environment,
                        "event_id": str(e.event_id),
                        "occurred_at": e.occurred_at.isoformat(),
                        "operation": e.operation,
                        "outcome": e.outcome,
                        "reason": e.reason,
                        "source": e.source,
                    }
                }
                handle.write(json.dumps(row, separators=(",", ":")) + "\n")
                count += 1
        Audit.objects.create(
            integration=app,
            action="soc.exported",
            object_id=app.slug,
            detail={"records": count, "integration_verified": False},
        )
        self.stdout.write(
            f"Exported {count} records to {path.name}. Wazuh ingestion remains unverified."
        )
