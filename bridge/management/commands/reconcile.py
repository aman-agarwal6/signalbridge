import json

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.utils import timezone

from bridge.models import Event, Investigation


class Command(BaseCommand):
    help = "Independently reconcile event and case counts using SQL."

    def handle(self, *args, **options):
        with connection.cursor() as c:
            c.execute(
                "SELECT i.slug,e.state,COUNT(*) FROM bridge_event e JOIN bridge_integration i ON i.id=e.integration_id GROUP BY i.slug,e.state ORDER BY i.slug,e.state"
            )
            rows = [{"app": r[0], "state": r[1], "count": r[2]} for r in c.fetchall()]
            c.execute("SELECT COUNT(*),COUNT(DISTINCT id) FROM bridge_event")
            total, unique = c.fetchone()
            c.execute("SELECT COUNT(*) FROM bridge_investigation")
            cases = c.fetchone()[0]
        if (
            total != unique
            or total != Event.objects.count()
            or cases != Investigation.objects.count()
            or sum(r["count"] for r in rows) != total
        ):
            raise CommandError("SQL reconciliation failed.")
        data = {
            "executed_at": timezone.now().isoformat(),
            "event_count": total,
            "unique_internal_ids": unique,
            "case_count": cases,
            "groups": rows,
            "status": "passed",
        }
        path = settings.BASE_DIR / "artifacts/local/sql-reconciliation.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n")
        self.stdout.write(json.dumps(data))
