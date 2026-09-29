from datetime import timedelta
from io import StringIO

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from bridge.contract import digest
from bridge.models import Audit, Event, Integration, Investigation
from tests.test_security import sample


class RetentionTests(TestCase):
    def test_preview_preserves_everything_and_apply_preserves_linked_and_pending(self):
        app = Integration.objects.create(slug="bettail", name="BetTail")
        rows = []
        for state in ("processed", "processed", "pending", "dead"):
            e = sample()
            rows.append(
                Event.objects.create(
                    integration=app,
                    event_id=e["event_id"],
                    occurred_at=timezone.now(),
                    actor=e["actor"],
                    resource=e["resource"],
                    episode=e["episode"],
                    operation=e["operation"],
                    outcome=e["outcome"],
                    reason=e["reason"],
                    environment=e["environment"],
                    payload=e,
                    digest=digest(e),
                    available_at=timezone.now(),
                    state=state,
                )
            )
        Event.objects.update(received_at=timezone.now() - timedelta(days=100))
        case = Investigation.objects.create(
            integration=app,
            rule="R1",
            correlation="x",
            title="x",
            severity="medium",
            explanation="x",
        )
        case.events.add(rows[0])
        call_command("retention", "bettail", stdout=StringIO())
        self.assertEqual(Event.objects.count(), 4)
        call_command("retention", "bettail", apply=True, stdout=StringIO())
        self.assertEqual(Event.objects.count(), 3)
        self.assertTrue(Event.objects.filter(pk=rows[0].pk).exists())
        self.assertTrue(Audit.objects.filter(action="retention.applied").exists())
