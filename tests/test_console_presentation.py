"""An operator must distinguish native provenance and incomplete collection."""

import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from bridge.models import Event, Integration, Membership


class ConsolePresentationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="documents", name="Private documents")
        cls.user = get_user_model().objects.create_user(username="presentation-analyst")
        Membership.objects.create(user=cls.user, integration=cls.app, role="analyst")
        cls.event = Event.objects.create(
            integration=cls.app,
            event_id=uuid.uuid4(),
            occurred_at=timezone.now(),
            actor="a" * 64,
            resource="b" * 64,
            episode=uuid.uuid4(),
            operation="private_record.read",
            outcome="denied",
            reason="membership_required",
            source="instrumented_lab",
            environment="lab",
            payload={},
            digest="c" * 64,
            state="dead",
            available_at=timezone.now(),
        )

    def setUp(self):
        self.client.force_login(self.user)

    def test_native_source_is_distinct_and_failed_queue_has_relevant_action(self):
        response = self.client.get("/?app=documents")
        self.assertContains(response, "Instrumented application observations")
        self.assertContains(response, 'class="source-symbol source-instrumented_lab">APP')
        self.assertContains(response, "Failed records need review; detection may be incomplete.")
        self.assertContains(response, "/events/?app=documents&amp;state=dead")
        self.assertContains(response, 'id="main" tabindex="-1"')
        html = response.content.decode()
        self.assertLess(html.index('id="priority-queue"'), html.index('class="overview-charts"'))

    def test_enabled_ingestion_is_not_presented_as_current_tool_connection(self):
        response = self.client.get("/integrations/?app=documents")
        self.assertContains(response, "Ingestion configured")
        self.assertNotContains(response, "Collector enabled")
        self.assertContains(response, "it does not establish a connection now")
        self.assertContains(response, 'id="delivery-evidence"')
        self.assertNotContains(response, 'id="delivery-evidence" open')
        self.assertContains(response, 'href="#delivery-evidence"')
        self.assertContains(response, 'id="collection-state"')
        self.assertContains(response, "Not integrated")
