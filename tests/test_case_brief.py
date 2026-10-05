"""Application behavior and confidentiality of the printable internal brief."""

import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase

from bridge.models import CaseTask, Integration, Investigation, Membership, Note
from tests import test_console as console_fixtures


class CaseBriefTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="documents", name="Synthetic documents")
        cls.other = Integration.objects.create(slug="expenses", name="Other app")
        cls.user = get_user_model().objects.create_user(username="brief-analyst")
        cls.membership = Membership.objects.create(
            user=cls.user, integration=cls.app, role="analyst"
        )
        cls.case = Investigation.objects.create(
            integration=cls.app,
            rule="R3",
            correlation="a" * 64,
            title="Access after removal",
            explanation="Source-reported access requires investigation.",
            severity="high",
            status="resolved",
        )
        cls.foreign = Investigation.objects.create(
            integration=cls.other,
            rule="R3",
            correlation="b" * 64,
            title="private-other-case-sentinel",
            severity="high",
        )
        cls.url = f"/investigations/{cls.case.pk}/brief/"

    def setUp(self):
        self.client.force_login(self.user)

    def test_roles_can_read_but_report_cannot_mutate(self):
        for role in ("viewer", "analyst", "reviewer"):
            Membership.objects.filter(pk=self.membership.pk).update(role=role)
            response = self.client.get(self.url)
            self.assertContains(response, "Save as PDF")
            self.assertContains(response, "Not recorded.")
            self.assertContains(response, "A resolved disposition means review is complete")
            self.assertEqual(response["Cache-Control"], "no-store, private")
            self.assertIn("noindex", response["X-Robots-Tag"])
            self.assertIn("script-src 'none'", response["Content-Security-Policy"])
        self.assertEqual(self.client.post(self.url, {"status": "verified"}).status_code, 405)
        self.case.refresh_from_db()
        self.assertEqual(self.case.status, "resolved")

    def test_cross_app_unknown_and_withdrawn_access_denied(self):
        for identifier in (self.foreign.pk, uuid.uuid4()):
            response = self.client.get(f"/investigations/{identifier}/brief/")
            self.assertEqual(response.status_code, 404)
            self.assertNotContains(response, self.foreign.title, status_code=404)
        self.membership.delete()
        self.assertEqual(self.client.get(self.url).status_code, 404)

    def test_anonymous_and_disabled_accounts_cannot_read(self):
        self.client.logout()
        self.assertEqual(self.client.get(self.url).status_code, 302)
        self.client.force_login(self.user)
        get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertEqual(self.client.get(self.url).status_code, 302)

    def test_notes_are_categorized_escaped_and_scoped(self):
        Note.objects.create(
            investigation=self.case,
            author=self.user,
            kind="uncertainty",
            text="<script>alert(1)</script>",
        )
        Note.objects.create(
            investigation=self.foreign, author=self.user, text="other-app-note-sentinel"
        )
        response = self.client.get(self.url)
        self.assertContains(response, "&lt;script&gt;alert(1)&lt;/script&gt;")
        self.assertNotContains(response, "<script>")
        self.assertNotContains(response, "other-app-note-sentinel")
        self.assertContains(response, "May contain analyst notes and account names")
        self.assertContains(response, "Uncertainty")

    def test_partial_notes_are_explicit(self):
        Note.objects.bulk_create(
            [Note(investigation=self.case, author=self.user, text=f"note {n}") for n in range(101)]
        )
        response = self.client.get(self.url)
        self.assertContains(response, "Only the latest 100 notes")
        self.assertNotContains(response, "<p>note 0</p>", html=True)
        self.assertContains(response, "note 100")

    def test_verified_task_without_valid_evidence_is_not_reported_as_verified(self):
        CaseTask.objects.create(
            investigation=self.case,
            created_by=self.user,
            kind="remediation",
            status="verified",
            title="Check the correction",
            evidence_sha256="e" * 64,
            case_version=self.case.version,
        )
        response = self.client.get(self.url)
        self.assertContains(response, "Verification needs review")
        self.assertContains(response, "No verification submission recorded")
        self.assertNotContains(response, "Verified within recorded lab scope")

    def test_event_scope_and_evidence_digest_visible(self):
        # Reuse the existing event factory without inheriting or rerunning its suite.
        from django.utils import timezone

        self.now, self.episode = timezone.now(), uuid.uuid4()
        event = console_fixtures.ConsoleTests.make_event.__func__(self, source="instrumented_lab")
        foreign = console_fixtures.ConsoleTests.make_event.__func__(
            self, integration=self.other, reason="foreign-evidence-sentinel"
        )
        self.case.events.add(event, foreign)
        response = self.client.get(self.url)
        self.assertContains(response, str(event.event_id))
        self.assertContains(response, event.digest)
        self.assertNotContains(response, str(foreign.event_id))
        self.assertNotContains(response, "foreign-evidence-sentinel")
        self.assertContains(response, "1 linked observation")

    def test_case_page_links_to_brief(self):
        self.assertContains(
            self.client.get(f"/investigations/{self.case.pk}/"), f'href="{self.url}"'
        )
