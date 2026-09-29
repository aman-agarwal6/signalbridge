"""Console behavior: scope, accurate summaries, filters, disclosure data and review gates."""

import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from bridge.models import CheckRun, Event, Integration, Investigation, Membership, WorkerHeartbeat
from bridge.services import create_replay


class ConsoleTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="bettail", name="BetTail")
        cls.other = Integration.objects.create(slug="netted", name="Netted")
        cls.viewer = get_user_model().objects.create_user(username="console-viewer")
        cls.reviewer = get_user_model().objects.create_user(username="console-reviewer")
        cls.author = get_user_model().objects.create_user(username="console-author")
        for user, role in (
            (cls.viewer, "viewer"),
            (cls.reviewer, "reviewer"),
            (cls.author, "analyst"),
        ):
            Membership.objects.create(user=user, integration=cls.app, role=role)
        cls.now = timezone.now()
        cls.episode = uuid.uuid4()
        cls.sql_event = cls.make_event(source="migration_lab", outcome="denied")
        cls.fixture_event = cls.make_event(
            source="synthetic_demo", outcome="allowed", state="pending"
        )
        cls.old_event = cls.make_event(
            source="legacy_unclassified",
            outcome="not_visible",
            occurred_at=cls.now - timedelta(days=40),
        )
        cls.foreign_event = cls.make_event(integration=cls.other, reason="foreign-event-sentinel")
        cls.critical = cls.make_case(title="Revocation review", severity="critical", rule="R2")
        cls.critical.events.add(cls.fixture_event)
        cls.medium = cls.make_case(title="Repeated access", severity="medium", rule="R1")
        cls.medium.events.add(cls.sql_event)
        cls.resolved = cls.make_case(
            title="Closed review", severity="critical", rule="R2", status="resolved"
        )
        cls.foreign_case = cls.make_case(integration=cls.other, title="foreign-case-sentinel")
        cls.foreign_case.events.add(cls.foreign_event)
        cls.check_run = CheckRun.objects.create(
            integration=cls.app,
            suite="Database checks",
            revision="a" * 40,
            digest="b" * 64,
            status="failed",
            result={
                "checks": [
                    {"id": "member", "status": "passed", "duration_ms": 5},
                    {"id": "outsider", "status": "failed", "duration_ms": 7},
                ],
                "migration_hashes": [{"file": "001_test.sql", "sha256": "c" * 64}],
                "duration_ms": 12,
            },
        )

    @classmethod
    def make_event(cls, **changes):
        fields = dict(
            integration=cls.app,
            event_id=uuid.uuid4(),
            occurred_at=cls.now - timedelta(minutes=5),
            actor="a" * 64,
            resource="b" * 64,
            episode=cls.episode,
            operation="private_record.read",
            outcome="denied",
            reason="membership_required",
            environment="test",
            source="migration_lab",
            payload={"note": "<script>sentinel()</script>"},
            digest="d" * 64,
            available_at=cls.now,
            state="processed",
        )
        fields.update(changes)
        return Event.objects.create(**fields)

    @classmethod
    def make_case(cls, **changes):
        fields = dict(
            integration=cls.app,
            title="Case",
            rule="R1",
            correlation=uuid.uuid4().hex,
            severity="medium",
            explanation="Recorded local evidence",
        )
        fields.update(changes)
        return Investigation.objects.create(**fields)

    def setUp(self):
        self.client.force_login(self.viewer)

    def test_all_console_screens_render_without_scripts(self):
        for url in (
            "/",
            "/events/",
            "/investigations/",
            f"/investigations/{self.critical.pk}/",
            "/checks/",
            "/replay/",
            "/integrations/",
            "/requirements/",
        ):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertIn("script-src 'none'", response["Content-Security-Policy"])
                self.assertEqual(response["Cache-Control"], "no-store, private")
                self.assertNotContains(response, "<script")
                self.assertNotContains(response, "foreign-case-sentinel")
                self.assertNotContains(response, "foreign-event-sentinel")

    def test_event_explorer_requires_membership_and_login(self):
        self.assertEqual(self.client.get("/events/?app=netted").status_code, 404)
        self.client.logout()
        self.assertEqual(self.client.get("/events/").status_code, 302)

    def test_combined_event_filters_do_not_cross_sources_or_apps(self):
        response = self.client.get(
            "/events/",
            {
                "source": "migration_lab",
                "outcome": "denied",
                "state": "processed",
                "range": "24h",
                "q": "membership",
            },
        )
        self.assertEqual(response.context["result_count"], 1)
        self.assertEqual(list(response.context["events"]), [self.sql_event])

    def test_uuid_search_and_episode_pivot(self):
        response = self.client.get("/events/", {"q": str(self.sql_event.event_id)})
        self.assertEqual(list(response.context["events"]), [self.sql_event])
        response = self.client.get("/events/", {"q": str(self.episode)})
        self.assertEqual(response.context["result_count"], 3)

    def test_calendar_day_and_time_window(self):
        self.assertEqual(self.client.get("/events/", {"range": "7d"}).context["result_count"], 2)
        self.assertEqual(
            self.client.get(
                "/events/", {"day": self.old_event.occurred_at.date().isoformat()}
            ).context["result_count"],
            1,
        )
        self.assertEqual(
            self.client.get(
                "/events/", {"day": "not-a-date", "state": "invalid", "p": "bad"}
            ).context["result_count"],
            3,
        )

    def test_event_pagination_preserves_filters_and_escapes_metadata(self):
        for _ in range(26):
            self.make_event()
        first = self.client.get("/events/", {"source": "migration_lab"})
        second = self.client.get("/events/", {"source": "migration_lab", "p": 2})
        self.assertEqual(first.context["result_count"], 27)
        self.assertEqual(len(first.context["events"]), 25)
        self.assertEqual(len(second.context["events"]), 2)
        self.assertFalse(set(first.context["events"]) & set(second.context["events"]))
        self.assertContains(first, "source=migration_lab&amp;p=2")
        self.assertContains(first, "&lt;script&gt;sentinel()&lt;/script&gt;")
        self.assertNotContains(first, "<script>sentinel")

    def test_related_cases_are_scoped_even_if_link_is_inconsistent(self):
        self.foreign_case.events.add(self.sql_event)
        response = self.client.get("/events/", {"q": str(self.sql_event.event_id)})
        self.assertNotContains(response, "foreign-case-sentinel")
        self.assertContains(response, "Repeated access")

    def test_case_previews_and_timeline_exclude_foreign_evidence(self):
        self.critical.events.add(self.foreign_event)
        for url in ("/", "/investigations/", f"/investigations/{self.critical.pk}/"):
            self.assertNotContains(self.client.get(url), "foreign-event-sentinel")
        response = self.client.get("/investigations/", {"q": str(self.critical.pk)})
        case = response.context["cases"][0]
        self.assertEqual(case.evidence_count, 1)
        self.assertEqual(len(case.preview_events), 1)

    def test_case_filters_sort_and_status_counts(self):
        response = self.client.get(
            "/investigations/",
            {"status": "open", "severity": "critical", "rule": "R2", "q": "revocation"},
        )
        self.assertEqual(response.context["cases"], [self.critical])
        self.assertEqual(response.context["total_cases"], 3)
        self.assertEqual(response.context["status_counts"], {"open": 2, "resolved": 1})
        response = self.client.get("/investigations/", {"status": "open", "sort": "priority"})
        self.assertEqual(response.context["cases"], [self.critical, self.medium])

    def test_status_tab_keeps_search_and_resets_pagination(self):
        response = self.client.get(
            "/investigations/", {"q": "review", "severity": "critical", "p": 2}
        )
        self.assertContains(response, "q=review&amp;severity=critical&amp;status=open")
        self.assertNotContains(response, "p=2&amp;status=open")

    def test_overview_counts_real_scope_and_open_cases(self):
        with patch("bridge.views.timezone.now", return_value=self.now):
            response = self.client.get("/")
        self.assertEqual(response.context["event_count"], 3)
        self.assertEqual(response.context["case_count"], 2)
        self.assertEqual(response.context["critical_count"], 1)
        self.assertEqual(response.context["activity_total"], 2)
        self.assertEqual(sum(day["count"] for day in response.context["activity"]), 2)
        self.assertEqual(sum(source["count"] for source in response.context["source_counts"]), 3)
        self.assertEqual(response.context["passed_checks"], 1)
        self.assertEqual(response.context["cases"], [self.critical, self.medium])
        self.assertFalse(response.context["worker_recent"])

    def test_old_worker_heartbeat_never_reads_as_recent(self):
        WorkerHeartbeat.objects.create(name="test", last_seen=self.now - timedelta(minutes=5))
        self.assertFalse(self.client.get("/").context["worker_recent"])

    def test_empty_scoped_workspace_has_honest_zero_and_no_run(self):
        Membership.objects.create(user=self.viewer, integration=self.other, role="viewer")
        Event.objects.filter(integration=self.other).delete()
        self.foreign_case.delete()
        response = self.client.get("/", {"app": "netted"})
        self.assertEqual(response.context["event_count"], 0)
        self.assertContains(response, "No open investigations")
        self.assertContains(response, "Not run")

    def test_case_disposition_shows_saved_value(self):
        self.client.force_login(self.reviewer)
        response = self.client.get(f"/investigations/{self.resolved.pk}/")
        self.assertContains(response, 'value="resolved" selected')
        self.assertNotContains(response, 'value="open" selected')

    def test_unsafe_stale_and_self_review_buttons_explain_block(self):
        self.client.force_login(self.reviewer)
        unsafe = create_replay(self.author, self.app, "unsafe")
        own = create_replay(self.reviewer, self.app, "revised")
        response = self.client.get("/replay/")
        self.assertContains(response, "A separate reviewer must decide on your proposal.")
        self.assertContains(
            response, "Approval is unavailable because required suspicious coverage was lost."
        )
        unsafe.result["safe"] = True
        unsafe.save()
        response = self.client.get("/replay/")
        self.assertContains(response, "This evidence is stale. Both review actions are blocked.")
        decisions = {r.pk: r.can_approve for r in response.context["replays"]}
        self.assertFalse(decisions[unsafe.pk])
        self.assertFalse(decisions[own.pk])
