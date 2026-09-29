"""Scoped console read-cost regressions using only a disposable Django test database."""

import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import RequestFactory, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from bridge import views
from bridge.contract import digest
from bridge.models import CheckRun, Event, Integration, Investigation, Membership


class ConsoleEfficiencyTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(username="console-read-cost")
        cls.app = Integration.objects.create(slug="bettail", name="BetTail")
        cls.lab = Integration.objects.create(slug="signalbridge", name="SignalBridge")
        cls.other = Integration.objects.create(slug="netted", name="Netted")
        for app in (cls.app, cls.lab):
            Membership.objects.create(user=cls.user, integration=app, role="viewer")
        now = timezone.now()
        events = []
        for index in range(50):
            value = {
                "schema_version": 1,
                "app": "bettail",
                "environment": "test",
                "event_id": str(uuid.uuid4()),
                "episode": str(uuid.uuid4()),
                "occurred_at": (now - timedelta(seconds=50 - index)).isoformat(),
                "actor": "a" * 64,
                "resource": f"{index:064x}",
                "operation": "private_record.read",
                "outcome": "denied",
                "reason": "membership_required",
                "context": None,
            }
            events.append(
                Event(
                    integration=cls.app,
                    payload=value,
                    digest=digest(value),
                    source="migration_lab" if index < 49 else "synthetic_demo",
                    available_at=now,
                    state=("dead" if index == 0 else "pending" if index == 1 else "processed"),
                    **{
                        key: value[key]
                        for key in (
                            "event_id",
                            "episode",
                            "occurred_at",
                            "actor",
                            "resource",
                            "operation",
                            "outcome",
                            "reason",
                            "environment",
                        )
                    },
                )
            )
        Event.objects.bulk_create(events)
        cls.case_ids = []
        for index in range(3):
            case = Investigation.objects.create(
                integration=cls.app,
                rule="R1",
                correlation=f"{index:064x}",
                title=f"Scoped case {index}",
                severity="medium",
                explanation="Synthetic read-cost evidence",
            )
            case.events.add(*events)
            cls.case_ids.append(case.pk)
        CheckRun.objects.create(
            integration=cls.app,
            suite="Test-only receipt",
            revision="a" * 40,
            digest="b" * 64,
            status="passed",
            result={"checks": [{"id": "one", "status": "passed"}]},
        )

    def setUp(self):
        self.client.force_login(self.user)

    def request_cost(self, path):
        with (
            CaptureQueriesContext(connection) as queries,
            patch.object(Event, "from_db", wraps=Event.from_db) as hydrated,
        ):
            response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        return response, len(queries), hydrated.call_count, list(queries)

    def test_request_costs_stay_bounded_without_loading_all_case_event_payloads(self):
        limits = {
            "/?app=bettail": (13, 16),
            "/investigations/?app=bettail": (9, 9),
            "/integrations/?app=bettail": (8, 0),
            "/lab/?app=signalbridge": (6, 0),
            "/findings/?app=signalbridge": (9, 0),
        }
        for path, (query_limit, hydration_limit) in limits.items():
            with self.subTest(path=path):
                _, count, hydrated, queries = self.request_cost(path)
                self.assertLessEqual(count, query_limit)
                self.assertLessEqual(hydrated, hydration_limit)
                self.assertFalse(any('"bridge_event"."payload"' in item["sql"] for item in queries))

    def test_scope_cost_and_membership_boundaries(self):
        request = RequestFactory().get("/?app=bettail")
        request.user = self.user
        with CaptureQueriesContext(connection) as queries:
            context = views.scope(request)
            apps = list(context["apps"])
        self.assertEqual(len(queries), 2)
        self.assertEqual({app.slug for app in apps}, {"bettail", "signalbridge"})
        self.assertEqual(context["app"].pk, self.app.pk)
        self.assertEqual(context["lab_app"].pk, self.lab.pk)
        self.assertEqual(context["role"], "viewer")
        self.assertFalse(context["can_write"])
        self.assertEqual(context["nav_open_count"], 3)
        self.assertEqual(self.client.get("/?app=netted").status_code, 404)

    def test_evidence_export_cost_and_counts(self):
        with CaptureQueriesContext(connection) as queries:
            report = views.evidence(self.app)
        self.assertEqual(len(queries), 4)
        self.assertEqual(
            report["counts"],
            {
                "accepted_events": 50,
                "processed_events": 48,
                "pending_events": 1,
                "dead_events": 1,
                "investigations": 3,
            },
        )
        self.assertEqual(
            report["telemetry_sources"],
            {"migration_lab": 49, "synthetic_demo": 1, "legacy_unclassified": 0},
        )

    def test_case_preview_sources_and_totals_cover_all_scoped_evidence(self):
        response, _, _, _ = self.request_cost("/investigations/?app=bettail")
        for case in response.context["cases"]:
            self.assertEqual(case.evidence_count, 50)
            self.assertEqual(len(case.preview_events), 3)
            self.assertEqual(set(case.source_labels), {"Observed SQL lab", "Synthetic fixture"})
            self.assertEqual([event.source for event in case.preview_events], ["migration_lab"] * 3)

    def test_full_page_loads_at_most_three_events_per_case_in_fixed_queries(self):
        events = list(Event.objects.filter(integration=self.app))
        for index in range(3, 23):
            case = Investigation.objects.create(
                integration=self.app,
                rule="R1",
                correlation=f"{index:064x}",
                title=f"Additional case {index}",
                severity="medium",
                explanation="Test-only evidence",
            )
            case.events.add(*events)
        response, queries, hydrated, captured = self.request_cost("/investigations/?app=bettail")
        self.assertEqual(len(response.context["cases"]), 20)
        self.assertLessEqual(queries, 9)
        self.assertEqual(hydrated, 60)
        self.assertIn("ROW_NUMBER()", " ".join(row["sql"] for row in captured))
        response, queries, hydrated, _ = self.request_cost("/investigations/?app=bettail&p=2")
        self.assertEqual(len(response.context["cases"]), 3)
        self.assertLessEqual(queries, 9)
        self.assertEqual(hydrated, 9)

    def test_inconsistent_foreign_link_cannot_leak_into_preview_labels_or_counts(self):
        foreign = Event.objects.order_by("occurred_at").first()
        foreign.pk = None
        foreign.integration = self.other
        foreign.event_id = uuid.uuid4()
        foreign.source = "legacy_unclassified"
        foreign.save()
        case = Investigation.objects.get(pk=self.case_ids[0])
        case.events.add(foreign)
        response, _, _, _ = self.request_cost("/investigations/?app=bettail")
        shown = next(row for row in response.context["cases"] if row.pk == case.pk)
        self.assertEqual(shown.evidence_count, 50)
        self.assertNotIn("Earlier development record", shown.source_labels)
        self.assertNotIn(foreign.pk, [event.pk for event in shown.preview_events])
        self.assertEqual(views.evidence(self.app)["counts"]["accepted_events"], 50)

    def test_case_scope_comes_from_authorized_object_not_conflicting_query_string(self):
        response = self.client.get(f"/investigations/{self.case_ids[0]}/?app=netted")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["app"].pk, self.app.pk)
        Membership.objects.filter(user=self.user, integration=self.app).delete()
        self.assertEqual(self.client.get(f"/investigations/{self.case_ids[0]}/").status_code, 404)

    def test_default_scope_and_empty_memberships_remain_explicit(self):
        request = RequestFactory().get("/")
        request.user = self.user
        self.assertEqual(views.scope(request)["app"].pk, self.app.pk)
        Membership.objects.filter(user=self.user).delete()
        self.assertEqual(self.client.get("/").status_code, 404)

    def test_capability_history_does_not_load_repeated_simulation_json(self):
        simulation = {
            "detection_quality": {
                "true_positive_scenarios": 5,
                "false_negative_scenarios": 0,
                "recall": 1,
            },
            "scenarios": [],
        }
        for index in range(24):
            CheckRun.objects.create(
                integration=self.lab,
                suite="Test history",
                revision="c" * 40,
                digest=f"{index + 100:064x}",
                status="passed",
                result={"evidence_kind": "offline_simulation", "simulation": simulation},
            )
        with patch.object(CheckRun, "from_db", wraps=CheckRun.from_db) as hydrated:
            response, queries, _, _ = self.request_cost("/lab/?app=signalbridge")
        self.assertLessEqual(queries, 6)
        self.assertEqual(len(response.context["runs"]), 20)
        full_reports = [call for call in hydrated.call_args_list if "result" in call.args[1]]
        self.assertEqual(len(full_reports), 1)
