"""Capability evidence is historical, scope-bound and honest about misses."""

from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from bridge.contract import digest
from bridge.models import CheckRun, Integration, Membership, Replay


class CapabilityConsoleTests(TestCase):
    def setUp(self):
        self.app = Integration.objects.create(slug="signalbridge", name="SignalBridge")
        self.other = Integration.objects.create(slug="bettail", name="BetTail")
        self.user = get_user_model().objects.create_user(username="lab-reader")
        Membership.objects.create(user=self.user, integration=self.app, role="viewer")
        self.client.force_login(self.user)
        self.run = CheckRun.objects.create(
            integration=self.app,
            suite="Offline capability lab",
            revision="a" * 40,
            digest="b" * 64,
            status="partial",
            result={
                "evidence_kind": "offline_simulation",
                "provenance": {"run_id": "c" * 32, "source_sha256": "d" * 64},
                "simulation": {
                    "started_at": "2026-09-24T04:40:05+00:00",
                    "detection_quality": {
                        "true_positive_scenarios": 4,
                        "false_negative_scenarios": 1,
                        "false_positive_scenarios": 0,
                        "true_negative_scenarios": 10,
                        "recall": 0.8,
                    },
                    "scenarios": [
                        {
                            "id": "bucket_boundary_gap",
                            "expected_rule": "R1",
                            "observed_rules": [],
                            "coverage_met": False,
                        }
                    ],
                    "controls": {},
                    "bounded_load": {},
                },
            },
        )

    def test_known_miss_visible_and_not_green(self):
        response = self.client.get("/lab/?app=signalbridge")
        self.assertEqual(response.status_code, 200)
        for text in (
            "Coverage gap measured",
            "Missed detection",
            "80% recall",
            "not independent attestation",
            "Safety boundaries",
            "not an operating-system sandbox",
        ):
            self.assertContains(response, text)
        self.assertNotContains(response, 'class="badge passed"')
        self.assertIn("no-store", response["Cache-Control"])

    def test_scope_filters_navigation_reports_and_exports(self):
        Membership.objects.filter(user=self.user).delete()
        Membership.objects.create(user=self.user, integration=self.other, role="viewer")
        self.assertEqual(self.client.get("/lab/?app=signalbridge").status_code, 404)
        self.assertEqual(self.client.get("/lab/?app=bettail").status_code, 404)
        self.assertEqual(self.client.get(f"/lab/{self.run.id}/export/").status_code, 404)
        self.assertNotContains(self.client.get("/?app=bettail"), "Capability lab")

    def test_export_digest_and_malformed_selection(self):
        response = self.client.get(f"/lab/{self.run.id}/export/")
        self.assertEqual(response.status_code, 200)
        report = response.json()
        saved = report.pop("export_sha256")
        self.assertEqual(saved, digest(report))
        self.assertEqual(report["status"], "partial")
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertEqual(self.client.get("/lab/?app=signalbridge&run=../bad").status_code, 404)
        self.client.logout()
        self.assertEqual(self.client.get(f"/lab/{self.run.id}/export/").status_code, 302)

    def test_empty_state_is_not_passing_and_other_evidence_is_excluded(self):
        self.run.result = {"evidence_kind": "supabase_http"}
        self.run.save()
        self.assertContains(self.client.get("/lab/?app=signalbridge"), "No capability run imported")
        self.assertEqual(self.client.get(f"/lab/{self.run.id}/export/").status_code, 404)

    def test_failed_results_are_not_green_or_given_the_wrong_cause(self):
        self.run.status = "failed"
        self.run.result["simulation"]["scenarios"] = [
            {
                "id": "authorized_read",
                "expected_rule": None,
                "observed_rules": ["R1"],
                "coverage_met": False,
            }
        ]
        self.run.save()
        response = self.client.get("/lab/?app=signalbridge")
        self.assertContains(response, "Execution recorded coverage failures")
        self.assertContains(response, "Unexpected alert")
        self.assertNotContains(response, "Splitting attempts across a boundary")
        self.assertNotContains(response, "Declared scenarios met their expectations")

    def test_self_scope_checks_redirect_to_the_correct_evidence_category(self):
        self.assertRedirects(self.client.get("/checks/?app=signalbridge"), "/lab/?app=signalbridge")


class PortableReplaySeedTests(TestCase):
    def test_extra_workspaces_do_not_break_or_receive_synthetic_replays(self):
        apps = [
            Integration.objects.create(slug=slug, name=slug)
            for slug in ("bettail", "netted", "signalbridge", "unrelated")
        ]
        for name in ("analyst", "reviewer"):
            user = get_user_model().objects.create_user(username=name)
            for app in apps[:2]:
                Membership.objects.create(user=user, integration=app, role=name)
        call_command("seed_replays", stdout=StringIO())
        self.assertEqual(Replay.objects.count(), 4)
        self.assertFalse(Replay.objects.filter(integration__in=apps[2:]).exists())
        call_command("seed_replays", stdout=StringIO())
        self.assertEqual(Replay.objects.count(), 4)
