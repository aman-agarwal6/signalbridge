"""Analyst evidence must remain scoped, reproducible and explicit about uncertainty."""

import hashlib
import importlib.util
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from bridge import detection_catalog
from bridge.contract import digest
from bridge.detection_catalog import explain_case
from bridge.engine import detections
from bridge.models import (
    Audit,
    Event,
    Integration,
    Investigation,
    Membership,
    Note,
    WorkerHeartbeat,
)
from bridge.operations import workspace_health
from bridge.services import create_replay


class DetectionWorkbenchTests(TestCase):
    def setUp(self):
        self.app = Integration.objects.create(slug="bettail", name="BetTail")
        self.other = Integration.objects.create(slug="netted", name="Netted")
        self.viewer = get_user_model().objects.create_user(username="reader")
        self.analyst = get_user_model().objects.create_user(username="analyst-audit")
        for user, role in ((self.viewer, "viewer"), (self.analyst, "analyst")):
            Membership.objects.create(user=user, integration=self.app, role=role)
        self.client.force_login(self.viewer)
        now = timezone.now().replace(minute=0, second=10, microsecond=0)
        episode = str(uuid.uuid4())
        self.rows = []
        for number in range(3):
            payload = {
                "schema_version": 1,
                "app": self.app.slug,
                "environment": "test",
                "event_id": str(uuid.uuid4()),
                "episode": episode,
                "occurred_at": (now + timedelta(seconds=number)).isoformat(),
                "actor": "a" * 64,
                "resource": f"{number:064x}",
                "operation": "private_record.read",
                "outcome": "denied",
                "reason": "membership_required",
                "context": None,
            }
            fields = {
                key: value
                for key, value in payload.items()
                if key not in {"schema_version", "app", "context"}
            }
            fields["occurred_at"] = now + timedelta(seconds=number)
            self.rows.append(
                Event.objects.create(
                    integration=self.app,
                    source="migration_lab",
                    payload=payload,
                    digest=digest(payload),
                    available_at=now,
                    state="processed",
                    **fields,
                )
            )
        finding = detections([row.payload for row in self.rows])[0]
        self.case = Investigation.objects.create(
            integration=self.app,
            rule="R1",
            severity="medium",
            title=finding["title"],
            explanation=finding["explanation"],
            correlation=hashlib.sha256(
                ("migration_lab|" + finding["correlation"]).encode()
            ).hexdigest(),
        )
        self.case.events.add(*self.rows)

    def test_rule_match_explains_exact_evidence_without_confidence_score(self):
        result = explain_case(self.case, self.rows)
        self.assertTrue(result["current_match"])
        self.assertEqual(result["distinct_resources"], 3)
        self.assertEqual(result["outcomes"], {"denied": 3})
        self.assertEqual(result["integrity_errors"], 0)
        self.assertNotIn("confidence_score", result)
        self.assertIn("historical", result["limits"][0])

    def test_changed_payload_or_model_fields_are_not_reproduced_as_clean(self):
        self.rows[0].digest = "f" * 64
        result = explain_case(self.case, self.rows)
        self.assertFalse(result["current_match"])
        self.assertEqual(result["integrity_errors"], 1)
        self.rows[0].digest = digest(self.rows[0].payload)
        self.rows[0].outcome = "allowed"
        self.assertEqual(explain_case(self.case, self.rows)["integrity_errors"], 1)

    def test_mixed_sources_fail_current_rule_comparison(self):
        self.rows[0].source = "synthetic_demo"
        result = explain_case(self.case, self.rows)
        self.assertFalse(result["current_match"])
        self.assertIn("Mixed", result["comparison"])

    def test_catalog_and_case_pages_are_scoped_and_script_free(self):
        for target in ("/detections/?app=bettail", f"/investigations/{self.case.pk}/"):
            response = self.client.get(target)
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, "private_record.read")
            self.assertNotContains(response, "<script")
            self.assertIn("no-store", response["Cache-Control"])
        self.assertEqual(self.client.get("/detections/?app=netted").status_code, 404)
        self.client.logout()
        self.assertEqual(self.client.get("/detections/").status_code, 302)

    def test_case_export_has_a_recomputable_digest_and_excludes_notes(self):
        Note.objects.create(
            investigation=self.case, author=self.analyst, text="private analyst note sentinel"
        )
        response = self.client.get(f"/investigations/{self.case.pk}/export/")
        body = response.json()
        self.assertEqual(body["report_sha256"], digest(body["report"]))
        self.assertEqual(len(body["report"]["events"]), 3)
        self.assertNotContains(response, "private analyst note sentinel")
        self.assertTrue(Audit.objects.filter(action="case.exported", integration=self.app).exists())

    def test_export_cannot_cross_application_membership(self):
        self.case.integration = self.other
        self.case.save()
        self.assertEqual(
            self.client.get(f"/investigations/{self.case.pk}/export/").status_code, 404
        )
        self.assertFalse(Audit.objects.filter(action="case.exported").exists())

    def test_disposition_requires_rationale_and_binds_evidence(self):
        self.client.force_login(self.analyst)
        target = f"/investigations/{self.case.pk}/"
        data = {"action": "disposition", "version": 1, "status": "resolved"}
        self.client.post(target, data)
        self.case.refresh_from_db()
        self.assertEqual(self.case.status, "open")
        rationale = "Confirmed expected access and documented the positive retest."
        self.client.post(target, dict(data, rationale=rationale))
        self.case.refresh_from_db()
        self.assertEqual((self.case.status, self.case.version), ("resolved", 2))
        audit = Audit.objects.get(action="case.disposition")
        self.assertEqual(audit.detail["rationale"], rationale)
        self.assertEqual(audit.detail["event_count"], 3)
        self.assertEqual(len(audit.detail["evidence_sha256"]), 64)
        self.assertEqual(Note.objects.get().text, rationale)
        self.client.post(target, dict(data, status="false_positive", rationale=rationale))
        self.assertEqual(Audit.objects.filter(action="case.disposition").count(), 1)

    def test_viewer_cannot_dispose_even_with_rationale(self):
        response = self.client.post(
            f"/investigations/{self.case.pk}/",
            {
                "action": "disposition",
                "version": 1,
                "status": "resolved",
                "rationale": "Attempted viewer change.",
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Note.objects.exists())

    def test_environment_filters_are_enforced(self):
        self.assertEqual(
            self.client.get("/events/?app=bettail&environment=lab").context["result_count"], 0
        )
        self.assertEqual(
            self.client.get("/events/?app=bettail&environment=test").context["result_count"], 3
        )

    def test_health_is_workspace_scoped_and_does_not_treat_silence_as_safety(self):
        self.rows[0].state = "dead"
        self.rows[0].save()
        self.assertEqual(workspace_health(self.app)["queue"]["dead"], 1)
        self.assertEqual(workspace_health(self.other)["streams"], [])
        self.assertEqual(workspace_health(self.other)["queue"]["dead"], 0)
        self.assertContains(
            self.client.get("/detections/?app=bettail"),
            "source silence is not classified as healthy",
        )

    def test_future_or_other_worker_heartbeat_cannot_mask_staleness(self):
        WorkerHeartbeat.objects.create(name="other", last_seen=timezone.now())
        self.assertFalse(workspace_health(self.app)["queue"]["worker_recent"])
        WorkerHeartbeat.objects.create(name="default", last_seen=timezone.now() + timedelta(days=1))
        self.assertFalse(workspace_health(self.app)["queue"]["worker_recent"])
        self.assertFalse(self.client.get("/?app=bettail").context["worker_recent"])

    def test_case_keeps_authorized_capability_lab_navigation(self):
        lab_app = Integration.objects.create(slug="signalbridge", name="SignalBridge")
        Membership.objects.create(user=self.viewer, integration=lab_app, role="viewer")
        self.assertContains(self.client.get(f"/investigations/{self.case.pk}/"), "Capability lab")

    def test_process_fingerprint_does_not_silently_follow_edited_disk_source(self):
        captured = detection_catalog.engine_fingerprint()
        with patch.object(detection_catalog, "_disk_fingerprint", return_value="f" * 64):
            self.assertEqual(detection_catalog.engine_fingerprint(), captured)
            state = detection_catalog.engine_source_state()
            self.assertEqual(state["process_source_sha256"], captured)
            self.assertEqual(state["disk_source_sha256"], "f" * 64)
            self.assertEqual(state["status"], "changed")
            self.assertTrue(state["restart_required"])

    def test_disk_drift_disables_rule_match_but_preserves_evidence_integrity_diagnostics(self):
        self.rows[0].digest = "f" * 64
        with (
            patch.object(detection_catalog, "_disk_fingerprint", return_value="f" * 64),
            patch.object(detection_catalog, "detections") as detect,
        ):
            analysis = explain_case(self.case, self.rows)
            response = self.client.get(f"/investigations/{self.case.pk}/")
        detect.assert_not_called()
        self.assertFalse(analysis["current_match"])
        self.assertEqual(analysis["integrity_errors"], 1)
        self.assertContains(response, "restart before comparing rules")
        self.assertNotContains(response, "Current rule matches linked evidence")

    def test_missing_source_is_graceful_and_does_not_claim_current_rule_match(self):
        captured = detection_catalog.engine_fingerprint()
        with patch.object(detection_catalog.Path, "read_bytes", side_effect=FileNotFoundError):
            analysis = explain_case(self.case, self.rows)
        self.assertEqual(analysis["engine_sha256"], captured)
        self.assertEqual(analysis["engine_source_state"]["status"], "unavailable")
        self.assertIsNone(analysis["engine_source_state"]["disk_source_sha256"])
        self.assertFalse(analysis["current_match"])

    def test_source_change_during_comparison_cannot_leave_a_current_match_claim(self):
        captured = detection_catalog.engine_fingerprint()
        with patch.object(detection_catalog, "_disk_fingerprint", side_effect=[captured, "f" * 64]):
            analysis = explain_case(self.case, self.rows)
        self.assertFalse(analysis["current_match"])
        self.assertEqual(analysis["engine_source_state"]["status"], "changed")

    def test_fresh_module_capture_changes_identity_without_mutating_running_snapshot(self):
        captured = detection_catalog.engine_fingerprint()
        spec = importlib.util.spec_from_file_location(
            "bridge._catalog_snapshot_test", detection_catalog.__file__
        )
        module = importlib.util.module_from_spec(spec)
        with patch.object(detection_catalog.Path, "read_bytes", return_value=b"replacement source"):
            spec.loader.exec_module(module)
            self.assertEqual(
                module.engine_fingerprint(), hashlib.sha256(b"replacement source" * 3).hexdigest()
            )
            self.assertEqual(module.engine_source_state()["status"], "unchanged")
        self.assertEqual(detection_catalog.engine_fingerprint(), captured)

    def test_disposition_keeps_process_identity_and_records_disk_drift(self):
        self.client.force_login(self.analyst)
        captured = detection_catalog.engine_fingerprint()
        with patch.object(detection_catalog, "_disk_fingerprint", return_value="f" * 64):
            self.client.post(
                f"/investigations/{self.case.pk}/",
                {
                    "action": "disposition",
                    "version": 1,
                    "status": "resolved",
                    "rationale": "Historical evidence reviewed; current rule comparison remains unavailable.",
                },
            )
        audit = Audit.objects.get(action="case.disposition")
        self.assertEqual(audit.detail["current_engine_sha256"], captured)
        self.assertEqual(audit.detail["engine_source_state"]["status"], "changed")
        self.assertEqual(audit.detail["engine_source_state"]["disk_source_sha256"], "f" * 64)

    def test_replay_history_survives_unavailable_current_source_without_approval(self):
        proposal = create_replay(self.analyst, self.app, "revised")
        with patch("bridge.views.evaluate", side_effect=ValueError("private-diagnostic-sentinel")):
            response = self.client.get("/replay/?app=bettail")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Current comparison unavailable")
        self.assertContains(response, "Restart SignalBridge")
        self.assertNotContains(response, "private-diagnostic-sentinel")
        displayed = response.context["replays"][0]
        self.assertEqual(displayed.pk, proposal.pk)
        self.assertTrue(displayed.stale)
        self.assertFalse(displayed.can_approve)
        self.assertTrue(response.context["comparison_unavailable"])
