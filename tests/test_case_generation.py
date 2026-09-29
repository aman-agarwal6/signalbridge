"""Generation evidence must stay honest under drift, partial review and case updates."""

import copy
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from bridge.case_provenance import case_generation, evidence_fingerprint
from bridge.detection_catalog import engine_fingerprint, explain_case
from bridge.models import Audit, Event, Integration, Investigation, Membership
from bridge.worker import drain, process_one
from tests.test_processing_efficiency import observation, rows


class CaseGenerationTests(TestCase):
    def setUp(self):
        self.app = Integration.objects.create(slug="processing-lab", name="Synthetic app")
        self.other = Integration.objects.create(slug="other-lab", name="Other synthetic app")
        self.user = get_user_model().objects.create_user(username="generation-reader")
        Membership.objects.create(user=self.user, integration=self.app, role="viewer")
        self.client.force_login(self.user)
        self.base = timezone.now().replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)

    def create_case(self, revoked=False):
        values = (
            [observation(0, self.base, outcome="allowed", reason="membership_removed")]
            if revoked
            else [observation(i, self.base) for i in range(3)]
        )
        Event.objects.bulk_create(rows(self.app, values))
        drain()
        return Investigation.objects.get()

    def explain(self, case, **kwargs):
        return case_generation(case, list(case.events.all()), engine_fingerprint(), **kwargs)

    def test_generated_case_binds_source_and_exact_evidence(self):
        case = self.create_case()
        record = Audit.objects.get(action="case.created").detail["generation"]
        self.assertEqual(record["process_source_sha256"], engine_fingerprint())
        self.assertEqual(record["disk_source_sha256_before"], record["disk_source_sha256_after"])
        self.assertEqual(record["event_count"], 3)
        self.assertEqual(
            record["evidence_sha256"],
            evidence_fingerprint(case.events.values_list("event_id", "digest", "source")),
        )
        result = self.explain(case)
        self.assertEqual(result["status"], "recorded")
        self.assertTrue(result["evidence_matches"])
        self.assertTrue(result["same_current_engine"])

    def test_r2_has_its_own_single_record_snapshot(self):
        case = self.create_case(revoked=True)
        self.assertEqual((case.rule, self.explain(case)["record"]["event_count"]), ("R2", 1))

    def test_duplicate_reprocessing_keeps_original_generation_audit(self):
        case = self.create_case()
        original = Audit.objects.get().detail
        Event.objects.update(state="pending")
        drain()
        self.assertEqual(Audit.objects.count(), 1)
        self.assertEqual(Audit.objects.get().detail, original)
        self.assertEqual(self.explain(case)["status"], "recorded")

    def test_late_evidence_preserves_original_and_adds_new_generation(self):
        case = self.create_case()
        first = Audit.objects.get()
        before = copy.deepcopy(first.detail)
        case.status = "resolved"
        case.save(update_fields=["status"])
        Event.objects.bulk_create(rows(self.app, [observation(3, self.base)]))
        drain()
        case.refresh_from_db()
        first.refresh_from_db()
        self.assertEqual(first.detail, before)
        self.assertEqual((case.status, case.version), ("open", 2))
        result = self.explain(case)
        self.assertEqual(
            (result["status"], result["record"]["event_count"], result["record"]["case_version"]),
            ("recorded", 4, 2),
        )
        self.assertEqual(Audit.objects.filter(action="case.reopened").count(), 1)

    def test_generation_write_failure_rolls_back_case_and_evidence(self):
        Event.objects.bulk_create(
            rows(
                self.app,
                [observation(0, self.base, outcome="allowed", reason="membership_removed")],
            )
        )
        with (
            patch("bridge.worker.generation_record", side_effect=ValueError("synthetic failure")),
            self.assertRaises(ValueError),
        ):
            process_one()
        self.assertFalse(Investigation.objects.exists())
        self.assertFalse(Audit.objects.exists())
        self.assertEqual((Event.objects.get().state, Event.objects.get().attempts), ("pending", 1))

    def test_disk_drift_is_recorded_without_silencing_detection(self):
        original = engine_fingerprint()
        with patch("bridge.detection_catalog._disk_fingerprint", side_effect=[original, "f" * 64]):
            case = self.create_case(revoked=True)
        result = self.explain(case)
        self.assertEqual(result["status"], "source_changed")
        self.assertTrue(result["evidence_matches"])
        self.assertEqual(result["record"]["disk_source_sha256_after"], "f" * 64)

    def test_unavailable_source_remains_unknown(self):
        with patch("bridge.detection_catalog._disk_fingerprint", return_value=None):
            case = self.create_case(revoked=True)
        self.assertEqual(self.explain(case)["status"], "source_unavailable")

    def test_new_current_engine_does_not_rewrite_recorded_snapshot(self):
        case = self.create_case()
        result = case_generation(case, list(case.events.all()), "f" * 64)
        self.assertEqual(result["status"], "recorded")
        self.assertFalse(result["same_current_engine"])

    def test_changed_key_bound_source_invalidates_evidence_binding(self):
        case = self.create_case()
        row = case.events.first()
        row.source = "synthetic_demo"
        row.save(update_fields=["source"])
        self.assertEqual(self.explain(case)["status"], "evidence_changed")

    def test_historical_case_is_not_backfilled_from_current_source(self):
        case = self.create_case()
        audit = Audit.objects.get()
        audit.detail.pop("generation")
        audit.save(update_fields=["detail"])
        self.assertEqual(self.explain(case)["status"], "unrecorded")
        self.assertIsNone(self.explain(case)["record"])

    def test_invalid_record_never_exposes_untrusted_detail(self):
        case = self.create_case()
        audit = Audit.objects.get()
        original = copy.deepcopy(audit.detail)
        for changes in (
            {"schema_version": True},
            {"case_version": case.version + 1},
            {"event_count": False},
            {"process_source_sha256": "private-sentinel"},
            {"extra": "private-sentinel"},
            {"correlation": "f" * 64},
            {"rule": "other-rule"},
        ):
            with self.subTest(changes=changes):
                audit.detail = copy.deepcopy(original)
                audit.detail["generation"].update(changes)
                audit.save(update_fields=["detail"])
                result = self.explain(case)
                self.assertEqual(result["status"], "invalid")
                self.assertIsNone(result["record"])
                self.assertNotIn("private-sentinel", str(result))

    def test_partial_display_and_changed_evidence_cannot_claim_binding(self):
        case = self.create_case()
        self.assertEqual(self.explain(case, complete=False)["status"], "partial")
        row = case.events.first()
        row.digest = "f" * 64
        row.save(update_fields=["digest"])
        self.assertEqual(self.explain(case)["status"], "evidence_changed")
        self.assertFalse(self.explain(case)["evidence_matches"])
        self.assertEqual(explain_case(case, list(case.events.all()))["integrity_errors"], 1)

    def test_payload_changed_without_digest_cannot_claim_generation_binding(self):
        case = self.create_case()
        row = case.events.first()
        row.payload = {**row.payload, "resource": "f" * 64}
        row.save(update_fields=["payload"])
        result = self.explain(case)
        self.assertEqual(result["status"], "evidence_inconsistent")
        self.assertFalse(result["evidence_matches"])

    def test_changed_indexed_field_cannot_claim_generation_binding(self):
        case = self.create_case()
        row = case.events.first()
        row.actor = "f" * 64
        row.save(update_fields=["actor"])
        result = self.explain(case)
        self.assertEqual(result["status"], "evidence_inconsistent")
        self.assertFalse(result["evidence_matches"])

    def test_malformed_stored_payloads_remain_inconsistent_without_render_failure(self):
        from bridge.contract import digest

        case = self.create_case()
        row = case.events.first()
        for value in ([], "invalid synthetic payload", 42, None):
            with self.subTest(value=value):
                row.payload = value
                # An in-memory corrupted record may come from an invalid import;
                # a matching stored digest must not make a non-object valid.
                row.digest = digest(value)
                events = [row, *case.events.exclude(pk=row.pk)]
                result = explain_case(case, events)
                self.assertEqual(result["integrity_errors"], 1)
                self.assertFalse(result["current_match"])
                self.assertFalse(result["generation"]["evidence_matches"])

    def test_export_does_not_present_changed_payload_as_matching_generation(self):
        case = self.create_case()
        row = case.events.first()
        row.payload = {**row.payload, "outcome": "allowed", "reason": "member"}
        row.save(update_fields=["payload"])
        response = self.client.get(f"/investigations/{case.pk}/export/")
        self.assertEqual(response.status_code, 200)
        analysis = response.json()["report"]["analysis"]
        self.assertEqual(analysis["integrity_errors"], 1)
        self.assertFalse(analysis["generation"]["evidence_matches"])
        self.assertEqual(analysis["generation"]["status"], "evidence_inconsistent")

    def test_scoped_latest_evidence_audit_excludes_other_app_and_analyst_actions(self):
        case = self.create_case()
        for app, action, actor in (
            (self.other, "case.created", None),
            (self.app, "case.disposition", self.user),
            (self.app, "case.created", self.user),
        ):
            Audit.objects.create(
                integration=app,
                object_id=str(case.pk),
                action=action,
                actor=actor,
                detail={"generation": {"private": "sentinel"}},
            )
        self.assertEqual(self.explain(case)["status"], "recorded")
        case.version += 1
        case.save(update_fields=["version"])
        self.assertEqual(self.explain(case)["status"], "recorded")

    def test_missing_latest_snapshot_does_not_fall_back_to_older_success(self):
        case = self.create_case()
        Audit.objects.create(
            integration=self.app, object_id=str(case.pk), action="case.evidence_added", detail={}
        )
        self.assertEqual(self.explain(case)["status"], "unrecorded")

    def test_generation_is_in_scoped_page_and_export_without_notes(self):
        case = self.create_case()
        response = self.client.get(f"/investigations/{case.pk}/")
        self.assertContains(response, "Recorded generation snapshot")
        self.assertContains(response, "Generation snapshot and retained evidence binding match")
        response = self.client.get(f"/investigations/{case.pk}/export/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["report"]["analysis"]["generation"]["status"], "recorded")
        self.assertNotIn("notes", response.json()["report"])
        Membership.objects.filter(user=self.user).delete()
        self.assertEqual(self.client.get(f"/investigations/{case.pk}/export/").status_code, 404)
