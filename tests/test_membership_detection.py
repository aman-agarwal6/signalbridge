"""Trust-boundary, late-arrival and negative controls for resource membership R3."""

import copy
import os
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from bridge.contract import ContractError, canonical, signature, validate_event
from bridge.detection_catalog import explain_case
from bridge.engine import detections
from bridge.models import Audit, Event, IngestKey, Integration, Investigation, Membership
from bridge.worker import CorrelationCapacityError, drain, process_one
from tests.test_processing_efficiency import observation, rows


def reading(index=1, base=None, **changes):
    return observation(
        index,
        base or timezone.now() - timedelta(hours=1),
        resource="b" * 64,
        outcome="allowed",
        reason="member",
        **changes,
    )


def change(index=0, state="removed", base=None, **changes):
    value = reading(index, base)
    value.update(
        schema_version=2,
        operation="membership.change",
        actor="c" * 64,
        reason="membership_removed" if state == "removed" else "member",
        membership={"subject": "a" * 64, "state": state},
    )
    value["event_id"] = str(
        uuid.uuid5(uuid.NAMESPACE_URL, "membership/" + value["event_id"] + state)
    )
    value.update(changes)
    return value


class MembershipContractTests(SimpleTestCase):
    def test_v1_remains_valid_and_v2_is_closed(self):
        for value in (reading(), change(), change(state="granted")):
            self.assertEqual(validate_event(value, "processing-lab"), value)
        invalid = [
            {"membership": {"subject": "a" * 64, "state": "removed", "authority": True}},
            {"membership": {"subject": "raw-name", "state": "removed"}},
            {"membership": {"subject": "a" * 64, "state": []}},
            {"schema_version": True},
            {"schema_version": 1},
            {"operation": "private_record.read"},
            {"outcome": "error"},
            {"reason": "member"},
        ]
        for patch_value in invalid:
            with self.subTest(fields=patch_value), self.assertRaises(ContractError):
                validate_event(change(**patch_value), "processing-lab")

    def test_subject_not_operator_is_correlated_without_suspicious_read_label(self):
        base = timezone.now() - timedelta(hours=1)
        result = detections([change(base=base), reading(base=base)])
        self.assertEqual([r["rule"] for r in result], ["R3"])
        self.assertEqual(len(result[0]["event_ids"]), 2)

    def test_legacy_membership_context_is_still_insufficient(self):
        value = change()
        value.pop("membership")
        value["schema_version"] = 1
        self.assertEqual(detections([value, reading()]), [])

    def test_negative_controls_and_24_hour_boundary(self):
        base = timezone.now() - timedelta(days=2)
        removed = change(base=base)
        for fields in (
            {"actor": "c" * 64},
            {"resource": "e" * 64},
            {"app": "other"},
            {"environment": "lab"},
            {"outcome": "denied"},
            {"outcome": "error"},
        ):
            value = reading(base=base)
            value.update(fields)
            with self.subTest(fields=fields):
                self.assertEqual(detections([removed, value]), [])
        for seconds, expected in ((-1, 0), (0, 0), (1, 1), (86400, 1), (86401, 0)):
            with self.subTest(seconds=seconds):
                self.assertEqual(len(detections([removed, reading(seconds, base)])), expected)

    def test_regrant_and_conflicting_state_do_not_alert(self):
        base = timezone.now() - timedelta(hours=1)
        for grant_time in (0, 1, 2):
            values = [change(base=base), change(grant_time, "granted", base), reading(2, base)]
            self.assertEqual(detections(values), [])


class MembershipPipelineTests(TestCase):
    def setUp(self):
        self.app = Integration.objects.create(slug="processing-lab", name="Synthetic R3 lab")
        self.base = timezone.now() - timedelta(hours=1)
        self.key = IngestKey.objects.create(
            integration=self.app,
            key_id="membership-test",
            secret_env="SB_MEMBERSHIP_TEST_KEY",
            environment="test",
            source="synthetic_demo",
        )
        self.secret = "nonfunctional-membership-unit-test-" + "x" * 48
        self.env = patch.dict(os.environ, {"SB_MEMBERSHIP_TEST_KEY": self.secret})
        self.env.start()
        self.addCleanup(self.env.stop)

    def send(self, value):
        raw, at = canonical(value), timezone.now().isoformat()
        return self.client.post(
            "/api/v1/events/processing-lab/",
            data=raw,
            content_type="application/json",
            HTTP_X_SB_KEY=self.key.key_id,
            HTTP_X_SB_TIME=at,
            HTTP_X_SB_SIGNATURE=signature(self.secret, self.app.slug, self.key.key_id, at, raw),
        )

    def authorize(self):
        self.key.can_assert_membership = True
        self.key.save(update_fields=["can_assert_membership"])

    def test_default_key_denies_membership_assertions_without_queue_writes(self):
        self.assertEqual(self.send(change(base=self.base)).status_code, 403)
        self.assertEqual(Event.objects.count(), 0)

    def test_capability_is_rechecked_under_transaction_lock(self):
        from bridge import ingestion

        original = ingestion.validate_event

        def revoke(*args, **kwargs):
            value = original(*args, **kwargs)
            IngestKey.objects.filter(pk=self.key.pk).update(can_assert_membership=False)
            return value

        self.authorize()
        with patch("bridge.ingestion.validate_event", side_effect=revoke):
            self.assertEqual(self.send(change(base=self.base)).status_code, 401)
        self.assertFalse(Event.objects.exists())

    def test_late_removal_links_both_events_and_audits_generation(self):
        self.authorize()
        for value in (reading(base=self.base), change(base=self.base)):
            self.assertEqual(self.send(value).status_code, 202)
            drain()
        case = Investigation.objects.get(rule="R3")
        self.assertEqual(case.events.count(), 2)
        self.assertTrue(explain_case(case, list(case.events.all()))["current_match"])
        self.assertEqual(
            Audit.objects.get(action="case.created").detail["generation"]["event_count"], 2
        )
        self.assertEqual(self.send(change(base=self.base)).json()["status"], "duplicate")
        drain()
        self.assertEqual(Investigation.objects.count(), 1)

    def test_late_grant_reopens_case_with_correction_without_erasing_history(self):
        self.authorize()
        for value in (change(base=self.base), reading(3, self.base)):
            self.assertEqual(self.send(value).status_code, 202)
            drain()
        case = Investigation.objects.get(rule="R3")
        first = copy.deepcopy(Audit.objects.get(action="case.created").detail)
        case.status = "resolved"
        case.save(update_fields=["status"])
        self.assertEqual(self.send(change(2, "granted", self.base)).status_code, 202)
        drain()
        case.refresh_from_db()
        self.assertEqual((case.status, case.version, case.severity), ("open", 2, "medium"))
        self.assertIn("reassessment", case.title)
        self.assertEqual(case.events.count(), 3)
        self.assertEqual(Audit.objects.get(action="case.created").detail, first)
        self.assertFalse(explain_case(case, list(case.events.all()))["current_match"])

    def test_source_boundaries_never_correlate(self):
        Event.objects.bulk_create(rows(self.app, [change(base=self.base)], "migration_lab"))
        Event.objects.bulk_create(rows(self.app, [reading(base=self.base)], "synthetic_demo"))
        drain()
        self.assertFalse(Investigation.objects.exists())

    def test_capacity_failure_is_visible_and_preserves_pending_work(self):
        Event.objects.bulk_create(rows(self.app, [change(base=self.base), reading(base=self.base)]))
        with (
            patch("bridge.worker.MAX_CORRELATION_EVENTS", 1),
            self.assertRaises(CorrelationCapacityError),
        ):
            process_one()
        self.assertTrue(
            Event.objects.filter(error_code="correlation_capacity", attempts=1).exists()
        )
        self.assertFalse(Investigation.objects.exists())

    def test_same_time_late_removal_does_not_claim_order(self):
        Event.objects.bulk_create(rows(self.app, [change(base=self.base), reading(0, self.base)]))
        drain()
        self.assertFalse(Investigation.objects.exists())

    def test_console_filters_r3_high_and_displays_affected_member(self):
        Event.objects.bulk_create(rows(self.app, [change(base=self.base), reading(base=self.base)]))
        drain()
        user = get_user_model().objects.create_user(username="r3-reader")
        Membership.objects.create(user=user, integration=self.app, role="viewer")
        self.client.force_login(user)
        listing = self.client.get("/investigations/?app=processing-lab&rule=R3&severity=high")
        self.assertContains(listing, "Allowed read after correlated membership removal")
        self.assertEqual(listing.context["selected_rule"], "R3")
        self.assertEqual(listing.context["selected_severity"], "high")
        case = Investigation.objects.get()
        detail = self.client.get(f"/investigations/{case.pk}/")
        self.assertContains(detail, "Affected account:")
        self.assertContains(detail, "Current rule matches linked evidence")
        self.assertNotContains(detail, "<script")
