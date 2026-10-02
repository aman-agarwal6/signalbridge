import json
import os
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.utils import timezone

from bridge.case_workflow import evidence_binding, operate
from bridge.models import (
    Audit,
    CaseTask,
    Event,
    Integration,
    Investigation,
    Membership,
    Note,
    ServiceCredential,
    ServiceNonce,
    ServiceRequest,
)
from bridge.service_api import request_signature
from bridge.services import WorkflowError
from tests.test_processing_efficiency import observation, rows

SECRET = "nonfunctional-service-api-fixture-only-" + "x" * 48


class CaseFixture(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create(username="analyst")
        self.viewer = User.objects.create(username="viewer")
        self.reviewer = User.objects.create(username="reviewer")
        self.app = Integration.objects.create(
            slug="enterprise-test",
            name="Synthetic app",
            business_owner="Synthetic business owner",
            asset_criticality="high",
        )
        self.other = Integration.objects.create(slug="other-app", name="Other synthetic app")
        self.membership = Membership.objects.create(
            user=self.analyst, integration=self.app, role="analyst"
        )
        Membership.objects.create(user=self.viewer, integration=self.app, role="viewer")
        self.review_membership = Membership.objects.create(
            user=self.reviewer, integration=self.app, role="reviewer"
        )
        self.case = Investigation.objects.create(
            integration=self.app,
            rule="R1",
            correlation="c" * 64,
            title="Synthetic investigation",
            severity="medium",
            explanation="Synthetic only",
        )
        Event.objects.bulk_create(
            rows(self.app, [observation(0, timezone.now(), app=self.app.slug)])
        )
        self.event = Event.objects.get()
        self.case.events.add(self.event)


class CaseOperationTests(CaseFixture):
    def test_acknowledgement_records_actor_time_and_prevents_duplicate_metric(self):
        current = operate(self.analyst, self.case.pk, 1, "acknowledge", {})
        self.assertEqual(current.acknowledged_by_id, self.analyst.pk)
        self.assertGreaterEqual(current.acknowledged_at, current.created_at)
        with self.assertRaises(WorkflowError):
            operate(self.analyst, self.case.pk, 2, "acknowledge", {})
        self.assertEqual(Audit.objects.filter(action="case.acknowledge").count(), 1)

    def test_assignment_is_current_active_and_app_scoped(self):
        foreign = Membership.objects.create(
            user=self.analyst, integration=self.other, role="analyst"
        )
        for member in (foreign, Membership.objects.get(user=self.viewer)):
            with self.assertRaises(WorkflowError):
                operate(self.analyst, self.case.pk, 1, "assign", {"assignee": str(member.pk)})
        current = operate(
            self.analyst, self.case.pk, 1, "assign", {"assignee": str(self.review_membership.pk)}
        )
        self.assertEqual(current.assignee_id, self.review_membership.pk)

    def test_due_date_is_bounded_and_audited(self):
        for days in (0, 91, "bad"):
            with self.assertRaises(WorkflowError):
                operate(self.analyst, self.case.pk, 1, "due", {"due_days": days})
        current = operate(self.analyst, self.case.pk, 1, "due", {"due_days": 7})
        self.assertGreater(current.due_at, timezone.now() + timedelta(days=6))

    def test_note_separates_facts_from_interpretation(self):
        operate(
            self.analyst,
            self.case.pk,
            1,
            "structured_note",
            {"kind": "uncertainty", "note": "Need the legitimate owner control."},
        )
        note = Note.objects.get()
        self.assertEqual(note.kind, "uncertainty")
        self.assertEqual(note.author, self.analyst)

    def test_task_work_state_cannot_assert_verified_remediation(self):
        current = operate(
            self.analyst,
            self.case.pk,
            1,
            "task",
            {"kind": "remediation", "title": "Correct the synthetic access check"},
        )
        task = CaseTask.objects.get()
        self.assertEqual(task.evidence_sha256, evidence_binding(current))
        with self.assertRaises(WorkflowError):
            operate(
                self.analyst,
                self.case.pk,
                2,
                "task_state",
                {"task_id": str(task.pk), "status": "verified"},
            )
        operate(
            self.analyst,
            self.case.pk,
            2,
            "task_state",
            {"task_id": str(task.pk), "status": "awaiting_retest"},
        )
        task.refresh_from_db()
        self.assertEqual(task.status, "awaiting_retest")

    def test_current_permission_and_case_version_required_for_every_write(self):
        with self.assertRaises(PermissionError):
            operate(self.viewer, self.case.pk, 1, "acknowledge", {})
        with self.assertRaises(WorkflowError):
            operate(self.analyst, self.case.pk, 5, "acknowledge", {})
        Membership.objects.filter(pk=self.membership.pk).update(role="viewer")
        with self.assertRaises(PermissionError):
            operate(self.analyst, self.case.pk, 1, "acknowledge", {})
        self.case.refresh_from_db()
        self.assertEqual(self.case.version, 1)
        self.assertEqual(Audit.objects.count(), 0)

    def test_browser_operation_requires_csrf_even_with_session(self):
        browser = Client(enforce_csrf_checks=True)
        browser.force_login(self.analyst)
        response = browser.post(
            f"/investigations/{self.case.pk}/work/", {"version": 1, "operation": "acknowledge"}
        )
        self.assertEqual(response.status_code, 403)
        self.case.refresh_from_db()
        self.assertIsNone(self.case.acknowledged_at)

    def test_historical_resolved_case_is_not_reclassified_as_verified(self):
        self.case.status = "resolved"
        self.case.save(update_fields=["status"])
        operate(
            self.analyst,
            self.case.pk,
            1,
            "structured_note",
            {"kind": "verification", "note": "Review complete, native retest not run."},
        )
        self.case.refresh_from_db()
        self.assertEqual(self.case.status, "resolved")
        self.assertFalse(CaseTask.objects.exists())


class ServiceApiTests(CaseFixture):
    def setUp(self):
        super().setUp()
        self.read_key = ServiceCredential.objects.create(
            integration=self.app,
            key_id="read-key",
            secret_env="SB_SERVICE_READ",
            capability="read_case_evidence",
        )
        self.task_key = ServiceCredential.objects.create(
            integration=self.app,
            key_id="task-key",
            secret_env="SB_SERVICE_TASK",
            capability="create_review_task",
        )
        self.environment = patch.dict(
            os.environ, {"SB_SERVICE_READ": SECRET + "read", "SB_SERVICE_TASK": SECRET + "task"}
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.browser = Client(enforce_csrf_checks=True)
        self.path = f"/api/v1/cases/{self.case.pk}/review-task/"

    def headers(self, key, method, path, body=b"", nonce=None, at=None):
        nonce, at = nonce or str(uuid.uuid4()), at or timezone.now().isoformat()
        return {
            "HTTP_X_SB_SERVICE_KEY": key.key_id,
            "HTTP_X_SB_SERVICE_NONCE": nonce,
            "HTTP_X_SB_SERVICE_TIME": at,
            "HTTP_X_SB_SERVICE_SIGNATURE": request_signature(
                os.environ[key.secret_env], key.key_id, nonce, at, method, path, body
            ),
        }

    def body(self, **changes):
        value = {
            "case_version": 1,
            "evidence_sha256": evidence_binding(self.case),
            "idempotency_key": str(uuid.uuid4()),
            "task_kind": "review_case_evidence",
        }
        value.update(changes)
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    def post(self, body, key=None, path=None, **headers):
        key, path = key or self.task_key, path or self.path
        return self.browser.post(
            path,
            body,
            content_type="application/json",
            **(headers or self.headers(key, "POST", path, body)),
        )

    def test_read_evidence_requires_machine_auth_and_excludes_free_text_notes(self):
        path = f"/api/v1/cases/{self.case.pk}/evidence/"
        self.browser.force_login(self.analyst)
        self.assertEqual(self.browser.get(path).status_code, 401)
        Note.objects.create(
            investigation=self.case, author=self.analyst, text="Synthetic private analyst narrative"
        )
        response = self.browser.get(path, **self.headers(self.read_key, "GET", path))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["evidence_sha256"], evidence_binding(self.case))
        self.assertNotIn("Synthetic private analyst narrative", response.content.decode())
        self.assertIn("no-store", response["Cache-Control"])

    def test_lost_reply_retry_creates_one_task_with_one_audit(self):
        body = self.body()
        first, second = self.post(body), self.post(body)
        self.assertEqual((first.status_code, second.status_code), (201, 200))
        self.assertEqual(first.json()["task_id"], second.json()["task_id"])
        self.assertTrue(second.json()["duplicate"])
        self.assertEqual(CaseTask.objects.count(), 1)
        self.assertEqual(ServiceRequest.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="case.machine_review_task").count(), 1)

    def test_nonce_replay_is_rejected_even_for_idempotent_body(self):
        body = self.body()
        headers = self.headers(self.task_key, "POST", self.path, body)
        self.assertEqual(self.post(body, **headers).status_code, 201)
        self.assertEqual(self.post(body, **headers).status_code, 409)
        self.assertEqual(CaseTask.objects.count(), 1)

    def test_same_idempotency_key_cannot_change_content_or_target(self):
        body = self.body()
        self.assertEqual(self.post(body).status_code, 201)
        changed = json.loads(body)
        changed["case_version"] = 2
        self.assertEqual(self.post(json.dumps(changed).encode()).status_code, 409)
        other_case = Investigation.objects.create(
            integration=self.app,
            rule="R1",
            correlation="d" * 64,
            title="Other case",
            severity="medium",
            explanation="Synthetic",
        )
        other_case.events.add(self.event)
        self.assertEqual(
            self.post(body, path=f"/api/v1/cases/{other_case.pk}/review-task/").status_code, 409
        )
        self.assertEqual(CaseTask.objects.count(), 1)

    def test_stale_case_version_or_evidence_is_not_accepted(self):
        self.assertEqual(self.post(self.body(case_version=9)).status_code, 409)
        self.assertEqual(self.post(self.body(evidence_sha256="f" * 64)).status_code, 409)
        self.assertFalse(CaseTask.objects.exists())

    def test_case_changed_after_first_task_invalidates_its_old_retry(self):
        body = self.body()
        self.assertEqual(self.post(body).status_code, 201)
        operate(self.analyst, self.case.pk, 2, "acknowledge", {})
        self.assertEqual(self.post(body).status_code, 409)
        self.assertEqual(CaseTask.objects.count(), 1)

    def test_capabilities_and_application_boundaries_are_enforced(self):
        self.assertEqual(self.post(self.body(), key=self.read_key).status_code, 403)
        foreign = Investigation.objects.create(
            integration=self.other,
            rule="R1",
            correlation="e" * 64,
            title="Foreign case",
            severity="medium",
            explanation="Synthetic",
        )
        self.assertEqual(
            self.post(self.body(), path=f"/api/v1/cases/{foreign.pk}/review-task/").status_code, 404
        )
        self.assertFalse(CaseTask.objects.exists())

    def test_disabled_key_or_app_rejects_current_requests(self):
        body = self.body()
        ServiceCredential.objects.filter(pk=self.task_key.pk).update(active=False)
        self.assertEqual(self.post(body).status_code, 401)
        ServiceCredential.objects.filter(pk=self.task_key.pk).update(active=True)
        Integration.objects.filter(pk=self.app.pk).update(enabled=False)
        self.assertEqual(self.post(body).status_code, 403)

    def test_bad_signature_expired_time_and_body_tampering_fail_closed(self):
        body = self.body()
        old = (timezone.now() - timedelta(minutes=2)).isoformat()
        self.assertEqual(
            self.post(
                body, **self.headers(self.task_key, "POST", self.path, body, at=old)
            ).status_code,
            401,
        )
        headers = self.headers(self.task_key, "POST", self.path, body)
        headers["HTTP_X_SB_SERVICE_SIGNATURE"] = "0" * 64
        self.assertEqual(self.post(body, **headers).status_code, 401)
        headers = self.headers(self.task_key, "POST", self.path, body)
        self.assertEqual(self.post(body + b" ", **headers).status_code, 401)
        self.assertFalse(CaseTask.objects.exists())

    def test_failed_authenticated_requests_still_consume_replay_and_rate_slots(self):
        body = b'{"invalid":true}'
        headers = self.headers(self.task_key, "POST", self.path, body)
        self.assertEqual(self.post(body, **headers).status_code, 400)
        self.assertEqual(self.post(body, **headers).status_code, 409)
        for _ in range(59):
            self.assertEqual(self.post(body).status_code, 400)
        self.assertEqual(self.post(body).status_code, 429)
        self.assertEqual(ServiceNonce.objects.count(), 60)

    def test_size_unknown_fields_and_automation_actions_are_bounded(self):
        self.assertEqual(self.post(b"x" * 4097).status_code, 413)
        for value in (self.body(task_kind="close_case"), self.body(command="shell"), b"[]"):
            self.assertEqual(self.post(value).status_code, 400)
        self.assertFalse(CaseTask.objects.exists())

    def test_corrupt_or_cross_app_evidence_is_not_reported_as_valid(self):
        body = self.body()
        Event.objects.filter(pk=self.event.pk).update(digest="0" * 64)
        self.assertEqual(self.post(body).status_code, 409)
        self.assertFalse(CaseTask.objects.exists())

    def test_automation_preserves_case_disposition_and_accounts(self):
        self.case.status = "resolved"
        self.case.save(update_fields=["status"])
        self.assertEqual(self.post(self.body()).status_code, 201)
        self.case.refresh_from_db()
        self.assertEqual(self.case.status, "resolved")
        self.assertTrue(get_user_model().objects.get(pk=self.analyst.pk).is_active)
