"""Disposable policy fixtures; these are not native source execution evidence."""

import copy
import io
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, transaction
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from bridge.case_verification import console_context, presentation
from bridge.case_workflow import evidence_binding, operate
from bridge.contract import digest
from bridge.models import (
    Audit,
    CaseTask,
    CaseVerification,
    CheckRun,
    Event,
    Integration,
    Investigation,
    Membership,
)
from bridge.reference_retest import PROFILE, SUITE, import_retest
from bridge.services import WorkflowError
from tests.test_processing_efficiency import observation, rows


class CaseVerificationFixture:
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create(username="retest-analyst")
        self.reviewer = User.objects.create(username="retest-reviewer")
        self.viewer = User.objects.create(username="retest-viewer")
        self.app = Integration.objects.create(slug="documents", name="Synthetic documents")
        for user, role in (
            (self.analyst, "analyst"),
            (self.reviewer, "reviewer"),
            (self.viewer, "viewer"),
        ):
            Membership.objects.create(user=user, integration=self.app, role=role)
        self.case = Investigation.objects.create(
            integration=self.app,
            rule="R3",
            correlation="d" * 64,
            title="Modeled reference correction",
            explanation="Policy fixture, not native proof",
            severity="high",
        )
        base = timezone.now() - timedelta(minutes=1)
        values = [
            observation(index, base, app="documents", environment="lab", resource="f" * 64)
            for index in range(4)
        ]
        values[0].update(
            schema_version=2,
            actor="b" * 64,
            operation="membership.change",
            outcome="allowed",
            reason="membership_removed",
            membership={"subject": "a" * 64, "state": "removed"},
        )
        values[1].update(outcome="allowed", reason="member")
        values[3].update(actor="b" * 64, outcome="allowed", reason="owner")
        Event.objects.bulk_create(rows(self.app, values, source="instrumented_lab"))
        Event.objects.update(
            state="processed",
            processed_at=base + timedelta(seconds=10),
            processed_by="native-reference-proof",
            processing_attempts=1,
        )
        self.events = list(Event.objects.order_by("occurred_at"))
        self.case.events.add(*self.events[:2])
        self.result = {
            "schema_version": 1,
            "evidence_kind": "native_reference_access",
            "profile": PROFILE,
            "run_id": uuid.uuid4().hex,
            "app": "documents",
            "case_id": str(self.case.pk),
            "case_evidence_sha256": None,
            "source_sha256": "c" * 64,
            "host_receipt_sha256": "e" * 64,
            "finished_at": timezone.now().isoformat(),
            "bindings": {
                kind: {"event_id": str(event.event_id), "digest": event.digest}
                for kind, event in zip(
                    ("removal", "failure", "denial", "owner_control"), self.events, strict=True
                )
            },
        }
        # Trusted-operator policy fixture. The command must separately call the
        # archive verifier; this direct helper does not claim native execution.
        self.run, _ = import_retest(self.result)
        self.case = operate(
            self.analyst,
            self.case.pk,
            1,
            "task",
            {
                "kind": "remediation",
                "title": "Verify denial and surviving owner access",
            },
        )
        self.task = CaseTask.objects.get()
        self.case = operate(
            self.analyst,
            self.case.pk,
            2,
            "task_state",
            {
                "task_id": str(self.task.pk),
                "status": "awaiting_retest",
            },
        )

    def submit(self, user=None):
        self.case = operate(
            user or self.analyst,
            self.case.pk,
            self.case.version,
            "submit_retest",
            {
                "task_id": str(self.task.pk),
                "check_run_id": str(self.run.pk),
            },
        )
        return CaseVerification.objects.latest("submitted_at")

    def decide(
        self,
        verification,
        user=None,
        decision="approved",
        rationale="The denied read and owner control match the retained lab scope.",
    ):
        return operate(
            user or self.reviewer,
            self.case.pk,
            self.case.version,
            "review_retest",
            {
                "verification_id": str(verification.pk),
                "decision": decision,
                "rationale": rationale,
            },
        )


class CaseVerificationTests(CaseVerificationFixture, TestCase):
    def test_matching_submission_and_independent_review_do_not_close_case(self):
        verification = self.submit()
        self.assertEqual(verification.case_version, self.case.version)
        self.case = self.decide(verification)
        self.task.refresh_from_db()
        verification.refresh_from_db()
        self.assertEqual(self.task.status, "verified")
        self.assertEqual(self.case.status, "open")
        self.assertEqual(verification.reviewer, self.reviewer)
        self.assertEqual(
            presentation(self.case, verification, evidence_binding(self.case)),
            ("Verified within recorded lab scope", False),
        )
        self.assertEqual(Audit.objects.filter(action="case.review_retest").count(), 1)

    def test_generic_task_state_cannot_set_verified(self):
        with self.assertRaises(WorkflowError):
            operate(
                self.analyst,
                self.case.pk,
                3,
                "task_state",
                {"task_id": str(self.task.pk), "status": "verified"},
            )
        self.assertFalse(CaseVerification.objects.exists())

    def test_rejection_retains_reason_and_does_not_mark_task_verified(self):
        verification = self.submit()
        self.decide(verification, decision="rejected")
        verification.refresh_from_db()
        self.task.refresh_from_db()
        self.assertEqual(verification.status, "rejected")
        self.assertEqual(self.task.status, "awaiting_retest")

    def test_creator_and_submitter_cannot_approve_even_after_role_promotion(self):
        verification = self.submit()
        Membership.objects.filter(user=self.analyst).update(role="reviewer")
        with self.assertRaises(WorkflowError):
            self.decide(verification, user=self.analyst)

    def test_task_assignee_cannot_approve(self):
        CaseTask.objects.filter(pk=self.task.pk).update(
            assignee=Membership.objects.get(user=self.reviewer)
        )
        with self.assertRaises(WorkflowError):
            self.decide(self.submit())

    def test_case_assignee_cannot_approve(self):
        Investigation.objects.filter(pk=self.case.pk).update(
            assignee=Membership.objects.get(user=self.reviewer)
        )
        with self.assertRaises(WorkflowError):
            self.decide(self.submit())

    def test_analyst_cannot_review(self):
        with self.assertRaises(PermissionError):
            self.decide(self.submit(), user=self.analyst)

    def test_viewer_cannot_submit_or_review(self):
        with self.assertRaises(PermissionError):
            self.submit(self.viewer)
        with self.assertRaises(PermissionError):
            self.decide(self.submit(), user=self.viewer)

    def test_withdrawn_reviewer_role_and_disabled_account_are_rejected(self):
        verification = self.submit()
        Membership.objects.filter(user=self.reviewer).update(role="viewer")
        with self.assertRaises(PermissionError):
            self.decide(verification)
        Membership.objects.filter(user=self.reviewer).update(role="reviewer")
        get_user_model().objects.filter(pk=self.reviewer.pk).update(is_active=False)
        with self.assertRaises(PermissionError):
            self.decide(verification)

    def test_other_application_reviewer_cannot_review(self):
        Membership.objects.filter(user=self.reviewer).delete()
        app = Integration.objects.create(slug="expenses", name="Synthetic expenses")
        Membership.objects.create(user=self.reviewer, integration=app, role="reviewer")
        with self.assertRaises(PermissionError):
            self.decide(self.submit())

    def test_case_version_change_requires_fresh_submission(self):
        verification = self.submit()
        self.case = operate(
            self.analyst,
            self.case.pk,
            self.case.version,
            "structured_note",
            {
                "kind": "uncertainty",
                "note": "Additional review is required.",
            },
        )
        with self.assertRaises(WorkflowError):
            self.decide(verification)
        fresh = self.submit()
        self.assertNotEqual(fresh.pk, verification.pk)
        self.decide(fresh)

    def test_duplicate_decision_does_not_create_duplicate_audit(self):
        verification = self.submit()
        self.case = self.decide(verification)
        with self.assertRaises(WorkflowError):
            self.decide(verification)
        self.assertEqual(Audit.objects.filter(action="case.review_retest").count(), 1)

    def test_changed_task_evidence_and_work_state_fail_closed(self):
        verification = self.submit()
        CaseTask.objects.filter(pk=self.task.pk).update(evidence_sha256="0" * 64)
        with self.assertRaises(WorkflowError):
            self.decide(verification)
        CaseTask.objects.filter(pk=self.task.pk).update(
            evidence_sha256=evidence_binding(self.case), status="open"
        )
        with self.assertRaises(WorkflowError):
            self.decide(verification)

    def test_changed_case_evidence_invalidates_prior_verified_label(self):
        verification = self.submit()
        self.case = self.decide(verification)
        verification.refresh_from_db()
        self.case.events.add(self.events[2])
        self.assertEqual(
            presentation(self.case, verification, evidence_binding(self.case)),
            ("Evidence or work state changed; review again", False),
        )

    def test_changed_receipt_even_with_recomputed_digest_requires_new_import(self):
        verification = self.submit()
        altered = copy.deepcopy(self.run.result)
        altered["host_receipt_sha256"] = "0" * 64
        CheckRun.objects.filter(pk=self.run.pk).update(result=altered, digest=digest(altered))
        with self.assertRaises(WorkflowError):
            self.decide(verification)

    def test_generic_green_run_and_missing_operator_audit_cannot_verify(self):
        Audit.objects.filter(action="retest.imported").delete()
        with self.assertRaises(WorkflowError):
            self.submit()
        self.run.result, self.run.suite = {"passed": True}, "Generic green tests"
        self.run.save()
        with self.assertRaises(WorkflowError):
            self.submit()

    def test_conflicting_scope_failed_run_or_missing_owner_control_rejected(self):
        for update in (
            {"app": "expenses"},
            {"profile": "reference-access-v1"},
            {
                "bindings": {
                    k: v for k, v in self.result["bindings"].items() if k != "owner_control"
                }
            },
        ):
            value = {**self.run.result, **update}
            with self.assertRaises(WorkflowError):
                import_retest(value)
        CheckRun.objects.filter(pk=self.run.pk).update(status="failed")
        with self.assertRaises(WorkflowError):
            self.submit()

    def test_wrong_subject_resource_episode_or_time_does_not_pass(self):
        original = copy.deepcopy(self.events[2].payload)
        for field, value in (
            ("actor", "c" * 64),
            ("resource", "c" * 64),
            ("episode", str(uuid.uuid4())),
            ("occurred_at", self.events[0].payload["occurred_at"]),
            ("outcome", "error"),
        ):
            changed = {**original, field: value}
            Event.objects.filter(pk=self.events[2].pk).update(
                payload=changed,
                digest=digest(changed),
                **{
                    field: timezone.datetime.fromisoformat(value)
                    if field == "occurred_at"
                    else value
                },
            )
            result = copy.deepcopy(self.run.result)
            result["bindings"]["denial"]["digest"] = digest(changed)
            with self.assertRaises(WorkflowError):
                import_retest(result)
            Event.objects.filter(pk=self.events[2].pk).update(
                payload=original,
                digest=digest(original),
                **{
                    field: timezone.datetime.fromisoformat(original[field])
                    if field == "occurred_at"
                    else original[field]
                },
            )

    def test_reviewer_rationale_is_required_and_bounded(self):
        verification = self.submit()
        for value in ("", "short", "x" * 1001):
            with self.assertRaises(WorkflowError):
                self.decide(verification, rationale=value)
        self.assertFalse(Audit.objects.filter(action="case.review_retest").exists())

    def test_only_awaiting_remediation_tasks_are_eligible(self):
        for changes in ({"kind": "review"}, {"status": "open"}, {"created_by": None}):
            original = {key: getattr(self.task, key) for key in changes}
            CaseTask.objects.filter(pk=self.task.pk).update(**changes)
            with self.assertRaises(WorkflowError):
                self.submit()
            CaseTask.objects.filter(pk=self.task.pk).update(**original)

    def test_operator_import_is_idempotent_and_dry_run_has_no_writes(self):
        before = (CheckRun.objects.count(), Audit.objects.count())
        run, created = import_retest(self.result)
        self.assertFalse(created)
        self.assertEqual(run.pk, self.run.pk)
        self.assertEqual(import_retest(self.result, dry_run=True), (None, False))
        self.assertEqual(before, (CheckRun.objects.count(), Audit.objects.count()))

    def test_import_never_fabricates_missing_native_case_or_events(self):
        before = (Investigation.objects.count(), Event.objects.count())
        with self.assertRaises(Investigation.DoesNotExist):
            import_retest({**self.result, "case_id": str(uuid.uuid4())})
        Event.objects.filter(pk=self.events[3].pk).delete()
        with self.assertRaises(WorkflowError):
            import_retest(self.result)
        self.assertEqual(Investigation.objects.count(), before[0])
        self.assertEqual(Event.objects.count(), before[1] - 1)

    def test_command_requires_archive_revalidation_and_operator_flag(self):
        with override_settings(LOCAL=False), self.assertRaises(CommandError):
            call_command(
                "import_reference_retest",
                run_id=self.result["run_id"],
                local_database_operator=True,
            )
        with self.assertRaises(CommandError):
            call_command(
                "import_reference_retest",
                run_id=self.result["run_id"],
                local_database_operator=False,
            )
        with (
            override_settings(LOCAL=True),
            patch(
                "bridge.management.commands.import_reference_retest.load_native_retest",
                side_effect=WorkflowError("incomplete"),
            ) as verifier,
        ):
            with self.assertRaises(CommandError):
                call_command(
                    "import_reference_retest",
                    run_id=self.result["run_id"],
                    local_database_operator=True,
                )
            verifier.assert_called_once()

    def test_csrf_protects_both_submission_and_review(self):
        verification = self.submit()
        browser = Client(enforce_csrf_checks=True)
        for user, operation, fields in (
            (self.analyst, "submit_retest", {"task_id": self.task.pk, "check_run_id": self.run.pk}),
            (
                self.reviewer,
                "review_retest",
                {
                    "verification_id": verification.pk,
                    "decision": "approved",
                    "rationale": "Synthetic review",
                },
            ),
        ):
            browser.force_login(user)
            response = browser.post(
                f"/investigations/{self.case.pk}/work/",
                {"version": self.case.version, "operation": operation, **fields},
            )
            self.assertEqual(response.status_code, 403)
        self.assertFalse(Audit.objects.filter(action="case.review_retest").exists())

    def test_console_shows_receipt_scope_and_hides_generic_green_run(self):
        context = console_context(self.case)
        self.assertEqual([run.pk for run in context["matching_retests"]], [self.run.pk])
        self.assertTrue(context["case_tasks"][0].can_submit_retest)
        verification = self.submit()
        browser = Client()
        browser.force_login(self.reviewer)
        response = browser.get(f"/investigations/{self.case.pk}/")
        self.assertContains(response, "Awaiting independent review")
        self.assertContains(response, "Retest receipt")
        self.assertContains(response, "review_retest")
        self.assertContains(response, verification.check_run.result["run_id"])

    def test_review_does_not_resurrect_historical_resolved_status(self):
        Investigation.objects.filter(pk=self.case.pk).update(status="resolved")
        verification = self.submit()
        self.case = self.decide(verification)
        self.assertEqual(self.case.status, "resolved")

    def test_database_constraint_rejects_unreviewed_approval_or_self_review(self):
        verification = self.submit()
        for changes in (
            {"status": "approved"},
            {
                "status": "approved",
                "reviewer": self.analyst,
                "rationale": "Self approval rejected",
                "decided_at": timezone.now(),
            },
        ):
            with self.assertRaises(IntegrityError), transaction.atomic():
                CaseVerification.objects.filter(pk=verification.pk).update(**changes)

    def test_failed_audit_write_rolls_back_review_and_task_state(self):
        verification = self.submit()
        with patch(
            "bridge.case_workflow.Audit.objects.create",
            side_effect=RuntimeError("modeled audit failure"),
        ):
            with self.assertRaises(RuntimeError):
                self.decide(verification)
        verification.refresh_from_db()
        self.task.refresh_from_db()
        self.assertEqual(verification.status, "pending")
        self.assertEqual(self.task.status, "awaiting_retest")

    def test_wrong_application_form_identifiers_are_rejected_without_exposure(self):
        other = Integration.objects.create(slug="other-retest", name="Other synthetic app")
        foreign = CheckRun.objects.create(
            integration=other,
            suite=SUITE,
            revision="0" * 64,
            digest="0" * 64,
            result={},
            status="passed",
        )
        browser = Client()
        browser.force_login(self.analyst)
        response = browser.post(
            f"/investigations/{self.case.pk}/work/",
            {
                "version": self.case.version,
                "operation": "submit_retest",
                "task_id": str(self.task.pk),
                "check_run_id": str(foreign.pk),
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(CaseVerification.objects.exists())

    def test_csrf_valid_browser_can_submit_and_independent_reviewer_can_decide(self):
        browser = Client(enforce_csrf_checks=True)
        browser.force_login(self.analyst)
        path = f"/investigations/{self.case.pk}/"
        self.assertEqual(browser.get(path).status_code, 200)
        response = browser.post(
            path + "work/",
            {
                "csrfmiddlewaretoken": browser.cookies["csrftoken"].value,
                "version": self.case.version,
                "operation": "submit_retest",
                "task_id": str(self.task.pk),
                "check_run_id": str(self.run.pk),
            },
        )
        self.assertEqual(response.status_code, 302)
        verification = CaseVerification.objects.get()
        self.case.refresh_from_db()
        browser.force_login(self.reviewer)
        self.assertEqual(browser.get(path).status_code, 200)
        response = browser.post(
            path + "work/",
            {
                "csrfmiddlewaretoken": browser.cookies["csrftoken"].value,
                "version": self.case.version,
                "operation": "review_retest",
                "verification_id": str(verification.pk),
                "decision": "approved",
                "rationale": "Both access controls match this recorded lab scope.",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertContains(browser.get(path), "Verified within recorded lab scope")

    def test_stale_verified_task_does_not_keep_a_green_work_label(self):
        verification = self.submit()
        self.case = self.decide(verification)
        self.case.events.add(self.events[2])
        task = console_context(self.case)["case_tasks"][0]
        self.assertEqual(task.work_label, "Verification needs review")

    def test_submission_history_is_bounded(self):
        CaseVerification.objects.bulk_create(
            [
                CaseVerification(
                    task=self.task,
                    check_run=self.run,
                    case_version=100 + index,
                    evidence_sha256=self.task.evidence_sha256,
                    check_digest=self.run.digest,
                    submitted_by=self.analyst,
                )
                for index in range(20)
            ]
        )
        with self.assertRaises(WorkflowError):
            self.submit()

    def test_case_forms_keep_bounds_and_reject_file_uploads_after_csrf(self):
        browser = Client(enforce_csrf_checks=True)
        browser.force_login(self.analyst)
        path = f"/investigations/{self.case.pk}/"
        browser.get(path)
        body = {
            "csrfmiddlewaretoken": browser.cookies["csrftoken"].value,
            "version": self.case.version,
            "operation": "structured_note",
            "kind": "observed_fact",
        }
        self.assertEqual(
            browser.post(path + "work/", {**body, "note": "x" * 9000}).status_code, 413
        )
        self.assertEqual(
            browser.post(
                path + "work/",
                {
                    **body,
                    "note": "No files allowed.",
                    "file": io.BytesIO(b"nonfunctional synthetic file"),
                },
            ).status_code,
            415,
        )
