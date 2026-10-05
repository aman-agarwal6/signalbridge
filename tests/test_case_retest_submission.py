"""Disposable analyst workflow regressions; no native receipt is executed."""

from contextlib import ExitStack
from unittest.mock import patch

from django.test import Client, TestCase

from bridge.case_verification import presentation
from bridge.case_workflow import evidence_binding, operate
from bridge.models import Audit, CaseVerification
from bridge.services import WorkflowError
from tests.test_case_verification import CaseVerificationFixture


class RetestSubmissionTests(CaseVerificationFixture, TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        for primitive in ("socket.socket", "subprocess.run", "subprocess.Popen"):
            stack.enter_context(
                patch(primitive, side_effect=AssertionError("Native primitive forbidden"))
            )
        super().setUp()

    def test_current_pending_review_cannot_be_superseded_by_repeat_submission(self):
        verification = self.submit()
        version = self.case.version
        audits = Audit.objects.count()
        for attempt in range(25):
            with (
                self.subTest(attempt=attempt),
                self.assertRaisesMessage(
                    WorkflowError, "already has a retest awaiting independent review"
                ),
            ):
                self.submit()
        self.case.refresh_from_db()
        verification.refresh_from_db()
        self.assertEqual(self.case.version, version)
        self.assertEqual(CaseVerification.objects.count(), 1)
        self.assertEqual(Audit.objects.count(), audits)
        self.assertEqual(
            presentation(self.case, verification, evidence_binding(self.case)),
            ("Awaiting independent review", True),
        )
        self.case = self.decide(verification)
        self.task.refresh_from_db()
        self.assertEqual(self.task.status, "verified")

    def test_csrf_valid_repeat_post_keeps_the_existing_review_and_case_version(self):
        verification = self.submit()
        version = self.case.version
        audits = Audit.objects.count()
        browser = Client(enforce_csrf_checks=True)
        browser.force_login(self.analyst)
        path = f"/investigations/{self.case.pk}/"
        self.assertEqual(browser.get(path).status_code, 200)
        response = browser.post(
            path + "work/",
            {
                "csrfmiddlewaretoken": browser.cookies["csrftoken"].value,
                "version": version,
                "operation": "submit_retest",
                "task_id": str(self.task.pk),
                "check_run_id": str(self.run.pk),
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertTrue(
            "Case update was not accepted." in body, "Repeat submission must show a safe rejection."
        )
        self.assertTrue(
            "Awaiting independent review" in body, "Existing review must remain available."
        )
        self.case.refresh_from_db()
        self.assertEqual(self.case.version, version)
        self.assertEqual(
            list(CaseVerification.objects.values_list("pk", flat=True)), [verification.pk]
        )
        self.assertEqual(Audit.objects.count(), audits)
        self.assertEqual(Audit.objects.filter(action="case.submit_retest").count(), 1)

    def test_stale_pending_submission_can_be_replaced_after_a_case_change(self):
        stale = self.submit()
        self.case = operate(
            self.analyst,
            self.case.pk,
            self.case.version,
            "structured_note",
            {"kind": "uncertainty", "note": "Review the scope alongside this additional context."},
        )
        with self.assertRaises(WorkflowError):
            self.decide(stale)
        fresh = self.submit()
        self.assertNotEqual(fresh.pk, stale.pk)
        self.assertEqual(fresh.case_version, self.case.version)
        self.case = self.decide(fresh)
        fresh.refresh_from_db()
        self.assertEqual(fresh.status, "approved")

    def test_rejected_submission_can_be_resubmitted_for_independent_review(self):
        rejected = self.submit()
        self.case = self.decide(
            rejected,
            decision="rejected",
            rationale="Reconsider the recorded limits before approval.",
        )
        fresh = self.submit()
        self.assertNotEqual(fresh.pk, rejected.pk)
        self.case = self.decide(fresh)
        rejected.refresh_from_db()
        fresh.refresh_from_db()
        self.assertEqual((rejected.status, fresh.status), ("rejected", "approved"))
