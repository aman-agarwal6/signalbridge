"""New native verification races; not satisfied by SQLite or modeled receipts."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from django.contrib.auth import get_user_model
from django.db import close_old_connections, connection, connections
from django.test import TransactionTestCase, tag

from bridge.case_workflow import operate
from bridge.models import Audit, CaseVerification, Membership
from bridge.services import WorkflowError
from tests.test_case_verification import CaseVerificationFixture


@tag("native_postgres")
class PostgresVerificationTests(CaseVerificationFixture, TransactionTestCase):
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql", "This gate requires genuine PostgreSQL.")
        super().setUp()

    def race(self, callbacks):
        ready = Barrier(2, timeout=10)

        def independent(callback):
            close_old_connections()
            try:
                ready.wait()
                try:
                    callback()
                    return "saved"
                except WorkflowError:
                    return "stale"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(independent, callbacks))
        self.assertEqual(sorted(results), ["saved", "stale"])

    def test_two_analysts_submit_once_at_the_same_case_version(self):
        other = get_user_model().objects.create(username="second-native-analyst")
        Membership.objects.create(user=other, integration=self.app, role="analyst")
        version = self.case.version

        def submit(user):
            return lambda: operate(
                user,
                self.case.pk,
                version,
                "submit_retest",
                {
                    "task_id": str(self.task.pk),
                    "check_run_id": str(self.run.pk),
                },
            )

        self.race([submit(self.analyst), submit(other)])
        self.assertEqual(CaseVerification.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="case.submit_retest").count(), 1)

    def test_two_independent_reviewers_have_one_decision_winner(self):
        verification = self.submit()
        other = get_user_model().objects.create(username="second-native-reviewer")
        Membership.objects.create(user=other, integration=self.app, role="reviewer")
        version = self.case.version

        def review(user, decision):
            return lambda: operate(
                user,
                self.case.pk,
                version,
                "review_retest",
                {
                    "verification_id": str(verification.pk),
                    "decision": decision,
                    "rationale": "Recorded lab controls reviewed by an independent reviewer.",
                },
            )

        self.race([review(self.reviewer, "approved"), review(other, "rejected")])
        self.assertEqual(Audit.objects.filter(action="case.review_retest").count(), 1)
        verification.refresh_from_db()
        self.assertIn(verification.status, ("approved", "rejected"))
        self.task.refresh_from_db()
        self.assertEqual(
            self.task.status, "verified" if verification.status == "approved" else "awaiting_retest"
        )
