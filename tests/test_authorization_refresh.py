"""Deterministic permission-change tests; no real accounts or native services."""

import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import transaction
from django.test import TestCase, TransactionTestCase

from bridge import findings, practice, services, views
from bridge.models import (
    Audit,
    Finding,
    Integration,
    Investigation,
    Membership,
    Note,
    PracticeEntry,
    PracticeSession,
    Replay,
)


class CaseAuthorizationRefreshTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="bettail", name="BetTail")
        cls.other = Integration.objects.create(slug="netted", name="Netted")
        cls.user = get_user_model().objects.create_user(username="revocation-test-analyst")
        Membership.objects.create(user=cls.user, integration=cls.app, role="analyst")
        Membership.objects.create(user=cls.user, integration=cls.other, role="reviewer")
        cls.case = Investigation.objects.create(
            integration=cls.app,
            rule="R1",
            correlation=uuid.uuid4().hex,
            title="Synthetic permission change",
            severity="medium",
            explanation="Test evidence",
        )

    def setUp(self):
        self.client.force_login(self.user)

    def submit_after_change(self, change, action="note"):
        original_scope = views.scope

        def changed_scope(*args, **kwargs):
            context = original_scope(*args, **kwargs)
            change()
            return context

        with patch.object(views, "scope", side_effect=changed_scope):
            return self.client.post(
                f"/investigations/{self.case.pk}/",
                {
                    "action": action,
                    "version": self.case.version,
                    "note": "A note that must require current write permission.",
                    "status": "resolved",
                    "rationale": "A disposition that must require current permission.",
                },
            )

    def assert_preserved(self):
        self.case.refresh_from_db()
        self.assertEqual(self.case.version, 1)
        self.assertEqual(self.case.status, "open")
        self.assertFalse(Note.objects.exists())
        self.assertFalse(Audit.objects.filter(action__startswith="case.").exists())

    def test_note_rejected_when_role_revoked_after_scope_check(self):
        response = self.submit_after_change(
            lambda: Membership.objects.filter(
                user=self.user,
                integration=self.app,
            ).update(role="viewer")
        )
        self.assert_preserved()
        self.assertEqual(response.status_code, 403)

    def test_disposition_rejected_when_role_revoked_after_scope_check(self):
        response = self.submit_after_change(
            lambda: Membership.objects.filter(
                user=self.user,
                integration=self.app,
            ).update(role="viewer"),
            action="disposition",
        )
        self.assert_preserved()
        self.assertEqual(response.status_code, 403)

    def test_deleted_membership_cannot_borrow_other_workspace_role(self):
        response = self.submit_after_change(
            lambda: Membership.objects.filter(
                user=self.user,
                integration=self.app,
            ).delete()
        )
        self.assert_preserved()
        self.assertEqual(response.status_code, 403)

    def test_account_disabled_after_scope_check_cannot_write(self):
        response = self.submit_after_change(
            lambda: (
                get_user_model()
                .objects.filter(
                    pk=self.user.pk,
                )
                .update(is_active=False)
            )
        )
        self.assert_preserved()
        self.assertEqual(response.status_code, 403)

    def test_authorized_case_note_still_saves_and_audits(self):
        response = self.submit_after_change(lambda: None)
        self.assertEqual(response.status_code, 302)
        self.case.refresh_from_db()
        self.assertEqual(self.case.version, 2)
        self.assertEqual(Note.objects.get().author, self.user)
        self.assertEqual(Audit.objects.get(action="case.note").actor, self.user)

    def test_authorized_case_disposition_still_saves_and_audits(self):
        response = self.submit_after_change(lambda: None, action="disposition")
        self.assertEqual(response.status_code, 302)
        self.case.refresh_from_db()
        self.assertEqual((self.case.version, self.case.status), (2, "resolved"))
        self.assertEqual(Note.objects.count(), 1)
        self.assertEqual(Audit.objects.get(action="case.disposition").integration, self.app)

    def test_case_moved_after_scope_check_cannot_use_stale_workspace_binding(self):
        response = self.submit_after_change(
            lambda: Investigation.objects.filter(pk=self.case.pk).update(integration=self.other)
        )
        self.assert_preserved()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.case.integration, self.other)

    def test_disabled_account_cannot_start_practice_with_stale_user_object(self):
        get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertTrue(self.user.is_active)
        with self.assertRaises(PermissionError):
            practice.start(self.user, self.app, "access-review")
        self.assertFalse(PracticeSession.objects.exists())
        self.assertFalse(PracticeEntry.objects.exists())

    def test_disabled_account_cannot_reveal_or_save_practice(self):
        attempt = practice.start(self.user, self.app, "access-review")
        get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
        for action in ("reveal", "save", "submit"):
            with self.subTest(action=action), self.assertRaises(PermissionError):
                practice.update(self.user, self.app, attempt.pk, 1, action, evidence="E2")
        attempt.refresh_from_db()
        self.assertEqual((attempt.version, attempt.status, attempt.revealed), (1, "draft", []))
        self.assertEqual(PracticeEntry.objects.count(), 1)

    def test_replay_creation_rechecks_account_after_evaluation(self):
        original = services.evaluate

        def deactivate(*args):
            result = original(*args)
            get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
            return result

        with patch.object(services, "evaluate", side_effect=deactivate):
            with self.assertRaises(PermissionError):
                services.create_replay(self.user, self.app, "revised")
        self.assertFalse(Replay.objects.exists())
        self.assertFalse(Audit.objects.exists())

    def test_replay_move_between_authorization_and_lock_rolls_back(self):
        proposal = services.create_replay(self.user, self.app, "revised")
        reviewer = get_user_model().objects.create_user(username="revocation-test-reviewer")
        Membership.objects.create(user=reviewer, integration=self.app, role="reviewer")
        original = services.write_membership

        def move(*args):
            membership = original(*args)
            Replay.objects.filter(pk=proposal.pk).update(integration=self.other)
            return membership

        with patch.object(services, "write_membership", side_effect=move):
            with self.assertRaises(PermissionError):
                services.decide_replay(reviewer, proposal.pk, "approved", proposal.version)
        proposal.refresh_from_db()
        self.assertEqual(
            (proposal.status, proposal.version, proposal.integration), ("pending", 1, self.app)
        )
        self.assertFalse(Audit.objects.filter(action="replay.approved").exists())

    def test_finding_move_between_authorization_and_lock_rolls_back(self):
        finding = Finding.objects.create(
            integration=self.app,
            tool="test",
            fingerprint="a" * 64,
            severity="warning",
            rule_id="test",
            title="Synthetic finding",
        )
        original = services.write_membership

        def move(*args):
            membership = original(*args)
            Finding.objects.filter(pk=finding.pk).update(integration=self.other)
            return membership

        with patch.object(findings, "write_membership", side_effect=move):
            with self.assertRaises(PermissionError):
                findings.triage(
                    self.user, finding.pk, "reviewed", finding.version, "Synthetic review"
                )
        finding.refresh_from_db()
        self.assertEqual(
            (finding.status, finding.version, finding.integration), ("open", 1, self.app)
        )
        self.assertFalse(Audit.objects.exists())


class WriteTransactionBoundaryTests(TransactionTestCase):
    def test_write_guard_refuses_to_run_without_transaction(self):
        user = get_user_model().objects.create_user(username="transaction-boundary-test")
        app = Integration.objects.create(slug="bettail", name="BetTail")
        Membership.objects.create(user=user, integration=app, role="analyst")
        with self.assertRaises(RuntimeError):
            services.write_membership(user, app)
        with transaction.atomic():
            self.assertEqual(services.write_membership(user, app).user_id, user.pk)
