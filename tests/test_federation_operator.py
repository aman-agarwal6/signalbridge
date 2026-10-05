"""Disposable local operator checks; never reset a workstation account."""

import io
import json
import secrets
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from bridge.federation import (
    FederationDenied,
    VerifiedIdentity,
    admit_verified_identity,
    provision_identity,
)
from bridge.federation_operator import prune_expired_runtime, recover_local_account
from bridge.models import (
    FederatedExchange,
    FederatedIdentity,
    FederatedLogoutNotice,
    FederatedSession,
    IdentityAudit,
    Integration,
    Membership,
)
from bridge.oidc_state import begin_exchange, consume_exchange, consume_verified_logout
from integrations.identity.protocol import VerifiedLogout
from tests.test_oidc_state import _OIDCFixture


@override_settings(FEDERATED_AUTH_ENABLED=True)
class FederationOperatorTests(_OIDCFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.user = get_user_model().objects.create_user(username="recovery-fixture-account")
        self.app = Integration.objects.create(slug="recovery-fixture", name="Synthetic recovery")
        Membership.objects.create(user=self.user, integration=self.app, role="analyst")
        self.identity, _ = provision_identity(
            issuer=self.issuer, subject="synthetic-recovery-subject", user_id=self.user.pk
        )
        self.login = VerifiedIdentity(
            issuer=self.issuer,
            subject=self.identity.subject,
            provider_session="synthetic-recovery-session",
            issued_at=self.now,
            authenticated_at=self.now,
            expires_at=self.now + timedelta(minutes=15),
        )

    def test_recovery_changes_password_and_revokes_old_browser_and_provider_sessions(self):
        browser = Client()
        browser.force_login(self.user)
        self.assertEqual(browser.get("/").status_code, 200)
        session = admit_verified_identity(self.request(), self.login)
        password = secrets.token_urlsafe(32)
        self.assertEqual(recover_local_account(self.identity.pk, password), 1)
        self.user.refresh_from_db()
        self.identity.refresh_from_db()
        session.refresh_from_db()
        self.assertTrue(self.user.check_password(password))
        self.assertFalse(self.identity.enabled)
        self.assertEqual(self.identity.version, 2)
        self.assertIsNotNone(session.revoked_at)
        self.assertEqual(browser.get("/").status_code, 302)
        self.assertTrue(Client().login(username=self.user.username, password=password))
        with self.assertRaises(FederationDenied):
            admit_verified_identity(self.request(), self.login)

    def test_recovery_preserves_roles_activation_and_privilege_flags(self):
        recover_local_account(self.identity.pk, secrets.token_urlsafe(32))
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertFalse(self.user.is_staff or self.user.is_superuser)
        self.assertEqual(Membership.objects.get(user=self.user).role, "analyst")
        self.assertEqual(get_user_model().objects.count(), 1)

    def test_recovery_disables_all_own_links_but_leaves_other_account_untouched(self):
        second, _ = provision_identity(
            issuer=self.issuer, subject="second-own-subject", user_id=self.user.pk
        )
        other = get_user_model().objects.create_user(username="recovery-other-fixture")
        other_identity, _ = provision_identity(
            issuer=self.issuer, subject="other-user-subject", user_id=other.pk
        )
        other_hash = other.password
        self.assertEqual(recover_local_account(second.pk, secrets.token_urlsafe(32)), 2)
        self.assertFalse(FederatedIdentity.objects.filter(user=self.user, enabled=True).exists())
        other_identity.refresh_from_db()
        other.refresh_from_db()
        self.assertTrue(other_identity.enabled)
        self.assertEqual(other.password, other_hash)
        self.assertEqual(IdentityAudit.objects.filter(action="account.recovered").count(), 2)

    def test_inactive_account_cannot_be_reenabled_by_recovery(self):
        get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
        with self.assertRaises(FederationDenied):
            recover_local_account(self.identity.pk, secrets.token_urlsafe(32))
        self.assertFalse(IdentityAudit.objects.filter(action="account.recovered").exists())

    def test_bad_password_and_reusing_password_fail_without_account_mutation(self):
        for password in (None, "short", "x" * 129, "x" * 16 + "\n"):
            with self.subTest(kind=type(password).__name__), self.assertRaises(FederationDenied):
                recover_local_account(self.identity.pk, password)
        password = secrets.token_urlsafe(32)
        recover_local_account(self.identity.pk, password)
        with self.assertRaises(FederationDenied):
            recover_local_account(self.identity.pk, password)
        self.assertEqual(IdentityAudit.objects.filter(action="account.recovered").count(), 1)

    def test_audit_failure_rolls_back_password_link_and_session_changes(self):
        session = admit_verified_identity(self.request(), self.login)
        original_hash = self.user.password
        with (
            patch("bridge.federation_operator._audit", side_effect=DatabaseError("synthetic")),
            self.assertRaises(DatabaseError),
        ):
            recover_local_account(self.identity.pk, secrets.token_urlsafe(32))
        self.user.refresh_from_db()
        self.identity.refresh_from_db()
        session.refresh_from_db()
        self.assertEqual(self.user.password, original_hash)
        self.assertTrue(self.identity.enabled)
        self.assertIsNone(session.revoked_at)

    def test_recovery_available_when_provider_feature_is_disabled_and_audit_is_redacted(self):
        password = secrets.token_urlsafe(32)
        output = io.StringIO()
        with (
            override_settings(FEDERATED_AUTH_ENABLED=False),
            patch("bridge.management.commands.federated_identity.sys.stdin", io.StringIO(password)),
        ):
            call_command(
                "federated_identity",
                "recover",
                local_database_operator=True,
                identity_id=str(self.identity.pk),
                stdout=output,
            )
        audit = IdentityAudit.objects.get(action="account.recovered")
        self.assertEqual(audit.origin, "local_operator")
        self.assertIsNone(audit.actor)
        serialized = output.getvalue() + json.dumps(
            list(IdentityAudit.objects.values()), default=str
        )
        for private in (password, self.user.username, self.identity.subject, self.issuer):
            self.assertNotIn(private, serialized)

    def test_operator_flag_required_for_recovery_and_prune(self):
        for action in ("recover", "prune"):
            with self.subTest(action=action), self.assertRaises(CommandError):
                call_command("federated_identity", action, stdout=io.StringIO())

    def test_command_rejects_multiline_password_and_unrelated_switches(self):
        for data, extra in (
            (secrets.token_urlsafe(32) + "\nsecond-line", {}),
            (secrets.token_urlsafe(32), {"apply": True}),
            (secrets.token_urlsafe(32), {"username": self.user.username}),
        ):
            with (
                self.subTest(extra=extra),
                patch("bridge.management.commands.federated_identity.sys.stdin", io.StringIO(data)),
                self.assertRaises(CommandError),
            ):
                call_command(
                    "federated_identity",
                    "recover",
                    local_database_operator=True,
                    identity_id=str(self.identity.pk),
                    stdout=io.StringIO(),
                    **extra,
                )
        self.assertFalse(IdentityAudit.objects.filter(action="account.recovered").exists())

    def expired_records(self, count):
        old = timezone.now() - timedelta(days=2)
        for number in range(count):
            digest = f"{number:064x}"
            FederatedExchange.objects.create(
                state_digest=digest,
                browser_digest="b" * 64,
                issuer_digest="c" * 64,
                created_at=old,
                expires_at=old + timedelta(minutes=5),
            )
            FederatedLogoutNotice.objects.create(
                token_digest=digest,
                scope_digest="d" * 64,
                received_at=old,
                block_until=old + timedelta(minutes=16),
            )
            FederatedSession.objects.create(
                identity=self.identity,
                identity_version=1,
                binding_digest=digest,
                created_at=old,
                authenticated_at=old,
                expires_at=old + timedelta(minutes=15),
            )

    def test_prune_is_preview_by_default_and_respects_each_table_batch_limit(self):
        self.expired_records(3)
        expected = {"login_states": 2, "logout_notices": 2, "registry_sessions": 2}
        self.assertEqual(prune_expired_runtime(limit=2), expected)
        self.assertEqual(FederatedSession.objects.count(), 3)
        self.assertEqual(prune_expired_runtime(apply=True, limit=2), expected)
        self.assertEqual(FederatedSession.objects.count(), 1)
        self.assertEqual(FederatedExchange.objects.count(), 1)
        self.assertEqual(FederatedLogoutNotice.objects.count(), 1)

    def test_prune_preserves_live_state_logout_barrier_and_audit(self):
        self.expired_records(1)
        request = self.request()
        state = begin_exchange(request, self.issuer)
        logout = VerifiedLogout(
            issuer=self.issuer,
            subject=self.identity.subject,
            provider_session=self.login.provider_session,
            token_id="active-logout-fixture",
            issued_at=self.now,
            expires_at=self.now + timedelta(minutes=2),
        )
        consume_verified_logout(logout)
        audit_count = IdentityAudit.objects.count()
        prune_expired_runtime(apply=True)
        consume_exchange(request, self.issuer, state)
        with self.assertRaises(FederationDenied):
            admit_verified_identity(self.request(), self.login)
        self.assertEqual(IdentityAudit.objects.count(), audit_count)
        self.assertEqual(FederatedIdentity.objects.count(), 1)

    def test_prune_keeps_recently_expired_rows_for_a_full_day(self):
        self.expired_records(1)
        recent = timezone.now() - timedelta(hours=12)
        FederatedExchange.objects.update(
            created_at=recent, expires_at=recent + timedelta(minutes=5)
        )
        prune_expired_runtime(apply=True)
        self.assertEqual(FederatedExchange.objects.count(), 1)

    def test_prune_command_requires_apply_and_excludes_unrelated_arguments(self):
        self.expired_records(1)
        output = io.StringIO()
        call_command("federated_identity", "prune", local_database_operator=True, stdout=output)
        self.assertIn("preview only", output.getvalue())
        self.assertEqual(FederatedSession.objects.count(), 1)
        with self.assertRaises(CommandError):
            call_command(
                "federated_identity",
                "prune",
                local_database_operator=True,
                identity_id=str(self.identity.pk),
                apply=True,
                stdout=io.StringIO(),
            )
        call_command(
            "federated_identity",
            "prune",
            local_database_operator=True,
            apply=True,
            stdout=io.StringIO(),
        )
        self.assertEqual(FederatedSession.objects.count(), 0)

    def test_prune_rejects_unbounded_and_ambiguous_parameters(self):
        for options in ({"limit": 201}, {"limit": 0}, {"limit": True}, {"apply": "true"}):
            with self.subTest(options=options), self.assertRaises(FederationDenied):
                prune_expired_runtime(**options)
