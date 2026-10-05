"""Real disposable SQL policy checks; no signed token or native IdP is implied."""

import json
from dataclasses import asdict, replace
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.db import DatabaseError, transaction
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

from bridge.federation import (
    SESSION_KEY,
    FederationDenied,
    VerifiedIdentity,
    admit_verified_identity,
    check_browser_admission,
    check_write_admission,
    provision_identity,
)
from bridge.models import (
    FederatedExchange,
    FederatedFlowWindow,
    FederatedIdentity,
    FederatedLogoutNotice,
    FederatedSession,
    IdentityAudit,
)
from bridge.oidc_state import (
    BROWSER_KEY,
    begin_exchange,
    consume_exchange,
    consume_verified_logout,
)
from integrations.identity.protocol import VerifiedLogout


class _OIDCFixture:
    def setUp(self):
        self.now = timezone.now().replace(microsecond=0)
        for module in ("bridge.oidc_state", "bridge.federation"):
            clock = patch(module + ".timezone", wraps=timezone)
            clock.start().now.return_value = self.now
            self.addCleanup(clock.stop)
        self.issuer = "https://identity-fixture.invalid/realms/lab"

    def request(self, *, secure=True):
        request = RequestFactory().get("/", secure=secure)
        SessionMiddleware(lambda req: None).process_request(request)
        request.session.save()
        AuthenticationMiddleware(lambda req: None).process_request(request)
        return request


@override_settings(FEDERATED_AUTH_ENABLED=True)
class OIDCStateTests(_OIDCFixture, TestCase):
    def test_callback_state_can_be_claimed_exactly_once(self):
        request = self.request()
        state = begin_exchange(request, self.issuer)
        consume_exchange(request, self.issuer, state)
        with self.assertRaises(FederationDenied):
            consume_exchange(request, self.issuer, state)
        self.assertEqual(FederatedExchange.objects.get().consumed_at, self.now)

    def test_other_browser_and_other_issuer_cannot_consume_state(self):
        request, other = self.request(), self.request()
        state = begin_exchange(request, self.issuer)
        begin_exchange(other, self.issuer)
        for browser, issuer in ((other, self.issuer), (request, self.issuer + "-other")):
            with self.subTest(issuer=issuer), self.assertRaises(FederationDenied):
                consume_exchange(browser, issuer, state)
        consume_exchange(request, self.issuer, state)

    def test_expired_or_future_created_state_cannot_be_consumed(self):
        for created in (self.now - timedelta(minutes=5), self.now + timedelta(seconds=6)):
            request = self.request()
            state = begin_exchange(request, self.issuer)
            FederatedExchange.objects.filter(consumed_at=None).update(
                created_at=created, expires_at=created + timedelta(minutes=5)
            )
            with self.subTest(created=created), self.assertRaises(FederationDenied):
                consume_exchange(request, self.issuer, state)

    def test_bad_state_values_fail_closed_without_consuming_good_state(self):
        request = self.request()
        state = begin_exchange(request, self.issuer)
        for invalid in (None, 1, {}, [], "", "x" * 42, "x" * 44, "!" * 43, "x" * 42 + "\n"):
            with self.subTest(kind=type(invalid).__name__), self.assertRaises(FederationDenied):
                consume_exchange(request, self.issuer, invalid)
        consume_exchange(request, self.issuer, state)

    def test_missing_browser_binding_cannot_claim_even_correct_state(self):
        request = self.request()
        state = begin_exchange(request, self.issuer)
        del request.session[BROWSER_KEY]
        with self.assertRaises(FederationDenied):
            consume_exchange(request, self.issuer, state)
        self.assertIsNone(FederatedExchange.objects.get().consumed_at)

    def test_disabled_plaintext_and_client_side_session_flows_are_rejected(self):
        for options, secure in (
            ({"FEDERATED_AUTH_ENABLED": False}, True),
            ({}, False),
            ({"SESSION_ENGINE": "django.contrib.sessions.backends.signed_cookies"}, True),
        ):
            with (
                self.subTest(options=options, secure=secure),
                override_settings(**options),
                self.assertRaises(FederationDenied),
            ):
                begin_exchange(self.request(secure=secure), self.issuer)
        self.assertEqual(FederatedExchange.objects.count(), 0)

    def test_per_browser_pending_limit_and_consumed_slot_reuse(self):
        request = self.request()
        states = [begin_exchange(request, self.issuer) for _ in range(4)]
        with self.assertRaises(FederationDenied):
            begin_exchange(request, self.issuer)
        consume_exchange(request, self.issuer, states[0])
        begin_exchange(request, self.issuer)
        self.assertEqual(FederatedExchange.objects.filter(consumed_at=None).count(), 4)

    def test_login_global_rate_survives_separate_browser_sessions_and_resets(self):
        for _ in range(20):
            begin_exchange(self.request(), self.issuer)
        with self.assertRaises(FederationDenied):
            begin_exchange(self.request(), self.issuer)
        FederatedFlowWindow.objects.filter(pk="login").update(
            window_start=self.now - timedelta(minutes=1)
        )
        begin_exchange(self.request(), self.issuer)
        self.assertEqual(FederatedFlowWindow.objects.get(pk="login").requests, 1)

    def test_state_and_browser_values_are_not_stored_in_flow_rows(self):
        request = self.request()
        state = begin_exchange(request, self.issuer)
        serialized = json.dumps(list(FederatedExchange.objects.values()), default=str)
        for private in (state, request.session[BROWSER_KEY], self.issuer):
            self.assertNotIn(private, serialized)


@override_settings(FEDERATED_AUTH_ENABLED=True)
class OIDCLogoutTests(_OIDCFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.user = get_user_model().objects.create_user(username="logout-fixture-user")
        self.identity, _ = provision_identity(
            issuer=self.issuer, subject="fixture-subject", user_id=self.user.pk
        )
        self.login = VerifiedIdentity(
            issuer=self.issuer,
            subject="fixture-subject",
            provider_session="fixture-provider-session",
            issued_at=self.now,
            authenticated_at=self.now,
            expires_at=self.now + timedelta(minutes=15),
        )
        self.logout = VerifiedLogout(
            issuer=self.issuer,
            subject=self.login.subject,
            provider_session=self.login.provider_session,
            token_id="fixture-logout-token-id",
            issued_at=self.now,
            expires_at=self.now + timedelta(minutes=2),
        )

    def admit(self, evidence=None):
        request = self.request()
        return request, admit_verified_identity(request, evidence or self.login)

    def test_logout_revokes_matching_sessions_and_denies_subsequent_reads_and_writes(self):
        request, session = self.admit()
        _, second = self.admit()
        self.assertEqual(consume_verified_logout(self.logout), 2)
        session.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual(session.revoked_at, self.now)
        self.assertEqual(second.revoked_at, self.now)
        with self.assertRaises(FederationDenied):
            check_browser_admission(request.user, request.session[SESSION_KEY])
        with transaction.atomic(), self.assertRaises(FederationDenied):
            check_write_admission(request.user)
        self.assertEqual(IdentityAudit.objects.filter(origin="provider_logout").count(), 2)

    def test_logout_scope_excludes_other_session_subject_and_issuer(self):
        self.admit()
        controls = [replace(self.login, provider_session="different-session")]
        for evidence in (
            replace(self.login, subject="different-subject"),
            replace(self.login, issuer=self.issuer + "-other"),
        ):
            provision_identity(
                issuer=evidence.issuer, subject=evidence.subject, user_id=self.user.pk
            )
            controls.append(evidence)
        control_requests = [self.admit(evidence)[0] for evidence in controls]
        self.assertEqual(consume_verified_logout(self.logout), 1)
        for request in control_requests:
            check_browser_admission(request.user, request.session[SESSION_KEY])
        self.assertEqual(FederatedSession.objects.filter(revoked_at=None).count(), 3)

    def test_replayed_token_is_rejected_and_cannot_be_rebound_to_another_session(self):
        self.admit()
        _, other = self.admit(replace(self.login, provider_session="other-session"))
        consume_verified_logout(self.logout)
        for evidence in (self.logout, replace(self.logout, provider_session="other-session")):
            with self.subTest(evidence=evidence), self.assertRaises(FederationDenied):
                consume_verified_logout(evidence)
        other.refresh_from_db()
        self.assertIsNone(other.revoked_at)
        self.assertEqual(FederatedLogoutNotice.objects.count(), 1)

    def test_late_login_from_logged_out_session_denied_but_new_session_allowed(self):
        consume_verified_logout(self.logout)
        with self.assertRaises(FederationDenied):
            self.admit()
        self.admit(replace(self.login, provider_session="fresh-session"))
        self.assertEqual(FederatedSession.objects.count(), 1)

    def test_logout_before_provisioning_blocks_late_old_login_without_creating_account(self):
        unlinked = replace(self.logout, subject="not-yet-provisioned")
        self.assertEqual(consume_verified_logout(unlinked), 0)
        self.assertEqual(get_user_model().objects.count(), 1)
        self.assertEqual(FederatedIdentity.objects.count(), 1)
        provision_identity(issuer=self.issuer, subject=unlinked.subject, user_id=self.user.pk)
        with self.assertRaises(FederationDenied):
            self.admit(replace(self.login, subject=unlinked.subject))

    def test_invalid_internal_logout_contract_never_revokes(self):
        self.admit()
        for evidence in (
            asdict(self.logout),
            replace(self.logout, issued_at=self.now + timedelta(seconds=6)),
            replace(self.logout, issued_at=self.now - timedelta(minutes=6)),
            replace(self.logout, expires_at=self.now),
            replace(self.logout, expires_at=self.now + timedelta(minutes=6)),
            replace(self.logout, expires_at=self.now.replace(tzinfo=None)),
            replace(self.logout, token_id=""),
            replace(self.logout, provider_session="bad\nsession"),
        ):
            with self.subTest(kind=type(evidence).__name__), self.assertRaises(FederationDenied):
                consume_verified_logout(evidence)
        self.assertFalse(FederatedLogoutNotice.objects.exists())
        self.assertFalse(FederatedSession.objects.exclude(revoked_at=None).exists())

    def test_disabled_feature_rejects_logout(self):
        with override_settings(FEDERATED_AUTH_ENABLED=False), self.assertRaises(FederationDenied):
            consume_verified_logout(self.logout)
        self.assertFalse(FederatedLogoutNotice.objects.exists())

    def test_audit_failure_rolls_back_session_notice_and_rate_counter(self):
        _, session = self.admit()
        with (
            patch("bridge.oidc_state._audit", side_effect=DatabaseError("synthetic failure")),
            self.assertRaises(DatabaseError),
        ):
            consume_verified_logout(self.logout)
        session.refresh_from_db()
        self.assertIsNone(session.revoked_at)
        self.assertFalse(FederatedLogoutNotice.objects.exists())
        self.assertEqual(FederatedFlowWindow.objects.get(pk="logout").requests, 0)
        self.assertEqual(consume_verified_logout(self.logout), 1)

    def test_logout_rate_limits_unique_validated_notices(self):
        for number in range(60):
            consume_verified_logout(replace(self.logout, token_id=f"notice-{number}"))
        with self.assertRaises(FederationDenied):
            consume_verified_logout(replace(self.logout, token_id="notice-over-limit"))
        self.assertEqual(FederatedLogoutNotice.objects.count(), 60)

    def test_notice_and_audit_do_not_retain_raw_provider_identifiers(self):
        self.admit()
        consume_verified_logout(self.logout)
        serialized = json.dumps(
            {
                "notices": list(FederatedLogoutNotice.objects.values()),
                "audits": list(IdentityAudit.objects.values()),
            },
            default=str,
        )
        for private in (
            self.logout.token_id,
            self.logout.subject,
            self.logout.provider_session,
            self.issuer,
        ):
            self.assertNotIn(private, serialized)
