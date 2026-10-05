"""Prepared native races. They fail, rather than skip, on another database.

These checks are not covered by the earlier nine-method PostgreSQL receipt.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

from django.contrib.auth import get_user_model
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.sessions.middleware import SessionMiddleware
from django.db import close_old_connections, connection, connections
from django.test import RequestFactory, TransactionTestCase, override_settings, tag
from django.utils import timezone

from bridge.federation import (
    FederationDenied,
    VerifiedIdentity,
    admit_verified_identity,
    provision_identity,
)
from bridge.models import FederatedExchange, FederatedLogoutNotice, FederatedSession, IdentityAudit
from bridge.oidc_state import begin_exchange, consume_exchange, consume_verified_logout
from integrations.identity.protocol import VerifiedLogout


@tag("native_postgres")
@override_settings(FEDERATED_AUTH_ENABLED=True)
class PostgresIdentityTests(TransactionTestCase):
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql", "This gate requires genuine PostgreSQL.")
        self.user = get_user_model().objects.create_user(username="identity-native-fixture")
        now = timezone.now()
        self.login = VerifiedIdentity(
            issuer="https://identity-native-fixture.invalid/realms/lab",
            subject="synthetic-subject",
            provider_session="synthetic-provider-session",
            issued_at=now,
            authenticated_at=now,
            expires_at=now + timedelta(minutes=15),
        )
        provision_identity(
            issuer=self.login.issuer, subject=self.login.subject, user_id=self.user.pk
        )
        self.logout = VerifiedLogout(
            issuer=self.login.issuer,
            subject=self.login.subject,
            provider_session=self.login.provider_session,
            token_id="synthetic-logout-token",
            issued_at=now,
            expires_at=now + timedelta(minutes=2),
        )

    def request(self, session_key=None):
        request = RequestFactory().get("/", secure=True)
        SessionMiddleware(lambda req: None).process_request(request)
        if session_key is None:
            request.session.save()
        else:
            request.session = SessionStore(session_key=session_key)
        AuthenticationMiddleware(lambda req: None).process_request(request)
        return request

    def race(self, first, second):
        ready = Barrier(2, timeout=10)

        def independent(callback):
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET statement_timeout = '5s'")
                    cursor.execute("SET lock_timeout = '2s'")
                ready.wait()
                try:
                    callback()
                    return "accepted"
                except FederationDenied:
                    return "denied"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(independent, callback) for callback in (first, second)]
            return [future.result(timeout=15) for future in futures]

    def test_two_callbacks_share_only_one_consumption(self):
        request = self.request()
        state = begin_exchange(request, self.login.issuer)
        session_key = request.session.session_key

        def consume():
            consume_exchange(self.request(session_key), self.login.issuer, state)

        self.assertEqual(sorted(self.race(consume, consume)), ["accepted", "denied"])
        self.assertIsNotNone(FederatedExchange.objects.get().consumed_at)

    def test_duplicate_logout_creates_one_notice_and_one_revocation(self):
        admit_verified_identity(self.request(), self.login)

        def logout():
            consume_verified_logout(self.logout)

        self.assertEqual(sorted(self.race(logout, logout)), ["accepted", "denied"])
        self.assertEqual(FederatedLogoutNotice.objects.count(), 1)
        self.assertEqual(IdentityAudit.objects.filter(origin="provider_logout").count(), 1)
        self.assertFalse(FederatedSession.objects.filter(revoked_at=None).exists())

    def test_login_racing_logout_cannot_leave_a_live_old_session(self):
        results = self.race(
            lambda: admit_verified_identity(self.request(), self.login),
            lambda: consume_verified_logout(self.logout),
        )
        self.assertEqual(results[1], "accepted")
        self.assertIn(results[0], {"accepted", "denied"})
        self.assertFalse(FederatedSession.objects.filter(revoked_at=None).exists())
        with self.assertRaises(FederationDenied):
            admit_verified_identity(self.request(), self.login)
