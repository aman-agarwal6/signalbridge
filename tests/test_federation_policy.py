"""Local identity-policy tests, not cryptographic OIDC or native Keycloak evidence."""

import io
import json
from dataclasses import replace
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, IntegrityError, transaction
from django.test import Client, RequestFactory, TestCase, override_settings
from django.utils import timezone

from bridge.federation import (
    SESSION_KEY,
    FederationDenied,
    VerifiedIdentity,
    admit_verified_identity,
    check_browser_admission,
    check_write_admission,
    provision_identity,
    revoke_browser_session,
    set_identity_enabled,
    validate_link,
)
from bridge.models import (
    FederatedIdentity,
    FederatedSession,
    IdentityAudit,
    Integration,
    Investigation,
    Membership,
    Note,
)
from bridge.services import write_membership


@override_settings(FEDERATED_AUTH_ENABLED=True)
class FederationPolicyTests(TestCase):
    def setUp(self):
        self.now = timezone.now().replace(microsecond=0)
        self.clock = patch("bridge.federation.timezone", wraps=timezone)
        self.clock.start().now.return_value = self.now
        self.addCleanup(self.clock.stop)
        self.user = get_user_model().objects.create_user(username="identity-fixture-analyst")
        self.other = get_user_model().objects.create_user(username="identity-fixture-other")
        self.app = Integration.objects.create(slug="identity-docs", name="Synthetic documents")
        self.other_app = Integration.objects.create(
            slug="identity-expenses", name="Synthetic expenses"
        )
        Membership.objects.create(user=self.user, integration=self.app, role="analyst")
        Membership.objects.create(user=self.other, integration=self.other_app, role="reviewer")
        self.evidence = VerifiedIdentity(
            issuer="https://identity-fixture.invalid/realms/lab",
            subject="synthetic-subject-never-a-live-account",
            provider_session="synthetic-provider-session",
            issued_at=self.now,
            authenticated_at=self.now,
            expires_at=self.now + timedelta(minutes=30),
        )
        self.identity, _ = provision_identity(
            issuer=self.evidence.issuer, subject=self.evidence.subject, user_id=self.user.pk
        )

    def request(self, *, secure=True):
        request = RequestFactory().get("/", secure=secure)
        SessionMiddleware(lambda req: None).process_request(request)
        request.session.save()
        AuthenticationMiddleware(lambda req: None).process_request(request)
        return request

    def admit(self, evidence=None):
        request = self.request()
        registry = admit_verified_identity(request, evidence or self.evidence)
        return request, registry

    def browser(self, request, *, csrf=False):
        browser = Client(enforce_csrf_checks=csrf)
        browser.cookies["sessionid"] = request.session.session_key
        return browser

    def test_explicit_link_does_not_change_roles_or_privileges(self):
        request, session = self.admit()
        self.assertEqual(request.user.pk, self.user.pk)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_staff or self.user.is_superuser)
        self.assertEqual(
            list(Membership.objects.filter(user=self.user).values_list("role", flat=True)),
            ["analyst"],
        )
        self.assertEqual(session.identity_id, self.identity.pk)

    def test_matching_email_is_not_an_identity_link(self):
        self.user.email = "same-fixture@example.invalid"
        self.user.save(update_fields=["email"])
        get_user_model().objects.create_user(username="unlinked-fixture", email=self.user.email)
        with self.assertRaises(FederationDenied):
            admit_verified_identity(
                self.request(), replace(self.evidence, subject="unlinked-subject")
            )
        self.assertFalse(FederatedSession.objects.exists())
        self.assertEqual(get_user_model().objects.count(), 3)

    def test_issuer_and_subject_must_both_match_exactly(self):
        for evidence in (
            replace(self.evidence, issuer=self.evidence.issuer + "/"),
            replace(self.evidence, issuer="https://other-issuer.invalid/realms/lab"),
            replace(self.evidence, subject=self.evidence.subject.upper()),
        ):
            with (
                self.subTest(issuer=evidence.issuer, subject=evidence.subject),
                self.assertRaises(FederationDenied),
            ):
                admit_verified_identity(self.request(), evidence)
        self.assertFalse(FederatedSession.objects.exists())

    def test_claim_dictionary_is_not_validated_adapter_evidence(self):
        with self.assertRaises(FederationDenied):
            admit_verified_identity(
                self.request(),
                {"iss": self.evidence.issuer, "sub": self.evidence.subject, "roles": ["reviewer"]},
            )
        self.assertFalse(FederatedSession.objects.exists())

    def test_invalid_link_metadata_is_rejected(self):
        for issuer, subject in (
            ("http://identity-fixture.invalid", "subject"),
            ("https://user:password@identity-fixture.invalid", "subject"),
            ("https://identity-fixture.invalid?query=x", "subject"),
            ("https://identity-fixture.invalid/#fragment", "subject"),
            ("https://identity-fixture.invalid:0", "subject"),
            (self.evidence.issuer, ["subject"]),
            (self.evidence.issuer, " subject"),
            (self.evidence.issuer, "subject\nvalue"),
            (self.evidence.issuer, "x" * 256),
        ):
            with self.subTest(issuer=issuer), self.assertRaises(FederationDenied):
                validate_link(issuer, subject)

    def test_link_is_idempotent_but_cannot_be_reassigned(self):
        identity, changed = provision_identity(
            issuer=self.evidence.issuer, subject=self.evidence.subject, user_id=self.user.pk
        )
        self.assertEqual(identity.pk, self.identity.pk)
        self.assertFalse(changed)
        with self.assertRaises(FederationDenied):
            provision_identity(
                issuer=self.evidence.issuer, subject=self.evidence.subject, user_id=self.other.pk
            )
        self.assertEqual(IdentityAudit.objects.count(), 1)

    def test_provisioning_refuses_inactive_or_missing_account(self):
        get_user_model().objects.filter(pk=self.other.pk).update(is_active=False)
        for user_id in (self.other.pk, 999999):
            with self.subTest(user_id=user_id), self.assertRaises(FederationDenied):
                provision_identity(
                    issuer=self.evidence.issuer, subject="new-subject", user_id=user_id
                )
        self.assertEqual(FederatedIdentity.objects.count(), 1)

    def test_provisioning_caps_links_per_account(self):
        for number in range(7):
            provision_identity(
                issuer=self.evidence.issuer, subject=f"additional-{number}", user_id=self.user.pk
            )
        with self.assertRaises(FederationDenied):
            provision_identity(
                issuer=self.evidence.issuer, subject="ninth-link", user_id=self.user.pk
            )
        self.assertEqual(FederatedIdentity.objects.count(), 8)

    def test_authentication_disabled_and_plaintext_fail_closed(self):
        with override_settings(FEDERATED_AUTH_ENABLED=False), self.assertRaises(FederationDenied):
            admit_verified_identity(self.request(), self.evidence)
        with self.assertRaises(FederationDenied):
            admit_verified_identity(self.request(secure=False), self.evidence)
        self.assertFalse(FederatedSession.objects.exists())

    def test_disabled_link_and_disabled_user_cannot_sign_in(self):
        set_identity_enabled(self.identity.pk, enabled=False)
        with self.assertRaises(FederationDenied):
            self.admit()
        set_identity_enabled(self.identity.pk, enabled=True)
        get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
        with self.assertRaises(FederationDenied):
            self.admit()
        self.assertFalse(FederatedSession.objects.exists())

    def test_stale_future_naive_or_expired_admission_times_rejected(self):
        variants = [
            replace(self.evidence, issued_at=self.now + timedelta(seconds=6)),
            replace(self.evidence, authenticated_at=self.now + timedelta(seconds=6)),
            replace(self.evidence, authenticated_at=self.now - timedelta(minutes=5, seconds=1)),
            replace(self.evidence, issued_at=self.now - timedelta(minutes=5, seconds=1)),
            replace(self.evidence, expires_at=self.now),
            replace(self.evidence, issued_at=self.now.replace(tzinfo=None)),
            replace(self.evidence, expires_at="later"),
            replace(self.evidence, provider_session=""),
        ]
        for evidence in variants:
            with self.subTest(evidence=evidence), self.assertRaises(FederationDenied):
                self.admit(evidence)
        self.assertFalse(FederatedSession.objects.exists())

    def test_expiry_is_fixed_and_capped_by_provider_expiry(self):
        request, session = self.admit()
        self.assertEqual(session.expires_at, self.now + timedelta(minutes=15))
        short = self.evidence.expires_at - timedelta(minutes=28)
        _, short_session = self.admit(replace(self.evidence, expires_at=short))
        self.assertEqual(short_session.expires_at, short)
        browser = self.browser(request)
        self.assertEqual(browser.get("/", secure=True).status_code, 200)
        session.refresh_from_db()
        self.assertEqual(session.expires_at, self.now + timedelta(minutes=15))

    def test_session_rotates_pre_authentication_cookie_and_stores_no_token(self):
        request = self.request()
        old_key = request.session.session_key
        session = admit_verified_identity(request, self.evidence)
        self.assertNotEqual(request.session.session_key, old_key)
        self.assertNotEqual(session.binding_digest, request.session[SESSION_KEY]["binding"])
        self.assertNotIn(
            self.evidence.provider_session,
            json.dumps(FederatedSession.objects.values().get(), default=str),
        )
        audit = list(IdentityAudit.objects.values())
        serialized = json.dumps(audit, default=str)
        for private in (
            self.evidence.subject,
            self.evidence.issuer,
            request.session.session_key,
            request.session[SESSION_KEY]["binding"],
        ):
            self.assertNotIn(private, serialized)

    def test_reauthentication_rotates_existing_authenticated_cookie(self):
        request, prior_registry = self.admit()
        prior_key = request.session.session_key
        admit_verified_identity(request, self.evidence)
        self.assertNotEqual(request.session.session_key, prior_key)
        prior_registry.refresh_from_db()
        self.assertEqual(prior_registry.revoked_at, self.now)
        self.assertEqual(FederatedSession.objects.filter(revoked_at=None).count(), 1)
        old_browser = Client()
        old_browser.cookies["sessionid"] = prior_key
        self.assertEqual(old_browser.get("/", secure=True).status_code, 302)

    def test_account_session_capacity_is_bounded(self):
        for _ in range(8):
            self.admit()
        with self.assertRaises(FederationDenied):
            self.admit()
        self.assertEqual(FederatedSession.objects.count(), 8)
        FederatedSession.objects.order_by("pk").first().delete()
        self.admit()

    def test_identity_cannot_silently_replace_a_different_authenticated_account(self):
        request = self.request()
        request.user = self.other
        with self.assertRaises(FederationDenied):
            admit_verified_identity(request, self.evidence)
        self.assertFalse(FederatedSession.objects.exists())

    def test_failed_admission_audit_rolls_back_registry_and_authentication_storage(self):
        request = self.request()
        with (
            patch(
                "bridge.federation._audit", side_effect=DatabaseError("fixture-audit-unavailable")
            ),
            self.assertRaises(DatabaseError),
        ):
            admit_verified_identity(request, self.evidence)
        self.assertFalse(FederatedSession.objects.exists())
        from django.contrib.sessions.models import Session

        self.assertFalse(Session.objects.filter(session_key=request.session.session_key).exists())

    def test_session_binding_cannot_be_borrowed_by_other_user(self):
        request, _ = self.admit()
        with self.assertRaises(FederationDenied):
            check_browser_admission(self.other, request.session[SESSION_KEY])

    def test_malformed_or_unknown_session_binding_is_rejected(self):
        request, _ = self.admit()
        marker = request.session[SESSION_KEY]
        for bad in (
            None,
            {},
            {**marker, "roles": ["reviewer"]},
            {**marker, "id": "not-a-uuid"},
            {**marker, "binding": "x" * 43},
            {**marker, "binding": ["token"]},
        ):
            with self.subTest(marker=bad), self.assertRaises(FederationDenied):
                check_browser_admission(self.user, bad)

    def test_expired_session_blocks_get_and_write(self):
        request, session = self.admit()
        browser = self.browser(request)
        with patch("bridge.federation.timezone.now", return_value=session.expires_at):
            response = browser.post("/investigations/", {}, secure=True)
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("_auth_user_id", browser.session)
        fresh = self.browser(request)
        with patch("bridge.federation.timezone.now", return_value=session.expires_at):
            response = fresh.get("/", secure=True)
        self.assertEqual(response.status_code, 302)

    def test_clock_reversal_and_disabled_feature_invalidate_existing_session(self):
        request, _ = self.admit()
        with (
            patch("bridge.federation.timezone.now", return_value=self.now - timedelta(seconds=6)),
            self.assertRaises(FederationDenied),
        ):
            check_browser_admission(self.user, request.session[SESSION_KEY])
        with override_settings(FEDERATED_AUTH_ENABLED=False), self.assertRaises(FederationDenied):
            check_browser_admission(self.user, request.session[SESSION_KEY])

    def test_disable_and_reenable_never_resurrect_old_session(self):
        request, registry = self.admit()
        set_identity_enabled(self.identity.pk, enabled=False)
        set_identity_enabled(self.identity.pk, enabled=True)
        registry.refresh_from_db()
        self.assertIsNotNone(registry.revoked_at)
        with self.assertRaises(FederationDenied):
            check_browser_admission(self.user, request.session[SESSION_KEY])
        _, new_session = self.admit()
        self.assertEqual(new_session.identity_version, 3)

    def test_disabled_account_and_removed_membership_take_effect_immediately(self):
        request, _ = self.admit()
        browser = self.browser(request)
        self.assertEqual(browser.get("/", secure=True).status_code, 200)
        Membership.objects.filter(user=self.user, integration=self.app).delete()
        self.assertEqual(browser.get("/", secure=True).status_code, 404)
        get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertEqual(browser.get("/", secure=True).status_code, 302)

    def test_cross_application_role_cannot_be_borrowed(self):
        request, _ = self.admit()
        self.assertEqual(
            self.browser(request).get("/?app=identity-expenses", secure=True).status_code, 404
        )
        with transaction.atomic(), self.assertRaises(PermissionError):
            write_membership(request.user, self.other_app)

    def test_revocation_after_request_check_blocks_transactional_case_write(self):
        request, _ = self.admit()
        check_browser_admission(request.user, request.session[SESSION_KEY])
        set_identity_enabled(self.identity.pk, enabled=False)
        with transaction.atomic(), self.assertRaises(FederationDenied):
            write_membership(request.user, self.app)
        self.assertFalse(Note.objects.exists())

    def test_http_case_write_rechecks_revocation_after_its_scope_lookup(self):
        from bridge import views

        request, _ = self.admit()
        case = Investigation.objects.create(
            integration=self.app,
            rule="R1",
            correlation="revoked-identity-case",
            title="Synthetic",
            severity="medium",
            explanation="Synthetic",
        )
        original = views.scope

        def revoke_after_scope(*args, **kwargs):
            context = original(*args, **kwargs)
            set_identity_enabled(self.identity.pk, enabled=False)
            return context

        with patch("bridge.views.scope", side_effect=revoke_after_scope):
            response = self.browser(request).post(
                f"/investigations/{case.pk}/",
                {"action": "note", "version": 1, "note": "This write must reject revocation."},
                secure=True,
            )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Note.objects.exists())
        case.refresh_from_db()
        self.assertEqual(case.version, 1)

    def test_write_guard_requires_transaction_and_current_registry(self):
        request, registry = self.admit()
        # TestCase itself wraps a transaction; explicitly exercise the precondition.
        with patch("bridge.federation.transaction.get_connection") as connection:
            connection.return_value.in_atomic_block = False
            with self.assertRaises(RuntimeError):
                check_write_admission(request.user)
        with transaction.atomic():
            self.assertEqual(write_membership(request.user, self.app).role, "analyst")
        FederatedSession.objects.filter(pk=registry.pk).update(revoked_at=self.now)
        with transaction.atomic(), self.assertRaises(FederationDenied):
            write_membership(request.user, self.app)

    def test_database_failure_is_unavailable_not_authenticated_fallback(self):
        request, _ = self.admit()
        with patch(
            "bridge.federation_middleware.check_browser_admission",
            side_effect=DatabaseError("private-detail"),
        ):
            response = self.browser(request).get("/", secure=True)
        self.assertEqual(response.status_code, 503)
        self.assertNotContains(response, "private-detail", status_code=503)

    def test_plaintext_request_cannot_use_registry_and_forwarded_header_is_insufficient(self):
        request, _ = self.admit()
        response = self.browser(request).get("/", HTTP_X_FORWARDED_PROTO="https")
        self.assertEqual(response.status_code, 302)

    def test_local_logout_is_csrf_protected_and_revokes_registry(self):
        request, registry = self.admit()
        response = self.browser(request, csrf=True).post("/logout/", {}, secure=True)
        self.assertEqual(response.status_code, 403)
        registry.refresh_from_db()
        self.assertIsNone(registry.revoked_at)
        browser = self.browser(request)
        self.assertEqual(browser.get("/logout/", secure=True).status_code, 405)
        self.assertEqual(browser.post("/logout/", {}, secure=True).status_code, 302)
        registry.refresh_from_db()
        self.assertEqual(registry.revoked_at, self.now)
        self.assertEqual(IdentityAudit.objects.filter(action="session.revoked").count(), 1)

    def test_repeat_logout_is_idempotent(self):
        request, _ = self.admit()
        revoke_browser_session(request.user, request.session[SESSION_KEY])
        revoke_browser_session(request.user, request.session[SESSION_KEY])
        self.assertEqual(IdentityAudit.objects.filter(action="session.revoked").count(), 1)

    def test_registry_constraints_reject_overlong_or_nonpositive_lifetime(self):
        _, registry = self.admit()
        for expiry in (self.now, self.now + timedelta(minutes=15, seconds=1)):
            with (
                self.subTest(expiry=expiry),
                self.assertRaises(IntegrityError),
                transaction.atomic(),
            ):
                FederatedSession.objects.filter(pk=registry.pk).update(expires_at=expiry)

    def test_operator_command_requires_explicit_local_operation(self):
        with self.assertRaises(CommandError):
            call_command(
                "federated_identity",
                "disable",
                identity_id=str(self.identity.pk),
                stdout=io.StringIO(),
            )
        self.identity.refresh_from_db()
        self.assertTrue(self.identity.enabled)

    def test_operator_command_keeps_subject_out_of_output_and_audits_origin(self):
        output = io.StringIO()
        with patch(
            "bridge.management.commands.federated_identity.sys.stdin",
            io.StringIO("synthetic-command-subject\n"),
        ):
            call_command(
                "federated_identity",
                "provision",
                local_database_operator=True,
                issuer=self.evidence.issuer,
                username=self.user.username,
                stdout=output,
            )
        self.assertNotIn("synthetic-command-subject", output.getvalue())
        self.assertNotIn(self.user.username, output.getvalue())
        audit = IdentityAudit.objects.order_by("pk").last()
        self.assertEqual(audit.origin, "local_operator")
        self.assertIsNone(audit.actor)

    def test_operator_command_rejects_extra_input_and_missing_account(self):
        for data, username in (
            ("first\nsecond", self.user.username),
            ("x" * 256, self.user.username),
            ("valid", "missing-account"),
        ):
            with (
                self.subTest(username=username),
                patch("bridge.management.commands.federated_identity.sys.stdin", io.StringIO(data)),
                self.assertRaises(CommandError),
            ):
                call_command(
                    "federated_identity",
                    "provision",
                    local_database_operator=True,
                    issuer=self.evidence.issuer,
                    username=username,
                    stdout=io.StringIO(),
                )
        self.assertEqual(FederatedIdentity.objects.count(), 1)

    def test_local_accounts_continue_without_federation_or_registry_queries(self):
        browser = Client()
        browser.force_login(self.user)
        with (
            override_settings(FEDERATED_AUTH_ENABLED=False),
            patch(
                "bridge.federation_middleware.check_browser_admission",
                side_effect=AssertionError("Unexpected identity check"),
            ),
        ):
            self.assertEqual(browser.get("/").status_code, 200)
            self.assertEqual(browser.post("/logout/").status_code, 302)

    def test_no_oidc_token_or_backchannel_route_is_exposed_by_foundation(self):
        for path in ("/oidc/callback/", "/oidc/logout/", "/oidc/backchannel/"):
            self.assertEqual(Client().post(path, {"id_token": "unsigned-fixture"}).status_code, 404)
        self.assertEqual(FederatedIdentity.objects.count(), 1)
        self.assertFalse(FederatedSession.objects.exists())

    def test_viewer_cannot_write_after_federated_admission(self):
        Membership.objects.filter(user=self.user, integration=self.app).update(role="viewer")
        request, _ = self.admit()
        case = Investigation.objects.create(
            integration=self.app,
            rule="R1",
            correlation="synthetic-identity-case",
            title="Synthetic",
            severity="medium",
            explanation="Synthetic",
        )
        response = self.browser(request).post(
            f"/investigations/{case.pk}/",
            {"action": "note", "version": 1, "note": "Must require analyst permission."},
            secure=True,
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Note.objects.exists())
