"""Django request/SQL boundaries with a modeled provider, never native SSO proof."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.http import HttpResponseRedirect
from django.test import Client, TestCase, override_settings

from bridge.federation import VerifiedIdentity, admit_verified_identity, provision_identity
from bridge.models import FederatedExchange, FederatedFlowWindow, FederatedSession
from bridge.oidc_state import begin_exchange
from integrations.identity.configuration import (
    AUTHORIZATION,
    CALLBACK,
    ISSUER,
    IdentityConfiguration,
)
from integrations.identity.protocol import TokenRejected, VerifiedLogout
from tests.test_oidc_state import _OIDCFixture

HOST = "127.0.0.1:18842"


@override_settings(
    FEDERATED_AUTH_ENABLED=True,
    ALLOWED_HOSTS=["127.0.0.1", "testserver"],
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="None",
    CSRF_COOKIE_SECURE=True,
)
class OIDCHTTPTests(_OIDCFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.browser = Client(enforce_csrf_checks=True)
        self.config = IdentityConfiguration(ca_file=Path("nonfunctional-fixture-ca"), jwks={})
        self.provider = Mock()
        self.provider.authorize_redirect.return_value = HttpResponseRedirect(AUTHORIZATION)
        self.patches = [
            patch("bridge.oidc_views.load_configuration", return_value=self.config),
            patch("bridge.oidc_views.create_client", return_value=self.provider),
            patch("bridge.oidc_views.log"),
        ]
        self.configuration_mock, self.factory_mock, self.logger = [p.start() for p in self.patches]
        for p in self.patches:
            self.addCleanup(p.stop)
        self.user = get_user_model().objects.create_user(username="http-identity-fixture")
        self.identity, _ = provision_identity(
            issuer=ISSUER, subject="http-fixture-subject", user_id=self.user.pk
        )
        self.evidence = VerifiedIdentity(
            issuer=ISSUER,
            subject=self.identity.subject,
            provider_session="http-fixture-session",
            issued_at=self.now,
            authenticated_at=self.now,
            expires_at=self.now + timedelta(minutes=15),
        )
        self.provider.authorize_access_token.return_value = {"userinfo": self.evidence}

    def form(self, path, data, **kwargs):
        return self.browser.post(
            path,
            urlencode(data, doseq=True),
            content_type="application/x-www-form-urlencoded",
            secure=kwargs.pop("secure", True),
            HTTP_HOST=kwargs.pop("HTTP_HOST", HOST),
            **kwargs,
        )

    def state(self):
        request = self.request()
        request.session = self.browser.session
        return begin_exchange(request, ISSUER)

    def test_disabled_routes_do_not_load_provider_or_exchange_tokens(self):
        with override_settings(FEDERATED_AUTH_ENABLED=False):
            for route in ("start", "callback", "backchannel"):
                response = self.browser.get(f"/sso/{route}/", secure=True, HTTP_HOST=HOST)
                self.assertEqual(response.status_code, 404)
        self.configuration_mock.assert_not_called()
        self.factory_mock.assert_not_called()

    def test_start_requires_csrf_and_passes_only_fixed_flow_parameters(self):
        self.assertEqual(self.form("/sso/start/", {}).status_code, 403)
        self.provider.authorize_redirect.assert_not_called()
        self.browser.get("/login/", secure=True, HTTP_HOST=HOST)
        response = self.form(
            "/sso/start/",
            {"csrfmiddlewaretoken": self.browser.cookies["csrftoken"].value},
            HTTP_ORIGIN="https://" + HOST,
        )
        self.assertEqual(response.status_code, 302)
        args, options = self.provider.authorize_redirect.call_args
        self.assertEqual(args[1], CALLBACK)
        self.assertEqual(options["response_mode"], "form_post")
        self.assertEqual(options["acr_values"], "2")
        self.assertEqual(options["max_age"], 300)
        self.assertEqual(len(options["nonce"]), 43)
        self.assertEqual(len(options["code_verifier"]), 64)
        self.assertEqual(FederatedExchange.objects.count(), 1)

    def test_callback_claims_state_and_admits_only_verified_internal_evidence(self):
        state = self.state()
        response = self.form("/sso/callback/", {"state": state, "code": "synthetic-code"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        self.assertEqual(FederatedSession.objects.count(), 1)
        self.assertEqual(FederatedExchange.objects.get().consumed_at, self.now)
        self.provider.framework.clear_state_data.assert_called_once()
        self.assertNotIn("synthetic-code", str(dict(self.browser.session)))

    def test_replayed_callback_never_repeats_token_exchange(self):
        state = self.state()
        data = {"state": state, "code": "synthetic-code"}
        self.assertEqual(self.form("/sso/callback/", data).status_code, 302)
        self.assertEqual(self.form("/sso/callback/", data).status_code, 403)
        self.assertEqual(self.provider.authorize_access_token.call_count, 1)

    def test_failed_exchange_consumes_state_and_redacts_provider_exception(self):
        state = self.state()
        secret_marker = "synthetic-code-not-to-log"
        self.provider.authorize_access_token.side_effect = RuntimeError(secret_marker)
        response = self.form("/sso/callback/", {"state": state, "code": secret_marker})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(secret_marker.encode(), response.content)
        self.assertNotIn(secret_marker, str(self.logger.mock_calls))
        self.assertIsNotNone(FederatedExchange.objects.get().consumed_at)
        self.assertFalse(FederatedSession.objects.exists())
        self.provider.framework.clear_state_data.assert_called_once()

    def test_raw_claims_are_not_admitted_as_verified_identity(self):
        self.provider.authorize_access_token.return_value = {
            "userinfo": {"sub": self.identity.subject, "roles": ["reviewer"]}
        }
        response = self.form("/sso/callback/", {"state": self.state(), "code": "synthetic"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(FederatedSession.objects.exists())

    def test_provider_error_or_issuer_mismatch_consumes_state_without_exchange(self):
        for extra in (
            {"error": "denied", "error_description": "private-fixture"},
            {"iss": ISSUER + "x"},
        ):
            response = self.form(
                "/sso/callback/", {"state": self.state(), "code": "synthetic", **extra}
            )
            self.assertEqual(response.status_code, 403)
            self.assertNotIn(b"private-fixture", response.content)
        self.provider.authorize_access_token.assert_not_called()
        self.assertFalse(FederatedExchange.objects.filter(consumed_at=None).exists())

    def test_plaintext_wrong_host_get_and_query_callbacks_fail_before_provider(self):
        data = {"state": "x" * 43, "code": "synthetic"}
        self.assertEqual(self.form("/sso/callback/", data, secure=False).status_code, 400)
        self.assertEqual(self.form("/sso/callback/", data, HTTP_HOST="testserver").status_code, 400)
        self.assertEqual(self.form("/sso/callback/?code=synthetic", data).status_code, 400)
        self.assertEqual(
            self.browser.get("/sso/callback/", secure=True, HTTP_HOST=HOST).status_code, 405
        )
        self.factory_mock.assert_not_called()

    def test_duplicate_extra_and_oversized_callback_fields_cannot_consume_state(self):
        state = self.state()
        for data in (
            {"state": [state, state], "code": "synthetic"},
            {"state": state, "code": "synthetic", "next": "https://other.invalid"},
            {"state": state, "code": "x" * 4096},
        ):
            self.assertEqual(self.form("/sso/callback/", data).status_code, 403)
        self.assertIsNone(FederatedExchange.objects.get().consumed_at)
        self.provider.authorize_access_token.assert_not_called()

    def test_wrong_browser_cannot_use_held_state(self):
        state = self.state()
        self.browser = Client(enforce_csrf_checks=True)
        self.assertEqual(
            self.form("/sso/callback/", {"state": state, "code": "synthetic"}).status_code, 403
        )
        self.provider.authorize_access_token.assert_not_called()

    def test_backchannel_requires_verified_token_then_revokes_without_browser_session(self):
        admitted = admit_verified_identity(self.request(), self.evidence)
        evidence = VerifiedLogout(
            issuer=ISSUER,
            subject=self.identity.subject,
            provider_session=self.evidence.provider_session,
            token_id="http-logout-fixture",
            issued_at=self.now,
            expires_at=self.now + timedelta(minutes=2),
        )
        with patch("bridge.oidc_views.verify_logout_token", return_value=evidence) as verify:
            self.assertEqual(
                self.form("/sso/backchannel/", {"logout_token": "modeled-token"}).status_code, 200
            )
            self.assertEqual(
                self.form("/sso/backchannel/", {"logout_token": "modeled-token"}).status_code, 403
            )
        self.assertEqual(verify.call_count, 2)
        admitted.refresh_from_db()
        self.assertIsNotNone(admitted.revoked_at)

    def test_signature_denial_and_rate_limit_do_not_revoke_sessions(self):
        admitted = admit_verified_identity(self.request(), self.evidence)
        FederatedFlowWindow.objects.create(operation="protocol", window_start=self.now, requests=59)
        with patch("bridge.oidc_views.verify_logout_token", side_effect=TokenRejected()) as verify:
            for _ in range(2):
                self.assertEqual(
                    self.form("/sso/backchannel/", {"logout_token": "invalid"}).status_code, 403
                )
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(FederatedFlowWindow.objects.get(pk="protocol").requests, 60)
        admitted.refresh_from_db()
        self.assertIsNone(admitted.revoked_at)

    def test_disabled_local_account_rejects_verified_login(self):
        get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
        self.assertEqual(
            self.form("/sso/callback/", {"state": self.state(), "code": "synthetic"}).status_code,
            403,
        )
        self.assertFalse(FederatedSession.objects.exists())

    def test_other_app_account_is_not_created_from_verified_subject(self):
        self.provider.authorize_access_token.return_value = {
            "userinfo": replace(self.evidence, subject="unprovisioned-subject")
        }
        self.assertEqual(
            self.form("/sso/callback/", {"state": self.state(), "code": "synthetic"}).status_code,
            403,
        )
        self.assertEqual(get_user_model().objects.count(), 1)

    def test_browser_case_mutations_still_need_csrf(self):
        self.browser.force_login(self.user)
        self.assertEqual(self.form("/logout/", {}).status_code, 403)

    def test_login_button_is_present_only_in_enabled_profile(self):
        response = self.browser.get("/login/", secure=True, HTTP_HOST=HOST)
        self.assertContains(response, "Sign in with organization account")
        with override_settings(FEDERATED_AUTH_ENABLED=False):
            response = self.browser.get("/login/", secure=True, HTTP_HOST=HOST)
        self.assertNotContains(response, "Sign in with organization account")
