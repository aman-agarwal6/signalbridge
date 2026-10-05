"""Optional real signed-token checks; require the reviewed identity environment.

Ephemeral keys/tokens stay in memory. No provider, HTTP, MFA interaction or native
SSO is simulated as complete. Missing dependencies fail collection, never skip.
"""

import base64
import copy
import json
import time

from django.contrib.auth import get_user_model
from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from joserfc import jwt
from joserfc.jwk import RSAKey

from bridge.federation import FederationDenied, admit_verified_identity, provision_identity
from bridge.models import FederatedSession, Membership

from .protocol import LOGOUT_EVENT, TokenRejected, verify_login_token, verify_logout_token


class SignedFixture:
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.key = RSAKey.generate_key(
            2048, parameters={"kid": "synthetic-ephemeral", "use": "sig", "alg": "RS256"}
        )
        cls.other_key = RSAKey.generate_key(
            2048, parameters={"kid": "synthetic-ephemeral", "use": "sig", "alg": "RS256"}
        )
        cls.jwks = {"keys": [cls.key.as_dict(private=False)]}
        cls.issuer = "https://identity-fixture.invalid/realms/lab"
        cls.audience = "signalbridge-fixture"
        cls.nonce = "synthetic-nonce-for-memory-only-test-0001"
        cls.access_token = "nonfunctional-synthetic-access-token"

    def claims(self):
        current = int(time.time())
        return {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": "synthetic-subject",
            "sid": "synthetic-provider-session",
            "iat": current,
            "exp": current + 240,
            "auth_time": current,
            "nonce": self.nonce,
            "acr": "2",
            "amr": ["pwd", "otp"],
        }

    def sign(self, claims, *, header=None, key=None):
        return jwt.encode(
            header or {"alg": "RS256", "kid": "synthetic-ephemeral", "typ": "JWT"},
            claims,
            key or self.key,
        )

    def login(self, claims=None, **overrides):
        arguments = {
            "jwks": self.jwks,
            "issuer": self.issuer,
            "audience": self.audience,
            "nonce": self.nonce,
            "access_token": self.access_token,
        }
        arguments.update(overrides)
        return verify_login_token(self.sign(claims or self.claims()), **arguments)

    def logout_claims(self):
        claims = self.claims()
        for name in ("nonce", "auth_time", "acr", "amr"):
            claims.pop(name)
        claims.update(events={LOGOUT_EVENT: {}}, jti="synthetic-logout-message")
        return claims

    def logout(self, claims=None, **overrides):
        arguments = {"jwks": self.jwks, "issuer": self.issuer, "audience": self.audience}
        arguments.update(overrides)
        return verify_logout_token(self.sign(claims or self.logout_claims()), **arguments)


class SignedTokenTests(SignedFixture, SimpleTestCase):
    def test_real_rs256_login_returns_only_the_local_identity_contract(self):
        evidence = self.login()
        self.assertEqual(evidence.subject, "synthetic-subject")
        self.assertEqual(evidence.issuer, self.issuer)
        self.assertEqual(evidence.provider_session, "synthetic-provider-session")
        self.assertFalse(hasattr(evidence, "roles"))

    def test_different_signing_key_and_modified_payload_are_rejected(self):
        original = self.sign(self.claims())
        head, payload, signature = original.split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        claims["sub"] = "other-subject"
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        for value in (
            self.sign(self.claims(), key=self.other_key),
            ".".join((head, payload, signature)),
        ):
            with self.assertRaises(TokenRejected):
                verify_login_token(
                    value,
                    jwks=self.jwks,
                    issuer=self.issuer,
                    audience=self.audience,
                    nonce=self.nonce,
                    access_token=self.access_token,
                )

    def test_wrong_issuer_audience_authorized_party_and_nonce_fail(self):
        for change in (
            {"iss": "https://other-provider.invalid/realms/lab"},
            {"aud": "other-client"},
            {"aud": [self.audience, "other-client"]},
            {"azp": "other-client"},
            {"nonce": "other-nonce"},
            {"nonce_supported": False},
        ):
            with self.subTest(fields=list(change)), self.assertRaises(TokenRejected):
                self.login({**self.claims(), **change})

    def test_mfa_claims_and_recent_authentication_are_required(self):
        for change in (
            {"acr": "1"},
            {"acr": 2},
            {"amr": ["pwd"]},
            {"amr": "pwd otp"},
            {"amr": ["pwd", "otp", "otp"]},
            {"auth_time": int(time.time()) - 301},
            {"auth_time": True},
            {"auth_time": int(time.time()) + 30},
        ):
            with self.subTest(fields=list(change)), self.assertRaises(TokenRejected):
                self.login({**self.claims(), **change})

    def test_expired_future_boolean_and_overlong_lifetimes_fail(self):
        current = int(time.time())
        for change in (
            {"exp": current},
            {"iat": current + 30},
            {"iat": current - 301},
            {"exp": True},
            {"iat": True},
            {"exp": current + 901},
            {"nbf": current + 30},
        ):
            with self.subTest(fields=list(change)), self.assertRaises(TokenRejected):
                self.login({**self.claims(), **change}, now=current)

    def test_optional_access_token_hash_must_match(self):
        with self.assertRaises(TokenRejected):
            self.login({**self.claims(), "at_hash": "nonfunctional-wrong-hash"})

    def test_token_kinds_are_not_interchangeable(self):
        with self.assertRaises(TokenRejected):
            self.login(self.logout_claims())
        with self.assertRaises(TokenRejected):
            self.logout(self.claims())

    def test_logout_requires_exact_event_subject_session_and_message_id(self):
        self.assertEqual(self.logout().token_id, "synthetic-logout-message")
        # Keycloak's revoke-offline-tokens client option adds this boolean.
        keycloak = {LOGOUT_EVENT: {}, "revoke_offline_access": True}
        self.assertEqual(
            self.logout({**self.logout_claims(), "events": keycloak}).token_id,
            "synthetic-logout-message",
        )
        for change in (
            {"events": {LOGOUT_EVENT: {"extra": True}}},
            {"events": {}},
            {"events": {"revoke_offline_access": True}},
            {"events": {LOGOUT_EVENT: {}, "revoke_offline_access": "yes"}},
            {"events": {LOGOUT_EVENT: {}, "other-event": {}}},
            {"sub": ""},
            {"sid": ""},
            {"jti": ""},
            {"nonce": "present"},
        ):
            with self.subTest(fields=list(change)), self.assertRaises(TokenRejected):
                self.logout({**self.logout_claims(), **change})

    def test_embedded_keys_and_header_urls_never_select_verification_material(self):
        for change in ({"jku": "https://outside.invalid/keys"}, {"jwk": self.jwks["keys"][0]}):
            header = {"alg": "RS256", "kid": "synthetic-ephemeral", "typ": "JWT", **change}
            token = self.sign(self.claims(), header=header)
            with self.assertRaises(TokenRejected):
                verify_logout_token(
                    token, jwks=self.jwks, issuer=self.issuer, audience=self.audience
                )

    def test_unknown_duplicate_or_private_keys_are_rejected(self):
        public = copy.deepcopy(self.jwks["keys"][0])
        for keys in (
            {"keys": [{**public, "kid": "wrong"}]},
            {"keys": [public, public]},
            {"keys": [self.key.as_dict(private=True)]},
        ):
            with self.assertRaises(TokenRejected):
                self.login(jwks=keys)

    def test_error_message_does_not_include_token_or_claim_contents(self):
        token = "synthetic-sensitive-marker"
        with self.assertRaises(TokenRejected) as error:
            verify_logout_token(token, jwks=self.jwks, issuer=self.issuer, audience=self.audience)
        self.assertEqual(str(error.exception), "Identity token validation failed.")
        self.assertIsNone(error.exception.__cause__)


@override_settings(FEDERATED_AUTH_ENABLED=True)
class SignedAdmissionTests(SignedFixture, TestCase):
    def request(self):
        request = RequestFactory().get("/", secure=True)
        SessionMiddleware(lambda req: None).process_request(request)
        request.session.save()
        AuthenticationMiddleware(lambda req: None).process_request(request)
        return request

    def test_valid_signature_does_not_create_accounts_or_roles(self):
        evidence = self.login({**self.claims(), "roles": ["admin", "reviewer"]})
        with self.assertRaises(FederationDenied):
            admit_verified_identity(self.request(), evidence)
        self.assertFalse(get_user_model().objects.exists())
        self.assertFalse(FederatedSession.objects.exists())
        user = get_user_model().objects.create_user(username="synthetic-local-account")
        provision_identity(issuer=self.issuer, subject=evidence.subject, user_id=user.pk)
        session = admit_verified_identity(self.request(), evidence)
        self.assertEqual(session.identity.user_id, user.pk)
        self.assertFalse(Membership.objects.exists())
        user.refresh_from_db()
        self.assertFalse(user.is_staff or user.is_superuser)

    def test_disabled_link_or_account_blocks_a_signature_verified_login(self):
        user = get_user_model().objects.create_user(username="synthetic-disabled-account")
        evidence = self.login()
        identity, _ = provision_identity(
            issuer=self.issuer, subject=evidence.subject, user_id=user.pk
        )
        identity.enabled = False
        identity.save(update_fields=["enabled"])
        with self.assertRaises(FederationDenied):
            admit_verified_identity(self.request(), evidence)
        identity.enabled = True
        identity.save(update_fields=["enabled"])
        user.is_active = False
        user.save(update_fields=["is_active"])
        with self.assertRaises(FederationDenied):
            admit_verified_identity(self.request(), evidence)
        self.assertFalse(FederatedSession.objects.exists())
