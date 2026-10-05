"""Real in-memory JOSE signatures with modeled refresh; no provider or DB proof.

Run only in the existing reviewed identity environment. Keys/JWTs remain in
memory and missing optional libraries fail collection instead of skipping.
"""

import base64
import hashlib
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase
from joserfc import jwt
from joserfc.jwk import RSAKey

from bridge.contract import canonical
from bridge.federation import VerifiedIdentity

from . import key_refresh
from .client import create_client
from .configuration import CALLBACK, CLIENT_ID, ISSUER, JWKS_ENDPOINT, IdentityConfiguration
from .protocol import LOGOUT_EVENT, TokenRejected, VerifiedLogout, verify_logout_token
from .transport import IdentityTransportError


class KeyRefreshSignatureTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.old = RSAKey.generate_key(
            2048, parameters={"kid": "memory-original", "use": "sig", "alg": "RS256"}
        )
        cls.rotated = RSAKey.generate_key(
            2048, parameters={"kid": "memory-rotated", "use": "sig", "alg": "RS256"}
        )
        cls.wrong = RSAKey.generate_key(
            2048, parameters={"kid": "memory-rotated", "use": "sig", "alg": "RS256"}
        )

    def setUp(self):
        self.clock = 100.0
        self.cache = key_refresh.PublicKeyCache(clock=lambda: self.clock)
        self.seed = {"keys": [self.old.as_dict(private=False)]}
        ca = Path(__file__).resolve().parent / "nonfunctional-memory-ca.pem"
        identity = (
            ISSUER,
            CLIENT_ID,
            CALLBACK,
            JWKS_ENDPOINT,
            str(ca.resolve()),
            "a" * 64,
            str(ca.with_name("nonfunctional-memory-keys.json").resolve()),
            hashlib.sha256(canonical(self.seed)).hexdigest(),
        )
        self.config = IdentityConfiguration(
            ca_file=ca, jwks=self.seed, key_refresh_identity=identity
        )
        self.client = create_client(self.config)
        self.nonce = "synthetic-memory-nonce-for-rotation-only-000001"
        self.access = "nonfunctional-memory-access-token"
        cache_patch = patch.object(key_refresh, "_CACHE", self.cache)
        cache_patch.start()
        self.addCleanup(cache_patch.stop)
        item = patch(
            "integrations.identity.key_refresh.jwks_get",
            return_value=canonical({"keys": [self.rotated.as_dict(private=False)]}),
        )
        self.fetch = item.start()
        self.addCleanup(item.stop)

    def claims(self):
        current = int(time.time())
        return {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "memory-subject",
            "sid": "memory-session",
            "iat": current,
            "exp": current + 240,
            "auth_time": current,
            "nonce": self.nonce,
            "acr": "2",
            "amr": ["pwd", "otp"],
            "at_hash": base64.urlsafe_b64encode(hashlib.sha256(self.access.encode()).digest()[:16])
            .rstrip(b"=")
            .decode(),
        }

    def sign(self, claims=None, key=None, typ="JWT"):
        key = key or self.rotated
        return jwt.encode(
            {"alg": "RS256", "kid": key.as_dict(private=False)["kid"], "typ": typ},
            self.claims() if claims is None else claims,
            key,
        )

    def login(self, token=None, *, nonce=None, access=None):
        return self.client.parse_id_token(
            {"id_token": token or self.sign(), "access_token": access or self.access},
            nonce or self.nonce,
        )

    def logout_claims(self):
        claims = self.claims()
        for field in ("nonce", "auth_time", "acr", "amr", "at_hash"):
            claims.pop(field)
        claims.update(events={LOGOUT_EVENT: {}}, jti="memory-logout-message")
        return claims

    def logout(self, token):
        return verify_logout_token(
            token, jwks=self.config.keys_for_token(token), issuer=ISSUER, audience=CLIENT_ID
        )

    def test_login_client_accepts_rotated_real_signature_after_fixed_fetch(self):
        evidence = self.login()
        self.assertIsInstance(evidence, VerifiedIdentity)
        self.assertEqual(evidence.subject, "memory-subject")
        self.fetch.assert_called_once_with(ca_file=self.config.ca_file, ca_sha256="a" * 64)

    def test_unknown_rotated_kid_refresh_replaces_old_trust_without_reseeding(self):
        self.fetch.return_value = canonical(self.seed)
        self.assertIsInstance(self.login(self.sign(key=self.old)), VerifiedIdentity)
        self.clock += 15
        self.fetch.return_value = canonical({"keys": [self.rotated.as_dict(private=False)]})
        self.assertIsInstance(self.login(), VerifiedIdentity)
        self.assertIsInstance(
            create_client(replace(self.config)).parse_id_token(
                {"id_token": self.sign(), "access_token": self.access}, self.nonce
            ),
            VerifiedIdentity,
        )
        with self.assertRaises(TokenRejected):
            self.login(self.sign(key=self.old))
        self.assertEqual(self.fetch.call_count, 2)

    def test_matching_kid_with_wrong_real_signature_is_never_accepted_or_refreshed(self):
        with self.assertRaises(TokenRejected):
            self.login(self.sign(key=self.wrong))
        with self.assertRaises(TokenRejected):
            self.login(self.sign(key=self.wrong))
        self.fetch.assert_called_once()

    def test_rotated_key_does_not_weaken_signed_claim_nonce_hash_or_mfa_checks(self):
        claims = self.claims()
        for changed in (
            {"iss": "https://other.invalid/realms/lab"},
            {"aud": "other-client"},
            {"azp": "other-client"},
            {"iat": True},
            {"exp": claims["iat"] - 1},
            {"nbf": claims["iat"] + 60},
            {"nonce": "wrong-nonce"},
            {"at_hash": "wrong-hash"},
            {"acr": "1"},
            {"amr": ["pwd"]},
            {"auth_time": claims["iat"] - 600},
        ):
            with self.subTest(fields=list(changed)), self.assertRaises(TokenRejected):
                self.login(self.sign({**claims, **changed}))
        with self.assertRaises(TokenRejected):
            self.login(access="different-memory-access-token")
        self.fetch.assert_called_once()

    def test_logout_rotated_real_signature_uses_same_resolver_and_strict_claims(self):
        token = self.sign(self.logout_claims(), typ="logout+jwt")
        evidence = self.logout(token)
        self.assertIsInstance(evidence, VerifiedLogout)
        self.assertEqual(evidence.provider_session, "memory-session")
        for changed in (
            {"nonce": self.nonce},
            {"events": {}},
            {"aud": "other-client"},
            {"jti": ""},
        ):
            with self.assertRaises(TokenRejected):
                self.logout(self.sign({**self.logout_claims(), **changed}, typ="logout+jwt"))
        self.fetch.assert_called_once()

    def test_private_or_unrelated_provider_keys_cannot_validate_real_tokens(self):
        for keys in ({"keys": [self.rotated.as_dict(private=True)]}, self.seed):
            self.fetch.return_value = canonical(keys)
            with (
                patch.object(
                    key_refresh, "_CACHE", key_refresh.PublicKeyCache(clock=lambda: self.clock)
                ),
                self.assertRaises(TokenRejected),
            ):
                self.login()

    def test_expired_cache_fetch_failure_denies_a_valid_real_signed_token(self):
        self.assertIsInstance(self.login(), VerifiedIdentity)
        self.clock += 300
        self.fetch.side_effect = IdentityTransportError()
        with self.assertRaises(IdentityTransportError):
            self.login()
        with self.assertRaises(TokenRejected):
            self.login()
        self.assertEqual(self.fetch.call_count, 2)

    def test_static_client_keeps_existing_trusted_file_behavior_without_fetch(self):
        config = replace(self.config, key_refresh_identity=None)
        evidence = create_client(config).parse_id_token(
            {"id_token": self.sign(key=self.old), "access_token": self.access}, self.nonce
        )
        self.assertIsInstance(evidence, VerifiedIdentity)
        self.fetch.assert_not_called()
