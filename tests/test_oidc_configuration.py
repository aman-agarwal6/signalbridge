"""Offline profile/path policy checks; test CA bytes are deliberately nonfunctional."""

import base64
import json

from django.test import SimpleTestCase, override_settings

from bridge.federation import FederationDenied
from integrations.identity.configuration import CALLBACK, ISSUER, load_configuration
from integrations.identity.protocol import TokenRejected
from tests.test_soc_delivery import disposable_root


@override_settings(
    FEDERATED_AUTH_ENABLED=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None",
    CSRF_COOKIE_SECURE=True,
    CSRF_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_NAME="sb_enterprise_session",
    CSRF_COOKIE_NAME="sb_enterprise_csrf",
    DEBUG=False,
)
class OIDCConfigurationTests(SimpleTestCase):
    def setUp(self):
        # Existing synthetic-fixture helper uses inherited workspace permissions;
        # Python's private tempfile ACL excludes the managed Windows test process.
        self.root = disposable_root(self)
        owned = self.root / "var" / "enterprise" / "identity"
        owned.mkdir(parents=True)
        self.ca, self.jwks = owned / "ca.pem", owned / "keys.json"
        self.ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
        self.keys = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": "public-metadata-fixture",
                    "e": "AQAB",
                    "n": base64.urlsafe_b64encode(b"\x80" + b"\x01" * 255).rstrip(b"=").decode(),
                }
            ]
        }
        self.jwks.write_text(json.dumps(self.keys), encoding="utf-8")
        self.options = override_settings(
            BASE_DIR=self.root, OIDC_CA_FILE=str(self.ca), OIDC_JWKS_FILE=str(self.jwks)
        )
        self.options.enable()
        self.addCleanup(self.options.disable)

    def test_public_metadata_is_loaded_only_from_explicit_owned_files(self):
        config = load_configuration()
        self.assertEqual(config.issuer, ISSUER)
        self.assertEqual(config.callback, CALLBACK)
        self.assertEqual(config.ca_file, self.ca)
        self.assertEqual(config.jwks, self.keys)

    def test_plaintext_cookies_debug_or_client_side_sessions_fail_closed(self):
        for options in (
            {"FEDERATED_AUTH_ENABLED": False},
            {"SESSION_COOKIE_SECURE": False},
            {"SESSION_COOKIE_HTTPONLY": False},
            {"SESSION_COOKIE_SAMESITE": "Lax"},
            {"CSRF_COOKIE_SECURE": False},
            {"CSRF_COOKIE_SAMESITE": "None"},
            {"DEBUG": True},
            {"SESSION_COOKIE_DOMAIN": "127.0.0.1"},
            {"SESSION_COOKIE_NAME": "sessionid"},
            {"CSRF_COOKIE_NAME": "csrftoken"},
            {"SESSION_ENGINE": "django.contrib.sessions.backends.signed_cookies"},
        ):
            with (
                self.subTest(options=options),
                override_settings(**options),
                self.assertRaises(FederationDenied),
            ):
                load_configuration()

    def test_outside_or_relative_key_paths_fail_before_read(self):
        for value in (
            str(self.root / "other.json"),
            "var/keys.json",
            "",
            "https://other.invalid/keys",
        ):
            with override_settings(OIDC_JWKS_FILE=value), self.assertRaises(FederationDenied):
                load_configuration()

    def test_private_key_fields_and_oversized_key_files_are_rejected(self):
        self.keys["keys"][0]["d"] = "nonfunctional-private-field"
        self.jwks.write_text(json.dumps(self.keys), encoding="utf-8")
        with self.assertRaises(TokenRejected):
            load_configuration()
        self.jwks.write_bytes(b"x" * 65537)
        with self.assertRaises(FederationDenied):
            load_configuration()

    def test_non_certificate_trust_file_cannot_be_selected(self):
        self.ca.write_bytes(b"not a certificate")
        with self.assertRaises(FederationDenied):
            load_configuration()
