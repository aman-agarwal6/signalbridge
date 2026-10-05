"""Public-key refresh policy and modeled network checks; no provider/DB execution."""

import base64
import hashlib
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from django.test import RequestFactory, SimpleTestCase, override_settings

from bridge.contract import canonical
from bridge.federation import FederationDenied
from integrations.identity import key_refresh
from integrations.identity.configuration import (
    CALLBACK,
    CLIENT_ID,
    ISSUER,
    JWKS_ENDPOINT,
    IdentityConfiguration,
    load_configuration,
)
from integrations.identity.protocol import TokenRejected
from integrations.identity.transport import IdentityTransportError, jwks_get
from tests.test_soc_delivery import disposable_root


def public_key(kid="modeled-original"):
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "e": "AQAB",
        "n": base64.urlsafe_b64encode(b"\x80" + b"\x01" * 255).rstrip(b"=").decode(),
    }


def compact(kid="modeled-original", **extra):
    # Deliberately unsigned fixture. Tests below check key selection only.
    head = {"alg": "RS256", "kid": kid, "typ": "JWT", **extra}
    encoded = base64.urlsafe_b64encode(canonical(head)).rstrip(b"=").decode()
    return encoded + ".e30.AA"


def configuration(profile="modeled-profile", keys=None):
    keys = keys or {"keys": [public_key()]}
    base = Path(__file__).resolve().parents[1] / "artifacts/local" / profile
    ca = base / "var/enterprise/identity/ca.pem"
    identity = (
        ISSUER,
        CLIENT_ID,
        CALLBACK,
        JWKS_ENDPOINT,
        str(ca.resolve()),
        "a" * 64,
        str((ca.parent / "keys.json").resolve()),
        hashlib.sha256(canonical(keys)).hexdigest(),
    )
    return IdentityConfiguration(ca_file=ca, jwks=keys, key_refresh_identity=identity)


class RefreshPolicyTests(SimpleTestCase):
    def setUp(self):
        self.now = 100.0
        self.cache = key_refresh.PublicKeyCache(clock=lambda: self.now)
        self.config = configuration()
        item = patch(
            "integrations.identity.key_refresh.jwks_get", return_value=canonical(self.config.jwks)
        )
        self.fetch = item.start()
        self.addCleanup(item.stop)

    def resolve(self, kid="modeled-original", config=None):
        return self.cache.resolve(config or self.config, compact(kid))

    def test_initial_provider_fetch_and_cache_hit_do_not_use_seed_fallback(self):
        self.assertEqual(self.resolve(), self.config.jwks)
        self.assertEqual(self.resolve(), self.config.jwks)
        self.fetch.assert_called_once_with(ca_file=self.config.ca_file, ca_sha256="a" * 64)

    def test_unknown_kids_share_cooldown_then_refresh_once(self):
        self.resolve()
        for number in range(25):
            with self.assertRaises(TokenRejected):
                self.resolve("attacker-unknown-" + str(number))
        self.assertEqual(self.fetch.call_count, 1)
        self.now += 15
        self.fetch.return_value = canonical({"keys": [public_key("modeled-rotated")]})
        self.assertEqual(self.resolve("modeled-rotated")["keys"][0]["kid"], "modeled-rotated")
        self.assertEqual(self.fetch.call_count, 2)
        with self.assertRaises(TokenRejected):
            self.resolve()  # Replaced keys are not merged into an indefinite trust set.
        self.assertEqual(self.fetch.call_count, 2)

    def test_missing_kid_after_fetch_does_not_trigger_second_fetch(self):
        with self.assertRaises(TokenRejected):
            self.resolve("unknown")
        self.fetch.assert_called_once()
        self.assertEqual(self.resolve(), self.config.jwks)

    def test_failed_expired_fetch_cannot_reseed_or_extend_trust(self):
        self.resolve()
        self.now += 300
        self.fetch.side_effect = IdentityTransportError()
        with self.assertRaises(IdentityTransportError):
            self.resolve()
        self.now += 1
        with self.assertRaises(TokenRejected):
            self.resolve(config=replace(self.config))
        self.assertEqual(self.fetch.call_count, 2)
        self.now += 14
        self.fetch.side_effect = None
        self.assertEqual(self.resolve(), self.config.jwks)
        self.assertEqual(self.fetch.call_count, 3)

    def test_failed_unknown_refresh_does_not_extend_existing_expiry(self):
        self.resolve()
        self.now += 15
        self.fetch.side_effect = IdentityTransportError()
        with self.assertRaises(IdentityTransportError):
            self.resolve("unknown")
        self.assertEqual(self.resolve(), self.config.jwks)
        self.now = 400
        with self.assertRaises(IdentityTransportError):
            self.resolve()

    def test_concurrent_refresh_uses_one_fetch_and_same_public_result(self):
        entered, release = threading.Event(), threading.Event()

        def response(**kwargs):
            entered.set()
            if not release.wait(2):
                raise AssertionError("Modeled fetch was not released")
            return canonical({"keys": [public_key("modeled-rotated")]})

        self.fetch.side_effect = response
        with ThreadPoolExecutor(max_workers=6) as pool:
            jobs = [pool.submit(self.resolve, "modeled-rotated") for _ in range(6)]
            self.assertTrue(entered.wait(1))
            release.set()
            results = [job.result(timeout=2) for job in jobs]
        self.assertTrue(all(value == results[0] for value in results))
        self.fetch.assert_called_once()

    def test_singleflight_wait_is_bounded_without_starting_another_fetch(self):
        entered, release = threading.Event(), threading.Event()

        def response(**kwargs):
            entered.set()
            if not release.wait(2):
                raise AssertionError("Modeled fetch was not released")
            return canonical(self.config.jwks)

        self.fetch.side_effect = response
        with ThreadPoolExecutor(max_workers=1) as pool:
            job = pool.submit(self.resolve)
            self.assertTrue(entered.wait(1))
            try:
                with (
                    patch.object(key_refresh, "SINGLEFLIGHT_WAIT", 0.01),
                    self.assertRaises(TokenRejected),
                ):
                    self.resolve()
            finally:
                release.set()
            job.result(timeout=2)
        self.fetch.assert_called_once()

    def test_cache_results_cannot_be_mutated_by_caller(self):
        keys = self.resolve()
        keys["keys"][0]["kid"] = "injected"
        self.assertEqual(self.resolve(), self.config.jwks)
        self.fetch.assert_called_once()

    def test_config_identity_switching_does_not_inherit_keys(self):
        self.resolve()
        other = configuration("different-ca-file")
        self.fetch.side_effect = IdentityTransportError()
        with self.assertRaises(IdentityTransportError):
            self.resolve(config=other)
        changed_ca = replace(
            self.config,
            key_refresh_identity=(
                *self.config.key_refresh_identity[:5],
                "b" * 64,
                *self.config.key_refresh_identity[6:],
            ),
        )
        with self.assertRaises(IdentityTransportError):
            self.resolve(config=changed_ca)
        self.assertEqual(self.fetch.call_count, 3)

    def test_profile_cap_preserves_existing_entries_and_budgets(self):
        for number in range(key_refresh.MAX_PROFILES):
            self.resolve(config=configuration("bounded-profile-" + str(number)))
        with self.assertRaises(TokenRejected):
            self.resolve(config=configuration("overflow-profile"))
        self.assertEqual(self.fetch.call_count, key_refresh.MAX_PROFILES)
        self.resolve(config=configuration("bounded-profile-0"))
        self.assertEqual(self.fetch.call_count, key_refresh.MAX_PROFILES)

    def test_changed_issuer_client_callback_or_seed_fails_before_fetch(self):
        for changes in (
            {"issuer": "https://outside.invalid/"},
            {"client_id": "other-client"},
            {"callback": "https://outside.invalid/callback"},
            {"jwks": {"keys": [public_key("changed-seed")]}},
        ):
            with self.subTest(fields=list(changes)), self.assertRaises(TokenRejected):
                self.resolve(config=replace(self.config, **changes))
        self.fetch.assert_not_called()

    def test_malformed_embedded_key_or_url_header_never_fetches(self):
        for token in (
            None,
            "not-a-token",
            "x" * 16385,
            compact(jku="https://outside.invalid/keys"),
            compact(jwk=public_key()),
            compact(alg="HS256"),
        ):
            with self.assertRaises(TokenRejected):
                self.cache.resolve(self.config, token)
        self.fetch.assert_not_called()

    def test_malformed_private_duplicate_oversized_or_unsupported_keys_fail_closed(self):
        row = public_key()
        invalid = [
            b"{",
            b'{"keys":[],"keys":[]}',
            b"x" * 65537,
            canonical({"keys": []}),
            canonical({"keys": [row, row]}),
            canonical({"keys": [{**row, "d": "nonfunctional"}]}),
            canonical({"keys": [{**row, "kty": "EC"}]}),
            canonical({"keys": [{**row, "alg": "RS512"}]}),
            canonical({"keys": [{**row, "key_ops": ["sign"]}]}),
            canonical({"keys": [public_key(str(i)) for i in range(9)]}),
            canonical({"keys": [{**row, "n": "A" * 342}]}),
            canonical({"keys": [{**row, "use": "enc", "alg": "RSA-OAEP"}]}),
        ]
        for raw in invalid:
            self.fetch.return_value = raw
            cache = key_refresh.PublicKeyCache(clock=lambda: self.now)
            with self.subTest(length=len(raw)), self.assertRaises(TokenRejected):
                cache.resolve(self.config, compact())

    def test_provider_encryption_keys_are_never_imported_as_verification_keys(self):
        row = public_key()
        encryption = {**row, "kid": "provider-encryption", "use": "enc", "alg": "RSA-OAEP"}
        self.fetch.return_value = canonical({"keys": [row, encryption]})
        self.assertEqual(self.resolve(), {"keys": [row]})
        self.fetch.return_value = canonical({"keys": [row, {**encryption, "kid": row["kid"]}]})
        self.now += 300
        with self.assertRaises(TokenRejected):
            self.resolve()

    def test_failed_initial_fetch_has_no_configured_seed_fallback(self):
        self.fetch.side_effect = IdentityTransportError()
        with self.assertRaises(IdentityTransportError):
            self.resolve()
        with self.assertRaises(TokenRejected):
            self.resolve()
        self.fetch.assert_called_once()

    @override_settings(FEDERATED_AUTH_ENABLED=True, ALLOWED_HOSTS=["127.0.0.1"])
    def test_backchannel_uses_the_same_refresh_resolver_before_logout_validation(self):
        from bridge.oidc_views import backchannel

        request = RequestFactory().post(
            "/sso/backchannel/",
            "logout_token=" + compact(),
            content_type="application/x-www-form-urlencoded",
            secure=True,
            HTTP_HOST="127.0.0.1:18842",
        )
        with (
            patch("bridge.oidc_views.load_configuration", return_value=self.config),
            patch("bridge.oidc_views.reserve_protocol_request"),
            patch("bridge.oidc_views.consume_verified_logout") as consume,
            patch("bridge.oidc_views.verify_logout_token", return_value=object()) as verify,
            patch.object(key_refresh, "_CACHE", self.cache),
        ):
            response = backchannel(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(verify.call_args.kwargs["jwks"], self.config.jwks)
        self.fetch.assert_called_once()
        consume.assert_called_once()


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
class RefreshConfigurationTests(SimpleTestCase):
    def setUp(self):
        self.root = disposable_root(self)
        folder = self.root / "var/enterprise/identity"
        folder.mkdir(parents=True)
        self.ca, self.keys = folder / "ca.pem", folder / "keys.json"
        self.ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
        self.keys.write_bytes(canonical({"keys": [public_key()]}))
        options = override_settings(OIDC_CA_FILE=str(self.ca), OIDC_JWKS_FILE=str(self.keys))
        options.enable()
        self.addCleanup(options.disable)

    def test_default_and_explicit_false_keep_static_mode_offline(self):
        with patch("integrations.identity.key_refresh.jwks_get") as fetch:
            for flag in (False,):
                with override_settings(OIDC_JWKS_REFRESH_ENABLED=flag):
                    config = load_configuration()
                    self.assertIsNone(config.key_refresh_identity)
                    self.assertEqual(config.keys_for_token("validation-occurs-later"), config.jwks)
        fetch.assert_not_called()

    def test_opt_in_loading_is_offline_and_binds_both_files_and_profile(self):
        with (
            override_settings(OIDC_JWKS_REFRESH_ENABLED=True),
            patch("integrations.identity.key_refresh.jwks_get") as fetch,
        ):
            config = load_configuration()
        self.assertEqual(
            config.key_refresh_identity[:4], (ISSUER, CLIENT_ID, CALLBACK, JWKS_ENDPOINT)
        )
        self.assertEqual(config.key_refresh_identity[4], str(self.ca.resolve()))
        self.assertEqual(config.key_refresh_identity[6], str(self.keys.resolve()))
        fetch.assert_not_called()

    def test_changed_ca_or_seed_creates_new_verified_configuration_identity(self):
        with override_settings(OIDC_JWKS_REFRESH_ENABLED=True):
            initial = load_configuration().key_refresh_identity
            self.ca.write_bytes(b"-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n")
            changed_ca = load_configuration().key_refresh_identity
            self.assertNotEqual(changed_ca, initial)
            self.keys.write_bytes(canonical({"keys": [public_key("different-seed")]}))
            self.assertNotEqual(load_configuration().key_refresh_identity, changed_ca)

    def test_truthy_strings_integers_and_null_do_not_enable_refresh(self):
        for value in ("1", "true", 1, None):
            with (
                override_settings(OIDC_JWKS_REFRESH_ENABLED=value),
                self.assertRaises(FederationDenied),
            ):
                load_configuration()


class RefreshTransportTests(SimpleTestCase):
    def setUp(self):
        self.ca = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        self.digest = hashlib.sha256(self.ca).hexdigest()
        self.connection = Mock()
        self.response = self.connection.getresponse.return_value
        self.response.status = 200
        self.response.headers.get_content_type.return_value = "application/json"
        self.response.getheader.return_value = "identity"
        self.response.read.return_value = canonical({"keys": [public_key()]})
        self.context = Mock(verify_flags=0)
        for name, value in (
            ("_owned_file", (Path("nonfunctional-ca"), self.ca)),
            ("ssl.SSLContext", self.context),
            ("IdentityHTTPSConnection", self.connection),
        ):
            item = patch("integrations.identity.transport." + name, return_value=value)
            item.start()
            self.addCleanup(item.stop)

    def get(self, **changes):
        return jwks_get(
            ca_file=Path("nonfunctional-ca"), ca_sha256=changes.get("digest", self.digest)
        )

    def test_exact_certs_get_has_explicit_ca_and_total_deadline_and_body_bound(self):
        self.assertEqual(self.get(), self.response.read.return_value)
        args, kwargs = self.connection.request.call_args
        self.assertEqual(args, ("GET", "/realms/signalbridge/protocol/openid-connect/certs"))
        self.assertEqual(
            kwargs["headers"],
            {"Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close"},
        )
        self.response.read.assert_called_once_with(65537)
        self.context.load_verify_locations.assert_called_once_with(cadata=self.ca.decode("ascii"))
        self.assertEqual(self.context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.connection.start.assert_called_once()
        self.connection.finish.assert_called_once()

    def test_changed_or_invalid_ca_fingerprint_fails_before_connection(self):
        for digest in ("b" * 64, "", None):
            with self.assertRaises(IdentityTransportError):
                self.get(digest=digest)
        self.connection.start.assert_not_called()

    def test_redirect_compression_wrong_media_and_http_error_are_rejected(self):
        for status, encoding, media in (
            (302, "identity", "application/json"),
            (500, "identity", "application/json"),
            (200, "gzip", "application/json"),
            (200, "identity", "text/html"),
        ):
            self.response.status, self.response.getheader.return_value = status, encoding
            self.response.headers.get_content_type.return_value = media
            with self.assertRaises(IdentityTransportError):
                self.get()
        self.response.read.assert_not_called()
        self.assertEqual(self.connection.finish.call_count, 4)

    def test_oversized_duplicate_nonobject_or_invalid_reply_fails_closed(self):
        for raw in (b"x" * 65537, b'{"keys":[],"keys":[]}', b"[]", b"{"):
            self.response.read.return_value = raw
            with self.assertRaises(IdentityTransportError):
                self.get()

    def test_expired_deadline_never_returns_reply_or_private_error_details(self):
        self.connection.remaining.side_effect = [1, TimeoutError("synthetic-private-detail")]
        with self.assertRaises(IdentityTransportError) as caught:
            self.get()
        self.assertNotIn("synthetic-private-detail", str(caught.exception))
        self.connection.finish.assert_called_once()
