"""Optional actual Authlib/JOSE checks; wire transport modeled, no native IdP.

Requires the reviewed dependency environment. Missing dependencies fail collection.
Ephemeral signatures stay in memory; no keys, tokens or authorization codes saved.
"""

import base64
import hashlib
import json
import secrets
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from django.contrib.auth.middleware import AuthenticationMiddleware
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory, TestCase, override_settings

from bridge.federation import VerifiedIdentity
from bridge.oidc_state import begin_exchange, consume_exchange

from .client import create_client
from .configuration import AUTHORIZATION, CALLBACK, CLIENT_ID, ISSUER, IdentityConfiguration
from .protocol import TokenRejected
from .protocol_tests import SignedFixture


@override_settings(FEDERATED_AUTH_ENABLED=True)
class EstablishedClientTests(SignedFixture, TestCase):
    def setUp(self):
        self.issuer, self.audience = ISSUER, CLIENT_ID
        self.config = IdentityConfiguration(
            ca_file=Path("nonfunctional-fixture-ca"), jwks=self.jwks
        )
        self.client = create_client(self.config)

    def request(self):
        request = RequestFactory().post(
            "/sso/start/", "", content_type="application/x-www-form-urlencoded", secure=True
        )
        SessionMiddleware(lambda req: None).process_request(request)
        request.session.save()
        AuthenticationMiddleware(lambda req: None).process_request(request)
        return request

    def start(self):
        request = self.request()
        state = begin_exchange(request, ISSUER)
        self.nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        redirect = self.client.authorize_redirect(
            request,
            CALLBACK,
            state=state,
            nonce=self.nonce,
            code_verifier=verifier,
            response_mode="form_post",
            max_age=300,
            acr_values="2",
        )
        return request, state, verifier, redirect

    def callback(self, request, state):
        response = RequestFactory().post(
            "/sso/callback/",
            urlencode({"state": state, "code": "synthetic-code"}),
            content_type="application/x-www-form-urlencoded",
            secure=True,
        )
        response.session, response.user = request.session, request.user
        consume_exchange(response, ISSUER, state)
        return response

    def token_response(self, *, key=None):
        return json.dumps(
            {
                "access_token": self.access_token,
                "token_type": "Bearer",
                "expires_in": 240,
                "id_token": self.sign(self.claims(), key=key),
            }
        ).encode()

    def test_authlib_generates_s256_challenge_and_server_only_verifier(self):
        request, state, verifier, response = self.start()
        address = urlsplit(response["Location"])
        self.assertEqual(address._replace(query="").geturl(), AUTHORIZATION)
        query = parse_qs(address.query)
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        self.assertEqual(query["code_challenge"], [expected])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["response_mode"], ["form_post"])
        self.assertEqual(query["redirect_uri"], [CALLBACK])
        self.assertEqual(query["scope"], ["openid"])
        self.assertNotIn(verifier, response["Location"])
        self.assertEqual(
            self.client.framework.get_state_data(request.session, state)["code_verifier"], verifier
        )

    def test_real_client_exchanges_fixed_pkce_fields_and_verifies_real_signature(self):
        request, state, verifier, _ = self.start()
        callback = self.callback(request, state)
        with patch(
            "integrations.identity.client.token_post", return_value=self.token_response()
        ) as transport:
            token = self.client.authorize_access_token(callback, leeway=5)
        self.assertIsInstance(token["userinfo"], VerifiedIdentity)
        self.assertEqual(token["userinfo"].subject, "synthetic-subject")
        body = transport.call_args.args[0]
        if isinstance(body, bytes):
            body = body.decode("ascii")
        self.assertEqual(
            parse_qs(body),
            {
                "grant_type": ["authorization_code"],
                "client_id": [CLIENT_ID],
                "redirect_uri": [CALLBACK],
                "code": ["synthetic-code"],
                "code_verifier": [verifier],
            },
        )
        self.assertIsNone(self.client.framework.get_state_data(request.session, state))
        self.assertNotIn(self.access_token, json.dumps(dict(request.session)))

    def test_missing_verifier_nonce_or_exact_redirect_fails_before_transport(self):
        for field, replacement in (
            ("code_verifier", None),
            ("nonce", None),
            ("redirect_uri", "https://other.invalid/"),
        ):
            request, state, _, _ = self.start()
            data = self.client.framework.get_state_data(request.session, state)
            data[field] = replacement
            self.client.framework.set_state_data(request.session, state, data)
            with (
                patch("integrations.identity.client.token_post") as transport,
                self.assertRaises(TokenRejected),
            ):
                self.client.authorize_access_token(self.callback(request, state), leeway=5)
            transport.assert_not_called()

    def test_wrong_real_signing_key_cannot_become_verified_identity(self):
        request, state, _, _ = self.start()
        with (
            patch(
                "integrations.identity.client.token_post",
                return_value=self.token_response(key=self.other_key),
            ),
            self.assertRaises(TokenRejected),
        ):
            self.client.authorize_access_token(self.callback(request, state), leeway=5)
        self.assertIsNone(self.client.framework.get_state_data(request.session, state))

    def test_wrong_signed_nonce_is_rejected_after_real_library_exchange(self):
        request, state, _, _ = self.start()
        self.nonce = secrets.token_urlsafe(32)
        with (
            patch("integrations.identity.client.token_post", return_value=self.token_response()),
            self.assertRaises(TokenRejected),
        ):
            self.client.authorize_access_token(self.callback(request, state), leeway=5)

    def test_optional_client_cannot_send_to_unreviewed_endpoint(self):
        with self.client._get_oauth_client() as client:
            with patch("integrations.identity.client.token_post") as transport:
                from .transport import IdentityTransportError

                with self.assertRaises(IdentityTransportError):
                    client.post("https://other.invalid/token", data={}, withhold_token=True)
                transport.assert_not_called()
