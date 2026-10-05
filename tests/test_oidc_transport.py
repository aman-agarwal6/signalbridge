"""Offline transport boundary checks; sockets/provider replies are modeled."""

import ssl
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from django.test import SimpleTestCase

from integrations.enterprise.https_deadline import BoundedHTTPSConnection
from integrations.identity.configuration import CALLBACK, CLIENT_ID
from integrations.identity.transport import (
    IdentityHTTPSConnection,
    IdentityTransportError,
    token_post,
)


class OIDCTransportTests(SimpleTestCase):
    def setUp(self):
        self.data = {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "redirect_uri": CALLBACK,
            "code": "synthetic-code",
            "code_verifier": "v" * 64,
        }
        self.connection = Mock()
        self.response = self.connection.getresponse.return_value
        self.response.status = 200
        self.response.headers.get_content_type.return_value = "application/json"
        self.response.getheader.return_value = "identity"
        self.response.read.return_value = b'{"id_token":"modeled"}'
        for target, value in (
            ("IdentityHTTPSConnection", self.connection),
            ("lab_context", Mock()),
        ):
            item = patch("integrations.identity.transport." + target, return_value=value)
            item.start()
            self.addCleanup(item.stop)

    def post(self, data=None):
        return token_post(urlencode(data or self.data), ca_file="fixture-ca-not-used")

    def test_fixed_token_post_uses_finite_body_and_finishes_connection(self):
        self.assertEqual(self.post(), b'{"id_token":"modeled"}')
        args, kwargs = self.connection.request.call_args
        self.assertEqual(args, ("POST", "/realms/signalbridge/protocol/openid-connect/token"))
        self.assertEqual(kwargs["headers"]["Accept-Encoding"], "identity")
        self.response.read.assert_called_once_with(65537)
        self.connection.start.assert_called_once()
        self.connection.finish.assert_called_once()

    def test_redirect_error_compression_and_wrong_media_are_rejected(self):
        for status, encoding, media in (
            (302, "identity", "application/json"),
            (500, "identity", "application/json"),
            (200, "gzip", "application/json"),
            (200, "identity", "text/html"),
        ):
            self.response.status = status
            self.response.getheader.return_value = encoding
            self.response.headers.get_content_type.return_value = media
            with (
                self.subTest(status=status, media=media),
                self.assertRaises(IdentityTransportError),
            ):
                self.post()
        self.response.read.assert_not_called()
        self.assertEqual(self.connection.finish.call_count, 4)

    def test_large_duplicate_non_object_and_malformed_json_are_rejected(self):
        for value in (b"x" * 65537, b'{"token":1,"token":2}', b"[]", b"{"):
            self.response.read.return_value = value
            with self.subTest(length=len(value)), self.assertRaises(IdentityTransportError):
                self.post()

    def test_read_after_deadline_never_returns_success(self):
        self.connection.remaining.side_effect = [1, TimeoutError("synthetic-private-detail")]
        with self.assertRaises(IdentityTransportError) as caught:
            self.post()
        self.assertNotIn("synthetic-private-detail", str(caught.exception))
        self.connection.finish.assert_called_once()

    def test_wrong_client_redirect_grant_and_verifier_rejected_before_connect(self):
        for changes in (
            {"client_id": "wrong"},
            {"redirect_uri": "https://other.invalid/"},
            {"grant_type": "password"},
            {"code_verifier": "short"},
            {"extra": "value"},
        ):
            with self.subTest(fields=list(changes)), self.assertRaises(IdentityTransportError):
                self.post({**self.data, **changes})
        self.connection.start.assert_not_called()

    def test_identity_connection_does_not_expand_reference_port_allowlist(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with self.assertRaises(ValueError):
            BoundedHTTPSConnection(18844, context=context, seconds=5)
        with self.assertRaises(ValueError):
            IdentityHTTPSConnection(18842, context=context, seconds=5)
        conn = IdentityHTTPSConnection(18844, context=context, seconds=5)
        self.assertEqual(conn.host, "127.0.0.2")
        conn.finish()
