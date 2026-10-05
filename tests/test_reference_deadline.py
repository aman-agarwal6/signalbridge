"""Offline deadline controls: no listening service, real sockets or lab claim."""

import io
import math
import ssl
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from integrations.enterprise.https_deadline import BoundedHTTPSConnection, lab_context
from integrations.enterprise.reference_http import ClosedHTTPSClient, RequestBudget


class ReferenceDeadlineTests(SimpleTestCase):
    def setUp(self):
        self.clock = 100.0
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.raw = Mock()
        self.tls = Mock()
        self.tls.makefile.side_effect = lambda *_args: io.BytesIO(
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}"
        )
        self.patches = [
            patch("integrations.enterprise.https_deadline.time.monotonic", self.now),
            patch("integrations.enterprise.https_deadline.socket.socket", return_value=self.raw),
            patch.object(ssl.SSLContext, "wrap_socket", return_value=self.tls),
            patch("integrations.enterprise.https_deadline.threading.Timer"),
        ]
        self.timer = None
        for item in self.patches:
            value = item.start()
            self.addCleanup(item.stop)
            self.timer = value

    def now(self):
        return self.clock

    def connection(self, **options):
        return BoundedHTTPSConnection(18842, context=self.context, seconds=5, **options)

    def test_connect_and_handshake_share_remaining_time_and_preserve_tls_checks(self):
        conn = self.connection()

        def connect(_address):
            self.clock += 1

        def handshake():
            self.clock += 1.5

        self.raw.connect.side_effect = connect
        self.tls.do_handshake.side_effect = handshake
        conn.start()
        conn.connect()
        self.raw.connect.assert_called_once_with(("127.0.0.1", 18842))
        self.raw.settimeout.assert_called_once_with(5)
        self.assertEqual([args.args[0] for args in self.tls.settimeout.call_args_list], [4, 2.5])
        self.context.wrap_socket.assert_called_once_with(
            self.raw, server_hostname="127.0.0.1", do_handshake_on_connect=False
        )
        self.assertTrue(self.context.check_hostname)
        self.assertEqual(self.context.verify_mode, ssl.CERT_REQUIRED)
        conn.finish()
        self.timer.return_value.cancel.assert_called_once()
        self.tls.close.assert_called()

    def test_expiry_during_connect_prevents_handshake_and_closes_raw_socket(self):
        conn = self.connection()
        self.raw.connect.side_effect = lambda _address: setattr(self, "clock", 106)
        conn.start()
        with self.assertRaises(TimeoutError):
            conn.connect()
        conn.finish()
        self.context.wrap_socket.assert_not_called()
        self.raw.close.assert_called()

    def test_timer_can_interrupt_tls_handshake_before_it_completes(self):
        conn = self.connection()

        def handshake():
            self.timer.call_args.args[1]()

        self.tls.do_handshake.side_effect = handshake
        conn.start()
        with self.assertRaises(TimeoutError):
            conn.connect()
        self.tls.shutdown.assert_called_once()
        conn.finish()

    def test_http10_detach_does_not_disarm_body_deadline(self):
        conn = self.connection()
        conn.start()
        conn.connect()
        conn.request("GET", "/login/")
        response = conn.getresponse()
        self.assertTrue(response.will_close)
        self.assertIsNone(conn.sock)
        self.tls.close.assert_not_called()
        self.timer.return_value.cancel.assert_not_called()
        # Exercise the real stdlib HTTP parser, with an in-memory TLS double.
        self.assertEqual(response.read(), b"{}")
        self.timer.call_args.args[1]()
        self.tls.shutdown.assert_called_once()
        with self.assertRaises(TimeoutError):
            conn.remaining()
        conn.finish()
        self.tls.close.assert_called_once()

    def test_expired_overall_budget_prevents_starting_a_connection(self):
        conn = self.connection(deadline=100.1)
        self.clock = 100.2
        with self.assertRaises(TimeoutError):
            conn.start()
        conn.finish()
        self.raw.connect.assert_not_called()
        self.timer.assert_not_called()

    def test_partial_overall_budget_is_not_extended_by_request_setup(self):
        conn = self.connection(deadline=100.5)
        self.clock = 100.25
        conn.start()
        self.assertEqual(self.timer.call_args.args[0], 0.25)
        conn.finish()

    def test_insecure_tls_or_unreviewed_endpoint_is_rejected_without_network(self):
        for port, seconds in ((443, 5), (18842, 6), (18842, 0), (18842, True), (18842, math.nan)):
            with self.subTest(port=port, seconds=seconds), self.assertRaises(ValueError):
                BoundedHTTPSConnection(port, seconds=seconds, context=self.context)
        self.context.check_hostname = False
        with self.assertRaises(ValueError):
            self.connection()
        self.raw.connect.assert_not_called()

    def test_connection_cannot_be_reused_after_completion(self):
        conn = self.connection()
        conn.start()
        conn.connect()
        conn.finish()
        with self.assertRaises(ValueError):
            conn.start()
        self.raw.connect.assert_called_once()

    def test_expired_body_is_not_returned_as_an_observation_or_session(self):
        client = object.__new__(ClosedHTTPSClient)
        client.context, client.budget, client.cookies = self.context, RequestBudget(), {}
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = b"{}"
        connection.remaining.side_effect = TimeoutError("test-only expired response")
        with patch(
            "integrations.enterprise.reference_http.BoundedHTTPSConnection",
            return_value=connection,
        ):
            with self.assertRaises(TimeoutError):
                client.request("GET", "/identity/")
        self.assertEqual(client.cookies, {})
        connection.finish.assert_called_once()
        self.assertEqual(client.budget.used, 1)

    def test_ca_context_ignores_keylog_environment_and_loads_only_explicit_trust(self):
        with (
            patch.dict("os.environ", {"SSLKEYLOGFILE": "nonfunctional-test-only-trace"}),
            patch.object(ssl.SSLContext, "load_verify_locations") as trust,
        ):
            context = lab_context("nonfunctional-test-only-ca")
        self.assertIsNone(context.keylog_filename)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertTrue(context.verify_flags & ssl.VERIFY_X509_STRICT)
        trust.assert_called_once_with(cafile="nonfunctional-test-only-ca")
