"""Offline transport controls and real transactional outbox regressions.

Transport replies are doubles; this suite does not establish native HTTP/TLS proof.
"""

import json
import os
import ssl
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db import connection
from django.test import SimpleTestCase, TransactionTestCase
from django.utils import timezone

from bridge.contract import signature

from .collector import APP_KEYS, NativeTransport, claim, deliver_one, finish
from .models import Outbox, Resource
from .telemetry import emit

KEY = "nonfunctional-collector-test-fixture-" + "x" * 48


class CollectorTests(TransactionTestCase):
    def setUp(self):
        self.environment = patch.dict(
            os.environ,
            {
                "SB_REF_PSEUDO_DOCUMENTS": KEY,
                "SB_REF_PSEUDO_EXPENSES": KEY + "other",
                "SB_REF_DELIVERY_DOCUMENTS": KEY + "documents",
                "SB_REF_DELIVERY_EXPENSES": KEY + "expenses",
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.user = get_user_model().objects.create(username="source-owner")
        self.resource = Resource.objects.create(
            app="documents", owner=self.user, label="Synthetic only", synthetic_content="SYNTHETIC"
        )
        self.row = emit(self.resource, self.user, "allowed", "owner")

    def acknowledgement(self, status=202):
        return status, json.dumps(
            {"status": "accepted" if status == 202 else "duplicate", "event_id": str(self.row.pk)}
        ).encode()

    def test_acknowledgement_requires_exact_identity_and_leaves_transaction_before_io(self):
        def transport(app, body, headers):
            self.assertFalse(connection.in_atomic_block)
            self.assertEqual(app, "documents")
            self.assertEqual(json.loads(body)["event_id"], str(self.row.pk))
            self.assertEqual(headers["X-SB-Key"], APP_KEYS[app])
            self.assertEqual(
                headers["X-SB-Signature"],
                signature(KEY + "documents", app, APP_KEYS[app], headers["X-SB-Time"], body),
            )
            return self.acknowledgement()

        self.assertEqual(deliver_one(transport), "acknowledged")
        self.row.refresh_from_db()
        self.assertEqual(self.row.attempts, 1)
        self.assertIsNotNone(self.row.acknowledged_at)
        self.assertIsNone(self.row.lease_token)
        self.assertIsNone(deliver_one(Mock(side_effect=AssertionError("No second delivery"))))

    def test_duplicate_acknowledgement_finishes_same_logical_event(self):
        self.assertEqual(deliver_one(lambda *args: self.acknowledgement(200)), "acknowledged")
        self.assertEqual(Outbox.objects.count(), 1)

    def test_lost_reply_retries_identical_event_without_duplicate_logical_acceptance(self):
        remote = {}

        def lost_reply(app, body, headers):
            remote[str(self.row.pk)] = body
            raise OSError("Simulated lost reply")

        self.assertEqual(deliver_one(lost_reply), "pending")
        Outbox.objects.filter(pk=self.row.pk).update(available_at=timezone.now())

        def retry(app, body, headers):
            self.assertEqual(body, remote[str(self.row.pk)])
            return self.acknowledgement(200)

        self.assertEqual(deliver_one(retry), "acknowledged")
        self.row.refresh_from_db()
        self.assertEqual(self.row.attempts, 2)
        self.assertEqual(len(remote), 1)

    def test_unexpired_lease_prevents_a_second_claim_then_expiry_recovers(self):
        now = timezone.now()
        first = claim(now)
        self.assertIsNone(claim(now))
        later = claim(now + timedelta(seconds=31))
        self.assertEqual(first.pk, later.pk)
        self.assertNotEqual(first.lease_token, later.lease_token)
        self.assertEqual(later.attempts, 2)

    def test_stale_reply_cannot_acknowledge_another_workers_lease(self):
        first = claim(timezone.now())
        replacement = uuid.uuid4()
        Outbox.objects.filter(pk=first.pk).update(lease_token=replacement)
        self.assertEqual(finish(first, "acknowledged"), "lease_lost")
        self.row.refresh_from_db()
        self.assertEqual(self.row.lease_token, replacement)
        self.assertEqual(self.row.state, "pending")
        self.assertIsNone(self.row.acknowledged_at)

    def test_expired_reply_is_not_accepted(self):
        first = claim(timezone.now())
        Outbox.objects.filter(pk=first.pk).update(
            leased_until=timezone.now() - timedelta(seconds=1)
        )
        self.assertEqual(finish(first, "acknowledged"), "lease_lost")
        self.assertIsNotNone(claim(timezone.now()))

    def test_invalid_acknowledgements_remain_pending(self):
        for body in (
            b"[]",
            b"null",
            b"bad-json",
            json.dumps({"status": "accepted", "event_id": str(uuid.uuid4())}).encode(),
            b"x" * 1025,
        ):
            with self.subTest(body_type=type(body).__name__, length=len(body)):
                Outbox.objects.filter(pk=self.row.pk).update(available_at=timezone.now())
                self.assertEqual(deliver_one(lambda *args, body=body: (202, body)), "pending")
        self.row.refresh_from_db()
        self.assertIsNone(self.row.acknowledged_at)

    def test_conflict_is_retained_for_operator_review(self):
        self.assertEqual(deliver_one(lambda *args: (409, b"{}")), "dead")
        self.row.refresh_from_db()
        self.assertEqual(self.row.error_code, "event_conflict")
        self.assertEqual(self.row.payload["event_id"], str(self.row.pk))

    def test_redirects_are_rejected_without_following(self):
        self.assertEqual(deliver_one(lambda *args: (302, b"{}")), "dead")
        self.row.refresh_from_db()
        self.assertEqual(self.row.error_code, "redirect_rejected")

    def test_service_failure_preserves_record_with_bounded_backoff(self):
        self.assertEqual(deliver_one(lambda *args: (503, b"{}")), "pending")
        self.row.refresh_from_db()
        self.assertGreater(self.row.available_at, timezone.now())
        self.assertLessEqual((self.row.available_at - timezone.now()).total_seconds(), 300)
        self.assertEqual(self.row.error_code, "collector_unavailable")

    def test_missing_or_shared_signing_keys_fail_before_claim(self):
        for key in ("", KEY + "documents"):
            with patch.dict(os.environ, {"SB_REF_DELIVERY_EXPENSES": key}):
                with self.assertRaises(ImproperlyConfigured):
                    deliver_one(Mock())
        self.row.refresh_from_db()
        self.assertEqual(self.row.attempts, 0)

    def test_modified_outbox_payload_never_reaches_transport(self):
        value = {**self.row.payload, "private_content": "must-never-export"}
        Outbox.objects.filter(pk=self.row.pk).update(payload=value)
        transport = Mock()
        self.assertEqual(deliver_one(transport), "dead")
        transport.assert_not_called()
        self.row.refresh_from_db()
        self.assertEqual(self.row.error_code, "invalid_outbox_record")

    def test_payload_changed_during_delivery_cannot_be_acknowledged(self):
        def transport(*args):
            Outbox.objects.filter(pk=self.row.pk).update(digest="a" * 64)
            return self.acknowledgement()

        self.assertEqual(deliver_one(transport), "dead")
        self.row.refresh_from_db()
        self.assertEqual(self.row.error_code, "outbox_changed")
        self.assertIsNone(self.row.acknowledged_at)


class NativeTransportControlTests(SimpleTestCase):
    def test_explicit_certificate_is_required_without_http_fallback(self):
        with patch.dict(os.environ, {"SB_REF_DELIVERY_CA": ""}):
            with self.assertRaises(ImproperlyConfigured):
                NativeTransport()

    def test_fixed_loopback_tls_destination_response_cap_and_connection_deadline(self):
        # TLS establishment and transport are doubled. Assert the configuration;
        # do not label this check as an executed native TLS connection.
        context = ssl.create_default_context()
        client = Mock()
        client.getresponse.return_value.status = 202
        client.getresponse.return_value.read.return_value = b"{}"
        with (
            patch.dict(os.environ, {"SB_REF_DELIVERY_CA": str(Path(__file__))}),
            patch(
                "reference_lab.collector.ssl.create_default_context", return_value=context
            ) as trust,
            patch(
                "reference_lab.collector.http.client.HTTPSConnection", return_value=client
            ) as connect,
            patch("reference_lab.collector.threading.Timer") as timer,
        ):
            transport = NativeTransport()
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(transport("documents", b"{}", {}), (202, b"{}"))
        trust.assert_called_once_with(cafile=str(Path(__file__)))
        connect.assert_called_once_with("127.0.0.1", 18841, timeout=5, context=context)
        client.getresponse.return_value.read.assert_called_once_with(1025)
        timer.return_value.start.assert_called_once()
        timer.return_value.cancel.assert_called_once()
        client.close.assert_called_once()
