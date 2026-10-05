"""Closed capture/HAR and mocked transport tests; none establish native ZAP proof."""

import copy
import json
import ssl
import uuid
from datetime import datetime, timedelta, timezone
from email.message import Message
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from integrations.enterprise.reference_http import ClosedHTTPSClient, RequestBudget
from integrations.zap_enterprise.capture import (
    DOC_PATH,
    STEPS,
    HeaderProfileError,
    captured_row,
    known_body,
    render_har,
    validate_pair,
    validate_rows,
)

START = datetime(2026, 10, 2, 12, tzinfo=timezone.utc)


def exchange(ordinal=1, phase="fault"):
    account, path, status = STEPS[ordinal]
    headers = [("Content-Type", "application/json")]
    if phase != "fault" or ordinal != 1:
        headers.append(("X-Content-Type-Options", "nosniff"))
    if path != "/identity/":
        headers.append(
            ("X-SB-Lab-Event-ID", str(uuid.uuid5(uuid.NAMESPACE_URL, phase + str(ordinal))))
        )
    return {
        "method": "GET",
        "path": path,
        "status": status,
        "http_version": "HTTP/1.0",
        "headers": headers,
        "body": json.dumps(known_body(account, path)).encode(),
        "started_at": (START + timedelta(seconds=ordinal)).isoformat(),
    }


def rows(phase="fault"):
    return [
        captured_row(exchange(i, phase), account, i, phase)
        for i, (account, _, _) in enumerate(STEPS)
    ]


class HeaderCaptureTests(SimpleTestCase):
    def test_equivalent_retest_rejects_reused_events_changed_headers_and_earlier_observations(self):
        before, after = rows(), rows("corrected")
        for row in after:
            row["started_at"] = (START + timedelta(seconds=5 + row["ordinal"])).isoformat()
        validate_pair({"fault": before, "corrected": after})
        for change in ("event", "header", "time"):
            altered = copy.deepcopy(after)
            if change == "event":
                altered[1]["event_id"] = before[1]["event_id"]
                altered[1]["headers"]["x-sb-lab-event-id"] = before[1]["event_id"]
            elif change == "header":
                altered[1]["headers"]["cache-control"] = "different"
            else:
                for row in altered:
                    row["started_at"] = (START + timedelta(seconds=row["ordinal"])).isoformat()
            with self.subTest(change=change), self.assertRaises(HeaderProfileError):
                validate_pair({"fault": before, "corrected": altered})

    def test_exact_known_controls_and_sanitized_har_preserve_actual_responses(self):
        for phase in ("fault", "corrected"):
            observations = rows(phase)
            har = json.loads(
                render_har(observations, phase, (START + timedelta(seconds=6)).isoformat())
            )
            self.assertEqual(len(har["log"]["entries"]), 5)
            for observed, entry in zip(observations, har["log"]["entries"], strict=True):
                self.assertEqual(entry["response"]["content"]["text"], observed["body"])
                self.assertEqual(entry["response"]["status"], observed["http_status"])
                self.assertEqual(entry["response"]["httpVersion"], observed["http_version"])
                self.assertEqual(entry["startedDateTime"], observed["started_at"])
                self.assertEqual(entry["request"]["cookies"], [])
                self.assertEqual(entry["response"]["cookies"], [])
                self.assertNotIn("postData", entry["request"])
                self.assertIn("placeholders", entry["comment"])

    def test_wrong_account_path_method_or_service_failure_never_qualifies(self):
        for key, value in (
            ("path", "/admin/"),
            ("method", "POST"),
            ("status", 503),
            ("status", True),
            ("http_version", "HTTP/2.0"),
        ):
            with self.subTest(key=key), self.assertRaises(HeaderProfileError):
                captured_row({**exchange(), key: value}, "document_member", 1, "fault")
        with self.assertRaises(HeaderProfileError):
            captured_row(exchange(), "operator", 1, "fault")

    def test_fixed_body_validation_rejects_unknown_data_duplicate_keys_and_boolean_substitution(
        self,
    ):
        variants = (
            b'{"error":"different"}',
            b'{"account":"document_member","authenticated":1}',
            b'{"account":"document_member","authenticated":true,"authenticated":true}',
            b"[]",
            b'{"account":"document_member","authenticated":NaN}',
            b"\xff",
            b"x" * 8193,
        )
        for raw in variants:
            with self.subTest(raw=raw[:80]), self.assertRaises(HeaderProfileError):
                captured_row({**exchange(0), "body": raw}, "document_member", 0, "fault")

    def test_header_injection_duplicates_and_credential_headers_are_rejected(self):
        for addition in (
            ("Content-Type", "application/json"),
            ("Cache-Control", "value\r\ninjected: bad"),
            ("Authorization", "synthetic"),
            ("Set-Cookie", "synthetic"),
            ("Cookie", "synthetic"),
            ("X-Frame-Options", "x" * 2049),
            ("Pragma", "\x00"),
        ):
            with self.subTest(addition=addition), self.assertRaises(HeaderProfileError):
                captured_row(
                    {**exchange(), "headers": [*exchange()["headers"], addition]},
                    "document_member",
                    1,
                    "fault",
                )

    def test_exact_fault_and_correction_header_controls_are_required(self):
        for ordinal, phase in ((1, "fault"), (1, "corrected"), (4, "fault"), (2, "fault")):
            value = exchange(ordinal, phase)
            value["headers"] = [
                (k, v) for k, v in value["headers"] if k.lower() != "x-content-type-options"
            ]
            if phase == "fault" and ordinal == 1:
                value["headers"].append(("X-Content-Type-Options", "nosniff"))
            with self.subTest(ordinal=ordinal, phase=phase), self.assertRaises(HeaderProfileError):
                captured_row(value, STEPS[ordinal][0], ordinal, phase)

    def test_secret_substrings_never_enter_capture_headers(self):
        secret = "nonfunctional-capture-cookie-test-" + "x" * 32
        value = exchange()
        value["headers"].append(("Cache-Control", secret))
        with self.assertRaises(HeaderProfileError):
            captured_row(value, "document_member", 1, "fault", (secret,))

    def test_missing_invalid_duplicate_or_identity_event_bindings_are_rejected(self):
        for value in (None, "bad", str(uuid.uuid4()).upper()):
            supplied = exchange()
            supplied["headers"] = [
                (k, v) for k, v in supplied["headers"] if k.lower() != "x-sb-lab-event-id"
            ]
            if value is not None:
                supplied["headers"].append(("X-SB-Lab-Event-ID", value))
            with self.subTest(value=value), self.assertRaises(HeaderProfileError):
                captured_row(supplied, "document_member", 1, "fault")
        supplied = exchange(0)
        supplied["headers"].append(("X-SB-Lab-Event-ID", str(uuid.uuid4())))
        with self.assertRaises(HeaderProfileError):
            captured_row(supplied, "document_member", 0, "fault")

    def test_partial_reordered_extra_or_reused_events_cannot_claim_complete_coverage(self):
        supplied = rows()
        variants = (
            supplied[:-1],
            list(reversed(supplied)),
            [*supplied, supplied[0]],
            [{**supplied[0], "extra": True}, *supplied[1:]],
        )
        for value in variants:
            with self.subTest(length=len(value)), self.assertRaises(HeaderProfileError):
                validate_rows(value, "fault")
        value = copy.deepcopy(supplied)
        value[4]["event_id"] = value[1]["event_id"]
        value[4]["headers"]["x-sb-lab-event-id"] = value[1]["event_id"]
        with self.assertRaises(HeaderProfileError):
            validate_rows(value, "fault")

    def test_invalid_timezone_chronology_and_profile_window_are_rejected(self):
        for timestamp in ("2026-10-02T12:00:00", "2026-10-02T12:00:00+01:00", "bad", 2, "x" * 41):
            with self.subTest(timestamp=timestamp), self.assertRaises(HeaderProfileError):
                captured_row({**exchange(), "started_at": timestamp}, "document_member", 1, "fault")
        for timestamp in (START - timedelta(seconds=1), START + timedelta(seconds=181)):
            value = rows()
            value[-1]["started_at"] = timestamp.isoformat()
            with self.assertRaises(HeaderProfileError):
                validate_rows(value, "fault")
        with self.assertRaises(HeaderProfileError):
            render_har(rows(), "fault", START.isoformat())

    def test_mocked_transport_retains_only_protected_get_response_and_clears_stale_capture(self):
        client = object.__new__(ClosedHTTPSClient)
        client.budget, client.cookies, client.context = (
            RequestBudget(),
            {},
            ssl.create_default_context(),
        )
        headers = Message()
        for name, value in exchange()["headers"]:
            headers[name] = value
        headers["Set-Cookie"] = "other=never-retained; Secure"
        connection = Mock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.version = 10
        connection.getresponse.return_value.headers = headers
        connection.getresponse.return_value.read.return_value = exchange()["body"]
        with patch(
            "integrations.enterprise.reference_http.BoundedHTTPSConnection", return_value=connection
        ):
            client.request("GET", DOC_PATH)
            self.assertNotIn("set-cookie", {k.lower() for k, _ in client.last_response["headers"]})
            self.assertEqual(client.last_response["body"], exchange()["body"])
            self.assertEqual(client.last_response["http_version"], "HTTP/1.0")
            del headers["X-SB-Lab-Event-ID"]
            client.request("POST", "/login/", b"synthetic-password-post")
            self.assertIsNone(client.last_response)
            client.last_response = {"stale": True}
            connection.connect.side_effect = TimeoutError("synthetic")
            with self.assertRaises(TimeoutError):
                client.request("GET", DOC_PATH)
            self.assertIsNone(client.last_response)
            connection.finish.assert_called()
