"""Offline native-transport control checks, never a launched source execution."""

import json
import uuid
from unittest.mock import patch

from django.test import SimpleTestCase

from integrations.enterprise.reference_http import (
    CONTENT,
    MAX_REQUESTS,
    RESOURCES,
    ClosedHTTPSClient,
    ProfileError,
    RequestBudget,
    allowed_path,
    content_observation,
    exercise,
)
from integrations.enterprise.reference_native_server import PrivateHandler
from integrations.enterprise.reference_native_support import configure, profile


class ReferenceNativeProfileTests(SimpleTestCase):
    def test_only_fixed_local_paths_are_permitted(self):
        path = f"/apps/documents/resources/{RESOURCES['documents']}/"
        self.assertEqual(allowed_path("GET", path), path)
        for method, value in (
            ("GET", "https://example.com/"),
            ("GET", "//127.0.0.1/login/"),
            ("GET", "/login/?next=https://example.com/"),
            ("GET", "/../login/"),
            ("DELETE", path),
            ("POST", path),
            ("GET", "/admin/"),
            ("GET", path.replace("documents", "expenses")),
        ):
            with self.subTest(method=method, path=value), self.assertRaises(ProfileError):
                allowed_path(method, value)

    def test_response_requires_status_and_exact_known_record(self):
        value = {
            "app": "documents",
            "record_id": str(RESOURCES["documents"]),
            "synthetic_content": CONTENT["documents"],
        }
        self.assertEqual(
            content_observation(200, value, "documents")["observation"], "known_content_returned"
        )
        self.assertEqual(
            content_observation(403, {"error": "Access denied."}, "documents")["observation"],
            "explicit_denial",
        )
        for status, response in (
            (503, None),
            (200, {}),
            (404, {"error": "Resource unavailable."}),
            (200, {**value, "synthetic_content": "different"}),
            (403, {}),
        ):
            with self.subTest(status=status, response=response):
                self.assertEqual(
                    content_observation(status, response, "documents")["observation"],
                    "inconclusive",
                )

    def test_budget_is_shared_finite_and_failed_requests_count(self):
        budget = RequestBudget()
        for _ in range(MAX_REQUESTS):
            budget.consume()
        with self.assertRaises(ProfileError):
            budget.consume()
        budget.used = 0
        with (
            patch(
                "integrations.enterprise.reference_http.time.monotonic",
                return_value=budget.deadline + 1,
            ),
            self.assertRaises(ProfileError),
        ):
            budget.consume()

    def test_invalid_request_is_rejected_before_a_socket_is_created(self):
        client = object.__new__(ClosedHTTPSClient)
        client.budget, client.cookies = RequestBudget(), {}
        with patch("integrations.enterprise.reference_http.BoundedHTTPSConnection") as socket:
            for method, path, body in (
                ("GET", "/login/", b"unexpected"),
                ("GET", "/admin/", b""),
                ("POST", "/login/", b"x" * 1025),
            ):
                with self.subTest(method=method, path=path), self.assertRaises(ProfileError):
                    client.request(method, path, body)
            for fields in (
                ("documents", "outside-account", "group", True),
                ("documents", "document_member", "group", 1),
                ("expenses", "expense_member", "wildcard", True),
            ):
                with self.assertRaises(ProfileError):
                    client.permission(*fields)
            socket.assert_not_called()

    def test_transport_failure_consumes_shared_request_budget(self):
        client = object.__new__(ClosedHTTPSClient)
        client.budget, client.cookies, client.context = RequestBudget(), {}, None
        with patch("integrations.enterprise.reference_http.BoundedHTTPSConnection") as connection:
            connection.return_value.connect.side_effect = OSError("test-only unavailable")
            with self.assertRaises(OSError):
                client.request("GET", "/login/")
            self.assertEqual(client.budget.used, 1)
            connection.return_value.start.assert_called_once()
            connection.return_value.finish.assert_called_once()

    def test_receipt_predicates_do_not_include_private_body(self):
        value = {
            "app": "documents",
            "record_id": str(RESOURCES["documents"]),
            "synthetic_content": CONTENT["documents"],
        }
        encoded = json.dumps(content_observation(200, value, "documents"))
        self.assertNotIn(CONTENT["documents"], encoded)
        self.assertNotIn(str(RESOURCES["documents"]), encoded)

    def test_service_failure_is_incomplete_even_if_restoration_succeeds(self):
        lab = OfflineReferenceDouble(fail_removed_read=True)
        result = exercise(lab.factory, PASSWORDS, lab.fault)
        self.assertFalse(result["completed"])
        self.assertTrue(result["restoration_verified"])
        self.assertFalse(lab.injected)
        self.assertTrue(all(lab.group.values()))
        self.assertFalse(any(lab.direct.values()))
        failed = next(row for row in result["steps"] if not row["passed"])
        self.assertEqual(failed["observation"], "inconclusive")
        self.assertNotIn("private-unexpected-error", json.dumps(result))

    def test_success_profile_keeps_denial_and_owner_controls_separate(self):
        lab = OfflineReferenceDouble()
        result = exercise(lab.factory, PASSWORDS, lab.fault)
        self.assertTrue(result["completed"])
        self.assertTrue(result["restoration_verified"])
        by_step = {row["step"]: row for row in result["steps"]}
        for app in RESOURCES:
            self.assertEqual(by_step[app + "_removed_member_denied"]["http_status"], 403)
            self.assertEqual(by_step[app + "_owner_control"]["http_status"], 200)
            self.assertTrue(by_step[app + "_session_still_valid"]["session_unchanged"])
            self.assertTrue(by_step[app + "_alternate_grant_preserved"]["effective_access"])
        self.assertTrue(by_step["bounded_regression_known_content"]["known_content"])
        self.assertEqual(by_step["regression_reset_denied"]["http_status"], 403)
        self.assertFalse(lab.injected)

    def test_failed_reset_never_reports_a_completed_native_profile(self):
        lab = OfflineReferenceDouble(fail_reset=True)
        result = exercise(lab.factory, PASSWORDS, lab.fault)
        self.assertFalse(result["completed"])
        self.assertFalse(result["restoration_verified"])
        self.assertTrue(any(row["step"] == "restoration_incomplete" for row in result["steps"]))
        self.assertNotIn("private-unexpected-error", json.dumps(result))

    def test_profile_requires_closed_and_separate_credentials(self):
        valid = {
            "accounts": PASSWORDS,
            **{
                name: "nonfunctional-source-profile-test-only-" + name
                for name in (
                    "source_secret",
                    "console_secret",
                    "pseudo_documents",
                    "pseudo_expenses",
                    "delivery_documents",
                    "delivery_expenses",
                )
            },
        }
        from unittest.mock import Mock

        path = Mock()
        path.is_file.return_value = True
        path.is_symlink.return_value = False
        path.stat.return_value.st_size = 1024
        for value in (
            valid,
            {**valid, "extra": "unexpected"},
            {**valid, "source_secret": valid["console_secret"]},
            {**valid, "source_secret": "short"},
        ):
            path.read_bytes.return_value = json.dumps(value).encode()
            if value is valid:
                self.assertEqual(profile(path), valid)
            else:
                with self.assertRaises(ValueError):
                    profile(path)

    def test_source_support_refuses_unreviewed_components_before_reading_secrets(self):
        for environment, platform in (
            ({"SB_SOURCE_PROOF": "1", "SB_SOURCE_COMPONENT": "source"}, "win32"),
            ({"SB_SOURCE_PROOF": "1", "SB_SOURCE_COMPONENT": "production"}, "linux"),
            (
                {
                    "SB_SOURCE_PROOF": "1",
                    "SB_SOURCE_COMPONENT": "source",
                    "PGHOST": "external.example",
                },
                "linux",
            ),
            ({"SB_SOURCE_COMPONENT": "source"}, "linux"),
        ):
            with (
                patch.dict("os.environ", environment, clear=True),
                patch("integrations.enterprise.reference_native_support.sys.platform", platform),
                patch("integrations.enterprise.reference_native_support.profile") as secrets,
            ):
                with self.assertRaises(ValueError):
                    configure()
                secrets.assert_not_called()

    def test_wsgi_tls_scheme_is_derived_from_direct_tls_transport(self):
        handler = object.__new__(PrivateHandler)
        with patch(
            "wsgiref.simple_server.WSGIRequestHandler.get_environ",
            return_value={"HTTP_X_FORWARDED_PROTO": "http"},
        ):
            self.assertEqual(handler.get_environ()["HTTPS"], "on")


PASSWORDS = {
    name: "nonfunctional-native-profile-test-only-" + name
    for name in ("operator", "document_member", "expense_member", "outsider")
}


class OfflineReferenceDouble:
    """No HTTP, database or source evidence; test the harness's decision boundaries."""

    def __init__(self, fail_removed_read=False, fail_reset=False):
        self.group = {app: True for app in RESOURCES}
        self.direct = {app: False for app in RESOURCES}
        self.injected, self.fail_removed_read, self.fail_reset = (
            False,
            fail_removed_read,
            fail_reset,
        )

    def factory(self):
        return OfflineClientDouble(self)

    def fault(self, enabled, duration):
        if not enabled and self.fail_reset:
            raise OSError("private-unexpected-error")
        self.injected = enabled


class OfflineClientDouble:
    def __init__(self, lab):
        self.lab, self.cookies, self.account = lab, {}, None
        self.last_event_id = None

    def sign_in(self, account, password):
        self.account = account
        self.cookies["sessionid"] = "nonfunctional-fixed-test-cookie-only"

    def request(self, method, path):
        return 200, {"account": self.account, "authenticated": True}

    def permission(self, app, subject, kind, granted):
        before = self.lab.group[app] or self.lab.direct[app]
        (self.lab.group if kind == "group" else self.lab.direct)[app] = granted
        after = self.lab.group[app] or self.lab.direct[app]
        self.last_event_id = str(uuid.uuid4()) if before != after else None
        return 200, {"effective_access": after}

    def read(self, app):
        self.last_event_id = str(uuid.uuid4())
        intended = "document_member" if app == "documents" else "expense_member"
        member = self.account == intended
        allowed = (
            self.account == "operator"
            or member
            and (
                self.lab.group[app]
                or self.lab.direct[app]
                or app == "documents"
                and self.lab.injected
            )
        )
        if member and not allowed and self.lab.fail_removed_read:
            self.lab.fail_removed_read = False
            return content_observation(503, None, app)
        value = (
            {"app": app, "record_id": str(RESOURCES[app]), "synthetic_content": CONTENT[app]}
            if allowed
            else {"error": "Access denied."}
        )
        return content_observation(200 if allowed else 403, value, app)
