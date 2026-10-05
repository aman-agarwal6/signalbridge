"""Driver wiring against disposable Django/SQLite, not HTTPS or native SSO proof."""

from unittest.mock import patch
from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings

from bridge.case_workflow import evidence_binding
from bridge.models import (
    Audit,
    CaseTask,
    CaseVerification,
    CheckRun,
    Event,
    Integration,
    Investigation,
    Membership,
    Note,
)
from integrations.identity.native_driver import case_controls, case_fixture, case_snapshot
from integrations.identity.native_http import (
    CONSOLE,
    NativeClient,
    NativeIdentityError,
    Reply,
    destination,
)


class ModeledHTTPClient(NativeClient):
    """Real application/CSRF behavior; password session and HTTP transport are modeled."""

    def __init__(self, user):
        self.browser = Client(enforce_csrf_checks=True)
        self.browser.force_login(user)
        self.browser.cookies["sb_enterprise_csrf"] = "c" * 32

    def csrf_token(self):
        return self.browser.cookies["sb_enterprise_csrf"].value

    def request(self, method, url, fields=None, **unused):
        origin, parsed = destination(url)
        if origin != CONSOLE:
            raise AssertionError("No provider calls in this modeled driver test")
        response = self.browser.generic(
            method,
            parsed.path,
            data=urlencode(fields or {}),
            content_type="application/x-www-form-urlencoded",
            secure=True,
            HTTP_HOST="127.0.0.1:18842",
            HTTP_ORIGIN=CONSOLE,
        )
        return Reply(response.status_code, url, response.content, response.get("Location", ""))


@override_settings(
    ALLOWED_HOSTS=["127.0.0.1"], CSRF_COOKIE_NAME="sb_enterprise_csrf", SECURE_SSL_REDIRECT=False
)
class NativeRoleDriverWiringTests(TestCase):
    def setUp(self):
        self.apps = {
            name: Integration.objects.create(slug=name, name="Synthetic " + name)
            for name in ("documents", "expenses")
        }
        self.cases = {name: case_fixture(app, "c" * 32) for name, app in self.apps.items()}
        self.clients = {}
        for role in ("analyst", "viewer", "reviewer"):
            user = get_user_model().objects.create(username="synthetic-" + role)
            Membership.objects.create(user=user, integration=self.apps["documents"], role=role)
            self.clients[role] = ModeledHTTPClient(user)
        self.rows = []

    def record(self, name, **facts):
        self.rows.append({"control": name, **facts})

    def test_driver_checks_real_role_denials_and_committed_positive_write(self):
        with patch("socket.socket", side_effect=AssertionError("No sockets")):
            case_controls(self.clients, self.cases, self.record)
        self.assertEqual(
            {row["control"] for row in self.rows},
            {
                "viewer_note_write_denied",
                "csrf_missing_write_denied",
                "analyst_note_write_persisted",
                "analyst_reviewer_action_denied",
                "analyst_cross_app_write_denied",
                "viewer_cross_app_write_denied",
                "reviewer_cross_app_write_denied",
            },
        )
        self.assertEqual(Note.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="case.structured_note").count(), 1)
        self.assertEqual(Investigation.objects.get(pk=self.cases["documents"]).version, 2)
        self.assertEqual(Investigation.objects.get(pk=self.cases["expenses"]).version, 1)
        self.assertFalse(CaseTask.objects.exists())
        self.assertFalse(CaseVerification.objects.exists())

    def test_fixture_cannot_be_mistaken_for_instrumented_source_or_retest(self):
        for case in Investigation.objects.all():
            self.assertTrue(evidence_binding(case))
            self.assertIn("no source execution", case.explanation)
        self.assertEqual(set(Event.objects.values_list("source", flat=True)), {"synthetic_demo"})
        self.assertEqual(set(Event.objects.values_list("state", flat=True)), {"pending"})
        self.assertFalse(CheckRun.objects.exists())

    def test_driver_refuses_denied_status_when_database_changed(self):
        viewer = self.clients["viewer"]
        original = viewer.case_work

        def mutate_then_deny(case_id, fields, **options):
            reply = original(case_id, fields, **options)
            Investigation.objects.filter(pk=case_id).update(status="resolved")
            return reply

        with patch.object(viewer, "case_work", side_effect=mutate_then_deny):
            with self.assertRaises(NativeIdentityError):
                case_controls(self.clients, self.cases, self.record)
        self.assertEqual(self.rows, [])

    def test_driver_refuses_to_count_csrf_failure_as_viewer_role_enforcement(self):
        with patch.object(
            self.clients["viewer"],
            "case_work",
            return_value=Reply(403, CONSOLE, b"CSRF verification failed"),
        ):
            with self.assertRaises(NativeIdentityError):
                case_controls(self.clients, self.cases, self.record)
        self.assertEqual(self.rows, [])

    def test_unchanged_local_session_loses_write_access_after_membership_removal(self):
        client = self.clients["analyst"]
        before = case_snapshot(self.cases["documents"])
        cookies = client.browser.cookies.output()
        Membership.objects.filter(role="analyst").delete()
        reply = client.case_work(
            self.cases["documents"],
            {
                "version": before[0],
                "operation": "structured_note",
                "kind": "observed_fact",
                "note": "Must not be written.",
            },
        )
        self.assertEqual(reply.status, 404)
        self.assertEqual(case_snapshot(self.cases["documents"]), before)
        self.assertEqual(client.browser.cookies.output(), cookies)
