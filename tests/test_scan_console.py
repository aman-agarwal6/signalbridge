"""Independent access, presentation and fixed-runner boundary tests."""

import hashlib
import json
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, TestCase, override_settings

from bridge.findings import import_scan
from bridge.management.commands.scan_local import normalize_locations, source_manifest
from bridge.models import Audit, Finding, Integration, Membership


def report(path="bridge/views.py", rule="S603", success=True):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Ruff", "version": "0.16.8"}},
                "invocations": [{"executionSuccessful": success}],
                "results": [
                    {
                        "ruleId": rule,
                        "message": {"text": "secret-scanner-message-sentinel"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": path},
                                    "region": {
                                        "startLine": 7,
                                        "snippet": {"text": "secret-code-sentinel"},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


class ScanConsoleTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(
            slug="scanner-tests", name="Scanner tests", enabled=False
        )
        cls.other = Integration.objects.create(
            slug="other-tests", name="Other tests", enabled=False
        )
        cls.author = get_user_model().objects.create_user(username="scan-console-author")
        cls.viewer = get_user_model().objects.create_user(username="scan-console-viewer")
        cls.foreign = get_user_model().objects.create_user(username="scan-console-foreign")
        cls.empty = get_user_model().objects.create_user(username="scan-console-empty")
        for user, app, role in (
            (cls.author, cls.app, "analyst"),
            (cls.viewer, cls.app, "viewer"),
            (cls.foreign, cls.other, "analyst"),
        ):
            Membership.objects.create(user=user, integration=app, role=role)
        cls.scan_run, _ = import_scan(cls.author, cls.app, json.dumps(report()).encode(), "sarif")
        cls.item = Finding.objects.get(integration=cls.app)
        cls.foreign_run, _ = import_scan(
            cls.foreign,
            cls.other,
            json.dumps(report("foreign-sentinel.py", "FOREIGN-SENTINEL")).encode(),
            "sarif",
        )
        cls.foreign_item = Finding.objects.get(integration=cls.other)

    def setUp(self):
        self.client.force_login(self.author)

    def url(self, path):
        return f"{path}?app={self.app.slug}"

    def detail_url(self):
        return self.url(f"/findings/{self.item.pk}/")

    def test_login_required_for_lists_details_exports_and_writes(self):
        self.client.logout()
        for path in (
            "/findings/",
            "/scans/",
            f"/findings/{self.item.pk}/",
            f"/scans/{self.scan_run.pk}/export/",
        ):
            with self.subTest(path=path):
                response = self.client.get(self.url(path))
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response.url.startswith("/login/?next="))
        self.assertEqual(self.client.post(self.detail_url(), {}).status_code, 302)

    def test_application_scope_applies_to_every_read_and_write(self):
        for path in ("/findings/", "/scans/"):
            response = self.client.get(self.url(path))
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, "FOREIGN-SENTINEL")
            self.assertNotContains(response, str(self.foreign_run.pk))
            self.assertEqual(self.client.get(f"{path}?app={self.other.slug}").status_code, 404)
        for path in (
            f"/findings/{self.foreign_item.pk}/",
            f"/scans/{self.foreign_run.pk}/export/",
        ):
            self.assertEqual(self.client.get(self.url(path)).status_code, 404)
        self.assertEqual(
            self.client.post(
                self.url(f"/findings/{self.foreign_item.pk}/"),
                {"status": "reviewed", "version": 1, "rationale": "Out of scope"},
            ).status_code,
            404,
        )
        self.foreign_item.refresh_from_db()
        self.assertEqual(self.foreign_item.status, "open")
        self.assertFalse(Audit.objects.filter(action="scan.exported").exists())

    def test_authenticated_account_without_memberships_has_no_default_access(self):
        self.client.force_login(self.empty)
        self.assertEqual(self.client.get("/findings/").status_code, 404)
        self.assertEqual(self.client.get(self.detail_url()).status_code, 404)

    def test_viewer_can_inspect_export_but_not_record_a_review(self):
        self.client.force_login(self.viewer)
        self.assertContains(
            self.client.get(self.detail_url()), "Analyst or reviewer access is required"
        )
        response = self.client.get(self.url(f"/scans/{self.scan_run.pk}/export/"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["application"], self.app.slug)
        denied = self.client.post(
            self.detail_url(),
            {
                "status": "reviewed",
                "version": 1,
                "rationale": "Viewer review",
            },
        )
        self.assertEqual(denied.status_code, 403)
        self.item.refresh_from_db()
        self.assertEqual(self.item.status, "open")

    def test_csrf_required_even_for_an_authorized_analyst(self):
        strict_client = Client(enforce_csrf_checks=True)
        strict_client.force_login(self.author)
        response = strict_client.post(
            self.detail_url(),
            {
                "status": "reviewed",
                "version": 1,
                "rationale": "No token",
            },
        )
        self.assertEqual(response.status_code, 403)
        self.item.refresh_from_db()
        self.assertEqual(self.item.version, 1)

    def test_status_tool_and_text_filters_keep_counts_scoped(self):
        response = self.client.get(self.url("/findings/") + "&q=S603&tool=Ruff&status=open")
        self.assertContains(response, str(self.item.pk))
        self.assertEqual(response.context["total_count"], 1)
        self.assertEqual(response.context["run_count"], 1)
        self.assertEqual(len(response.context["findings"]), 1)
        response = self.client.get(self.url("/findings/") + "&status=reviewed")
        self.assertEqual(len(response.context["findings"]), 0)
        response = self.client.get(self.url("/findings/") + "&q=not-present")
        self.assertEqual(len(response.context["findings"]), 0)

    def test_rationale_and_search_queries_are_escaped(self):
        payload = '<script>alert("review")</script>'
        response = self.client.post(
            self.detail_url(),
            {
                "status": "reviewed",
                "version": 1,
                "rationale": payload,
            },
            follow=True,
        )
        self.assertContains(response, "&lt;script&gt;")
        self.assertNotContains(response, payload)
        response = self.client.get("/findings/", {"app": self.app.slug, "q": payload})
        self.assertContains(response, "&lt;script&gt;")
        self.assertNotContains(response, payload)

    def test_normalized_ui_and_export_never_include_report_snippets(self):
        for path in (
            "/findings/",
            "/scans/",
            f"/findings/{self.item.pk}/",
            f"/scans/{self.scan_run.pk}/export/",
        ):
            response = self.client.get(self.url(path))
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, "secret-scanner-message-sentinel")
            self.assertNotContains(response, "secret-code-sentinel")
            self.assertIn("no-store", response["Cache-Control"])
        exported = self.client.get(self.url(f"/scans/{self.scan_run.pk}/export/")).json()
        self.assertEqual(exported["report_digest"], self.scan_run.digest)
        self.assertEqual(exported["findings"][0]["path"], "bridge/views.py")

    def test_stale_review_preserves_current_decision(self):
        first = self.client.post(
            self.detail_url(),
            {
                "status": "reviewed",
                "version": 1,
                "rationale": "First decision",
            },
        )
        self.assertEqual(first.status_code, 302)
        stale = self.client.post(
            self.detail_url(),
            {
                "status": "false_positive",
                "version": 1,
                "rationale": "Stale decision",
            },
            follow=True,
        )
        self.assertContains(stale, "This finding changed")
        self.item.refresh_from_db()
        self.assertEqual(self.item.status, "reviewed")
        self.assertEqual(Audit.objects.filter(action="finding.triaged").count(), 1)

    def test_failed_report_coverage_is_preserved_with_local_execution(self):
        run, _ = import_scan(
            self.author,
            self.app,
            json.dumps(report(success=False)).encode(),
            "sarif",
            source_revision="a" * 40,
            manifest={"bridge/views.py": "b" * 64},
            execution={
                "runner": "signalbridge-ruff",
                "returncode": 0,
                "duration_ms": 10,
                "started_at": "2026-09-24T00:00:00+00:00",
                "finished_at": "2026-09-24T00:00:01+00:00",
                "original_digest": "c" * 64,
            },
        )
        self.assertEqual(run.coverage_status, "failed")
        self.assertEqual(run.provenance, "local_execution")
        response = self.client.get(self.url("/scans/"))
        self.assertContains(response, "Report failed")

    def test_bettail_integrations_renders_collector_coverage_and_optional_adapters(self):
        app = Integration.objects.create(
            slug="bettail", name="BetTail", coverage="Recorded BetTail lab coverage"
        )
        Membership.objects.create(user=self.author, integration=app, role="analyst")
        response = self.client.get("/integrations/?app=bettail")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "<h1>Integrations</h1>", html=True)
        for text in (
            "BetTail collector",
            "Recorded BetTail lab coverage",
            "Ingestion configured",
            "Database authorization",
            "Actual repository migrations",
            "Ruff + SARIF",
            "pip-audit",
            "Not integrated",
        ):
            self.assertContains(response, text)
        self.assertNotContains(response, "SignalBridge scanner workspace")


class ScannerSetupTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="setup-scanner", password="Private-test-password"
        )
        self.other = get_user_model().objects.create_user(username="setup-second")

    def provision(self, *grants):
        call_command("setup_scanners", grant=list(grants), stdout=StringIO())

    def test_provision_is_idempotent_preserves_credentials_and_requires_explicit_access(self):
        password_hash = self.user.password
        self.provision("setup-scanner:analyst")
        self.provision("setup-scanner:analyst")
        app = Integration.objects.get(slug="signalbridge")
        self.assertFalse(app.enabled)
        self.user.refresh_from_db()
        self.assertEqual(self.user.password, password_hash)
        self.assertEqual(Membership.objects.filter(integration=app).count(), 1)
        self.assertFalse(Membership.objects.filter(user=self.other).exists())
        self.assertEqual(Audit.objects.filter(action="scanner.access_granted").count(), 1)

    def test_conflicting_later_grant_rolls_back_earlier_grant_and_audit(self):
        self.provision("setup-scanner:analyst")
        with self.assertRaises(CommandError):
            self.provision("setup-second:viewer", "setup-scanner:reviewer")
        self.assertFalse(Membership.objects.filter(user=self.other).exists())
        self.assertEqual(Membership.objects.get(user=self.user).role, "analyst")
        self.assertEqual(Audit.objects.filter(action="scanner.access_granted").count(), 1)

    def test_conflicting_new_setup_rolls_back_workspace_creation(self):
        with self.assertRaises(CommandError):
            self.provision("setup-scanner:analyst", "setup-scanner:reviewer")
        self.assertFalse(Integration.objects.filter(slug="signalbridge").exists())
        self.assertFalse(Membership.objects.exists())

    @override_settings(LOCAL=False)
    def test_setup_is_local_only(self):
        with self.assertRaises(CommandError):
            self.provision("setup-scanner:analyst")
        self.assertFalse(Integration.objects.exists())

    def test_setup_refuses_event_collector_workspace_or_inactive_user(self):
        app = Integration.objects.create(slug="signalbridge", name="SignalBridge", enabled=True)
        with self.assertRaises(CommandError):
            self.provision("setup-scanner:analyst")
        app.enabled = False
        app.save()
        self.user.is_active = False
        self.user.save()
        with self.assertRaises(CommandError):
            self.provision("setup-scanner:analyst")
        self.assertFalse(Membership.objects.exists())

    def test_self_workspace_opens_scanner_queue_and_hides_unrelated_lab_navigation(self):
        self.provision("setup-scanner:analyst")
        self.client.force_login(self.user)
        response = self.client.get("/?app=signalbridge")
        self.assertRedirects(response, "/findings/?app=signalbridge")
        page = self.client.get(response.url)
        self.assertContains(page, "Security findings")
        for destination in ("/events/", "/investigations/", "/checks/", "/replay/"):
            self.assertNotContains(page, f'href="{destination}?app=signalbridge"')

    def test_self_workspace_integrations_renders_adapters_without_source_app_coverage_claims(self):
        self.provision("setup-scanner:analyst")
        self.client.force_login(self.user)
        response = self.client.get("/integrations/?app=signalbridge")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "<h1>Integrations</h1>", html=True)
        for text in (
            "SignalBridge scanner workspace",
            "Ruff + SARIF",
            "pip-audit",
            "Not integrated",
        ):
            self.assertContains(response, text)
        for text in (
            "SignalBridge collector",
            "Collector enabled",
            "Collector disabled",
            "Actual repository migrations challenged",
            "Database authorization",
            "LAST ACCEPTED EVENT",
            "PROCESSING QUEUE",
        ):
            self.assertNotContains(response, text)


class FixedRunnerBoundaryTests(TestCase):
    def setUp(self):
        self.root = Path(settings.BASE_DIR).resolve()
        self.source = self.root / "bridge" / "views.py"

    def test_manifest_only_reads_fixed_source_allowlist_and_hashes_exact_bytes(self):
        manifest = source_manifest(self.root)
        self.assertEqual(
            manifest["manage.py"],
            hashlib.sha256((self.root / "manage.py").read_bytes()).hexdigest(),
        )
        self.assertTrue(
            all(
                path == "manage.py" or path.startswith(("bridge/", "config/", "scripts/"))
                for path in manifest
            )
        )
        self.assertFalse(
            any(
                path.startswith(("var/", "private-source/", "tests/", ".venv/"))
                for path in manifest
            )
        )

    def test_manifest_refuses_symlinks_and_resolved_external_paths(self):
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaises(CommandError):
                source_manifest(self.root)
        with patch.object(Path, "resolve", return_value=self.root.parent / "other.py"):
            with self.assertRaises(CommandError):
                source_manifest(self.root)

    def test_normalization_is_exact_allowlist_bound_and_strips_absolute_root(self):
        data = report(self.source.as_uri())
        data["runs"][0]["originalUriBaseIds"] = {"ROOT": {"uri": self.root.as_uri()}}
        data["runs"][0]["artifacts"] = [{"location": {"uri": self.source.as_uri()}}]
        normalized = json.loads(normalize_locations(data, self.root, {"bridge/views.py": "a" * 64}))
        run = normalized["runs"][0]
        self.assertEqual(
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"],
            {"uri": "bridge/views.py"},
        )
        self.assertNotIn("originalUriBaseIds", run)
        self.assertNotIn("artifacts", run)

    def test_normalization_rejects_remote_outside_and_unscanned_locations(self):
        for uri in (
            "https://example.invalid/views.py",
            "file://remote-host/views.py",
            (self.root.parent / "foreign.py").as_uri(),
            (self.root / "tests" / "test_security.py").as_uri(),
        ):
            with self.subTest(uri=uri), self.assertRaises(CommandError):
                normalize_locations(report(uri), self.root, {"bridge/views.py": "a" * 64})
