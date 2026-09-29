"""The web-report adapter cannot cross application or provenance boundaries."""

import json
from io import BytesIO, StringIO
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from bridge.findings import import_scan, triage
from bridge.models import Audit, Finding, FindingObservation, Integration, Membership, ScanRun
from bridge.scanner_reports import ReportError
from bridge.services import WorkflowError


def web_report():
    return {
        "@version": "2.16.1",
        "site": [
            {
                "@name": "http://signalbridge-zap-target:8000",
                "@host": "signalbridge-zap-target",
                "@port": "8000",
                "@ssl": "false",
                "alerts": [
                    {
                        "pluginid": "10020",
                        "alertRef": "10020",
                        "riskcode": "2",
                        "confidence": "2",
                        "count": "1",
                        "name": "private-title-sentinel",
                        "desc": "private-description-sentinel",
                        "instances": [
                            {
                                "uri": "http://signalbridge-zap-target:8000/login/",
                                "method": "GET",
                                "evidence": "private-evidence-sentinel",
                                "request-header": "Cookie: private-cookie-sentinel",
                                "response-body": "private-body-sentinel",
                            }
                        ],
                    }
                ],
            }
        ],
    }


class ZapImportTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(
            slug="signalbridge", name="SignalBridge", enabled=False
        )
        cls.other = Integration.objects.create(slug="bettail", name="BetTail")
        cls.analyst = get_user_model().objects.create_user(username="zap-analyst")
        cls.viewer = get_user_model().objects.create_user(username="zap-viewer")
        cls.foreign = get_user_model().objects.create_user(username="zap-foreign")
        for user, app, role in (
            (cls.analyst, cls.app, "analyst"),
            (cls.analyst, cls.other, "analyst"),
            (cls.viewer, cls.app, "viewer"),
            (cls.foreign, cls.other, "analyst"),
        ):
            Membership.objects.create(user=user, integration=app, role=role)

    def load(self, data=None, user=None, app=None, **kwargs):
        raw = json.dumps(web_report() if data is None else data).encode()
        return import_scan(user or self.analyst, app or self.app, raw, "zap", **kwargs)

    def test_import_is_idempotent_unknown_and_sanitized(self):
        run, created = self.load()
        repeated, again = self.load()
        self.assertTrue(created)
        self.assertFalse(again)
        self.assertEqual(run.pk, repeated.pk)
        self.assertEqual((run.format, run.tool, run.provenance), ("zap", "ZAP", "claimed_report"))
        self.assertEqual((run.coverage_status, run.input_count), ("unknown", 0))
        self.assertEqual((run.source_revision, run.manifest, run.execution), ("", {}, {}))
        finding = Finding.objects.get(integration=self.app)
        self.assertEqual(finding.severity, "medium")
        self.assertEqual((finding.path, finding.line, finding.package), ("", None, ""))
        self.assertIn("GET /login/", finding.title)
        self.assertEqual(FindingObservation.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="scan.imported").count(), 1)
        normalized = json.dumps(FindingObservation.objects.get().snapshot)
        self.assertNotIn("private-", normalized)

    def test_foreign_app_cannot_receive_fixed_signalbridge_report(self):
        with self.assertRaises(ReportError):
            self.load(app=self.other)
        self.assertFalse(ScanRun.objects.exists())
        self.assertFalse(Finding.objects.exists())
        self.assertFalse(Audit.objects.exists())

    def test_viewer_foreign_and_inactive_users_cannot_import(self):
        for user in (self.viewer, self.foreign):
            with self.subTest(user=user.username), self.assertRaises(PermissionError):
                self.load(user=user)
        self.analyst.is_active = False
        self.analyst.save(update_fields=["is_active"])
        with self.assertRaises(PermissionError):
            self.load()
        self.assertFalse(ScanRun.objects.exists())

    def test_external_instance_rolls_back_whole_import(self):
        report = web_report()
        report["site"][0]["alerts"][0]["instances"][0]["uri"] = "https://example.invalid/"
        with self.assertRaises(ReportError):
            self.load(data=report)
        self.assertFalse(Finding.objects.exists())
        self.assertFalse(ScanRun.objects.exists())
        self.assertFalse(Audit.objects.exists())

    def test_empty_report_does_not_close_prior_finding_or_claim_coverage(self):
        self.load()
        report = web_report()
        report["site"][0]["alerts"] = []
        run, _ = self.load(data=report)
        self.assertEqual(
            (run.finding_count, run.coverage_status, run.input_count), (0, "unknown", 0)
        )
        self.assertEqual(Finding.objects.get().status, "open")

    def test_import_cannot_claim_source_provenance(self):
        with self.assertRaises(WorkflowError):
            self.load(source_revision="a" * 40)
        with self.assertRaises(WorkflowError):
            self.load(
                source_revision="a" * 40,
                manifest={"bridge/views.py": "b" * 64},
                execution={
                    "runner": "signalbridge-ruff",
                    "returncode": 0,
                    "duration_ms": 1,
                    "started_at": "2026-09-24T00:00:00+00:00",
                    "finished_at": "2026-09-24T00:00:01+00:00",
                    "original_digest": "c" * 64,
                },
            )
        self.assertFalse(ScanRun.objects.exists())

    def test_review_binds_to_unverified_observation_without_elevating_it(self):
        run, _ = self.load()
        finding = Finding.objects.get()
        triage(
            self.analyst,
            finding.pk,
            "reviewed",
            finding.version,
            "Synthetic report reviewed; actual scan remains unverified.",
        )
        record = Audit.objects.get(action="finding.triaged")
        self.assertEqual(record.detail["evidence"]["provenance"], "claimed_report")
        self.assertEqual(record.detail["evidence"]["source_file_digest"], "")
        run.refresh_from_db()
        self.assertEqual(run.coverage_status, "unknown")

    def test_scoped_console_and_export_do_not_expose_raw_report(self):
        run, _ = self.load()
        finding = Finding.objects.get()
        self.client.force_login(self.analyst)
        for url in (
            "/scans/?app=signalbridge",
            f"/findings/{finding.pk}/?app=signalbridge",
            f"/scans/{run.pk}/export/?app=signalbridge",
        ):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertNotIn(b"private-", response.content)
        page = self.client.get(f"/findings/{finding.pk}/?app=signalbridge")
        self.assertContains(page, "REPORTED ZAP RISK")
        self.assertContains(page, "Unverified imported claim")
        self.client.force_login(self.foreign)
        self.assertEqual(self.client.get(f"/scans/{run.pk}/export/?app=bettail").status_code, 404)

    def test_cli_accepts_zap_but_keeps_fixed_workspace_boundary(self):
        raw = json.dumps(web_report()).encode()
        with patch.object(Path, "open", side_effect=lambda *args, **kwargs: BytesIO(raw)):
            path = Path("synthetic-zap.json")
            output = StringIO()
            call_command(
                "import_scan",
                "signalbridge",
                str(path),
                format="zap",
                user=self.analyst.username,
                stdout=output,
            )
            self.assertIn("coverage unknown", output.getvalue())
            with self.assertRaises(CommandError):
                call_command(
                    "import_scan",
                    "bettail",
                    str(path),
                    format="zap",
                    user=self.analyst.username,
                    stdout=StringIO(),
                )
        self.assertEqual(ScanRun.objects.count(), 1)
