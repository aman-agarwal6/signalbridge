"""Scanner evidence stays scoped, honest and distinct from analyst decisions."""

import hashlib
from io import BytesIO, StringIO
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from bridge.findings import MAX_REPORT_BYTES, import_scan, triage
from bridge.models import Audit, Finding, FindingObservation, Integration, Membership, ScanRun
from bridge.services import WorkflowError


class FindingTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="scan-app", name="Scan app", enabled=False)
        cls.other = Integration.objects.create(slug="other-app", name="Other")
        cls.users = {}
        for role in ("viewer", "analyst", "reviewer"):
            user = get_user_model().objects.create_user(username="scan-" + role)
            Membership.objects.create(user=user, integration=cls.app, role=role)
            cls.users[role] = user
        cls.outsider = get_user_model().objects.create_user(username="scan-outsider")
        cls.item = SimpleNamespace(
            fingerprint="a" * 64,
            severity="warning",
            rule_id="S101",
            title="Reported code finding",
            path="bridge/example.py",
            line=12,
            package="",
            package_version="",
            fix_versions=(),
            suppressed=False,
        )

    def report(self, findings=None, **changes):
        values = dict(
            format="sarif",
            tool="Ruff",
            version="1.0",
            coverage_status="unknown",
            input_count=1,
            skipped_count=0,
            suppressed_count=0,
            findings=(self.item,) if findings is None else tuple(findings),
        )
        values.update(changes)
        return SimpleNamespace(**values)

    def import_report(self, raw=b"report", app=None, user=None, report=None, **options):
        with patch("bridge.findings.parse_report", return_value=report or self.report()):
            return import_scan(
                user or self.users["analyst"], app or self.app, raw, "sarif", **options
            )

    def test_import_requires_role_in_selected_app(self):
        for user, app in (
            (self.users["viewer"], self.app),
            (self.outsider, self.app),
            (self.users["analyst"], self.other),
        ):
            with self.assertRaises(PermissionError):
                self.import_report(user=user, app=app)
        self.assertEqual(ScanRun.objects.count(), 0)
        self.import_report(user=self.users["reviewer"])
        self.assertEqual(ScanRun.objects.count(), 1)

    def test_repeated_report_is_idempotent_with_original_importer(self):
        first, created = self.import_report()
        second, repeated = self.import_report(user=self.users["reviewer"])
        self.assertTrue(created)
        self.assertFalse(repeated)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(second.imported_by, self.users["analyst"])
        self.assertEqual(Finding.objects.count(), 1)
        self.assertEqual(FindingObservation.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="scan.imported").count(), 1)

    def test_report_identity_and_findings_are_isolated_by_app_and_tool(self):
        Membership.objects.create(
            user=self.users["analyst"], integration=self.other, role="analyst"
        )
        first, _ = self.import_report()
        other, _ = self.import_report(app=self.other)
        self.import_report(raw=b"different tool", report=self.report(tool="OtherScanner"))
        self.assertNotEqual(first.pk, other.pk)
        self.assertEqual(Finding.objects.count(), 3)

    def test_import_digest_counts_and_unknown_coverage_are_preserved(self):
        run, _ = self.import_report(
            report=self.report(input_count=4, skipped_count=2, suppressed_count=1)
        )
        self.assertEqual(run.digest, hashlib.sha256(b"report").hexdigest())
        self.assertEqual(run.provenance, "claimed_report")
        self.assertEqual(run.coverage_status, "unknown")
        self.assertEqual((run.input_count, run.skipped_count, run.suppressed_count), (4, 2, 1))
        self.assertEqual(run.finding_count, 1)
        self.assertEqual(run.manifest, {})
        self.assertEqual(run.execution, {})

    def test_changed_report_updates_details_without_changing_triage(self):
        self.import_report()
        finding = Finding.objects.get()
        triage(self.users["analyst"], finding.pk, "accepted_risk", 1, "Reviewed in test scope.")
        changed = SimpleNamespace(**{**vars(self.item), "severity": "error"})
        self.import_report(raw=b"new report", report=self.report(findings=[changed]))
        finding.refresh_from_db()
        self.assertEqual(finding.status, "accepted_risk")
        self.assertEqual(finding.version, 3)
        self.assertEqual(finding.severity, "error")
        self.assertEqual(FindingObservation.objects.order_by("pk").first().severity, "warning")
        self.assertEqual(FindingObservation.objects.count(), 2)

    def test_absent_result_never_closes_finding_or_implies_remediation(self):
        self.import_report()
        empty, _ = self.import_report(
            raw=b"empty report", report=self.report(findings=[], input_count=0)
        )
        finding = Finding.objects.get()
        self.assertEqual(empty.finding_count, 0)
        self.assertEqual(finding.status, "open")
        self.assertEqual(finding.observations.count(), 1)

    def test_new_scan_invalidates_an_already_open_review_form(self):
        self.import_report()
        finding = Finding.objects.get()
        self.import_report(raw=b"new execution")
        with self.assertRaises(WorkflowError):
            triage(self.users["analyst"], finding.pk, "reviewed", finding.version, "Old evidence.")
        finding.refresh_from_db()
        self.assertEqual(finding.status, "open")
        self.assertEqual(finding.version, 2)

    def test_suppression_is_recorded_without_automatically_deciding(self):
        item = SimpleNamespace(**{**vars(self.item), "suppressed": True})
        self.import_report(report=self.report(findings=[item], suppressed_count=1))
        self.assertTrue(FindingObservation.objects.get().suppressed)
        self.assertEqual(Finding.objects.get().status, "open")

    def test_observation_snapshot_cannot_be_edited_through_save(self):
        self.import_report()
        observation = FindingObservation.objects.get()
        self.assertEqual(observation.snapshot["path"], self.item.path)
        observation.path = "changed.py"
        with self.assertRaises(ValueError):
            observation.save()
        observation.refresh_from_db()
        self.assertEqual(observation.path, self.item.path)

    def test_stale_triage_rejected_and_audit_records_rationale(self):
        self.import_report()
        finding = Finding.objects.get()
        changed = triage(self.users["analyst"], finding.pk, "reviewed", 1, " Checked evidence. ")
        self.assertEqual(changed.version, 2)
        with self.assertRaises(WorkflowError):
            triage(self.users["reviewer"], finding.pk, "false_positive", 1, "Stale view.")
        audit = Audit.objects.get(action="finding.triaged")
        self.assertEqual(audit.detail["rationale"], "Checked evidence.")
        self.assertEqual(audit.detail["previous_status"], "open")
        self.assertEqual(audit.detail["version"], 2)

    def test_triage_scope_role_status_and_rationale_are_enforced(self):
        self.import_report()
        finding = Finding.objects.get()
        for user in (self.users["viewer"], self.outsider):
            with self.assertRaises(PermissionError):
                triage(user, finding.pk, "reviewed", 1, "Test")
        for status, rationale in (("fixed", "Test"), ("reviewed", " "), ("reviewed", "x" * 2001)):
            with self.assertRaises(WorkflowError):
                triage(self.users["analyst"], finding.pk, status, 1, rationale)
        self.assertFalse(Audit.objects.filter(action="finding.triaged").exists())

    def test_size_limit_precedes_parser(self):
        with patch("bridge.findings.parse_report") as parser:
            with self.assertRaises(ValueError):
                import_scan(self.users["analyst"], self.app, b"x" * (MAX_REPORT_BYTES + 1), "sarif")
        parser.assert_not_called()

    def test_local_execution_is_bound_to_source_and_original_report(self):
        execution = dict(
            runner="signalbridge-ruff",
            returncode=1,
            duration_ms=12,
            started_at="2026-09-24T00:00:00+00:00",
            finished_at="2026-09-24T00:00:01+00:00",
            original_digest="b" * 64,
        )
        run, _ = self.import_report(
            source_revision="c" * 40, manifest={"bridge/example.py": "d" * 64}, execution=execution
        )
        self.assertEqual(run.provenance, "local_execution")
        self.assertEqual(run.source_revision, "c" * 40)
        self.assertEqual(run.execution["original_digest"], "b" * 64)
        imported, _ = self.import_report()
        self.assertNotEqual(run.pk, imported.pk)
        self.assertEqual(imported.provenance, "claimed_report")
        with self.assertRaises(WorkflowError):
            self.import_report(execution=execution)
        with self.assertRaises(WorkflowError):
            self.import_report(source_revision="c" * 40)
        with self.assertRaises(WorkflowError):
            self.import_report(
                source_revision="c" * 40, manifest={"../escape.py": "d" * 64}, execution=execution
            )

    def test_transaction_rolls_back_failed_observation(self):
        with patch(
            "bridge.findings.FindingObservation.objects.bulk_create", side_effect=ValueError("test")
        ):
            with self.assertRaises(ValueError):
                self.import_report()
        self.assertFalse(ScanRun.objects.exists())
        self.assertFalse(Finding.objects.exists())
        self.assertFalse(Audit.objects.exists())

    def test_cli_import_has_no_execution_override_and_checks_account(self):
        with patch("pathlib.Path.open", side_effect=lambda *args, **kwargs: BytesIO(b"report")):
            with self.assertRaises(CommandError):
                call_command(
                    "import_scan",
                    self.app.slug,
                    "report.json",
                    format="sarif",
                    user=self.users["viewer"].username,
                )
            with patch("bridge.findings.parse_report", return_value=self.report()):
                call_command(
                    "import_scan",
                    self.app.slug,
                    "report.json",
                    format="sarif",
                    user=self.users["analyst"].username,
                    stdout=StringIO(),
                )
        self.assertEqual(ScanRun.objects.get().provenance, "claimed_report")
