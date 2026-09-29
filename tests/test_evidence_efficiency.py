"""Batched evidence writes preserve authorization, immutable facts and atomicity."""

import copy
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, connection
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from bridge.findings import import_scan
from bridge.models import Audit, Finding, FindingObservation, Integration, Membership, ScanRun
from bridge.scanner_reports import parse_report
from tests.test_scanner_reports import encoded, sarif_report


def many_findings(count=40, severity="warning"):
    report = sarif_report()
    original = report["runs"][0]["results"][0]
    rows = []
    for index in range(count):
        row = copy.deepcopy(original)
        row["locations"][0]["physicalLocation"]["region"]["startLine"] = index + 1
        row["level"] = severity
        if index % 2:
            row["suppressions"] = [{"kind": "external", "status": "underReview"}]
        rows.append(row)
    report["runs"][0]["results"] = rows
    return encoded(report)


class EvidenceWriteEfficiencyTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="evidence-efficiency", name="Evidence")
        cls.user = get_user_model().objects.create_user(username="evidence-efficiency-operator")
        Membership.objects.create(user=cls.user, integration=cls.app, role="analyst")

    def add(self, raw=None):
        return import_scan(self.user, self.app, raw or many_findings(), "sarif")

    def test_observation_inserts_are_batched_with_every_fact_preserved(self):
        raw = many_findings()
        expected = parse_report(raw, "sarif")
        with CaptureQueriesContext(connection) as queries:
            run, created = self.add(raw)
        inserts = [
            row["sql"]
            for row in queries
            if row["sql"].startswith('INSERT INTO "bridge_findingobservation"')
        ]
        self.assertEqual(
            len(inserts),
            1,
            f"40 observations used {len(inserts)} INSERTs; {len(queries)} total SQL",
        )
        self.assertTrue(created)
        self.assertEqual(run.finding_count, 40)
        actual = list(run.observations.order_by("line"))
        for observation, finding in zip(actual, expected.findings, strict=True):
            self.assertEqual(
                observation.snapshot,
                {
                    key: list(getattr(finding, key))
                    if key in ("fix_versions", "suppression_statuses")
                    else getattr(finding, key)
                    for key in observation.snapshot
                },
            )
        self.assertNotIn("sentinel", str([row.snapshot for row in actual]))

    def test_repeat_import_does_not_write_or_change_review_versions(self):
        run, _ = self.add()
        before = list(Finding.objects.order_by("pk").values_list("pk", "version"))
        with CaptureQueriesContext(connection) as queries:
            repeated, created = self.add()
        self.assertEqual(repeated.pk, run.pk)
        self.assertFalse(created)
        self.assertFalse(
            any(row["sql"].startswith(("INSERT", "UPDATE", "DELETE")) for row in queries)
        )
        self.assertEqual(before, list(Finding.objects.order_by("pk").values_list("pk", "version")))
        self.assertEqual(FindingObservation.objects.count(), 40)

    def test_larger_report_spans_bounded_batches_without_dropping_observations(self):
        with CaptureQueriesContext(connection) as queries:
            run, _ = self.add(many_findings(count=205))
        inserts = [
            row["sql"]
            for row in queries
            if row["sql"].startswith('INSERT INTO "bridge_findingobservation"')
        ]
        self.assertLessEqual(len(inserts), 4)
        self.assertEqual(run.observations.count(), 205)
        self.assertEqual(run.observations.values("finding_id").distinct().count(), 205)

    def test_changed_report_preserves_prior_facts_and_advances_each_version_once(self):
        prior, _ = self.add()
        changed, _ = self.add(many_findings(severity="error"))
        self.assertEqual(set(prior.observations.values_list("severity", flat=True)), {"warning"})
        self.assertEqual(set(changed.observations.values_list("severity", flat=True)), {"error"})
        self.assertEqual(set(Finding.objects.values_list("version", flat=True)), {2})
        self.assertEqual(Finding.objects.count(), 40)

    def test_membership_revoked_during_parse_prevents_every_import_write(self):
        def revoke(raw, format):
            result = parse_report(raw, format)
            Membership.objects.filter(user=self.user, integration=self.app).delete()
            return result

        with patch("bridge.findings.parse_report", side_effect=revoke):
            with self.assertRaises(PermissionError):
                self.add()
        self.assertFalse(ScanRun.objects.exists())
        self.assertFalse(Finding.objects.exists())
        self.assertFalse(FindingObservation.objects.exists())
        self.assertFalse(Audit.objects.exists())

    def test_operator_disabled_in_database_during_parse_is_not_authorized_by_stale_object(self):
        def disable(raw, format):
            result = parse_report(raw, format)
            get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
            return result

        with patch("bridge.findings.parse_report", side_effect=disable):
            with self.assertRaises(PermissionError):
                self.add()
        self.assertFalse(ScanRun.objects.exists())
        self.assertFalse(Audit.objects.exists())

    def test_observation_batch_failure_rolls_back_findings_run_and_audit(self):
        with patch.object(
            FindingObservation.objects, "bulk_create", side_effect=IntegrityError("test failure")
        ):
            with self.assertRaises(IntegrityError):
                self.add()
        for model in (Finding, FindingObservation, ScanRun, Audit):
            self.assertFalse(model.objects.exists())

    def test_failed_new_observations_do_not_advance_existing_evidence_or_versions(self):
        first, _ = self.add(many_findings(count=3))
        with patch.object(
            FindingObservation.objects, "bulk_create", side_effect=IntegrityError("test failure")
        ):
            with self.assertRaises(IntegrityError):
                self.add(many_findings(count=3, severity="error"))
        self.assertEqual(ScanRun.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="scan.imported").count(), 1)
        self.assertEqual(Finding.objects.count(), 3)
        self.assertEqual(set(Finding.objects.values_list("version", flat=True)), {1})
        self.assertEqual(set(Finding.objects.values_list("severity", flat=True)), {"warning"})
        self.assertEqual(first.observations.count(), 3)


class AssuranceLocalBoundaryTests(SimpleTestCase):
    @override_settings(LOCAL=False)
    def test_nonlocal_assurance_import_fails_before_artifact_reads_even_in_dry_run(self):
        with patch("bridge.management.commands.import_assurance.load_assurance") as loader:
            for dry_run in (False, True):
                with self.subTest(dry_run=dry_run), self.assertRaisesRegex(CommandError, "local"):
                    call_command(
                        "import_assurance",
                        run_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                        dry_run=dry_run,
                        stdout=StringIO(),
                    )
            loader.assert_not_called()
