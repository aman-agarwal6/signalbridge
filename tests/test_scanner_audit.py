"""Adversarial scanner audit regressions; synthetic reports and a disposable database only."""

import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from bridge.findings import _provenance, evidence_binding, import_scan, triage
from bridge.models import Audit, Finding, FindingObservation, Integration, Membership, ScanRun
from bridge.scan_views import attach_evidence
from bridge.scanner_guidance import guidance
from bridge.scanner_reports import ReportError, parse_report
from bridge.services import WorkflowError
from tests.test_scanner_reports import pip_report, sarif_report


def encoded(data):
    return json.dumps(data).encode()


def execution(runner="signalbridge-ruff"):
    return {
        "runner": runner,
        "returncode": 1,
        "duration_ms": 10,
        "started_at": "2026-09-24T00:00:00+00:00",
        "finished_at": "2026-09-24T00:00:01+00:00",
        "original_digest": "c" * 64,
    }


class ScannerParserAuditTests(SimpleTestCase):
    def test_maximum_dependency_identifiers_cannot_overflow_stored_title(self):
        data = pip_report()
        data["dependencies"][0]["name"] = "p" * 128
        data["dependencies"][0]["vulns"][0]["id"] = "A" * 128
        item = parse_report(encoded(data), "pip-audit").findings[0]
        self.assertLessEqual(len(item.title), 240)
        self.assertEqual(item.package, "p" * 128)
        self.assertEqual(item.rule_id, "A" * 128)

    def test_conflicting_or_invalid_sarif_rule_index_fails_instead_of_misattribution(self):
        data = sarif_report()
        result = data["runs"][0]["results"][0]
        result["ruleIndex"] = 0
        self.assertEqual(parse_report(encoded(data), "sarif").findings[0].rule_id, "S603")
        for index in (True, -1, 1, "0"):
            result["ruleIndex"] = index
            with self.subTest(index=index), self.assertRaises(ReportError):
                parse_report(encoded(data), "sarif")
        result["ruleIndex"] = 0
        result["ruleId"] = "S104"
        with self.assertRaises(ReportError):
            parse_report(encoded(data), "sarif")

    def test_unresolved_artifact_base_is_rejected_without_fetching_or_reading(self):
        data = sarif_report()
        artifact = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]
        artifact["uriBaseId"] = "ROOT"
        data["runs"][0]["originalUriBaseIds"] = {"ROOT": {"uri": "https://untrusted.invalid/"}}
        with patch("pathlib.Path.read_bytes") as read, self.assertRaises(ReportError):
            parse_report(encoded(data), "sarif")
        read.assert_not_called()

    def test_nonstandard_revision_lengths_and_ambiguous_manifest_paths_are_rejected(self):
        for length in (39, 41, 48, 63, 65):
            with self.subTest(length=length), self.assertRaises(WorkflowError):
                _provenance("a" * length, {"bridge/views.py": "b" * 64}, execution())
        for path in (
            "a//b.py",
            "a/",
            "a/./b.py",
            "a/%62.py",
            "a/b.py?x",
            "a/b.py#x",
            "a/\u202e.py",
        ):
            with self.subTest(path=path), self.assertRaises(WorkflowError):
                _provenance("a" * 40, {path: "b" * 64}, execution())
        for length in (40, 64):
            self.assertEqual(
                _provenance("a" * length, {"bridge/views.py": "b" * 64}, execution())[0],
                "local_execution",
            )

    def test_rule_guidance_is_curated_and_never_uses_imported_links_or_messages(self):
        data = sarif_report()
        data["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"] = "https://untrusted.invalid/"
        item = parse_report(encoded(data), "sarif").findings[0]
        # Parsed findings do not carry a tool name; the model's tool is a separate field.
        from types import SimpleNamespace

        advice = guidance(SimpleNamespace(tool="Ruff", rule_id=item.rule_id))
        self.assertTrue(advice["url"].startswith("https://docs.astral.sh/ruff/rules/"))
        self.assertNotIn("untrusted.invalid", json.dumps(advice))
        for field in ("why", "validate", "remediation", "unknowns", "level_label"):
            self.assertTrue(advice[field])


class ScannerEvidenceAuditTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(
            slug="scanner-audit", name="Scanner audit", enabled=False
        )
        cls.other = Integration.objects.create(slug="scanner-other", name="Other", enabled=False)
        cls.author = get_user_model().objects.create_user(username="scanner-audit-author")
        Membership.objects.create(user=cls.author, integration=cls.app, role="analyst")
        Membership.objects.create(user=cls.author, integration=cls.other, role="analyst")

    def setUp(self):
        self.client.force_login(self.author)

    def add(self, data=None, app=None, local=False, **overrides):
        options = (
            {
                "source_revision": "a" * 40,
                "manifest": {"bridge/views.py": "b" * 64},
                "execution": execution(),
            }
            if local
            else {}
        )
        options.update(overrides)
        return import_scan(
            self.author, app or self.app, encoded(data or sarif_report()), "sarif", **options
        )[0]

    def item(self):
        return Finding.objects.get(integration=self.app)

    def detail(self, item=None):
        item = item or self.item()
        return self.client.get(f"/findings/{item.pk}/?app={self.app.slug}")

    def test_review_binds_exact_immutable_observation_and_source_evidence(self):
        run = self.add(local=True)
        item = self.item()
        observation = item.observations.get()
        triage(self.author, item.pk, "accepted_risk", item.version, "Validated in synthetic scope.")
        audit = Audit.objects.get(action="finding.triaged")
        self.assertEqual(audit.detail["evidence"], evidence_binding(observation))
        self.assertEqual(audit.detail["finding_version_reviewed"], 1)
        self.assertEqual(audit.detail["evidence"]["source_file_digest"], "b" * 64)
        self.assertEqual(audit.detail["evidence"]["report_digest"], run.digest)
        self.assertFalse(audit.detail["evidence"]["current_source_checked"])
        self.assertNotIn("secret-message-sentinel", json.dumps(audit.detail))
        self.assertContains(self.detail(), "Latest observation reviewed")

    def test_new_evidence_marks_review_stale_without_rewriting_the_prior_decision(self):
        self.add()
        item = self.item()
        triage(
            self.author, item.pk, "false_positive", item.version, "First observed source reviewed."
        )
        prior = Audit.objects.get(action="finding.triaged").detail
        changed = sarif_report()
        changed["runs"][0]["results"][0]["level"] = "error"
        self.add(changed)
        item.refresh_from_db()
        self.assertEqual(item.status, "false_positive")
        self.assertEqual(Audit.objects.get(action="finding.triaged").detail, prior)
        self.assertContains(self.detail(), "New evidence needs review")
        self.assertContains(
            self.client.get(f"/findings/?app={self.app.slug}"), "New evidence needs review"
        )
        triage(self.author, item.pk, "reviewed", item.version, "New observation inspected.")
        self.assertContains(self.detail(), "Latest observation reviewed")

    def test_legacy_review_is_not_retroactively_given_an_evidence_binding(self):
        self.add()
        item = self.item()
        Audit.objects.create(
            integration=self.app,
            actor=self.author,
            action="finding.triaged",
            object_id=str(item.pk),
            detail={"status": "reviewed", "rationale": "Earlier review"},
        )
        response = self.detail()
        self.assertContains(response, "Earlier review not bound")
        self.assertFalse(response.context["finding"].review["current"])

    def test_later_absent_result_is_not_a_fix_or_an_implicit_review(self):
        self.add()
        item = self.item()
        triage(self.author, item.pk, "reviewed", item.version, "Recorded assessment.")
        clean = sarif_report()
        clean["runs"][0]["results"] = []
        self.add(clean)
        response = self.detail()
        self.assertTrue(response.context["newer_report"])
        self.assertContains(response, "Its absence does not establish a correction")
        item.refresh_from_db()
        self.assertEqual(item.status, "reviewed")

    def test_cross_application_audit_and_observation_cannot_poison_latest_evidence(self):
        run = self.add()
        item = self.item()
        foreign = self.add(app=self.other)
        original = item.observations.get()
        FindingObservation.objects.create(
            scan_run=foreign,
            finding=item,
            **{
                name: getattr(original, name)
                for name in ("severity", "rule_id", "title", "path", "line")
            },
        )
        Audit.objects.create(
            integration=self.other,
            actor=self.author,
            action="finding.triaged",
            object_id=str(item.pk),
            detail={"rationale": "foreign-sentinel", "status": "accepted_risk"},
        )
        response = self.detail()
        self.assertEqual(response.context["finding"].evidence["run_id"], str(run.pk))
        self.assertNotContains(response, "foreign-sentinel")
        self.assertNotContains(response, str(foreign.pk))

    def test_finding_without_an_observation_cannot_be_reviewed(self):
        item = Finding.objects.create(
            integration=self.app,
            tool="Ruff",
            fingerprint="f" * 64,
            severity="warning",
            rule_id="S603",
            title="Synthetic orphan",
        )
        with self.assertRaisesRegex(WorkflowError, "recorded observation"):
            triage(self.author, item.pk, "reviewed", 1, "No evidence exists.")
        self.assertFalse(Audit.objects.filter(action="finding.triaged").exists())

    def test_inactive_operator_cannot_import_or_triage_with_a_retained_membership(self):
        self.add()
        item = self.item()
        self.author.is_active = False
        with self.assertRaises(PermissionError):
            self.add()
        with self.assertRaises(PermissionError):
            triage(self.author, item.pk, "reviewed", 1, "Inactive operator.")
        self.assertEqual(ScanRun.objects.count(), 1)

    def test_local_runner_tool_format_and_manifest_membership_fail_closed(self):
        for data, options in (
            (sarif_report(), {"manifest": {"other.py": "b" * 64}}),
            (sarif_report(), {"execution": execution("signalbridge-pip-audit")}),
        ):
            with self.subTest(options=options), self.assertRaises(WorkflowError):
                self.add(data, local=True, **options)
        data = sarif_report()
        data["runs"][0]["tool"]["driver"]["name"] = "OtherScanner"
        with self.assertRaises(WorkflowError):
            self.add(data, local=True)
        data = sarif_report()
        data["runs"][0]["results"][0]["locations"] = []
        with self.assertRaises(WorkflowError):
            self.add(data, local=True)
        self.assertFalse(ScanRun.objects.exists())

    def test_dependency_local_evidence_requires_the_fixed_input_manifest(self):
        with self.assertRaises(WorkflowError):
            import_scan(
                self.author,
                self.app,
                encoded(pip_report()),
                "pip-audit",
                source_revision="a" * 40,
                manifest={"unrelated.txt": "b" * 64},
                execution=execution("signalbridge-pip-audit"),
            )
        self.assertFalse(ScanRun.objects.exists())

    def test_detail_teaches_validation_without_inventing_severity_confidence_or_currentness(self):
        self.add(local=True)
        with patch("pathlib.Path.read_bytes", side_effect=AssertionError("No live source reads")):
            response = self.detail()
        for text in (
            "Why this was flagged",
            "What the evidence establishes",
            "How to validate",
            "Remediation and retest",
            "What remains unknown",
            "Current checkout not compared",
            "Not assessed by this scanner workbench",
            "RECORDED FILE SHA-256",
            "b" * 64,
        ):
            self.assertContains(response, text)
        self.assertNotContains(response, "secret-message-sentinel")
        self.assertNotContains(response, "secret-code-sentinel")

    def test_imported_evidence_has_no_claimed_file_hash_or_local_execution(self):
        self.add()
        response = self.detail()
        self.assertContains(response, "Unverified imported claim")
        self.assertContains(response, "No source-file hash is bound to this observation")
        self.assertEqual(response.context["finding"].evidence["source_file_digest"], "")

    def test_zero_advisory_history_exposes_counted_scope_and_does_not_claim_all_dependencies(self):
        data = {"dependencies": [{"name": "example", "version": "1.0", "vulns": []}]}
        run, _ = import_scan(
            self.author,
            self.app,
            encoded(data),
            "pip-audit",
            source_revision="a" * 40,
            manifest={"requirements.txt": "b" * 64},
            execution=execution("signalbridge-pip-audit"),
        )
        response = self.client.get(f"/scans/?app={self.app.slug}")
        self.assertContains(response, "1 explicit dependency entries")
        self.assertContains(response, "transitive, development, npm and deployed dependencies")
        exported = self.client.get(f"/scans/{run.pk}/export/?app={self.app.slug}").json()
        self.assertIn("Current checkout not compared", exported["scope_explanation"]["currentness"])

    def test_latest_evidence_queries_are_bounded_per_page_and_scoped(self):
        self.add()
        data = sarif_report()
        data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] = (
            13
        )
        self.add(data)
        records = list(Finding.objects.filter(integration=self.app))
        with self.assertNumQueries(2):
            enriched = attach_evidence(records, self.app)
        self.assertEqual(len(enriched), 2)
        self.assertTrue(all(item.evidence["available"] for item in enriched))

    def test_suppression_remains_visible_and_separate_from_review(self):
        data = sarif_report()
        data["runs"][0]["results"][0]["suppressions"] = [{"kind": "external", "status": "accepted"}]
        self.add(data)
        response = self.detail()
        self.assertContains(response, "Suppressed in the latest source report")
        self.assertContains(response, "Not reviewed")
        self.assertEqual(self.item().status, "open")
