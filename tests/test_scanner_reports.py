"""Adversarial coverage of bounded scanner interoperability, independent of the database."""

import json
from dataclasses import asdict
from unittest import TestCase

from bridge.scanner_reports import MAX_BYTES, ParsedReport, ReportError, parse_report


def encoded(value):
    return json.dumps(value).encode()


def pip_report():
    return {
        "dependencies": [
            {
                "name": "Example_Package",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "CVE-2099-12345",
                        "fix_versions": ["2.0", "1.1", "2.0"],
                        "description": "secret-description-sentinel",
                        "aliases": ["secret-alias-sentinel"],
                    }
                ],
            }
        ],
        "fixes": [],
    }


def sarif_report():
    return {
        "version": "2.1.0",
        "$schema": "https://never-fetch.invalid/schema.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Ruff",
                        "version": "0.16.8",
                        "rules": [{"id": "S603", "defaultConfiguration": {"level": "warning"}}],
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": [
                    {
                        "ruleId": "S603",
                        "message": {"text": "password=secret-message-sentinel"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "bridge/views.py"},
                                    "region": {
                                        "startLine": 12,
                                        "snippet": {"text": "secret-code-sentinel"},
                                    },
                                }
                            }
                        ],
                        "webRequest": {"headers": {"Authorization": "secret-header-sentinel"}},
                    }
                ],
                "artifacts": [{"location": {"uri": "bridge/views.py"}}],
            }
        ],
    }


class ScannerReportTests(TestCase):
    def parse(self, data, format="sarif"):
        return parse_report(encoded(data), format)

    def test_pip_normalizes_dependency_metadata_without_raw_content(self):
        result = self.parse(pip_report(), "pip-audit")
        self.assertIsInstance(result, ParsedReport)
        self.assertEqual((result.tool, result.version, result.input_count), ("pip-audit", "", 1))
        self.assertEqual(result.coverage_status, "complete")
        finding = result.findings[0]
        self.assertEqual(finding.package, "example-package")
        self.assertEqual(finding.package_version, "1.0")
        self.assertEqual(finding.fix_versions, ("1.1", "2.0"))
        self.assertEqual(finding.severity, "unknown")
        self.assertEqual(len(finding.fingerprint), 64)
        self.assertNotIn("sentinel", json.dumps(asdict(result)))

    def test_skipped_dependencies_are_incomplete_even_with_no_findings(self):
        data = {"dependencies": [{"name": "local-package", "skip_reason": "private-source"}]}
        result = self.parse(data, "pip-audit")
        self.assertEqual(result.coverage_status, "incomplete")
        self.assertEqual((result.input_count, result.skipped_count), (1, 1))
        self.assertEqual(result.findings, ())
        self.assertNotIn("private-source", json.dumps(asdict(result)))

    def test_valid_clean_dependency_report_is_distinct_from_empty_input(self):
        result = self.parse(
            {"dependencies": [{"name": "django", "version": "5.2.17", "vulns": []}]},
            "pip-audit",
        )
        self.assertEqual((result.coverage_status, result.findings), ("complete", ()))
        for data in ({"dependencies": []}, {}, [], {"dependencies": [{}]}):
            with self.subTest(data=data), self.assertRaises(ReportError):
                self.parse(data, "pip-audit")

    def test_pip_rejects_missing_vulnerability_fields_and_bad_shapes(self):
        for mutation in (
            lambda dep: dep.pop("vulns"),
            lambda dep: dep.update(vulns={}),
            lambda dep: dep.update(version=None),
            lambda dep: dep["vulns"][0].pop("fix_versions"),
            lambda dep: dep["vulns"][0].update(fix_versions="2.0"),
            lambda dep: dep.update(skip_reason="skipped"),
            lambda dep: dep.update(name="<script>"),
        ):
            data = pip_report()
            mutation(data["dependencies"][0])
            with self.subTest(mutation=mutation), self.assertRaises(ReportError):
                self.parse(data, "pip-audit")

    def test_pip_rejects_duplicate_normalized_packages_and_findings(self):
        data = pip_report()
        data["dependencies"].append({"name": "example-package", "version": "1", "vulns": []})
        with self.assertRaises(ReportError):
            self.parse(data, "pip-audit")
        data = pip_report()
        data["dependencies"][0]["vulns"] *= 2
        with self.assertRaises(ReportError):
            self.parse(data, "pip-audit")

    def test_sarif_retains_fixed_descriptor_and_levels_not_raw_messages(self):
        result = self.parse(sarif_report())
        self.assertEqual((result.tool, result.version, result.input_count), ("Ruff", "0.16.8", 1))
        self.assertEqual(result.coverage_status, "complete")
        finding = result.findings[0]
        self.assertEqual(finding.title, "Ruff reported rule S603")
        self.assertEqual(
            (finding.path, finding.line, finding.severity), ("bridge/views.py", 12, "warning")
        )
        self.assertNotIn("sentinel", json.dumps(asdict(result)))
        self.assertNotIn("never-fetch", json.dumps(asdict(result)))

    def test_paths_normalize_and_fingerprint_changes_with_location(self):
        data = sarif_report()
        finding = self.parse(data).findings[0]
        location = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        location["artifactLocation"]["uri"] = ".\\bridge\\views.py"
        normalized = self.parse(data).findings[0]
        self.assertEqual(normalized.fingerprint, finding.fingerprint)
        location["region"]["startLine"] = 13
        self.assertNotEqual(self.parse(data).findings[0].fingerprint, finding.fingerprint)

    def test_fingerprint_distinguishes_package_version(self):
        data = pip_report()
        old = self.parse(data, "pip-audit").findings[0].fingerprint
        data["dependencies"][0]["version"] = "1.1"
        self.assertNotEqual(old, self.parse(data, "pip-audit").findings[0].fingerprint)

    def test_sarif_failed_unknown_and_notification_coverage(self):
        data = sarif_report()
        run = data["runs"][0]
        run["results"] = []
        run["invocations"] = [{"executionSuccessful": False}]
        self.assertEqual(self.parse(data).coverage_status, "failed")
        run.pop("invocations")
        self.assertEqual(self.parse(data).coverage_status, "unknown")
        run["invocations"] = [
            {"executionSuccessful": True, "toolExecutionNotifications": [{"level": "warning"}]}
        ]
        self.assertEqual(self.parse(data).coverage_status, "incomplete")
        run["invocations"] = [{"executionSuccessful": True}]
        self.assertEqual(self.parse(data).coverage_status, "complete")
        run["invocations"] = [{"exitCode": 0}]
        with self.assertRaises(ReportError):
            self.parse(data)

    def test_suppression_metadata_is_visible_without_justification(self):
        data = sarif_report()
        finding = data["runs"][0]["results"][0]
        finding["suppressions"] = [
            {"kind": "inSource", "status": "accepted", "justification": "secret-sentinel"},
            {"kind": "external", "status": "underReview"},
        ]
        report = self.parse(data)
        self.assertEqual(report.suppressed_count, 1)
        self.assertTrue(report.findings[0].suppressed)
        self.assertEqual(report.findings[0].suppression_statuses, ("accepted", "underReview"))
        self.assertNotIn("secret-sentinel", json.dumps(asdict(report)))
        finding["suppressions"] = [{"kind": "external", "status": "rejected"}]
        self.assertFalse(self.parse(data).findings[0].suppressed)

    def test_sarif_default_and_explicit_levels(self):
        data = sarif_report()
        driver = data["runs"][0]["tool"]["driver"]
        driver["rules"][0]["defaultConfiguration"]["level"] = "note"
        self.assertEqual(self.parse(data).findings[0].severity, "note")
        data["runs"][0]["results"][0]["level"] = "error"
        self.assertEqual(self.parse(data).findings[0].severity, "error")
        data["runs"][0]["results"][0]["level"] = "critical"
        with self.assertRaises(ReportError):
            self.parse(data)

    def test_sarif_rejects_unsafe_artifact_locations(self):
        for path in (
            "/etc/passwd",
            "C:/Users/person/file.py",
            "C:relative.py",
            "\\\\server\\share\\file.py",
            "file:///C:/file.py",
            "https://example.test/file.py",
            "../secret.py",
            "bridge/../secret.py",
            "%2e%2e/secret.py",
            "%252e%252e/secret.py",
            "x.py?token=secret",
            "x.py#fragment",
            "x\u0000.py",
            "x\u202e.py",
            "x" * 501,
            ".",
        ):
            data = sarif_report()
            artifact = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                "artifactLocation"
            ]
            artifact["uri"] = path
            with self.subTest(path=path), self.assertRaises(ReportError):
                self.parse(data)

    def test_sarif_rejects_unsupported_or_incomplete_reports(self):
        for mutation in (
            lambda data: data.update(version="2.0.0"),
            lambda data: data.update(runs=[]),
            lambda data: data["runs"].append(data["runs"][0]),
            lambda data: data["runs"][0].pop("results"),
            lambda data: data["runs"][0].update(externalPropertyFileReferences={}),
            lambda data: data.update(inlineExternalProperties=[]),
            lambda data: data["runs"][0]["results"][0].pop("ruleId"),
            lambda data: data["runs"][0]["results"][0].update(rule={"index": 1}),
            lambda data: data["runs"][0]["results"][0].update(message={"markdown": "**x**"}),
        ):
            data = sarif_report()
            mutation(data)
            with self.subTest(mutation=mutation), self.assertRaises(ReportError):
                self.parse(data)

    def test_sarif_rejects_indexed_locations_bad_lines_and_duplicate_results(self):
        data = sarif_report()
        physical = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        physical["artifactLocation"]["index"] = 1
        with self.assertRaises(ReportError):
            self.parse(data)
        physical["artifactLocation"].pop("index")
        for line in (True, "12", 0, -1, 10000001):
            physical["region"]["startLine"] = line
            with self.subTest(line=line), self.assertRaises(ReportError):
                self.parse(data)
        data = sarif_report()
        data["runs"][0]["results"] *= 2
        with self.assertRaises(ReportError):
            self.parse(data)

    def test_json_rejects_duplicates_nonfinite_invalid_encoding_and_wrong_format(self):
        for raw in (
            b'{"dependencies": [], "dependencies": []}',
            b'{"ignored":{"x":1,"x":2}}',
            b'{"ignored": NaN}',
            b'{"ignored": Infinity}',
            b'{"ignored": 1e9999}',
            b"\xff",
            b"{",
            b"[]",
        ):
            with self.subTest(raw=raw), self.assertRaises(ReportError):
                parse_report(raw, "pip-audit")
        with self.assertRaises(ReportError):
            parse_report(encoded(pip_report()), "unknown")

    def test_json_rejects_size_depth_and_finding_overflow(self):
        with self.assertRaises(ReportError):
            parse_report(b" " * (MAX_BYTES + 1), "pip-audit")
        with self.assertRaises(ReportError):
            parse_report(b"[" * 33 + b"0" + b"]" * 33, "pip-audit")
        data = pip_report()
        data["dependencies"][0]["vulns"] = [
            {"id": f"CVE-2099-{index}", "fix_versions": []} for index in range(2001)
        ]
        with self.assertRaises(ReportError):
            self.parse(data, "pip-audit")
        data = sarif_report()
        data["runs"][0]["results"] *= 2001
        with self.assertRaises(ReportError):
            self.parse(data)

    def test_json_quoted_brackets_do_not_count_as_depth(self):
        data = pip_report()
        data["description"] = "[" * 100 + '\\"' + "]" * 100
        self.assertEqual(len(self.parse(data, "pip-audit").findings), 1)

    def test_errors_do_not_echo_untrusted_values(self):
        data = pip_report()
        data["dependencies"][0]["name"] = "password=secret-error-sentinel"
        with self.assertRaises(ReportError) as caught:
            self.parse(data, "pip-audit")
        self.assertNotIn("sentinel", str(caught.exception))

    def test_sarif_does_not_promote_security_properties_to_scanner_level(self):
        data = sarif_report()
        result = data["runs"][0]["results"][0]
        result["properties"] = {"security-severity": "10.0", "secret": "sentinel"}
        report = self.parse(data)
        self.assertEqual(report.findings[0].severity, "warning")
        self.assertNotIn("10.0", json.dumps(asdict(report)))

    def test_sarif_passes_and_absent_baseline_tombstones_are_not_current_findings(self):
        for key, value in (
            ("kind", "pass"),
            ("kind", "notApplicable"),
            ("baselineState", "absent"),
            ("baselineState", "invalid"),
        ):
            data = sarif_report()
            data["runs"][0]["results"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ReportError):
                self.parse(data)

    def test_failed_invocation_cannot_hide_malformed_later_invocations(self):
        data = sarif_report()
        data["runs"][0]["invocations"] = [{"executionSuccessful": False}, {}]
        with self.assertRaises(ReportError):
            self.parse(data)

    def test_report_fields_respect_persistence_limits(self):
        data = pip_report()
        data["dependencies"][0]["version"] = "1" * 101
        with self.assertRaises(ReportError):
            self.parse(data, "pip-audit")
        data = sarif_report()
        data["runs"][0]["tool"]["driver"]["version"] = "1" * 81
        with self.assertRaises(ReportError):
            self.parse(data)
