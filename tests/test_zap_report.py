"""Offline denial tests for the fixed-target ZAP metadata boundary; no scanner runtime."""

import copy
import json
import threading
from contextlib import nullcontext
from dataclasses import asdict
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

from bridge.scanner_reports import MAX_BYTES, ParsedReport, ReportError
from bridge.zap_report import (
    APPROVED_PATHS,
    MAX_ALERTS,
    MAX_INSTANCES_PER_ALERT,
    MAX_TEXT,
    TARGET_ORIGIN,
    TARGET_PROFILE,
    parse_zap_report,
)
from integrations.zap import contract, run_passive


def fixture():
    return {
        "@programName": "ZAP",
        "@version": "2.17.0",
        "@generated": "synthetic-time",
        "created": "synthetic-time",
        "sequences": [],
        "site": [
            {
                "@name": TARGET_ORIGIN,
                "@host": "signalbridge-zap-target",
                "@port": "8000",
                "@ssl": "false",
                "alerts": [
                    {
                        "pluginid": "10020",
                        "alertRef": "10020-1",
                        "riskcode": "2",
                        "confidence": "2",
                        "alert": "untrusted-title-sentinel",
                        "desc": "<script>private-description-sentinel</script>",
                        "solution": "private-solution-sentinel",
                        "reference": "https://external.invalid/private-reference-sentinel",
                        "tags": {"private-tag-sentinel": "private-value-sentinel"},
                        "instances": [
                            {
                                "id": "1",
                                "uri": TARGET_ORIGIN + "/login/",
                                "method": "GET",
                                "param": "private-cookie-name-sentinel",
                                "attack": "private-attack-sentinel",
                                "evidence": "private-cookie-value-sentinel",
                                "otherinfo": "private-context-sentinel",
                                "request-header": "GET /login/ HTTP/1.1\r\nCookie: private-sentinel\r\n",
                                "request-body": "private-request-sentinel",
                                "response-header": "HTTP/1.1 200 OK\r\nSet-Cookie: private-sentinel\r\n",
                                "response-body": "private-response-sentinel",
                            }
                        ],
                        "count": "1",
                    }
                ],
            }
        ],
    }


class ZapReportTests(TestCase):
    def parse(self, data):
        return parse_zap_report(json.dumps(data).encode())

    def assert_rejected(self, data, pattern=None):
        with self.assertRaises(ReportError) as raised:
            self.parse(data)
        self.assertNotIn("sentinel", str(raised.exception))
        if pattern:
            self.assertRegex(str(raised.exception), pattern)

    def test_metadata_contract_never_retains_raw_http_or_evidence(self):
        report = self.parse(fixture())
        self.assertIsInstance(report, ParsedReport)
        self.assertEqual((report.format, report.tool, report.version), ("zap", "ZAP", "2.17.0"))
        self.assertEqual((report.coverage_status, report.input_count), ("unknown", 0))
        finding = report.findings[0]
        self.assertEqual(finding.rule_id, "10020-1")
        self.assertEqual(finding.severity, "medium")
        self.assertEqual(
            finding.title, "ZAP reported rule 10020-1 on GET /login/ (reported confidence: medium)"
        )
        self.assertEqual((finding.path, finding.line, finding.package), ("", None, ""))
        self.assertEqual(len(finding.fingerprint), 64)
        self.assertFalse(finding.suppressed)
        rendered = json.dumps(asdict(report))
        self.assertNotIn("sentinel", rendered)
        self.assertNotIn("http", rendered)
        self.assertNotIn("Set-Cookie", rendered)

    def test_no_alerts_is_unknown_coverage_not_a_completed_clean_scan(self):
        data = fixture()
        data["site"][0]["alerts"] = []
        report = self.parse(data)
        self.assertEqual(report.findings, ())
        self.assertEqual(report.coverage_status, "unknown")
        self.assertEqual(report.input_count, 0)

    def test_supplied_execution_source_success_and_suppression_claims_are_refused(self):
        for name, value in (
            ("execution_verified", True),
            ("coverage_status", "complete"),
            ("provenance", "local_execution"),
            ("source_revision", "a" * 40),
            ("success", True),
            ("sequences", [{}]),
            ("redirects", []),
        ):
            with self.subTest(name=name):
                data = fixture()
                data[name] = value
                self.assert_rejected(data)
        data = fixture()
        data["site"][0]["alerts"][0]["suppressed"] = True
        self.assert_rejected(data)

    def test_optional_traditional_report_metadata_is_validated_and_not_retained(self):
        data = fixture()
        expected = self.parse(data)
        del data["@programName"]
        del data["sequences"]
        del data["site"][0]["alerts"][0]["instances"][0]["id"]
        self.assertEqual(self.parse(data), expected)
        self.assertNotIn("@programName", json.dumps(asdict(expected)))
        self.assertNotIn("sequences", json.dumps(asdict(expected)))

    def test_sequences_are_never_accepted_by_the_fixed_anonymous_profile(self):
        for sequence in ([{}], ["private-sentinel"], {}, None, "", 0, False):
            data = fixture()
            data["sequences"] = sequence
            with self.subTest(sequence=sequence):
                self.assert_rejected(data)

    def test_report_program_name_is_exact_and_bounded_when_present(self):
        for name in ("Other", "ZAP\n", "private-sentinel", "x" * 33, {}, None, True):
            data = fixture()
            data["@programName"] = name
            with self.subTest(name=name):
                self.assert_rejected(data)

    def test_instance_id_must_be_a_bounded_positive_decimal_string(self):
        for identifier in (
            "0",
            "01",
            "-1",
            " 1",
            "1\n",
            "1" * 10,
            "private-sentinel",
            1,
            True,
            None,
            {},
        ):
            data = fixture()
            data["site"][0]["alerts"][0]["instances"][0]["id"] = identifier
            with self.subTest(identifier=identifier):
                self.assert_rejected(data)
        data = fixture()
        data["site"][0]["alerts"][0]["instances"][0]["id"] = "999999999"
        self.assertEqual(self.parse(data), self.parse(fixture()))

    def test_all_fixed_get_endpoints_have_distinct_stable_fingerprints(self):
        data = fixture()
        alert = data["site"][0]["alerts"][0]
        alert["instances"] = [
            {"uri": TARGET_ORIGIN + path, "method": "GET"} for path in ("/", "/login/", "/health/")
        ]
        alert["count"] = "3"
        first = self.parse(data)
        self.assertEqual(len({item.fingerprint for item in first.findings}), 3)
        alert["instances"].reverse()
        alert["desc"] = "changed-private-sentinel"
        self.assertEqual(first, self.parse(data))

    def test_same_endpoint_cookie_instances_consolidate_without_hiding_invalid_instances(self):
        data = fixture()
        alert = data["site"][0]["alerts"][0]
        alert["instances"].append(copy.deepcopy(alert["instances"][0]))
        alert["instances"][1]["param"] = "second-cookie-sentinel"
        alert["count"] = "2"
        self.assertEqual(len(self.parse(data).findings), 1)
        alert["instances"][1]["uri"] = "https://external.invalid/"
        self.assert_rejected(data)

    def test_false_positive_or_confirmed_confidence_remain_unreviewed_tool_claims(self):
        for confidence, label in (("0", "false positive"), ("4", "confirmed")):
            with self.subTest(confidence=confidence):
                data = fixture()
                data["site"][0]["alerts"][0]["confidence"] = confidence
                report = self.parse(data)
                self.assertIn(f"reported confidence: {label}", report.findings[0].title)
                self.assertFalse(report.findings[0].suppressed)
                self.assertEqual(report.suppressed_count, 0)
                self.assertEqual(report.coverage_status, "unknown")

    def test_site_identity_cannot_alias_a_host_console_public_or_sibling_target(self):
        for name, value in (
            ("@name", "http://127.0.0.1:8741"),
            ("@name", TARGET_ORIGIN + "/"),
            ("@host", "bettail"),
            ("@port", "8741"),
            ("@ssl", "true"),
            ("@port", 8000),
            ("@ssl", False),
        ):
            with self.subTest(name=name, value=value):
                data = fixture()
                data["site"][0][name] = value
                self.assert_rejected(data)

    def test_instance_url_requires_exact_origin_and_path_without_normalization(self):
        for url in (
            "http://127.0.0.1:8741/login/",
            "https://public.invalid/",
            "/login/",
            TARGET_ORIGIN + "/private-sentinel/",
            TARGET_ORIGIN + "/login/?token=private-sentinel",
            TARGET_ORIGIN + "/login/#private-sentinel",
            TARGET_ORIGIN + "/login/../health/",
            TARGET_ORIGIN + "/%6cogin/",
            TARGET_ORIGIN + "/login/%2e%2e/health/",
            TARGET_ORIGIN + "//login/",
            TARGET_ORIGIN.upper() + "/login/",
            "http://private-sentinel@signalbridge-zap-target:8000/login/",
            "http://signalbridge-zap-target:8000.evil.invalid/login/",
            "http://signalbridge-zap-target.:8000/login/",
            TARGET_ORIGIN + "/login/\n",
            "http://signalbridge-zap-target:08000/login/",
            TARGET_ORIGIN + "\\login\\",
            None,
            [],
        ):
            with self.subTest(url=url):
                data = fixture()
                data["site"][0]["alerts"][0]["instances"][0]["uri"] = url
                self.assert_rejected(data)

    def test_only_get_is_accepted_even_on_the_correct_target(self):
        for method in ("POST", "DELETE", "HEAD", "get", "GET\r\nprivate-sentinel", None):
            with self.subTest(method=method):
                data = fixture()
                data["site"][0]["alerts"][0]["instances"][0]["method"] = method
                self.assert_rejected(data)

    def test_explicit_redirect_headers_and_fields_fail_without_printing_destinations(self):
        for header in (
            "HTTP/1.1 302 Found\r\nLocation: https://private-sentinel.invalid/\r\n",
            "HTTP/2 307\r\nlocation: /login/\r\n",
            "HTTP/1.1 200 OK\r\n LOCATION : https://private-sentinel.invalid/\r\n",
            "HTTP/1.1 304 Not Modified\r\n",
            "invalid-private-sentinel",
        ):
            with self.subTest(header=header):
                data = fixture()
                data["site"][0]["alerts"][0]["instances"][0]["response-header"] = header
                self.assert_rejected(data)
        for key in ("redirect", "redirects", "redirect_uri", "location", "responseHeader"):
            data = fixture()
            data["site"][0]["alerts"][0]["instances"][0][key] = "private-sentinel"
            self.assert_rejected(data)

    def test_inconsistent_missing_empty_or_duplicate_site_inventory_fails(self):
        for sites in (None, [], {}, [fixture()["site"][0]] * 2):
            data = fixture()
            data["site"] = sites
            self.assert_rejected(data)
        for name in ("@name", "@host", "@port", "@ssl", "alerts"):
            data = fixture()
            del data["site"][0][name]
            self.assert_rejected(data)

    def test_bad_or_inconsistent_rule_identity_and_duplicate_alerts_fail(self):
        for field, value in (
            ("pluginid", "-1"),
            ("pluginid", 10020),
            ("pluginid", "010020"),
            ("alertRef", "10021-1"),
            ("alertRef", "10020-private-sentinel"),
            ("alertRef", "https://private-sentinel.invalid"),
        ):
            data = fixture()
            data["site"][0]["alerts"][0][field] = value
            self.assert_rejected(data)
        data = fixture()
        data["site"][0]["alerts"] *= 2
        self.assert_rejected(data)

    def test_numeric_metadata_is_strict_and_bounded(self):
        for field, bad_values in (
            ("riskcode", (True, -1, 4, "01", " 2", "2.0", 2.0)),
            ("confidence", (False, -1, 5, "02", "sentinel", 2.0)),
            ("count", (True, 0, 2, "01", "1.0", 1.0)),
        ):
            for value in bad_values:
                with self.subTest(field=field, value=value):
                    data = fixture()
                    data["site"][0]["alerts"][0][field] = value
                    self.assert_rejected(data)
        data = fixture()
        alert = data["site"][0]["alerts"][0]
        alert.update(riskcode=2, confidence=2, count=1)
        self.assertEqual(self.parse(data).findings[0].severity, "medium")

    def test_instances_counts_and_global_workload_are_bounded(self):
        for instances in (None, {}, [], [fixture()["site"][0]["alerts"][0]["instances"][0]] * 51):
            data = fixture()
            data["site"][0]["alerts"][0]["instances"] = instances
            self.assert_rejected(data)
        data = fixture()
        data["site"][0]["alerts"] *= MAX_ALERTS + 1
        self.assert_rejected(data)
        data = fixture()
        alert = data["site"][0]["alerts"][0]
        alert["instances"] *= MAX_INSTANCES_PER_ALERT
        alert["count"] = str(MAX_INSTANCES_PER_ALERT)
        with patch("bridge.zap_report.MAX_TOTAL_INSTANCES", MAX_INSTANCES_PER_ALERT - 1):
            self.assert_rejected(data, "total instance limit")

    def test_version_and_all_ignored_raw_fields_are_bounded_and_type_checked(self):
        for version in (None, "Dev Build", "2.17.0\nprivate-sentinel", "1" * 25):
            data = fixture()
            data["@version"] = version
            self.assert_rejected(data)
        for value in ([], {}, None, "x" * (MAX_TEXT + 1)):
            data = fixture()
            data["site"][0]["alerts"][0]["desc"] = value
            self.assert_rejected(data)
        data = fixture()
        data["site"][0]["alerts"][0]["tags"] = {"name": []}
        self.assert_rejected(data)

    def test_insights_do_not_create_coverage_or_leak_descriptions_and_reject_foreign_sites(self):
        data = fixture()
        data["insights"] = [{"site": TARGET_ORIGIN, "description": "private-sentinel"}]
        self.assertNotIn("sentinel", json.dumps(asdict(self.parse(data))))
        data["insights"][0]["site"] = "https://private-sentinel.invalid"
        self.assert_rejected(data)

    def test_session_wide_insights_are_discarded_without_assigning_target_coverage(self):
        data = fixture()
        data["insights"] = [{"site": "", "description": "private-global-insight-sentinel"}]
        self.assertEqual(self.parse(data), self.parse(fixture()))
        for site in (None, [], {}, 0, " ", TARGET_ORIGIN + "/", "https://private.invalid"):
            data["insights"][0]["site"] = site
            with self.subTest(site=site):
                self.assert_rejected(data)
        del data["insights"][0]["site"]
        self.assert_rejected(data)

    def test_shared_loader_rejects_ambiguous_oversized_or_nonfinite_json(self):
        for raw in (
            b'{"site": [], "site": []}',
            b'{"number": NaN}',
            b'{"number": 1e999}',
            b'"not-an-object"',
            b"\xff",
            b"{" * 33 + b"}" * 33,
            b" " * (MAX_BYTES + 1),
            b"",
            "not-bytes",
        ):
            with self.subTest(kind=type(raw).__name__):
                with self.assertRaises(ReportError):
                    parse_zap_report(raw)

    def test_parser_never_opens_files_networks_or_processes(self):
        with (
            patch("builtins.open", side_effect=AssertionError("filesystem I/O")),
            patch("socket.socket", side_effect=AssertionError("network I/O")),
            patch("subprocess.Popen", side_effect=AssertionError("process I/O")),
        ):
            self.assertEqual(self.parse(fixture()).tool, "ZAP")

    def test_declared_profile_cannot_drift_from_the_import_target_boundary(self):
        profile_path = Path(__file__).resolve().parents[1] / "integrations/zap/profile.json"
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        self.assertEqual(profile["profile"], TARGET_PROFILE)
        self.assertEqual(profile["origin"], TARGET_ORIGIN)
        self.assertEqual(
            profile["requests"], [{"method": "GET", "path": path} for path in APPROVED_PATHS]
        )
        for name in ("follow_redirects", "spider", "active_scan", "authentication"):
            self.assertIs(profile[name], False)
        self.assertEqual(profile["proposed_runtime_limits"]["maximum_target_requests"], 3)


class ZapPilotDriverTests(TestCase):
    def test_bounded_diagnostics_preserve_actual_count_and_categories_without_raw_inputs(self):
        client = Mock()
        history = self.history()
        history["messages"][0]["requestHeader"] = (
            "GET https://private-sentinel.invalid/token HTTP/1.1\r\nAuthorization: private-sentinel\r\n\r\n"
        )
        client.api.side_effect = [
            {"numberOfMessages": "6"},
            history,
            {
                "urls": [
                    contract.ORIGIN,
                    contract.ORIGIN + "/",
                    "https://private-sentinel.invalid/token",
                ]
            },
            {"mode": "safe"},
            {"scanOnlyInScope": "true"},
            {"scanners": [{"id": "10021", "enabled": "true"}]},
        ]
        observations, summary = run_passive.collect_diagnostics(client)
        self.assertEqual(summary["message_count"], {"type": "string", "value": 6})
        self.assertEqual(summary["message_inventory_length"], 6)
        self.assertEqual(summary["site_tree_entries"][0]["category"], "fixed_origin_without_path")
        self.assertEqual(summary["site_tree_entries"][2]["category"], "unexpected")
        self.assertNotIn("private-sentinel", json.dumps(summary))
        self.assertNotIn("requestHeader", json.dumps(summary))
        self.assertTrue(summary["header_rule_enabled"])
        self.assertTrue(summary["passive_only_in_scope"])
        with self.assertRaisesRegex(run_passive.PilotError, "history_request_scope"):
            run_passive.verify_history(client, observations)
        self.assertEqual(client.api.call_count, 6)

    def test_diagnostics_do_not_echo_invalid_numeric_or_url_values_and_keep_read_failures(self):
        client = Mock()
        client.api.side_effect = [
            {"numberOfMessages": "private-sentinel"},
            run_passive.PilotError("fixed_read_failure"),
            {"urls": ["x" * 2049]},
            {"mode": "safe"},
            {"scanOnlyInScope": "false"},
            {"scanners": []},
        ]
        _, summary = run_passive.collect_diagnostics(client)
        self.assertEqual(summary["unavailable_reads"], ["history"])
        self.assertEqual(summary["message_count"]["value"], "not_bounded_numeric")
        self.assertEqual(summary["site_tree_entries"], [{"category": "invalid_or_oversized"}])
        self.assertNotIn("private-sentinel", json.dumps(summary))
        self.assertFalse(summary["passive_only_in_scope"])

    def test_failed_report_summary_retains_only_fixed_paths_and_numeric_rule_metadata(self):
        data = fixture()
        data["site"][0]["alerts"][0]["desc"] = "private-description-sentinel"
        summary = run_passive.failure_report_summary(json.dumps(data).encode())
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["execution_provenance"], "none")
        self.assertNotIn("private-description-sentinel", json.dumps(summary))
        self.assertNotIn("evidence", json.dumps(summary))
        for path in ("http://external.invalid/", contract.ORIGIN + "/unapproved/"):
            bad = copy.deepcopy(data)
            bad["site"][0]["alerts"][0]["instances"][0]["uri"] = path
            with self.assertRaisesRegex(run_passive.PilotError, "failure_report_scope"):
                run_passive.failure_report_summary(json.dumps(bad).encode())

    def history(self):
        messages = [
            {
                "id": str(index),
                "type": "1",
                "timestamp": "1",
                "rtt": "1",
                "cookieParams": "",
                "note": "",
                "tags": [],
                "requestHeader": f"GET {contract.ORIGIN}{path} HTTP/1.1\r\nHost: {contract.HOST}\r\n\r\n",
                "requestBody": "",
                "responseHeader": f"HTTP/1.1 200 OK\r\nX-SignalBridge-Fixture: {contract.PROFILE}\r\nX-SignalBridge-Request-Ordinal: {index}\r\n\r\n",
                "responseBody": contract.BODIES[path].decode(),
            }
            for index, path in enumerate(contract.PATHS, 1)
        ]
        for index, path in enumerate(contract.PATHS, 1):
            messages.append(
                {
                    **copy.deepcopy(messages[index - 1]),
                    "id": str(index + 3),
                    "type": "0",
                    "timestamp": "0",
                    "rtt": "0",
                    "requestHeader": f"GET {contract.ORIGIN}{path.rstrip('/')} HTTP/1.1\r\nHost: {contract.HOST}\r\n\r\n",
                    "responseHeader": "HTTP/1.0 0\r\n\r\n",
                    "responseBody": "",
                }
            )
        return {"messages": messages}

    def history_client(self, payload=None, count="6"):
        client = Mock()
        client.api.side_effect = [{"numberOfMessages": count}, payload or self.history()]
        return client

    def test_actual_message_inventory_is_unfiltered_bounded_and_contains_no_raw_evidence(self):
        client = self.history_client()
        result = run_passive.verify_history(client)
        self.assertEqual(
            result,
            {
                "history_verified": True,
                "history_message_count": 6,
                "history_proxied_count": 3,
                "history_internal_count": 3,
                "history_request_paths": list(contract.PATHS),
                "history_internal_ancestor_paths": ["", "/login", "/health"],
            },
        )
        self.assertEqual(client.api.call_args_list[-1].args, ("core", "view", "messages"))
        self.assertEqual(client.api.call_args_list[-1].kwargs, {"start": "0", "count": "8"})
        self.assertNotIn("requestHeader", str(result))
        self.assertNotIn("responseBody", str(result))

    def test_history_rejects_missing_extra_duplicate_and_out_of_scope_records(self):
        mutations = [
            lambda rows: rows.pop(),
            lambda rows: rows.append(copy.deepcopy(rows[0])),
            lambda rows: rows[1].update(id=rows[0]["id"]),
            lambda rows: rows[1].update(requestHeader=rows[0]["requestHeader"]),
            lambda rows: rows[0].update(
                requestHeader="GET https://external.invalid/ HTTP/1.1\r\nHost: external.invalid\r\n\r\n"
            ),
            lambda rows: rows[0].update(
                requestHeader=rows[0]["requestHeader"].replace("GET ", "POST ")
            ),
            lambda rows: rows[0].update(type="0"),
            lambda rows: rows[3].update(type="1"),
            lambda rows: rows[4].update(requestHeader=rows[3]["requestHeader"]),
            lambda rows: rows[3].update(
                requestHeader=f"GET {contract.ORIGIN}/unapproved HTTP/1.1\r\nHost: {contract.HOST}\r\n\r\n"
            ),
        ]
        for mutate in mutations:
            payload = self.history()
            mutate(payload["messages"])
            with self.assertRaises(run_passive.PilotError):
                run_passive.verify_history(self.history_client(payload))
        for count in ("2", "3", "4", "5", "7", 6, True):
            with self.assertRaises(run_passive.PilotError):
                run_passive.verify_history(self.history_client(count=count))

    def test_history_only_allows_proxied_and_temporary_types(self):
        for index in (0, 3):
            for kind in (1, 0, True, None, "2", "3", "6", "14", "15", "16", "-1"):
                payload = self.history()
                payload["messages"][index]["type"] = kind
                with (
                    self.subTest(index=index, kind=kind),
                    self.assertRaisesRegex(run_passive.PilotError, "history_message_type"),
                ):
                    run_passive.verify_history(self.history_client(payload))

    def test_internal_records_require_unsent_metadata_and_cloned_headers(self):
        for field, value in (
            ("timestamp", "1"),
            ("rtt", "1"),
            ("responseHeader", "HTTP/1.1 200 OK\r\n\r\n"),
            ("responseHeader", "HTTP/1.0 0\r\nLocation: https://private.invalid/\r\n\r\n"),
            ("responseBody", "private-sentinel"),
            ("requestBody", "private-sentinel"),
            ("cookieParams", "private-sentinel"),
            ("note", "private-sentinel"),
            ("tags", ["private-sentinel"]),
            (
                "requestHeader",
                f"GET {contract.ORIGIN} HTTP/1.1\r\nHost: {contract.HOST}\r\nCookie: private-sentinel\r\n\r\n",
            ),
            (
                "requestHeader",
                f"GET {contract.ORIGIN} HTTP/1.1\r\nHost: {contract.HOST}\r\nX-Unexpected: private-sentinel\r\n\r\n",
            ),
        ):
            payload = self.history()
            payload["messages"][3][field] = value
            with self.subTest(field=field), self.assertRaises(run_passive.PilotError) as raised:
                run_passive.verify_history(self.history_client(payload))
            self.assertNotIn("private-sentinel", str(raised.exception))

    def test_internal_header_clone_omits_entity_headers_and_inventory_order_is_irrelevant(self):
        payload = self.history()
        payload["messages"][0]["requestHeader"] = (
            f"GET {contract.ORIGIN}/ HTTP/1.1\r\nHost: {contract.HOST}\r\n"
            "Content-Type: text/plain\r\nContent-Length: 0\r\n\r\n"
        )
        payload["messages"].reverse()
        result = run_passive.verify_history(self.history_client(payload))
        self.assertEqual(result["history_proxied_count"], 3)
        self.assertEqual(result["history_internal_count"], 3)

    def test_history_rejects_credentials_redirects_bad_body_and_faked_fixture_identity(self):
        for field, value in (
            (
                "requestHeader",
                f"GET {contract.ORIGIN}/ HTTP/1.1\r\nHost: {contract.HOST}\r\nCookie: private-sentinel\r\n\r\n",
            ),
            ("requestBody", "private-sentinel"),
            ("cookieParams", "private-sentinel"),
            (
                "responseHeader",
                "HTTP/1.1 302 Found\r\nLocation: https://private-sentinel.invalid/\r\n\r\n",
            ),
            ("responseHeader", "HTTP/1.1 200 OK\r\nX-SignalBridge-Fixture: fake\r\n\r\n"),
            ("responseBody", "private-sentinel"),
        ):
            payload = self.history()
            payload["messages"][0][field] = value
            with self.subTest(field=field), self.assertRaises(run_passive.PilotError) as raised:
                run_passive.verify_history(self.history_client(payload))
            self.assertNotIn("private-sentinel", str(raised.exception))

    def test_history_header_bounds_and_duplicate_host_are_not_normalized_away(self):
        for header in (
            "x" * 8193,
            f"GET {contract.ORIGIN}/ HTTP/1.1\nHost: {contract.HOST}\n\n",
            f"GET {contract.ORIGIN}/ HTTP/1.1\r\nHost: {contract.HOST}\r\nHost: {contract.HOST}\r\n\r\n",
            f"GET {contract.ORIGIN}/ HTTP/1.1\r\n Host: {contract.HOST}\r\n\r\n",
        ):
            payload = self.history()
            payload["messages"][0]["requestHeader"] = header
            with self.assertRaises(run_passive.PilotError):
                run_passive.verify_history(self.history_client(payload))

    def test_configure_uses_pinned_context_api_parameter_and_only_safe_operations(self):
        client = Mock()

        def response(component, kind, name, **parameters):
            values = {
                "mode": {"mode": "safe"},
                "urls": {"urls": []},
                "numberOfMessages": {"numberOfMessages": "0"},
                "scanOnlyInScope": {"scanOnlyInScope": "true"},
                "scanners": {"scanners": [{"id": "10021", "enabled": "true"}]},
            }
            return values.get(name, {"Result": "OK"})

        client.api.side_effect = response
        run_passive.configure(client)
        calls = client.api.call_args_list
        scope_calls = [
            call for call in calls if call.args == ("context", "action", "setContextInScope")
        ]
        self.assertEqual(len(scope_calls), 1)
        self.assertEqual(
            scope_calls[0].kwargs, {"contextName": contract.PROFILE, "booleanInScope": "true"}
        )
        self.assertTrue(all(call.args in run_passive._API_ROUTES for call in calls))
        self.assertFalse(any(call.args[0] in {"ascan", "spider", "ajaxSpider"} for call in calls))

    def response(self, path="/", status=200, headers=None, body=None):
        values = {
            "X-SignalBridge-Fixture": contract.PROFILE,
            "X-SignalBridge-Request-Ordinal": "1",
        }
        values.update(headers or {})
        response = Mock(status=status)
        response.getheader.side_effect = values.get
        response.read.return_value = contract.BODIES[path] if body is None else body
        return response

    def client(self):
        return run_passive.Client("private-api-key-sentinel", 100)

    def test_proxy_request_has_exact_target_no_api_key_and_no_redirect_loop(self):
        response = self.response()
        connection = Mock()
        connection.getresponse.return_value = response
        client = self.client()
        with (
            patch.object(run_passive.time, "monotonic", return_value=0),
            patch.object(run_passive, "network_deadline", return_value=nullcontext()) as deadline,
            patch.object(
                run_passive.http.client, "HTTPConnection", return_value=connection
            ) as ctor,
        ):
            client.target("/")
        ctor.assert_called_once_with("127.0.0.1", 8080, timeout=5)
        connection.request.assert_called_once_with(
            "GET", contract.ORIGIN + "/", headers={"Host": contract.HOST, "Connection": "close"}
        )
        self.assertNotIn("private-api-key-sentinel", str(connection.request.call_args))
        deadline.assert_called_once_with(5)
        response.read.assert_called_once_with(contract.BODY_LIMIT + 1)
        connection.close.assert_called_once()
        self.assertEqual(client.target_requests[0]["status"], "passed")

    def test_redirect_is_not_followed_or_counted_as_a_pass(self):
        for status, headers in ((302, {}), (200, {"Location": "https://private-sentinel.invalid"})):
            with self.subTest(status=status):
                connection = Mock()
                connection.getresponse.return_value = self.response(status=status, headers=headers)
                client = self.client()
                with (
                    patch.object(run_passive.time, "monotonic", return_value=0),
                    patch.object(run_passive, "network_deadline", return_value=nullcontext()),
                    patch.object(
                        run_passive.http.client, "HTTPConnection", return_value=connection
                    ),
                    self.assertRaisesRegex(run_passive.PilotError, "redirect"),
                ):
                    client.target("/")
                self.assertEqual(connection.request.call_count, 1)
                self.assertEqual(client.target_requests[0]["status"], "attempted")
                connection.close.assert_called_once()

    def test_request_order_or_extra_request_refused_before_connection(self):
        client = self.client()
        with patch.object(run_passive.http.client, "HTTPConnection") as connection:
            for path in ("/login/", "/redirect/", "https://external.invalid"):
                with self.assertRaisesRegex(run_passive.PilotError, "target_sequence_refused"):
                    client.target(path)
            client.target_requests = [{}, {}, {}]
            with self.assertRaises(run_passive.PilotError):
                client.target("/")
        connection.assert_not_called()

    def test_expired_deadline_and_response_size_refuse_completion(self):
        client = self.client()
        with (
            patch.object(run_passive.time, "monotonic", return_value=101),
            patch.object(run_passive.http.client, "HTTPConnection") as connection,
            self.assertRaisesRegex(run_passive.PilotError, "total_deadline"),
        ):
            client.request("/JSON/core/view/version/", {}, 10)
        connection.assert_not_called()
        connection = Mock()
        connection.getresponse.return_value = self.response(body=b"x" * 11)
        with (
            patch.object(run_passive.time, "monotonic", return_value=99),
            patch.object(run_passive, "network_deadline", return_value=nullcontext()) as deadline,
            patch.object(run_passive.http.client, "HTTPConnection", return_value=connection),
            self.assertRaisesRegex(run_passive.PilotError, "response_size_limit"),
        ):
            client.request("/JSON/core/view/version/", {}, 10)
        deadline.assert_called_once_with(1)

    def test_fake_fixture_or_extra_target_request_cannot_pass(self):
        for headers, body in (
            ({"X-SignalBridge-Fixture": "wrong"}, None),
            ({"X-SignalBridge-Request-Ordinal": "2"}, None),
            ({"X-Content-Type-Options": "nosniff"}, None),
            ({}, b"unrecognized-body"),
        ):
            client = self.client()
            with (
                patch.object(
                    client,
                    "request",
                    return_value=(
                        contract.BODIES["/"] if body is None else body,
                        self.response(headers=headers),
                    ),
                ),
                self.assertRaises(run_passive.PilotError),
            ):
                client.target("/")

    def test_api_key_only_goes_to_local_allowlisted_api_route(self):
        client = self.client()
        with patch.object(
            client, "request", return_value=(b'{"version":"2.17.0"}', None)
        ) as request:
            self.assertEqual(client.api("core", "view", "version"), {"version": "2.17.0"})
            self.assertEqual(request.call_args.args[0], "/JSON/core/view/version/")
            self.assertEqual(
                request.call_args.args[1], {"X-ZAP-API-Key": "private-api-key-sentinel"}
            )
            with self.assertRaises(run_passive.PilotError):
                client.api("ascan", "action", "scan")
            self.assertEqual(request.call_count, 1)

    def test_api_json_rejects_duplicates_nonfinite_constants_and_overflowing_exponents(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}'):
            with self.assertRaisesRegex(run_passive.PilotError, "invalid_api_json"):
                run_passive.decode(raw)

    def test_linux_wall_timer_interrupts_and_is_cleared_even_on_failure(self):
        with (
            patch.object(run_passive.sys, "platform", "linux"),
            patch.object(run_passive.signal, "ITIMER_REAL", 0, create=True),
            patch.object(run_passive.signal, "SIGALRM", 14, create=True),
            patch.object(run_passive.signal, "getitimer", return_value=(0.0, 0.0), create=True),
            patch.object(run_passive.signal, "setitimer", create=True) as timer,
            patch.object(run_passive.signal, "signal", return_value="previous") as handler,
            self.assertRaisesRegex(run_passive.PilotError, "network_wall_deadline"),
        ):
            with run_passive.network_deadline(2):
                run_passive.network_alarm(14, None)
        self.assertEqual(timer.call_args_list[0].args, (0, 2))
        self.assertEqual(timer.call_args_list[-1].args, (0, 0))
        self.assertEqual(handler.call_args_list[-1].args, (14, "previous"))

    def test_private_log_redacts_api_key_even_across_chunks(self):
        secret = "a" * 32
        stream = Mock()
        stream.read.side_effect = [
            b"prefix " + secret[:10].encode(),
            secret[10:].encode() + b" tail",
            b"",
        ]
        overflow = threading.Event()
        with patch.object(run_passive, "private_write") as write:
            path = Path("/evidence/process.log")
            run_passive.collect_log(stream, path, overflow, secret)
            raw = write.call_args.args[1]
            self.assertNotIn(secret.encode(), raw)
            self.assertIn(b"[redacted-api-key]", raw)
        self.assertFalse(overflow.is_set())

    def test_truncated_log_does_not_preserve_partial_api_key(self):
        secret = "abcdefgh" * 4
        stream = Mock()
        stream.read.side_effect = [b"prefix " + secret.encode() + b" suffix", b""]
        overflow = threading.Event()
        with (
            patch.object(run_passive, "LOG_LIMIT", 24),
            patch.object(run_passive, "private_write") as write,
        ):
            run_passive.collect_log(stream, Path("/evidence/process.log"), overflow, secret)
        self.assertTrue(overflow.is_set())
        self.assertEqual(write.call_args.args[1], b"")

    def test_report_with_api_key_is_refused_without_writing_or_echoing_it(self):
        client = self.client()
        with patch.object(client, "request", return_value=(b"private-api-key-sentinel", None)):
            with self.assertRaisesRegex(run_passive.PilotError, "api_key_in_report") as raised:
                client.report()
        self.assertNotIn("sentinel", str(raised.exception))

    def test_known_header_control_requires_two_positive_and_one_negative_path(self):
        data = fixture()
        alert = data["site"][0]["alerts"][0]
        alert["pluginid"] = "10021"
        alert["instances"] = [
            {"uri": contract.ORIGIN + path, "method": "GET"} for path in ("/", "/login/")
        ]
        self.assertEqual(run_passive.control_results(json.dumps(data).encode())["status"], "passed")
        for extra in (
            [],
            [{"uri": contract.ORIGIN + "/health/", "method": "GET"}],
            [{"uri": "https://external.invalid/", "method": "GET"}],
        ):
            failed = copy.deepcopy(data)
            if not extra:
                failed["site"][0]["alerts"][0]["instances"] = []
            else:
                failed["site"][0]["alerts"][0]["instances"].extend(extra)
            with self.assertRaises(run_passive.PilotError):
                run_passive.control_results(json.dumps(failed).encode())

    def test_runtime_contract_matches_parser_without_loading_application_data(self):
        self.assertEqual(contract.ORIGIN, TARGET_ORIGIN)
        self.assertEqual(contract.PROFILE, TARGET_PROFILE)
        self.assertEqual(contract.PATHS, APPROVED_PATHS)
        self.assertTrue(all(len(body) < contract.BODY_LIMIT for body in contract.BODIES.values()))
