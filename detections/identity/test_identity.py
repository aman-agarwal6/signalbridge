"""Checks for the identity rules, the log readers and the scoring. Run from the repository root:

python -m unittest discover -s detections -t . -p "test_*.py"

The rule tests use small hand-made rows. The report test needs the pinned inputs
(python -m detections.identity.fetch) and is skipped without them. The false-alarm baseline is
about 3 GB and isn't fetched here; its tests check the committed baseline-report.json against
the current rules and pins.
"""

import json
import re
import sqlite3
import unittest
from collections import Counter
from datetime import datetime, timedelta

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

from . import baseline
from .fetch import check_url, is_verified, load_sources, local_file, safe_relative
from .logs import (
    ENTRA_AUDIT,
    ENTRA_SIGNIN,
    WINDOWS_SECURITY,
    entra_rows,
    lanl_row,
    read_rows,
    windows_rows,
)
from .score import DETECTIONS, REPORT, RULES, build_report, hits, own_rules, sha256

# Technique IDs checked by hand against MITRE ATT&CK Enterprise.
ATTACK_TAGS = {
    "attack.credential-access",
    "attack.initial-access",
    "attack.persistence",
    "attack.t1078.002",
    "attack.t1078.004",
    "attack.t1098",
    "attack.t1098.001",
    "attack.t1098.005",
    "attack.t1110.003",
    "attack.t1528",
    "attack.t1558.003",
    "attack.t1558.004",
    "attack.t1621",
}
START = datetime(2026, 10, 22, 9)
RULES_BY_KEY = own_rules()


def at(seconds):
    return (START + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S.000")


def fires(key, rows):
    return hits(rows, [RULES_BY_KEY[key]])[key] > 0


def ticket(second, requester, service, status="0x0", timestamp=None):
    return {
        "timestamp": timestamp or at(second),
        "EventID": "4769",
        "Status": status,
        "TargetUserName": requester,
        "ServiceName": service,
    }


def failure(second, event_id, user, ip="::ffff:10.0.1.15", status="0xC000006A", **extra):
    row = {
        "timestamp": at(second),
        "EventID": event_id,
        "Computer": "dc01.example.test",
        "IpAddress": ip,
        "TargetUserName": user,
        "Status": status,
    }
    row.update(extra)
    return row


def signin(second, result, user="ana@example.test", ip="203.0.113.7", protocol="none"):
    return {
        "timestamp": at(second),
        "ResultType": str(result),
        "UserPrincipalName": user,
        "IPAddress": ip,
        "AuthenticationProtocol": protocol,
    }


def audit(operation, **extra):
    row = {"timestamp": at(0), "OperationName": operation, "Result": "success"}
    row.update(extra)
    return row


class RuleFiles(unittest.TestCase):
    def test_rules_load_with_unique_ids_and_known_attack_tags(self):
        rules = SigmaCollection.load_ruleset([RULES])
        rules.resolve_rule_references()
        ids = [rule.id for rule in rules.rules]
        self.assertEqual(len(ids), len(set(ids)))
        referenced = {
            reference.rule.name
            for rule in rules.rules
            if isinstance(rule, SigmaCorrelationRule)
            for reference in rule.rules
        }
        detections = set(DETECTIONS.values())
        for rule in rules.rules:
            if rule.name in detections:
                tags = {str(tag) for tag in rule.tags}
                self.assertLessEqual(tags, ATTACK_TAGS, rule.name)
                self.assertTrue(
                    any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", tag) for tag in tags), rule.name
                )
            else:
                self.assertIn(rule.name, referenced, "a base rule must feed a correlation")
                self.assertEqual(str(rule.level), "informational", rule.name)
        self.assertEqual(detections, {rule.name for rule in rules.rules} & detections)

    def test_every_detection_compiles_for_its_log_source(self):
        sources = {WINDOWS_SECURITY, ENTRA_SIGNIN, ENTRA_AUDIT}
        for key, rule in RULES_BY_KEY.items():
            self.assertIn(rule.source, sources, key)
            self.assertTrue(rule.query.lstrip().upper().startswith(("SELECT", "WITH")), key)


class Manifest(unittest.TestCase):
    def setUp(self):
        self.sources = load_sources()

    def test_expectations_name_known_rules(self):
        sigmahq = {item["name"] for item in self.sources["sigmahq_rules"]}
        ids = [item["id"] for item in self.sources["datasets"]]
        self.assertEqual(len(ids), len(set(ids)))
        for item in self.sources["datasets"]:
            self.assertLessEqual(set(item["expect"]["mine"]), set(DETECTIONS), item["id"])
            self.assertLessEqual(set(item["expect"]["sigmahq"]), sigmahq, item["id"])
            self.assertIn(item["format"], ("windows_xml", "entra_json"))
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")

    def test_paths_cannot_leave_the_data_folder(self):
        for path in ("../secrets.txt", "/etc/passwd", "a//b.log", "a/./b.log", "a\\b.log", ""):
            with self.assertRaises(ValueError, msg=path):
                safe_relative(path)
        self.assertEqual(
            safe_relative("T1621/azuread/azure-audit.log"), "T1621/azuread/azure-audit.log"
        )

    def test_fetch_only_uses_pinned_https_hosts(self):
        check_url("https://raw.githubusercontent.com/SigmaHQ/sigma/abc/rules/x.yml")
        for url in (
            "http://raw.githubusercontent.com/x.yml",
            "https://example.com/x.yml",
            "https://raw.githubusercontent.com.example.com/x.yml",
            "file:///etc/passwd",
        ):
            with self.assertRaises(ValueError, msg=url):
                check_url(url)


class Readers(unittest.TestCase):
    def test_windows_fields_across_namespaces_and_lines(self):
        text = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            "<EventID>4738</EventID><TimeCreated SystemTime='2022-02-22T18:08:10.1234567Z'/>"
            "<Channel>Security</Channel><Computer>dc01</Computer></System><EventData>"
            "<Data Name='UserAccountControl'>\n\t\t%%2089\n\t\t%%2096</Data></EventData></Event>\n"
            "<Event xmlns='http://schemas.microsoft.com/win/2006/08/events/event'><System>"
            "<EventID>4769</EventID><TimeCreated SystemTime='2022-02-22T18:08:11Z'/>"
            "<Channel>Security</Channel><Computer>dc01</Computer></System><EventData>"
            "<Data Name='ServiceName'>sql01</Data></EventData></Event>\n"
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            "<EventID>4104</EventID><TimeCreated SystemTime='2022-02-22T18:08:12Z'/>"
            "<Channel>Microsoft-Windows-PowerShell/Operational</Channel></System></Event>"
        )
        rows = list(windows_rows(text))
        self.assertEqual([source for source, _ in rows], [WINDOWS_SECURITY, WINDOWS_SECURITY])
        first, second = rows[0][1], rows[1][1]
        self.assertEqual(first["timestamp"], "2022-02-22 18:08:10.123")
        self.assertIn("%%2096", first["UserAccountControl"])
        self.assertEqual((second["EventID"], second["ServiceName"]), ("4769", "sql01"))

    def test_windows_document_types_are_refused(self):
        with self.assertRaises(ValueError):
            list(windows_rows('<!DOCTYPE x [<!ENTITY a "b">]><Event></Event>'))

    def test_entra_records_get_sentinel_columns(self):
        signin_record = {
            "time": "2023-08-03T22:00:48.7263711Z",
            "category": "SignInLogs",
            "operationName": "Sign-in activity",
            "resultType": "0",
            "properties": {
                "userPrincipalName": "ana@example.test",
                "ipAddress": "203.0.113.7",
                "authenticationProtocol": "deviceCode",
                "status": {"errorCode": 0},
            },
        }
        audit_record = {
            "time": "2023-10-27T19:05:44.7048245Z",
            "category": "AuditLogs",
            "operationName": "Consent to application",
            "properties": {
                "category": "ApplicationManagement",
                "result": "success",
                "targetResources": [
                    {
                        "modifiedProperties": [
                            {"displayName": "ConsentContext.IsAdminConsent", "newValue": '"False"'}
                        ]
                    }
                ],
            },
        }
        other = {"time": "2023-08-03T22:00:49Z", "category": "ServicePrincipalSignInLogs"}
        text = "\n".join(json.dumps(r) for r in (signin_record, audit_record, other))
        ignored = Counter()
        rows = list(entra_rows(text, ignored))
        self.assertEqual(dict(ignored), {"ServicePrincipalSignInLogs": 1})
        (s_source, s_row), (a_source, a_row) = rows
        self.assertEqual((s_source, a_source), (ENTRA_SIGNIN, ENTRA_AUDIT))
        self.assertEqual(s_row["AuthenticationProtocol"], "deviceCode")
        self.assertEqual(s_row["IPAddress"], "203.0.113.7")
        self.assertEqual(json.loads(s_row["Status"]), {"errorCode": 0})
        self.assertEqual(s_row["properties.status.errorCode"], "0")
        self.assertEqual(a_row["Category"], "ApplicationManagement")
        self.assertNotIn("category", a_row, "the Sentinel column wins over a raw name")
        self.assertEqual(a_row["ConsentContext.IsAdminConsent"], "False")

    def test_lanl_records_get_windows_field_names(self):
        ticket_row = lanl_row(
            {
                "EventID": 4769,
                "UserName": "User624729",
                "ServiceName": "Comp883934$",
                "DomainName": "Domain002",
                "Status": "0x0",
                "Source": "Comp309534",
                "LogHost": "ActiveDirectory",
                "Time": 90061,
            }
        )
        self.assertEqual(ticket_row["timestamp"], "1970-01-02 01:01:01.000")
        self.assertEqual(
            {key: ticket_row[key] for key in ("EventID", "TargetUserName", "Computer")},
            {"EventID": "4769", "TargetUserName": "User624729", "Computer": "ActiveDirectory"},
        )
        self.assertEqual(ticket_row["IpAddress"], "Comp309534")
        ntlm = lanl_row({"EventID": 4776, "UserName": "u", "Source": "Comp1", "Time": 0})
        self.assertEqual(ntlm["Workstation"], "Comp1")
        self.assertNotIn("IpAddress", ntlm, "NTLM checks name a workstation, not an address")
        for bad in (-1, "5", 1.5, True, None):
            with self.assertRaises(ValueError, msg=bad):
                lanl_row({"EventID": 4769, "Time": bad})


class Detections(unittest.TestCase):
    def test_w1_counts_distinct_user_run_services_from_any_requester(self):
        user = [ticket(i * 60, "bob@EXAMPLE.TEST", f"svc{i}") for i in range(5)]
        self.assertTrue(fires("W1", user))
        self.assertFalse(fires("W1", user[:4]))
        computer = [ticket(i, "WS01$@EXAMPLE.TEST", f"svc{i}") for i in range(5)]
        self.assertTrue(fires("W1", computer))
        machines = [ticket(i, "bob@EXAMPLE.TEST", f"host{i}$") for i in range(5)]
        self.assertFalse(fires("W1", machines + [ticket(9, "bob@EXAMPLE.TEST", "krbtgt")]))
        spread = [ticket(i * 180, "bob@EXAMPLE.TEST", f"svc{i}") for i in range(5)]
        self.assertFalse(fires("W1", spread), "five services over twelve minutes")

    def test_w2_needs_ten_accounts_from_one_source(self):
        spray = [failure(i, "4771", f"user{i}") for i in range(10)]
        self.assertTrue(fires("W2", spray))
        self.assertFalse(fires("W2", spray[:9]))
        refused_tgt = [failure(i, "4768", f"user{i}", status="0x6") for i in range(10)]
        self.assertTrue(fires("W2", refused_tgt))
        issued_tgt = [failure(i, "4768", f"user{i}", status="0x0") for i in range(10)]
        self.assertFalse(fires("W2", issued_tgt))
        sources = [failure(i, "4625", f"user{i}", ip=f"10.0.0.{i}") for i in range(10)]
        self.assertFalse(fires("W2", sources))

    def test_w3_disabled_account_codes(self):
        self.assertTrue(fires("W3", [failure(0, "4625", "leaver", SubStatus="0xC0000072")]))
        self.assertTrue(fires("W3", [failure(0, "4776", "leaver", status="0xc0000072")]))
        self.assertTrue(fires("W3", [failure(0, "4768", "leaver", status="0x12")]))
        self.assertFalse(fires("W3", [failure(0, "4625", "user", SubStatus="0xC000006A")]))
        self.assertFalse(fires("W3", [failure(0, "4769", "user", status="0x12")]))

    def test_w4_matches_the_preauth_flag_literally(self):
        def change(value):
            return [{"timestamp": at(0), "EventID": "4738", "UserAccountControl": value}]

        self.assertTrue(fires("W4", change("\n\t\t%%2089\n\t\t%%2096")))
        self.assertFalse(fires("W4", change("%%2089")))
        self.assertFalse(fires("W4", change("x2096")), "a % in the rule is not a wildcard")

    def test_w5_groups_ntlm_failures_by_workstation(self):
        spray = [
            failure(i, "4776", f"user{i}", ip=None, status="0xc000006a", Workstation="WS01")
            for i in range(10)
        ]
        self.assertTrue(fires("W5", spray))
        self.assertFalse(fires("W5", spray[:9]))
        ok = [dict(row, Status="0x0") for row in spray]
        self.assertFalse(fires("W5", ok))

    def test_e1_needs_ten_accounts_from_one_address(self):
        spray = [signin(i, 50126, user=f"user{i}@example.test") for i in range(10)]
        self.assertTrue(fires("E1", spray))
        spread = [
            signin(i, 50126, user=f"user{i}@example.test", ip=f"198.51.100.{i}") for i in range(10)
        ]
        self.assertFalse(fires("E1", spread))
        one_user = [signin(i, 50126) for i in range(30)]
        self.assertFalse(fires("E1", one_user))

    def test_e2_needs_three_mfa_failures(self):
        self.assertTrue(fires("E2", [signin(i * 60, 500121) for i in range(3)]))
        self.assertFalse(fires("E2", [signin(i * 60, 500121) for i in range(2)]))
        self.assertFalse(fires("E2", [signin(i * 400, 500121) for i in range(3)]))

    def test_e3_successful_device_code_only(self):
        self.assertTrue(fires("E3", [signin(0, 0, protocol="deviceCode")]))
        self.assertTrue(fires("E3", [signin(0, 0, protocol="DEVICECODE")]), "Sigma ignores case")
        self.assertFalse(fires("E3", [signin(0, 50199, protocol="deviceCode")]))
        self.assertFalse(fires("E3", [signin(0, 0)]))

    def test_e4_new_method_from_authentication_methods(self):
        registered = audit(
            "User registered security info", LoggedByService="Authentication Methods"
        )
        self.assertTrue(fires("E4", [registered]))
        self.assertFalse(fires("E4", [audit("Update user", LoggedByService="Core Directory")]))

    def test_e5_current_and_older_activity_names(self):
        self.assertTrue(fires("E5", [audit("Create Temporary Access Pass method for user")]))
        older = audit(
            "Admin registered security info",
            ResultReason="Admin registered temporary access pass method for user",
        )
        self.assertTrue(fires("E5", [older]))
        phone = audit("Admin registered security info", ResultReason="Admin registered phone")
        self.assertFalse(fires("E5", [phone]))

    def test_e6_successful_consent(self):
        self.assertTrue(fires("E6", [audit("Consent to application")]))
        self.assertFalse(fires("E6", [audit("Consent to application", Result="failure")]))

    def test_e7_credential_changes_only(self):
        for name in (
            "Update application – Certificates and secrets management ",
            "Update application - Certificates and secrets management",
            "Add service principal credentials",
        ):
            self.assertTrue(fires("E7", [audit(name)]), name)
        federated = audit(
            "Update service principal",
            TargetResources='[{"modifiedProperties": [{"displayName": "FederatedIdentityCredentials"}]}]',
        )
        self.assertTrue(fires("E7", [federated]))
        renamed = audit(
            "Update service principal",
            TargetResources='[{"modifiedProperties": [{"displayName": "DisplayName"}]}]',
        )
        self.assertFalse(fires("E7", [renamed]))

    def test_e8_disabled_account_code(self):
        self.assertTrue(fires("E8", [signin(0, 50057)]))
        self.assertFalse(fires("E8", [signin(0, 50126)]))


class Baseline(unittest.TestCase):
    def test_loaded_events_cover_every_windows_rule(self):
        for side in baseline.windows_rules().values():
            for key, rule in side.items():
                self.assertTrue(baseline.event_ids(rule.rule), key)
        self.assertEqual(baseline.event_ids(RULES_BY_KEY["W1"].rule), {"4769"})
        self.assertEqual(
            baseline.event_ids(RULES_BY_KEY["W3"].rule), {"4625", "4768", "4771", "4776"}
        )

    def test_fetch_only_uses_the_mirror(self):
        check_url("https://lanl.ma.ic.ac.uk/data/2017/wls/wls_day-01.bz2", baseline.ALLOWED_HOSTS)
        for url in ("http://lanl.ma.ic.ac.uk/x.bz2", "https://csr.lanl.gov/x.bz2"):
            with self.assertRaises(ValueError, msg=url):
                check_url(url, baseline.ALLOWED_HOSTS)

    def test_overlapping_windows_are_one_alert(self):
        def window(group, end):
            return {
                "group_keys": json.dumps({"TargetUserName": group}),
                "window_start": end - 600,
                "window_end": end,
                "metric_value": 5,
            }

        alerts = baseline.episodes(
            [window("a", 1000), window("a", 1300), window("a", 1590), window("a", 2500)]
            + [window("b", 1000)]
        )
        self.assertEqual(
            [(json.loads(a["group"])["TargetUserName"], a["windows"]) for a in alerts],
            [
                ("a", 3),
                ("a", 1),
                ("b", 1),
            ],
        )

    def test_lowered_threshold_leaves_the_rule_alone(self):
        rule = RULES_BY_KEY["W1"]
        low = baseline.lowered(rule)
        self.assertIn(">= 1)", low.query)
        self.assertIn(">= 5)", rule.query)
        self.assertEqual(rule.rule.condition.count, 5)

    def test_hourly_scoring_keeps_windows_that_cross_the_hour(self):
        rules = {"W1": RULES_BY_KEY["W1"]}
        columns = baseline.baseline_columns(rules.values())
        db = sqlite3.connect(":memory:")
        db.execute(baseline.table_sql("week", columns))
        for i in range(5):
            row = ticket(0, "bob", f"svc{i}", timestamp=baseline.stamp(3360 + i * 60))
            db.execute(
                f"INSERT INTO week VALUES ({', '.join('?' for _ in columns)})",
                [row.get(column) for column in columns],
            )
        found = baseline.run_week(db, rules, columns)["W1"]
        self.assertEqual([row["time"] for row in found], [3600], "services at 00:56-01:00")


class Report(unittest.TestCase):
    def test_report_is_current(self):
        sources = load_sources()
        pinned = [("attack_data", item) for item in sources["datasets"]] + [
            ("sigmahq", item) for item in sources["sigmahq_rules"]
        ]
        if not all(
            is_verified(local_file(k, i["path"]), i["sha256"], i["bytes"]) for k, i in pinned
        ):
            self.skipTest("pinned inputs not fetched; run python -m detections.identity.fetch")
        expected = json.dumps(build_report(), indent=2, ensure_ascii=False) + "\n"
        self.assertEqual(REPORT.read_text(encoding="utf-8"), expected)

    def test_baseline_report_matches_the_rules_and_pins(self):
        report = json.loads(baseline.REPORT.read_text(encoding="utf-8"))
        current = {
            path.relative_to(RULES).as_posix(): sha256(path)
            for path in sorted(RULES.rglob("*.yml"))
        }
        self.assertEqual(report["rules_sha256"], current, "rerun the baseline after a rule change")
        sources = load_sources()
        self.assertEqual(report["baseline"], sources["baseline"])
        self.assertEqual(report["sigmahq"], sources["sigmahq"])
        sides = baseline.windows_rules()
        self.assertEqual(
            {side: set(r) for side, r in report["rules"].items()},
            {side: set(r) for side, r in sides.items()},
        )
        days = [f"day-{item['day']:02d}" for item in sources["baseline"]["files"]]
        for side in report["rules"].values():
            for key, result in side.items():
                self.assertEqual(list(result["per_day"]), days, key)
                self.assertEqual(
                    sum(d["alerts"] for d in result["per_day"].values()), result["alerts"]
                )

    def test_reader_counts_every_pinned_dataset_format(self):
        for item in load_sources()["datasets"]:
            path = local_file("attack_data", item["path"])
            if not path.exists():
                self.skipTest("pinned inputs not fetched")
            rows, _ = read_rows(path, item["format"])
            self.assertTrue(any(rows.values()), item["id"])


if __name__ == "__main__":
    unittest.main()
