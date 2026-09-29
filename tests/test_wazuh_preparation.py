"""Regression tests for preparation safeguards, not tests of Wazuh itself."""

import copy
import types
import unittest
from pathlib import Path

from integrations.wazuh import verify_static as prep


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.config = prep.read_bounded(prep.HERE / "manager-lab.conf")
        self.rules_data = prep.read_bounded(prep.HERE / "signalbridge_rules.xml")
        self.lines = prep.read_bounded(prep.HERE / "fixtures/events.jsonl").decode().splitlines()
        self.expectations = prep.parse_json(
            prep.read_bounded(prep.HERE / "fixtures/expectations.json").decode()
        )
        self.row = prep.parse_json(self.lines[0])

    def test_recorded_scope_and_complete_corpus(self):
        result = prep.verify()
        self.assertEqual(result["fixture_count"], 27)
        self.assertFalse(result["wazuh_executed"])
        self.assertFalse(result["collection_verified"])

    def test_shallow_container_import_needs_no_repository_parent(self):
        module = types.ModuleType("wazuh_shallow_test")
        module.__file__ = str(Path(Path.cwd().anchor) / "pilot" / "verify_static.py")
        source = prep.read_bounded(prep.HERE / "verify_static.py")
        exec(compile(source, module.__file__, "exec"), module.__dict__)
        self.assertEqual(module.HERE.name, "pilot")
        values = prep.contract_values()
        self.assertEqual(module.validate_export(self.row, values)["app"], "bettail")
        module.verify_config(module.parse_xml(self.config))
        with self.assertRaisesRegex(module.PreparationError, "repository_context_required"):
            module.verify_export_source()

    def test_extra_sensitive_fields_rejected_before_staging(self):
        for key in ("token", "actor", "resource", "password", "expected_rule"):
            with self.subTest(key=key):
                row = copy.deepcopy(self.row)
                row["signalbridge"][key] = "NONFUNCTIONAL_TEST_PLACEHOLDER"
                with self.assertRaises(prep.PreparationError):
                    prep.validate_export(row)

    def test_typed_version_duplicate_keys_and_malformed_json_rejected(self):
        for version in (True, "1", 1.0, 2):
            with self.subTest(version=version):
                row = copy.deepcopy(self.row)
                row["signalbridge"]["export_version"] = version
                with self.assertRaises(prep.PreparationError):
                    prep.validate_export(row)
        for value in ('{"key":1,"key":2}', '{"key":', "[" * 3000):
            with self.assertRaises(prep.PreparationError):
                prep.parse_json(value)

    def test_bad_time_environment_source_and_identity_rejected(self):
        for key, value in (
            ("occurred_at", "2026-09-24T12:00:00"),
            ("occurred_at", "2026-99-99T12:00:00Z"),
            ("environment", "production"),
            ("source", "host_agent"),
            ("event_id", "not-a-uuid"),
        ):
            with self.subTest(key=key, value=value):
                row = copy.deepcopy(self.row)
                row["signalbridge"][key] = value
                with self.assertRaises(prep.PreparationError):
                    prep.validate_export(row)

    def test_legacy_source_is_valid_export_but_not_trusted_for_alerting(self):
        self.row["signalbridge"]["source"] = "legacy_unclassified"
        prep.validate_export(self.row)
        self.assertFalse(prep.field_predicates(prep.read_rules(self.rules_data)[0], self.row))

    def test_response_enrollment_or_host_scanning_enablement_rejected(self):
        for section in ("active-response", "auth", "rootcheck", "syscheck", "cluster"):
            with self.subTest(section=section):
                config = prep.parse_xml(self.config)
                config.find(section + "/disabled").text = "no"
                with self.assertRaises(prep.PreparationError):
                    prep.verify_config(config)

    def test_command_external_collector_and_duplicate_sections_rejected(self):
        mutations = (
            self.config.replace(
                b"</ossec_config>", b"<command><name>example</name></command></ossec_config>"
            ),
            self.config.replace(b"/signalbridge/input/events.jsonl", b"/var/log/auth.log"),
            self.config.replace(
                b"</ossec_config>",
                b"<localfile><location>/other</location></localfile></ossec_config>",
            ),
        )
        for data in mutations:
            with self.assertRaises(prep.PreparationError):
                prep.verify_config(prep.parse_xml(data))

    def test_email_archives_and_update_checks_cannot_be_enabled_silently(self):
        for setting in ("email_notification", "logall", "logall_json", "update_check"):
            config = prep.parse_xml(self.config)
            config.find("global/" + setting).text = "yes"
            with self.assertRaises(prep.PreparationError):
                prep.verify_config(config)

    def test_modules_and_indexer_cannot_be_enabled_silently(self):
        for section in ("sca", "indexer", "vulnerability-detection"):
            config = prep.parse_xml(self.config)
            config.find(section + "/enabled").text = "yes"
            with self.assertRaises(prep.PreparationError):
                prep.verify_config(config)
        config = prep.parse_xml(self.config)
        config.find("wodle/disabled").text = "no"
        with self.assertRaises(prep.PreparationError):
            prep.verify_config(config)

    def test_dtd_and_entity_declarations_rejected(self):
        with self.assertRaises(prep.PreparationError):
            prep.parse_xml(b'<!DOCTYPE x [<!ENTITY y "test">]><x>&y;</x>')

    def test_raw_log_and_unbounded_rule_changes_rejected(self):
        for data in (
            self.rules_data.replace(b"<options>no_full_log</options>", b""),
            self.rules_data.replace(b"^migration_lab$", b"migration_lab"),
        ):
            with self.assertRaises(prep.PreparationError):
                prep.read_rules(data)

    def test_mutated_revocation_predicate_is_detected(self):
        rules = prep.read_rules(self.rules_data)
        for field in rules[1].findall("field"):
            if field.get("name") == "signalbridge.reason":
                field.text = "^membership_required$"
        with self.assertRaises(prep.PreparationError):
            prep.check_vectors(rules, self.lines, self.expectations)

    def test_synthetic_promoted_to_observed_is_detected(self):
        rules = prep.read_rules(self.rules_data)
        for field in rules[1].findall("field"):
            if field.get("name") == "signalbridge.source":
                field.text = "^(migration_lab|synthetic_demo)$"
        with self.assertRaises(prep.PreparationError):
            prep.check_vectors(rules, self.lines, self.expectations)

    def test_missing_or_reordered_expectation_does_not_silently_pass(self):
        for cases in (self.expectations["cases"][:-1], list(reversed(self.expectations["cases"]))):
            expected = {**self.expectations, "cases": cases}
            with self.assertRaises(prep.PreparationError):
                prep.check_vectors(prep.read_rules(self.rules_data), self.lines, expected)


if __name__ == "__main__":
    unittest.main()
