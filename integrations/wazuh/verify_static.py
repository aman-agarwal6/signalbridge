"""Offline contract/configuration checks. This does not run or emulate Wazuh."""

import ast
import hashlib
import json
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAX_BYTES = 65536
EXPORT_FIELDS = {
    "export_version",
    "app",
    "environment",
    "event_id",
    "occurred_at",
    "operation",
    "outcome",
    "reason",
    "source",
}


class PreparationError(ValueError):
    pass


def repository_root():
    """Repository-only checks resolve lazily; runtime helpers also run at /pilot."""
    if len(HERE.parents) < 2:
        raise PreparationError("repository_context_required")
    return HERE.parents[1]


def require(condition, code):
    if not condition:
        raise PreparationError(code)


def read_bounded(path):
    require(not path.is_symlink() and path.is_file(), "regular_file_required")
    with path.open("rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, "file_too_large")
    return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def parse_json(text):
    require(len(text.encode("utf8")) <= MAX_BYTES, "json_too_large")
    try:
        return json.loads(text, object_pairs_hook=unique_object)
    except (ValueError, RecursionError) as exc:
        raise PreparationError("invalid_json") from exc


def contract_values():
    tree = ast.parse(read_bounded(repository_root() / "bridge" / "contract.py"))
    names = {"OPERATIONS", "OUTCOMES", "REASONS"}
    result = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in names:
                result[target.id] = ast.literal_eval(node.value)
    require(set(result) == names, "event_contract_changed")
    return result


def verify_export_source():
    """Read source structure without importing Django, a database, or settings."""
    tree = ast.parse(read_bounded(repository_root() / "bridge/management/commands/export_soc.py"))
    rows = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "row" for t in node.targets)
    ]
    require(len(rows) == 1 and isinstance(rows[0], ast.Dict), "export_structure_changed")
    require(
        [ast.literal_eval(k) for k in rows[0].keys] == ["signalbridge"], "export_envelope_changed"
    )
    inner = rows[0].values[0]
    require(isinstance(inner, ast.Dict), "export_structure_changed")
    require({ast.literal_eval(k) for k in inner.keys} == EXPORT_FIELDS, "export_fields_changed")
    index = [ast.literal_eval(k) for k in inner.keys].index("export_version")
    require(ast.literal_eval(inner.values[index]) == 1, "export_version_changed")


def validate_export(row, values=None):
    """Strict v1 shape for a future staging boundary, not authenticity verification."""
    values = values or contract_values()
    require(type(row) is dict and set(row) == {"signalbridge"}, "invalid_envelope")
    event = row["signalbridge"]
    require(type(event) is dict and set(event) == EXPORT_FIELDS, "invalid_fields")
    require(
        type(event["export_version"]) is int and event["export_version"] == 1, "invalid_version"
    )
    require(
        all(
            type(event[k]) is str and 1 <= len(event[k]) <= 64
            for k in EXPORT_FIELDS - {"export_version"}
        ),
        "invalid_scalar",
    )
    require(event["app"] in {"bettail", "netted"}, "invalid_app")
    require(event["environment"] in {"lab", "test"}, "invalid_environment")
    require(
        event["source"] in {"migration_lab", "synthetic_demo", "legacy_unclassified"},
        "invalid_source",
    )
    for key in ("operation", "outcome", "reason"):
        require(event[key] in values[key.upper() + "S"], "invalid_observation")
    try:
        require(str(uuid.UUID(event["event_id"])) == event["event_id"], "invalid_event_id")
        require(
            len(event["occurred_at"]) <= 40 and "T" in event["occurred_at"], "invalid_timestamp"
        )
        date = datetime.fromisoformat(event["occurred_at"].replace("Z", "+00:00"))
        require(date.tzinfo is not None and date.utcoffset() is not None, "invalid_timestamp")
    except (ValueError, TypeError) as exc:
        raise PreparationError("invalid_identity_or_timestamp") from exc
    return event


def parse_xml(data):
    require(
        len(data) <= MAX_BYTES and b"<!" not in re.sub(rb"<!--.*?-->", b"", data, flags=re.S),
        "unsafe_xml",
    )
    try:
        return ET.fromstring(data)
    except ET.ParseError as exc:
        raise PreparationError("invalid_xml") from exc


def verify_config(config):
    require(config.tag == "ossec_config", "invalid_config_root")
    allowed = {
        "global",
        "alerts",
        "logging",
        "active-response",
        "auth",
        "cluster",
        "rootcheck",
        "syscheck",
        "sca",
        "wodle",
        "vulnerability-detection",
        "indexer",
        "ruleset",
        "localfile",
    }
    require(all(child.tag in allowed for child in config), "unexpected_config_section")
    for name in allowed - {"wodle"}:
        require(len(config.findall(name)) == 1, "duplicate_or_missing_section")
    disabled = ["active-response", "auth", "cluster", "rootcheck", "syscheck"]
    for section in disabled:
        require(
            list(config.find(section))[0].tag == "disabled"
            and len(config.find(section)) == 1
            and config.findtext(section + "/disabled") == "yes",
            "unsafe_enabled_feature",
        )
    for section in ("sca", "vulnerability-detection", "indexer"):
        require(
            len(config.find(section)) == 1 and config.findtext(section + "/enabled") == "no",
            "unsafe_enabled_feature",
        )
    wodles = config.findall("wodle")
    require(
        len(wodles) == 3
        and {w.get("name") for w in wodles} == {"syscollector", "osquery", "docker-listener"},
        "unexpected_module",
    )
    require(
        all(len(w) == 1 and w.findtext("disabled") == "yes" for w in wodles),
        "unsafe_enabled_feature",
    )
    global_values = {node.tag: node.text for node in config.find("global")}
    require(len(global_values) == len(config.find("global")), "duplicate_global_setting")
    require(
        global_values
        == {
            "jsonout_output": "yes",
            "alerts_log": "no",
            "logall": "no",
            "logall_json": "no",
            "email_notification": "no",
            "update_check": "no",
            "rotate_interval": "10m",
            "max_output_size": "5M",
        },
        "unsafe_global_setting",
    )
    require(
        [(e.tag, e.text) for e in config.find("localfile")]
        == [
            ("location", "/signalbridge/input/events.jsonl"),
            ("log_format", "json"),
            ("only-future-events", "yes"),
        ],
        "unsafe_collection_scope",
    )
    require(
        [(e.tag, e.text) for e in config.find("ruleset")]
        == [
            ("decoder_dir", "ruleset/decoders"),
            ("rule_dir", "ruleset/rules"),
            ("rule_include", "etc/rules/signalbridge_rules.xml"),
        ],
        "unexpected_ruleset",
    )
    require(
        [(e.tag, e.text) for e in config.find("alerts")] == [("log_alert_level", "3")],
        "unexpected_alert_threshold",
    )
    require(
        [(e.tag, e.text) for e in config.find("logging")] == [("log_format", "plain")],
        "unexpected_logging",
    )
    require(
        not any(
            node.tag in {"command", "integration", "remote", "agentless", "syslog_output"}
            for node in config.iter()
        ),
        "unsafe_side_effect",
    )


def read_rules(data):
    root = parse_xml(data)
    require(
        root.tag == "group" and root.get("name") == "signalbridge,application_security,",
        "unexpected_rule_group",
    )
    rules = list(root)
    require(
        [r.get("id") for r in rules] == [str(i) for i in range(100200, 100206)],
        "unexpected_rule_ids",
    )
    require(
        [r.get("level") for r in rules] == ["0", "12", "5", "3", "3", "4"], "unexpected_rule_levels"
    )
    for index, rule in enumerate(rules):
        require(
            rule.tag == "rule" and set(rule.attrib) == {"id", "level"}, "unexpected_rule_attribute"
        )
        require(
            all(
                n.tag in {"decoded_as", "if_sid", "field", "description", "options", "group"}
                for n in rule
            ),
            "unsupported_rule_construct",
        )
        require(
            rule.findtext("options") == "no_full_log" and len(rule.findall("options")) == 1,
            "raw_log_not_suppressed",
        )
        if index == 0:
            require(
                rule.findtext("decoded_as") == "json" and rule.find("if_sid") is None,
                "unexpected_rule_root",
            )
            require(
                {f.get("name") for f in rule.findall("field")}
                == {"signalbridge." + k for k in EXPORT_FIELDS},
                "incomplete_rule_envelope",
            )
        else:
            require(
                rule.findtext("if_sid") == "100200" and rule.find("decoded_as") is None,
                "unexpected_rule_parent",
            )
        fields = rule.findall("field")
        require(
            fields and len({f.get("name") for f in fields}) == len(fields), "duplicate_rule_field"
        )
        for field in fields:
            require(
                set(field.attrib) == {"name", "type"} and field.get("type") == "pcre2",
                "unsupported_field_type",
            )
            require(
                field.get("name") in {"signalbridge." + k for k in EXPORT_FIELDS},
                "unknown_rule_field",
            )
            pattern = field.text or ""
            require(
                pattern.startswith("^") and pattern.endswith("$") and len(pattern) <= 256,
                "unbounded_rule_pattern",
            )
            re.compile(pattern)
    return rules


def field_predicates(rule, row):
    """Check these simple field patterns with Python, NOT Wazuh/PCRE2 semantics."""
    event = row.get("signalbridge", {})
    for field in rule.findall("field"):
        key = field.get("name").split(".", 1)[1]
        value = event.get(key)
        if type(value) not in (str, int) or re.fullmatch(field.text, str(value)) is None:
            return False
    return True


def check_vectors(rules, lines, expectations):
    require(
        expectations.get("schema_version") == 1
        and expectations.get("kind") == "synthetic_rule_expectations_not_observed_results",
        "invalid_expectation_schema",
    )
    cases = expectations.get("cases", [])
    require(1 <= len(lines) == len(cases) <= 64, "incomplete_fixture_matrix")
    require(len({c["id"] for c in cases}) == len(cases), "duplicate_fixture_id")
    values = contract_values()
    for index, (line, case) in enumerate(zip(lines, cases, strict=True), 1):
        require(case["line"] == index, "fixture_order_changed")
        row = parse_json(line)
        valid = True
        try:
            validate_export(row, values)
        except PreparationError:
            valid = False
        require(valid is case["export_contract_valid"], "fixture_contract_mismatch")
        candidates = []
        if field_predicates(rules[0], row):
            candidates = [r for r in rules[1:] if field_predicates(r, row)]
            require(len(candidates) <= 1, "overlapping_child_predicates")
            candidates = candidates or [rules[0]]
        chosen = candidates[0] if candidates else None
        rule_id = chosen.get("id") if chosen is not None else None
        level = int(chosen.get("level")) if chosen is not None else None
        require(
            rule_id == case["expected_rule"] and level == case["expected_level"],
            "fixture_predicate_mismatch",
        )
        require(
            case["expected_alert"] is (level is not None and level >= 3), "fixture_alert_mismatch"
        )
    return len(cases)


def verify():
    verify_export_source()
    snapshot = parse_json(read_bounded(HERE / "event-contract.json").decode("utf8"))
    require(
        {key: set(value) for key, value in snapshot.items()} == contract_values(),
        "runtime_contract_snapshot_changed",
    )
    config = read_bounded(HERE / "manager-lab.conf")
    rule_data = read_bounded(HERE / "signalbridge_rules.xml")
    event_data = read_bounded(HERE / "fixtures/events.jsonl")
    expected_data = read_bounded(HERE / "fixtures/expectations.json")
    verify_config(parse_xml(config))
    count = check_vectors(
        read_rules(rule_data),
        event_data.decode("utf8").splitlines(),
        parse_json(expected_data.decode("utf8")),
    )
    return {
        "check": "offline_preparation_only",
        "fixture_count": count,
        "wazuh_executed": False,
        "collection_verified": False,
        "rules_sha256": hashlib.sha256(rule_data).hexdigest(),
        "config_sha256": hashlib.sha256(config).hexdigest(),
        "fixtures_sha256": hashlib.sha256(event_data).hexdigest(),
        "expectations_sha256": hashlib.sha256(expected_data).hexdigest(),
    }


if __name__ == "__main__":
    try:
        print(json.dumps(verify(), sort_keys=True))
    except (PreparationError, OSError, UnicodeError, KeyError, TypeError, SyntaxError, re.error):
        raise SystemExit(
            "Wazuh preparation check failed; inspect controlled source files."
        ) from None
