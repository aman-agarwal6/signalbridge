"""Closed enterprise Wazuh metadata profile; validation does not execute Wazuh."""

import re
import uuid

from bridge.contract import OPERATIONS, OUTCOMES, REASONS, canonical, timestamp

APPS = {"bettail", "netted", "documents", "expenses"}
SOURCES = {"migration_lab", "synthetic_demo", "instrumented_lab", "legacy_unclassified"}
OBSERVATION_FIELDS = {
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
SIGNAL_FIELDS = {
    "signal_version",
    "origin",
    "app",
    "signal_id",
    "case_id",
    "case_version",
    "rule_id",
    "rule_version",
    "severity",
    "environment",
    "source",
    "generated_at",
    "evidence_sha256",
    "generation_source_sha256",
    "evidence_count",
    "included_event_ids",
    "evidence_complete",
}
MAX_PACKET_BYTES = 4096
MAX_INCLUDED_IDS = 25
LOCATIONS = {
    "observation": "/signalbridge/input/observations.jsonl",
    "detection": "/signalbridge/input/detections.jsonl",
}


def segmented_location(app, channel, number):
    """Closed collector mount mapping, not a host path or runtime attestation."""
    require(
        isinstance(app, str) and app in APPS and isinstance(channel, str) and channel in LOCATIONS
    )
    require(type(number) is int and 0 <= number <= 7)
    name = "observations" if channel == "observation" else "detections"
    return f"/signalbridge/input/{app}/{channel}/{name}-{number:03}.jsonl"


class EnterpriseWazuhError(ValueError):
    pass


def require(condition, code="invalid_enterprise_wazuh_record"):
    if not condition:
        raise EnterpriseWazuhError(code)


def identifier(value):
    try:
        require(isinstance(value, str) and str(uuid.UUID(value)) == value)
    except (ValueError, AttributeError, TypeError):
        raise EnterpriseWazuhError("invalid_identifier") from None
    return value


def envelope(packet, key, fields):
    require(isinstance(packet, dict) and set(packet) == {key})
    row = packet[key]
    require(isinstance(row, dict) and set(row) == fields)
    require(len(canonical(packet)) <= MAX_PACKET_BYTES)
    require(row["app"] in APPS and row["environment"] in {"lab", "test"})
    require(row["source"] in SOURCES)
    return row


def validate_observation(packet):
    row = envelope(packet, "signalbridge", OBSERVATION_FIELDS)
    require(type(row["export_version"]) is int and row["export_version"] == 2)
    require(all(isinstance(row[key], str) for key in OBSERVATION_FIELDS - {"export_version"}))
    identifier(row["event_id"])
    timestamp(row["occurred_at"])
    require(
        row["operation"] in OPERATIONS and row["outcome"] in OUTCOMES and row["reason"] in REASONS
    )
    return row


def validate_signal(packet):
    row = envelope(packet, "signalbridge_detection", SIGNAL_FIELDS)
    require(type(row["signal_version"]) is int and row["signal_version"] == 1)
    require(row["origin"] == "signalbridge" and row["rule_id"] in {"R1", "R2", "R3", "R4", "R5"})
    require(
        row["severity"]
        == (
            "critical" if row["rule_id"] == "R2" else "high" if row["rule_id"] == "R3" else "medium"
        )
    )
    identifier(row["signal_id"])
    identifier(row["case_id"])
    timestamp(row["generated_at"])
    require(
        isinstance(row["rule_version"], str)
        and re.fullmatch(r"[a-z0-9-]{1,40}", row["rule_version"])
    )
    require(type(row["case_version"]) is int and 1 <= row["case_version"] <= 2**31 - 1)
    for name in ("evidence_sha256", "generation_source_sha256"):
        require(isinstance(row[name], str) and re.fullmatch(r"[a-f0-9]{64}", row[name]))
    require(type(row["evidence_count"]) is int and 1 <= row["evidence_count"] <= 1000)
    require(isinstance(row["included_event_ids"], str))
    ids = row["included_event_ids"].split(",")
    require(1 <= len(ids) == len(set(ids)) == min(row["evidence_count"], MAX_INCLUDED_IDS))
    require(all(identifier(value) for value in ids))
    require(
        type(row["evidence_complete"]) is int
        and row["evidence_complete"] == int(row["evidence_count"] <= MAX_INCLUDED_IDS)
    )
    return row


def expected_rule(packet):
    if "signalbridge_detection" in packet:
        row = validate_signal(packet)
        return (
            ("100221", 12)
            if row["rule_id"] == "R2"
            else ("100222", 10)
            if row["rule_id"] == "R3"
            else ("100223", 5)
        )
    row = validate_observation(packet)
    if row["source"] == "legacy_unclassified":
        return None
    if row["operation"] == "private_record.read" and row["outcome"] == "denied":
        return "100211", 3
    if row["operation"] == "private_record.read" and row["outcome"] == "not_visible":
        return "100212", 3
    if row["outcome"] == "error" and row["reason"] == "dependency_unavailable":
        return "100213", 4
    return None


def validate_native_record(value, packet, kind, *, now):
    """Match a sanitized packet to the selected standalone-manager JSON record."""
    require(
        isinstance(value, dict)
        and set(value)
        <= {
            "timestamp",
            "agent",
            "manager",
            "id",
            "decoder",
            "location",
            "data",
            "rule",
            "full_log",
            "predecoder",
        }
    )
    channel = "detection" if "signalbridge_detection" in packet else "observation"
    data = validate_signal(packet) if channel == "detection" else validate_observation(packet)
    require(
        isinstance(value.get("location"), str)
        and value["location"]
        in {LOCATIONS[channel]} | {segmented_location(data["app"], channel, n) for n in range(8)}
    )
    require(
        isinstance(value.get("id"), str) and re.fullmatch(r"[0-9]{1,20}\.[0-9]{1,20}", value["id"])
    )
    require(isinstance(value.get("agent"), dict) and value["agent"].get("id") == "000")
    require(isinstance(value.get("decoder"), dict) and value["decoder"].get("name") == "json")
    decoded = value.get("data")
    require(isinstance(decoded, dict) and set(decoded) == set(packet))
    normalized = decoded[next(iter(packet))]
    require(isinstance(normalized, dict) and set(normalized) == set(data))
    # Native dynamic fields can be strings or JSON numbers; prevent True == 1.
    require(
        all(
            type(normalized[key]) in (str, int) and str(normalized[key]) == str(data[key])
            for key in data
        )
    )
    observed = timestamp(value.get("timestamp"))
    require(
        timestamp(data["generated_at" if channel == "detection" else "occurred_at"])
        <= observed
        <= now
    )
    require(kind in {"archive", "alert"})
    if kind == "alert":
        rule = expected_rule(packet)
        require(rule is not None and "full_log" not in value)
        actual = value.get("rule")
        require(
            isinstance(actual, dict)
            and actual.get("id") == rule[0]
            and type(actual.get("level")) is int
            and actual["level"] == rule[1]
        )
    else:
        from integrations.wazuh.verify_static import parse_json

        require(isinstance(value.get("full_log"), str))
        require(canonical(parse_json(value["full_log"])) == canonical(packet))
    return observed
