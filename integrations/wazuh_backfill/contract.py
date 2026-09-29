"""Pure backfill input and observed-record contract; never executes a tool."""

import hashlib
import json
import uuid
from collections import Counter

if __package__:
    from integrations.wazuh import run_context
    from integrations.wazuh import verify_static as prep
else:
    import run_context
    import verify_static as prep

MAX_INPUT = 128 * 1024
MAX_OUTPUT = 2 * 1024**2
MAX_RECORDS = 100
SPOOL = "/signalbridge/input/events.jsonl"
APP = "bettail"


class BackfillError(ValueError):
    pass


def require(value, code):
    if not value:
        raise BackfillError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def load_manifest(raw):
    require(type(raw) is bytes and len(raw) <= 256 * 1024, "backfill_manifest_size")

    def constant(_value):
        raise BackfillError("backfill_manifest_number")

    return json.loads(raw, object_pairs_hook=prep.unique_object, parse_constant=constant)


def uuid_text(value):
    require(type(value) is str and str(uuid.UUID(value)) == value, "backfill_uuid")
    return value


def expected_rule(event):
    if event["source"] == "legacy_unclassified":
        return None
    if event["operation"] == "private_record.read":
        if event["outcome"] == "allowed" and event["reason"] in {
            "membership_removed",
            "policy_regression",
        }:
            return ["100201", 12] if event["source"] == "migration_lab" else ["100202", 5]
        if event["outcome"] == "denied":
            return ["100203", 3]
        if event["outcome"] == "not_visible":
            return ["100204", 3]
    if event["outcome"] == "error" and event["reason"] == "dependency_unavailable":
        return ["100205", 4]
    return None


def packets(raw, values=None):
    require(
        type(raw) is bytes and 0 < len(raw) <= MAX_INPUT and raw.endswith(b"\n"),
        "backfill_input_size",
    )
    result = {}
    for line in raw.splitlines():
        packet = prep.parse_json(line.decode("ascii"))
        event = prep.validate_export(packet, values)
        require(event["app"] == APP and event["environment"] == "lab", "backfill_input_scope")
        require(event["event_id"] not in result, "backfill_duplicate_input")
        result[event["event_id"]] = packet
        require(len(result) <= MAX_RECORDS, "backfill_record_limit")
    return result


def validate_input(manifest, raw, values=None):
    require(
        type(manifest) is dict
        and set(manifest)
        == {
            "schema_version",
            "kind",
            "app",
            "stream_id",
            "revision",
            "offset",
            "sha256",
            "batches",
            "packets",
            "expected_alerts",
        },
        "backfill_manifest_shape",
    )
    require(
        type(manifest["schema_version"]) is int
        and manifest["schema_version"] == 1
        and manifest["kind"] == "signalbridge-wazuh-backfill-input"
        and manifest["app"] == APP,
        "backfill_manifest_scope",
    )
    uuid_text(manifest["stream_id"])
    require(type(manifest["revision"]) is int and manifest["revision"] >= 0, "backfill_revision")
    expected = packets(raw, values)
    alerts = {
        identity: rule
        for identity, packet in expected.items()
        if (rule := expected_rule(packet["signalbridge"])) is not None
    }
    require(
        manifest["packets"] == expected
        and manifest["expected_alerts"] == alerts
        and type(manifest["offset"]) is int
        and manifest["offset"] == len(raw)
        and manifest["sha256"] == sha(raw),
        "backfill_manifest_content",
    )
    batches = manifest["batches"]
    require(type(batches) is list and 0 < len(batches) <= MAX_RECORDS, "backfill_batch_limit")
    offset, count, ids = 0, 0, set()
    for batch in batches:
        require(
            type(batch) is dict and set(batch) == {"id", "offset", "bytes", "records", "sha256"},
            "backfill_batch_shape",
        )
        identity = uuid_text(batch["id"])
        require(identity not in ids, "backfill_batch_duplicate")
        ids.add(identity)
        require(
            all(type(batch[key]) is int for key in ("offset", "bytes", "records"))
            and batch["offset"] == offset
            and 0 < batch["bytes"] <= MAX_INPUT,
            "backfill_batch_offset",
        )
        chunk = raw[offset : offset + batch["bytes"]]
        require(
            sha(chunk) == batch["sha256"] and len(packets(chunk, values)) == batch["records"],
            "backfill_batch_content",
        )
        offset += batch["bytes"]
        count += batch["records"]
    require(offset == len(raw) and count == len(expected), "backfill_batch_inventory")
    return expected, alerts


def observations(raw, expected, *, alerts=False, complete=True, hostname=None, window=None):
    require(type(raw) is bytes and len(raw) <= MAX_OUTPUT, "backfill_output_size")
    require(not complete or not raw or raw.endswith(b"\n"), "backfill_incomplete_output")
    seen = Counter()
    rules = {}
    for line in raw.split(b"\n")[:-1]:
        row = prep.parse_json(line.decode("utf8"))
        require(
            type(row) is dict
            and row.get("location") == SPOOL
            and type(row.get("decoder")) is dict
            and row.get("decoder", {}).get("name") == "json",
            "backfill_observation_origin",
        )
        require(
            type(row.get("agent")) is dict and row["agent"].get("id") == "000",
            "backfill_observation_agent",
        )
        if hostname is not None:
            require(
                type(row.get("manager")) is dict and row["manager"].get("name") == hostname,
                "backfill_observation_manager",
            )
        require(type(row.get("data")) is dict, "backfill_observation_shape")
        data = row.get("data", {}).get("signalbridge")
        require(
            type(data) is dict and set(data) == prep.EXPORT_FIELDS, "backfill_observation_shape"
        )
        identity = data.get("event_id")
        require(type(identity) is str and identity in expected, "backfill_foreign_record")
        packet = expected[identity]
        normalized = dict(data)
        if normalized.get("export_version") == "1":
            normalized["export_version"] = 1
        require(
            type(normalized.get("export_version")) is int and normalized == packet["signalbridge"],
            "backfill_observation_content",
        )
        if window is not None:
            require(
                window[0] <= run_context.utc_time(row.get("timestamp")) <= window[1],
                "backfill_observation_time",
            )
        if alerts:
            rule = expected_rule(packet["signalbridge"])
            observed = row.get("rule", {})
            require(
                rule is not None
                and type(observed) is dict
                and "full_log" not in row
                and str(observed.get("id")) == rule[0]
                and type(observed.get("level")) is int
                and observed["level"] == rule[1],
                "backfill_alert_rule",
            )
            rules[identity] = rule[0]
        else:
            require(prep.parse_json(row.get("full_log", "")) == packet, "backfill_archive_content")
        seen[identity] += 1
        require(seen[identity] == 1 and len(seen) <= MAX_RECORDS, "backfill_duplicate_output")
    return rules if alerts else dict(seen)
