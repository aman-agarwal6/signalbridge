"""Bounded run identity shared by the local Wazuh driver and receipt importer.

This prevents accidental cross-run reuse, not forgery by the trusted host owner.
No filesystem, network or process operations occur here.
"""

import json
import re
import uuid
from datetime import datetime, timezone

MAX_CONTEXT_BYTES = 1024


def run_uuid(value):
    if not isinstance(value, str):
        raise ValueError("wazuh_run_identity")
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError("wazuh_run_identity")
    return parsed


def utc_time(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("wazuh_run_time")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(None):
        raise ValueError("wazuh_run_time")
    return parsed


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("wazuh_context_duplicate_key")
            result[key] = value
        return result

    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_CONTEXT_BYTES:
        raise ValueError("wazuh_context_size")
    value = json.loads(raw, object_pairs_hook=unique)
    if type(value) is not dict or set(value) != {
        "schema_version",
        "kind",
        "run_id",
        "prepared_at",
        "source_sha256",
    }:
        raise ValueError("wazuh_context_shape")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["kind"] != "signalbridge-wazuh-run-context"
        or not isinstance(value["source_sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["source_sha256"])
    ):
        raise ValueError("wazuh_context_shape")
    run_uuid(value["run_id"])
    utc_time(value["prepared_at"])
    return value


def event_id(run_id, fixture_id):
    """Stable within a run, disjoint across runs; fixture originals stay unchanged."""
    return str(uuid.uuid5(run_uuid(run_id), "signalbridge-wazuh:" + fixture_id))
