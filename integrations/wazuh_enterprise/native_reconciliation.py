"""Closed native bootstrap reconciliation; parsing never attests an execution.

Expected packets come from the idle export snapshot, not a handpicked subset of
native output. Custom alerts and archive inputs must reconcile, with native
copies and repeated tool IDs counted separately from logical source records.
"""

import hashlib
import os
from collections import Counter

from bridge.contract import canonical, parse_json

from .collector_profile import recipe
from .contract import (
    expected_rule,
    require,
    segmented_location,
    validate_native_record,
    validate_observation,
    validate_signal,
)
from .export_snapshot import _plain, inspect_exports, manifest

MAX_NATIVE_FILE_BYTES = 4 * 1024**2
MAX_NATIVE_RECORD_BYTES = 16384
MAX_NATIVE_COPIES = 3
CUSTOM_IDS = {"100211", "100212", "100213", "100221", "100222", "100223"}


def _identity(packet):
    channel = "detection" if "signalbridge_detection" in packet else "observation"
    row = (validate_observation if channel == "observation" else validate_signal)(packet)
    return row["app"], channel, row["event_id" if channel == "observation" else "signal_id"]


def expected_exports(root, raw_manifest):
    inspected = inspect_exports(root, raw_manifest)
    limits = recipe()["input"]
    require(
        inspected["logical_records"] <= limits["bootstrap_logical_records"],
        "native_bootstrap_record_limit",
    )
    require(
        sum(row["bytes"] for row in inspected["streams"]) <= limits["bootstrap_input_bytes"],
        "native_bootstrap_input_limit",
    )
    require(
        all(
            inspected["scope_counts"][f"{app}/observation"] > 0 for app in ("documents", "expenses")
        ),
        "native_bootstrap_missing_app",
    )
    expected = {}
    for stream in manifest(raw_manifest)["streams"]:
        stem = "observations" if stream["channel"] == "observation" else "detections"
        for segment in stream["segments"]:
            path = root / stream["app"] / stream["channel"] / f"{stem}-{segment['number']:03}.jsonl"
            before = _plain(path, directory=False)
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            with os.fdopen(os.open(path, flags), "rb") as handle:
                opened = os.fstat(handle.fileno())
                require(
                    (opened.st_dev, opened.st_ino, opened.st_size, opened.st_nlink)
                    == (before.st_dev, before.st_ino, segment["bytes"], 1),
                    "native_bootstrap_input_changed",
                )
                raw = handle.read(segment["bytes"] + 1)
                after = os.fstat(handle.fileno())
                require(
                    (after.st_size, after.st_mtime_ns) == (opened.st_size, opened.st_mtime_ns),
                    "native_bootstrap_input_changed",
                )
            _plain(path, directory=False)
            require(
                len(raw) == segment["bytes"]
                and hashlib.sha256(raw).hexdigest() == segment["sha256"],
                "native_bootstrap_input_changed",
            )
            for line in raw.splitlines(keepends=True):
                packet = parse_json(line)
                key = _identity(packet)
                require(key not in expected, "native_bootstrap_duplicate_input")
                expected[key] = (
                    packet,
                    segmented_location(stream["app"], stream["channel"], segment["number"]),
                )
    require(len(expected) == inspected["logical_records"], "native_bootstrap_input_count")
    return expected


def reconcile(archives, alerts, expected, *, now, final=False):
    require(
        type(expected) is dict and 0 < len(expected) <= 128, "native_bootstrap_expected_inventory"
    )
    counts = {"archive": Counter(), "alert": Counter()}
    tool_ids = {"archive": {}, "alert": {}}
    partial = {}
    noncustom_alerts = 0
    for kind, raw in (("archive", archives), ("alert", alerts)):
        require(
            isinstance(raw, bytes) and len(raw) <= MAX_NATIVE_FILE_BYTES,
            "native_bootstrap_output_limit",
        )
        partial[kind] = bool(raw and not raw.endswith(b"\n"))
        require(not final or not partial[kind], "native_bootstrap_incomplete_output")
        for line in raw.split(b"\n")[:-1]:
            require(0 < len(line) <= MAX_NATIVE_RECORD_BYTES, "native_bootstrap_record_size")
            value = parse_json(line)
            require(type(value) is dict, "native_bootstrap_record_shape")
            decoded = value.get("data")
            require(type(decoded) is dict and len(decoded) == 1, "native_bootstrap_decoded_shape")
            key_name = next(iter(decoded))
            require(
                key_name in {"signalbridge", "signalbridge_detection"}
                and type(decoded[key_name]) is dict,
                "native_bootstrap_decoded_shape",
            )
            channel = "observation" if key_name == "signalbridge" else "detection"
            row = decoded[key_name]
            key = (
                row.get("app"),
                channel,
                row.get("event_id" if channel == "observation" else "signal_id"),
            )
            require(all(isinstance(part, str) for part in key), "native_bootstrap_decoded_identity")
            require(key in expected, "native_bootstrap_unexpected_record")
            packet, location = expected[key]
            require(
                _identity(packet) == key and value.get("location") == location,
                "native_bootstrap_record_binding",
            )
            if kind == "alert":
                rule = value.get("rule")
                require(
                    type(rule) is dict and isinstance(rule.get("id"), str),
                    "native_bootstrap_alert_rule",
                )
                if rule["id"] not in CUSTOM_IDS:
                    # Its presence fails bootstrap acceptance rather than being
                    # silently filtered to make the negative controls favorable.
                    noncustom_alerts += 1
                    continue
            validate_native_record(value, packet, kind, now=now)
            signature = hashlib.sha256(canonical(value)).hexdigest()
            # Wazuh derives "id" from the epoch second and the alerts-file
            # offset, so different events archived in one second share it.
            # A conflict is one id carrying different content for one record.
            native_id = (value["id"], key)
            require(
                native_id not in tool_ids[kind] or tool_ids[kind][native_id] == signature,
                "native_bootstrap_tool_id_conflict",
            )
            tool_ids[kind][native_id] = signature
            counts[kind][key] += 1
            require(counts[kind][key] <= MAX_NATIVE_COPIES, "native_bootstrap_duplicate_bound")
    expected_alerts = {
        key for key, (packet, _) in expected.items() if expected_rule(packet) is not None
    }
    complete = (
        not any(partial.values())
        and set(counts["archive"]) == set(expected)
        and set(counts["alert"]) == expected_alerts
        and not noncustom_alerts
    )
    return {
        "native_record_format_verified": not noncustom_alerts,
        "expected_logical_inputs": len(expected),
        "archived_logical_inputs": len(counts["archive"]),
        "missing_archive_inputs": len(expected.keys() - counts["archive"].keys()),
        "expected_alert_inputs": len(expected_alerts),
        "alerted_logical_inputs": len(counts["alert"]),
        "missing_alert_inputs": len(expected_alerts - counts["alert"].keys()),
        "physical_archive_copies": sum(counts["archive"].values()),
        "physical_alert_copies": sum(counts["alert"].values()),
        "distinct_archive_tool_ids": len(tool_ids["archive"]),
        "distinct_alert_tool_ids": len(tool_ids["alert"]),
        "repeated_archive_tool_ids": sum(counts["archive"].values()) - len(tool_ids["archive"]),
        "repeated_alert_tool_ids": sum(counts["alert"].values()) - len(tool_ids["alert"]),
        "extra_archive_copies": sum(counts["archive"].values()) - len(counts["archive"]),
        "extra_alert_copies": sum(counts["alert"].values()) - len(counts["alert"]),
        "unexpected_noncustom_alerts": noncustom_alerts,
        "partial_native_files": partial,
        "bootstrap_counts_match": complete,
        "genuine_source_execution_verified": False,
        "native_runtime_execution_verified": False,
        "continuous_delivery_verified": False,
        "forwarded_detections_are_independent_wazuh_rediscovery": False,
    }
