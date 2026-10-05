"""Assemble the closed reliability ledger from retained native evidence.

Pure functions over bytes; no Docker, network or database. Every row is checked
by reliability.measure afterwards. Unknown or unmatched outcomes are retained.
"""

import json
from collections import defaultdict
from datetime import datetime

from bridge.contract import digest, timestamp

from .lab_clock import WallMapping
from .reliability import APPS, DAY_MS, FINAL_DRAIN_MS, INTERRUPTIONS, LedgerError

WAZUH_WINDOWS = ("collector_rotation", "wazuh_connector")


def require(condition, code="ledger_input"):
    if not condition:
        raise LedgerError(code)


def lines(raw, limit=800_000):
    require(isinstance(raw, bytes))
    rows = []
    for count, line in enumerate(raw.splitlines(), 1):
        require(count <= limit, "ledger_line_limit")
        if line.strip():
            rows.append(json.loads(line))
    return rows


def wazuh_plan(run_id, scale=1.0):
    """Stop/start windows the Wazuh driver applies; scale shortens rehearsals only."""
    require(type(scale) is float and 0 < scale <= 1, "window_scale")
    rows = []
    for name, start, end, _ in INTERRUPTIONS:
        if name in WAZUH_WINDOWS:
            rows.append({"component": name, "action": "stop", "at_ms": int(start * scale)})
            rows.append({"component": name, "action": "start", "at_ms": int(end * scale)})
    return {"run_id": run_id, "mode": "continuous", "windows": rows}


def attempts(raw_files):
    """Pair durable start/end records; a start without an end is an unknown call."""
    started, ended = {}, {}
    for raw in raw_files:
        for row in lines(raw):
            key = (row["app"], row["event_id"], row["start_ms"])
            require(row["phase"] in ("start", "end"), "attempt_phase")
            target = started if row["phase"] == "start" else ended
            require(key not in target, "attempt_duplicate_record")
            target[key] = row
    require(set(ended) <= set(started), "attempt_end_without_start")
    result = []
    for key, start in sorted(started.items(), key=lambda item: item[0][2]):
        end = ended.get(key)
        result.append(
            {
                "kind": "attempt",
                "app": start["app"],
                "event_id": start["event_id"],
                "digest": start["digest"],
                "start_ms": start["start_ms"],
                "end_ms": end["end_ms"] if end else None,
                "result": end["result"] if end else "unknown",
            }
        )
    return result


def tool_rows(archive_lines, sources, origin, mapping=None):
    """Bind native archived observations to their source events by content."""
    rows = []
    # Wazuh ids are not unique per event, so the physical capture ordinal makes
    # each native record distinct; repeated events stay extra physical records.
    for ordinal, record in enumerate(archive_lines):
        data = record.get("data") if isinstance(record, dict) else None
        packet = data.get("signalbridge") if isinstance(data, dict) else None
        if not isinstance(packet, dict):
            continue
        key = (packet.get("app"), packet.get("event_id"))
        source = sources.get(key)
        if source is None:
            continue
        native = record.get("id")
        require(isinstance(native, str) and len(native) <= 60, "tool_native_id")
        at = timestamp(_wazuh_time(record.get("timestamp")))
        wall_ms = int((at - origin).total_seconds() * 1000)
        rows.append(
            {
                "kind": "tool",
                "app": key[0],
                "event_id": key[1],
                "digest": source["digest"],
                # Wazuh stamps records with the VM wall clock; map onto the lab timeline.
                "at_ms": (mapping.lab_ms(wall_ms) if mapping else wall_ms),
                "native_id": native + ":" + str(ordinal),
            }
        )
    return rows


def _wazuh_time(value):
    """Wazuh writes +0000 offsets; normalize to an ISO offset before parsing."""
    require(isinstance(value, str) and len(value) <= 40, "tool_timestamp")
    if len(value) > 5 and value[-5] in "+-" and value[-4:].isdigit():
        value = value[:-2] + ":" + value[-2:]
    return value


def request_starts(requests_raw):
    """Each read's send time from the workload journal, keyed by slot."""
    starts = {}
    for row in lines(requests_raw):
        if row.get("kind") == "read_started":
            require(row["slot"] not in starts, "duplicate_read_start")
            starts[row["slot"]] = row["at_ms"]
    return starts


def assemble(
    *,
    source_raw,
    attempt_files,
    stored_raw,
    archive_raw,
    origin,
    samples_raw=b"",
    requests_raw=b"",
):
    require(isinstance(origin, datetime) and origin.utcoffset() is not None, "ledger_origin")
    source = [row for row in lines(source_raw) if row.get("kind") == "source"]
    # Schedule adherence is judged when the workload sent each read.
    starts = request_starts(requests_raw)
    for row in source:
        require(row["slot"] in starts, "source_without_request")
        row["sent_ms"] = starts[row["slot"]]
    by_key = {(row["app"], row["event_id"]): row for row in source}
    stored = lines(stored_raw)
    samples = [(row["lab_ms"], row["wall_ms"]) for row in lines(samples_raw, limit=200_000)]
    mapping = WallMapping(samples) if samples else None
    tool = tool_rows(lines(archive_raw), by_key, origin, mapping)
    maximum = DAY_MS + FINAL_DRAIN_MS
    counts, kept = defaultdict(int), []
    for row in [*source, *attempts(attempt_files), *stored, *tool]:
        require(row.get("app") in APPS, "ledger_scope")
        times = [
            row[field]
            for field in ("sent_ms", "at_ms", "start_ms", "end_ms", "accepted_ms", "processed_ms")
            if row.get(field) is not None
        ]
        require(all(type(value) is int and value >= 0 for value in times), "ledger_offset")
        # Never alter evidence: an observation after the declared window is
        # excluded and counted, so the analyzer reports that event as missing.
        if any(value > maximum for value in times):
            counts["after_window_" + row["kind"]] += 1
            continue
        counts[row["kind"]] += 1
        kept.append(row)
    return kept, dict(counts)


def stored_row(event, origin):
    """Console-side row shape, computed from committed database timestamps."""
    accepted = int((event["received_at"] - origin).total_seconds() * 1000)
    processed = (
        int((event["processed_at"] - origin).total_seconds() * 1000)
        if event["processed_at"] is not None
        else None
    )
    return {
        "kind": "stored",
        "app": event["app"],
        "event_id": event["event_id"],
        "digest": event["digest"] if event["digest"] == digest(event["payload"]) else "0" * 64,
        "accepted_ms": accepted,
        "processed_ms": processed,
        "worker": event["processed_by"] if processed is not None else "",
    }
