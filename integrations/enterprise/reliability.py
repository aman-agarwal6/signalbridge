"""Fixed workload and bounded event-ledger measurements; never native attestation.

This module opens no sockets, starts no processes, and changes no lab state.
Source observations must come from real HTTP paths in the eventual native driver.
Neither manufactured ledgers nor an accelerated replay establish a 24-hour run.
"""

import hashlib
import json
import re
import uuid
from collections import Counter
from dataclasses import dataclass
from heapq import merge

DAY_MS = 86_400_000
FINAL_DRAIN_MS = 600_000
APPS = ("documents", "expenses")
BURST_STARTS = tuple(hour * 3_600_000 for hour in (1, 4, 7, 10, 13, 16, 19, 22))
EXPECTED_EVENTS = 47_760
MAX_ROWS = 800_000
MAX_BYTES = 256 * 1024 * 1024
MAX_LINE_BYTES = 1024
PROFILE = "enterprise-reliability-v1"
HASH = re.compile(r"[0-9a-f]{64}\Z")
TOOL_ID = re.compile(r"[A-Za-z0-9_.:-]{1,80}\Z")
# Fixed windows are proposals for the eventual reviewed launch, not authorization.
INTERRUPTIONS = (
    ("workers", 7_200_000, 7_320_000, 7_620_000),
    ("collector", 18_000_000, 18_090_000, 18_390_000),
    ("source_delivery", 28_800_000, 28_980_000, 29_280_000),
    ("collector_rotation", 43_200_000, 43_260_000, 43_560_000),
    ("wazuh_connector", 61_200_000, 61_500_000, 61_800_000),
)


class LedgerError(ValueError):
    """Messages are closed codes, never input content or identifiers."""


@dataclass(frozen=True)
class Slot:
    index: int
    app: str
    due_ms: int
    phase: str


def schedule():
    """Integer offsets, balanced scopes, no normal traffic inside burst minutes."""
    normal = (
        (offset, APPS[(offset // 2000) % 2], "steady")
        for offset in range(0, DAY_MS, 2000)
        if not any(start <= offset < start + 60_000 for start in BURST_STARTS)
    )
    bursts = (
        (start + tick * 100, APPS[tick % 2], "burst")
        for start in BURST_STARTS
        for tick in range(600)
    )
    for index, (due, app, phase) in enumerate(merge(normal, bursts)):
        yield Slot(index, app, due, phase)


def declaration():
    """A content identity freezes targets/windows before any launch or results."""
    return {
        "profile": PROFILE,
        "status": "proposed_native_launch_unimplemented_and_unapproved",
        "duration_ms": DAY_MS,
        "maximum_final_drain_ms": FINAL_DRAIN_MS,
        "applications": list(APPS),
        "normal_interval_per_app_ms": 4000,
        "normal_app_stagger_ms": 2000,
        "burst_starts_ms": list(BURST_STARTS),
        "burst_duration_ms": 60_000,
        "burst_total_events_per_second": 10,
        "burst_semantics": "replace_normal_cadence",
        "expected_events": EXPECTED_EVENTS,
        "expected_events_per_app": EXPECTED_EVENTS // 2,
        "maximum_generation_lateness_ms": 250,
        # Revised before the measured run: lateness is judged when the workload
        # sends each read; the source's own recorded time is reported separately.
        "generation_lateness_basis": "workload_request_start",
        "source_response": "source_recorded_time_minus_request_start_reported_not_targeted",
        "clock": "run_origin_plus_vm_monotonic_tool_wall_times_mapped_by_samples",
        "ingestion_p95_strictly_below_ms": 500,
        "ingestion_population": "first_successful_acknowledgement_per_logical_event",
        "processing_p95_strictly_below_ms": 5000,
        "percentile": "nearest_rank",
        "latency_exclusion_basis": "sample_start_in_fixed_interruption_or_recovery_window",
        "interruptions": [
            {"component": name, "start_ms": start, "end_ms": end, "recover_by_ms": recovery}
            for name, start, end, recovery in INTERRUPTIONS
        ],
        "recovery_requirement": "every_source_event_created_before_end_reaches_processing_and_tool_by_recover_by",
        "required_additional_evidence": [
            "Reviewed launch profile, capacity/headroom checks and independent runtime watchdog.",
            "Native source HTTP observations, exact outbox/database/tool snapshots and artifact hashes.",
            "Measured monotonic 24-hour span, clock alignment, actual interruptions and recoveries.",
            "Two active worker identities and physical executions, including rolled-back attempts.",
            "Exact case/task identity reconciliation, idempotency and lost-reply evidence.",
            "Separate PostgreSQL/delivery-state restoration and a working restored application.",
            "Main and independent shutdown evidence, fault reset and final capacity readings.",
        ],
        "limits": "Event-ledger measurements alone cannot pass the enterprise reliability gate.",
    }


def declaration_hash():
    raw = json.dumps(declaration(), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _integer(value, minimum=0, maximum=DAY_MS + FINAL_DRAIN_MS):
    if type(value) is not int or not minimum <= value <= maximum:
        raise LedgerError("invalid_integer")
    return value


def _uuid(value):
    if not isinstance(value, str) or len(value) != 36:
        raise LedgerError("invalid_identifier")
    try:
        valid = str(uuid.UUID(value)) == value
    except ValueError:
        valid = False
    if not valid:
        raise LedgerError("invalid_identifier")
    return value


FIELDS = {
    "source": {"kind", "slot", "app", "event_id", "digest", "sent_ms", "at_ms"},
    "attempt": {"kind", "app", "event_id", "digest", "start_ms", "end_ms", "result"},
    "stored": {"kind", "app", "event_id", "digest", "accepted_ms", "processed_ms", "worker"},
    "tool": {"kind", "app", "event_id", "digest", "at_ms", "native_id"},
}


def _validated(row):
    if not isinstance(row, dict) or not isinstance(row.get("kind"), str):
        raise LedgerError("invalid_record")
    kind = row["kind"]
    if kind not in FIELDS or set(row) != FIELDS[kind]:
        raise LedgerError("invalid_fields")
    if row["app"] not in APPS or not isinstance(row["digest"], str):
        raise LedgerError("invalid_scope_or_digest")
    if not HASH.fullmatch(row["digest"]):
        raise LedgerError("invalid_scope_or_digest")
    key = (row["app"], _uuid(row["event_id"]))
    if kind == "source":
        _integer(row["slot"], maximum=EXPECTED_EVENTS - 1)
        _integer(row["sent_ms"])
        _integer(row["at_ms"])
    elif kind == "attempt":
        _integer(row["start_ms"])
        if row["result"] not in ("accepted", "duplicate", "retry", "rejected", "unknown"):
            raise LedgerError("invalid_attempt_result")
        if row["end_ms"] is None:
            if row["result"] != "unknown":
                raise LedgerError("missing_attempt_end")
        else:
            _integer(row["end_ms"], minimum=row["start_ms"])
    elif kind == "stored":
        _integer(row["accepted_ms"])
        if row["processed_ms"] is not None:
            _integer(row["processed_ms"], minimum=row["accepted_ms"])
            if row["worker"] not in ("worker-1", "worker-2"):
                raise LedgerError("invalid_worker")
        elif row["worker"] != "":
            raise LedgerError("worker_without_completion")
    else:
        _integer(row["at_ms"])
        if not isinstance(row["native_id"], str) or not TOOL_ID.fullmatch(row["native_id"]):
            raise LedgerError("invalid_tool_identifier")
    return kind, key


def _percentiles(samples):
    if not samples:
        return {"samples": 0, "p95_ms": None, "maximum_ms": None}
    ordered = sorted(samples)
    return {
        "samples": len(samples),
        "p95_ms": ordered[(len(ordered) * 95 + 99) // 100 - 1],
        "maximum_ms": ordered[-1],
    }


def _excluded(start):
    return any(begin <= start < recovery for _, begin, _, recovery in INTERRUPTIONS)


def measure(rows, *, elapsed_ms, profile_sha256):
    """Reconcile a closed synthetic ledger; retain missing and unknown outcomes.

    All offsets must share the native run's independently verified clock origin.
    Supplied elapsed time is checked for consistency, not certified as wall time.
    The result contains counts only, never raw IDs, source content or credentials.
    """
    _integer(elapsed_ms)
    if profile_sha256 != declaration_hash():
        raise LedgerError("profile_changed")
    slots = tuple(schedule())
    sources, by_slot, stored, tool, attempts = {}, {}, {}, {}, Counter()
    acknowledgements = {}
    digests, native_ids, attempt_results = {}, {}, Counter()
    anomalies = Counter()
    transport, transport_normal, ingestion, ingestion_normal = [], [], [], []
    processing, processing_normal = [], []
    source_response = []
    latest_attempt_end, earliest_attempt_start = {}, {}
    maximum_time = 0
    for count, row in enumerate(rows, 1):
        if count > MAX_ROWS:
            raise LedgerError("row_limit")
        kind, key = _validated(row)
        digest = row["digest"]
        if key in digests and digests[key] != digest:
            anomalies["conflicting_digests"] += 1
        digests.setdefault(key, digest)
        for field in ("sent_ms", "at_ms", "start_ms", "end_ms", "accepted_ms", "processed_ms"):
            if row.get(field) is not None:
                maximum_time = max(maximum_time, row[field])
        if kind == "source":
            slot = slots[row["slot"]]
            if slot.app != row["app"]:
                anomalies["wrong_app_slots"] += 1
            if not slot.due_ms <= row["sent_ms"] <= slot.due_ms + 250:
                anomalies["off_schedule_observations"] += 1
            if row["at_ms"] < row["sent_ms"]:
                anomalies["source_time_before_request"] += 1
            else:
                source_response.append(row["at_ms"] - row["sent_ms"])
            if key in sources:
                anomalies["duplicate_source_identities"] += 1
            if row["slot"] in by_slot:
                anomalies["duplicate_slots"] += 1
            sources.setdefault(key, row)
            by_slot.setdefault(row["slot"], key)
        elif kind == "attempt":
            attempts[key] += 1
            attempt_results[row["result"]] += 1
            earliest_attempt_start[key] = min(
                earliest_attempt_start.get(key, row["start_ms"]), row["start_ms"]
            )
            if row["end_ms"] is None:
                anomalies["unfinished_physical_attempts"] += 1
                latest_attempt_end[key] = elapsed_ms
            else:
                latest_attempt_end[key] = max(
                    latest_attempt_end.get(key, row["end_ms"]), row["end_ms"]
                )
                latency = row["end_ms"] - row["start_ms"]
                transport.append(latency)
                if not _excluded(row["start_ms"]):
                    transport_normal.append(latency)
                if row["result"] in ("accepted", "duplicate") and (
                    key not in acknowledgements or row["end_ms"] < acknowledgements[key]["end_ms"]
                ):
                    acknowledgements[key] = row
        elif kind == "stored":
            if key in stored:
                anomalies["duplicate_logical_database_rows"] += 1
            stored.setdefault(key, row)
        else:
            native_key = row["native_id"]
            if native_key in native_ids and native_ids[native_key] != key:
                anomalies["conflicting_native_identities"] += 1
            native_ids.setdefault(native_key, key)
            if key not in tool or row["at_ms"] < tool[key]["at_ms"]:
                tool[key] = row
            attempt_results["tool_physical_records"] += 1

    if maximum_time > elapsed_ms:
        raise LedgerError("observations_after_end")
    source_keys = set(sources)
    for label, observed in (("database", stored), ("tool", tool), ("attempt", attempts)):
        anomalies["unexpected_" + label + "_identities"] = len(set(observed) - source_keys)
    missing_attempts = len(source_keys - set(attempts))
    accepted_keys = source_keys & set(stored)
    completed = set()
    for key in source_keys & set(attempts):
        if earliest_attempt_start[key] < sources[key]["at_ms"]:
            anomalies["attempt_before_source"] += 1
    for key in source_keys & set(acknowledgements):
        row = acknowledgements[key]
        latency = row["end_ms"] - row["start_ms"]
        ingestion.append(latency)
        if not _excluded(row["start_ms"]):
            ingestion_normal.append(latency)
        if key not in stored or row["end_ms"] < stored[key]["accepted_ms"]:
            anomalies["acknowledgement_without_prior_acceptance"] += 1
    for key in accepted_keys:
        row, source = stored[key], sources[key]
        if row["accepted_ms"] < source["at_ms"]:
            anomalies["acceptance_before_source"] += 1
        if earliest_attempt_start.get(key, DAY_MS + FINAL_DRAIN_MS) > row["accepted_ms"]:
            anomalies["acceptance_without_prior_attempt"] += 1
        if key in latest_attempt_end and row["accepted_ms"] > latest_attempt_end[key]:
            anomalies["acceptance_after_attempts"] += 1
        if row["processed_ms"] is not None:
            completed.add(key)
            latency = row["processed_ms"] - row["accepted_ms"]
            processing.append(latency)
            if not _excluded(row["accepted_ms"]):
                processing_normal.append(latency)
    for key in source_keys & set(tool):
        if key not in stored or tool[key]["at_ms"] < stored[key]["accepted_ms"]:
            anomalies["tool_without_prior_acceptance"] += 1
    recovery = []
    for component, _, end, deadline in INTERRUPTIONS:
        due = {key for key, source in sources.items() if source["at_ms"] < end}
        late = sum(
            key not in completed
            or stored[key]["processed_ms"] > deadline
            or key not in tool
            or tool[key]["at_ms"] > deadline
            for key in due
        )
        recovery.append({"component": component, "events_due": len(due), "late_or_missing": late})
    ingest_stats, processing_stats = _percentiles(ingestion_normal), _percentiles(processing_normal)
    complete_population = (
        len(by_slot) == EXPECTED_EVENTS
        and len(source_keys) == EXPECTED_EVENTS
        and len(accepted_keys) == EXPECTED_EVENTS
        and len(completed) == EXPECTED_EVENTS
        and len(source_keys & set(tool)) == EXPECTED_EVENTS
        and len(source_keys & set(acknowledgements)) == EXPECTED_EVENTS
        and missing_attempts == 0
    )
    measurements_met = (
        elapsed_ms >= DAY_MS
        and complete_population
        and not any(anomalies.values())
        and not any(item["late_or_missing"] for item in recovery)
        and ingest_stats["p95_ms"] is not None
        and ingest_stats["p95_ms"] < 500
        and processing_stats["p95_ms"] is not None
        and processing_stats["p95_ms"] < 5000
    )
    return {
        "schema_version": 1,
        "profile": PROFILE,
        "profile_sha256": profile_sha256,
        "status": "ledger_targets_met" if measurements_met else "ledger_targets_not_met",
        "native_acceptance": "not_established_by_this_measurement",
        "declared_elapsed_ms": elapsed_ms,
        "expected_source_events": EXPECTED_EVENTS,
        "observed_slots": len(by_slot),
        "missing_slots": EXPECTED_EVENTS - len(by_slot),
        "source_events": len(source_keys),
        "source_events_per_app": dict(Counter(key[0] for key in source_keys)),
        "accepted_logical_events": len(accepted_keys),
        "processed_logical_events": len(completed),
        "tool_observed_logical_events": len(source_keys & set(tool)),
        "missing_acceptance": len(source_keys - set(stored)),
        "missing_processing": len(source_keys - completed),
        "missing_tool_observation": len(source_keys - set(tool)),
        "missing_transport_evidence": missing_attempts,
        "missing_acknowledgements": len(source_keys - set(acknowledgements)),
        "physical_transport_calls": sum(attempts.values()),
        "additional_transport_calls": sum(max(0, value - 1) for value in attempts.values()),
        "transport_and_tool_outcomes": dict(attempt_results),
        "tool_distinct_native_ids": len(native_ids),
        "tool_additional_physical_records": attempt_results["tool_physical_records"] - len(tool),
        "source_response": _percentiles(source_response),
        "transport_all_periods": _percentiles(transport),
        "transport_outside_fixed_windows": _percentiles(transport_normal),
        "ingestion_all_periods": _percentiles(ingestion),
        "ingestion_outside_fixed_windows": ingest_stats,
        "processing_all_periods": _percentiles(processing),
        "processing_outside_fixed_windows": processing_stats,
        "anomalies": dict(sorted(anomalies.items())),
        "recovery": recovery,
        "limitations": declaration()["required_additional_evidence"],
    }


def json_lines(stream):
    """Read finite binary JSONL; reject duplicate keys and non-JSON numbers."""
    total = 0

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise LedgerError("duplicate_json_field")
            result[key] = value
        return result

    def constant(_value):
        raise LedgerError("invalid_json_constant")

    for count in range(MAX_ROWS + 1):
        raw = stream.readline(MAX_LINE_BYTES + 1)
        if not raw:
            return
        total += len(raw)
        if len(raw) > MAX_LINE_BYTES or total > MAX_BYTES or count == MAX_ROWS:
            raise LedgerError("ledger_size_limit")
        if not raw.endswith(b"\n"):
            raise LedgerError("unfinished_json_line")
        try:
            row = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        except (ValueError, UnicodeError, RecursionError):
            raise LedgerError("invalid_json_record") from None
        _validated(row)
        yield row
