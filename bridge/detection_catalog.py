"""Explain the bounded rules and their evidence without inventing risk or confidence scores."""

import hashlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .case_provenance import case_generation
from .engine import detections

RULES = {
    "R1": {
        "id": "R1",
        "name": "Repeated private-resource access failures",
        "severity": "medium",
        "intent": "Find repeated attempts across distinct private resources for investigation.",
        "logic": "Three or more distinct resources from private_record.read events with denied or not_visible outcomes within a rolling five-minute window (inclusive), for one app, environment, evidence source and actor. Cases group qualifying window endpoints into fixed UTC five-minute buckets; a case's combined evidence may span more than five minutes.",
        "inputs": "app, environment, key-bound source, operation, actor, resource, outcome, occurred_at, event_id",
        "false_positives": "A legitimate user following expired links, stale memberships or unavailable records can produce this pattern. Repeated requests for one resource do not meet the threshold.",
        "blind_spots": "Attempts spread beyond five minutes may not alert. Sustained activity can create related cases in adjacent endpoint buckets. Missing source events cannot be detected from an empty queue. Actor pseudonyms from different lab runs are not a shared identity.",
        "priority_reason": "Medium review priority reflects repetition; it is not a probability of malicious activity.",
        "validation": [
            "Check whether the evidence is observed lab activity, a synthetic fixture, or an unclassified older record.",
            "Confirm at least three distinct resources fall within a qualifying five-minute window. A case may combine several such windows. Keep denied and not_visible outcomes separate.",
            "Confirm expected membership and resource existence in the controlled source environment. An empty query result alone proves neither.",
            "Reproduce the authorized and unauthorized paths, record the explanation, then retest after any scoped fix.",
        ],
    },
    "R2": {
        "id": "R2",
        "name": "Allowed access after a reported boundary change",
        "severity": "critical",
        "intent": "Prioritize a source report that access succeeded after removal or during a controlled policy regression.",
        "logic": "A private_record.read event with an allowed outcome and reason membership_removed or policy_regression. The source supplies that reason; SignalBridge does not independently infer revocation from another event.",
        "inputs": "app, environment, key-bound source, operation, event_id, actor, resource, outcome, reason",
        "false_positives": "A mislabeled source operation, a deliberately injected lab fault, or an incorrect revocation assumption can produce the signal. It does not establish a live breach.",
        "blind_spots": "The detector cannot independently prove resource sensitivity, revocation timing, source correctness, or an attacker's intent. Uninstrumented reads remain invisible.",
        "priority_reason": "Critical review priority reflects the potential permission failure if the source account is correct. Exploitability and real-world impact remain unverified.",
        "validation": [
            "Establish whether policy_regression denotes an intentional disposable fault or an unexpected result.",
            "Verify the same identity still has a valid session and its membership was actually removed before the read.",
            "Check that a real private resource was returned, rather than an empty result, error or administrative bypass.",
            "Contain only within an authorized environment; correct the source permission boundary and run positive, negative and restoration tests.",
        ],
    },
}


def _disk_fingerprint():
    directory = Path(__file__).parent
    try:
        return hashlib.sha256(
            b"".join(
                (directory / name).read_bytes()
                for name in ("engine.py", "contract.py", "worker.py")
            )
        ).hexdigest()
    except OSError:
        return None


# The local launcher imports this module during startup. Freeze that source snapshot;
# rereading edited files must never silently change an already-running process's identity.
# This assumes coherent source at startup, not an attestation of loaded Python bytecode.
_PROCESS_SOURCE_SHA256 = _disk_fingerprint()


def engine_fingerprint():
    return _PROCESS_SOURCE_SHA256


def engine_source_state():
    disk = _disk_fingerprint()
    captured = engine_fingerprint()
    status = (
        "unavailable"
        if disk is None or captured is None
        else "unchanged"
        if disk == captured
        else "changed"
    )
    return {
        "process_source_sha256": captured,
        "disk_source_sha256": disk,
        "status": status,
        "restart_required": status != "unchanged",
        "scope": "Source snapshot at catalog module import; assumes coherent startup files, not bytecode attestation.",
    }


def explain_case(case, events, *, evidence_complete=True):
    """Use linked, app-scoped records only; current comparison is not historical attestation."""
    events = sorted(events, key=lambda e: (e.occurred_at, str(e.event_id)))
    rule = RULES.get(case.rule)
    cohorts = {(e.environment, e.source, e.actor) for e in events}
    generation = case_generation(case, events, engine_fingerprint(), complete=evidence_complete)
    integrity_errors = generation["integrity_errors"]
    matches = False
    comparison = "No comparable linked evidence"
    source_state = engine_source_state()
    if source_state["restart_required"]:
        comparison = "Source identity changed or is unavailable; restore readable source and restart before comparing rules"
    elif events and rule and len(cohorts) == 1 and not integrity_errors:
        try:
            current = detections([event.payload for event in events])
            matches = any(
                row["rule"] == case.rule
                and hashlib.sha256(
                    (events[0].source + "|" + row["correlation"]).encode()
                ).hexdigest()
                == case.correlation
                for row in current
            )
            comparison = (
                "Current rule matches linked evidence"
                if matches
                else "Current rule does not reproduce this case"
            )
        except (KeyError, TypeError, ValueError, OverflowError):
            comparison = "Linked evidence could not be evaluated"
    elif integrity_errors:
        comparison = "Stored evidence consistency needs review"
    elif len(cohorts) > 1:
        comparison = "Mixed correlation scope needs review"
    # A file edit during comparison must not leave an apparently current result.
    if not source_state["restart_required"]:
        source_state = engine_source_state()
        if source_state["restart_required"]:
            matches = False
            comparison = "Source identity changed or is unavailable; restore readable source and restart before comparing rules"
    buckets = sorted({int(event.occurred_at.timestamp()) // 300 * 300 for event in events})
    return {
        "rule": rule,
        "engine_sha256": engine_fingerprint(),
        "engine_source_state": source_state,
        "generation": generation,
        "comparison": comparison,
        "current_match": matches,
        "integrity_errors": integrity_errors,
        "event_count": len(events),
        "distinct_resources": len({e.resource for e in events}),
        "actors": sorted({e.actor for e in events}),
        "environments": sorted({e.environment for e in events}),
        "sources": sorted({e.get_source_display() for e in events}),
        "outcomes": dict(Counter(e.outcome for e in events)),
        "reasons": dict(Counter(e.reason for e in events)),
        "first_at": events[0].occurred_at.isoformat() if events else None,
        "last_at": events[-1].occurred_at.isoformat() if events else None,
        "bucket_starts": [
            datetime.fromtimestamp(value, timezone.utc).isoformat() for value in buckets
        ],
        "limits": [
            "The current-rule comparison is separate from a recorded generation snapshot; historical cases without one remain unrecorded.",
            "The process source fingerprint was captured at module import. It assumes coherent startup files and is not independent attestation of loaded bytecode. Disk drift disables the current-rule match claim until restart.",
            "Rolling-window R1 uses a new case identity. Older fixed-bucket cases remain historical and are not silently relabeled as current-rule results.",
            "A matching digest checks stored consistency, not independent truth or protection from a database administrator.",
            "Priority expresses review urgency. Confidence, exploitability and production impact are not scored.",
        ],
    }
