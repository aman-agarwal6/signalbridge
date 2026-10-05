"""Reconcile the fixed source proof, without equating delivery with detection.

Inputs are bounded synthetic receipts. They are neither signatures nor evidence
of a native execution by themselves: the host must additionally verify runtime,
source snapshot, raw-log identity and shutdown. No imports perform IO.
"""

import re
import uuid
from datetime import datetime, timezone

from bridge.contract import canonical, digest, timestamp, validate_event

APPS = ("documents", "expenses")
MAX_EVENTS = 80
MAX_CASES = 20
MAX_RECEIPT_BYTES = 262144
WORKER = "native-reference-proof"


class ReconciliationError(ValueError):
    """Closed error codes only; never echo a supplied value or body."""


def require(condition, code):
    if not condition:
        raise ReconciliationError(code)


def identifier(value):
    try:
        valid = isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        valid = False
    require(valid, "invalid_identifier")
    return value


def closed(value, fields):
    require(isinstance(value, dict) and set(value) == set(fields), "invalid_fields")


def expected_steps():
    """The operator's declared sequence, including the final restoration reads."""
    steps = {}
    for account in ("document_member", "expense_member", "operator", "outsider"):
        steps["authenticated_" + account] = {"passed": True}
    for app in APPS:
        for name, allowed in (
            ("allowed", True),
            ("outsider_denied", False),
            ("cross_app_denied", False),
        ):
            steps[app + "_" + name] = read_facts(allowed)
        steps[app + "_permission_removed"] = {"http_status": 200, "effective_access": False}
        steps[app + "_session_still_valid"] = {
            "http_status": 200,
            "identity_matched": True,
            "session_unchanged": True,
        }
        steps[app + "_removed_member_denied"] = read_facts(False)
        steps[app + "_owner_control"] = read_facts(True)
        if app == "documents":
            steps["bounded_regression_known_content"] = read_facts(True)
            steps["regression_reset_denied"] = read_facts(False)
            steps["documents_reset_owner_control"] = read_facts(True)
        steps[app + "_permission_restored"] = {"http_status": 200, "effective_access": True}
        steps[app + "_restored_known_content"] = read_facts(True)
        steps[app + "_alternate_grant_preserved"] = {"http_status": 200, "effective_access": True}
        steps[app + "_alternate_grant_content"] = read_facts(True)
    for app in APPS:
        steps[app + "_final_restore_known_content"] = read_facts(True)
    return steps


def read_facts(allowed):
    return {
        "http_status": 200 if allowed else 403,
        "observation": "known_content_returned" if allowed else "explicit_denial",
        "known_content": allowed,
    }


def _trace(value):
    closed(value, ("completed", "restoration_verified", "steps"))
    require(value["completed"] is True and value["restoration_verified"] is True, "incomplete_http")
    expected = expected_steps()
    rows = value["steps"]
    require(isinstance(rows, list) and len(rows) == len(expected), "incomplete_controls")
    result = {}
    for row, (name, facts) in zip(rows, expected.items(), strict=True):
        auth = name.startswith("authenticated_")
        fields = {"step", "passed", *facts} | (set() if auth else {"event_id"})
        closed(row, fields)
        require(row["step"] == name and row["passed"] is True, "incomplete_controls")
        # True == 1 in Python. Evidence flags and HTTP statuses need exact types.
        require(
            all(type(row[k]) is type(v) and row[k] == v for k, v in facts.items()),
            "control_predicate_changed",
        )
        no_event = auth or name.endswith(("session_still_valid", "alternate_grant_preserved"))
        if not auth:
            if no_event:
                require(row["event_id"] is None, "unexpected_assertion")
            else:
                identifier(row["event_id"])
        result[name] = row
    return result


def _events(rows, *, source, now):
    require(isinstance(rows, list) and 1 <= len(rows) <= MAX_EVENTS, "event_bound")
    fields = {"event_id", "app", "state", "digest", "payload"}
    fields |= (
        {"attempts"}
        if source
        else {"source", "processing_attempts", "processed_by", "processed_at"}
    )
    result = {}
    for row in rows:
        closed(row, fields)
        key = identifier(row["event_id"])
        require(key not in result, "duplicate_logical_event")
        require(isinstance(row["app"], str) and row["app"] in APPS, "unexpected_scope")
        payload = row["payload"]
        try:
            validate_event(payload, row["app"], now=now)
            require(len(canonical(payload)) <= 4096, "event_bound")
        except (ValueError, TypeError, OverflowError, RecursionError):
            raise ReconciliationError("invalid_event_contract") from None
        require(
            payload["event_id"] == key
            and payload["environment"] == "lab"
            and payload["context"] is None
            and payload["operation"] in ("private_record.read", "membership.change"),
            "unexpected_event_profile",
        )
        require(
            isinstance(row["digest"], str)
            and re.fullmatch("[a-f0-9]{64}", row["digest"])
            and row["digest"] == digest(payload),
            "digest_mismatch",
        )
        attempts = row["attempts" if source else "processing_attempts"]
        require(type(attempts) is int and 1 <= attempts <= MAX_EVENTS, "invalid_attempt_count")
        require(row["state"] == ("acknowledged" if source else "processed"), "incomplete_delivery")
        if not source:
            require(row["source"] == "instrumented_lab", "untrusted_provenance")
            require(row["processed_by"] == WORKER, "wrong_worker")
            try:
                at = timestamp(row["processed_at"])
                require(timestamp(payload["occurred_at"]) <= at <= now, "invalid_processing_time")
            except ValueError:
                raise ReconciliationError("invalid_processing_time") from None
        result[key] = row
    return result


def _bind_controls(trace, events):
    seen, payloads, actors = set(), {}, {}
    for name, row in trace.items():
        key = row.get("event_id")
        if key is None:
            continue
        require(key in events and key not in seen, "missing_or_reused_binding")
        seen.add(key)
        app = "expenses" if name.startswith("expenses_") else "documents"
        payload = events[key]["payload"]
        require(payload["app"] == app, "cross_app_binding")
        if "observation" in row:
            require(
                payload["schema_version"] == 1
                and payload["operation"] == "private_record.read"
                and payload["outcome"] == ("allowed" if row["known_content"] else "denied")
                and payload["reason"]
                == (
                    "owner"
                    if name.endswith("owner_control")
                    else "member"
                    if row["known_content"]
                    else "membership_required"
                ),
                "read_binding_changed",
            )
        else:
            require(
                payload["schema_version"] == 2
                and payload["operation"] == "membership.change"
                and payload["membership"]["state"]
                == ("removed" if name.endswith("permission_removed") else "granted"),
                "assertion_binding_changed",
            )
        payloads[name] = payload
    require(seen == set(events), "unexplained_logical_event")
    for app in APPS:
        member = payloads[app + "_allowed"]["actor"]
        owner = payloads[app + "_owner_control"]["actor"]
        outsider = payloads[app + "_outsider_denied"]["actor"]
        cross = payloads[app + "_cross_app_denied"]["actor"]
        require(len({member, owner, outsider, cross}) == 4, "identity_control_collapsed")
        actors[app] = {member, owner, outsider, cross}
        resource = payloads[app + "_allowed"]["resource"]
        episode = payloads[app + "_allowed"]["episode"]
        last = None
        for name, payload in payloads.items():
            if payload["app"] != app:
                continue
            require(
                payload["resource"] == resource and payload["episode"] == episode,
                "resource_control_changed",
            )
            at = timestamp(payload["occurred_at"])
            require(last is None or at > last, "ambiguous_source_order")
            last = at
            if payload["operation"] == "membership.change":
                require(
                    payload["actor"] == owner and payload["membership"]["subject"] == member,
                    "wrong_affected_account",
                )
            elif name.endswith("owner_control"):
                require(payload["actor"] == owner, "wrong_read_identity")
            elif not name.endswith(("outsider_denied", "cross_app_denied")):
                require(payload["actor"] == member, "wrong_read_identity")
    require(actors["documents"].isdisjoint(actors["expenses"]), "cross_app_pseudonym_reuse")
    require(
        payloads["documents_allowed"]["resource"] != payloads["expenses_allowed"]["resource"],
        "cross_app_pseudonym_reuse",
    )


def reconcile(execution, source, console, *, now=None):
    """Return finite, content-free reconciliation metrics or reject incomplete proof."""
    now = now or datetime.now(timezone.utc)
    require(now.tzinfo is not None and now.utcoffset() is not None, "invalid_clock")
    try:
        size = len(canonical([execution, source, console]))
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise ReconciliationError("invalid_receipt") from None
    require(size <= MAX_RECEIPT_BYTES, "receipt_bound")
    trace = _trace(execution)
    closed(source, ("events", "fault_enabled", "direct_grants"))
    closed(console, ("events", "cases"))
    require(
        source["fault_enabled"] is False
        and type(source["direct_grants"]) is int
        and source["direct_grants"] == 0,
        "restoration_incomplete",
    )
    sent = _events(source["events"], source=True, now=now)
    received = _events(console["events"], source=False, now=now)
    require(sent.keys() == received.keys(), "delivery_discrepancy")
    require(
        all(
            sent[key]["payload"] == received[key]["payload"]
            and sent[key]["digest"] == received[key]["digest"]
            for key in sent
        ),
        "delivery_discrepancy",
    )
    _bind_controls(trace, sent)
    cases = console["cases"]
    require(isinstance(cases, list) and 1 <= len(cases) <= MAX_CASES, "case_bound")
    # This profile contains only two resources and four denials at most per app.
    # It should produce one R3 case, without needing a suspicious source label.
    require(len(cases) == 1, "unexpected_case_count")
    case = cases[0]
    closed(case, ("case_id", "app", "rule", "severity", "status", "version", "evidence_event_ids"))
    identifier(case["case_id"])
    require(
        case["app"] == "documents"
        and case["rule"] == "R3"
        and case["severity"] == "high"
        and case["status"] == "open"
        and type(case["version"]) is int
        and case["version"] >= 1,
        "regression_detection_missing",
    )
    evidence = case["evidence_event_ids"]
    require(isinstance(evidence, list) and len(evidence) == 2, "invalid_case_evidence")
    require(
        set(map(identifier, evidence))
        == {
            trace["documents_permission_removed"]["event_id"],
            trace["bounded_regression_known_content"]["event_id"],
        },
        "wrong_regression_evidence",
    )
    logical = len(sent)
    attempts = sum(row["attempts"] for row in sent.values())
    return {
        "schema_version": 1,
        "profile": "reference-access-v2",
        "reconciled": True,
        "http_controls": len(trace),
        "logical_source_events": logical,
        "logical_processed_events": len(received),
        "committed_outbox_claims": attempts,
        "additional_outbox_claims": attempts - logical,
        "logical_cases": len(cases),
        "regression_case_id": case["case_id"],
        "regression_evidence_event_ids": sorted(evidence),
        "per_app_events": {app: sum(row["app"] == app for row in sent.values()) for app in APPS},
        "restoration_verified": True,
        "limitations": [
            "Reconciliation alone does not establish native runtime execution, TLS, PostgreSQL or verified shutdown.",
            "Committed outbox claims may precede a crash or validation rejection; they are not physical transport counts or duplicate acceptance.",
            "One fixed source regression is component proof, not detection accuracy or enterprise coverage.",
        ],
    }
