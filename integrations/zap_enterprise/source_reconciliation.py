"""Exact source-event/delivery reconciliation; no inference of native execution."""

import hashlib
from datetime import datetime, timezone

from bridge.contract import canonical, timestamp
from integrations.enterprise.reference_reconciliation import _events, closed

from .capture import PROFILE, identifier, require, validate_pair

SUMMARY_FIELDS = {
    "profile",
    "completed",
    "native_zap_executed",
    "failure",
    "fault_disabled",
    "restoration_checks",
    "restoration_event_ids",
    "phase_requests",
    "phase_attempted_requests",
    "captured_at",
    "response_digests",
}


def reconcile(summary, phases, source, console, *, now=None):
    now = now or datetime.now(timezone.utc)
    require(len(canonical([summary, phases, source, console])) <= 262144)
    closed(summary, SUMMARY_FIELDS)
    require(
        summary["profile"] == PROFILE
        and summary["completed"] is True
        and summary["native_zap_executed"] is False
    )
    require(summary["failure"] == "" and summary["fault_disabled"] is True)
    accounts = {"document_member", "operator"}
    require(
        summary["restoration_checks"] == {name: True for name in accounts}
        and all(type(v) is bool for v in summary["restoration_checks"].values())
    )
    closed(summary["restoration_event_ids"], accounts)
    for field in ("phase_requests", "phase_attempted_requests"):
        require(
            summary[field] == {"fault": 5, "corrected": 5}
            and all(type(v) is int for v in summary[field].values())
        )
    validate_pair(phases)
    require(timestamp(summary["captured_at"]) <= now)
    closed(summary["response_digests"], ("fault", "corrected"))
    require(
        summary["response_digests"]
        == {
            phase: [hashlib.sha256(row["body"].encode()).hexdigest() for row in rows]
            for phase, rows in phases.items()
        }
    )
    closed(source, ("events", "fault_enabled", "direct_grants", "header_fault"))
    closed(console, ("events", "cases"))
    require(
        source["fault_enabled"] is False
        and type(source["direct_grants"]) is int
        and source["direct_grants"] == 0
    )
    closed(source["header_fault"], ("enabled", "scope", "started_at", "expires_at"))
    fault = source["header_fault"]
    require(
        fault["enabled"] is False
        and fault["scope"] == "fixed synthetic document/member header only"
    )
    start, end = timestamp(fault["started_at"]), timestamp(fault["expires_at"])
    require(start <= now and 0 < (end - start).total_seconds() <= 600)
    require(
        start
        <= timestamp(phases["fault"][0]["started_at"])
        <= timestamp(phases["fault"][-1]["started_at"])
        < end
    )
    sent, received = (
        _events(source["events"], source=True, now=now),
        _events(console["events"], source=False, now=now),
    )
    require(len(sent) == 8 and sent.keys() == received.keys() and console["cases"] == [])
    require(
        all(
            sent[key]["payload"] == received[key]["payload"]
            and sent[key]["digest"] == received[key]["digest"]
            for key in sent
        )
    )
    bindings, subjects, resources = {}, {}, {}
    for phase in ("fault", "corrected"):
        for row in phases[phase]:
            if row["event_id"] is None:
                continue
            key = identifier(row["event_id"])
            require(key in sent and key not in bindings)
            app = "expenses" if row["http_status"] == 403 else "documents"
            expected = {
                "operation": "private_record.read",
                "outcome": "denied" if app == "expenses" else "allowed",
                "reason": "membership_required"
                if app == "expenses"
                else "owner"
                if row["account"] == "operator"
                else "member",
            }
            payload = sent[key]["payload"]
            require(
                payload["app"] == app
                and payload["schema_version"] == 1
                and all(payload[k] == v for k, v in expected.items())
            )
            require(
                timestamp(payload["occurred_at"]) >= timestamp(row["started_at"])
                and timestamp(payload["occurred_at"]) <= timestamp(summary["captured_at"])
            )
            principal = (app, row["account"])
            require(principal not in subjects or subjects[principal] == payload["actor"])
            subjects[principal] = payload["actor"]
            asset = (payload["resource"], payload["episode"])
            require(app not in resources or resources[app] == asset)
            resources[app] = asset
            bindings[key] = expected
    require(
        subjects[("documents", "document_member")] != subjects[("documents", "operator")]
        and subjects[("documents", "document_member")] != subjects[("expenses", "document_member")]
    )
    require(resources["documents"][0] != resources["expenses"][0])
    for account, key in summary["restoration_event_ids"].items():
        key = identifier(key)
        require(key in sent and key not in bindings)
        payload = sent[key]["payload"]
        require(
            payload["app"] == "documents"
            and payload["schema_version"] == 1
            and payload["operation"] == "private_record.read"
            and payload["outcome"] == "allowed"
            and payload["reason"] == ("owner" if account == "operator" else "member")
        )
        require(
            payload["actor"] == subjects[("documents", account)]
            and (payload["resource"], payload["episode"]) == resources["documents"]
        )
        require(
            timestamp(payload["occurred_at"]) >= timestamp(phases["corrected"][-1]["started_at"])
            and timestamp(payload["occurred_at"]) <= timestamp(summary["captured_at"])
        )
        bindings[key] = {"restoration": True}
    require(set(bindings) == set(sent))
    return {
        "profile": PROFILE,
        "reconciled": True,
        "logical_source_events": 8,
        "logical_processed_events": 8,
        "logical_cases": 0,
        "source_outbox_claims": sum(row["attempts"] for row in sent.values()),
        "worker_committed_attempts": sum(row["processing_attempts"] for row in received.values()),
        "runtime_attested": False,
        "source_capture_attested": False,
    }
