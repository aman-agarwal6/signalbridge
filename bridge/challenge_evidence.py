"""Closed validation and honest scoring for the fixed detection challenge profile."""

from bridge.contract import canonical
from bridge.simulation_evidence import finite, integer, require, stamp
from simulations.challenge_cases import PROFILE, catalog, declaration_sha256

LIMITS = [
    "Predeclared builder-authored cases; authors knew the rules. Not an independent blind holdout.",
    "Rule-contract checks and desired capability probes have separate denominators.",
    "A completed execution can contain contract failures and unsupported capabilities.",
    "Synthetic source labels are fixture metadata; no real access or attacker activity was observed.",
    "Membership changes lack an authoritative affected-member relationship in this event contract.",
    "In-process SQLite with accidental network/process guards; not production capacity or an OS sandbox.",
]


def score_rows(rows):
    """Validate identities/counts before deriving outcomes; never trust claimed pass flags."""
    cases = catalog()
    require(isinstance(rows, list) and len(rows) == len(cases), "challenge_rows_incomplete")
    contracts = []
    probes = []
    for case, row in zip(cases, rows, strict=True):
        require(
            isinstance(row, dict)
            and set(row)
            == {
                "id",
                "observed_rules",
                "case_count",
                "accepted",
                "duplicates",
                "processed",
            },
            "invalid_challenge_row",
        )
        require(row["id"] == case.id, "challenge_order_or_identity_mismatch")
        rules = row["observed_rules"]
        require(
            isinstance(rules, list)
            and len(rules) <= 2
            and all(isinstance(r, str) and r in {"R1", "R2"} for r in rules)
            and rules == sorted(set(rules)),
            "invalid_challenge_rules",
        )
        require(
            all(
                integer(row[k], 150) for k in ("case_count", "accepted", "duplicates", "processed")
            ),
            "invalid_challenge_counts",
        )
        unique = sum(r.repeat is None for r in case.readings)
        require(
            row["accepted"] == row["processed"] == unique
            and row["duplicates"] == len(case.readings) - unique,
            "challenge_delivery_reconciliation_failed",
        )
        require(
            bool(rules) == bool(row["case_count"]) and len(rules) <= row["case_count"] <= unique,
            "challenge_case_count_mismatch",
        )
        if case.category == "rule_contract":
            contracts.append(
                {
                    "id": case.id,
                    "met": rules == list(case.rules) and row["case_count"] == case.cases,
                }
            )
        else:
            # Probes describe desired coverage, not expected silence to be celebrated.
            probes.append({"id": case.id, "alert_observed": bool(rules)})
    return {
        "rule_contract": {
            "met": sum(r["met"] for r in contracts),
            "total": len(contracts),
            "failed_ids": [r["id"] for r in contracts if not r["met"]],
        },
        "capability_probes": {
            "alert_observed": sum(r["alert_observed"] for r in probes),
            "total": len(probes),
            "unmet_ids": [r["id"] for r in probes if not r["alert_observed"]],
        },
    }


def validate_result(report):
    require(
        isinstance(report, dict)
        and set(report)
        == {
            "schema_version",
            "kind",
            "declaration_sha256",
            "started_at",
            "finished_at",
            "execution_status",
            "database",
            "transport",
            "rows",
            "requests_executed",
            "records_processed",
            "duration_seconds",
            "summary",
        },
        "invalid_challenge_result",
    )
    require(
        type(report["schema_version"]) is int
        and report["schema_version"] == 1
        and report["kind"] == PROFILE
        and report["declaration_sha256"] == declaration_sha256(),
        "challenge_declaration_changed",
    )
    require(
        report["execution_status"] == "completed"
        and report["database"] == "disposable in-memory SQLite"
        and report["transport"] == "Django in-process test client",
        "challenge_execution_incomplete",
    )
    elapsed = (stamp(report["finished_at"]) - stamp(report["started_at"])).total_seconds()
    duration = report["duration_seconds"]
    require(
        finite(duration, 120)
        and duration > 0
        and 0 < elapsed <= 120
        and abs(elapsed - duration) <= 1,
        "invalid_challenge_duration",
    )
    summary = score_rows(report["rows"])
    require(canonical(report["summary"]) == canonical(summary), "challenge_summary_mismatch")
    requests = sum(len(case.readings) for case in catalog())
    processed = sum(sum(r.repeat is None for r in case.readings) for case in catalog())
    require(
        integer(report["requests_executed"], 150)
        and report["requests_executed"] == requests
        and integer(report["records_processed"], 150)
        and report["records_processed"] == processed,
        "challenge_total_reconciliation_failed",
    )
    status = (
        "failed"
        if summary["rule_contract"]["failed_ids"]
        else "partial"
        if summary["capability_probes"]["unmet_ids"]
        else "passed"
    )
    return status, report


def display_rows(report):
    validate_result(report)
    rows = []
    for case, observed in zip(catalog(), report["rows"], strict=True):
        probe = case.category == "capability_probe"
        rows.append(
            {
                **observed,
                "title": case.title,
                "purpose": case.purpose,
                "category": "Capability probe" if probe else "Rule contract",
                "expected": "Desired: at least one alert"
                if probe
                else f"{', '.join(case.rules) or 'No alert'}; {case.cases} case(s)",
                "met": bool(observed["observed_rules"])
                if probe
                else observed["observed_rules"] == list(case.rules)
                and observed["case_count"] == case.cases,
            }
        )
    return rows
