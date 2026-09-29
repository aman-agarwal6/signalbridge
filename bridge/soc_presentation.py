"""Historical pilot presentation, scoped to imported self-assurance evidence."""

import hashlib
import json
import re
import uuid
from datetime import datetime

from integrations.wazuh.run_context import utc_time

from .models import CheckRun

TOOLS = ("wazuh", "zap")
SHA = re.compile(r"[0-9a-f]{64}\Z")
METRICS = {
    "wazuh": (
        ("logtest_cases", "Actual rule-engine cases"),
        ("collection_inputs", "File-collection inputs"),
        ("alerts", "Expected synthetic alerts observed"),
        ("negative_controls", "Collection controls without custom alerts"),
        ("tail_sentinels", "Included collection tail sentinel"),
    ),
    "zap": (
        ("requests", "Fixed GET requests"),
        ("header_positive_paths", "Expected header signals"),
        ("header_negative_paths", "Header control without the signal"),
        ("reported_findings", "Sanitized report findings"),
    ),
}
EXPECTED_COUNTS = {
    "wazuh": {
        "logtest_cases": 27,
        "collection_inputs": 19,
        "fixture_inputs": 18,
        "tail_sentinels": 1,
        "alerts": 12,
        "negative_controls": 7,
    },
    "zap": {"requests": 3, "header_positive_paths": 2, "header_negative_paths": 1},
}

RULE_MEANINGS = {
    "100201": (
        12,
        "Allowed access flagged by source context. Verify the underlying removal and read evidence before calling it a vulnerability.",
    ),
    "100202": (
        5,
        "Synthetic allowed-access scenario. This exercises a rule; it does not establish a real application flaw.",
    ),
    "100203": (
        3,
        "Denied read. This can indicate that the control worked; it does not establish an attack.",
    ),
    "100204": (3, "Record not visible. Absence alone does not establish an authorization denial."),
    "100205": (
        4,
        "Dependency failure. The security conclusion may be inconclusive until the service is restored and the check repeated.",
    ),
}


def bound_observations(pilot, provenance):
    binding = pilot.get("run_binding")
    if binding is None:
        return []
    if (
        type(binding) is not dict
        or set(binding)
        != {
            "version",
            "run_id",
            "started_at",
            "finished_at",
            "context_sha256",
            "alerts_sha256",
            "observations",
        }
        or type(binding["version"]) is not int
        or binding["version"] != 2
        or binding["run_id"] != pilot["run_id"]
    ):
        raise ValueError("Invalid run binding")
    for key, receipt_key in (("context_sha256", "run_context"), ("alerts_sha256", "alerts")):
        if (
            not SHA.fullmatch(binding[key])
            or binding[key] != provenance["receipt_sha256"][receipt_key]
        ):
            raise ValueError("Invalid bound receipt digest")
    elapsed = (utc_time(binding["finished_at"]) - utc_time(binding["started_at"])).total_seconds()
    if not 0 < elapsed <= 180 or utc_time(binding["finished_at"]) > utc_time(pilot["recorded_at"]):
        raise ValueError("Invalid bound receipt time")
    rows, seen, result = binding["observations"], set(), []
    if type(rows) is not list or len(rows) != 12:
        raise ValueError("Invalid observation count")
    for row in rows:
        if (
            type(row) is not dict
            or set(row) != {"event_id", "rule_id", "level", "app", "source", "outcome", "reason"}
            or row["rule_id"] not in RULE_MEANINGS
            or row["app"] not in ("bettail", "netted")
            or row["source"] not in ("synthetic_demo", "migration_lab")
            or row["outcome"] not in ("allowed", "denied", "not_visible", "error")
            or not isinstance(row["reason"], str)
            or not re.fullmatch(r"[a-z_]{1,40}", row["reason"])
            or type(row["level"]) is not int
            or row["level"] != RULE_MEANINGS[row["rule_id"]][0]
        ):
            raise ValueError("Invalid observation")
        identity = uuid.UUID(row["event_id"])
        if identity.version != 5 or str(identity) != row["event_id"] or row["event_id"] in seen:
            raise ValueError("Invalid observation identity")
        seen.add(row["event_id"])
        result.append(
            {
                **row,
                "meaning": RULE_MEANINGS[row["rule_id"]][1],
                "outcome_label": row["outcome"].replace("_", " "),
                "reason_label": row["reason"].replace("_", " "),
            }
        )
    return result


def present_receipt(run, tool):
    card = {
        "has_receipt": run is not None,
        "verified": False,
        "status_label": "Pilot not verified",
        "metrics": [],
    }
    if run is None:
        return card
    card.update(
        imported_at=run.created_at,
        summary="The latest imported record does not establish a completed local pilot.",
        proof_note="No verified pilot conclusion is shown for this record.",
    )
    if run.status != "passed":
        card["status_label"] = {
            "failed": "Latest receipt failed",
            "blocked": "Latest receipt blocked",
        }.get(run.status, "Receipt needs review")
        return card
    # The local importer establishes provenance. Recheck its canonical content
    # digest and source binding so damaged/stale rows cannot keep a verified badge.
    # This detects inconsistency, not an administrator rewriting data and hashes.
    result = run.result
    try:
        pilot = result["pilot"]
        counts = pilot["counts"]
        provenance = pilot["provenance"]
        valid = (
            result["evidence_kind"] == "soc_pilot"
            and result["tool"] == tool
            and result["app"] == "signalbridge"
            and result["status"] == "passed"
            and pilot["scope"] == "synthetic_fixture"
            and pilot["source_app_assessed"] is False
            and pilot["continuous_connection"] is False
            and pilot["stopped_at_end"] is True
            and provenance["verification"]
            == "builder_local_receipt_consistency_and_fresh_stopped_gate"
            and provenance["fresh_stopped_gate_required"] is True
            and all(
                type(counts.get(key)) is int and counts[key] == expected
                for key, expected in EXPECTED_COUNTS[tool].items()
            )
            and all(
                type(counts[key]) is int and 0 <= counts[key] <= 10000 for key, _ in METRICS[tool]
            )
            and SHA.fullmatch(run.digest) is not None
            and hashlib.sha256(
                json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            ).hexdigest()
            == run.digest
            and isinstance(run.revision, str)
            and SHA.fullmatch(run.revision) is not None
            and provenance["source_sha256"] == run.revision
        )
        tested_at = datetime.fromisoformat(pilot["recorded_at"].replace("Z", "+00:00"))
        valid = valid and tested_at.tzinfo is not None and tested_at.utcoffset() is not None
        version = pilot["runtime_version"]
        valid = (
            valid
            and isinstance(version, str)
            and re.fullmatch(r"[0-9A-Za-z.+_-]{1,48}", version) is not None
        )
        run_id = pilot["run_id"]
        valid = (
            valid
            and isinstance(run_id, str)
            and str(uuid.UUID(run_id)) == run_id
            and uuid.UUID(run_id).version == 4
        )
        if not valid:
            raise ValueError("Unsupported receipt")
        observations = bound_observations(pilot, provenance) if tool == "wazuh" else []
    except (AttributeError, KeyError, TypeError, ValueError):
        card["status_label"] = "Receipt needs review"
        return card
    card.update(
        verified=True,
        status_label="Local pilot verified",
        tested_at=tested_at,
        runtime_version=version,
        receipt_digest=run.digest,
        run_id=run_id,
        metrics=[{"label": label, "value": counts[key]} for key, label in METRICS[tool]],
        observations=observations,
    )
    if tool == "wazuh":
        card["summary"] = (
            "27 real Wazuh rule checks and a separate 19-input file-collection exercise completed in the synthetic lab."
        )
        card["proof_note"] = (
            "The pinned manager processed the declared synthetic inputs. Twelve expected alerts include one tail sentinel; these are test results, not application vulnerabilities. No dashboard or continuous event delivery was exercised."
        )
        card["binding_note"] = (
            "Run identity, start/finish times and all 12 retained alert bodies were reconciled at import. The event IDs belong to this run."
            if observations
            else "Legacy receipt: runtime output was associated through its folder and gates. Embedded run identity, timing and retained alert bodies were not verified."
        )
    else:
        card["summary"] = (
            "A real ZAP process passively inspected three fixed GET requests against a disposable fixture."
        )
        card["proof_note"] = (
            "The scanner and header controls were exercised against a synthetic target. The sanitized report retains its own import provenance. No source application, authenticated session or active exploit scan was assessed."
        )
    if SHA.fullmatch(run.revision or ""):
        card["source_digest"] = run.revision
    containers = provenance.get("containers", [])
    prefix = "wazuh/wazuh-manager@sha256:" if tool == "wazuh" else "zaproxy/zap-stable@sha256:"
    if isinstance(containers, list):
        for container in containers[:3]:
            reference = container.get("image_reference") if isinstance(container, dict) else None
            if (
                isinstance(reference, str)
                and reference.startswith(prefix)
                and SHA.fullmatch(reference[len(prefix) :])
            ):
                card["image_digest"] = reference
                break
    return card


def pilot_cards(app):
    """No cross-workspace query, filesystem read, process launch or live probe."""
    if app.slug != "signalbridge":
        return {tool + "_pilot": present_receipt(None, tool) for tool in TOOLS}
    cards = {}
    for tool in TOOLS:
        run = (
            CheckRun.objects.filter(
                integration=app, result__evidence_kind="soc_pilot", result__tool=tool
            )
            .order_by("-created_at", "-id")
            .first()
        )
        cards[tool + "_pilot"] = present_receipt(run, tool)
    return cards
