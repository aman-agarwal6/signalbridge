"""Read-only, app-scoped historical receipt presentation; no files or Docker calls."""

import hashlib
import json
import math
from collections import Counter

from integrations.wazuh.run_context import run_uuid, utc_time
from integrations.wazuh.verify_static import EXPORT_FIELDS, validate_export
from integrations.wazuh_backfill.contract import expected_rule, uuid_text

from .assurance import sha
from .soc_delivery import VALUES
from .soc_presentation import RULE_MEANINGS


def require(value):
    if not value:
        raise ValueError("Backfill receipt needs review")


def backfill_card(app, run=None):
    card = {"has_receipt": False, "verified": False}
    if app.slug != "bettail":
        return card
    if run is None:
        return card
    card["has_receipt"] = True
    try:
        result = run.result
        provenance = result["provenance"]
        require(
            run.integration_id == app.pk
            and result["evidence_kind"] == "wazuh_backfill"
            and run.status == result["status"] == "passed"
            and result["app"] == app.slug
            and result["tool"] == "wazuh"
            and type(result["schema_version"]) is int
            and result["schema_version"] == 1
            and result["runtime_version"] == "4.14.8"
            and result["continuous_connection"] is False
            and result["source_app_assessed"] is False
            and result["stopped_at_end"] is True
            and provenance["fresh_stopped_gate_required"] is True
            and sha(run.revision)
            and run.revision == provenance["source_sha256"]
            and sha(provenance["execution_sha256"])
            and sha(provenance["container_id"])
            and run.digest
            == hashlib.sha256(
                json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            ).hexdigest()
        )
        run_uuid(result["run_id"])
        elapsed = (utc_time(result["finished_at"]) - utc_time(result["started_at"])).total_seconds()
        duration = result["duration_seconds"]
        require(
            type(duration) in (int, float)
            and math.isfinite(duration)
            and 0 < elapsed <= 180
            and abs(elapsed - duration) <= 2
            and utc_time(result["recorded_at"]) >= utc_time(result["finished_at"])
        )
        stream = result["stream"]
        uuid_text(stream["stream_id"])
        require(
            type(stream["revision"]) is int
            and stream["revision"] >= 0
            and type(stream["offset"]) is int
            and 0 < stream["offset"] <= 128 * 1024
            and sha(stream["sha256"])
        )
        rows = result["observations"]
        require(type(rows) is list and 0 < len(rows) <= 100)
        seen, alerts, sources, presented = set(), 0, Counter(), []
        for row in rows:
            require(type(row) is dict and set(row) == EXPORT_FIELDS | {"rule_id", "level"})
            event = validate_export({"signalbridge": {k: row[k] for k in EXPORT_FIELDS}}, VALUES)
            require(
                event["app"] == app.slug
                and event["environment"] == "lab"
                and event["event_id"] not in seen
            )
            seen.add(event["event_id"])
            rule = expected_rule(event)
            require(
                (rule is None and row["rule_id"] is None and row["level"] is None)
                or (
                    rule is not None
                    and row["rule_id"] == rule[0]
                    and type(row["level"]) is int
                    and row["level"] == rule[1]
                )
            )
            alerts += int(rule is not None)
            sources[event["source"]] += 1
            presented.append(
                {
                    **row,
                    "meaning": RULE_MEANINGS[rule[0]][1]
                    if rule
                    else "Archived without a matching custom alert. This is not a benign verdict.",
                }
            )
        counts = {
            "inputs": len(rows),
            "received": len(rows),
            "alerts": alerts,
            "nonalerts": len(rows) - alerts,
            "missing": 0,
            "duplicates": 0,
            "rule_cases": 27,
        }
        require(
            result["counts"] == counts
            and all(type(n) is int for n in result["counts"].values())
            and result["source_counts"] == dict(sources)
            and all(type(n) is int for n in result["source_counts"].values())
        )
        receipt_hashes = provenance["receipt_sha256"]
        require(
            type(receipt_hashes) is dict
            and all(sha(h) for h in receipt_hashes.values())
            and {
                "wazuh-backfill/archives.jsonl",
                "wazuh-backfill/alerts.jsonl",
                "created-gate.json",
                "running-gate.json",
                "exited-gate.json",
                "host-result.json",
            }
            <= set(receipt_hashes)
        )
        card.update(
            verified=True,
            counts=counts,
            source_counts=dict(sources),
            observations=presented,
            run_id=result["run_id"],
            tested_at=utc_time(result["finished_at"]),
            receipt_digest=run.digest,
            source_digest=run.revision,
            input_digest=stream["sha256"],
            stream=stream,
            duration=duration,
        )
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        pass
    return card
