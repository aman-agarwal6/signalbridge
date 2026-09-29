"""Fixed reviewed integration snapshots for the offline employer presentation.

No settings, database, private logs, tool process or network access. Content pins
use canonical JSON so Git line-ending conversions do not invalidate the review.
They establish reviewed bytes, not independent attestation or current health.
"""

import hashlib
import json
from collections import Counter

RECEIPTS = {
    "20260925-wazuh-product-backfill.json": "f3a158f93ffaa0134e75ac849215f3cdf2835c8dc459cef1e794773f6987d673",
    "20260925-wazuh-reviewed-records.json": "b7695ad3df9be7d49ce2645e2f57a02bbd358c2af28802cb6aef303c3203a239",
    "20260925-zap-repeat-failure.json": "4a41d658caef9fa36580b7e2c9a2aab520ab336d3a468d104fc79e870a68d86b",
    "20260925-zap-console-import.json": "27d7dbb254d358ea0f1b6f969479d6b6eb32b16fb3cfb77ab9a5875254d8c205",
}
RULES = {
    "100201": (
        "Observed boundary signal",
        "Allowed read with a lab-observed boundary-change reason. Verify the permission context.",
        12,
    ),
    "100202": (
        "Synthetic boundary signal",
        "Allowed read from a declared synthetic scenario. A detector exercise, not a breach.",
        5,
    ),
    "100203": (
        "Denied request",
        "The request was denied. This may show a working permission boundary.",
        3,
    ),
    "100204": (
        "Record not visible",
        "The record was not visible. Absence alone does not establish an authorization denial.",
        3,
    ),
}


def canonical_sha(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    ).hexdigest()


def load_integrations(root, read_public, require):
    """Omit an absent snapshot; fail closed on partial, changed or mixed evidence."""
    available = [(root / "docs/evidence" / name).exists() for name in RECEIPTS]
    if not any(available):
        return None
    require(all(available), "Integration presentation needs every reviewed receipt.")
    values, identities = [], []
    for name, expected in RECEIPTS.items():
        value, raw_sha = read_public(root, name)
        require(
            canonical_sha(value) == expected,
            "Integration receipt differs from the reviewed snapshot.",
        )
        values.append(value)
        identities.append(
            {"receipt": name, "receipt_sha256": raw_sha, "reviewed_content_sha256": expected}
        )
    backfill, records, zap, imported = values
    rows = records["observations"]
    require(
        backfill["run_id"] == records["run_id"]
        and backfill["imported_receipt_sha256"] == records["imported_receipt_sha256"]
        and records["counts"] == backfill["counts"]
        and len(rows) == len({r["event_id"] for r in rows}) == backfill["counts"]["received"]
        and Counter(r["rule_id"] for r in rows if r["rule_id"]) == backfill["alert_rule_counts"],
        "Integration record reconciliation failed.",
    )
    decorated = []
    for row in rows:
        title, explanation, level = RULES.get(
            row["rule_id"],
            (
                "Archived without custom alert",
                "Wazuh received this record without one of the custom rule alerts. This is not a benign verdict.",
                None,
            ),
        )
        require(row["level"] == level, "Integration rule level is inconsistent.")
        decorated.append(
            {
                **row,
                "meaning": title,
                "interpretation": explanation,
                "short_id": row["event_id"][:8],
            }
        )
    decorated.sort(key=lambda r: (r["rule_id"] is None, r["rule_id"] or "", r["event_id"]))
    zap_runs = []
    for run in zap["runs"]:
        imported_run = next(
            (item for item in imported["runs"] if item["run_id"] == run["run_id"]), None
        )
        require(
            imported_run is not None
            and imported_run["status"] == run["observation"]["scan_status"]
            and imported_run["counts"] == run["observation"]["counts"],
            "ZAP execution and console receipt disagree.",
        )
        zap_runs.append(
            {
                "run_id": run["run_id"],
                "failed": run["observation"]["scan_status"] == "failed",
                "accepted": run["observation"]["target_accepted"],
                "counts": run["observation"]["counts"],
                "duration_seconds": run["duration_seconds"],
                "finished_at": run["finished_at"],
                "scanner_exit_code": run["scanner_exit_code"],
                "stopped": run["stopped_at_end"],
                "coverage": imported_run["coverage"],
                "imported_receipt_sha256": imported_run["receipt_sha256"],
            }
        )
    return {
        "scope": "Historical executions of real tools with local lab inputs; no live service connection.",
        "wazuh": {
            "run_id": backfill["run_id"],
            "version": backfill["version"],
            "counts": backfill["counts"],
            "finished_at": backfill["finished_at"],
            "duration_seconds": backfill["duration_seconds"],
            "source_counts": backfill["source_counts"],
            "input_sha256": backfill["input"]["sha256"],
            "records": decorated,
            "rules": [
                {"id": key, "title": RULES[key][0], "count": count}
                for key, count in backfill["alert_rule_counts"].items()
            ],
            "isolation": backfill["isolation"],
        },
        "zap": {
            "runs": zap_runs,
            "version": "2.17.0",
            "import_duplicates": imported["repeat_imports_created_duplicates"],
            "import_receipts": imported["new_receipts"],
            "audit_records": imported["new_audit_records"],
        },
        "receipts": identities,
    }
