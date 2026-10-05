"""Replay the frozen 48-scenario round through the Python rules and the compiled Sigma rules.

Each scenario is rebuilt exactly as scripts/evaluate_enterprise_detection.py delivers it, then
evaluated twice: by bridge.engine.detections() and by the Sigma rules compiled to SQLite and run
on an in-memory table. The report records which rules fired for each scenario, beside the rules
the published evaluation receipt recorded. It compares rule logic only; it does not measure
accuracy.

Run from the repository root:
    python -m detections.sigma.replay          # rewrite replay-report.json
    python -m detections.sigma.replay --check  # fail if the report is out of date
"""

import argparse
import hashlib
import json
import sqlite3
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path

from bridge.engine import detections

from .compile import DETECTIONS, PACKAGES, RULES, sqlite_queries

ROOT = Path(__file__).resolve().parents[2]
ROUND = ROOT / "fixtures/enterprise_detection_evaluation/round-20261005-public-release"
RECEIPT = ROOT / "docs/evidence/20261005-enterprise-detection-evaluation-public-release.json"
REPORT = Path(__file__).parent / "replay-report.json"
# The evaluator starts at a UTC midnight; offsets keep the same fixed-bucket alignment.
BASE = datetime(2026, 10, 2, tzinfo=timezone.utc)
COLUMNS = (
    "timestamp",
    "event_id",
    "app",
    "environment",
    "source",
    "actor",
    "resource",
    "operation",
    "outcome",
    "reason",
    "membership.subject",
    "membership.state",
)


def sha256(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def frozen_round():
    raw = (ROUND / "inputs.json").read_bytes()
    declaration = json.loads((ROUND / "declaration.json").read_text(encoding="utf-8"))
    freeze = json.loads((ROUND / "freeze.json").read_text(encoding="utf-8"))
    if hashlib.sha256(raw).hexdigest() != declaration["inputs_sha256"]:
        raise ValueError("Frozen scenario inputs do not match their declaration.")
    if freeze["round_id"] != declaration["round_id"]:
        raise ValueError("Freeze and declaration belong to different rounds.")
    return freeze["round_id"], json.loads(raw), hashlib.sha256(raw).hexdigest()


def scenario_events(round_id, index, scenario):
    """Stored events for one scenario. Repeated deliveries are deduplicated at ingestion."""
    events = []
    for position, observation in enumerate(scenario["events"]):
        if "repeat_of" in observation:
            continue
        value = dict(observation)
        scope = value.pop("app_scope")
        source = value.pop("source_scope")
        offset = value.pop("offset_seconds")
        identity = f"enterprise/{round_id}/{scenario['id']}"
        value.update(
            app=f"enterprise-eval-{index}-{scope}",
            occurred_at=(BASE + timedelta(seconds=offset)).isoformat(),
            event_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{identity}/{position}")),
            episode=str(uuid.uuid5(uuid.NAMESPACE_URL, identity)),
        )
        events.append((source, value))
    return events


def python_rules(events):
    """The worker evaluates each app and key-bound source separately."""
    groups = defaultdict(list)
    for source, event in events:
        groups[(event["app"], source)].append(event)
    return sorted({row["rule"] for group in groups.values() for row in detections(group)})


def sigma_rules(events, queries):
    db = sqlite3.connect(":memory:")
    try:
        columns = ", ".join('"' + name + '" TEXT' for name in COLUMNS)
        db.execute("CREATE TABLE logs (" + columns + ")")
        rows = []
        for source, event in events:
            membership = event.get("membership") or {}
            at = datetime.fromisoformat(event["occurred_at"]).astimezone(timezone.utc)
            rows.append(
                (
                    at.strftime("%Y-%m-%d %H:%M:%S"),
                    event["event_id"],
                    event["app"],
                    event["environment"],
                    source,
                    event["actor"],
                    event["resource"],
                    event["operation"],
                    event["outcome"],
                    event["reason"],
                    membership.get("subject"),
                    membership.get("state"),
                )
            )
        placeholders = ", ".join("?" for _ in COLUMNS)
        db.executemany("INSERT INTO logs VALUES (" + placeholders + ")", rows)
        return sorted(rule for rule, query in queries.items() if db.execute(query).fetchall())
    finally:
        db.close()


def build_report():
    round_id, scenarios, inputs_sha256 = frozen_round()
    receipt = {
        row["id"]: row for row in json.loads(RECEIPT.read_text(encoding="utf-8"))["scenarios"]
    }
    queries = sqlite_queries()
    results = []
    for index, scenario in enumerate(scenarios):
        events = scenario_events(round_id, index, scenario)
        published = receipt[scenario["id"]]
        python, sigma = python_rules(events), sigma_rules(events, queries)
        results.append(
            {
                "id": scenario["id"],
                "title": published["title"],
                "label": published["label"],
                "receipt_rules": sorted(published["rules"]),
                "python_rules": python,
                "sigma_rules": sigma,
                "sigma_agrees": python == sigma,
            }
        )
    per_rule = {}
    for rule in DETECTIONS:
        fired = [(rule in row["python_rules"], rule in row["sigma_rules"]) for row in results]
        per_rule[rule] = {
            "both": sum(p and s for p, s in fired),
            "python_only": sum(p and not s for p, s in fired),
            "sigma_only": sum(s and not p for p, s in fired),
        }
    return {
        "kind": "signalbridge-sigma-replay",
        "round_id": round_id,
        "inputs_sha256": inputs_sha256,
        "engine_sha256": {
            name: sha256(ROOT / name) for name in ("bridge/engine.py", "bridge/contract.py")
        },
        "rules_sha256": {path.name: sha256(path) for path in sorted(RULES.glob("*.yml"))},
        "packages": {name: version(name) for name in PACKAGES},
        "method": (
            "Each scenario is rebuilt as the published evaluator delivers it (UTC-midnight base, "
            "declared offsets, repeats removed). Python: bridge.engine.detections() per app and "
            "source. Sigma: the rules compiled by pySigma-backend-sqlite and executed on an "
            "in-memory SQLite table. A rule counts as fired if it returns any row."
        ),
        "summary": {
            "scenarios": len(results),
            "python_matches_receipt": sum(r["python_rules"] == r["receipt_rules"] for r in results),
            "sigma_matches_python": sum(r["sigma_agrees"] for r in results),
            "per_rule": per_rule,
        },
        "scenarios": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the report is out of date")
    args = parser.parse_args()
    text = json.dumps(build_report(), indent=2) + "\n"
    if args.check:
        current = REPORT.read_text(encoding="utf-8") if REPORT.exists() else None
        if current != text:
            print("replay-report.json is out of date")
            return 1
        print("replay-report.json is current")
        return 0
    REPORT.write_text(text, encoding="utf-8", newline="\n")
    summary = json.loads(text)["summary"]
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
