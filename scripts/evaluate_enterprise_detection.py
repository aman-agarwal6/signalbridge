"""A separate immutable enterprise round; never rewrite the September evaluation.

Bounded signed in-process delivery and memory-only SQLite. This builder-authored
round measures declared synthetic scenarios, not independent production accuracy.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import sys
import time
import uuid
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.evaluate_detection import FROZEN_FILES, metrics, safe_directory
from scripts.run_enterprise_lab import offline_guards, require_memory_database, verify_guards

# A formatting correction after the first execution needs a fresh source identity.
# The earlier round remains intact; this is a repeat of its selected scenarios,
# not a new independent dataset or stronger statistical evidence.
DATA = ROOT / "fixtures/enterprise_detection_evaluation/round-20261001-format2"
FILES = (*FROZEN_FILES, "scripts/evaluate_enterprise_detection.py", "scripts/run_enterprise_lab.py")
MAX_REQUESTS = 600
MAX_SECONDS = 180


def checksums():
    # Include all Django implementation and migration files, including newly
    # added ones; generated datasets and receipts are outside this source set.
    files = set(FILES)
    for directory in ("bridge", "config"):
        for path in (ROOT / directory).rglob("*.py"):
            if path.is_symlink() or any(part == "__pycache__" for part in path.parts):
                raise ValueError("Frozen implementation contains a redirected source file.")
            files.add(path.relative_to(ROOT).as_posix())
    return {
        name: hashlib.sha256((ROOT / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        for name in sorted(files)
    }


def freeze():
    safe_directory(DATA)
    value = {
        "schema_version": 1,
        "round_id": str(uuid.uuid4()),
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "files": checksums(),
        "normalization": "CRLF to LF only",
        "independent_holdout": False,
    }
    with (DATA / "freeze.json").open("x", encoding="utf8") as handle:
        handle.write(json.dumps(value, indent=2) + "\n")


def inputs(raw):
    if len(raw) > 1024**2:
        raise ValueError("Enterprise dataset exceeds its byte bound.")
    rows = json.loads(raw)
    if not isinstance(rows, list) or not 40 <= len(rows) <= 60:
        raise ValueError("Declare 40–60 distinct scenarios in this round.")
    ids, requests = set(), 0
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"id", "events"}
            or not isinstance(row["id"], str)
            or not re.fullmatch(r"Q[0-9]{2}", row["id"])
            or row["id"] in ids
        ):
            raise ValueError("Invalid or duplicate scenario identity.")
        ids.add(row["id"])
        if not isinstance(row["events"], list) or not 1 <= len(row["events"]) <= 30:
            raise ValueError("Scenario request bound exceeded.")
        requests += len(row["events"])
        for index, event in enumerate(row["events"]):
            if not isinstance(event, dict):
                raise ValueError("Invalid scenario observation.")
            if "repeat_of" in event:
                if (
                    set(event) != {"repeat_of"}
                    or type(event["repeat_of"]) is not int
                    or not 0 <= event["repeat_of"] < index
                    or "repeat_of" in row["events"][event["repeat_of"]]
                ):
                    raise ValueError("Repeat must identify one earlier original request.")
                continue
            if (
                event.get("app_scope") not in ("documents", "expenses")
                or event.get("source_scope") not in ("instrumented_lab", "synthetic_demo")
                or event.get("environment") not in ("test", "lab")
                or type(event.get("offset_seconds")) is not int
                or not 0 <= event["offset_seconds"] <= 172800
                or any(
                    k in event
                    for k in (
                        "app",
                        "event_id",
                        "occurred_at",
                        "episode",
                        "label",
                        "title",
                        "expected_rules",
                    )
                )
            ):
                raise ValueError("Observation scope or timestamp escaped the declared profile.")
    if requests > MAX_REQUESTS:
        raise ValueError("Enterprise request bound exceeded.")
    return rows


def declared():
    value = json.loads((DATA / "freeze.json").read_text(encoding="utf8"))
    if value["files"] != checksums():
        raise ValueError("Frozen enterprise implementation changed; create a new round.")
    return value


def seal():
    frozen = declared()
    raw, labels = (DATA / "inputs.json").read_bytes(), (DATA / "labels.json").read_bytes()
    inputs(raw)
    value = {
        "round_id": frozen["round_id"],
        "declared_at": datetime.now(timezone.utc).isoformat(),
        "inputs_sha256": hashlib.sha256(raw).hexdigest(),
        "labels_sha256": hashlib.sha256(labels).hexdigest(),
        "authorship": "AI/builder-authored after source freeze, not blind or independent.",
    }
    with (DATA / "declaration.json").open("x", encoding="utf8") as handle:
        handle.write(json.dumps(value, indent=2) + "\n")


def evaluate():
    frozen = declared()
    raw, label_bytes = (DATA / "inputs.json").read_bytes(), (DATA / "labels.json").read_bytes()
    declaration = json.loads((DATA / "declaration.json").read_text(encoding="utf8"))
    if (
        declaration["round_id"] != frozen["round_id"]
        or declaration["inputs_sha256"] != hashlib.sha256(raw).hexdigest()
        or declaration["labels_sha256"] != hashlib.sha256(label_bytes).hexdigest()
    ):
        raise ValueError("Declared enterprise data changed; preserve this round.")
    scenarios = inputs(raw)
    if len(label_bytes) > 100000:
        raise ValueError("Labels exceed their byte bound.")
    started, clock = datetime.now(timezone.utc), time.monotonic()
    os.environ.update(
        DJANGO_SETTINGS_MODULE="config.simulation_settings",
        SB_SECRET_KEY=secrets.token_urlsafe(64),
        SB_EVALUATION_KEY=secrets.token_urlsafe(64),
    )
    predictions = []
    with ExitStack() as stack:
        offline_guards(stack)
        verify_guards()
        import django
        from django.conf import settings

        require_memory_database(settings.DATABASES)
        django.setup()
        from django.core.management import call_command
        from django.test import Client

        from bridge.contract import canonical, signature
        from bridge.detection_catalog import RULES
        from bridge.models import Event, IngestKey, Integration, Investigation
        from bridge.worker import drain

        versions = {key: rule["version"] for key, rule in RULES.items()}
        call_command("migrate", verbosity=0, interactive=False)
        client = Client()
        base = started.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=3)
        for index, scenario in enumerate(scenarios):
            apps, credentials, originals, deliveries, initial_cases = {}, {}, {}, [], set()
            for position, observation in enumerate(scenario["events"]):
                if time.monotonic() - clock > MAX_SECONDS:
                    raise ValueError("Enterprise evaluation deadline exceeded.")
                repeat = "repeat_of" in observation
                if repeat:
                    value, key = originals[observation["repeat_of"]]
                else:
                    value = dict(observation)
                    scope, source, offset = (
                        value.pop("app_scope"),
                        value.pop("source_scope"),
                        value.pop("offset_seconds"),
                    )
                    if scope not in apps:
                        slug = f"enterprise-eval-{index}-{scope}"
                        apps[scope] = Integration.objects.create(
                            slug=slug, name="Synthetic " + scope
                        )
                    app = apps[scope]
                    credential = (scope, source, value["environment"])
                    if credential not in credentials:
                        credentials[credential] = IngestKey.objects.create(
                            integration=app,
                            key_id=f"eval-{index}-{len(credentials)}",
                            source=source,
                            environment=value["environment"],
                            secret_env="SB_EVALUATION_KEY",
                            can_assert_membership=True,
                        )
                    key = credentials[credential]
                    value.update(
                        app=app.slug,
                        occurred_at=(base + timedelta(seconds=offset)).isoformat(),
                        event_id=str(
                            uuid.uuid5(
                                uuid.NAMESPACE_URL,
                                f"enterprise/{frozen['round_id']}/{scenario['id']}/{position}",
                            )
                        ),
                        episode=str(
                            uuid.uuid5(
                                uuid.NAMESPACE_URL,
                                f"enterprise/{frozen['round_id']}/{scenario['id']}",
                            )
                        ),
                    )
                    originals[position] = (value, key)
                body, at = canonical(value), datetime.now(timezone.utc).isoformat()
                response = client.post(
                    f"/api/v1/events/{value['app']}/",
                    data=body,
                    content_type="application/json",
                    HTTP_X_SB_KEY=key.key_id,
                    HTTP_X_SB_TIME=at,
                    HTTP_X_SB_SIGNATURE=signature(
                        os.environ["SB_EVALUATION_KEY"], value["app"], key.key_id, at, body
                    ),
                )
                if response.status_code != (200 if repeat else 202):
                    raise ValueError(
                        "Enterprise delivery was not accepted with the expected logical identity."
                    )
                drain(limit=1000, worker_id="enterprise-evaluation")
                cases = list(
                    Investigation.objects.filter(integration__in=apps.values()).order_by(
                        "rule", "correlation"
                    )
                )
                active = [c for c in cases if c.rule != "R3" or c.severity == "high"]
                initial_cases.update(str(c.pk) for c in active)
                deliveries.append(
                    {
                        "event_id": value["event_id"],
                        "http_status": response.status_code,
                        "source": key.source,
                        "app_scope": next(
                            name for name, app in apps.items() if app.slug == value["app"]
                        ),
                        "active_case_count": len(active),
                        "active_rules": sorted({c.rule for c in active}),
                    }
                )
            if (
                Event.objects.filter(integration__in=apps.values())
                .exclude(state="processed")
                .exists()
            ):
                raise ValueError("Enterprise evaluation has unprocessed records.")
            predictions.append(
                {
                    "id": scenario["id"],
                    "alerted": bool(active),
                    "initial_alerted": bool(initial_cases),
                    "rules": sorted({c.rule for c in active}),
                    "initial_cases_for_review": len(initial_cases),
                    "final_active_cases": len(active),
                    "corrected_cases": sum(
                        str(c.pk) in initial_cases and c.rule == "R3" and c.severity == "medium"
                        for c in cases
                    ),
                    "logical_events": len(originals),
                    "physical_requests": len(deliveries),
                    "duplicate_requests": sum(d["http_status"] == 200 for d in deliveries),
                    "deliveries": deliveries,
                    "cases": [
                        {
                            "rule": c.rule,
                            "priority": c.severity,
                            "version": c.version,
                            "evidence_events": c.events.count(),
                        }
                        for c in cases
                    ],
                }
            )
    labels = json.loads(label_bytes)
    if set(labels) != {r["id"] for r in predictions} or any(
        not isinstance(v, dict)
        or set(v) != {"label", "title", "rationale"}
        or v["label"] not in ("suspicious", "benign", "inconclusive")
        or any(
            not isinstance(v[k], str) or not 1 <= len(v[k]) <= 1000 for k in ("title", "rationale")
        )
        for v in labels.values()
    ):
        raise ValueError("Enterprise oracle labels do not match the declared scenarios.")
    for row in predictions:
        row.update(labels[row["id"]])
    if frozen["files"] != checksums():
        raise ValueError("Source changed during enterprise evaluation.")
    return {
        "schema_version": 1,
        "kind": "signalbridge-enterprise-detection-evaluation-v1",
        "executed_at": started.isoformat(),
        "duration_seconds": round(time.monotonic() - clock, 3),
        "implementation": frozen,
        "declaration": declaration,
        "rule_versions": versions,
        "unit": "One declared scenario; any final active detection is a positive prediction.",
        "metrics": metrics(predictions),
        "initial_metrics": metrics([{**r, "alerted": r["initial_alerted"]} for r in predictions]),
        "workload": {
            "initial_cases_for_review": sum(r["initial_cases_for_review"] for r in predictions),
            "final_active_cases": sum(r["final_active_cases"] for r in predictions),
            "corrected_cases": sum(r["corrected_cases"] for r in predictions),
            "physical_requests": sum(r["physical_requests"] for r in predictions),
            "logical_events": sum(r["logical_events"] for r in predictions),
            "duplicate_requests": sum(r["duplicate_requests"] for r in predictions),
        },
        "scenarios": predictions,
        "limits": [
            "Builder-authored selected synthetic scenarios, not an independent holdout or production benchmark.",
            "Oracle labels are joined after predictions; authors knew the rules, so this is not blindness.",
            "Inconclusive cases are excluded from binary metrics but retained in workload and results.",
            "Initial review workload includes alerts later corrected; no false alert is relabeled to improve accuracy.",
            "Django signed in-process requests and memory-only SQLite; no native source, tool, enterprise identity, latency SLA or soak proof.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--freeze", action="store_true")
    actions.add_argument("--seal", action="store_true")
    args = parser.parse_args()
    if args.freeze:
        freeze()
        print("New enterprise implementation identity frozen; September preserved.")
    elif args.seal:
        seal()
        print("Enterprise dataset sealed before execution.")
    else:
        result = evaluate()
        output = ROOT / "artifacts/local/enterprise-detection-evaluation"
        safe_directory(output)
        target = output / (uuid.uuid4().hex + ".json")
        with target.open("x", encoding="utf8") as handle:
            handle.write(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"metrics": result["metrics"], "workload": result["workload"]}, indent=2))
        print("Retained local execution: " + str(target))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
