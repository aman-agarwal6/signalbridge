"""Fixed, labeled offline evaluation through signed ingestion and the real worker.

No servers, Docker, private configuration, external traffic or source-app mutation.
Rules and the evaluator are frozen separately from inputs and sealed labels.
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
import uuid
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.run_enterprise_lab import offline_guards, require_memory_database, verify_guards

DATA = ROOT / "fixtures/detection_evaluation"
FROZEN_FILES = (
    "bridge/engine.py",
    "bridge/contract.py",
    "bridge/worker.py",
    "bridge/ingestion.py",
    "bridge/models.py",
    "bridge/case_provenance.py",
    "bridge/detection_catalog.py",
    "config/simulation_settings.py",
    "scripts/evaluate_detection.py",
)


def checksums():
    # Line endings are normalized for cross-platform verification; bytes otherwise exact.
    return {
        name: hashlib.sha256((ROOT / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        for name in FROZEN_FILES
    }


def safe_directory(path):
    for part in (path, *path.parents):
        if part == ROOT:
            break
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("Evaluation paths cannot be links or junctions.")
    if not path.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError("Evaluation path escaped the repository.")
    path.mkdir(parents=True, exist_ok=True)


def freeze():
    safe_directory(DATA)
    record = {
        "schema_version": 1,
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "files": checksums(),
        "normalization": "CRLF to LF only",
        "independent_holdout": False,
        "scope": "Builder-operated pre-evaluation freeze; no third-party attestation.",
    }
    # An existing round is immutable: changed rules require a reviewed new round.
    with (DATA / "freeze.json").open("x", encoding="utf8") as handle:
        json.dump(record, handle, indent=2)
        handle.write("\n")


def seal():
    safe_directory(DATA)
    frozen = json.loads((DATA / "freeze.json").read_text())
    if frozen["files"] != checksums():
        raise ValueError("Frozen implementation changed before dataset declaration.")
    declaration = {
        "declared_at": datetime.now(timezone.utc).isoformat(),
        "inputs_sha256": hashlib.sha256((DATA / "inputs.json").read_bytes()).hexdigest(),
        "labels_sha256": hashlib.sha256((DATA / "labels.json").read_bytes()).hexdigest(),
        "authorship": "AI/builder-authored after implementation freeze; not independent or blind.",
    }
    with (DATA / "declaration.json").open("x", encoding="utf8") as handle:
        json.dump(declaration, handle, indent=2)
        handle.write("\n")


def metrics(rows):
    scored = [r for r in rows if r["label"] in ("suspicious", "benign")]
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for row in scored:
        positive = row["label"] == "suspicious"
        key = ("tp" if positive else "fp") if row["alerted"] else ("fn" if positive else "tn")
        counts[key] += 1
    tp, fp, fn, tn = (counts[k] for k in ("tp", "fp", "fn", "tn"))
    return {
        **counts,
        "scored_scenarios": len(scored),
        "suspicious_scenarios": tp + fn,
        "benign_scenarios": fp + tn,
        "inconclusive_scenarios": len(rows) - len(scored),
        "precision": {
            "numerator": tp,
            "denominator": tp + fp,
            "value": tp / (tp + fp) if tp + fp else None,
        },
        "recall": {
            "numerator": tp,
            "denominator": tp + fn,
            "value": tp / (tp + fn) if tp + fn else None,
        },
        "false_positive_rate": {
            "numerator": fp,
            "denominator": fp + tn,
            "value": fp / (fp + tn) if fp + tn else None,
        },
    }


def evaluate():
    safe_directory(DATA)
    frozen = json.loads((DATA / "freeze.json").read_text())
    if frozen["files"] != checksums():
        raise ValueError("Frozen implementation changed; do not reuse this evaluation round.")
    raw = (DATA / "inputs.json").read_bytes()
    declaration = json.loads((DATA / "declaration.json").read_text())
    label_bytes = (DATA / "labels.json").read_bytes()
    if (
        declaration["inputs_sha256"] != hashlib.sha256(raw).hexdigest()
        or declaration["labels_sha256"] != hashlib.sha256(label_bytes).hexdigest()
    ):
        raise ValueError("Declared dataset changed; preserve this round and review the change.")
    if len(raw) > 150_000:
        raise ValueError("Evaluation inputs exceed their bound.")
    inputs = json.loads(raw)
    if not 1 <= len(inputs) <= 40 or sum(len(s["events"]) for s in inputs) > 150:
        raise ValueError("Evaluation exceeds fixed case/request limits.")
    if len({s["id"] for s in inputs}) != len(inputs):
        raise ValueError("Scenario IDs must be unique.")
    predictions = []
    started = datetime.now(timezone.utc)
    clock = time.perf_counter()
    os.environ["DJANGO_SETTINGS_MODULE"] = "config.simulation_settings"
    os.environ["SB_SECRET_KEY"] = secrets.token_urlsafe(64)
    os.environ["SB_EVALUATION_KEY"] = secrets.token_urlsafe(64)
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
        from bridge.models import Event, IngestKey, Integration, Investigation
        from bridge.worker import drain

        call_command("migrate", verbosity=0, interactive=False)
        client = Client()
        base = started.replace(microsecond=0) - timedelta(days=2)
        for index, scenario in enumerate(inputs):
            slug = f"evaluation-{index}"
            app = Integration.objects.create(slug=slug, name=slug)
            key = IngestKey.objects.create(
                integration=app,
                key_id=slug,
                source="synthetic_demo",
                environment="test",
                secret_env="SB_EVALUATION_KEY",
                can_assert_membership=True,
            )
            deliveries = []
            for position, observation in enumerate(scenario["events"]):
                # Oracle labels/titles never enter collector requests.
                value = dict(observation)
                offset = value.pop("offset_seconds")
                value.update(
                    app=slug,
                    occurred_at=(base + timedelta(seconds=offset)).isoformat(),
                    event_id=str(
                        uuid.uuid5(uuid.NAMESPACE_URL, f"evaluation/{scenario['id']}/{position}")
                    ),
                    episode=str(uuid.uuid5(uuid.NAMESPACE_URL, f"evaluation/{scenario['id']}")),
                )
                body = canonical(value)
                at = datetime.now(timezone.utc).isoformat()
                response = client.post(
                    f"/api/v1/events/{slug}/",
                    data=body,
                    content_type="application/json",
                    HTTP_X_SB_KEY=key.key_id,
                    HTTP_X_SB_TIME=at,
                    HTTP_X_SB_SIGNATURE=signature(
                        os.environ["SB_EVALUATION_KEY"], slug, key.key_id, at, body
                    ),
                )
                if response.status_code != 202:
                    raise ValueError("Evaluation delivery did not enter the queue.")
                # Drain after every delivery to exercise arrival ordering and correction.
                drain(limit=150)
                deliveries.append(
                    {
                        "event_id": value["event_id"],
                        "offset_seconds": offset,
                        "operation": value["operation"],
                        "outcome": value["outcome"],
                        "http_status": response.status_code,
                    }
                )
            if Event.objects.filter(integration=app).exclude(state="processed").exists():
                raise ValueError("Evaluation has unprocessed events.")
            cases = list(
                Investigation.objects.filter(integration=app).order_by("rule", "correlation")
            )
            active = [c for c in cases if c.rule != "R3" or c.severity == "high"]
            predictions.append(
                {
                    "id": scenario["id"],
                    "alerted": bool(active),
                    "rules": sorted({c.rule for c in active}),
                    "case_count": len(cases),
                    "reassessment_cases": sum(
                        c.rule == "R3" and c.severity == "medium" for c in cases
                    ),
                    "deliveries": deliveries,
                    "cases": [
                        {
                            "rule": c.rule,
                            "priority": c.severity,
                            "title": c.title,
                            "evidence_events": c.events.count(),
                            "version": c.version,
                        }
                        for c in cases
                    ],
                }
            )
    # Open labels only after every prediction is complete. This is separation,
    # not blindness: the same builder knows the detector and scenarios.
    labels = json.loads(label_bytes)
    if set(labels) != {r["id"] for r in predictions} or any(
        v["label"] not in ("suspicious", "benign", "inconclusive") for v in labels.values()
    ):
        raise ValueError("Labels do not match the fixed evaluation inputs.")
    for row in predictions:
        row.update(labels[row["id"]])
    if checksums() != frozen["files"]:
        raise ValueError("Source changed during evaluation.")
    return {
        "schema_version": 1,
        "kind": "signalbridge-membership-evaluation-v1",
        "executed_at": started.isoformat(),
        "duration_seconds": round(time.perf_counter() - clock, 3),
        "implementation": frozen,
        "declaration": declaration,
        "inputs_sha256": hashlib.sha256(raw).hexdigest(),
        "labels_sha256": hashlib.sha256(label_bytes).hexdigest(),
        "unit": "one scenario; any active detection is a positive prediction",
        "metrics": metrics(predictions),
        "scenarios": predictions,
        "limits": [
            "AI/builder-authored, not blind or independent; small selected dataset.",
            "Inconclusive scenarios are displayed but excluded from binary accuracy metrics.",
            "Historical alerts corrected by late evidence are reported separately, not counted as current alerts.",
            "Django in-process signed requests and memory-only SQLite; no native tools or real source app.",
            "No wall-clock soak, production accuracy, HTTP latency or enterprise parity claim.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--seal", action="store_true")
    args = parser.parse_args()
    if args.freeze and args.seal:
        raise ValueError("Freeze implementation and seal the dataset in separate steps.")
    if args.freeze:
        freeze()
        print("Implementation frozen. Declare inputs and labels before evaluation.")
    elif args.seal:
        seal()
        print("Dataset declaration sealed before evaluation.")
    else:
        result = evaluate()
        output = ROOT / "artifacts/local/detection-evaluation"
        safe_directory(output)
        target = output / (uuid.uuid4().hex + ".json")
        with target.open("x", encoding="utf8") as handle:
            json.dump(result, handle, indent=2)
            handle.write("\n")
        print(json.dumps(result["metrics"], indent=2))
        print("Local evidence: " + str(target))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
