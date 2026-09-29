"""Labels live in a separate file and are joined only after engine decisions."""

import hashlib
from pathlib import Path

from django.conf import settings

from .contract import digest, parse_json, timestamp, validate_event
from .engine import triage

SOURCE_DRIFT_MESSAGE = (
    "Replay source changed or is unavailable. Restart SignalBridge before running "
    "or reviewing a comparison."
)


def _source_snapshot():
    directory = Path(__file__).parent
    try:
        # Preserve the established fingerprint ordering for historical comparisons.
        return tuple(
            (directory / name).read_bytes()
            for name in ("engine.py", "contract.py", "evaluation.py")
        )
    except OSError:
        return None


# The WSGI startup imports this module before serving requests. This identifies a
# coherent source snapshot at startup, not an attestation of Python bytecode.
_PROCESS_SOURCE_PARTS = _source_snapshot()
_PROCESS_ENGINE_SHA256 = (
    hashlib.sha256(b"".join(_PROCESS_SOURCE_PARTS)).hexdigest()
    if _PROCESS_SOURCE_PARTS is not None
    else None
)


def require_runtime_source():
    if _PROCESS_SOURCE_PARTS is None or _source_snapshot() != _PROCESS_SOURCE_PARTS:
        raise ValueError(SOURCE_DRIFT_MESSAGE)
    return _PROCESS_ENGINE_SHA256


def fixture_paths():
    return (
        settings.BASE_DIR / "fixtures" / "events.json",
        settings.BASE_DIR / "fixtures" / "labels.json",
    )


def evaluate(policy, app):
    engine_hash = require_runtime_source()
    event_path, label_path = fixture_paths()
    inputs = parse_json(event_path.read_bytes())
    labels = parse_json(label_path.read_bytes())
    if not isinstance(inputs, list) or not isinstance(labels, list) or not inputs or not labels:
        raise ValueError("Evaluation requires event and label lists.")
    event_ids, episode_scopes = set(), {}
    for event in inputs:
        if not isinstance(event, dict) or not isinstance(event.get("app"), str):
            raise ValueError("Invalid evaluation event.")
        validate_event(event, event["app"], now=timestamp(event["occurred_at"]))
        identity = (event["app"], event["event_id"])
        if identity in event_ids:
            raise ValueError("Duplicate evaluation event identifier.")
        event_ids.add(identity)
        episode = (event["app"], event["episode"])
        scope = (event["actor"], event["environment"])
        if episode in episode_scopes and episode_scopes[episode] != scope:
            raise ValueError("An evaluation episode must have one actor and environment.")
        episode_scopes[episode] = scope
    label_map = {}
    for label in labels:
        if (
            not isinstance(label, dict)
            or set(label) != {"app", "episode", "scenario", "suspicious"}
            or any(
                not isinstance(label[field], str) or not label[field]
                for field in ("app", "episode", "scenario")
            )
            or type(label["suspicious"]) is not bool
        ):
            raise ValueError("Invalid evaluation label.")
        identity = (label["app"], label["episode"])
        if identity in label_map:
            raise ValueError("Duplicate evaluation episode label.")
        label_map[identity] = label
    if set(label_map) != set(episode_scopes):
        raise ValueError("Incomplete evaluation dataset.")
    dataset_hash = digest({"inputs": inputs, "labels": labels})
    events = [e for e in inputs if e["app"] == app]
    answer = {x["episode"]: x for x in labels if x["app"] == app}
    if not events or set(answer) != {e["episode"] for e in events}:
        raise ValueError("Incomplete evaluation dataset.")
    baseline = triage(events, "baseline")
    cases = triage(events, policy)
    kept = {c["episode"] for c in cases}
    required = {key for key, value in answer.items() if value["suspicious"]}
    benign = set(answer) - required
    missed = sorted(required - kept)
    result = {
        "policy": policy,
        "dataset": "synthetic development v1",
        "events": len(events),
        "episodes": len(answer),
        "baseline_cases": len(baseline),
        "reviewable_cases": len(cases),
        "benign_cases": sum(c["episode"] in benign for c in cases),
        "required_suspicious_episodes": len(required),
        "retained_suspicious_episodes": len(required & kept),
        "missed_episodes": missed,
        "case_reduction_percent": round((len(baseline) - len(cases)) * 100 / len(baseline), 2)
        if baseline
        else None,
        "retention_percent": round(len(required & kept) * 100 / len(required), 2)
        if required
        else None,
        "safe": bool(required) and not missed,
        "cases": cases,
        "limitations": [
            "Synthetic development examples; not a blind holdout.",
            "No claim of real analyst time saved.",
            "Approval is advisory; no source-app policy is changed.",
        ],
    }
    # Do not publish a result if an edit was observed during the comparison either.
    require_runtime_source()
    return dataset_hash, engine_hash, result
