"""Blind evaluation: scenarios written by someone who never saw SignalBridge's rules.

The steps, run from the repository root:
    python -m detections.blind.blind freeze ROUND   # record the rules before the author starts
    python -m detections.blind.blind check FILE     # format check only; never runs the detector
    python -m detections.blind.blind seal ROUND FILE  # copy and hash the author's file on receipt
    python -m detections.blind.blind score ROUND    # run the frozen rules once and write the result

See detections/blind/README.md for the protocol and AUTHOR-GUIDE.md for the author's brief.
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from bridge.contract import OPERATIONS, OUTCOMES, REASONS, ContractError, validate_event
from scripts.evaluate_detection import FROZEN_FILES, metrics

from ..sigma.compile import sqlite_queries
from ..sigma.replay import BASE, ROOT, python_rules, sigma_rules

HERE = Path(__file__).parent
ROUNDS = HERE / "rounds"
# Everything that decides a verdict: the official evaluator's frozen files, the event rebuild
# and Sigma code, the Sigma rules and this file. Score refuses if any changed after freeze.
RULE_FILES = (
    *FROZEN_FILES,
    "detections/sigma/replay.py",
    "detections/sigma/compile.py",
    "detections/blind/blind.py",
)
RULE_GLOBS = ("detections/sigma/rules/*.yml",)
ATTESTATION = (
    "I wrote these scenarios without reading SignalBridge's detection rules, code or "
    "documentation beyond the author guide, and without discussing the rules with its builder."
)
PRIVATE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+|\b\d{1,3}(?:\.\d{1,3}){3}\b")
APPS = ("documents", "expenses")
SOURCES = ("instrumented_lab", "synthetic_demo")
ENVIRONMENTS = ("test", "lab")
LABELS = ("suspicious", "benign", "inconclusive")
EVENT_KEYS = {"at", "app", "environment", "source", "actor", "resource", "operation"}
EVENT_KEYS |= {"outcome", "reason", "membership"}
NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,39}")
ROUND = re.compile(r"[a-z0-9][a-z0-9-]{2,40}")
MAX_SECONDS = 172800


class BlindError(ValueError):
    pass


def sha256(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def rule_hashes():
    files = [ROOT / name for name in RULE_FILES]
    for pattern in RULE_GLOBS:
        files += sorted(ROOT.glob(pattern))
    return {path.relative_to(ROOT).as_posix(): sha256(path) for path in files}


def round_dir(name):
    if not ROUND.fullmatch(name):
        raise BlindError("Round names use lowercase letters, digits and hyphens.")
    return ROUNDS / name


def seconds(value, where):
    """Times are offsets from the scenario start: 90, "1:30" or "1:00:00"."""
    if isinstance(value, bool):
        raise BlindError(f"{where}: 'at' must be a time such as 0:30 or 1:05:00.")
    if isinstance(value, int):
        total = value
    elif isinstance(value, str) and re.fullmatch(r"\d{1,3}(:\d{2}){1,2}", value.strip()):
        total = 0
        for part in value.strip().split(":"):
            total = total * 60 + int(part)
    else:
        raise BlindError(f"{where}: 'at' must be a time such as 0:30 or 1:05:00.")
    if not 0 <= total <= MAX_SECONDS:
        raise BlindError(f"{where}: times must be between 0:00 and 48:00:00.")
    return total


def private_text(value, where):
    # Synthetic data only: reject anything shaped like an email or IP address.
    if PRIVATE.search(value):
        raise BlindError(f"{where}: remove email or IP addresses; use made-up names only.")


def choice(value, allowed, where, field):
    if value not in allowed:
        raise BlindError(f"{where}: '{field}' must be one of {', '.join(allowed)}.")
    return value


def name(value, where, field):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise BlindError(
            f"{where}: '{field}' must be a short lowercase name such as alice or doc-1."
        )
    return value


def load(path):
    """Parse and check an author file. Raises BlindError with a plain message."""
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except yaml.YAMLError as error:
        raise BlindError(f"The file is not valid YAML: {error}") from None
    if not isinstance(data, dict) or set(data) != {"author", "attestation", "scenarios"}:
        raise BlindError(
            "The file needs exactly three top-level keys: author, attestation, scenarios."
        )
    if not isinstance(data["author"], str) or not 1 <= len(data["author"].strip()) <= 80:
        raise BlindError("'author' is how you want to be credited publicly, or 'anonymous'.")
    if (
        not isinstance(data["attestation"], str)
        or " ".join(data["attestation"].split()) != ATTESTATION
    ):
        raise BlindError("'attestation' must be the exact statement from the guide, unchanged.")
    private_text(data["author"], "author")
    scenarios = data["scenarios"]
    if not isinstance(scenarios, list) or not 20 <= len(scenarios) <= 60:
        raise BlindError("Write between 20 and 60 scenarios.")
    seen = set()
    for scenario in scenarios:
        check_scenario(scenario, seen)
    return data


def check_scenario(scenario, seen):
    if not isinstance(scenario, dict):
        raise BlindError(
            "Each scenario must be a mapping with id, title, label, rationale and events."
        )
    sid = scenario.get("id")
    where = f"scenario {sid!r}"
    if set(scenario) != {"id", "title", "label", "rationale", "events"}:
        raise BlindError(f"{where}: use exactly id, title, label, rationale and events.")
    if not isinstance(sid, str) or not re.fullmatch(r"B\d{2}", sid):
        raise BlindError(f"{where}: ids are B01, B02 and so on (the EX examples must be replaced).")
    if sid in seen:
        raise BlindError(f"{where}: this id is used twice.")
    seen.add(sid)
    for field in ("title", "rationale"):
        if not isinstance(scenario[field], str) or not 3 <= len(scenario[field].strip()) <= 1000:
            raise BlindError(f"{where}: '{field}' needs a sentence (up to 1000 characters).")
        private_text(scenario[field], f"{where} {field}")
    choice(scenario["label"], LABELS, where, "label")
    events = scenario["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= 30:
        raise BlindError(f"{where}: give between 1 and 30 events.")
    for number, event in enumerate(events, 1):
        check_event(event, f"{where}, event {number}")


def check_event(event, where):
    if not isinstance(event, dict) or not set(event) <= EVENT_KEYS:
        unknown = sorted(set(event) - EVENT_KEYS) if isinstance(event, dict) else []
        raise BlindError(f"{where}: unknown fields {unknown}; see the guide for the allowed ones.")
    for field in ("at", "actor", "resource", "operation", "outcome", "reason"):
        if field not in event:
            raise BlindError(f"{where}: '{field}' is required.")
    seconds(event["at"], where)
    choice(event.get("app", "documents"), APPS, where, "app")
    choice(event.get("environment", "test"), ENVIRONMENTS, where, "environment")
    choice(event.get("source", "instrumented_lab"), SOURCES, where, "source")
    name(event["actor"], where, "actor")
    name(event["resource"], where, "resource")
    choice(event["operation"], sorted(OPERATIONS), where, "operation")
    choice(event["outcome"], sorted(OUTCOMES), where, "outcome")
    choice(event["reason"], sorted(REASONS), where, "reason")
    membership = event.get("membership")
    if event["operation"] == "membership.change":
        if not isinstance(membership, dict) or set(membership) != {"subject", "state"}:
            raise BlindError(f"{where}: a membership.change needs membership: {{subject, state}}.")
        name(membership["subject"], where, "membership subject")
        state = choice(membership["state"], ("removed", "granted"), where, "membership state")
        expected = "membership_removed" if state == "removed" else "member"
        if event["outcome"] != "allowed" or event["reason"] != expected:
            raise BlindError(
                f"{where}: a membership change is recorded with outcome allowed and reason "
                f"{expected} (state {state})."
            )
    elif membership is not None:
        raise BlindError(f"{where}: only membership.change events have a membership field.")


def pseudonym(round_name, scenario_id, app, name_value):
    """Stable, scenario-scoped stand-in for a name, in the contract's 64-hex format."""
    key = f"blind/{round_name}/{scenario_id}/{app}/{name_value}"
    return hashlib.sha256(key.encode()).hexdigest()


def convert(round_name, index, scenario):
    """One author scenario as (source, event) pairs, in the contract's wire format."""
    identity = f"blind/{round_name}/{scenario['id']}"
    events = []
    for position, raw in enumerate(scenario["events"]):
        scope = raw.get("app", "documents")
        app = f"blind-{round_name}-{index}-{scope}"
        at = BASE + timedelta(seconds=seconds(raw["at"], scenario["id"]))
        event = {
            "schema_version": 2 if raw["operation"] == "membership.change" else 1,
            "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{identity}/{position}")),
            "app": app,
            "environment": raw.get("environment", "test"),
            "occurred_at": at.isoformat(),
            "actor": pseudonym(round_name, scenario["id"], scope, raw["actor"]),
            "resource": pseudonym(round_name, scenario["id"], scope, raw["resource"]),
            "episode": str(uuid.uuid5(uuid.NAMESPACE_URL, identity)),
            "operation": raw["operation"],
            "outcome": raw["outcome"],
            "reason": raw["reason"],
            "context": None,
        }
        if raw["operation"] == "membership.change":
            subject = raw["membership"]["subject"]
            event["membership"] = {
                "subject": pseudonym(round_name, scenario["id"], scope, subject),
                "state": raw["membership"]["state"],
            }
        try:
            validate_event(event, app, now=at)
        except ContractError as error:
            raise BlindError(f"scenario {scenario['id']}: {error}") from None
        events.append((raw.get("source", "instrumented_lab"), event))
    return events


def git_commit():
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() or None if result.returncode == 0 else None


def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def write_json(path, value):
    if path.exists():
        raise BlindError(f"{path.name} already exists; each step runs once per round.")
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")


def freeze(round_name):
    target = round_dir(round_name)
    target.mkdir(parents=True, exist_ok=True)
    write_json(
        target / "freeze.json",
        {"round": round_name, "frozen_at": now(), "commit": git_commit(), "files": rule_hashes()},
    )


def seal(round_name, source):
    target = round_dir(round_name)
    if not (target / "freeze.json").exists():
        raise BlindError("Freeze the round before the author starts, then seal what they send.")
    data = load(source)
    copy = target / "scenarios.yml"
    if copy.exists():
        raise BlindError("This round is already sealed.")
    shutil.copyfile(source, copy)
    write_json(
        target / "seal.json",
        {
            "round": round_name,
            "sealed_at": now(),
            "scenarios_sha256": sha256(copy),
            "scenarios": len(data["scenarios"]),
            "author": data["author"].strip(),
            "attestation": ATTESTATION,
        },
    )


def score(round_name):
    target = round_dir(round_name)
    frozen = json.loads((target / "freeze.json").read_text(encoding="utf-8"))
    sealed = json.loads((target / "seal.json").read_text(encoding="utf-8"))
    if frozen["files"] != rule_hashes():
        raise BlindError(
            "A frozen file changed after the freeze; this round cannot be scored. If a fix was"
            " needed, freeze a new round openly and say so."
        )
    copy = target / "scenarios.yml"
    if sha256(copy) != sealed["scenarios_sha256"]:
        raise BlindError("The sealed scenario file was changed after sealing.")
    data = load(copy)
    queries = sqlite_queries()
    rows = []
    for index, scenario in enumerate(data["scenarios"]):
        events = convert(round_name, index, scenario)
        python, sigma = python_rules(events), sigma_rules(events, queries)
        rows.append(
            {
                "id": scenario["id"],
                "title": scenario["title"],
                "label": scenario["label"],
                "rationale": scenario["rationale"],
                "python_rules": python,
                "sigma_rules": sigma,
                "alerted": bool(python),
            }
        )
    sigma_rows = [{**row, "alerted": bool(row["sigma_rules"])} for row in rows]
    write_json(
        target / "result.json",
        {
            "kind": "signalbridge-blind-evaluation",
            "round": round_name,
            "scored_at": now(),
            "freeze": frozen,
            "seal": sealed,
            "unit": "One scenario; any rule that fires counts as an alert.",
            "metrics": metrics(rows),
            "sigma_metrics": metrics(sigma_rows),
            "scenarios": rows,
            "limits": [
                "Author-attested blind: the author signed that they did not read the rules, but the repository is public, so this cannot be enforced.",
                "One external author's synthetic scenarios; not an independent accuracy measurement or production traffic.",
                "Scored once with every verdict-deciding file frozen before the author started; no file changed for this round.",
                "Scored with bridge.engine.detections() on the converted events, which reproduced the full evaluator in 48 of 48 frozen scenarios; not the Django pipeline itself.",
            ],
        },
    )
    return json.loads((target / "result.json").read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("freeze").add_argument("round")
    sub.add_parser("check").add_argument("file")
    sealer = sub.add_parser("seal")
    sealer.add_argument("round")
    sealer.add_argument("file")
    sub.add_parser("score").add_argument("round")
    args = parser.parse_args()
    try:
        if args.command == "freeze":
            freeze(args.round)
            print(f"Froze {len(rule_hashes())} rule files for round {args.round}.")
        elif args.command == "check":
            data = load(args.file)
            print(f"Format OK: {len(data['scenarios'])} scenarios. (The detector was not run.)")
        elif args.command == "seal":
            seal(args.round, args.file)
            print(f"Sealed round {args.round}.")
        else:
            result = score(args.round)
            print(json.dumps(result["metrics"], indent=2))
    except BlindError as error:
        print(f"Not accepted: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
