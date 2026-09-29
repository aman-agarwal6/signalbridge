"""Refresh local offline proof and the employer viewer; no native labs or publication.

Uses the installed interpreter and Node, fixed core checks, and two bounded
in-memory profiles. Raw logs stay private; public summaries contain validated
fields only. A failed/interrupted run preserves its marker for operator review.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge import challenge_evidence, simulation_evidence
from scripts import portfolio, record_verification, run_enterprise_lab
from scripts.check_publication import collect_secrets
from simulations.challenge_cases import declaration_sha256

MAX_BYTES = 2 * 1024 * 1024


class RefreshError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise RefreshError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_aux(root, directory, name):
    require(name in {"stdout.txt", "stderr.txt", "declaration.json"}, "Invalid evidence file.")
    path = directory / name
    portfolio.unlinked(root, path)
    require(
        path.is_file() and path.stat().st_size <= MAX_BYTES, "Evidence file missing or oversized."
    )
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "Evidence file oversized.")
    return raw


def curate(root, run_id, *, challenge=False):
    """Validate retained bytes and create a new bounded summary, never copy logs."""
    require(type(challenge) is bool, "Choose a fixed simulation profile.")
    raw = simulation_evidence.read_fixed(root, run_id, "result.json")
    provenance_raw = simulation_evidence.read_fixed(root, run_id, "provenance.json")
    report = simulation_evidence.json_document(raw)
    provenance = simulation_evidence.json_document(provenance_raw)
    current = record_verification.source_manifest(root)
    simulation_evidence.validate_manifest(current)
    require(
        type(provenance["schema_version"]) is int
        and provenance["schema_version"] == 1
        and provenance["run_id"] == run_id
        and provenance["source_before"] == provenance["source_after"] == current
        and provenance["source_unchanged"] is True
        and provenance["execution_verified"] is True
        and type(provenance["exit_code"]) is int
        and provenance["exit_code"] == 0,
        "Simulation did not verify unchanged current source.",
    )
    require(provenance["result_sha256"] == sha(raw), "Retained result digest differs.")
    require(
        isinstance(provenance["git"]["head"], str)
        and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", provenance["git"]["head"])
        and type(provenance["git"]["dirty"]) is bool
        and isinstance(provenance["python"], str)
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", provenance["python"]),
        "Invalid runtime or revision identity.",
    )
    require(set(provenance["logs"]) == {"stdout.txt", "stderr.txt"}, "Invalid log inventory.")
    directory = root / "artifacts/local/simulation" / run_id
    retained_aux = {}
    for name, expected in provenance["logs"].items():
        retained_aux[name] = read_aux(root, directory, name)
        require(sha(retained_aux[name]) == expected, "Retained log digest differs.")
    if challenge:
        status, normalized = challenge_evidence.validate_result(report)
        retained_aux["declaration.json"] = read_aux(root, directory, "declaration.json")
        require(
            provenance["coverage_status"] == status
            and provenance["declaration_unchanged"] is True
            and provenance["declaration_sha256"] == declaration_sha256()
            and sha(retained_aux["declaration.json"]) == declaration_sha256(),
            "Challenge declaration or coverage differs.",
        )
        limits = challenge_evidence.LIMITS
    else:
        simulation_evidence.validate_evidence(run_id, raw, provenance_raw)
        status, normalized = simulation_evidence.validate_result(report)
        # The public result uses the producer schema; derived coverage is rebuilt
        # by consumers. Free-form producer descriptions are replaced by constants.
        normalized.pop("coverage")
        limits = simulation_evidence.LIMITS
    require(
        simulation_evidence.stamp(normalized["finished_at"]) <= datetime.now(timezone.utc),
        "Execution time is in the future.",
    )
    receipt = {
        "schema_version": 1,
        "kind": "signalbridge-detection-challenge-receipt"
        if challenge
        else "signalbridge-offline-simulation-receipt",
        "run_id": run_id,
        "execution_verified": True,
        "source_sha256": current["sha256"],
        "source_file_count": current["file_count"],
        "source_unchanged": True,
        "git_head_at_execution": provenance["git"]["head"],
        "working_tree_dirty_at_execution": provenance["git"]["dirty"],
        "python": provenance["python"],
        "exit_code": 0,
        "result_sha256": sha(raw),
        "provenance_sha256": sha(provenance_raw),
        "log_sha256": dict(provenance["logs"]),
        "results": normalized,
        "limits": limits,
    }
    encoded = (json.dumps(receipt, indent=2, allow_nan=False) + "\n").encode("utf8")
    require(
        not any(secret.encode("utf8") in encoded for secret in collect_secrets(root)),
        "Known private value detected; summary withheld.",
    )
    profile = "challenge" if challenge else "simulation"
    name = f"{datetime.now(timezone.utc):%Y%m%d}-{profile}-{run_id}.json"
    target = root / "docs/evidence" / name
    portfolio.unlinked(root, target)
    target.parent.mkdir(parents=True, exist_ok=True)
    require(record_verification.source_manifest(root) == current, "Source changed during curation.")
    require(
        simulation_evidence.read_fixed(root, run_id, "result.json") == raw
        and simulation_evidence.read_fixed(root, run_id, "provenance.json") == provenance_raw
        and all(read_aux(root, directory, name) == saved for name, saved in retained_aux.items()),
        "Retained evidence changed during curation.",
    )
    with target.open("xb") as handle:
        handle.write(encoded)
    return name, status


def refresh(root=ROOT):
    root = Path(root).resolve(strict=True)
    marker = root / "var/evidence-refresh.lock"
    portfolio.unlinked(root, marker)
    marker.parent.mkdir(exist_ok=True)
    run_id = uuid.uuid4().hex
    token = json.dumps({"run_id": run_id, "pid": os.getpid()}) + "\n"
    try:
        with marker.open("x", encoding="utf8") as handle:
            handle.write(token)
    except FileExistsError:
        raise RefreshError(
            "A refresh marker exists. Inspect the recorded run before retrying."
        ) from None
    output = root / "var/evidence-refresh" / run_id
    portfolio.unlinked(root, output)
    output.mkdir(parents=True, exist_ok=False)
    summary = {"run_id": run_id, "status": "started", "stages": {}}
    completed = False
    try:
        before = record_verification.source_manifest(root)
        print("1/4: recording fixed offline software verification.", flush=True)
        core, _ = record_verification.run_verification(root=root, export_public=True)
        summary["stages"]["core"] = core["run_id"]
        require(core["passed"] is True, "Core checks did not pass; viewer was not refreshed.")
        selected = {}
        for name, challenge in (("simulation", False), ("challenge", True)):
            print(f"{'3' if challenge else '2'}/4: running the fixed {name} profile.", flush=True)
            execution, _ = run_enterprise_lab.run(challenge=challenge)
            summary["stages"][name] = execution["run_id"]
            require(execution["execution_verified"] is True, "Simulation execution did not verify.")
            filename, coverage = curate(root, execution["run_id"], challenge=challenge)
            selected[name] = filename
            summary[name + "_coverage"] = coverage
        require(
            record_verification.source_manifest(root) == before, "Source changed during refresh."
        )
        print("4/4: rebuilding the viewer from the verified summaries.", flush=True)
        portfolio.build(
            root=root,
            core_receipt=core["run_id"] + ".json",
            simulation_receipt=selected["simulation"],
            challenge_receipt=selected["challenge"],
        )
        portfolio.unlinked(root, marker)
        require(
            marker.read_text(encoding="utf8") == token,
            "Refresh marker changed; preserved for review.",
        )
        summary.update(status="completed", source_sha256=before["sha256"], receipts=selected)
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf8")
        marker.unlink()
        completed = True
        return summary
    finally:
        if not completed:
            summary["status"] = "incomplete; marker and evidence preserved"
            (output / "summary.json").write_text(
                json.dumps(summary, indent=2) + "\n", encoding="utf8"
            )


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    try:
        summary = refresh()
    except (ValueError, OSError, KeyError, TypeError):
        print(
            "Refresh incomplete. Inspect var/evidence-refresh and its marker; preserve prior evidence."
        )
        return 1
    print(json.dumps(summary, indent=2))
    print("Viewer refreshed locally. Native integrations were not rerun; nothing was published.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
