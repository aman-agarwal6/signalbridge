"""Host-side reliability measurement over a retained run; no Docker or network.

Reads only the run's own evidence folder, assembles the closed ledger and calls
the declared analyzer. A rehearsal is measured for diagnostics only and can
never report the 24-hour targets as met.
"""

import json
from datetime import datetime
from pathlib import Path

from .reference_host_evidence import safe_path
from .reliability import DAY_MS, FINAL_DRAIN_MS, declaration_hash, measure
from .reliability_ledger import assemble

MAX_EVIDENCE = 256 * 1024**2


def read(path, root, limit=MAX_EVIDENCE):
    checked = safe_path(path, root)
    if not checked.is_file() or checked.stat().st_size > limit:
        raise ValueError("Reliability evidence is missing or exceeds its bound.")
    return checked.read_bytes()


def manager_archive(directory):
    """The manager's sealed capture; absent when no manager ran (tool targets fail)."""
    path = Path(directory) / "wazuh/evidence/native-archives.jsonl"
    return read(path, directory, 512 * 1024**2) if path.exists() else b""


def evaluate(directory, *, rehearsal_ms=0, archive_raw=None):
    directory = Path(directory)
    evidence = directory / "evidence"
    clock = json.loads(read(directory / "clock/reliability-clock.json", directory, 4096))
    archive_raw = manager_archive(directory) if archive_raw is None else archive_raw
    samples = evidence / "reliability-clock-samples.jsonl"
    samples_raw = read(samples, directory, 32 * 1024**2) if samples.exists() else b""
    origin = datetime.fromisoformat(clock["origin_utc"])
    source = read(evidence / "reliability-source/source.jsonl", directory)
    requests = read(evidence / "reliability-source/requests.jsonl", directory)
    attempts = [
        read(path, directory)
        for path in sorted((evidence / "reliability-collector").glob("attempts-*.jsonl"))
    ]
    stored = read(evidence / "reliability-stored.jsonl", directory)
    rows, counts = assemble(
        source_raw=source,
        attempt_files=attempts,
        stored_raw=stored,
        archive_raw=archive_raw,
        origin=origin,
        samples_raw=samples_raw,
        requests_raw=requests,
    )
    runner = json.loads(read(evidence / "reliability-runner.json", directory, 262144))
    elapsed = (
        DAY_MS + FINAL_DRAIN_MS
        if not rehearsal_ms
        else min(
            DAY_MS + FINAL_DRAIN_MS,
            max(
                [0]
                + [v for r in rows for k, v in r.items() if k.endswith("_ms") and type(v) is int]
            ),
        )
    )
    result = measure(rows, elapsed_ms=elapsed, profile_sha256=declaration_hash())
    if rehearsal_ms:
        result["status"] = "rehearsal_not_a_24_hour_result"
    return {"measurement": result, "ledger_counts": counts, "runner": runner}
