"""Preserve exact SOC gate inputs before a pilot; no Docker or service operations.

Creates one new, immutable-by-convention snapshot under the fixed private run.
An interrupted copy is retained without a completion manifest and cannot be reused.
This does not make a filesystem immutable to its owner or provide crash durability.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import verify_soc_pilot as gate

SCRIPTS = ("verify_soc_pilot.py", "verify_supabase_isolation.py")
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILES = 258
SnapshotError = gate.VerificationError


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _relative(value):
    return (
        isinstance(value, str)
        and 0 < len(value) <= 500
        and "\\" not in value
        and ":" not in value
        and all(part not in ("", ".", "..") for part in value.split("/"))
        and all(char.isprintable() for char in value)
    )


def copy_plan(profile, source):
    """Flatten only the gate's current closed source schema into fixed relative paths."""
    if (
        profile not in gate.NAMES
        or not isinstance(source, dict)
        or set(source) != {"package", *SCRIPTS}
    ):
        raise SnapshotError("soc_snapshot_source_schema")
    package = source["package"]
    if not isinstance(package, dict) or not 1 <= len(package) <= MAX_FILES - len(SCRIPTS):
        raise SnapshotError("soc_snapshot_file_inventory")
    rows = []
    for relative, digest in package.items():
        if not _relative(relative) or not _digest(digest):
            raise SnapshotError("soc_snapshot_source_schema")
        rows.append(("package/" + relative, ROOT / "integrations" / profile / relative, digest))
    for name in SCRIPTS:
        if not _digest(source[name]):
            raise SnapshotError("soc_snapshot_source_schema")
        rows.append(("scripts/" + name, ROOT / "scripts" / name, source[name]))
    if len({relative.casefold() for relative, _, _ in rows}) != len(rows):
        raise SnapshotError("soc_snapshot_ambiguous_path")
    return sorted(rows)


def read_checked(path, expected):
    info = gate._safe(path, directory=False)
    if info.st_size > MAX_FILE_BYTES:
        raise SnapshotError("soc_snapshot_file_bound")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_nlink) != (info.st_dev, info.st_ino, 1):
            raise SnapshotError("soc_snapshot_file_changed")
        raw = stream.read(MAX_FILE_BYTES + 1)
    after = gate._safe(path, directory=False)
    if (after.st_dev, after.st_ino, after.st_size) != (info.st_dev, info.st_ino, info.st_size):
        raise SnapshotError("soc_snapshot_file_changed")
    if len(raw) > MAX_FILE_BYTES or hashlib.sha256(raw).hexdigest() != expected:
        raise SnapshotError("soc_snapshot_content_changed")
    return raw


def _write(path, raw):
    gate._safe(path.parent, directory=True)
    with path.open("xb") as handle:
        handle.write(raw)
    gate._safe(path, directory=False)


def _mkdir(path):
    gate._safe(path.parent, directory=True)
    path.mkdir()  # Exclusive and ordinary inherited workspace ACL; never chmod the host.
    gate._safe(path, directory=True)


def snapshot(profile, run_id):
    gate.validate_request(profile, run_id, "created")
    if ROOT != gate.ROOT:
        raise SnapshotError("soc_snapshot_workspace_mismatch")
    source = gate.source_hashes(profile, run_id)
    plan = copy_plan(profile, source)
    # Validate every source and byte bound before creating any output directory.
    total = 0
    for _, path, expected in plan:
        total += len(read_checked(path, expected))
        if total > MAX_TOTAL_BYTES:
            raise SnapshotError("soc_snapshot_total_bound")
    run_directory = ROOT / "var/soc/pilot" / run_id
    gate._safe(run_directory, directory=True)
    source_directory = run_directory / "source"
    if source_directory.exists():
        gate._safe(source_directory, directory=True)
    else:
        _mkdir(source_directory)
    destination = source_directory / profile
    _mkdir(destination)  # Existing complete or interrupted snapshots always fail closed.
    created = {destination}
    for relative, path, expected in plan:
        target = destination / relative
        for parent in reversed(target.parents):
            if parent.is_relative_to(destination) and parent not in created:
                _mkdir(parent)
                created.add(parent)
        raw = read_checked(path, expected)
        _write(target, raw)
        read_checked(target, expected)
    if gate.source_hashes(profile, run_id) != source:
        raise SnapshotError("soc_snapshot_source_changed_during_copy")
    helper = ROOT / "scripts/snapshot_soc_pilot.py"
    gate._safe(helper, directory=False)
    manifest = {
        "schema_version": 1,
        "profile": profile,
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat(),
        "source_sha256": gate.base.sha256(gate.base.canonical(source)),
        "source_manifest": source,
        "files": {relative: expected for relative, _, expected in plan},
        "snapshot_helper_sha256": gate.base.sha256(helper.read_bytes()),
        "byte_count": total,
        "limitations": [
            "Retained copied source, not an independent or tamper-proof attestation.",
            "Local filesystem owner remains trusted; no permission changes or fsync durability claim.",
            "Snapshot includes gate inputs only, not container image contents, private outputs or secrets.",
        ],
    }
    raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    digest = gate.base.sha256(raw)
    _write(destination / "manifest.sha256", (digest + "\n").encode())
    _write(destination / "manifest.json", raw)  # Completion record is deliberately last.
    return {
        "status": "passed",
        "profile": profile,
        "run_id": run_id,
        "source_sha256": manifest["source_sha256"],
        "manifest_sha256": digest,
        "file_count": len(plan),
        "byte_count": total,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=tuple(gate.NAMES), required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        result = snapshot(args.profile, args.run_id)
    except SnapshotError as error:
        result = {"status": "failed", "errors": [str(error)]}
    except (OSError, ValueError, TypeError):
        result = {"status": "failed", "errors": ["soc_snapshot_unavailable_or_incomplete"]}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
