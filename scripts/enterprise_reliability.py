"""Print the fixed proposal or measure one retained, bounded synthetic ledger.

No launch, download, service control, environment changes or output-file writes.
"""

import argparse
import hashlib
import json
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrations.enterprise.reliability import (
    MAX_BYTES,
    LedgerError,
    declaration,
    declaration_hash,
    json_lines,
    measure,
)


def ledger_path(value):
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    boundary = ROOT / "var" / "enterprise" / "reliability"
    if not path.is_relative_to(boundary) or ".." in path.parts or path.suffix != ".jsonl":
        raise LedgerError("ledger_outside_reliability_directory")
    for candidate in (path, *path.parents):
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise LedgerError("redirected_ledger")
        if candidate == ROOT:
            break
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
        raise LedgerError("invalid_ledger_file")
    if not path.resolve().is_relative_to(boundary.resolve()):
        raise LedgerError("redirected_ledger")
    return path


class HashedReader:
    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()

    def readline(self, maximum):
        raw = self.stream.readline(maximum)
        self.digest.update(raw)
        return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("declaration")
    analyze = commands.add_parser("measure")
    analyze.add_argument("--ledger", required=True)
    analyze.add_argument("--elapsed-ms", required=True, type=int)
    analyze.add_argument("--profile-sha256", required=True)
    args = parser.parse_args(argv)
    if args.command == "declaration":
        print(json.dumps({"declaration": declaration(), "sha256": declaration_hash()}, indent=2))
        return 0
    try:
        path = ledger_path(args.ledger)
        with path.open("rb") as stream:
            reader = HashedReader(stream)
            result = measure(
                json_lines(reader),
                elapsed_ms=args.elapsed_ms,
                profile_sha256=args.profile_sha256,
            )
            result["ledger_sha256"] = reader.digest.hexdigest()
    except (OSError, LedgerError):
        print(json.dumps({"status": "invalid_ledger", "native_acceptance": "not_established"}))
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "ledger_targets_met" else 1


if __name__ == "__main__":
    raise SystemExit(main())
