"""Bounded native SQLite backup and isolated restoration drill; no live replacement."""

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.runtime_identity import _plain_path, workspace_id
from integrations.wazuh.verify_static import contract_values, parse_json, validate_export
from scripts.record_verification import source_manifest

DB_LIMIT = 128 * 1024**2
STREAM_LIMIT = 16 * 1024**2
MANIFEST_LIMIT = 1024**2
MAX_ROWS = 100_000
SECONDS = 20
FREE_FLOOR = 25 * 1024**3
REQUIRED_TABLES = {
    "auth_user",
    "bridge_event",
    "bridge_integration",
    "bridge_socstream",
    "bridge_socbatch",
    "bridge_socdelivery",
    "bridge_practicesession",
    "django_migrations",
}
LIMITS = [
    "Private local SQLite/database and delivery-file recovery; no PostgreSQL or production proof.",
    "Runtime signing keys, credentials files, source checkouts and external-tool evidence are excluded.",
    "Restoration is a separate copy; it never replaces the working database or starts a server.",
    "Cooperating writers are briefly locked during backup; trusted local administrators remain a boundary.",
    "Checksums detect changed content, not malicious replacement of both payload and manifest.",
    "No host power-loss, lost-machine, encryption-at-rest or off-device disaster-recovery claim.",
]


class BackupError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise BackupError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()


def deadline_check(deadline):
    require(time.monotonic() < deadline, "operation_deadline")


def safe(root, path, *, directory=False, exists=True):
    root = Path(os.path.abspath(root))
    path = Path(os.path.abspath(path))
    require(path.is_relative_to(root), "path_boundary")
    for parent in (*reversed(path.parents), path):
        _plain_path(parent, directory=parent != path or directory)
    require(path.resolve() == path, "path_boundary")
    require(not exists or path.exists(), "path_missing")
    if path.exists() and not directory:
        require(path.stat().st_nlink == 1, "hardlink_rejected")
    return path


def bounded_read(root, path, limit):
    safe(root, path)
    info = path.stat()
    require(info.st_size <= limit, "file_size_limit")
    with path.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        require((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), "file_changed")
        raw = handle.read(limit + 1)
    require(len(raw) <= limit, "file_size_limit")
    require((path.stat().st_dev, path.stat().st_ino) == (info.st_dev, info.st_ino), "file_changed")
    return raw


def write_new(root, path, raw):
    safe(root, path, exists=False)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as handle:
        require(handle.write(raw) == len(raw), "short_write")
        handle.flush()
        os.fsync(handle.fileno())


def make_directory(root, path):
    safe(root, path, directory=True, exists=False)
    # Windows inherits the existing private runtime directory's ACL. Python's
    # special 0700 ACL excludes the desktop sandbox identity on this host.
    path.mkdir(mode=0o777 if os.name == "nt" else 0o700)
    safe(root, path, directory=True)


def identifier(value):
    try:
        require(
            type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).version == 4,
            "invalid_backup_id",
        )
    except (ValueError, AttributeError, TypeError):
        raise BackupError("invalid_backup_id") from None
    return value


def local_mode():
    require(
        os.environ.get("SB_MODE", "local") == "local"
        and not any(value for key, value in os.environ.items() if key.startswith("SB_DB_"))
        and os.environ.get("DJANGO_SETTINGS_MODULE", "config.settings") == "config.settings",
        "local_sqlite_only",
    )


def connect(path, *, write=False):
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = path.with_name(path.name + suffix)
        _plain_path(sidecar, directory=False)
        require(not sidecar.exists() or sidecar.stat().st_nlink == 1, "hardlink_rejected")
    connection = sqlite3.connect(
        path.as_uri() + ("?mode=rw" if write else "?mode=ro"), uri=True, timeout=2
    )
    connection.execute("PRAGMA trusted_schema=OFF")
    if not write:
        connection.execute("PRAGMA query_only=ON")
    return connection


def database_facts(connection, deadline):
    connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    require(
        connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "database_integrity"
    )
    require(
        not connection.execute("PRAGMA foreign_key_check").fetchmany(1), "foreign_key_integrity"
    )
    schema = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
    ).fetchall()
    tables = [row[1] for row in schema if row[0] == "table"]
    require(REQUIRED_TABLES <= set(tables) and len(tables) <= 100, "database_schema")
    facts = {}
    total = 0
    for name in tables:
        require(re.fullmatch(r"[a-z][a-z0-9_]{0,100}", name) is not None, "table_name")
        hashes = []
        # The identifier comes only from the bounded schema allow-pattern above.
        for row in connection.execute('SELECT * FROM "' + name + '"'):
            deadline_check(deadline)
            total += 1
            require(total <= MAX_ROWS, "database_row_limit")
            values = [
                (type(value).__name__, value.hex() if isinstance(value, bytes) else value)
                for value in row
            ]
            hashes.append(digest(encoded(values)))
        facts[name] = {"rows": len(hashes), "sha256": digest(encoded(sorted(hashes)))}
    return {
        "schema_sha256": digest(encoded(schema)),
        "tables": facts,
        "rows": total,
        "logical_sha256": digest(encoded([schema, facts])),
    }


def stream_state(root, connection, folder, deadline):
    """Retain committed bytes and only an exact prefix of the pending batch."""
    streams = connection.execute(
        "SELECT s.id,s.offset,s.prefix_sha256,i.slug FROM bridge_socstream s JOIN bridge_integration i ON i.id=s.integration_id ORDER BY s.id"
    ).fetchall()
    require(len(streams) <= 2, "stream_count_limit")
    expected_names = set()
    result = {}
    values = contract_values()
    for stream_id, offset, prefix, app in streams:
        deadline_check(deadline)
        require(
            app in {"bettail", "netted"} and type(offset) is int and 0 <= offset <= STREAM_LIMIT,
            "stream_scope",
        )
        name = str(uuid.UUID(stream_id)) + ".jsonl"
        expected_names.add(name)
        batches = connection.execute(
            "SELECT body,body_sha256,start_offset,record_count,state FROM bridge_socbatch WHERE stream_id=? ORDER BY start_offset,state LIMIT 1001",
            (stream_id,),
        ).fetchall()
        require(len(batches) <= 1000, "batch_count_limit")
        committed = b""
        pending = b""
        ids = set()
        records = 0
        for body, checksum, start, count, state in batches:
            deadline_check(deadline)
            require(type(body) is str and len(body) <= 128 * 1024, "batch_size")
            raw = body.encode("ascii")
            require(
                digest(raw) == checksum
                and start == len(committed)
                and state in {"staged", "file_appended"}
                and not pending,
                "batch_consistency",
            )
            lines = raw.splitlines(keepends=True)
            require(
                type(count) is int and len(lines) == count and 0 < count <= 100, "batch_records"
            )
            for line in lines:
                require(line.endswith(b"\n"), "partial_batch_record")
                event = validate_export(parse_json(line.decode("ascii")), values)
                require(event["app"] == app and event["event_id"] not in ids, "batch_event_scope")
                ids.add(event["event_id"])
            records += count
            if state == "file_appended":
                committed += raw
            else:
                pending = raw
            require(len(committed) + len(pending) <= STREAM_LIMIT, "stream_capacity")
        require(len(committed) == offset and digest(committed) == prefix, "committed_prefix")
        path = folder / name
        safe(root, path, exists=False)
        raw = bounded_read(root, path, STREAM_LIMIT) if path.exists() else b""
        require((path.exists() or offset == 0) and raw.startswith(committed), "collector_prefix")
        tail = raw[offset:]
        require(len(tail) <= len(pending) and pending.startswith(tail), "collector_pending_tail")
        result[name] = {
            "exists": path.exists(),
            "bytes": len(raw),
            "sha256": digest(raw),
            "committed_bytes": offset,
            "pending_bytes_written": len(tail),
            "staged_bytes": len(pending),
            "records": records,
        }
    if folder.exists():
        safe(root, folder, directory=True)
        actual = list(folder.iterdir())
        require(
            len(actual) <= 2 and {p.name for p in actual} <= expected_names,
            "unknown_collector_file",
        )
        for path in actual:
            safe(root, path)
    return result


def capacity(root):
    require(
        shutil.disk_usage(root).free >= FREE_FLOOR + 2 * DB_LIMIT + 4 * STREAM_LIMIT, "disk_reserve"
    )


def create_backup(root=ROOT):
    local_mode()
    root = Path(root).absolute()
    deadline = time.monotonic() + SECONDS
    capacity(root)
    db = safe(root, root / "var/signalbridge.sqlite3")
    require(db.stat().st_size <= DB_LIMIT, "database_size_limit")
    parent = root / "var/backups"
    if not parent.exists():
        make_directory(root, parent)
    safe(root, parent, directory=True)
    backup_id = str(uuid.uuid4())
    directory = parent / backup_id
    make_directory(root, directory)
    make_directory(root, directory / "soc-delivery")
    target_db = directory / "database.sqlite3"
    write_new(root, target_db, b"")
    before = source_manifest(ROOT)
    # A separate reserved writer lock freezes cooperating DB/file publishers.
    # Copy with another read connection: SQLite backup on the writing connection can stall.
    with closing(connect(db, write=True)) as lock:
        lock.execute("BEGIN IMMEDIATE")
        try:
            with closing(connect(db)) as source, closing(connect(target_db, write=True)) as target:
                page_size = source.execute("PRAGMA page_size").fetchone()[0]

                def progress(_status, _remaining, total):
                    deadline_check(deadline)
                    require(
                        total * page_size <= DB_LIMIT,
                        "database_size_limit",
                    )

                source.backup(target, pages=128, progress=progress, sleep=0.05)
                target.execute("PRAGMA journal_mode=DELETE")
                facts = database_facts(source, deadline)
                require(database_facts(target, deadline) == facts, "backup_database_mismatch")
                streams = stream_state(root, source, root / "var/soc-delivery", deadline)
                for name, item in streams.items():
                    if item["exists"]:
                        raw = bounded_read(root, root / "var/soc-delivery" / name, STREAM_LIMIT)
                        require(digest(raw) == item["sha256"], "collector_changed")
                        write_new(root, directory / "soc-delivery" / name, raw)
                require(
                    stream_state(root, target, directory / "soc-delivery", deadline) == streams,
                    "backup_stream_mismatch",
                )
        finally:
            lock.rollback()
    raw = bounded_read(root, target_db, DB_LIMIT)
    with target_db.open("r+b") as handle:
        os.fsync(handle.fileno())
    require(source_manifest(ROOT) == before, "source_changed")
    manifest = {
        "schema_version": 1,
        "kind": "signalbridge-local-backup",
        "backup_id": backup_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "workspace_id": workspace_id(root),
        "source": before,
        "database": {"bytes": len(raw), "sha256": digest(raw), **facts},
        "streams": streams,
        "limits": LIMITS,
    }
    deadline_check(deadline)
    write_new(root, directory / "manifest.json", encoded(manifest))
    return manifest


def parse_manifest(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "manifest_duplicate_key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    require(
        type(value) is dict
        and set(value)
        == {
            "schema_version",
            "kind",
            "backup_id",
            "created_at",
            "workspace_id",
            "source",
            "database",
            "streams",
            "limits",
        },
        "manifest_shape",
    )
    require(
        type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["kind"] == "signalbridge-local-backup"
        and value["limits"] == LIMITS,
        "manifest_version",
    )
    identifier(value["backup_id"])
    return value


def verify_bundle(root, directory, deadline):
    safe(root, directory, directory=True)
    require(
        {p.name for p in directory.iterdir()}
        == {"manifest.json", "database.sqlite3", "soc-delivery"},
        "bundle_inventory",
    )
    manifest = parse_manifest(bounded_read(root, directory / "manifest.json", MANIFEST_LIMIT))
    require(manifest["workspace_id"] == workspace_id(root), "backup_workspace_mismatch")
    db = directory / "database.sqlite3"
    raw = bounded_read(root, db, DB_LIMIT)
    require(
        manifest["database"]["bytes"] == len(raw) and manifest["database"]["sha256"] == digest(raw),
        "backup_database_digest",
    )
    with closing(connect(db)) as connection:
        facts = database_facts(connection, deadline)
        require(
            manifest["database"] == {"bytes": len(raw), "sha256": digest(raw), **facts},
            "backup_database_facts",
        )
        require(
            stream_state(root, connection, directory / "soc-delivery", deadline)
            == manifest["streams"],
            "backup_stream_facts",
        )
    return manifest


def verify_backup(backup_id, root=ROOT):
    local_mode()
    root = Path(root).absolute()
    manifest = verify_bundle(
        root, root / "var/backups" / identifier(backup_id), time.monotonic() + SECONDS
    )
    require(manifest["backup_id"] == backup_id, "backup_identity_mismatch")
    return manifest


def restore_check(backup_id, root=ROOT):
    local_mode()
    root = Path(root).absolute()
    capacity(root)
    deadline = time.monotonic() + SECONDS
    source = root / "var/backups" / identifier(backup_id)
    manifest = verify_bundle(root, source, deadline)
    require(manifest["backup_id"] == backup_id, "backup_identity_mismatch")
    parent = root / "var/recovery-checks"
    if not parent.exists():
        make_directory(root, parent)
    run_id = str(uuid.uuid4())
    directory = parent / run_id
    make_directory(root, directory)
    payload = directory / "payload"
    make_directory(root, payload)
    make_directory(root, payload / "soc-delivery")
    for name, limit in [("database.sqlite3", DB_LIMIT), ("manifest.json", MANIFEST_LIMIT)]:
        write_new(root, payload / name, bounded_read(root, source / name, limit))
    for name, item in manifest["streams"].items():
        # Names have been reconstructed and compared with the SQLite ledger by verify_bundle.
        if item["exists"]:
            write_new(
                root,
                payload / "soc-delivery" / name,
                bounded_read(root, source / "soc-delivery" / name, STREAM_LIMIT),
            )
    require(verify_bundle(root, payload, deadline) == manifest, "restored_bundle_mismatch")
    with closing(connect(payload / "database.sqlite3", write=True)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute("CREATE TABLE sb_restore_probe (value INTEGER NOT NULL)")
            connection.execute("INSERT INTO sb_restore_probe VALUES (1)")
            require(
                connection.execute("SELECT value FROM sb_restore_probe").fetchall() == [(1,)],
                "restored_write_probe",
            )
        finally:
            connection.rollback()
    require(verify_bundle(root, payload, deadline) == manifest, "restored_rollback_mismatch")
    require(verify_bundle(root, source, deadline) == manifest, "backup_changed")
    result = {
        "schema_version": 1,
        "kind": "signalbridge-local-restore-check",
        "status": "passed",
        "run_id": run_id,
        "backup_id": backup_id,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "logical_sha256": manifest["database"]["logical_sha256"],
        "database_rows": manifest["database"]["rows"],
        "streams": len(manifest["streams"]),
        "writable_copy_verified": True,
        "live_replacement": False,
        "limits": LIMITS,
    }
    write_new(root, directory / "result.json", encoded(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("create")
    for name in ("verify", "restore-check"):
        commands.add_parser(name).add_argument("backup_id")
    args = parser.parse_args()
    try:
        result = (
            create_backup()
            if args.action == "create"
            else verify_backup(args.backup_id)
            if args.action == "verify"
            else restore_check(args.backup_id)
        )
        print(
            json.dumps(
                {
                    "status": "passed",
                    "action": args.action,
                    "backup_id": result["backup_id"],
                    "run_id": result.get("run_id"),
                    "live_replacement": False,
                }
            )
        )
        print(
            "Private recovery material stays under var/. Runtime keys are excluded; preserve the original configuration separately."
        )
        return 0
    except (
        BackupError,
        OSError,
        sqlite3.Error,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
    ) as error:
        print(
            "Recovery operation stopped: "
            + (str(error) if type(error) is BackupError else type(error).__name__)
            + ". Preserve partial files for review.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
