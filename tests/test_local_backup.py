"""Native SQLite recovery checks against disposable synthetic files only."""

import json
import os
import shutil
import sqlite3
import time
import unittest
import uuid
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from scripts import local_backup as backup


class LocalBackupTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[1] / "artifacts/local"
        parent.mkdir(parents=True, exist_ok=True)
        self.root = parent / ("backup-test-" + uuid.uuid4().hex)
        self.root.mkdir()

        def cleanup():
            backup.safe(parent, self.root, directory=True)
            for directory, folders, files in os.walk(self.root, followlinks=False):
                for name in folders:
                    backup.safe(self.root, Path(directory) / name, directory=True)
                for name in files:
                    backup.safe(self.root, Path(directory) / name)
            shutil.rmtree(self.root)

        self.addCleanup(cleanup)
        (self.root / "var/soc-delivery").mkdir(parents=True)
        self.db = self.root / "var/signalbridge.sqlite3"
        with closing(sqlite3.connect(self.db)) as connection:
            connection.executescript("""
                PRAGMA foreign_keys=ON;
                CREATE TABLE auth_user(id INTEGER PRIMARY KEY, password TEXT);
                CREATE TABLE bridge_event(id TEXT PRIMARY KEY, content TEXT);
                CREATE TABLE bridge_integration(id INTEGER PRIMARY KEY, slug TEXT);
                CREATE TABLE bridge_socstream(id TEXT PRIMARY KEY, offset INTEGER,
                    prefix_sha256 TEXT, integration_id INTEGER REFERENCES bridge_integration(id));
                CREATE TABLE bridge_socbatch(id INTEGER PRIMARY KEY, body TEXT, body_sha256 TEXT,
                    start_offset INTEGER, record_count INTEGER, state TEXT,
                    stream_id TEXT REFERENCES bridge_socstream(id));
                CREATE TABLE bridge_socdelivery(id INTEGER PRIMARY KEY);
                CREATE TABLE bridge_practicesession(id INTEGER PRIMARY KEY, notes TEXT);
                CREATE TABLE django_migrations(id INTEGER PRIMARY KEY);
                INSERT INTO bridge_integration VALUES(1, 'bettail');
                INSERT INTO auth_user VALUES(1, 'synthetic-nonfunctional-hash');
                INSERT INTO bridge_practicesession VALUES(1, 'Synthetic learner note: uncertainty');
                INSERT INTO bridge_event VALUES('fixture', 'synthetic private evidence');
            """)
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def stream(self, *, pending=False, partial=False):
        stream_id = uuid.uuid4().hex
        row = {
            "signalbridge": {
                "export_version": 1,
                "app": "bettail",
                "environment": "test",
                "event_id": str(uuid.uuid4()),
                "occurred_at": "2026-09-25T00:00:00Z",
                "operation": "private_record.read",
                "outcome": "denied",
                "reason": "membership_required",
                "source": "synthetic_demo",
            }
        }
        body = backup.encoded(row)
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute(
                "INSERT INTO bridge_socstream VALUES(?,?,?,1)",
                (
                    stream_id,
                    0 if pending else len(body),
                    backup.digest(b"" if pending else body),
                ),
            )
            connection.execute(
                "INSERT INTO bridge_socbatch VALUES(1,?,?,0,1,?,?)",
                (
                    body.decode(),
                    backup.digest(body),
                    "staged" if pending else "file_appended",
                    stream_id,
                ),
            )
            connection.commit()
        path = self.root / "var/soc-delivery" / (str(uuid.UUID(stream_id)) + ".jsonl")
        path.write_bytes(body[: len(body) // 2] if partial else body)
        return path

    def facts(self):
        with closing(backup.connect(self.db)) as connection:
            return backup.database_facts(connection, time.monotonic() + 10)

    def test_real_snapshot_and_restore_preserve_every_row_and_live_bytes(self):
        stream = self.stream()
        before = self.db.read_bytes(), stream.read_bytes(), self.facts()
        manifest = backup.create_backup(self.root)
        self.assertEqual(backup.verify_backup(manifest["backup_id"], self.root), manifest)
        result = backup.restore_check(manifest["backup_id"], self.root)
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["writable_copy_verified"])
        self.assertFalse(result["live_replacement"])
        restored = self.root / "var/recovery-checks" / result["run_id"] / "payload/database.sqlite3"
        with closing(backup.connect(restored)) as connection:
            self.assertEqual(
                connection.execute("SELECT notes FROM bridge_practicesession").fetchone(),
                ("Synthetic learner note: uncertainty",),
            )
            self.assertEqual(
                connection.execute("SELECT password FROM auth_user").fetchone(),
                ("synthetic-nonfunctional-hash",),
            )
        self.assertEqual(before, (self.db.read_bytes(), stream.read_bytes(), self.facts()))

    def test_wal_snapshot_includes_uncheckpointed_committed_rows(self):
        with closing(sqlite3.connect(self.db)) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute("INSERT INTO bridge_practicesession VALUES(2, 'WAL-only note')")
            writer.commit()
            manifest = backup.create_backup(self.root)
            self.assertEqual(manifest["database"]["tables"]["bridge_practicesession"]["rows"], 2)
            self.assertEqual(
                backup.restore_check(manifest["backup_id"], self.root)["status"], "passed"
            )

    def test_interrupted_append_is_preserved_without_becoming_a_committed_delivery(self):
        path = self.stream(pending=True, partial=True)
        manifest = backup.create_backup(self.root)
        state = manifest["streams"][path.name]
        self.assertEqual(state["committed_bytes"], 0)
        self.assertEqual(state["pending_bytes_written"], path.stat().st_size)
        self.assertGreater(state["staged_bytes"], state["pending_bytes_written"])
        backup.restore_check(manifest["backup_id"], self.root)

    def test_tampered_payload_fails_before_restoration(self):
        path = self.stream()
        manifest = backup.create_backup(self.root)
        directory = self.root / "var/backups" / manifest["backup_id"]
        target = directory / "soc-delivery" / path.name
        original = target.read_bytes()
        target.write_bytes(original + b"unexpected")
        with self.assertRaisesRegex(backup.BackupError, "collector_pending_tail"):
            backup.restore_check(manifest["backup_id"], self.root)
        self.assertFalse((self.root / "var/recovery-checks").exists())
        target.write_bytes(original)
        database = directory / "database.sqlite3"
        database.write_bytes(database.read_bytes() + b"changed")
        with self.assertRaisesRegex(backup.BackupError, "backup_database_digest"):
            backup.verify_backup(manifest["backup_id"], self.root)

    def test_missing_committed_file_and_unknown_file_fail_without_manifest(self):
        path = self.stream()
        raw = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(backup.BackupError, "collector_prefix"):
            backup.create_backup(self.root)
        path.write_bytes(raw)
        (path.parent / "unexpected.txt").write_text("synthetic")
        with self.assertRaisesRegex(backup.BackupError, "unknown_collector_file"):
            backup.create_backup(self.root)
        self.assertEqual(list((self.root / "var/backups").glob("*/manifest.json")), [])

    def test_manifest_identity_and_duplicate_keys_rejected(self):
        manifest = backup.create_backup(self.root)
        directory = self.root / "var/backups" / manifest["backup_id"]
        path = directory / "manifest.json"
        original = path.read_bytes()
        value = json.loads(original)
        value["workspace_id"] = "0" * 64
        path.write_bytes(backup.encoded(value))
        with self.assertRaisesRegex(backup.BackupError, "backup_workspace_mismatch"):
            backup.verify_backup(manifest["backup_id"], self.root)
        path.write_bytes(b'{"schema_version":1,' + original[1:])
        with self.assertRaisesRegex(backup.BackupError, "manifest_duplicate_key"):
            backup.verify_backup(manifest["backup_id"], self.root)
        for invalid in ("../outside", "x", "0" * 32, str(uuid.uuid1())):
            with self.subTest(invalid=invalid), self.assertRaises(backup.BackupError):
                backup.verify_backup(invalid, self.root)

    def test_wrong_ledger_hash_and_unrelated_tail_rejected(self):
        path = self.stream()
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute("UPDATE bridge_socbatch SET body_sha256=?", ("0" * 64,))
            connection.commit()
        with self.assertRaisesRegex(backup.BackupError, "batch_consistency"):
            backup.create_backup(self.root)
        self.assertTrue(path.exists())

    def test_foreign_key_damage_is_not_called_a_verified_backup(self):
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute(
                "INSERT INTO bridge_socstream VALUES(?,0,?,99)",
                (uuid.uuid4().hex, backup.digest(b"")),
            )
            connection.commit()
        with self.assertRaisesRegex(backup.BackupError, "foreign_key_integrity"):
            backup.create_backup(self.root)

    def test_busy_writer_stops_without_mutating_live_data(self):
        before = self.db.read_bytes()
        started = time.monotonic()
        with closing(sqlite3.connect(self.db)) as writer:
            writer.execute("BEGIN IMMEDIATE")
            with self.assertRaises(sqlite3.OperationalError):
                backup.create_backup(self.root)
            writer.rollback()
        self.assertLess(time.monotonic() - started, 8)
        self.assertEqual(self.db.read_bytes(), before)

    def test_budget_mode_and_deadline_fail_closed(self):
        with (
            patch.object(backup, "FREE_FLOOR", 2**63),
            self.assertRaisesRegex(backup.BackupError, "disk_reserve"),
        ):
            backup.create_backup(self.root)
        with (
            patch.dict(os.environ, {"SB_DB_HOST": "nonfunctional.invalid"}),
            self.assertRaisesRegex(backup.BackupError, "local_sqlite_only"),
        ):
            backup.create_backup(self.root)
        with (
            patch.object(backup, "SECONDS", -1),
            self.assertRaisesRegex(backup.BackupError, "operation_deadline"),
        ):
            backup.create_backup(self.root)
        with (
            patch.object(backup, "DB_LIMIT", 1),
            self.assertRaisesRegex(backup.BackupError, "database_size_limit"),
        ):
            backup.create_backup(self.root)

    def test_hardlinked_files_are_rejected(self):
        linked = self.root / "var/linked.sqlite3"
        os.link(self.db, linked)
        try:
            with self.assertRaisesRegex(backup.BackupError, "hardlink_rejected"):
                backup.create_backup(self.root)
        finally:
            linked.unlink()

    def test_paths_cannot_escape_and_existing_bundle_is_not_overwritten(self):
        with self.assertRaisesRegex(backup.BackupError, "path_boundary"):
            backup.safe(self.root, self.root / "../outside")
        manifest = backup.create_backup(self.root)
        with patch.object(backup.uuid, "uuid4", return_value=uuid.UUID(manifest["backup_id"])):
            with self.assertRaises(FileExistsError):
                backup.create_backup(self.root)
        self.assertEqual(backup.verify_backup(manifest["backup_id"], self.root), manifest)
