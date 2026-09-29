"""Migration runner guard tests with synthetic files and mocked PostgreSQL only."""

import hashlib
import json
import os
import shutil
import uuid
from contextlib import redirect_stdout
from io import StringIO
from unittest import TestCase
from unittest.mock import MagicMock, patch

from scripts import migrate_supabase_lab as migration


class MigrationGuardTests(TestCase):
    def setUp(self):
        self.test_root = migration.ROOT / "var/tests"
        self.root = self.test_root / ("migration-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup)
        self.lab = self.root / "var/labs/bettail"
        self.snapshot = self.root / "synthetic-snapshot"
        self.sql = b"begin; select 'synthetic fixture'; commit;"
        path = self.snapshot / "supabase/migrations/001_synthetic.sql"
        path.parent.mkdir(parents=True)
        path.write_bytes(self.sql)
        self.files = [{"file": path.name, "sha256": hashlib.sha256(self.sql).hexdigest()}]
        self.metadata = {
            "app": "bettail",
            "snapshot_digest": "a" * 64,
            "source_revision": "b" * 40,
            "source_dirty": True,
            "files": {"supabase/migrations/" + path.name: self.files[0]["sha256"]},
        }
        self.connection = MagicMock()
        self.connection.__enter__.return_value = self.connection
        self.cursor = MagicMock()
        self.connection.cursor.return_value.__enter__.return_value = self.cursor
        self.cursor.fetchone.side_effect = [("off",), (None, None), ("off",), (False, False, False)]
        self.cursor.fetchall.return_value = [
            (item["file"], item["sha256"], self.metadata["source_revision"]) for item in self.files
        ]
        self.patches = [
            patch.object(migration, "ROOT", self.root),
            patch.object(migration, "LAB", self.lab),
            patch.object(migration, "manifest", return_value=(self.metadata, self.files)),
            patch.object(migration, "isolation_gate"),
            patch.object(migration.psycopg, "connect", return_value=self.connection),
            patch.dict(
                os.environ,
                {
                    "PGHOSTADDR": "203.0.113.40",
                    "PGSERVICE": "forbidden-service",
                    "PGPASSFILE": "forbidden-password-file",
                    "PGOPTIONS": "-c statement_timeout=0",
                },
            ),
            patch.object(migration, "read_database_password", return_value="0123456789abcdef" * 4),
        ]
        self.started = [item.start() for item in self.patches]
        for item in reversed(self.patches):
            self.addCleanup(item.stop)
        self.manifest_mock, self.gate, self.connect = self.started[2:5]

    def cleanup(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.test_root.resolve()) or not target.name.startswith(
            "migration-"
        ):
            raise RuntimeError("Unsafe test cleanup target")
        shutil.rmtree(target)

    def run_main(self):
        with redirect_stdout(StringIO()):
            return migration.main([str(self.snapshot)])

    def recorded_report(self):
        paths = list((self.lab / "migration-runs").glob("*.json"))
        self.assertEqual(len(paths), 1)
        return json.loads(paths[0].read_text(encoding="utf-8"))

    def executed(self):
        return [call.args[0] for call in self.cursor.execute.call_args_list]

    def test_environment_overrides_are_removed_before_gate_and_failed_gate_never_connects(self):
        def reject():
            self.assertFalse(any(name.upper().startswith("PG") for name in os.environ))
            raise ValueError("Synthetic isolation rejection")

        self.gate.side_effect = reject
        with self.assertRaises(ValueError):
            self.run_main()
        self.connect.assert_not_called()
        self.assertFalse(self.lab.exists())

    def test_invalid_snapshot_or_provenance_never_reaches_isolation_or_database(self):
        self.manifest_mock.side_effect = ValueError("Synthetic invalid snapshot provenance")
        with self.assertRaises(ValueError):
            self.run_main()
        self.gate.assert_not_called()
        self.connect.assert_not_called()
        self.assertFalse(self.lab.exists())

    def test_success_uses_fixed_host_and_hostaddr_and_records_per_file_evidence(self):
        def connect(**kwargs):
            self.assertFalse(any(name.upper().startswith("PG") for name in os.environ))
            return self.connection

        self.connect.side_effect = connect
        self.assertEqual(self.run_main(), 0)
        kwargs = self.connect.call_args.kwargs
        self.assertEqual(
            (kwargs["host"], kwargs["hostaddr"], kwargs["port"]), ("127.0.0.1", "127.0.0.1", 55322)
        )
        self.assertEqual(
            (kwargs["dbname"], kwargs["user"], kwargs["sslmode"]),
            ("postgres", "postgres", "disable"),
        )
        self.assertEqual(kwargs["options"], "-c statement_timeout=45000")
        self.assertEqual(kwargs["password"], "0123456789abcdef" * 4)
        self.assertEqual(self.gate.call_count, 2)
        self.assertEqual(self.manifest_mock.call_count, 2)
        report = self.recorded_report()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["applied"], self.files)
        self.assertIn("not an all-or-nothing", report["limits"])
        state = json.loads((self.lab / "lab-state.json").read_text())
        self.assertEqual(state["migrations"]["count"], 1)
        self.assertEqual(state["migrations"]["files"], self.files)

    def test_nonempty_database_is_preserved_without_executing_source_or_creating_ledger(self):
        self.cursor.fetchone.side_effect = [("off",), ("profiles", "signalbridge_lab.migrations")]
        self.assertEqual(self.run_main(), 1)
        self.assertTrue(all(statement.startswith("select ") for statement in self.executed()))
        self.connection.commit.assert_not_called()
        self.assertEqual(self.recorded_report()["applied"], [])
        self.assertFalse((self.lab / "lab-state.json").exists())

    def test_enabled_cron_prevents_every_mutation(self):
        self.cursor.fetchone.side_effect = [("on",)]
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(len(self.executed()), 1)
        self.assertTrue(self.executed()[0].startswith("select "))
        self.connection.commit.assert_not_called()
        self.assertFalse((self.lab / "lab-state.json").exists())

    def test_hash_mismatch_stops_before_source_sql_and_never_marks_ready(self):
        (self.snapshot / "supabase/migrations/001_synthetic.sql").write_bytes(b"changed SQL")
        self.assertEqual(self.run_main(), 1)
        self.assertNotIn("changed SQL", self.executed())
        self.assertNotIn(self.sql.decode(), self.executed())
        self.assertEqual(self.recorded_report()["applied"], [])
        self.assertFalse((self.lab / "lab-state.json").exists())

    def test_failed_final_isolation_keeps_applied_ledger_but_does_not_claim_ready(self):
        self.gate.side_effect = [None, ValueError("Synthetic final isolation rejection")]
        self.assertEqual(self.run_main(), 1)
        report = self.recorded_report()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["applied"], self.files)
        self.assertFalse((self.lab / "lab-state.json").exists())

    def test_provider_enablement_prevents_ready_state(self):
        self.cursor.fetchone.side_effect = [("off",), (None, None), ("off",), (False, True, False)]
        self.assertEqual(self.run_main(), 1)
        self.assertEqual(self.recorded_report()["status"], "failed")
        self.assertFalse((self.lab / "lab-state.json").exists())

    def test_missing_private_password_never_connects_or_creates_a_run(self):
        migration.read_database_password.side_effect = ValueError("Credential unavailable")
        with self.assertRaises(ValueError):
            self.run_main()
        self.connect.assert_not_called()
        self.assertFalse(self.lab.exists())

    def test_driver_error_does_not_store_connection_parameters_or_password(self):
        private = "synthetic-private-driver-detail"
        self.connect.side_effect = RuntimeError(private)
        self.assertEqual(self.run_main(), 1)
        report = self.recorded_report()
        self.assertEqual(report["status"], "failed")
        self.assertNotIn(private, json.dumps(report))
        error_file = next((self.lab / "migration-runs").glob("*.error.txt"))
        self.assertNotIn(private, error_file.read_text())
