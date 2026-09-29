"""Disposable ledger inspection checks; never opens the application's database."""

import json
import shutil
import sqlite3
import unittest
import uuid
from contextlib import closing

from integrations.wazuh_backfill import inspect_ledger as target
from scripts.local_backup import safe


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.fixture_parent = target.ROOT / "artifacts/local"
        self.root = self.fixture_parent / ("backfill-ledger-test-" + uuid.uuid4().hex)
        self.root.mkdir()
        self.addCleanup(self.cleanup_fixture)
        (self.root / "var/soc-delivery").mkdir(parents=True)
        self.stream = uuid.uuid4()
        self.batch = uuid.uuid4()
        self.event = uuid.uuid4()
        self.path = self.root / "var/soc-delivery" / (str(self.stream) + ".jsonl")
        self.db = self.root / "var/signalbridge.sqlite3"
        fixture = target.ROOT / "integrations/wazuh/fixtures/events.jsonl"
        self.packet = json.loads(fixture.read_text().splitlines()[2])
        self.packet["signalbridge"].update(
            app="bettail", environment="lab", event_id=str(self.event)
        )
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.executescript(
                "CREATE TABLE bridge_integration(id,slug,enabled); CREATE TABLE bridge_socstream(id,offset,prefix_sha256,revision,integration_id); CREATE TABLE bridge_socbatch(id,body,body_sha256,start_offset,record_count,state,stream_id); CREATE TABLE bridge_event(id,event_id,integration_id); CREATE TABLE bridge_socdelivery(event_id,batch_id);"
            )
            connection.execute("INSERT INTO bridge_integration VALUES(1,?,1)", ("bettail",))
            connection.execute("INSERT INTO bridge_event VALUES(1,?,1)", (self.event.hex,))
            connection.execute("INSERT INTO bridge_socdelivery VALUES(1,?)", (self.batch.hex,))
        self.write_packet()

    def write_packet(self):
        raw = (json.dumps(self.packet, separators=(",", ":")) + "\n").encode("ascii")
        self.path.write_bytes(raw)
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute("DELETE FROM bridge_socstream")
            connection.execute("DELETE FROM bridge_socbatch")
            connection.execute(
                "INSERT INTO bridge_socstream VALUES(?,?,?,?,1)",
                (self.stream.hex, len(raw), target.sha(raw), 1),
            )
            connection.execute(
                "INSERT INTO bridge_socbatch VALUES(?,?,?,?,?,?,?)",
                (
                    self.batch.hex,
                    raw.decode(),
                    target.sha(raw),
                    0,
                    1,
                    "file_appended",
                    self.stream.hex,
                ),
            )

    def mutate(self, sql, values=()):
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.execute(sql, values)

    def cleanup_fixture(self):
        safe(self.fixture_parent, self.root, directory=True)
        for path in self.root.rglob("*"):
            safe(self.root, path, directory=path.is_dir())
        shutil.rmtree(self.root)

    def test_exact_committed_metadata_passes_without_database_write(self):
        before = target.sha(self.db.read_bytes())
        path, report = target.inspect(self.root)
        self.assertEqual(path, self.path)
        self.assertEqual(report["expected_alerts"], {str(self.event): ["100202", 5]})
        self.assertEqual(before, target.sha(self.db.read_bytes()))

    def test_unclassified_record_is_retained_without_promoting_source_trust(self):
        self.packet["signalbridge"]["source"] = "legacy_unclassified"
        self.write_packet()
        _, report = target.inspect(self.root)
        self.assertEqual(len(report["packets"]), 1)
        self.assertEqual(report["expected_alerts"], {})

    def test_other_app_environment_and_extra_fields_are_rejected(self):
        for field, value in [
            ("app", "netted"),
            ("environment", "test"),
            ("source", "arbitrary"),
            ("unexpected", "value"),
        ]:
            old = self.packet["signalbridge"].copy()
            self.packet["signalbridge"][field] = value
            self.write_packet()
            with self.subTest(field=field), self.assertRaises((ValueError, ValueError)):
                target.inspect(self.root)
            self.packet["signalbridge"] = old

    def test_file_tampering_and_incomplete_tail_are_rejected(self):
        raw = self.path.read_bytes()
        for changed in (raw[:-1], raw + b"x", raw.replace(b"allowed", b"denied!")):
            self.path.write_bytes(changed)
            with self.subTest(length=len(changed)), self.assertRaises(ValueError):
                target.inspect(self.root)

    def test_uncommitted_batch_and_wrong_offset_or_digest_are_rejected(self):
        for column, value in [
            ("state", "staged"),
            ("start_offset", 1),
            ("body_sha256", "0" * 64),
            ("record_count", 2),
        ]:
            self.write_packet()
            self.mutate("UPDATE bridge_socbatch SET " + column + "=?", (value,))
            with self.subTest(column=column), self.assertRaises(ValueError):
                target.inspect(self.root)

    def test_cross_app_and_wrong_event_ledger_links_are_rejected(self):
        for sql, args in [
            ("UPDATE bridge_event SET integration_id=2", ()),
            ("UPDATE bridge_event SET event_id=?", (uuid.uuid4().hex,)),
        ]:
            self.mutate(sql, args)
            with self.subTest(sql=sql), self.assertRaises(ValueError):
                target.inspect(self.root)
            self.mutate("UPDATE bridge_event SET integration_id=1,event_id=?", (self.event.hex,))

    def test_disabled_application_is_rejected(self):
        self.mutate("UPDATE bridge_integration SET enabled=0")
        with self.assertRaises(ValueError):
            target.inspect(self.root)


if __name__ == "__main__":
    unittest.main()
