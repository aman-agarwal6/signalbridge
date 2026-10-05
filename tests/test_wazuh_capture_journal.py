"""Real disposable files/SQLite; synthetic bytes, no Wazuh process execution."""

import hashlib
import os
import sqlite3
import uuid
from unittest.mock import patch

from django.test import SimpleTestCase

from integrations.wazuh_enterprise import capture_journal as capture
from integrations.wazuh_enterprise.contract import EnterpriseWazuhError
from tests.test_soc_delivery import disposable_root


class CaptureJournalTests(SimpleTestCase):
    def setUp(self):
        self.root = disposable_root(self)
        self.run = str(uuid.uuid4())
        self.journal = capture.CaptureJournal(self.root, self.run, create=True)
        self.addCleanup(self.journal.close)
        self.reader = capture.PinnedCapture(self.journal, "archive")
        self.addCleanup(self.reader.close)

    def source(self, name, raw):
        path = self.root / name
        path.write_bytes(raw)
        return path

    def attach(self, path):
        self.reader.attach(path, capture.identity(path.stat()))

    def raw(self):
        return self.journal.captured("archive", limit=capture.MAX_BYTES)

    def test_appends_are_durable_and_resuming_same_file_does_not_duplicate(self):
        path = self.source("first.json", b'{"synthetic":1}\n')
        self.attach(path)
        self.reader.drain()
        self.reader.close()
        self.journal.close()
        second = capture.CaptureJournal(self.root, self.run)
        self.addCleanup(second.close)
        reader = capture.PinnedCapture(second, "archive")
        self.addCleanup(reader.close)
        reader.attach(path, capture.identity(path.stat()))
        reader.drain()
        with path.open("ab") as handle:
            handle.write(b'{"synthetic":2}\n')
        reader.drain()
        self.assertEqual(second.captured("archive", limit=1024), path.read_bytes())
        self.assertEqual(second.db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0], 2)
        second.verify()

    def test_switch_drains_unread_old_generation_before_new_generation(self):
        first = self.source("old.json", b'{"synthetic":1}\n')
        self.attach(first)
        self.reader.drain()
        with first.open("ab") as handle:
            handle.write(b'{"synthetic":2}\n')
        second = self.source("new.json", b'{"synthetic":3}\n')
        self.attach(second)
        self.reader.drain(seal=True)
        self.assertEqual(self.raw(), first.read_bytes() + second.read_bytes())
        self.assertEqual(
            self.journal.db.execute("SELECT sealed FROM sources ORDER BY sequence").fetchall(),
            [(1,), (1,)],
        )

    def test_half_line_persists_but_rotation_cannot_silently_join_unrelated_records(self):
        first = self.source("old.json", b'{"synthetic":')
        self.attach(first)
        self.reader.drain()
        self.assertEqual(self.raw(), first.read_bytes())
        second = self.source("new.json", b"1}\n")
        with self.assertRaisesMessage(EnterpriseWazuhError, "capture_rotated_partial_line"):
            self.attach(second)
        self.assertEqual(self.journal.db.execute("SELECT COUNT(*) FROM sources").fetchone()[0], 1)
        with first.open("ab") as handle:
            handle.write(b"1}\n")
        self.attach(second)
        self.reader.drain()
        self.assertEqual(self.raw(), first.read_bytes() + second.read_bytes())

    def test_missing_previous_generation_after_restart_fails_instead_of_skipping(self):
        first = self.source("old.json", b"one\n")
        self.attach(first)
        self.reader.drain()
        self.reader.close()
        second = self.source("new.json", b"two\n")
        with self.assertRaisesMessage(EnterpriseWazuhError, "capture_previous_generation_missing"):
            self.attach(second)
        self.assertEqual(self.raw(), b"one\n")
        self.attach(first)
        self.attach(second)
        self.reader.drain()
        self.assertEqual(self.raw(), b"one\ntwo\n")

    def test_failure_between_bytes_and_offset_rolls_back_both_and_retry_recovers(self):
        row = self.journal.begin("archive", "1:1")
        with patch.object(self.journal, "_advance", side_effect=OSError("synthetic interruption")):
            with self.assertRaises(OSError):
                self.journal.append(row[0], 0, b"one\n", prefix_digest=capture.EMPTY)
        self.assertEqual(self.journal.active("archive")[2], 0)
        self.assertEqual(self.raw(), b"")
        self.assertTrue(self.journal.append(row[0], 0, b"one\n", prefix_digest=capture.EMPTY))
        self.assertFalse(self.journal.append(row[0], 0, b"one\n", prefix_digest=capture.EMPTY))
        self.assertEqual(self.raw(), b"one\n")
        self.journal.verify()

    def test_stale_or_conflicting_append_cannot_rewrite_committed_evidence(self):
        row = self.journal.begin("archive", "1:1")
        self.journal.append(row[0], 0, b"one\n", prefix_digest=capture.EMPTY)
        for offset, raw, digest in (
            (0, b"bad\n", capture.EMPTY),
            (7, b"two\n", capture.EMPTY),
            (4, b"two\n", capture.EMPTY),
        ):
            with self.subTest(offset=offset), self.assertRaises(EnterpriseWazuhError):
                self.journal.append(row[0], offset, raw, prefix_digest=digest)
        self.assertEqual(self.raw(), b"one\n")

    def test_prefix_change_is_detected_at_restart_or_seal(self):
        path = self.source("first.json", b"one\n")
        self.attach(path)
        self.reader.drain()
        path.write_bytes(b"two\n")
        with self.assertRaisesMessage(EnterpriseWazuhError, "capture_native_changed_at_rotation"):
            self.reader.drain(seal=True)
        self.reader.close()
        with self.assertRaisesMessage(EnterpriseWazuhError, "capture_native_prefix_changed"):
            self.attach(path)
        self.assertEqual(self.raw(), b"one\n")

    def test_truncation_and_native_identity_conflict_preserve_checkpoint(self):
        path = self.source("first.json", b"one\n")
        self.attach(path)
        self.reader.drain()
        path.write_bytes(b"x")
        with self.assertRaisesMessage(
            EnterpriseWazuhError, "capture_native_truncated_or_oversized"
        ):
            self.reader.drain()
        with self.assertRaisesMessage(EnterpriseWazuhError, "capture_native_identity"):
            self.reader.attach(path, "wrong")
        self.assertEqual(self.raw(), b"one\n")

    def test_capacity_failure_rolls_back_and_never_deletes_prior_evidence(self):
        row = self.journal.begin("archive", "1:1")
        self.journal.append(row[0], 0, b"one\n", prefix_digest=capture.EMPTY)
        with (
            patch.object(capture, "MAX_BYTES", 7),
            self.assertRaisesMessage(EnterpriseWazuhError, "capture_capacity"),
        ):
            self.journal.append(
                row[0], 4, b"two\n", prefix_digest=hashlib.sha256(b"one\n").hexdigest()
            )
        self.assertEqual(self.raw(), b"one\n")
        with self.assertRaisesMessage(EnterpriseWazuhError, "capture_read_limit"):
            self.journal.captured("archive", limit=3)

    def test_corrupt_durable_chunk_and_wrong_run_are_rejected_on_open(self):
        row = self.journal.begin("archive", "1:1")
        self.journal.append(row[0], 0, b"one\n", prefix_digest=capture.EMPTY)
        with self.assertRaisesMessage(EnterpriseWazuhError, "capture_run"):
            capture.CaptureJournal(self.root, str(uuid.uuid4()))
        with self.journal.db:
            self.journal.db.execute("UPDATE chunks SET body=?", (b"bad\n",))
        with self.assertRaisesMessage(EnterpriseWazuhError, "capture_checkpoint_digest"):
            capture.CaptureJournal(self.root, self.run)

    def test_archive_and_alert_offsets_are_separate_and_generations_are_bounded(self):
        archive = self.journal.begin("archive", "1:1")
        alert = self.journal.begin("alert", "1:1")
        self.journal.append(archive[0], 0, b"a\n", prefix_digest=capture.EMPTY)
        self.journal.append(alert[0], 0, b"b\n", prefix_digest=capture.EMPTY)
        self.assertEqual(self.raw(), b"a\n")
        self.assertEqual(self.journal.captured("alert", limit=100), b"b\n")
        self.journal.seal(archive[0], 2, hashlib.sha256(b"a\n").hexdigest())
        with (
            patch.object(capture, "MAX_GENERATIONS", 2),
            self.assertRaisesMessage(EnterpriseWazuhError, "capture_generation_limit"),
        ):
            self.journal.begin("archive", "1:2")
        self.journal.verify()

    def test_existing_capture_database_is_never_overwritten_and_hardlink_is_rejected(self):
        with self.assertRaises(FileExistsError):
            capture.CaptureJournal(self.root, self.run, create=True)
        alias = self.root / "unexpected.sqlite3"
        os.link(self.journal.path, alias)
        with self.assertRaisesMessage(EnterpriseWazuhError, "capture_database_file"):
            capture.CaptureJournal(self.root, self.run)

    def test_chunk_size_and_sealed_sources_are_enforced(self):
        row = self.journal.begin("archive", "1:1")
        with self.assertRaisesMessage(EnterpriseWazuhError, "capture_append"):
            self.journal.append(
                row[0], 0, b"x" * (capture.CHUNK_BYTES + 1), prefix_digest=capture.EMPTY
            )
        self.journal.seal(row[0], 0, capture.EMPTY)
        with self.assertRaisesMessage(EnterpriseWazuhError, "capture_source_not_active"):
            self.journal.append(row[0], 0, b"one\n", prefix_digest=capture.EMPTY)
        with self.assertRaisesMessage(EnterpriseWazuhError, "capture_sealed_source_reopened"):
            self.journal.begin("archive", "1:1")

    def test_older_inode_reuse_creates_a_new_generation_without_overwriting_history(self):
        for inode, raw in (("1:1", b"one\n"), ("1:2", b"two\n"), ("1:1", b"three\n")):
            row = self.journal.begin("archive", inode)
            self.journal.append(row[0], 0, raw, prefix_digest=capture.EMPTY)
            self.journal.seal(row[0], len(raw), hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.raw(), b"one\ntwo\nthree\n")
        self.assertEqual(self.journal.db.execute("SELECT COUNT(*) FROM sources").fetchone()[0], 3)
        self.journal.verify()

    def test_sqlite_errors_remain_failures_without_false_checkpoint_advance(self):
        row = self.journal.begin("archive", "1:1")
        with patch.object(
            self.journal, "_advance", side_effect=sqlite3.OperationalError("synthetic full disk")
        ):
            with self.assertRaises(sqlite3.OperationalError):
                self.journal.append(row[0], 0, b"one\n", prefix_digest=capture.EMPTY)
        self.assertEqual(self.raw(), b"")
        self.assertEqual(self.journal.active("archive")[2], 0)

    def test_readonly_review_does_not_change_evidence_and_cannot_append(self):
        row = self.journal.begin("archive", "1:1")
        self.journal.append(row[0], 0, b"one\n", prefix_digest=capture.EMPTY)
        before = self.journal.path.read_bytes()
        reviewer = capture.CaptureJournal(self.root, self.run, readonly=True)
        self.addCleanup(reviewer.close)
        self.assertEqual(reviewer.captured("archive", limit=100), b"one\n")
        with self.assertRaises(sqlite3.OperationalError):
            reviewer.append(row[0], 4, b"two\n", prefix_digest=hashlib.sha256(b"one\n").hexdigest())
        reviewer.close()
        self.assertEqual(self.journal.path.read_bytes(), before)
