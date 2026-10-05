"""Offline adapter checks; DB RPCs and the HTTP transport are modeled here."""

import json
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from bridge.contract import signature
from integrations.bettail_enterprise import collector, prepare


class Connection:
    autocommit = True

    def __init__(self, payload, finished=True):
        self.payload, self.finished = payload, finished
        self.calls = []

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def execute(self, sql, values):
        self.calls.append((sql, values))

    def fetchone(self):
        if len(self.calls) == 1:
            return [self.payload]
        if self.finished is True:
            identifier, _, state, error = self.calls[-1][1]
            return [{"event_id": identifier, "state": state, "error": error}]
        return [self.finished]


def event():
    return {
        "schema_version": 2,
        "event_id": str(uuid.uuid4()),
        "app": "bettail",
        "environment": "lab",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "actor": "a" * 64,
        "resource": "b" * 64,
        "episode": str(uuid.uuid4()),
        "operation": "membership.change",
        "outcome": "allowed",
        "reason": "membership_removed",
        "context": None,
        "membership": {"subject": "c" * 64, "state": "removed"},
    }


class CollectorTests(TestCase):
    def test_console_transport_is_fixed_and_bounds_the_acknowledgement(self):
        calls = []

        class Client:
            def __init__(self, port, **kwargs):
                calls.append(("configure", port, kwargs))

            def start(self):
                calls.append("start")

            def connect(self):
                calls.append("connect")

            def request(self, method, target, **kwargs):
                calls.append((method, target))

            def getresponse(self):
                return self

            status = 302

            def read(self, limit):
                self.assert_limit = limit
                calls.append(("read", limit))
                return b"{}"

            def remaining(self):
                calls.append("deadline")

            def finish(self):
                calls.append("finish")

        context = object()
        with patch.object(collector, "BoundedHTTPSConnection", Client):
            self.assertEqual(collector.ConsoleTransport(context)(b"{}", {}), (302, b"{}"))
        self.assertEqual(calls[0], ("configure", 18841, {"seconds": 5, "context": context}))
        self.assertIn(("POST", "/api/v1/events/bettail/"), calls)
        self.assertIn(("read", 1025), calls)
        self.assertEqual(calls[-2:], ["deadline", "finish"])

    def test_acceptance_is_bound_to_event_and_app_signature(self):
        value = event()
        connection = Connection(value)
        key = "synthetic-never-installed-key-" * 2

        def transport(body, headers):
            self.assertEqual(len(connection.calls), 1)  # No transaction spans network IO.
            self.assertEqual(json.loads(body), value)
            self.assertEqual(
                headers["X-SB-Signature"],
                signature(key, "bettail", collector.KEY_ID, headers["X-SB-Time"], body),
            )
            return 202, json.dumps({"status": "accepted", "event_id": value["event_id"]}).encode()

        result = collector.deliver_one(connection, key, transport)
        self.assertEqual(result["state"], "acknowledged")
        self.assertEqual(connection.calls[1][1][0], value["event_id"])
        self.assertEqual(connection.calls[1][1][1], connection.calls[0][1][0])

    def test_lost_reply_retains_logical_event_for_retry(self):
        value = event()
        connection = Connection(value)

        def offline(*args):
            raise TimeoutError("synthetic interruption")

        result = collector.deliver_one(connection, "x" * 32, offline)
        self.assertEqual(
            result, {"event_id": value["event_id"], "state": "pending", "error": "transport_failed"}
        )

    def test_conflicts_wrong_receipts_and_redirects_are_not_delivery(self):
        identifier = str(uuid.uuid4())
        self.assertEqual(collector.receipt(identifier, 409, b"{}"), ("dead", "event_conflict"))
        self.assertEqual(collector.receipt(identifier, 302, b"{}"), ("dead", "redirect_rejected"))
        self.assertEqual(
            collector.receipt(identifier, 202, b"{}"), ("pending", "invalid_acknowledgement")
        )
        good = json.dumps({"status": "duplicate", "event_id": identifier}).encode()
        self.assertEqual(collector.receipt(identifier, 200, good), ("acknowledged", ""))
        self.assertEqual(
            collector.receipt(identifier, 202, good), ("pending", "invalid_acknowledgement")
        )
        self.assertEqual(
            collector.receipt(identifier, 200, b" " * 1025), ("pending", "invalid_acknowledgement")
        )

    def test_duplicate_keys_cannot_be_an_acknowledgement(self):
        identifier = str(uuid.uuid4())
        for raw in (
            '{"event_id":"wrong","event_id":"' + identifier + '","status":"accepted"}',
            '{"event_id":"' + identifier + '","status":"wrong","status":"accepted"}',
            '{"event_id":"' + identifier + '","status":"accepted","extra":NaN}',
        ):
            self.assertEqual(
                collector.receipt(identifier, 202, raw.encode()),
                ("pending", "invalid_acknowledgement"),
            )

    def test_cross_app_record_never_reaches_transport(self):
        value = event()
        value["app"] = "netted"

        def transport(*_):
            self.fail("cross-app send")

        result = collector.deliver_one(Connection(value), "x" * 32, transport)
        self.assertEqual(result["state"], "dead")
        self.assertEqual(result["error"], "invalid_outbox_record")

    def test_expired_claim_cannot_be_reported_as_acknowledged(self):
        value = event()
        result = collector.deliver_one(
            Connection(value, finished=None),
            "x" * 32,
            lambda *_: (
                202,
                json.dumps({"status": "accepted", "event_id": value["event_id"]}).encode(),
            ),
        )
        self.assertEqual(result["state"], "lease_lost")

    def test_exhausted_retry_reports_the_retained_terminal_state(self):
        value = event()
        terminal = {"event_id": value["event_id"], "state": "dead", "error": "retry_exhausted"}
        result = collector.deliver_one(
            Connection(value, finished=terminal), "x" * 32, lambda *_: (503, b"{}")
        )
        self.assertEqual(result, terminal)

    def test_completion_receipt_cannot_change_event_or_invent_acceptance(self):
        value = event()
        for invalid in (
            False,
            {"event_id": str(uuid.uuid4()), "state": "pending", "error": "collector_unavailable"},
            {"event_id": value["event_id"], "state": "acknowledged", "error": ""},
        ):
            connection = Connection(value, finished=invalid)
            with self.assertRaises(ValueError):
                collector.deliver_one(connection, "x" * 32, lambda *_: (503, b"{}"))

    def test_requires_autocommit_before_claim(self):
        connection = Connection(event())
        connection.autocommit = False
        with self.assertRaises(ValueError):
            collector.deliver_one(connection, "x" * 32, lambda *_: self.fail("network"))
        self.assertFalse(connection.calls)


class CopyTests(TestCase):
    def test_prior_copy_is_preserved_without_overwrite(self):
        with tempfile.TemporaryDirectory(dir=prepare.ROOT) as directory:
            root = Path(directory)
            destination = root / "var/enterprise/bettail-access"
            destination.mkdir(parents=True)
            retained = destination / "operator-note.txt"
            retained.write_bytes(b"synthetic retained work")
            metadata = {"files": {}, "source_revision": "0" * 40, "source_dirty": False}
            with (
                patch.object(prepare, "ROOT", root),
                patch.object(prepare, "payload", return_value=({}, metadata)),
                self.assertRaises(FileExistsError),
            ):
                prepare.prepare()
            self.assertEqual(retained.read_bytes(), b"synthetic retained work")
            self.assertFalse((destination / "source").exists())

    def test_private_paths_and_obvious_credentials_are_rejected(self):
        for relative, raw in (
            ("src/credentials/config.ts", b"ordinary source"),
            ("src/config.ts", b"-----BEGIN PRIVATE KEY-----"),
            ("src/config.ts", b"postgresql://synthetic:nonfunctional@lab.invalid/db"),
            ("src/config.ts", b"AKIA" + b"0" * 16),
        ):
            with self.assertRaises(ValueError):
                prepare.public_source(relative, raw)
        prepare.public_source("src/config.ts", b"process.env.SUPABASE_SERVICE_ROLE_KEY")

    def test_non_utf8_source_is_rejected(self):
        with self.assertRaises(UnicodeError):
            prepare.public_source("src/config.ts", b"\xff\xfe")

    def test_patch_rejects_changed_anchor(self):
        with self.assertRaises(ValueError):
            prepare.replace_once("changed source", "expected", "replacement")
        with self.assertRaises(ValueError):
            prepare.replace_once("same same", "same", "replacement")

    def test_file_bound_checked_before_reading(self):
        with tempfile.TemporaryDirectory(dir=prepare.ROOT) as directory:
            path = Path(directory) / "source.ts"
            path.write_bytes(b"ordinary source")
            with patch.object(prepare, "MAX_BYTES", 5), self.assertRaises(ValueError):
                prepare.read(path)

    def test_hardlinked_source_is_rejected(self):
        import os

        with tempfile.TemporaryDirectory(dir=prepare.ROOT) as directory:
            path = Path(directory) / "source.ts"
            path.write_bytes(b"ordinary source")
            os.link(path, Path(directory) / "alias.ts")
            with self.assertRaises(ValueError):
                prepare.read(path)

    def test_sql_guards_are_prepared_not_native_acceptance(self):
        sql = (prepare.ADAPTER / "202610020001_signalbridge_access.sql").read_text(encoding="utf-8")
        # Negative guard against accidentally publishing an impersonation RPC.
        self.assertIn(
            "revoke all on all functions in schema sb_bettail from public,anon,authenticated", sql
        )
        self.assertIn("for update skip locked", sql)
        self.assertIn("original_mutate", sql)
        self.assertNotIn("grant execute on all functions", sql)
        self.assertIn("original.pronargdefaults<>0", sql)
        self.assertIn("'bt_mutate.','original_mutate.'", sql)
        self.assertIn("if auth.uid() is distinct from subject then", sql)
        self.assertEqual(sql.count("if auth.uid() is distinct from previous_actor then"), 2)
        self.assertIn("limit 100\n ) update sb_bettail.outbox", sql)
        self.assertIn(
            "set state='dead',error_code='retry_exhausted',lease=null,lease_until=null", sql
        )
        self.assertIn(
            "revoke all on function sb_bettail.effective(sb_bettail.watched,uuid) from sb_bettail_delivery",
            sql,
        )
