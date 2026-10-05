"""Ledger assembly over synthetic retained evidence; no Docker, network or database."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest import TestCase

from integrations.enterprise.reliability import DAY_MS, FINAL_DRAIN_MS, INTERRUPTIONS, LedgerError
from integrations.enterprise.reliability_ledger import assemble, attempts, tool_rows, wazuh_plan

ORIGIN = datetime(2026, 10, 4, tzinfo=timezone.utc)


def jsonl(rows):
    return b"".join(json.dumps(row).encode() + b"\n" for row in rows)


def source(slot=0, app="documents"):
    return {
        "kind": "source",
        "slot": slot,
        "app": app,
        "event_id": str(uuid.uuid4()),
        "digest": "a" * 64,
        "at_ms": 1000 * slot,
    }


class LedgerTests(TestCase):
    def test_unmatched_attempt_start_is_retained_as_unknown(self):
        event = source()
        key = {"app": "documents", "event_id": event["event_id"], "digest": "a" * 64}
        raw = jsonl(
            [
                {"phase": "start", "start_ms": 10, **key},
                {"phase": "end", "start_ms": 10, "end_ms": 40, "result": "accepted", **key},
                {"phase": "start", "start_ms": 90, **key},
            ]
        )
        rows = attempts([raw])
        self.assertEqual([r["result"] for r in rows], ["accepted", "unknown"])
        self.assertEqual(rows[1]["end_ms"], None)
        orphan = jsonl([{"phase": "end", "start_ms": 5, "end_ms": 6, "result": "retry", **key}])
        with self.assertRaises(LedgerError):
            attempts([orphan])

    def test_tool_rows_bind_by_source_identity_and_reuse_source_digest(self):
        event = source()
        sources = {("documents", event["event_id"]): event}
        archive = [
            {
                "id": "1790000000.12",
                "timestamp": (ORIGIN + timedelta(seconds=3)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                "data": {"signalbridge": {"app": "documents", "event_id": event["event_id"]}},
            },
            {"id": "1790000000.13", "timestamp": "2026-10-04T00:00:04.000+0000", "data": {}},
            {
                "id": "1790000000.14",
                "timestamp": "2026-10-04T00:00:05.000+0000",
                "data": {"signalbridge": {"app": "expenses", "event_id": event["event_id"]}},
            },
        ]
        rows = tool_rows(archive, sources, ORIGIN)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["digest"], "a" * 64)
        self.assertEqual(rows[0]["at_ms"], 3000)

    def test_observations_after_the_declared_window_are_excluded_and_counted(self):
        early, late = source(1), source(2)
        late["at_ms"] = DAY_MS + FINAL_DRAIN_MS + 1
        rows, counts = assemble(
            source_raw=jsonl([early, late]),
            attempt_files=[],
            stored_raw=b"",
            archive_raw=b"",
            origin=ORIGIN,
            requests_raw=jsonl(
                [{"kind": "read_started", "slot": s, "at_ms": s * 1000} for s in (1, 2)]
            ),
        )
        self.assertEqual([r["event_id"] for r in rows], [early["event_id"]])
        self.assertEqual(counts, {"source": 1, "after_window_source": 1})

    def test_wazuh_windows_follow_the_declared_profile_and_scale_only_for_rehearsal(self):
        full = wazuh_plan("a" * 32)
        declared = {name: (start, end) for name, start, end, _ in INTERRUPTIONS}
        for window in full["windows"]:
            start, end = declared[window["component"]]
            self.assertEqual(window["at_ms"], start if window["action"] == "stop" else end)
        short = wazuh_plan("a" * 32, 0.01)
        self.assertTrue(all(w["at_ms"] < DAY_MS * 0.01 for w in short["windows"]))
        for scale in (0.0, 1.5, 1):
            with self.subTest(scale=scale), self.assertRaises(LedgerError):
                wazuh_plan("a" * 32, scale)


class RequestStartTests(TestCase):
    def test_each_source_read_needs_exactly_one_recorded_send(self):
        event = source(3)
        common = dict(stored_raw=b"", archive_raw=b"", origin=ORIGIN, attempt_files=[])
        rows, _ = assemble(
            source_raw=jsonl([event]),
            requests_raw=jsonl([{"kind": "read_started", "slot": 3, "at_ms": 2999}]),
            **common,
        )
        self.assertEqual(rows[0]["sent_ms"], 2999)
        with self.assertRaises(LedgerError):
            assemble(source_raw=jsonl([event]), requests_raw=b"", **common)
        twice = [{"kind": "read_started", "slot": 3, "at_ms": 1}] * 2
        with self.assertRaises(LedgerError):
            assemble(source_raw=jsonl([event]), requests_raw=jsonl(twice), **common)
