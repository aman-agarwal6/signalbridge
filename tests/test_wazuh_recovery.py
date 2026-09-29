"""Offline archive/parser regressions; no Wazuh or Docker execution."""

import copy
import json
import unittest
from unittest.mock import Mock, patch

from integrations.wazuh_recovery import run_delivery as recovery


class ArchiveReconciliationTests(unittest.TestCase):
    def setUp(self):
        fixture = recovery.base.prep.HERE / "fixtures/events.jsonl"
        self.packet = json.loads(fixture.read_text().splitlines()[12])
        self.identity = self.packet["signalbridge"]["event_id"]
        self.expected = {self.identity: self.packet}
        self.row = {
            "location": str(recovery.base.INPUT),
            "decoder": {"name": "json"},
            "full_log": json.dumps(self.packet),
            "data": {
                "signalbridge": {
                    key: str(value) for key, value in self.packet["signalbridge"].items()
                }
            },
        }

    def encoded(self, row=None):
        return (json.dumps(self.row if row is None else row) + "\n").encode()

    def test_nonalert_records_are_proved_by_archive_content_not_alert_count(self):
        self.assertEqual(recovery.reconcile(self.encoded(), self.expected), {self.identity: 1})
        self.assertEqual(recovery.reconcile(b"", self.expected), {})

    def test_duplicate_copies_are_counted_and_bounded(self):
        self.assertEqual(recovery.reconcile(self.encoded() * 3, self.expected), {self.identity: 3})
        with self.assertRaisesRegex(recovery.base.PilotFailure, "archive_duplicate_bound"):
            recovery.reconcile(self.encoded() * 4, self.expected)

    def test_incomplete_final_line_is_not_promoted_to_an_observation(self):
        self.assertEqual(recovery.reconcile(self.encoded()[:-1], self.expected), {})
        self.assertEqual(
            recovery.reconcile(self.encoded() + self.encoded()[:40], self.expected),
            {self.identity: 1},
        )

    def test_foreign_location_and_decoder_are_rejected(self):
        for field, value in (("location", "/etc/passwd"), ("decoder", {"name": "foreign"})):
            row = copy.deepcopy(self.row)
            row[field] = value
            with self.subTest(field=field), self.assertRaises(recovery.base.PilotFailure):
                recovery.reconcile(self.encoded(row), self.expected)

    def test_decoded_content_must_match_the_input(self):
        row = copy.deepcopy(self.row)
        row["data"]["signalbridge"]["reason"] = "policy_regression"
        with self.assertRaisesRegex(recovery.base.PilotFailure, "archive_decoded_mismatch"):
            recovery.reconcile(self.encoded(row), self.expected)

    def test_extra_decoded_fields_and_unknown_events_are_rejected(self):
        row = copy.deepcopy(self.row)
        row["data"]["signalbridge"]["extra"] = "synthetic-marker"
        with self.assertRaises(recovery.base.PilotFailure):
            recovery.reconcile(self.encoded(row), self.expected)
        with self.assertRaisesRegex(recovery.base.PilotFailure, "archive_input_mismatch"):
            recovery.reconcile(self.encoded(), {})

    def test_raw_record_must_have_exact_expected_shape(self):
        for value in ("{}", json.dumps({**self.packet, "extra": "synthetic"})):
            row = copy.deepcopy(self.row)
            row["full_log"] = value
            with self.subTest(value=value), self.assertRaises(recovery.base.PilotFailure):
                recovery.reconcile(self.encoded(row), self.expected)

    def test_malformed_and_oversized_archives_are_rejected(self):
        for raw in (b'{"a":1,"a":2}\n', b"{invalid}\n", b"x" * (recovery.base.FILE_LIMIT + 1)):
            with (
                self.subTest(length=len(raw)),
                self.assertRaises((recovery.base.PilotFailure, ValueError)),
            ):
                recovery.reconcile(raw, self.expected)

    def test_collector_stop_requires_signal_exit_and_exact_persisted_checkpoint(self):
        pilot = recovery.RecoveryPilot()
        pilot.launches["wazuh-logcollector"] = 1
        process, log = Mock(), Mock()
        process.returncode = 1
        pilot.children = [(process, log, True)]
        payload = b"synthetic record\n"
        checkpoint = {
            "files": [
                {
                    "path": str(recovery.base.INPUT),
                    "offset": str(len(payload)),
                    "hash": recovery.hashlib.sha1(payload, usedforsecurity=False).hexdigest(),
                }
            ]
        }
        saved = json.dumps(checkpoint).encode()
        signal_log = b"SIGNAL [(15)-(Terminated)] Received. Exit Cleaning..."
        with (
            patch.object(pilot, "signal_process"),
            patch.object(recovery.base, "regular_file", side_effect=[signal_log, saved, payload]),
        ):
            pilot.stop_collector(process)
        self.assertEqual(pilot.report["collector_stops"][0]["offset"], len(payload))
        self.assertIs(pilot.children[0][2], False)
        for code, message in ((0, signal_log), (1, b"unrelated"), (-15, signal_log)):
            process.returncode = code
            with (
                patch.object(pilot, "signal_process"),
                patch.object(recovery.base, "regular_file", return_value=message),
                self.assertRaisesRegex(recovery.base.PilotFailure, "collector_stop_failed"),
            ):
                pilot.stop_collector(process)
        process.returncode = 1
        checkpoint["files"][0]["offset"] = "0"
        with (
            patch.object(pilot, "signal_process"),
            patch.object(
                recovery.base,
                "regular_file",
                side_effect=[signal_log, json.dumps(checkpoint).encode(), payload],
            ),
            self.assertRaisesRegex(recovery.base.PilotFailure, "checkpoint_content"),
        ):
            pilot.stop_collector(process)
