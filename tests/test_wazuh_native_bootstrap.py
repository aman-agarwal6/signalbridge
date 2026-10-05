"""Modeled native output and real scratch-file checks; never manager execution."""

import os
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.test import SimpleTestCase
from django.utils import timezone

from bridge.contract import canonical, timestamp
from integrations.wazuh_enterprise import native_collector as driver
from integrations.wazuh_enterprise.capture_journal import CaptureJournal, PinnedCapture
from integrations.wazuh_enterprise.contract import EnterpriseWazuhError, segmented_location
from integrations.wazuh_enterprise.native_reconciliation import reconcile
from tests.test_soc_delivery import disposable_root


class NativeBootstrapControls(SimpleTestCase):
    def setUp(self):
        self.now = timezone.now()
        self.expected = {}
        for app in ("documents", "expenses"):
            event = str(uuid.uuid4())
            packet = {
                "signalbridge": {
                    "export_version": 2,
                    "app": app,
                    "environment": "lab",
                    "event_id": event,
                    "occurred_at": (self.now - timedelta(minutes=1)).isoformat(),
                    "operation": "private_record.read",
                    "outcome": "denied",
                    "reason": "membership_required",
                    "source": "instrumented_lab",
                }
            }
            self.expected[(app, "observation", event)] = (
                packet,
                segmented_location(app, "observation", 0),
            )

    def native(self, index, *, kind="archive"):
        packet, location = list(self.expected.values())[index]
        value = {
            "timestamp": self.now.isoformat(),
            "agent": {"id": "000", "name": "modeled-manager"},
            "manager": {"name": "modeled-manager"},
            "id": f"1700000000.{index + 1}",
            "decoder": {"name": "json"},
            "location": location,
            "data": {key: {k: str(v) for k, v in row.items()} for key, row in packet.items()},
        }
        if kind == "archive":
            value["full_log"] = canonical(packet).decode()
        else:
            value["rule"] = {
                "id": "100211",
                "level": 3,
                "description": "Modeled output, no tool run",
            }
        return value

    def bytes(self, values):
        return b"".join(canonical(v) + b"\n" for v in values)

    def check(self, archives=None, alerts=None, **kwargs):
        return reconcile(
            self.bytes(archives if archives is not None else [self.native(i) for i in range(2)]),
            self.bytes(
                alerts if alerts is not None else [self.native(i, kind="alert") for i in range(2)]
            ),
            self.expected,
            now=self.now,
            **kwargs,
        )

    def test_all_expected_inputs_and_alerts_match_without_runtime_or_delivery_attestation(self):
        result = self.check(final=True)
        self.assertTrue(result["bootstrap_counts_match"])
        self.assertEqual(result["archived_logical_inputs"], 2)
        self.assertEqual(result["alerted_logical_inputs"], 2)
        self.assertFalse(result["genuine_source_execution_verified"])
        self.assertFalse(result["native_runtime_execution_verified"])
        self.assertFalse(result["continuous_delivery_verified"])
        self.assertFalse(result["forwarded_detections_are_independent_wazuh_rediscovery"])

    def test_physical_copies_tool_identity_repeats_and_logical_events_remain_separate(self):
        first = self.native(0)
        other_id = {**first, "id": "1700000000.9"}
        result = self.check([first, self.native(1), first, other_id])
        self.assertTrue(result["bootstrap_counts_match"])
        self.assertEqual(result["physical_archive_copies"], 4)
        self.assertEqual(result["distinct_archive_tool_ids"], 3)
        self.assertEqual(result["repeated_archive_tool_ids"], 1)
        self.assertEqual(result["archived_logical_inputs"], 2)
        self.assertEqual(result["extra_archive_copies"], 2)
        with self.assertRaisesMessage(EnterpriseWazuhError, "native_bootstrap_duplicate_bound"):
            self.check([first] * 4 + [self.native(1)])

    def test_partial_and_empty_native_files_remain_incomplete(self):
        raw = self.bytes([self.native(i) for i in range(2)])[:-1]
        alerts = self.bytes([self.native(i, kind="alert") for i in range(2)])
        result = reconcile(raw, alerts, self.expected, now=self.now)
        self.assertFalse(result["bootstrap_counts_match"])
        self.assertTrue(result["partial_native_files"]["archive"])
        self.assertEqual(result["missing_archive_inputs"], 1)
        with self.assertRaisesMessage(EnterpriseWazuhError, "native_bootstrap_incomplete_output"):
            reconcile(raw, alerts, self.expected, now=self.now, final=True)
        self.assertEqual(
            reconcile(b"", b"", self.expected, now=self.now)["missing_archive_inputs"], 2
        )

    def test_native_identity_location_full_log_and_time_conflicts_are_rejected(self):
        for update in (
            {"location": segmented_location("expenses", "observation", 0)},
            {"agent": {"id": "001"}},
            {"full_log": "{}"},
            {"timestamp": (self.now + timedelta(seconds=1)).isoformat()},
        ):
            wrong = {**self.native(0), **update}
            with self.subTest(update=update), self.assertRaises(EnterpriseWazuhError):
                self.check([wrong, self.native(1)])
        altered = {**self.native(0), "manager": {"name": "altered-manager"}}
        with self.assertRaisesMessage(EnterpriseWazuhError, "native_bootstrap_tool_id_conflict"):
            self.check([self.native(0), altered, self.native(1)])

    def test_wazuh_compact_utc_offset_timestamps_reconcile(self):
        # Wazuh writes "+0000"; the image's bundled Python 3.10 rejected it
        # before bridge.contract.timestamp normalized the offset.
        compact = (
            self.now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{self.now.microsecond // 1000:03d}+0000"
        )
        archives = [{**self.native(i), "timestamp": compact} for i in range(2)]
        alerts = [{**self.native(i, kind="alert"), "timestamp": compact} for i in range(2)]
        result = self.check(archives, alerts, final=True)
        self.assertTrue(result["bootstrap_counts_match"])
        self.assertEqual(timestamp(compact), timestamp(compact[:-5] + "+00:00"))
        self.assertEqual(timestamp("2026-10-03T07:01:01-0530").utcoffset(), timedelta(0))

    def test_distinct_events_sharing_a_native_id_are_accepted(self):
        # Native run f23cf0d7 archived 24 events under two ids: Wazuh builds
        # "id" from the epoch second and the alerts-file offset.
        shared = {**self.native(1), "id": "1700000000.1"}
        result = self.check([self.native(0), shared], final=True)
        self.assertTrue(result["bootstrap_counts_match"])
        self.assertEqual(result["distinct_archive_tool_ids"], 2)
        self.assertEqual(result["repeated_archive_tool_ids"], 0)

    def test_unexpected_custom_alert_and_noncustom_native_alert_cannot_disappear(self):
        wrong = self.native(0, kind="alert")
        wrong["rule"] = {"id": "100222", "level": 10}
        with self.assertRaises(EnterpriseWazuhError):
            self.check(alerts=[wrong, self.native(1, kind="alert")])
        wrong["rule"] = {"id": "5555", "level": 7}
        result = self.check(alerts=[wrong, self.native(1, kind="alert")])
        self.assertFalse(result["bootstrap_counts_match"])
        self.assertFalse(result["native_record_format_verified"])
        self.assertEqual(result["unexpected_noncustom_alerts"], 1)

    def test_native_file_and_record_capacity_fail_without_partial_success(self):
        with self.assertRaisesMessage(EnterpriseWazuhError, "native_bootstrap_output_limit"):
            reconcile(b"x" * (4 * 1024**2 + 1), b"", self.expected, now=self.now)
        with self.assertRaisesMessage(EnterpriseWazuhError, "native_bootstrap_record_size"):
            reconcile(b"x" * 16385 + b"\n", b"", self.expected, now=self.now)
        wrong = self.native(0)
        wrong["data"]["signalbridge"]["event_id"] = str(uuid.uuid4())
        with self.assertRaisesMessage(EnterpriseWazuhError, "native_bootstrap_unexpected_record"):
            self.check([wrong, self.native(1)])

    def test_closed_fresh_context_rejects_future_expired_bool_and_changed_scope(self):
        value = {
            "context_version": 1,
            "run_id": str(uuid.uuid4()),
            "prepared_at": self.now.isoformat(),
            "source_sha256": "a" * 64,
            "manifest_sha256": "b" * 64,
        }
        self.assertEqual(driver.validate_context(canonical(value), now=self.now), value)
        for key, changed in (
            ("context_version", True),
            ("run_id", "../../outside"),
            ("source_sha256", "unknown"),
            ("prepared_at", (self.now - timedelta(seconds=901)).isoformat()),
            ("prepared_at", (self.now + timedelta(seconds=1)).isoformat()),
        ):
            wrong = {**value, key: changed}
            with self.subTest(key=key), self.assertRaises(ValueError):
                driver.validate_context(canonical(wrong), now=self.now)
        value["native_execution_verified"] = True
        with self.assertRaisesMessage(EnterpriseWazuhError, "native_collector_context_fields"):
            driver.validate_context(canonical(value), now=self.now)

    def test_unapproved_host_context_rejects_before_any_process_start(self):
        with (
            patch.object(driver.sys, "platform", "win32"),
            patch.object(driver.subprocess, "Popen") as spawn,
        ):
            with self.assertRaisesMessage(EnterpriseWazuhError, "isolated_linux_root_required"):
                driver.NativeCollector().run()
            spawn.assert_not_called()

    def test_real_current_daily_hardlink_pair_is_bounded_and_extra_alias_is_rejected(self):
        root = disposable_root(self)
        folder = root / "wazuh/logs/archives"
        day = folder / "2026/Oct/ossec-archive-02.json"
        day.parent.mkdir(parents=True)
        current = folder / "archives.json"
        day.write_bytes(b"synthetic native-file fixture\n")
        os.link(day, current)
        with patch.object(driver, "WAZUH", root / "wazuh"):
            identity, raw = driver.current_native_file("archive")
            self.assertEqual(raw, b"synthetic native-file fixture\n")
            self.assertEqual(identity, (current.stat().st_dev, current.stat().st_ino))
            os.link(current, root / "unaccounted-link")
            with self.assertRaisesMessage(EnterpriseWazuhError, "native_collector_log_file"):
                driver.current_native_file("archive")

    def test_collector_drains_and_retains_both_real_file_generations(self):
        root = disposable_root(self)
        evidence = root / "evidence"
        evidence.mkdir()
        collector = driver.NativeCollector()
        collector.expected = self.expected
        collector.journal = CaptureJournal(evidence, str(uuid.uuid4()), create=True)
        self.addCleanup(collector.journal.close)
        collector.captures = {
            kind: PinnedCapture(collector.journal, kind) for kind in collector.last
        }
        for reader in collector.captures.values():
            self.addCleanup(reader.close)

        def files(generation, archives, alerts):
            folder = root / generation
            for name, prefix, raw in (
                ("archives", "archive", archives),
                ("alerts", "alerts", alerts),
            ):
                day = folder / "logs" / name / "2026/Oct" / f"ossec-{prefix}-02.json"
                day.parent.mkdir(parents=True)
                day.write_bytes(raw)
                os.link(day, folder / "logs" / name / f"{name}.json")
            return folder

        first = self.bytes([self.native(0)])
        late = self.bytes([self.native(1)])
        alerts = self.bytes([self.native(i, kind="alert") for i in range(2)])
        old = files("old", first, alerts)
        with patch.object(driver, "WAZUH", old):
            self.assertFalse(collector.poll_records()["bootstrap_counts_match"])
        with patch.object(driver, "current_native_file", side_effect=FileNotFoundError):
            self.assertFalse(collector.poll_records()["bootstrap_counts_match"])
        self.assertEqual(collector.last["archive"][1], first)
        with (old / "logs/archives/archives.json").open("ab") as output:
            output.write(late)
        new = files("new", first, b"")
        # Switching the supplied fixed root models Linux inode replacement while
        # real old/new file handles and the durable journal execute on Windows.
        # This does not claim a native Wazuh rotation or Linux unlink test.
        with patch.object(driver, "WAZUH", new):
            self.assertTrue(collector.poll_records()["bootstrap_counts_match"])
        collector.close_capture()
        self.assertEqual(collector.last["archive"][1], first + late + first)
        self.assertEqual(collector.last["alert"][1], alerts)
