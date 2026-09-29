"""Mocked/parser regressions. No subprocess, container, listener or Wazuh execution."""

import copy
import json
import os
import shutil
import signal
import unittest
import uuid
from pathlib import Path
from unittest.mock import Mock, patch

from integrations.wazuh import run_pilot as pilot
from integrations.wazuh import verify_static as prep


def cli_output(rule="100201", level=12):
    text = "Starting wazuh-logtest v4.14.8\n**Phase 1: Completed pre-decoding.\n"
    text += "**Phase 2: Completed decoding.\n        name: 'json'\n"
    if rule is not None:
        text += f"**Phase 3: Completed filtering (rules).\n        id: '{rule}'\n        level: '{level}'\n"
    return text.encode()


class PilotParserTests(unittest.TestCase):
    def setUp(self):
        self.event = prep.parse_json(
            prep.read_bounded(prep.HERE / "fixtures/events.jsonl").decode().splitlines()[0]
        )["signalbridge"]
        self.event_id = self.event["event_id"]
        self.alert = {"rule": {"id": "100201", "level": 12}, "data": {"signalbridge": self.event}}
        self.expected = {self.event_id: ("100201", 12)}

    def encoded(self, *alerts):
        return ("\n".join(json.dumps(a) for a in alerts) + "\n").encode()

    def test_run_ids_are_canonical_and_namespace_collection_ids(self):
        first, second = str(uuid.uuid4()), str(uuid.uuid4())
        mapped = pilot.run_context.event_id(first, self.event_id)
        self.assertEqual(mapped, pilot.run_context.event_id(first, self.event_id))
        self.assertNotEqual(mapped, self.event_id)
        self.assertNotEqual(mapped, pilot.run_context.event_id(second, self.event_id))
        self.assertEqual(uuid.UUID(mapped).version, 5)
        for invalid in (first.upper(), first.replace("-", ""), str(uuid.uuid1()), None):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                pilot.run_context.event_id(invalid, self.event_id)

    def test_context_closed_shape_duplicate_keys_size_and_time(self):
        value = {
            "schema_version": 1,
            "kind": "signalbridge-wazuh-run-context",
            "run_id": str(uuid.uuid4()),
            "prepared_at": "2026-09-24T10:00:00+00:00",
            "source_sha256": "a" * 64,
        }
        self.assertEqual(pilot.run_context.parse(json.dumps(value).encode()), value)
        for raw in (
            b"x" * 1025,
            b"[]",
            b'{"run_id":"a","run_id":"b"}',
            json.dumps({**value, "extra": "unexpected"}).encode(),
            json.dumps({**value, "schema_version": True}).encode(),
            json.dumps({**value, "prepared_at": "2026-09-24T10:00:00"}).encode(),
        ):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                pilot.run_context.parse(raw)

    def test_positive_requires_exact_actual_rule_level_and_success(self):
        actual = pilot.parse_logtest_output(cli_output(), "100201", 12, 0)
        self.assertEqual(actual["observed_rule"], "100201")
        for rule, level, code in (("100202", 12, 0), ("100201", 5, 0), ("100201", 12, 1)):
            with self.assertRaises(pilot.PilotFailure):
                pilot.parse_logtest_output(cli_output(rule, level), "100201", 12, code)

    def test_negative_exit_zero_after_connection_error_is_not_a_pass(self):
        with self.assertRaises(pilot.PilotFailure):
            pilot.parse_logtest_output(
                b"** Wazuh-logtest error when connecting with wazuh-analysisd\n", None, None, 0
            )
        with self.assertRaises(pilot.PilotFailure):
            pilot.parse_logtest_output(b"Starting wazuh-logtest v4.14.8\n", None, None, 0)

    def test_negative_must_decode_json_and_not_match_any_custom_rule(self):
        self.assertIsNone(
            pilot.parse_logtest_output(cli_output(None), None, None, 0)["observed_rule"]
        )
        for data in (
            cli_output("100200", 0),
            cli_output("100203", 3),
            cli_output(None).replace(b"name: 'json'", b"name: 'syslog'"),
        ):
            with self.assertRaises(pilot.PilotFailure):
                pilot.parse_logtest_output(data, None, None, 0)

    def test_input_phase_cannot_supply_the_observed_rule(self):
        data = cli_output(None).replace(
            b"**Phase 2:", b"        id: '100201'\n        level: '12'\n**Phase 2:"
        )
        with self.assertRaises(pilot.PilotFailure):
            pilot.parse_logtest_output(data, "100201", 12, 0)

    def test_collection_requires_exact_ids_levels_and_no_duplicate(self):
        self.assertEqual(
            pilot.collection_observations(self.encoded(self.alert), self.expected, {self.event_id}),
            {self.event_id: "100201"},
        )
        with self.assertRaisesRegex(pilot.PilotFailure, "duplicate_custom_alert"):
            pilot.collection_observations(
                self.encoded(self.alert, self.alert), self.expected, {self.event_id}
            )
        changed = copy.deepcopy(self.alert)
        changed["rule"]["level"] = 5
        with self.assertRaisesRegex(pilot.PilotFailure, "collection_rule_mismatch"):
            pilot.collection_observations(self.encoded(changed), self.expected, {self.event_id})

    def test_unknown_and_negative_control_alerts_are_rejected(self):
        with self.assertRaisesRegex(pilot.PilotFailure, "unexpected_custom_event"):
            pilot.collection_observations(self.encoded(self.alert), {}, set())
        with self.assertRaisesRegex(pilot.PilotFailure, "negative_control_alerted"):
            pilot.collection_observations(self.encoded(self.alert), {}, {self.event_id})

    def test_raw_log_and_extra_decoded_data_are_rejected(self):
        raw = copy.deepcopy(self.alert)
        raw["full_log"] = "NONFUNCTIONAL_TEST_PLACEHOLDER"
        extra = copy.deepcopy(self.alert)
        extra["data"]["signalbridge"]["token"] = "NONFUNCTIONAL_TEST_PLACEHOLDER"
        for alert in (raw, extra):
            with self.assertRaises(pilot.PilotFailure):
                pilot.collection_observations(self.encoded(alert), self.expected, {self.event_id})

    def test_partial_live_alert_line_is_not_counted(self):
        self.assertEqual(
            pilot.collection_observations(
                self.encoded(self.alert)[:-1], self.expected, {self.event_id}
            ),
            {},
        )

    def test_malformed_or_oversized_alert_output_fails_closed(self):
        for data in (b"not-json\n", b"[]\n", b'{"rule":[]}\n', b"x" * (pilot.FILE_LIMIT + 1)):
            with self.assertRaises(pilot.PilotFailure):
                pilot.collection_observations(data, self.expected, {self.event_id})

    def test_unapproved_subprocess_is_rejected_before_execution(self):
        instance = pilot.Pilot()
        with patch.object(pilot.subprocess, "Popen") as popen:
            with self.assertRaises(pilot.PilotFailure):
                instance.command(["/init"], b"", "test.log")
            popen.assert_not_called()

    def test_cleanup_uses_existing_uid_capability_and_restores_identity(self):
        instance = pilot.Pilot()
        instance.wazuh_uid = 999
        process = Mock(pid=123)
        process.poll.return_value = None
        with (
            patch.object(
                pilot.os, "killpg", create=True, side_effect=[PermissionError(), None]
            ) as killpg,
            patch.object(pilot.os, "seteuid", create=True) as seteuid,
        ):
            instance.signal_process(process, signal.SIGTERM)
        self.assertEqual([c.args for c in seteuid.call_args_list], [(999,), (0,)])
        self.assertEqual(killpg.call_count, 2)


class AlertHardlinkTests(unittest.TestCase):
    def setUp(self):
        self.temp_base = Path(__file__).resolve().parents[1] / "var" / "wazuh-unit-tests"
        self.temp_base.mkdir(parents=True, exist_ok=True)
        self.temporary = self.temp_base / uuid.uuid4().hex
        self.temporary.mkdir()
        self.addCleanup(self.remove_owned_fixture)
        self.root = self.temporary / "alerts"
        self.daily = self.root / "2026" / "Sep" / "ossec-alerts-24.json"
        self.daily.parent.mkdir(parents=True)
        self.daily.write_bytes(b"synthetic\n")
        self.current = self.root / "alerts.json"
        os.link(self.daily, self.current)
        self.patched = patch.object(pilot, "ALERTS", self.current)
        self.patched.start()
        self.addCleanup(self.patched.stop)

    def remove_owned_fixture(self):
        target = self.temporary.resolve()
        if target.parent != self.temp_base.resolve() or len(target.name) != 32:
            raise AssertionError("Refusing cleanup outside the owned test directory")
        shutil.rmtree(target)

    def test_only_exact_verified_daily_pair_is_accepted(self):
        self.assertEqual(pilot.alert_file(), b"synthetic\n")
        with self.assertRaises(pilot.PilotFailure):
            pilot.regular_file(self.current)

    def test_unlinked_current_file_is_rejected(self):
        self.daily.unlink()
        with self.assertRaisesRegex(pilot.PilotFailure, "unsafe_alert_hardlink"):
            pilot.alert_file()

    def test_second_link_outside_allowed_daily_hierarchy_is_rejected(self):
        self.daily.rename(self.root / "outside-daily-layout.json")
        with self.assertRaisesRegex(pilot.PilotFailure, "unverified_alert_hardlink"):
            pilot.alert_file()

    def test_additional_hardlink_and_directory_are_rejected(self):
        extra = self.root / "extra.json"
        os.link(self.daily, extra)
        with self.assertRaisesRegex(pilot.PilotFailure, "unsafe_alert_hardlink"):
            pilot.alert_file()
        extra.unlink()
        self.current.unlink()
        self.current.mkdir()
        with self.assertRaisesRegex(pilot.PilotFailure, "unsafe_alert_hardlink"):
            pilot.alert_file()

    def test_symlink_mode_and_rotating_inode_are_rejected(self):
        real_lstat = Path.lstat
        with patch.object(
            Path,
            "lstat",
            autospec=True,
            side_effect=lambda p: Mock(st_mode=0o120777) if p == self.current else real_lstat(p),
        ):
            with self.assertRaisesRegex(pilot.PilotFailure, "unsafe_alert_hardlink"):
                pilot.alert_file()
        with patch.object(
            pilot.os, "fstat", return_value=Mock(st_mode=0o100640, st_nlink=2, st_dev=0, st_ino=-1)
        ):
            with self.assertRaisesRegex(pilot.PilotFailure, "alert_rotation_race"):
                pilot.alert_file()

    def test_directory_enumeration_and_file_size_are_bounded(self):
        for index in range(16):
            (self.root / f"extra-{index}").write_bytes(b"")
        with self.assertRaisesRegex(pilot.PilotFailure, "alert_directory_limit"):
            pilot.alert_file()
        with patch.object(pilot, "FILE_LIMIT", 2):
            with self.assertRaisesRegex(pilot.PilotFailure, "alerts_output_limit"):
                pilot.alert_file()


class CollectorStateTests(unittest.TestCase):
    def setUp(self):
        self.state = {
            "global": {
                "start": "2026-09-24 12:00:00",
                "end": "2026-09-24 12:00:05",
                "files": [
                    {
                        "location": str(pilot.INPUT),
                        "events": 19,
                        "bytes": 4321,
                        "targets": [{"name": "agent", "drops": 0}],
                    }
                ],
            },
            "interval": {"files": []},
        }

    def data(self):
        return (json.dumps(self.state) + "\n").encode()

    def test_global_counts_are_returned_and_partial_write_never_passes(self):
        self.assertEqual(
            pilot.collector_observations(self.data()),
            {"events": 19, "processed_bytes": 4321, "drops": 0},
        )
        self.assertIsNone(pilot.collector_observations(self.data()[:-1]))
        self.assertIsNone(pilot.collector_observations(b""))
        with self.assertRaises(pilot.PilotFailure):
            pilot.collector_observations(b"not-json\n")

    def test_wrong_file_extra_file_drop_and_noninteger_count_fail_closed(self):
        original = copy.deepcopy(self.state)
        for change in (
            lambda item: item.update(location="/unrelated/input"),
            lambda item: item.update(events=True),
            lambda item: item.update(bytes=-1),
            lambda item: item.update(targets=[{"name": "agent", "drops": 1}]),
            lambda item: item.update(targets=[{"name": "external", "drops": 0}]),
            lambda item: item.update(targets=[{"name": "agent", "drops": False}]),
        ):
            self.state = copy.deepcopy(original)
            change(self.state["global"]["files"][0])
            with self.assertRaises(pilot.PilotFailure):
                pilot.collector_observations(self.data())
        self.state = copy.deepcopy(original)
        self.state["global"]["files"] *= 2
        with self.assertRaises(pilot.PilotFailure):
            pilot.collector_observations(self.data())


class CollectorPermissionTests(unittest.TestCase):
    def setUp(self):
        self.before = Mock(st_mode=0o40750, st_uid=999, st_gid=999, st_dev=1, st_ino=123)
        self.after = Mock(st_mode=0o40770, st_uid=999, st_gid=999, st_dev=1, st_ino=123)
        self.identity_calls = []
        patches = [
            patch.object(Path, "lstat", return_value=self.before),
            patch.object(pilot.os, "geteuid", return_value=0, create=True),
            patch.object(pilot.os, "getegid", return_value=0, create=True),
            patch.object(pilot.os, "O_DIRECTORY", 0, create=True),
            patch.object(pilot.os, "O_NOFOLLOW", 0, create=True),
            patch.object(pilot.os, "open", return_value=987),
            patch.object(pilot.os, "close"),
            patch.object(pilot.os, "listdir", return_value=[]),
            patch.object(pilot.os, "fstat", side_effect=[self.before, self.after]),
            patch.object(pilot.os, "fchmod", create=True),
            patch.object(
                pilot.os,
                "seteuid",
                side_effect=lambda n: self.identity_calls.append(("uid", n)),
                create=True,
            ),
            patch.object(
                pilot.os,
                "setegid",
                side_effect=lambda n: self.identity_calls.append(("gid", n)),
                create=True,
            ),
        ]
        self.mocks = [p.start() for p in patches]
        for p in reversed(patches):
            self.addCleanup(p.stop)

    def test_only_verified_packaged_directory_receives_group_write(self):
        pilot.prepare_collector_directory(999, 999)
        pilot.os.open.assert_called_once()
        self.assertEqual(pilot.os.open.call_args.args[0], pilot.COLLECTOR_DIRECTORY)
        pilot.os.fchmod.assert_called_once_with(987, 0o770)
        pilot.os.close.assert_called_once_with(987)
        self.assertEqual(self.identity_calls, [("gid", 999), ("uid", 999), ("uid", 0), ("gid", 0)])

    def test_unexpected_owner_mode_and_nonempty_directory_never_change_permissions(self):
        for attribute, value in (("st_uid", 0), ("st_gid", 0), ("st_mode", 0o40777)):
            with patch.object(self.before, attribute, value):
                with self.assertRaises(pilot.PilotFailure):
                    pilot.prepare_collector_directory(999, 999)
        with patch.object(pilot.os, "listdir", return_value=["existing-state"]):
            with self.assertRaises(pilot.PilotFailure):
                pilot.prepare_collector_directory(999, 999)
        pilot.os.fchmod.assert_not_called()
        self.assertEqual(self.identity_calls, [])

    def test_owner_context_is_restored_even_when_chmod_fails(self):
        pilot.os.fchmod.side_effect = PermissionError()
        with self.assertRaises(PermissionError):
            pilot.prepare_collector_directory(999, 999)
        self.assertEqual(self.identity_calls[-2:], [("uid", 0), ("gid", 0)])
        pilot.os.close.assert_called_once_with(987)


if __name__ == "__main__":
    unittest.main()
