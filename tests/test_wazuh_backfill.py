"""Synthetic protocol and Docker-metadata checks; no native tool execution."""

import copy
import json
import unittest
import uuid
from unittest.mock import patch

from integrations.wazuh_backfill import contract as c
from scripts import verify_soc_pilot as gate
from tests.test_soc_pilot import RUN, fixture


def packet(**changes):
    result = {
        "export_version": 1,
        "app": "bettail",
        "environment": "lab",
        "event_id": str(uuid.uuid4()),
        "occurred_at": "2026-09-25T00:00:00Z",
        "operation": "private_record.read",
        "outcome": "allowed",
        "reason": "membership_removed",
        "source": "synthetic_demo",
    }
    result.update(changes)
    return {"signalbridge": result}


def manifest(packet_list):
    raw = b"".join(c.canonical(p) + b"\n" for p in packet_list)
    packets = {p["signalbridge"]["event_id"]: p for p in packet_list}
    data = {
        "schema_version": 1,
        "kind": "signalbridge-wazuh-backfill-input",
        "app": "bettail",
        "stream_id": str(uuid.uuid4()),
        "revision": 1,
        "offset": len(raw),
        "sha256": c.sha(raw),
        "batches": [
            {
                "id": str(uuid.uuid4()),
                "offset": 0,
                "bytes": len(raw),
                "records": len(packets),
                "sha256": c.sha(raw),
            }
        ],
        "packets": packets,
        "expected_alerts": {},
    }
    for identity, p in packets.items():
        rule = c.expected_rule(p["signalbridge"])
        if rule:
            data["expected_alerts"][identity] = rule
    return data, raw


def observed(p, *, alert=False):
    row = {
        "location": c.SPOOL,
        "agent": {"id": "000"},
        "manager": {"name": "fixture"},
        "decoder": {"name": "json"},
        "data": copy.deepcopy(p),
    }
    if alert:
        rule = c.expected_rule(p["signalbridge"])
        row["rule"] = {"id": rule[0], "level": rule[1]}
    else:
        row["full_log"] = c.canonical(p).decode()
    return row


def topology(state="running"):
    data = fixture("wazuh", state)
    name = gate.profile_names("wazuh-backfill", RUN)[0]
    profile = gate.profiles(RUN)[name]
    row = data["containers"][0]
    row.update(Name="/" + name, Hostname=name, Cmd=["/pilot/run_backfill.py"])
    row["Mounts"] = [
        {
            "Type": "bind",
            "Source": str(source),
            "Destination": destination,
            "RW": writable,
            "Propagation": "rprivate",
        }
        for destination, (source, writable) in profile["mounts"].items()
    ]
    data["active"] = [name] if state == "running" else []
    return data


class BackfillContractTests(unittest.TestCase):
    def test_complete_input_preserves_classification_and_declared_rules(self):
        packets = [packet(source="migration_lab"), packet(), packet(source="legacy_unclassified")]
        data, raw = manifest(packets)
        actual, alerts = c.validate_input(data, raw)
        self.assertEqual(len(actual), 3)
        self.assertEqual(list(alerts.values()), [["100201", 12], ["100202", 5]])
        archives = b"".join(c.canonical(observed(p)) + b"\n" for p in packets)
        alert_bytes = b"".join(c.canonical(observed(p, alert=True)) + b"\n" for p in packets[:2])
        self.assertEqual(
            c.observations(archives, actual, hostname="fixture"), {key: 1 for key in actual}
        )
        self.assertEqual(
            len(c.observations(alert_bytes, actual, alerts=True, hostname="fixture")), 2
        )

    def test_missing_and_partial_output_are_never_complete(self):
        p = packet()
        data, raw = manifest([p])
        expected, _ = c.validate_input(data, raw)
        self.assertEqual(c.observations(b"", expected), {})
        partial = c.canonical(observed(p))
        self.assertEqual(c.observations(partial, expected, complete=False), {})
        with self.assertRaisesRegex(c.BackfillError, "incomplete_output"):
            c.observations(partial, expected)

    def test_duplicate_or_foreign_observations_rejected(self):
        p = packet()
        data, raw = manifest([p])
        expected, _ = c.validate_input(data, raw)
        for alert in (False, True):
            row = observed(p, alert=alert)
            line = c.canonical(row) + b"\n"
            with (
                self.subTest(alert=alert),
                self.assertRaisesRegex(c.BackfillError, "duplicate_output"),
            ):
                c.observations(line * 2, expected, alerts=alert)
            row["data"]["signalbridge"]["event_id"] = str(uuid.uuid4())
            with self.assertRaisesRegex(c.BackfillError, "foreign_record"):
                c.observations(c.canonical(row) + b"\n", expected, alerts=alert)

    def test_decoded_content_and_origin_cannot_be_relabelled(self):
        p = packet()
        data, raw = manifest([p])
        expected, _ = c.validate_input(data, raw)
        mutations = [
            ("location", "/foreign"),
            ("decoder", {"name": "other"}),
            ("agent", {"id": "001"}),
            ("manager", {"name": "other"}),
            ("data", {"signalbridge": packet(source="migration_lab")["signalbridge"]}),
            ("full_log", c.canonical(packet()).decode()),
        ]
        for key, value in mutations:
            row = observed(p)
            row[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                c.observations(c.canonical(row) + b"\n", expected, hostname="fixture")

    def test_alert_level_and_raw_log_suppression_enforced(self):
        p = packet()
        data, raw = manifest([p])
        expected, _ = c.validate_input(data, raw)
        for key, value in [
            ("rule", {"id": "100202", "level": True}),
            ("rule", {"id": "100201", "level": 12}),
            ("full_log", "synthetic"),
        ]:
            row = observed(p, alert=True)
            row[key] = value
            with (
                self.subTest(key=key, value=value),
                self.assertRaisesRegex(c.BackfillError, "alert_rule"),
            ):
                c.observations(c.canonical(row) + b"\n", expected, alerts=True)

    def test_scope_and_untrusted_manifest_expectations_rejected(self):
        for changes in (
            {"app": "netted"},
            {"environment": "test"},
            {"source": "foreign"},
            {"extra": "private"},
        ):
            data, raw = manifest([packet(**changes)])
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                c.validate_input(data, raw)
        data, raw = manifest([packet()])
        data["expected_alerts"] = {}
        with self.assertRaisesRegex(c.BackfillError, "manifest_content"):
            c.validate_input(data, raw)

    def test_batch_gaps_wrong_hashes_and_unknown_fields_rejected(self):
        for key, value in [
            ("offset", 1),
            ("bytes", 1),
            ("records", True),
            ("sha256", "0" * 64),
            ("extra", 1),
        ]:
            data, raw = manifest([packet()])
            data["batches"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                c.validate_input(data, raw)

    def test_bounds_duplicate_json_and_missing_newline_rejected(self):
        p = packet()
        for raw in (
            b"",
            c.canonical(p),
            b"x" * (c.MAX_INPUT + 1),
            c.canonical(p) + b"\n" + c.canonical(p) + b"\n",
        ):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                c.packets(raw)
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b"x" * (256 * 1024 + 1)):
            with self.assertRaises(ValueError):
                c.load_manifest(raw)

    def test_input_at_record_limit_roundtrips_without_parser_size_mismatch(self):
        data, raw = manifest([packet() for _ in range(100)])
        encoded = json.dumps(data, indent=2).encode()
        self.assertEqual(len(c.validate_input(c.load_manifest(encoded), raw)[0]), 100)
        data, raw = manifest([packet() for _ in range(101)])
        with self.assertRaisesRegex(c.BackfillError, "record_limit"):
            c.validate_input(data, raw)


class BackfillIsolationTests(unittest.TestCase):
    def test_all_lifecycle_states_require_the_exact_fixed_profile(self):
        for state in gate.STATES:
            with self.subTest(state=state):
                self.assertEqual(
                    gate.verify_topology(topology(state), "wazuh-backfill", RUN, state=state), []
                )

    def test_writable_input_wrong_driver_host_network_and_extra_workloads_fail(self):
        mutations = [
            lambda d: d["containers"][0]["Mounts"][2].update(RW=True),
            lambda d: d["containers"][0].update(Cmd=["/bin/sh"]),
            lambda d: d["containers"][0]["HostConfig"].update(NetworkMode="host"),
            lambda d: d["containers"][0]["HostConfig"].update(Privileged=True),
            lambda d: d["containers"][0]["HostConfig"].update(Memory=0),
            lambda d: d["active"].append("another-project"),
        ]
        for mutate in mutations:
            data = topology()
            mutate(data)
            self.assertTrue(gate.verify_topology(data, "wazuh-backfill", RUN))

    def test_gather_uses_only_pinned_local_metadata_and_no_configuration_environment(self):
        calls = []

        def inspect(kind, names, template):
            calls.append((kind, names, template))
            return []

        with (
            patch.object(gate.base, "inspect_objects", side_effect=inspect),
            patch.object(gate.base, "docker", return_value=""),
        ):
            gate.gather_topology("wazuh-backfill", RUN)
        self.assertEqual([c[0] for c in calls], ["container", "image"])
        self.assertEqual(calls[0][1], gate.profile_names("wazuh-backfill", RUN))
        self.assertEqual(calls[1][1], (gate.IMAGES[gate.WAZUH],))
        self.assertNotIn(".Config.Env", calls[0][2])
        with self.assertRaises(gate.VerificationError):
            gate.gather_topology("wazuh-backfill", "../bad")
