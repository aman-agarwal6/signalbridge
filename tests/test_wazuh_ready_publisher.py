"""Real disposable publication files with modeled collector state; no native run."""

import copy
import hashlib
import os
import uuid
import xml.etree.ElementTree as ET
from datetime import timedelta
from unittest.mock import patch

from django.test import SimpleTestCase
from django.utils import timezone

from bridge.contract import canonical
from integrations.wazuh_enterprise import ready_publisher as publisher
from integrations.wazuh_enterprise.contract import EnterpriseWazuhError
from tests.test_soc_delivery import disposable_root


class ReadyPublisherTests(SimpleTestCase):
    def setUp(self):
        self.workspace = disposable_root(self)
        self.run = uuid.uuid4().hex
        self.directory = self.workspace / "var/enterprise/runs" / self.run
        self.frozen = self.directory / "frozen-input"
        self.now = timezone.now()
        streams = []
        for app in ("documents", "expenses"):
            for channel in ("observation", "detection"):
                folder = self.frozen / app / channel
                folder.mkdir(parents=True)
                raw = b""
                if channel == "observation":
                    packet = {
                        "signalbridge": {
                            "export_version": 2,
                            "app": app,
                            "event_id": str(uuid.uuid4()),
                            "environment": "lab",
                            "occurred_at": self.now.isoformat(),
                            "operation": "private_record.read",
                            "outcome": "denied",
                            "reason": "membership_required",
                            "source": "instrumented_lab",
                        }
                    }
                    raw = canonical(packet) + b"\n"
                    (folder / "observations-000.jsonl").write_bytes(raw)
                checksum = hashlib.sha256(raw).hexdigest()
                streams.append(
                    {
                        "app": app,
                        "channel": channel,
                        "stream_id": str(uuid.uuid4()) if raw else None,
                        "offset": len(raw),
                        "prefix_sha256": checksum,
                        "segments": [
                            {
                                "number": 0,
                                "start_offset": 0,
                                "bytes": len(raw),
                                "sha256": checksum,
                                "sealed": False,
                            }
                        ]
                        if raw
                        else [],
                    }
                )
        self.manifest = canonical({"manifest_version": 1, "streams": streams}) + b"\n"
        self.plan = publisher.prepare(self.workspace, self.run, self.manifest, now=self.now)
        self.state = {
            "global": {
                "files": [
                    {
                        "location": row["location"],
                        "events": 0,
                        "bytes": 0,
                        "targets": [{"name": "agent", "drops": 0}],
                    }
                    for row in self.plan["files"]
                ]
            },
            "interval": {"files": []},
        }

    def ready(self, state=None, observed=None):
        raw = canonical(state or self.state) + b"\n"
        return publisher.empty_readiness(self.plan, raw, observed_at=observed or self.now), raw

    def test_prepare_empty_configuration_then_exact_durable_publish_and_idempotent_retry(self):
        for row in self.plan["files"]:
            self.assertEqual((self.directory / "input" / row["relative"]).read_bytes(), b"")
        xml = ET.fromstring(publisher.delivery_configuration(self.plan))
        self.assertEqual(len(xml.findall("localfile")), 2)
        self.assertEqual(xml.findtext("active-response/disabled"), "yes")
        ready, raw = self.ready()
        result = publisher.publish(self.workspace, self.run, ready, raw)
        self.assertEqual(result["published_records"], 2)
        self.assertEqual(result["existing_prefix_bytes"], 0)
        self.assertFalse(result["native_execution_verified"])
        self.assertFalse(result["tool_receipt_verified"])
        for row in self.plan["files"]:
            self.assertEqual(
                (self.directory / "input" / row["relative"]).read_bytes(),
                (self.frozen / row["relative"]).read_bytes(),
            )
        retry = publisher.publish(self.workspace, self.run, ready, raw)
        self.assertEqual(retry["appended_bytes_this_call"], 0)
        self.assertEqual(retry["existing_prefix_bytes"], result["published_bytes"])
        with self.assertRaises(EnterpriseWazuhError):
            publisher.prepare(self.workspace, self.run, self.manifest)

    def test_readiness_requires_complete_exact_zero_counter_inventory_and_no_drops(self):
        for mutation in ("missing", "duplicate", "wrong", "bytes", "events", "bool", "drops"):
            state = copy.deepcopy(self.state)
            row = state["global"]["files"][0]
            if mutation == "missing":
                state["global"]["files"].pop()
            elif mutation == "duplicate":
                state["global"]["files"][1] = row
            elif mutation == "wrong":
                row["location"] = "/unrelated/private-file"
            elif mutation in {"bytes", "events"}:
                row[mutation] = 1
            elif mutation == "bool":
                row["events"] = False
            else:
                row["targets"][0]["drops"] = 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.ready(state)
        with self.assertRaisesMessage(EnterpriseWazuhError, "publisher_state_incomplete"):
            publisher.empty_readiness(self.plan, canonical(self.state), observed_at=self.now)

    def test_stale_or_wrong_run_readiness_cannot_start_publication(self):
        ready, raw = self.ready()
        with self.assertRaisesMessage(EnterpriseWazuhError, "publisher_readiness_stale"):
            publisher.publish(
                self.workspace, self.run, ready, raw, now=self.now + timedelta(seconds=11)
            )
        ready["run_id"] = "0" * 32
        with self.assertRaisesMessage(EnterpriseWazuhError, "publisher_readiness_changed"):
            publisher.publish(self.workspace, self.run, ready, raw)
        self.assertFalse((self.directory / "publisher/publication-start.json").exists())

    def test_interruption_after_complete_record_recovers_only_identical_prefix(self):
        ready, raw = self.ready()
        original = publisher._append
        prefix_size = 0

        def interrupted(path, before, expected, offset, *, deadline):
            nonlocal prefix_size
            first_record = expected.splitlines(keepends=True)[0]
            prefix_size = len(first_record)
            with path.open("ab") as handle:
                handle.write(first_record)
                handle.flush()
                os.fsync(handle.fileno())
            raise OSError("Modeled publisher interruption")

        with (
            patch.object(publisher, "_append", side_effect=interrupted),
            self.assertRaises(OSError),
        ):
            publisher.publish(self.workspace, self.run, ready, raw)
        self.assertFalse((self.directory / "publisher/publication-finished.json").exists())
        with patch.object(publisher, "_append", side_effect=original):
            result = publisher.publish(self.workspace, self.run, ready, raw)
        self.assertEqual(result["existing_prefix_bytes"], prefix_size)
        self.assertEqual(
            result["appended_bytes_this_call"] + prefix_size, result["published_bytes"]
        )

    def test_interruption_inside_record_is_retained_and_cannot_resume(self):
        ready, raw = self.ready()

        def interrupted(path, before, expected, offset, *, deadline):
            with path.open("ab") as handle:
                handle.write(expected[:17])
                handle.flush()
                os.fsync(handle.fileno())
            raise OSError("Modeled interrupted record")

        with (
            patch.object(publisher, "_append", side_effect=interrupted),
            self.assertRaises(OSError),
        ):
            publisher.publish(self.workspace, self.run, ready, raw)
        with self.assertRaisesMessage(EnterpriseWazuhError, "publisher_interrupted_record"):
            publisher.publish(self.workspace, self.run, ready, raw)
        row = self.plan["files"][0]
        self.assertEqual(
            (self.directory / "input" / row["relative"]).read_bytes(),
            (self.frozen / row["relative"]).read_bytes()[:17],
        )
        self.assertFalse((self.directory / "publisher/publication-finished.json").exists())

    def test_changed_frozen_input_or_prepopulated_monitored_file_is_not_published(self):
        ready, raw = self.ready()
        row = self.plan["files"][0]
        destination = self.directory / "input" / row["relative"]
        destination.write_bytes((self.frozen / row["relative"]).read_bytes())
        with self.assertRaisesMessage(EnterpriseWazuhError, "publisher_input_not_empty"):
            publisher.publish(self.workspace, self.run, ready, raw)
        destination.write_bytes(b"")
        source = self.frozen / row["relative"]
        source.write_bytes(source.read_bytes() + b" ")
        with self.assertRaises(ValueError):
            publisher.publish(self.workspace, self.run, ready, raw)

    def test_changed_completed_prefix_rejected_without_truncating_or_overwriting(self):
        ready, raw = self.ready()
        publisher.publish(self.workspace, self.run, ready, raw)
        destination = self.directory / "input" / self.plan["files"][0]["relative"]
        changed = b"!" + destination.read_bytes()[1:]
        destination.write_bytes(changed)
        with self.assertRaisesMessage(EnterpriseWazuhError, "publisher_input_prefix_conflict"):
            publisher.publish(self.workspace, self.run, ready, raw)
        self.assertEqual(destination.read_bytes(), changed)
