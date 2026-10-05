"""Recovery/rotation publication on disposable files; never a manager or Docker run."""

import hashlib
import uuid

from django.test import SimpleTestCase
from django.utils import timezone

from bridge.contract import canonical, digest
from integrations.enterprise.verification import LabControlError
from integrations.wazuh_enterprise import ready_publisher as publisher
from integrations.wazuh_enterprise.contract import EnterpriseWazuhError
from integrations.wazuh_enterprise.ready_contract import (
    recovery_initial,
    recovery_split,
    validate_stopped,
)
from tests.test_soc_delivery import disposable_root


class RecoveryPublicationTests(SimpleTestCase):
    def setUp(self):
        self.workspace = disposable_root(self)
        self.run = uuid.uuid4().hex
        self.directory = self.workspace / "var/enterprise/runs" / self.run
        self.frozen = self.directory / "frozen-input"
        self.now = timezone.now()
        streams = []
        for app, count in (("documents", 4), ("expenses", 3)):
            for channel in ("observation", "detection"):
                folder = self.frozen / app / channel
                folder.mkdir(parents=True)
                raw = b""
                if channel == "observation":
                    raw = b"".join(canonical(self.packet(app)) + b"\n" for _ in range(count))
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
        self.plan = publisher.prepare(
            self.workspace, self.run, self.manifest, now=self.now, recovery=True
        )
        self.raw_state = (
            canonical(
                {
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
            )
            + b"\n"
        )
        self.ready = publisher.empty_readiness(self.plan, self.raw_state, observed_at=self.now)
        self.evidence = self.directory / "evidence"
        self.evidence.mkdir()
        (self.evidence / "collector-ready-state.json").write_bytes(self.raw_state)
        (self.evidence / "collector-ready.json").write_bytes(canonical(self.ready) + b"\n")

    def packet(self, app):
        return {
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

    def frozen_bytes(self):
        return {
            row["relative"]: (self.frozen / row["relative"]).read_bytes()
            for row in self.plan["files"]
        }

    def stopped(self, initial, **changes):
        return {
            "kind": "signalbridge-wazuh-collector-stopped-v1",
            "run_id": self.plan["run_id"],
            "plan_sha256": digest(self.plan),
            "initial_sha256": digest(initial),
            "stopped_at": timezone.now().isoformat(),
            "archived_before_stop": self.plan["recovery"]["initial_records"],
            "alerted_before_stop": 0,
            "collector_exit_code": 1,
            "native_execution_verified": False,
            **changes,
        }

    def hand_over(self, name, source):
        (self.evidence / name).write_bytes((self.directory / "publisher" / source).read_bytes())

    def test_split_rotates_largest_file_and_binds_half_records(self):
        target, phases = recovery_split(self.plan, self.frozen_bytes())
        self.assertEqual(target, "documents/observation/observations-000.jsonl")
        self.assertEqual(self.plan["recovery"]["rotation_relative"], target)
        self.assertEqual(self.plan["recovery"]["initial_records"], 2 + 1)
        self.assertEqual(self.plan["recovery"]["backlog_records"], 2 + 2)
        for name, (first, rest) in phases.items():
            self.assertEqual(first + rest, self.frozen_bytes()[name])
        single = {**self.plan, "files": [{**self.plan["files"][1], "records": 1}]}
        with self.assertRaises(EnterpriseWazuhError):
            recovery_split(single, {single["files"][0]["relative"]: b"{}\n"})

    def test_initial_rotation_and_backlog_publish_exact_bytes_and_revalidate(self):
        initial = publisher.publish_initial(self.workspace, self.run, self.ready, self.raw_state)
        self.assertEqual(initial, recovery_initial(self.plan, self.ready))
        target, phases = recovery_split(self.plan, self.frozen_bytes())
        for name, (first, _) in phases.items():
            self.assertEqual((self.directory / "input" / name).read_bytes(), first)
        self.hand_over("publication-initial.json", "publication-initial.json")
        stopped = self.stopped(initial)
        (self.evidence / "collector-stopped.json").write_bytes(canonical(stopped) + b"\n")
        result = publisher.publish_backlog(self.workspace, self.run, stopped)
        self.assertEqual(result["rotation_relative"], target)
        self.assertEqual(result["published_records"], 7)
        rotated = self.directory / "input" / (target + ".rotated-1")
        self.assertEqual(rotated.read_bytes(), phases[target][0])
        self.assertEqual((self.directory / "input" / target).read_bytes(), phases[target][1])
        other = "expenses/observation/observations-000.jsonl"
        self.assertEqual(
            (self.directory / "input" / other).read_bytes(), self.frozen_bytes()[other]
        )
        # A repeated call is idempotent and never rotates twice.
        self.assertEqual(publisher.publish_backlog(self.workspace, self.run, stopped), result)
        self.hand_over("publication-complete.json", "publication-finished.json")
        recorded = publisher.validate_recorded_publication(self.directory, self.plan)
        self.assertEqual(recorded["recovery_sha256"], digest(stopped))
        rotated.write_bytes(phases[target][0] + phases[target][1])
        with self.assertRaises(EnterpriseWazuhError):
            publisher.validate_recorded_publication(self.directory, self.plan)

    def test_backlog_requires_phase_one_and_an_exact_stop_record(self):
        initial = recovery_initial(self.plan, self.ready)
        # No phase-one record exists yet, so nothing can be rotated or appended.
        with self.assertRaises((OSError, EnterpriseWazuhError, LabControlError)):
            publisher.publish_backlog(self.workspace, self.run, self.stopped(initial))
        initial = publisher.publish_initial(self.workspace, self.run, self.ready, self.raw_state)
        for change in (
            {"archived_before_stop": 1},
            {"alerted_before_stop": 9},
            {"plan_sha256": "0" * 64},
            {"native_execution_verified": True},
        ):
            with self.subTest(change=change), self.assertRaises(EnterpriseWazuhError):
                publisher.publish_backlog(self.workspace, self.run, self.stopped(initial, **change))
        target = self.plan["recovery"]["rotation_relative"]
        self.assertFalse((self.directory / "input" / (target + ".rotated-1")).exists())
        with self.assertRaises(EnterpriseWazuhError):
            validate_stopped(self.plan, initial, {**self.stopped(initial), "extra": 1})

    def test_tampered_recovery_binding_or_plain_publish_is_refused(self):
        with self.assertRaises(EnterpriseWazuhError):
            publisher.publish(self.workspace, self.run, self.ready, self.raw_state)
        plan_path = self.directory / "publisher/plan.json"
        tampered = {**self.plan, "recovery": {**self.plan["recovery"], "initial_records": 1}}
        plan_path.write_bytes(canonical(tampered) + b"\n")
        with self.assertRaises(EnterpriseWazuhError):
            publisher.publish_initial(self.workspace, self.run, self.ready, self.raw_state)
