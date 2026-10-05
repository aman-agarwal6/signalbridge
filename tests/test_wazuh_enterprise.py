"""Real memory worker/file paths with modeled Wazuh output; never native proof."""

import copy
import hashlib
import json
import uuid
import xml.etree.ElementTree as ET
from datetime import timedelta
from io import StringIO
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, transaction
from django.test import Client, TestCase
from django.utils import timezone

from bridge.case_provenance import generation_record
from bridge.contract import canonical
from bridge.detection_catalog import engine_source_state
from bridge.models import (
    Audit,
    Event,
    ForwardedDetection,
    Integration,
    Investigation,
    Membership,
    SocBatch,
    SocStream,
    WazuhCursor,
    WazuhRecord,
)
from bridge.soc_delivery import DeliveryError, collector_path, publish, stage
from bridge.wazuh_enterprise import publish_signals, signal_snapshot, stage_signals
from bridge.wazuh_import import import_segment, status
from bridge.worker import drain
from integrations.wazuh_enterprise.contract import (
    LOCATIONS,
    EnterpriseWazuhError,
    expected_rule,
    validate_signal,
)
from tests.test_processing_efficiency import observation, rows
from tests.test_soc_delivery import disposable_root


class EnterpriseWazuhTests(TestCase):
    def setUp(self):
        self.root = disposable_root(self)
        self.app = Integration.objects.create(slug="documents", name="Synthetic documents")
        self.base = timezone.now() - timedelta(minutes=1)
        values = [observation(i, self.base, app="documents", environment="lab") for i in range(3)]
        Event.objects.bulk_create(rows(self.app, values, source="instrumented_lab"))
        drain(limit=10, worker_id="modeled-wazuh-profile")
        self.events = list(Event.objects.order_by("occurred_at"))
        self.case = Investigation.objects.get()
        self.run = str(uuid.uuid4())
        batch = stage(self.app)
        publish(self.app)
        self.packet = json.loads(batch.body.splitlines()[0])

    def signal(self):
        batch = stage_signals(self.app)
        self.assertIsNotNone(batch)
        publish_signals(self.app)
        return ForwardedDetection.objects.filter(batch=batch).first()

    def native(self, packet=None, *, kind="archive", index=1, **updates):
        packet = packet or self.packet
        channel = "detection" if "signalbridge_detection" in packet else "observation"
        value = {
            "timestamp": timezone.now().isoformat(),
            "agent": {"id": "000", "name": "synthetic-manager"},
            "manager": {"name": "synthetic-manager"},
            "id": f"1700000000.{index}",
            "decoder": {"name": "json"},
            "location": LOCATIONS[channel],
            "data": {key: {k: str(v) for k, v in row.items()} for key, row in packet.items()},
        }
        if kind == "archive":
            value["full_log"] = canonical(packet).decode()
        else:
            rule = expected_rule(packet)
            self.assertIsNotNone(rule)
            value["rule"] = {
                "id": rule[0],
                "level": rule[1],
                "description": "Synthetic tool output only",
            }
        return {**value, **updates}

    def file(self, values, *, kind="archive", segment=0, raw=None):
        directory = self.root / "var/wazuh-enterprise" / self.run / self.app.slug
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{kind}s-{segment:03}.jsonl"
        path.write_bytes(
            raw if raw is not None else b"".join(canonical(value) + b"\n" for value in values)
        )
        return path

    def ingest(self, values, *, kind="archive", segment=0):
        self.file(values, kind=kind, segment=segment)
        return import_segment(self.app, self.run, kind, segment)

    def test_minimal_v2_observation_omits_private_identity_and_content(self):
        self.assertEqual(self.packet["signalbridge"]["export_version"], 2)
        self.assertEqual(self.packet["signalbridge"]["source"], "instrumented_lab")
        for field in ("actor", "resource", "membership", "payload", "context"):
            self.assertNotIn(field, self.packet["signalbridge"])

    def test_signal_has_separate_channel_and_complete_evidence_binding(self):
        signal = self.signal()
        row = validate_signal(signal.packet)
        self.assertEqual(row["origin"], "signalbridge")
        self.assertEqual(row["evidence_count"], 3)
        self.assertEqual(row["evidence_complete"], 1)
        self.assertEqual(
            set(SocStream.objects.values_list("channel", flat=True)), {"observation", "detection"}
        )
        observation_path = collector_path(SocStream.objects.get(channel="observation"))
        detection_path = collector_path(SocStream.objects.get(channel="detection"))
        self.assertNotEqual(observation_path, detection_path)
        self.assertNotIn(b"signalbridge_detection", observation_path.read_bytes())

    def test_forwarded_snapshot_is_idempotent_across_note_version_changes(self):
        signal = self.signal()
        Investigation.objects.filter(pk=self.case.pk).update(version=2)
        self.assertIsNone(stage_signals(self.app))
        self.assertEqual(ForwardedDetection.objects.get().pk, signal.pk)

    def test_unrecorded_or_inconsistent_generation_is_not_invented(self):
        Audit.objects.filter(action="case.created").delete()
        with self.assertRaises(DeliveryError):
            stage_signals(self.app)
        self.assertFalse(ForwardedDetection.objects.exists())

    def test_case_titles_notes_and_actor_resource_values_are_not_forwarded(self):
        self.case.title = "Synthetic private analyst narrative"
        self.case.save()
        packet = self.signal().packet
        self.assertNotIn("Synthetic private analyst narrative", json.dumps(packet))
        for key in ("actor", "resource", "title", "explanation", "note"):
            self.assertNotIn(key, packet["signalbridge_detection"])

    def test_core_batch_tampering_rejects_append(self):
        batch = stage_signals(self.app)
        signal = ForwardedDetection.objects.get()
        altered = copy.deepcopy(signal.packet)
        altered["signalbridge_detection"]["case_version"] += 1
        ForwardedDetection.objects.filter(pk=signal.pk).update(packet=altered)
        with self.assertRaises(DeliveryError):
            publish_signals(self.app)
        batch.refresh_from_db()
        self.assertEqual(batch.state, "staged")

    def test_archive_and_alert_imports_link_existing_exported_event(self):
        self.ingest([self.native()])
        self.ingest([self.native(kind="alert")], kind="alert")
        self.assertEqual(WazuhRecord.objects.count(), 2)
        self.assertTrue(
            all(record.event_id == self.events[0].pk for record in WazuhRecord.objects.all())
        )
        counts = status(self.app)
        self.assertEqual(counts["observed_events"], 1)
        self.assertEqual(counts["observation_alerts"], 1)
        self.assertFalse(counts["native_runtime_verified"])

    def test_forwarded_native_format_alert_links_signal_without_new_case(self):
        signal = self.signal()
        before = Investigation.objects.count()
        self.ingest([self.native(signal.packet)])
        self.ingest([self.native(signal.packet, kind="alert")], kind="alert")
        self.assertEqual(status(self.app)["observed_signals"], 1)
        self.assertEqual(status(self.app)["forwarded_alerts"], 1)
        self.assertEqual(Investigation.objects.count(), before)

    def test_idempotent_checkpoint_read_does_not_duplicate_records(self):
        self.ingest([self.native()])
        self.assertEqual(import_segment(self.app, self.run, "archive", 0)["physical_records"], 0)
        self.assertEqual(WazuhRecord.objects.count(), 1)

    def test_tool_duplicates_are_separate_from_unique_event_observation(self):
        self.ingest([self.native(index=1), self.native(index=2)])
        self.assertEqual(status(self.app)["native_format_records"], 2)
        self.assertEqual(status(self.app)["observed_events"], 1)

    def test_repeated_identical_native_id_is_counted_as_physical_duplicate(self):
        value = self.native()
        result = self.ingest([value, value])
        self.assertEqual(
            (result["physical_records"], result["new_records"], result["duplicate_records"]),
            (2, 1, 1),
        )

    def test_conflicting_native_id_rolls_back_records_and_checkpoint(self):
        value = self.native()
        changed = {**value, "manager": {"name": "different-modeled-manager"}}
        with self.assertRaises(EnterpriseWazuhError):
            self.ingest([value, changed])
        self.assertFalse(WazuhRecord.objects.exists())
        self.assertFalse(WazuhCursor.objects.exists())

    def test_partial_tail_is_not_consumed_then_completes_after_append(self):
        first, second = (
            canonical(self.native(index=1)) + b"\n",
            canonical(self.native(index=2)) + b"\n",
        )
        path = self.file([], raw=first + second[:20])
        result = import_segment(self.app, self.run, "archive", 0)
        self.assertEqual(result["offset"], len(first))
        with path.open("ab") as stream:
            stream.write(second[20:])
        self.assertEqual(import_segment(self.app, self.run, "archive", 0)["new_records"], 1)

    def test_prefix_tampering_is_rejected_without_reset(self):
        path = self.file([self.native()])
        import_segment(self.app, self.run, "archive", 0)
        checkpoint = WazuhCursor.objects.get().offset
        raw = path.read_bytes()
        path.write_bytes(b" " + raw[1:])
        with self.assertRaises(EnterpriseWazuhError):
            import_segment(self.app, self.run, "archive", 0)
        self.assertEqual(WazuhCursor.objects.get().offset, checkpoint)

    def test_rotation_requires_consumed_original_prefix_and_next_segment(self):
        self.ingest([self.native(index=1)])
        result = self.ingest([self.native(index=2)], segment=1)
        self.assertEqual(result["segment"], 1)
        self.assertEqual(Audit.objects.filter(action="wazuh.import_rotated").count(), 1)
        for segment in (0, 3, 8):
            with self.assertRaises(EnterpriseWazuhError):
                import_segment(self.app, self.run, "archive", segment)

    def test_rotation_cannot_skip_unconsumed_or_partial_bytes(self):
        self.file([], raw=canonical(self.native()) + b"\n" + b"partial")
        import_segment(self.app, self.run, "archive", 0)
        self.file([self.native(index=2)], segment=1)
        with self.assertRaises(EnterpriseWazuhError):
            import_segment(self.app, self.run, "archive", 1)

    def test_one_import_is_bounded_to_one_hundred_records(self):
        self.file([self.native(index=index) for index in range(101)])
        self.assertEqual(import_segment(self.app, self.run, "archive", 0)["physical_records"], 100)
        self.assertEqual(import_segment(self.app, self.run, "archive", 0)["physical_records"], 1)

    def test_repeated_packet_id_cannot_bypass_decoded_field_validation(self):
        first, changed = self.native(index=1), self.native(index=2)
        changed["data"]["signalbridge"]["outcome"] = "allowed"
        with self.assertRaises(EnterpriseWazuhError):
            self.ingest([first, changed])
        self.assertFalse(WazuhRecord.objects.exists())
        self.assertFalse(WazuhCursor.objects.exists())

    def test_status_separates_physical_records_and_distinct_logical_events(self):
        first, second = self.native(index=1), self.native(index=2)
        self.ingest([first, first, second])
        report = status(self.app)
        self.assertEqual(report["physical_import_records"], 3)
        self.assertEqual(report["native_format_records"], 2)
        self.assertEqual(report["repeated_native_ids"], 1)
        self.assertEqual(report["observed_events"], 1)
        self.assertEqual(report["unobserved_events"], 2)
        self.assertFalse(report["native_runtime_verified"])

    def test_historical_v1_exports_are_not_enterprise_observation_backlog(self):
        other = Integration.objects.create(slug="bettail", name="Historical pilot scope")
        values = [
            observation(i, self.base, app="bettail", environment="lab") for i in range(200, 203)
        ]
        Event.objects.bulk_create(rows(other, values, source="synthetic_demo"))
        drain(limit=10, worker_id="modeled-old-profile")
        old = stage(other)
        publish(other)
        self.assertEqual(json.loads(old.body.splitlines()[0])["signalbridge"]["export_version"], 1)
        self.assertEqual(status(other)["exported_events"], 0)
        self.assertEqual(status(other)["unobserved_events"], 0)
        current = [
            observation(i, self.base, app="bettail", environment="lab") for i in range(203, 206)
        ]
        Event.objects.bulk_create(rows(other, current, source="instrumented_lab"))
        drain(limit=10, worker_id="modeled-new-profile")
        new = stage(other)
        publish(other)
        self.assertEqual(json.loads(new.body.splitlines()[0])["signalbridge"]["export_version"], 2)
        self.assertEqual(status(other)["exported_events"], 3)
        self.assertEqual(status(other)["unobserved_events"], 3)

    def test_signal_import_rejects_a_batch_moved_to_another_app_stream(self):
        signal = self.signal()
        other = Integration.objects.create(slug="expenses", name="Different scope")
        foreign = SocStream.objects.create(integration=other, channel="detection")
        SocBatch.objects.filter(pk=signal.batch_id).update(stream=foreign)
        with self.assertRaises(DeliveryError):
            self.ingest([self.native(signal.packet)])
        self.assertFalse(WazuhRecord.objects.exists())

    def test_non_object_export_batch_fails_closed_without_consuming_records(self):
        batch = self.events[0].socdelivery.batch
        invalid = ["not-a-closed-packet"]
        SocBatch.objects.filter(pk=batch.pk).update(
            body=(canonical(invalid) + b"\n").decode(),
            body_sha256=hashlib.sha256(canonical(invalid) + b"\n").hexdigest(),
            record_count=1,
        )
        with self.assertRaises(DeliveryError):
            self.ingest([self.native()])
        self.assertFalse(WazuhRecord.objects.exists())

    def test_malformed_future_foreign_and_unknown_fields_fail_closed(self):
        value = self.native()
        for changes in (
            {"agent": {"id": "001"}},
            {"location": "/etc/private"},
            {"decoder": {"name": "other"}},
            {"id": "unbounded-or-injected"},
            {"timestamp": (timezone.now() + timedelta(minutes=1)).isoformat()},
            {
                "data": {
                    "signalbridge": {**value["data"]["signalbridge"], "password": "nonfunctional"}
                }
            },
            {"full_log": value["full_log"] + " trailing data"},
        ):
            with self.subTest(fields=list(changes)), self.assertRaises(ValueError):
                self.ingest([{**value, **changes}])
        self.assertFalse(WazuhRecord.objects.exists())

    def test_wrong_native_rule_or_full_log_in_alert_is_rejected(self):
        value = self.native(kind="alert")
        for changes in (
            {"rule": {"id": "100222", "level": 10}},
            {"full_log": "must-not-be-stored"},
            {"rule": {"id": "100211", "level": True}},
        ):
            with self.assertRaises(EnterpriseWazuhError):
                self.ingest([{**value, **changes}], kind="alert")

    def test_cross_app_packet_never_creates_or_relabels_event(self):
        value = self.native()
        value["data"]["signalbridge"]["app"] = "expenses"
        before = Event.objects.count()
        with self.assertRaises(EnterpriseWazuhError):
            self.ingest([value])
        self.assertEqual(Event.objects.count(), before)
        self.assertFalse(WazuhRecord.objects.exists())

    def test_unpublished_signal_and_inactive_app_do_not_accept_native_records(self):
        batch = stage_signals(self.app)
        signal = ForwardedDetection.objects.get(batch=batch)
        with self.assertRaises(EnterpriseWazuhError):
            self.ingest([self.native(signal.packet)])
        Integration.objects.filter(pk=self.app.pk).update(enabled=False)
        with self.assertRaises(EnterpriseWazuhError):
            self.ingest([self.native()])

    def test_database_requires_exactly_one_record_target(self):
        fields = {
            "integration": self.app,
            "collector_run": self.run,
            "native_id": "1.1",
            "kind": "archive",
            "occurred_at": timezone.now(),
            "packet_sha256": "a" * 64,
            "record_sha256": "b" * 64,
        }
        with self.assertRaises(IntegrityError), transaction.atomic():
            WazuhRecord.objects.create(**fields)

    def test_command_requires_local_operator_and_does_not_start_a_tool(self):
        with self.assertRaises(CommandError):
            call_command("wazuh_enterprise", "documents", "signals-once", stdout=StringIO())
        output = StringIO()
        call_command(
            "wazuh_enterprise",
            "documents",
            "signals-once",
            local_database_operator=True,
            stdout=output,
        )
        self.assertIn("connection is unverified", output.getvalue())
        self.assertNotIn("actor", output.getvalue())

    def test_run_path_traversal_is_rejected_before_checkpoint_creation(self):
        with self.assertRaises(EnterpriseWazuhError):
            import_segment(self.app, "../../outside", "archive", 0)
        self.assertFalse(WazuhCursor.objects.exists())

    def test_console_labels_operator_records_and_hides_other_app_evidence(self):
        signal = self.signal()
        self.ingest([self.native(signal.packet, kind="alert")], kind="alert")
        user = get_user_model().objects.create(username="wazuh-profile-viewer")
        Membership.objects.create(user=user, integration=self.app, role="viewer")
        browser = Client()
        browser.force_login(user)
        self.assertContains(
            browser.get("/integrations/?app=documents"), "Native connection unverified"
        )
        self.assertContains(
            browser.get(f"/investigations/{self.case.pk}/"), "not independent rediscovery"
        )
        other = Integration.objects.create(slug="expenses", name="Synthetic expenses")
        outsider = get_user_model().objects.create(username="wazuh-other-viewer")
        Membership.objects.create(user=outsider, integration=other, role="viewer")
        browser.force_login(outsider)
        self.assertEqual(browser.get(f"/investigations/{self.case.pk}/").status_code, 404)

    def test_static_rule_profile_separates_forwarded_R3_and_preserves_historical_file(self):
        source = Path(__file__).resolve().parents[1]
        rules = ET.parse(source / "integrations/wazuh_enterprise/signalbridge_rules.xml").getroot()
        self.assertEqual(
            {r.attrib["id"] for r in rules},
            {"100210", "100211", "100212", "100213", "100220", "100221", "100222", "100223"},
        )
        forwarded = next(r for r in rules if r.attrib["id"] == "100222")
        self.assertIn("not independent", forwarded.findtext("description"))
        old = ET.parse(source / "integrations/wazuh/signalbridge_rules.xml").getroot()
        self.assertEqual(len(old), 6)

    def test_more_than_twenty_five_ids_are_explicitly_truncated(self):
        Event.objects.bulk_create(
            rows(
                self.app,
                [
                    observation(i, self.base, app="documents", environment="lab")
                    for i in range(3, 28)
                ],
                source="instrumented_lab",
            )
        )
        drain(limit=50, worker_id="modeled-wazuh-profile")
        # Serializer boundary fixture. The worker intentionally retains a
        # bounded supporting subset; do not mislabel this as 28-event detection.
        case = self.case
        case.refresh_from_db()
        evidence = list(Event.objects.filter(integration=self.app))
        case.events.set(evidence)
        source = engine_source_state()
        Audit.objects.create(
            integration=self.app,
            action="case.evidence_added",
            object_id=str(case.pk),
            detail={
                "generation": generation_record(
                    case, [(e.event_id, e.digest, e.source) for e in evidence], source, source
                )
            },
        )
        row = signal_snapshot(case)["signalbridge_detection"]
        self.assertGreater(row["evidence_count"], 25)
        self.assertEqual(len(row["included_event_ids"].split(",")), 25)
        self.assertEqual(row["evidence_complete"], 0)

    def test_bounded_signal_sweep_does_not_starve_new_cases(self):
        evidence = list(self.case.events.all())
        bindings = [(e.event_id, e.digest, e.source) for e in evidence]
        source = engine_source_state()
        for index in range(26):
            case = Investigation.objects.create(
                integration=self.app,
                rule="R1",
                correlation=f"{index:064x}",
                title="Modeled sweep fixture",
                severity="medium",
                explanation="Not independent detection evidence",
            )
            case.events.add(*evidence)
            Audit.objects.create(
                integration=self.app,
                action="case.created",
                object_id=str(case.pk),
                detail={"generation": generation_record(case, bindings, source, source)},
            )
        first = stage_signals(self.app)
        publish_signals(self.app)
        second = stage_signals(self.app)
        publish_signals(self.app)
        self.assertEqual(first.record_count + second.record_count, 27)
        self.assertEqual(ForwardedDetection.objects.count(), 27)

    def test_actual_memory_R3_is_forwarded_as_core_detection_not_native_rediscovery(self):
        other = Integration.objects.create(slug="expenses", name="Synthetic expenses")
        removal = observation(
            100,
            self.base - timedelta(seconds=100),
            app="expenses",
            environment="lab",
            actor="b" * 64,
            resource="f" * 64,
            schema_version=2,
            operation="membership.change",
            outcome="allowed",
            reason="membership_removed",
            membership={"subject": "a" * 64, "state": "removed"},
        )
        read = observation(
            101,
            self.base - timedelta(seconds=100),
            app="expenses",
            environment="lab",
            resource="f" * 64,
            outcome="allowed",
            reason="member",
        )
        Event.objects.bulk_create(rows(other, [removal, read], source="instrumented_lab"))
        drain(limit=10, worker_id="modeled-r3-proof")
        batch = stage_signals(other)
        publish_signals(other)
        signal = ForwardedDetection.objects.get(batch=batch)
        self.assertEqual(signal.packet["signalbridge_detection"]["rule_id"], "R3")
        self.assertEqual(expected_rule(signal.packet), ("100222", 10))
        obs = stage(other)
        publish(other)
        allowed = next(
            json.loads(line)
            for line in obs.body.splitlines()
            if json.loads(line)["signalbridge"]["outcome"] == "allowed"
            and json.loads(line)["signalbridge"]["operation"] == "private_record.read"
        )
        self.assertIsNone(expected_rule(allowed))
