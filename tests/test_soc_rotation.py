"""Real disposable SQL/file export recovery; reduced bounds, no Wazuh process."""

import hashlib
import json
import os
import uuid
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, transaction
from django.test import TestCase, override_settings
from django.utils import timezone

from bridge.contract import canonical
from bridge.models import (
    Audit,
    Event,
    Integration,
    Membership,
    SocBatch,
    SocDelivery,
    SocSegment,
    SocStream,
    WazuhCursor,
    WazuhRecord,
)
from bridge.soc_delivery import DeliveryError, collector_path, publish, stage, status
from bridge.soc_rotation import export_inventory, segment_path
from bridge.wazuh_enterprise import publish_signals, stage_signals
from bridge.wazuh_import import import_segment
from bridge.worker import drain
from integrations.wazuh_enterprise.contract import (
    EnterpriseWazuhError,
    segmented_location,
)
from tests.test_processing_efficiency import observation, rows
from tests.test_soc_delivery import disposable_root


@override_settings(SOC_SEGMENTED_EXPORT=True)
class SocRotationTests(TestCase):
    def setUp(self):
        self.root = disposable_root(self)
        self.app = Integration.objects.create(slug="documents", name="Synthetic documents")
        self.base = timezone.now() - timedelta(minutes=1)
        self.counter = 0
        self.run = str(uuid.uuid4())

    def event(self, app=None, *, processed=True):
        app = app or self.app
        value = observation(self.counter, self.base, app=app.slug, environment="lab")
        self.counter += 1
        row = rows(app, [value], source="instrumented_lab")[0]
        row.state = "processed" if processed else "pending"
        row.save()
        return row

    def staged(self):
        self.event()
        return stage(self.app)

    def append(self):
        batch = self.staged()
        publish(self.app)
        batch.refresh_from_db()
        return batch

    def assert_pending(self, batch, offset=0):
        batch.refresh_from_db()
        batch.stream.refresh_from_db()
        batch.segment.refresh_from_db()
        self.assertEqual(batch.state, "staged")
        self.assertIsNone(batch.appended_at)
        self.assertEqual(batch.stream.offset, offset)
        self.assertFalse(
            Audit.objects.filter(action="soc.delivery_appended", object_id=str(batch.pk))
        )

    def native(self, batch, *, location=None, index=1):
        packet = json.loads(batch.body.splitlines()[0])
        return {
            "timestamp": timezone.now().isoformat(),
            "agent": {"id": "000", "name": "synthetic-manager"},
            "manager": {"name": "synthetic-manager"},
            "id": f"1700000000.{index}",
            "decoder": {"name": "json"},
            "location": location
            or segmented_location("documents", "observation", batch.segment.number),
            "data": {key: {k: str(v) for k, v in row.items()} for key, row in packet.items()},
            "full_log": canonical(packet).decode(),
        }

    def import_values(self, values):
        parent = self.root / "var/wazuh-enterprise" / self.run / "documents"
        parent.mkdir(parents=True, exist_ok=True)
        (parent / "archives-000.jsonl").write_bytes(b"".join(canonical(v) + b"\n" for v in values))
        return import_segment(self.app, self.run, "archive", 0)

    def test_fresh_opt_in_records_scoped_bytes_and_preserves_whole_stream_digest(self):
        batch = self.append()
        stream = SocStream.objects.get()
        segment = SocSegment.objects.get()
        self.assertTrue(stream.segmented_export)
        self.assertEqual(segment.byte_count, len(batch.body))
        self.assertEqual(segment_path(segment).read_bytes(), batch.body.encode())
        self.assertEqual(stream.prefix_sha256, hashlib.sha256(batch.body.encode()).hexdigest())
        inventory = export_inventory(stream)
        self.assertFalse(inventory["native_observed"])
        self.assertFalse(inventory["files_inspected"])
        self.assertIsNone(status(self.app)["manager_observed"])
        with self.assertRaises(DeliveryError):
            collector_path(stream)

    def test_default_legacy_layout_and_existing_metadata_are_preserved(self):
        with override_settings(SOC_SEGMENTED_EXPORT=False):
            batch = self.append()
            self.assertIsNone(batch.segment)
            self.assertEqual(collector_path(batch.stream).read_bytes(), batch.body.encode())
        old = collector_path(batch.stream).read_bytes()
        self.event()
        with self.assertRaisesMessage(DeliveryError, "segmentation_requires_fresh_stream"):
            stage(self.app)
        self.assertEqual(collector_path(batch.stream).read_bytes(), old)
        self.assertFalse(SocSegment.objects.exists())
        self.assertEqual(status(self.app)["eligible"], 1)

    def test_mode_persists_when_setting_is_disabled_and_pending_stage_is_idempotent(self):
        batch = self.staged()
        self.assertEqual(stage(self.app).pk, batch.pk)
        with override_settings(SOC_SEGMENTED_EXPORT=False):
            publish(self.app)
            second = self.append()
        self.assertEqual(second.segment_id, batch.segment_id)
        self.assertEqual(SocBatch.objects.count(), 2)

    def test_rotation_retains_ordered_hashes_sealing_and_unobserved_status(self):
        first = self.staged()
        with patch("bridge.soc_rotation.SEGMENT_BYTES", len(first.body) * 2):
            publish(self.app)
            second, third = self.append(), self.append()
            segments = list(SocSegment.objects.order_by("number"))
            self.assertEqual(len(segments), 2)
            self.assertIsNotNone(segments[0].sealed_at)
            self.assertIsNone(segments[1].sealed_at)
            self.assertEqual(second.segment_id, first.segment_id)
            self.assertEqual(third.segment_id, segments[1].pk)
            raw = b"".join(segment_path(s).read_bytes() for s in segments)
            stream = SocStream.objects.get()
            self.assertEqual(stream.prefix_sha256, hashlib.sha256(raw).hexdigest())
            self.assertEqual(segments[1].start_offset, len(first.body) + len(second.body))
            self.assertEqual(stream.offset, len(raw))
            self.assertEqual(status(self.app)["rotation"]["remaining_segments"], 6)
            self.assertEqual(Audit.objects.filter(action="soc.segment_sealed").count(), 1)

    def test_partial_and_complete_pending_tails_resume_without_duplicate_bytes(self):
        for size in (19, None):
            with self.subTest(size=size):
                batch = self.staged()
                path = segment_path(batch.segment)
                committed = path.read_bytes() if path.exists() else b""
                tail = batch.body.encode()[:size]
                path.write_bytes(committed + tail)
                publish(self.app)
                self.assertEqual(path.read_bytes(), committed + batch.body.encode())
                audit = Audit.objects.get(action="soc.delivery_appended", object_id=str(batch.pk))
                self.assertEqual(audit.detail["recovered_bytes"], len(tail))
                self.assertIsNone(publish(self.app))

    def test_fsync_failure_retains_physical_bytes_and_rolls_back_sql_then_recovers(self):
        batch = self.staged()
        with patch(
            "bridge.soc_rotation.os.fsync", side_effect=OSError("modeled interrupted fsync")
        ):
            with self.assertRaises(OSError):
                publish(self.app)
        self.assert_pending(batch)
        self.assertEqual(batch.segment.byte_count, 0)
        self.assertEqual(segment_path(batch.segment).read_bytes(), batch.body.encode())
        publish(self.app)
        self.assertEqual(segment_path(batch.segment).read_bytes(), batch.body.encode())

    def test_unexplained_tail_is_rejected_without_truncating_or_consuming_batch(self):
        batch = self.staged()
        path = segment_path(batch.segment)
        path.write_bytes(b"unexpected synthetic bytes\n")
        with self.assertRaisesMessage(DeliveryError, "segment_tail_conflict"):
            publish(self.app)
        self.assert_pending(batch)
        self.assertEqual(path.read_bytes(), b"unexpected synthetic bytes\n")

    def test_active_prefix_and_missing_committed_file_are_rejected(self):
        first = self.append()
        second = self.staged()
        path = segment_path(first.segment)
        original = path.read_bytes()
        path.write_bytes(b"X" + original[1:])
        with self.assertRaisesMessage(DeliveryError, "segment_prefix_changed"):
            publish(self.app)
        self.assert_pending(second, offset=len(first.body))
        path.unlink()
        with self.assertRaisesMessage(DeliveryError, "segment_missing"):
            publish(self.app)
        self.assert_pending(second, offset=len(first.body))

    def test_sealed_file_tampering_stops_next_append_and_preserves_pending_work(self):
        first = self.staged()
        with patch("bridge.soc_rotation.SEGMENT_BYTES", len(first.body)):
            publish(self.app)
            second = self.staged()
            path = segment_path(first.segment)
            original = path.read_bytes()
            path.write_bytes(b"X" + original[1:])
            with self.assertRaisesMessage(DeliveryError, "sealed_segment_changed"):
                publish(self.app)
            self.assert_pending(second, offset=len(first.body))
            path.write_bytes(original)
            publish(self.app)
            self.assertEqual(SocSegment.objects.count(), 2)

    def test_eight_segment_capacity_stops_without_deleting_or_staging_ninth(self):
        first = self.staged()
        with patch("bridge.soc_rotation.SEGMENT_BYTES", len(first.body)):
            publish(self.app)
            for _ in range(7):
                self.append()
            before = {s.number: segment_path(s).read_bytes() for s in SocSegment.objects.all()}
            self.event()
            with self.assertRaisesMessage(DeliveryError, "segment_capacity_reached"):
                stage(self.app)
            self.assertEqual(SocSegment.objects.count(), 8)
            self.assertEqual(SocBatch.objects.count(), 8)
            self.assertEqual(status(self.app)["eligible"], 1)
            self.assertEqual(status(self.app)["rotation"]["remaining_segments"], 0)
            self.assertEqual(status(self.app)["rotation"]["active_remaining_bytes"], 0)
            self.assertEqual(
                before, {s.number: segment_path(s).read_bytes() for s in SocSegment.objects.all()}
            )

    def test_inconsistent_offsets_fail_closed_and_status_reports_metadata_error(self):
        batch = self.staged()
        SocSegment.objects.filter(pk=batch.segment_id).update(start_offset=1)
        with self.assertRaisesMessage(DeliveryError, "segment_offset_mismatch"):
            publish(self.app)
        self.assert_pending(batch)
        value = status(self.app)["rotation"]
        self.assertEqual(value["error"], "segment_offset_mismatch")
        self.assertFalse(value["files_inspected"])
        self.assertFalse(value["native_observed"])

    def test_cross_app_batch_segment_binding_is_rejected(self):
        batch = self.staged()
        other = Integration.objects.create(slug="expenses", name="Synthetic expenses")
        self.event(other)
        other_batch = stage(other)
        SocBatch.objects.filter(pk=batch.pk).update(segment=other_batch.segment)
        with self.assertRaisesMessage(DeliveryError, "batch_segment_scope_mismatch"):
            publish(self.app)
        self.assert_pending(batch)
        self.assertFalse(segment_path(batch.segment).exists())

    def test_database_limits_numbers_bytes_unique_segments_and_open_segment(self):
        batch = self.staged()
        for update in ({"number": 8}, {"number": -1}, {"byte_count": 2097153}):
            with (
                self.subTest(update=update),
                self.assertRaises(IntegrityError),
                transaction.atomic(),
            ):
                SocSegment.objects.filter(pk=batch.segment_id).update(**update)
        for number in (0, 1):
            with (
                self.subTest(number=number),
                self.assertRaises(IntegrityError),
                transaction.atomic(),
            ):
                SocSegment.objects.create(stream=batch.stream, number=number, start_offset=0)

    def test_hardlinked_output_is_rejected_before_write(self):
        batch = self.staged()
        path = segment_path(batch.segment)
        outside = self.root / "synthetic-retained-file"
        outside.write_bytes(b"synthetic evidence\n")
        os.link(outside, path)
        with self.assertRaises(DeliveryError):
            publish(self.app)
        self.assert_pending(batch)
        self.assertEqual(outside.read_bytes(), b"synthetic evidence\n")

    def test_legacy_v1_cannot_opt_in_and_cli_reports_controlled_error(self):
        app = Integration.objects.create(slug="bettail", name="Synthetic BetTail")
        self.event(app)
        Event.objects.filter(integration=app).update(source="synthetic_demo", environment="test")
        with self.assertRaises(CommandError):
            call_command("soc_delivery", "bettail", "once", stdout=StringIO())
        self.assertFalse(SocStream.objects.filter(integration=app).exists())
        self.assertFalse(SocDelivery.objects.filter(event__integration=app).exists())

    def test_core_signals_keep_separate_scoped_segment_and_origin(self):
        for _ in range(3):
            self.event(processed=False)
        drain(limit=10, worker_id="modeled-segment-signal")
        stage(self.app)
        publish(self.app)
        signal = stage_signals(self.app)
        publish_signals(self.app)
        self.assertEqual(signal.stream.channel, "detection")
        self.assertIn(b"signalbridge_detection", segment_path(signal.segment).read_bytes())
        self.assertNotIn(
            b"signalbridge_detection",
            segment_path(SocSegment.objects.get(stream__channel="observation")).read_bytes(),
        )
        self.assertEqual(
            json.loads(signal.body)["signalbridge_detection"]["origin"], "signalbridge"
        )

    def test_native_format_import_requires_exact_published_segment_not_another_allowed_path(self):
        first = self.staged()
        with patch("bridge.soc_rotation.SEGMENT_BYTES", len(first.body)):
            publish(self.app)
            second = self.append()
        for location in (
            segmented_location("documents", "observation", 0),
            segmented_location("expenses", "observation", 1),
            "/signalbridge/input/observations.jsonl",
        ):
            with self.subTest(location=location), self.assertRaises(EnterpriseWazuhError):
                self.import_values([self.native(second, location=location)])
            self.assertFalse(WazuhRecord.objects.exists())
            self.assertFalse(WazuhCursor.objects.exists())
        result = self.import_values([self.native(first), self.native(second, index=2)])
        self.assertEqual(result["new_records"], 2)
        self.assertFalse(result["native_runtime_verified"])

    def test_repeated_import_cannot_change_location_even_after_target_cache_hit(self):
        batch = self.append()
        first = self.native(batch)
        second = self.native(
            batch, location=segmented_location("documents", "observation", 1), index=2
        )
        with self.assertRaises(EnterpriseWazuhError):
            self.import_values([first, second])
        self.assertFalse(WazuhRecord.objects.exists())
        self.assertFalse(WazuhCursor.objects.exists())

    def test_console_explains_retention_and_does_not_claim_collector_health(self):
        self.append()
        user = get_user_model().objects.create_user(username="synthetic-segment-viewer")
        Membership.objects.create(user=user, integration=self.app, role="viewer")
        self.client.force_login(user)
        response = self.client.get("/integrations/?app=documents")
        self.assertContains(response, "Retained enterprise segments")
        self.assertContains(response, "Segments are retained and never overwritten automatically")
        self.assertContains(response, "Native connection unverified")
        self.assertContains(response, "not live file inspection or Wazuh receipt")
        self.assertNotContains(response, "synthetic-manager")

    def test_location_factory_has_closed_types_scope_and_bounds(self):
        for args in (
            ("../documents", "observation", 0),
            ("documents", "invalid", 0),
            ("documents", "observation", True),
            ("documents", "observation", 8),
            ([], "observation", 0),
        ):
            with self.subTest(args=args), self.assertRaises(EnterpriseWazuhError):
                segmented_location(*args)
