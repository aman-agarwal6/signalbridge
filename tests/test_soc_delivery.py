"""Synthetic local-outbox checks; files and the Django database are disposable."""

import hashlib
import json
import shutil
import threading
import uuid
from datetime import timedelta
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, OperationalError, connections, transaction
from django.db.models.deletion import ProtectedError
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from bridge import soc_delivery
from bridge.contract import canonical
from bridge.models import Audit, Event, Integration, Membership, SocBatch, SocDelivery, SocStream


def disposable_root(test):
    # Normal mkdir avoids Python 3.13+ Windows tempfile ACLs excluding the
    # sandbox identity. Only synthetic files enter this unique ignored directory.
    parent = Path(__file__).resolve().parents[1] / "artifacts" / "local"
    parent.mkdir(parents=True, exist_ok=True)
    root = parent / f"soc-test-{uuid.uuid4().hex}"
    root.mkdir()
    if not root.resolve().is_relative_to(parent.resolve()) or root.is_symlink():
        raise AssertionError("Disposable test root escaped its parent")
    test.addCleanup(shutil.rmtree, root)
    settings = override_settings(BASE_DIR=root, LOCAL=True)
    settings.enable()
    test.addCleanup(settings.disable)
    return root


class SocDeliveryTests(TestCase):
    def setUp(self):
        self.root = disposable_root(self)
        self.app = Integration.objects.create(slug="bettail", name="Synthetic BetTail")
        self.other = Integration.objects.create(slug="netted", name="Synthetic Netted")

    def event(self, app=None, **changes):
        now = timezone.now()
        fields = {
            "integration": app or self.app,
            "event_id": uuid.uuid4(),
            "occurred_at": now,
            "actor": "a" * 64,
            "resource": "b" * 64,
            "episode": uuid.uuid4(),
            "operation": "private_record.read",
            "outcome": "denied",
            "reason": "membership_required",
            "environment": "test",
            "source": "synthetic_demo",
            "payload": {"private_fixture": "synthetic-only-private-content"},
            "digest": "c" * 64,
            "available_at": now,
            "state": "processed",
        }
        fields.update(changes)
        return Event.objects.create(**fields)

    def staged(self):
        self.event()
        batch = soc_delivery.stage(self.app)
        return batch, batch.stream, soc_delivery.collector_path(batch.stream)

    def assert_pending(self, batch, stream, *, offset=0, prefix=None):
        batch.refresh_from_db()
        stream.refresh_from_db()
        self.assertEqual(batch.state, "staged")
        self.assertIsNone(batch.appended_at)
        self.assertEqual(stream.offset, offset)
        if prefix is not None:
            self.assertEqual(stream.prefix_sha256, prefix)
        self.assertFalse(
            Audit.objects.filter(action="soc.delivery_appended", object_id=str(batch.pk)).exists()
        )

    def test_selection_is_bounded_and_deterministic_for_equal_timestamps(self):
        received = timezone.now() - timedelta(days=1)
        events = [self.event(id=uuid.UUID(int=index)) for index in range(105, 0, -1)]
        Event.objects.filter(pk__in=[event.pk for event in events]).update(received_at=received)
        pending = self.event(state="pending")
        dead = self.event(state="dead")
        other = self.event(self.other)

        first = soc_delivery.stage(self.app)
        ids = [json.loads(line)["signalbridge"]["event_id"] for line in first.body.splitlines()]
        expected = list(
            Event.objects.filter(integration=self.app, state="processed").order_by(
                "received_at", "id"
            )[:100]
        )
        self.assertEqual(ids, [str(event.event_id) for event in expected])
        self.assertEqual(first.record_count, 100)
        self.assertEqual(SocDelivery.objects.count(), 100)
        self.assertFalse(SocDelivery.objects.filter(event__in=[pending, dead, other]).exists())
        soc_delivery.publish(self.app)
        second = soc_delivery.stage(self.app)
        self.assertEqual(second.record_count, 5)
        self.assertEqual(SocDelivery.objects.count(), 105)

    def test_late_processing_is_selected_after_a_newer_event_was_published(self):
        old = self.event(state="pending")
        Event.objects.filter(pk=old.pk).update(received_at=timezone.now() - timedelta(days=2))
        recent = self.event()
        first = soc_delivery.stage(self.app)
        soc_delivery.publish(self.app)
        Event.objects.filter(pk=old.pk).update(state="processed")
        second = soc_delivery.stage(self.app)
        self.assertEqual(list(second.socdelivery_set.values_list("event_id", flat=True)), [old.pk])
        self.assertEqual(
            list(first.socdelivery_set.values_list("event_id", flat=True)), [recent.pk]
        )
        soc_delivery.publish(self.app)
        self.assertIsNone(soc_delivery.stage(self.app))
        self.assertEqual(SocDelivery.objects.count(), 2)

    def test_staging_and_publishing_are_idempotent(self):
        batch, stream, path = self.staged()
        self.assertFalse(path.exists())
        self.assertEqual(soc_delivery.stage(self.app).pk, batch.pk)
        self.assertEqual(Audit.objects.filter(action="soc.delivery_staged").count(), 1)
        published = soc_delivery.publish(self.app)
        self.assertEqual(published.pk, batch.pk)
        original = path.read_bytes()
        self.assertEqual(original, batch.body.encode("ascii"))
        self.assertIsNone(soc_delivery.publish(self.app))
        self.assertIsNone(soc_delivery.stage(self.app))
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(SocBatch.objects.count(), 1)
        self.assertEqual(SocDelivery.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="soc.delivery_appended").count(), 1)
        stream.refresh_from_db()
        self.assertEqual(stream.offset, len(original))
        self.assertEqual(stream.prefix_sha256, hashlib.sha256(original).hexdigest())

    def test_streams_files_status_and_audits_are_application_scoped(self):
        self.event()
        self.event(self.other)
        first = soc_delivery.stage(self.app)
        second = soc_delivery.stage(self.other)
        first_path = soc_delivery.collector_path(first.stream)
        second_path = soc_delivery.collector_path(second.stream)
        self.assertNotEqual(first_path, second_path)
        self.assertEqual(first_path.parent, self.root / "var" / "soc-delivery")
        soc_delivery.publish(self.app)
        self.assertFalse(second_path.exists())
        self.assertEqual(soc_delivery.status(self.app)["file_appended"], 1)
        self.assertEqual(soc_delivery.status(self.other)["file_appended"], 0)
        self.assertEqual(soc_delivery.status(self.other)["staged"], 1)
        self.assertIsNone(soc_delivery.status(self.app)["manager_observed"])
        self.assertEqual(json.loads(first.body)["signalbridge"]["app"], "bettail")
        self.assertEqual(json.loads(second.body)["signalbridge"]["app"], "netted")
        self.assertFalse(
            Audit.objects.filter(integration=self.other, action="soc.delivery_appended").exists()
        )

    def test_export_is_closed_and_never_copies_payload_or_identifiers(self):
        event = self.event(error_code="synthetic-private-error")
        batch = soc_delivery.stage(self.app)
        envelope = json.loads(batch.body)
        self.assertEqual(set(envelope), {"signalbridge"})
        self.assertEqual(
            set(envelope["signalbridge"]),
            {
                "export_version",
                "app",
                "environment",
                "event_id",
                "occurred_at",
                "operation",
                "outcome",
                "reason",
                "source",
            },
        )
        for value in (
            event.actor,
            event.resource,
            str(event.episode),
            event.digest,
            "synthetic-only-private-content",
            "synthetic-private-error",
        ):
            self.assertNotIn(value, batch.body)
        self.assertEqual(batch.body.encode("ascii"), canonical(envelope) + b"\n")
        self.assertEqual(batch.body_sha256, hashlib.sha256(batch.body.encode("ascii")).hexdigest())

    def test_invalid_export_values_roll_back_entire_staging_operation(self):
        event = self.event()
        for field, value in (
            ("operation", "unknown.operation"),
            ("outcome", "not-a-valid-outcome"),
            ("reason", "not-a-valid-reason"),
            ("environment", "production"),
            ("source", "private-source"),
        ):
            with self.subTest(field=field):
                original = getattr(event, field)
                Event.objects.filter(pk=event.pk).update(**{field: value})
                with self.assertRaisesRegex(soc_delivery.DeliveryError, "invalid_export_record"):
                    soc_delivery.stage(self.app)
                self.assertEqual(SocStream.objects.count(), 0)
                self.assertEqual(SocBatch.objects.count(), 0)
                self.assertEqual(SocDelivery.objects.count(), 0)
                self.assertEqual(Audit.objects.count(), 0)
                Event.objects.filter(pk=event.pk).update(**{field: original})

    def test_event_scope_mismatch_is_rejected(self):
        event = self.event(self.other)
        with self.assertRaisesRegex(soc_delivery.DeliveryError, "event_scope_mismatch"):
            soc_delivery.event_row(event, self.app)

    def test_disabled_app_is_rechecked_from_database(self):
        self.event()
        Integration.objects.filter(pk=self.app.pk).update(enabled=False)
        self.assertTrue(self.app.enabled)
        for operation in (soc_delivery.stage, soc_delivery.publish):
            with self.subTest(operation=operation.__name__):
                with self.assertRaisesRegex(soc_delivery.DeliveryError, "app_disabled"):
                    operation(self.app)
        self.assertEqual(SocStream.objects.count(), 0)
        self.assertFalse((self.root / "var").exists())

    def test_nonlocal_and_unsupported_apps_cannot_mutate_outbox(self):
        self.event()
        with override_settings(LOCAL=False):
            for operation in (soc_delivery.stage, soc_delivery.publish):
                with self.assertRaisesRegex(soc_delivery.DeliveryError, "local_only"):
                    operation(self.app)
        unsupported = Integration.objects.create(slug="signalbridge", name="Synthetic scope")
        for operation in (soc_delivery.stage, soc_delivery.publish):
            with self.assertRaisesRegex(soc_delivery.DeliveryError, "unsupported_app"):
                operation(unsupported)
        self.assertEqual(SocStream.objects.count(), 0)
        self.assertFalse((self.root / "var").exists())

    def test_empty_stage_creates_no_batch_delivery_audit_or_file(self):
        self.assertIsNone(soc_delivery.stage(self.app))
        self.assertIsNone(soc_delivery.publish(self.app))
        self.assertEqual(SocBatch.objects.count(), 0)
        self.assertEqual(SocDelivery.objects.count(), 0)
        self.assertEqual(Audit.objects.count(), 0)
        self.assertFalse((self.root / "var").exists())
        self.assertEqual(soc_delivery.status(self.app)["eligible"], 0)

    def test_publish_without_staging_fails_without_file_write(self):
        with self.assertRaisesRegex(soc_delivery.DeliveryError, "stream_not_staged"):
            soc_delivery.publish(self.app)
        self.assertFalse((self.root / "var").exists())

    def test_partial_write_recovers_exactly_once(self):
        batch, stream, path = self.staged()
        body = batch.body.encode("ascii")
        prefix = body[: len(body) // 2]
        path.write_bytes(prefix)
        soc_delivery.publish(self.app)
        self.assertEqual(path.read_bytes(), body)
        self.assertIsNone(soc_delivery.publish(self.app))
        self.assertEqual(path.read_bytes(), body)
        audit = Audit.objects.get(action="soc.delivery_appended")
        self.assertEqual(audit.detail["recovered_bytes"], len(prefix))
        self.assertIs(audit.detail["manager_observed"], False)
        stream.refresh_from_db()
        self.assertEqual(stream.offset, len(body))

    def test_full_file_before_database_commit_recovers_without_reappend(self):
        batch, stream, path = self.staged()
        body = batch.body.encode("ascii")
        path.write_bytes(body)
        with patch("bridge.soc_delivery.os.fsync") as fsync:
            soc_delivery.publish(self.app)
        fsync.assert_called_once()
        self.assertEqual(path.read_bytes(), body)
        self.assertEqual(
            Audit.objects.get(action="soc.delivery_appended").detail["recovered_bytes"], len(body)
        )
        stream.refresh_from_db()
        self.assertEqual(stream.offset, len(body))

    def test_fsync_failure_preserves_staged_ledger_and_retry_recovers(self):
        batch, stream, path = self.staged()
        with patch("bridge.soc_delivery.os.fsync", side_effect=OSError("synthetic fsync failure")):
            with self.assertRaises(OSError):
                soc_delivery.publish(self.app)
        self.assert_pending(batch, stream, prefix=hashlib.sha256(b"").hexdigest())
        self.assertEqual(path.read_bytes(), batch.body.encode("ascii"))
        soc_delivery.publish(self.app)
        self.assertEqual(path.read_bytes(), batch.body.encode("ascii"))
        self.assertEqual(SocDelivery.objects.count(), 1)

    def test_staging_audit_failure_rolls_back_all_ledger_state(self):
        self.event()
        with patch(
            "bridge.soc_delivery.Audit.objects.create",
            side_effect=RuntimeError("synthetic audit failure"),
        ):
            with self.assertRaises(RuntimeError):
                soc_delivery.stage(self.app)
        self.assertEqual(SocStream.objects.count(), 0)
        self.assertEqual(SocBatch.objects.count(), 0)
        self.assertEqual(SocDelivery.objects.count(), 0)
        self.assertEqual(soc_delivery.status(self.app)["eligible"], 1)
        self.assertFalse((self.root / "var").exists())

    def test_publish_audit_failure_keeps_recoverable_bytes_and_rolls_back_ack(self):
        batch, stream, path = self.staged()
        with patch(
            "bridge.soc_delivery.Audit.objects.create",
            side_effect=RuntimeError("synthetic audit failure"),
        ):
            with self.assertRaises(RuntimeError):
                soc_delivery.publish(self.app)
        self.assert_pending(batch, stream)
        self.assertEqual(path.read_bytes(), batch.body.encode("ascii"))
        soc_delivery.publish(self.app)
        self.assertEqual(path.read_bytes(), batch.body.encode("ascii"))
        self.assertEqual(Audit.objects.filter(action="soc.delivery_appended").count(), 1)

    def test_committed_prefix_change_or_truncation_never_advances(self):
        first, stream, path = self.staged()
        soc_delivery.publish(self.app)
        committed = path.read_bytes()
        self.event()
        second = soc_delivery.stage(self.app)
        for changed, code in (
            (b"X" + committed[1:], "collector_prefix_changed"),
            (committed[:-1], "collector_truncated"),
        ):
            with self.subTest(code=code):
                path.write_bytes(changed)
                with self.assertRaisesRegex(soc_delivery.DeliveryError, code):
                    soc_delivery.publish(self.app)
                self.assertEqual(path.read_bytes(), changed)
                self.assert_pending(
                    second,
                    stream,
                    offset=len(committed),
                    prefix=hashlib.sha256(committed).hexdigest(),
                )
        path.write_bytes(committed)
        soc_delivery.publish(self.app)
        self.assertEqual(path.read_bytes(), committed + second.body.encode("ascii"))
        first.refresh_from_db()
        self.assertEqual(first.state, "file_appended")

    def test_unrecognized_or_overlong_tail_fails_without_overwriting(self):
        batch, stream, path = self.staged()
        body = batch.body.encode("ascii")
        for bad in (b"unrecognized-tail", body + b"extra", b"X" + body[1:]):
            with self.subTest(size=len(bad)):
                path.write_bytes(bad)
                with self.assertRaisesRegex(soc_delivery.DeliveryError, "collector_tail_conflict"):
                    soc_delivery.publish(self.app)
                self.assertEqual(path.read_bytes(), bad)
                self.assert_pending(batch, stream)

    def test_missing_previously_acknowledged_collector_fails_closed(self):
        first, stream, path = self.staged()
        soc_delivery.publish(self.app)
        prior = path.read_bytes()
        path.unlink()
        self.event()
        second = soc_delivery.stage(self.app)
        with self.assertRaisesRegex(soc_delivery.DeliveryError, "collector_missing"):
            soc_delivery.publish(self.app)
        self.assertFalse(path.exists())
        self.assert_pending(second, stream, offset=len(prior))
        first.refresh_from_db()
        self.assertEqual(first.state, "file_appended")

    def test_staged_digest_or_offset_tampering_is_rejected_before_file_write(self):
        batch, stream, path = self.staged()
        SocBatch.objects.filter(pk=batch.pk).update(body_sha256="0" * 64)
        with self.assertRaisesRegex(soc_delivery.DeliveryError, "staged_digest_mismatch"):
            soc_delivery.publish(self.app)
        self.assertFalse(path.exists())
        self.assert_pending(batch, stream)
        SocBatch.objects.filter(pk=batch.pk).update(
            body_sha256=hashlib.sha256(batch.body.encode("ascii")).hexdigest(),
            start_offset=1,
        )
        with self.assertRaisesRegex(soc_delivery.DeliveryError, "staged_offset_mismatch"):
            soc_delivery.publish(self.app)
        self.assertFalse(path.exists())
        self.assert_pending(batch, stream)

    def test_closed_staged_schema_is_revalidated_even_with_matching_digest(self):
        batch, stream, path = self.staged()
        row = json.loads(batch.body)
        row["signalbridge"]["private_extra"] = "synthetic-private-value"
        changed = canonical(row) + b"\n"
        SocBatch.objects.filter(pk=batch.pk).update(
            body=changed.decode("ascii"), body_sha256=hashlib.sha256(changed).hexdigest()
        )
        with self.assertRaisesRegex(soc_delivery.DeliveryError, "invalid_staged_record"):
            soc_delivery.publish(self.app)
        self.assertFalse(path.exists())
        self.assert_pending(batch, stream)

    def test_cross_app_staged_body_is_rejected_even_with_matching_digest(self):
        batch, stream, path = self.staged()
        row = json.loads(batch.body)
        row["signalbridge"]["app"] = "netted"
        changed = canonical(row) + b"\n"
        SocBatch.objects.filter(pk=batch.pk).update(
            body=changed.decode("ascii"), body_sha256=hashlib.sha256(changed).hexdigest()
        )
        with self.assertRaises(soc_delivery.DeliveryError):
            soc_delivery.publish(self.app)
        self.assertFalse(path.exists())
        self.assert_pending(batch, stream)

    def test_missing_event_ledger_binding_is_rejected(self):
        batch, stream, path = self.staged()
        SocDelivery.objects.filter(batch=batch).delete()
        with self.assertRaisesRegex(soc_delivery.DeliveryError, "staged_ledger_mismatch"):
            soc_delivery.publish(self.app)
        self.assertFalse(path.exists())
        self.assert_pending(batch, stream)

    def test_extra_cross_app_ledger_link_is_not_hidden_by_scope_filter(self):
        batch, stream, path = self.staged()
        SocDelivery.objects.create(event=self.event(self.other), batch=batch)
        with self.assertRaisesRegex(soc_delivery.DeliveryError, "staged_ledger_mismatch"):
            soc_delivery.publish(self.app)
        self.assertFalse(path.exists())
        self.assert_pending(batch, stream)

    def test_foreign_app_ledger_replacement_is_rejected(self):
        batch, stream, path = self.staged()
        own = SocDelivery.objects.get(batch=batch).event
        foreign = self.event(self.other, event_id=own.event_id)
        SocDelivery.objects.filter(batch=batch).update(event=foreign)
        with self.assertRaisesRegex(soc_delivery.DeliveryError, "staged_ledger_scope_mismatch"):
            soc_delivery.publish(self.app)
        self.assertFalse(path.exists())
        self.assert_pending(batch, stream)

    def test_unsafe_file_type_is_bounded_command_error_and_keeps_ledger(self):
        batch, stream, path = self.staged()
        path.mkdir()
        with self.assertRaisesRegex(CommandError, "unsafe_collector_path"):
            call_command("soc_delivery", "bettail", "publish", stdout=StringIO())
        self.assertTrue(path.is_dir())
        self.assert_pending(batch, stream)

    def test_stream_capacity_checks_stage_and_publish_without_acknowledgement(self):
        self.event()
        with patch("bridge.soc_delivery.MAX_STREAM_BYTES", 1):
            with self.assertRaisesRegex(soc_delivery.DeliveryError, "stream_capacity_reached"):
                soc_delivery.stage(self.app)
        self.assertEqual(SocStream.objects.count(), 0)
        self.assertEqual(SocDelivery.objects.count(), 0)
        batch = soc_delivery.stage(self.app)
        stream = batch.stream
        path = soc_delivery.collector_path(stream)
        body = batch.body.encode("ascii")
        with patch("bridge.soc_delivery.MAX_STREAM_BYTES", len(body) - 1):
            with self.assertRaisesRegex(soc_delivery.DeliveryError, "stream_capacity_reached"):
                soc_delivery.publish(self.app)
        self.assertFalse(path.exists())
        self.assert_pending(batch, stream)
        with patch("bridge.soc_delivery.MAX_STREAM_BYTES", len(body)):
            soc_delivery.publish(self.app)
            self.event()
            with self.assertRaisesRegex(soc_delivery.DeliveryError, "stream_capacity_reached"):
                soc_delivery.stage(self.app)
        self.assertEqual(path.read_bytes(), body)
        self.assertEqual(SocDelivery.objects.count(), 1)

    def test_batch_capacity_failure_does_not_claim_events(self):
        self.event()
        with patch("bridge.soc_delivery.MAX_BATCH_BYTES", 1):
            with self.assertRaisesRegex(soc_delivery.DeliveryError, "batch_capacity_reached"):
                soc_delivery.stage(self.app)
        self.assertEqual(SocBatch.objects.count(), 0)
        self.assertEqual(SocDelivery.objects.count(), 0)
        self.assertEqual(Audit.objects.count(), 0)

    def test_over_capacity_file_is_preserved_and_not_acknowledged(self):
        batch, stream, path = self.staged()
        body = batch.body.encode("ascii")
        bad = body + b"extra"
        path.write_bytes(bad)
        with patch("bridge.soc_delivery.MAX_STREAM_BYTES", len(body)):
            with self.assertRaisesRegex(soc_delivery.DeliveryError, "collector_capacity_reached"):
                soc_delivery.publish(self.app)
        self.assertEqual(path.read_bytes(), bad)
        self.assert_pending(batch, stream)

    def test_retention_preserves_staged_and_appended_delivery_evidence(self):
        appended = self.event()
        soc_delivery.stage(self.app)
        soc_delivery.publish(self.app)
        staged = self.event()
        soc_delivery.stage(self.app)
        eligible = self.event()
        pending = self.event(state="pending")
        dead = self.event(state="dead")
        other = self.event(self.other)
        Event.objects.update(received_at=timezone.now() - timedelta(days=100))
        preview = StringIO()
        call_command("retention", "bettail", stdout=preview)
        self.assertIn("Would remove 1", preview.getvalue())
        self.assertEqual(Event.objects.count(), 6)
        call_command("retention", "bettail", apply=True, stdout=StringIO())
        self.assertFalse(Event.objects.filter(pk=eligible.pk).exists())
        self.assertEqual(
            set(Event.objects.values_list("pk", flat=True)),
            {event.pk for event in (appended, staged, pending, dead, other)},
        )
        self.assertEqual(SocDelivery.objects.count(), 2)
        self.assertEqual(SocBatch.objects.count(), 2)
        self.assertEqual(
            Audit.objects.get(action="retention.applied").detail["unlinked_events_deleted"], 1
        )

    def test_database_prevents_duplicate_stream_pending_batch_and_delivery(self):
        batch, stream, _ = self.staged()
        event = SocDelivery.objects.get(batch=batch).event
        for model, fields in (
            (SocStream, {"integration": self.app}),
            (
                SocBatch,
                {
                    "stream": stream,
                    "body": batch.body,
                    "body_sha256": batch.body_sha256,
                    "start_offset": 0,
                    "record_count": 1,
                },
            ),
            (SocDelivery, {"event": event, "batch": batch}),
        ):
            with self.subTest(model=model.__name__):
                with self.assertRaises(IntegrityError), transaction.atomic():
                    model.objects.create(**fields)
        self.assertEqual(SocStream.objects.count(), 1)
        self.assertEqual(SocBatch.objects.count(), 1)
        self.assertEqual(SocDelivery.objects.count(), 1)

    def test_database_rejects_unrecognized_acknowledgement_state(self):
        batch, _, _ = self.staged()
        with self.assertRaises(IntegrityError), transaction.atomic():
            SocBatch.objects.filter(pk=batch.pk).update(state="manager_received")
        batch.refresh_from_db()
        self.assertEqual(batch.state, "staged")

    def test_delivery_links_prevent_cascade_deletion_of_evidence(self):
        batch, stream, _ = self.staged()
        event = SocDelivery.objects.get(batch=batch).event
        for record in (event, batch, stream, self.app):
            with self.subTest(record=type(record).__name__):
                with self.assertRaises(ProtectedError):
                    record.delete()
        self.assertEqual(SocDelivery.objects.count(), 1)

    def test_command_once_is_bounded_idempotent_and_disclaims_manager_receipt(self):
        self.event()
        output = StringIO()
        call_command("soc_delivery", "bettail", "once", stdout=output)
        lines = output.getvalue().splitlines()
        summary = json.loads(lines[0])
        self.assertEqual(summary["file_appended"], 1)
        self.assertEqual(summary["staged"], 0)
        self.assertIsNone(summary["manager_observed"])
        self.assertIn("Wazuh receipt has not been established", lines[1])
        call_command("soc_delivery", "bettail", "once", stdout=StringIO())
        self.assertEqual(SocBatch.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="soc.delivery_appended").count(), 1)

    def test_command_error_is_bounded_and_preserves_recoverable_state(self):
        batch, stream, path = self.staged()
        with patch("bridge.soc_delivery.os.fsync", side_effect=OSError("synthetic-private-error")):
            with self.assertRaises(CommandError) as error:
                call_command("soc_delivery", "bettail", "publish", stdout=StringIO())
        self.assertIn("preserve the ledger and file", str(error.exception))
        self.assertNotIn("synthetic-private-error", str(error.exception))
        self.assert_pending(batch, stream)
        self.assertEqual(path.read_bytes(), batch.body.encode("ascii"))

    def test_status_command_reads_metadata_without_creating_files(self):
        self.event()
        output = StringIO()
        call_command("soc_delivery", "bettail", "status", stdout=output)
        summary = json.loads(output.getvalue().splitlines()[0])
        self.assertEqual(summary["eligible"], 1)
        self.assertEqual(summary["bytes"], 0)
        self.assertIsNone(summary["stream_id"])
        self.assertEqual(SocStream.objects.count(), 0)
        self.assertFalse((self.root / "var").exists())

    def test_every_command_action_requires_local_mode_before_querying_database(self):
        with override_settings(LOCAL=False):
            for action in ("status", "stage", "publish", "once"):
                with self.subTest(action=action):
                    with self.assertNumQueries(0):
                        with self.assertRaises(CommandError):
                            call_command("soc_delivery", "bettail", action, stdout=StringIO())
        self.assertFalse((self.root / "var").exists())

    def test_console_scopes_delivery_counts_and_cannot_imply_manager_receipt(self):
        viewer = get_user_model().objects.create_user(username="synthetic-delivery-viewer")
        Membership.objects.create(user=viewer, integration=self.app, role="viewer")
        self.event()
        self.event(self.other)
        self.event(self.other)
        soc_delivery.stage(self.app)
        soc_delivery.publish(self.app)
        soc_delivery.stage(self.other)
        self.client.force_login(viewer)
        with patch(
            "bridge.soc_delivery.collector_path",
            side_effect=AssertionError("UI must not inspect collector"),
        ):
            response = self.client.get("/integrations/?app=bettail")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["delivery"]["file_appended"], 1)
        self.assertEqual(response.context["delivery"]["staged"], 0)
        self.assertIsNone(response.context["delivery"]["manager_observed"])
        self.assertContains(response, "Local acknowledgement, not Wazuh ingestion")
        self.assertContains(response, "opening this page does not inspect the file or the manager")
        self.assertEqual(self.client.get("/integrations/?app=netted").status_code, 404)

    def test_anonymous_console_request_cannot_read_delivery_ledger(self):
        self.event()
        soc_delivery.stage(self.app)
        response = self.client.get("/integrations/?app=bettail")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith("/login/"))

    def test_signalbridge_console_does_not_inherit_source_app_delivery(self):
        lab = Integration.objects.create(slug="signalbridge", name="Synthetic lab")
        viewer = get_user_model().objects.create_user(username="synthetic-lab-viewer")
        Membership.objects.create(user=viewer, integration=lab, role="viewer")
        self.event()
        soc_delivery.stage(self.app)
        self.client.force_login(viewer)
        response = self.client.get("/integrations/?app=signalbridge")
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.context["delivery"])
        self.assertNotContains(response, "FILE APPEND CONFIRMED")


class SocDeliveryTransactionTests(TransactionTestCase):
    """Real transaction boundaries and cooperating threads on Django's test DB."""

    def setUp(self):
        self.root = disposable_root(self)
        self.app = Integration.objects.create(slug="bettail", name="Synthetic BetTail")
        now = timezone.now()
        Event.objects.create(
            integration=self.app,
            event_id=uuid.uuid4(),
            occurred_at=now,
            actor="a" * 64,
            resource="b" * 64,
            episode=uuid.uuid4(),
            operation="private_record.read",
            outcome="denied",
            reason="membership_required",
            environment="test",
            source="synthetic_demo",
            payload={},
            digest="c" * 64,
            available_at=now,
            state="processed",
        )

    def test_staging_rejects_outer_transaction_before_creating_recovery_intent(self):
        with transaction.atomic():
            with self.assertRaisesRegex(RuntimeError, "durable atomic block"):
                soc_delivery.stage(self.app)
        self.assertEqual(SocStream.objects.count(), 0)
        self.assertEqual(SocBatch.objects.count(), 0)
        self.assertEqual(SocDelivery.objects.count(), 0)
        self.assertFalse((self.root / "var").exists())

    def test_publishing_rejects_outer_transaction_before_writing_file(self):
        batch = soc_delivery.stage(self.app)
        path = soc_delivery.collector_path(batch.stream)
        with transaction.atomic():
            with self.assertRaisesRegex(RuntimeError, "durable atomic block"):
                soc_delivery.publish(self.app)
        self.assertFalse(path.exists())
        batch.refresh_from_db()
        self.assertEqual(batch.state, "staged")
        self.assertEqual(batch.stream.offset, 0)
        self.assertEqual(SocDelivery.objects.count(), 1)
        self.assertFalse(Audit.objects.filter(action="soc.delivery_appended").exists())

    def test_two_publishers_append_once_and_lock_contention_is_retryable(self):
        batch = soc_delivery.stage(self.app)
        barrier = threading.Barrier(2)
        outcomes = []
        lock = threading.Lock()

        def worker():
            # Each thread obtains its own ORM connection to the disposable DB.
            try:
                barrier.wait(timeout=5)
                result = soc_delivery.publish(self.app)
                outcome = ("ok", str(result.pk) if result is not None else None)
            except OperationalError as error:
                outcome = ("locked" if "locked" in str(error).lower() else "error", str(error))
            except Exception as error:
                outcome = ("error", f"{type(error).__name__}: {error}")
            finally:
                connections.close_all()
            with lock:
                outcomes.append(outcome)

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads), "Publisher thread timed out")
        self.assertEqual(len(outcomes), 2)
        self.assertFalse([outcome for outcome in outcomes if outcome[0] == "error"], outcomes)
        # Shared-cache SQLite can reject both contenders while each holds a
        # conflicting read lock. Only recognized lock contention is retryable;
        # the serial retry below must still produce exactly one acknowledgement.
        soc_delivery.publish(self.app)
        batch.refresh_from_db()
        stream = SocStream.objects.get(integration=self.app)
        body = batch.body.encode("ascii")
        self.assertEqual(soc_delivery.collector_path(stream).read_bytes(), body)
        self.assertEqual(stream.offset, len(body))
        self.assertEqual(stream.prefix_sha256, hashlib.sha256(body).hexdigest())
        self.assertEqual(SocBatch.objects.filter(state="file_appended").count(), 1)
        self.assertEqual(SocDelivery.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="soc.delivery_appended").count(), 1)
