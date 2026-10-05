"""Disposable SQL/real file snapshot and config controls; no native manager."""

import copy
import hashlib
import json
import os
import uuid
import xml.etree.ElementTree as ET
from datetime import timedelta
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from bridge.contract import canonical
from bridge.models import Audit, Event, Integration, SocStream, WazuhRecord
from bridge.soc_delivery import DeliveryError, delivery_location, publish, stage
from bridge.soc_rotation import segment_path
from bridge.wazuh_collector_snapshot import capture_idle_exports
from bridge.wazuh_enterprise import publish_signals, stage_signals
from bridge.worker import drain
from integrations.wazuh_enterprise.collector_profile import (
    INTERNAL_OPTIONS,
    configuration,
    recipe,
    verify_configuration,
    verify_recipe,
)
from integrations.wazuh_enterprise.contract import EnterpriseWazuhError
from integrations.wazuh_enterprise.export_snapshot import inspect_exports, manifest
from tests.test_processing_efficiency import observation, rows
from tests.test_soc_delivery import disposable_root


class CollectorConfigurationTests(SimpleTestCase):
    def test_fixed_scopes_paths_disabled_modules_and_no_native_claim(self):
        raw = configuration()
        package = Path(__file__).resolve().parents[1] / "integrations/wazuh_enterprise"
        self.assertEqual((package / "manager-lab.conf").read_bytes(), raw)
        self.assertEqual((package / "local_internal_options.conf").read_bytes(), INTERNAL_OPTIONS)
        self.assertEqual(json.loads((package / "collector-stage-plan.json").read_bytes()), recipe())
        result = verify_configuration(raw, INTERNAL_OPTIONS)
        self.assertEqual(result["monitored_paths"], 32)
        self.assertFalse(result["native_execution_verified"])
        root = ET.fromstring(raw)
        paths = [node.findtext("location") for node in root.findall("localfile")]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertNotIn("bettail", " ".join(paths))
        self.assertNotIn("netted", " ".join(paths))
        for node in root.findall("localfile"):
            self.assertEqual(node.findtext("only-future-events"), "no")
            self.assertEqual(node.find("only-future-events").attrib, {"max-size": "16MB"})
        self.assertIn(b"logcollector.vcheck_files=1\n", INTERNAL_OPTIONS)

    def test_widened_collection_response_or_network_sections_are_rejected(self):
        for fragment in (
            "<localfile><location>/etc/passwd</location><log_format>syslog</log_format></localfile>",
            "<remote><connection>secure</connection></remote>",
            "<integration><name>custom-external-webhook</name></integration>",
            "<command><name>unexpected-command</name><executable>unexpected-file</executable></command>",
        ):
            changed = configuration().replace(
                b"</ossec_config>", fragment.encode() + b"</ossec_config>"
            )
            with self.subTest(fragment=fragment), self.assertRaises(EnterpriseWazuhError):
                verify_configuration(changed, INTERNAL_OPTIONS)

    def test_disabled_controls_recovery_archive_or_rules_cannot_be_weakened(self):
        changes = (
            (b"<disabled>yes</disabled>", b"<disabled>no</disabled>"),
            (b"<logall_json>yes</logall_json>", b"<logall_json>no</logall_json>"),
            (b'max-size="16MB">no', b'max-size="1KB">no'),
            (b'max-size="16MB">no', b'max-size="16MB">yes'),
            (b"signalbridge_enterprise_rules.xml", b"unreviewed_rules.xml"),
            (b"/documents/observation/", b"/expenses/observation/"),
        )
        for old, new in changes:
            with self.subTest(old=old), self.assertRaises(EnterpriseWazuhError):
                verify_configuration(configuration().replace(old, new, 1), INTERNAL_OPTIONS)
        with self.assertRaises(EnterpriseWazuhError):
            verify_configuration(
                configuration(),
                INTERNAL_OPTIONS.replace(b"remote_commands=0", b"remote_commands=1"),
            )

    def test_xml_declarations_entities_duplicates_and_oversize_are_rejected(self):
        for raw in (
            b'<!DOCTYPE ossec_config [<!ENTITY attack "unexpected">]>' + configuration(),
            configuration() + configuration(),
            b"x" * 32769,
        ):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                verify_configuration(raw, INTERNAL_OPTIONS)

    def test_preparation_recipe_is_typed_non_launchable_and_bounded(self):
        result = verify_recipe(recipe())
        self.assertFalse(result["launch_authorized"])
        self.assertFalse(result["native_execution_verified"])
        for key, changed in (
            ("network", "host"),
            ("published_ports", 1),
            ("cpus", True),
            ("cpus", 1.0),
            ("pids", 256.0),
            ("docker_socket", True),
            ("privileged", True),
            ("cap_add", ["SYS_ADMIN"]),
        ):
            value = copy.deepcopy(recipe())
            value["container"][key] = changed
            with self.subTest(key=key), self.assertRaises(EnterpriseWazuhError):
                verify_recipe(value)
        value = recipe()
        value["launch_authorized"] = True
        with self.assertRaises(EnterpriseWazuhError):
            verify_recipe(value)


@override_settings(SOC_SEGMENTED_EXPORT=True)
class CollectorSnapshotTests(TestCase):
    def setUp(self):
        self.root = disposable_root(self)
        self.apps = {
            name: Integration.objects.create(slug=name, name=f"Synthetic {name}")
            for name in ("documents", "expenses")
        }
        self.counter = 0
        self.base = timezone.now() - timedelta(minutes=1)
        self.run = str(uuid.uuid4())
        self.batches = {}
        for name, app in self.apps.items():
            self.event(app)
            self.batches[name] = stage(app)
            publish(app)

    def event(self, app, *, processed=True):
        packet = observation(self.counter, self.base, app=app.slug, environment="lab")
        self.counter += 1
        row = rows(app, [packet], source="instrumented_lab")[0]
        row.state = "processed" if processed else "pending"
        row.save()
        return row

    def directory(self, run=None):
        return self.root / "var/wazuh-enterprise/native" / (run or self.run)

    def capture(self):
        result = capture_idle_exports(self.run)
        raw = (self.directory() / "manifest.json").read_bytes()
        return result, raw

    def inspect(self, value):
        return inspect_exports(self.directory() / "input", canonical(value) + b"\n")

    def test_native_delivery_rejects_an_unreviewed_filesystem_destination(self):
        with (
            override_settings(SOC_DELIVERY_ROOT=Path("/tmp/unreviewed-signalbridge-export")),
            patch.dict(
                os.environ,
                {"SB_SOURCE_PROOF": "1", "SB_SOURCE_COMPONENT": "console"},
                clear=False,
            ),
            patch("bridge.soc_delivery.sys.platform", "linux"),
            self.assertRaisesMessage(DeliveryError, "unsafe_delivery_root"),
        ):
            delivery_location()

    def test_real_idle_sql_exports_are_copied_without_native_or_source_attestation(self):
        before = {s.pk: (s.offset, s.prefix_sha256, s.revision) for s in SocStream.objects.all()}
        result, raw = self.capture()
        self.assertEqual(result["logical_records"], 2)
        self.assertTrue(result["committed_file_snapshot_verified"])
        self.assertFalse(result["genuine_source_execution_verified"])
        self.assertFalse(result["native_collector_execution_verified"])
        self.assertFalse(result["continuous_collection_verified"])
        self.assertFalse(result["private_host_acl_verified"])
        self.assertFalse(result["snapshot_live_after_capture"])
        self.assertEqual(
            result["scope_counts"],
            {
                "documents/observation": 1,
                "documents/detection": 0,
                "expenses/observation": 1,
                "expenses/detection": 0,
            },
        )
        self.assertEqual(
            before, {s.pk: (s.offset, s.prefix_sha256, s.revision) for s in SocStream.objects.all()}
        )
        self.assertFalse(WazuhRecord.objects.exists())
        self.assertEqual(manifest(raw)["manifest_version"], 1)
        audits = list(Audit.objects.filter(action="wazuh.collector_snapshot"))
        self.assertEqual(len(audits), 2)
        self.assertTrue(
            all(
                a.actor_id is None and a.detail["origin"] == "local_database_operator"
                for a in audits
            )
        )
        self.assertNotIn("actor", raw.decode())
        self.assertNotIn("resource", raw.decode())

    def test_dry_run_does_not_create_files_or_check_existing_file_bytes(self):
        source = segment_path(self.batches["documents"].segment)
        source.unlink()
        before = set(self.root.rglob("*"))
        result = capture_idle_exports(self.run, dry_run=True)
        self.assertTrue(result["database_inventory_only"])
        self.assertFalse(result["files_inspected"])
        self.assertEqual(before, set(self.root.rglob("*")))
        self.assertFalse(self.directory().exists())

    def test_pending_batch_prevents_snapshot_before_any_copy(self):
        self.event(self.apps["documents"])
        stage(self.apps["documents"])
        with self.assertRaisesMessage(DeliveryError, "collector_snapshot_pending_batch"):
            capture_idle_exports(self.run)
        self.assertFalse(self.directory().exists())

    def test_disabled_or_missing_scope_and_non_local_execution_are_rejected(self):
        Integration.objects.filter(slug="expenses").update(enabled=False)
        with self.assertRaisesMessage(DeliveryError, "collector_app_disabled"):
            capture_idle_exports(self.run)
        self.assertFalse(self.directory().exists())
        Integration.objects.filter(slug="expenses").update(slug="missing-reference")
        with self.assertRaisesMessage(DeliveryError, "collector_app_inventory"):
            capture_idle_exports(self.run)
        with (
            override_settings(LOCAL=False),
            self.assertRaisesMessage(DeliveryError, "collector_snapshot_local_only"),
        ):
            capture_idle_exports(self.run)

    def test_existing_native_snapshot_cannot_be_overwritten(self):
        self.capture()
        before = {str(p): p.read_bytes() for p in self.directory().rglob("*") if p.is_file()}
        with self.assertRaisesMessage(DeliveryError, "collector_snapshot_run_exists"):
            capture_idle_exports(self.run)
        self.assertEqual(
            before, {str(p): p.read_bytes() for p in self.directory().rglob("*") if p.is_file()}
        )

    def test_tampered_source_retains_incomplete_copy_without_completed_summary(self):
        path = segment_path(self.batches["documents"].segment)
        original = path.read_bytes()
        path.write_bytes(b"X" + original[1:])
        with self.assertRaisesMessage(DeliveryError, "collector_snapshot_source_digest"):
            capture_idle_exports(self.run)
        self.assertTrue(self.directory().exists())
        self.assertFalse((self.directory() / "snapshot.json").exists())
        self.assertFalse((self.directory() / "manifest.json").exists())
        path.write_bytes(original)
        with self.assertRaisesMessage(DeliveryError, "collector_snapshot_run_exists"):
            capture_idle_exports(self.run)
        self.assertEqual(capture_idle_exports(str(uuid.uuid4()))["logical_records"], 2)

    def test_physical_tail_not_in_committed_inventory_is_rejected_and_preserved(self):
        path = segment_path(self.batches["documents"].segment)
        before = path.read_bytes()
        path.write_bytes(before + b"unexpected synthetic pending tail\n")
        with self.assertRaisesMessage(DeliveryError, "collector_snapshot_source_changed"):
            capture_idle_exports(self.run)
        self.assertEqual(path.read_bytes(), before + b"unexpected synthetic pending tail\n")

    def test_hardlinked_source_is_rejected_without_native_output(self):
        source = segment_path(self.batches["documents"].segment)
        os.link(source, self.root / "synthetic-hardlink")
        with self.assertRaises(DeliveryError):
            capture_idle_exports(self.run)
        self.assertFalse((self.directory() / "snapshot.json").exists())
        self.assertFalse(WazuhRecord.objects.exists())

    def test_legacy_single_file_stream_cannot_be_silently_reclassified_or_copied(self):
        SocStream.objects.filter(integration=self.apps["documents"]).update(segmented_export=False)
        with self.assertRaisesMessage(DeliveryError, "collector_snapshot_legacy_stream"):
            capture_idle_exports(self.run)
        self.assertFalse(self.directory().exists())
        self.assertEqual(Event.objects.filter(source="instrumented_lab").count(), 2)

    def test_configuration_snapshot_contains_real_forwarded_core_signal(self):
        app = self.apps["documents"]
        for _ in range(3):
            self.event(app, processed=False)
        drain(limit=10, worker_id="modeled-collector-snapshot")
        stage(app)
        publish(app)
        signal = stage_signals(app)
        self.assertIsNotNone(signal)
        publish_signals(app)
        result, _ = self.capture()
        self.assertEqual(result["scope_counts"]["documents/detection"], 1)
        self.assertFalse(result["native_collector_execution_verified"])
        self.assertFalse(WazuhRecord.objects.exists())

    def test_unaccounted_filename_and_cross_app_packet_are_rejected(self):
        _, raw = self.capture()
        value = manifest(raw)
        parent = self.directory() / "input/documents/observation"
        extra = parent / "unexpected.jsonl"
        extra.write_bytes(b"{}\n")
        with self.assertRaisesMessage(EnterpriseWazuhError, "export_unaccounted_file"):
            self.inspect(value)
        extra.unlink()
        expense_path = self.directory() / "input/expenses/observation/observations-000.jsonl"
        packet = json.loads(expense_path.read_bytes())
        changed = canonical(packet) + b"\n"
        (parent / "observations-000.jsonl").write_bytes(changed)
        row = next(
            s for s in value["streams"] if s["app"] == "documents" and s["channel"] == "observation"
        )
        row["offset"] = row["segments"][0]["bytes"] = len(changed)
        row["prefix_sha256"] = row["segments"][0]["sha256"] = hashlib.sha256(changed).hexdigest()
        with self.assertRaisesMessage(EnterpriseWazuhError, "export_packet_scope_or_encoding"):
            self.inspect(value)

    def test_duplicate_logical_record_across_retained_segments_is_rejected(self):
        _, raw = self.capture()
        value = manifest(raw)
        row = next(
            s for s in value["streams"] if s["app"] == "documents" and s["channel"] == "observation"
        )
        parent = self.directory() / "input/documents/observation"
        packet = (parent / "observations-000.jsonl").read_bytes()
        (parent / "observations-001.jsonl").write_bytes(packet)
        row["segments"][0]["sealed"] = True
        row["segments"].append(
            {
                "number": 1,
                "start_offset": len(packet),
                "bytes": len(packet),
                "sha256": hashlib.sha256(packet).hexdigest(),
                "sealed": False,
            }
        )
        row["offset"] = 2 * len(packet)
        row["prefix_sha256"] = hashlib.sha256(packet * 2).hexdigest()
        with self.assertRaisesMessage(EnterpriseWazuhError, "export_duplicate_logical_record"):
            self.inspect(value)

    def test_private_fields_are_rejected_even_with_updated_inventory_hashes(self):
        _, raw = self.capture()
        value = manifest(raw)
        path = self.directory() / "input/documents/observation/observations-000.jsonl"
        packet = json.loads(path.read_bytes())
        packet["signalbridge"]["actor"] = "synthetic-private-field"
        changed = canonical(packet) + b"\n"
        path.write_bytes(changed)
        row = next(
            s for s in value["streams"] if s["app"] == "documents" and s["channel"] == "observation"
        )
        row["offset"] = row["segments"][0]["bytes"] = len(changed)
        row["prefix_sha256"] = row["segments"][0]["sha256"] = hashlib.sha256(changed).hexdigest()
        with self.assertRaises(EnterpriseWazuhError):
            self.inspect(value)

    def test_manifest_rejects_changed_types_duplicate_scopes_offsets_and_sealing(self):
        _, raw = self.capture()
        value = manifest(raw)
        row_index = next(
            i
            for i, s in enumerate(value["streams"])
            if s["app"] == "documents" and s["channel"] == "observation"
        )
        for field, changed in (
            ("offset", True),
            ("stream_id", "../../outside"),
            ("prefix_sha256", "x" * 64),
            ("app", "bettail"),
        ):
            mutated = copy.deepcopy(value)
            mutated["streams"][row_index][field] = changed
            with self.subTest(field=field), self.assertRaises(EnterpriseWazuhError):
                manifest(canonical(mutated))
        for field, changed in (
            ("number", True),
            ("start_offset", 1),
            ("bytes", 2097153),
            ("sealed", True),
        ):
            mutated = copy.deepcopy(value)
            mutated["streams"][row_index]["segments"][0][field] = changed
            with self.subTest(field=field), self.assertRaises(EnterpriseWazuhError):
                manifest(canonical(mutated))
        value["streams"][1] = copy.deepcopy(value["streams"][0])
        with self.assertRaisesMessage(EnterpriseWazuhError, "export_duplicate_scope"):
            manifest(canonical(value))

    def test_scan_is_bounded_and_whole_stream_hash_is_checked(self):
        _, raw = self.capture()
        value = manifest(raw)
        with (
            patch("integrations.wazuh_enterprise.export_snapshot.MAX_LOGICAL_RECORDS", 1),
            self.assertRaisesMessage(EnterpriseWazuhError, "export_record_capacity"),
        ):
            self.inspect(value)
        row = next(
            s for s in value["streams"] if s["app"] == "documents" and s["channel"] == "observation"
        )
        row["prefix_sha256"] = "b" * 64
        with self.assertRaisesMessage(EnterpriseWazuhError, "export_whole_stream_digest"):
            self.inspect(value)

    def test_cli_requires_operator_and_reports_no_manager_or_acl_proof(self):
        with self.assertRaises(CommandError):
            call_command("prepare_wazuh_collector", run_id=self.run, stdout=StringIO())
        self.assertFalse(self.directory().exists())
        with self.assertRaises(CommandError):
            call_command(
                "prepare_wazuh_collector",
                run_id="../../outside",
                local_database_operator=True,
                stdout=StringIO(),
            )
        output = StringIO()
        call_command(
            "prepare_wazuh_collector", run_id=self.run, local_database_operator=True, stdout=output
        )
        self.assertIn(
            "private host ACLs and native collector delivery remain unverified", output.getvalue()
        )
        self.assertNotIn("actor", output.getvalue())
        self.assertFalse(WazuhRecord.objects.exists())
