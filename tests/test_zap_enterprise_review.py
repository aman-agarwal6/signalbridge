"""Synthetic historical native-format review fixtures; no native execution claim."""

import copy
import io
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase, override_settings

from bridge import zap_enterprise_review as review
from bridge.contract import digest, timestamp
from bridge.models import Audit, CheckRun, Event, Integration, Membership
from integrations.enterprise.reference_reconciliation import WORKER
from integrations.enterprise.verification import LabControlError
from integrations.zap_enterprise.capture import HeaderProfileError
from integrations.zap_enterprise.scanner_contract import IMAGE
from integrations.zap_enterprise.scanner_contract import digest as archive_digest
from tests.test_processing_efficiency import observation, rows
from tests.test_zap_enterprise_capture import START
from tests.test_zap_enterprise_host_evidence import phase_receipts
from tests.test_zap_enterprise_runtime import package

RUN = "a" * 32


def modeled_evidence():
    """Use real closed API parser fixtures; raw execution facts remain modeled."""
    value = package()
    analyses = {phase: phase_receipts(value, phase)[2] for phase in ("fault", "corrected")}
    bindings, native_events = {app: [] for app in review.APPS}, []
    for phase in ("fault", "corrected"):
        for row in value["phases"][phase]:
            if row["event_id"] is None:
                continue
            app = "expenses" if row["http_status"] == 403 else "documents"
            payload = observation(
                len(native_events),
                START,
                app=app,
                environment="lab",
                event_id=row["event_id"],
                resource="f" * 64,
                occurred_at=row["started_at"],
                outcome="denied" if app == "expenses" else "allowed",
                reason="membership_required"
                if app == "expenses"
                else "owner"
                if row["account"] == "operator"
                else "member",
            )
            native = {
                "app": app,
                "event_id": payload["event_id"],
                "payload": payload,
                "digest": digest(payload),
                "state": "processed",
                "source": "instrumented_lab",
                "processing_attempts": 1,
                "processed_by": WORKER,
                "processed_at": (START + timedelta(seconds=14)).isoformat(),
            }
            native_events.append(native)
            bindings[app].append(
                {
                    "phase": phase,
                    "ordinal": row["ordinal"],
                    "event": native,
                    "native_message_id": analyses[phase]["history"]["message_ids"][row["ordinal"]],
                }
            )
    for name, identifier in value["execution"]["restoration_event_ids"].items():
        payload = observation(
            len(native_events),
            START,
            app="documents",
            environment="lab",
            event_id=identifier,
            resource="f" * 64,
            outcome="allowed",
            reason="owner" if name == "operator" else "member",
        )
        native = {
            "app": "documents",
            "event_id": identifier,
            "payload": payload,
            "digest": digest(payload),
            "state": "processed",
            "source": "instrumented_lab",
            "processing_attempts": 1,
            "processed_by": WORKER,
            "processed_at": (START + timedelta(seconds=14)).isoformat(),
        }
        native_events.append(native)
        bindings["documents"].append(
            {"phase": "restoration", "ordinal": name, "event": native, "native_message_id": None}
        )
    result = {
        "schema_version": 1,
        "evidence_kind": review.KIND,
        "profile": review.PROFILE,
        "run_id": RUN,
        "source_run_id": value["source_run_id"],
        "source_sha256": value["source_sha256"],
        "scanner_host_receipt_sha256": "b" * 64,
        "source_host_receipt_sha256": value["source_receipt_sha256"],
        "executed_at": (START + timedelta(seconds=40)).isoformat(),
        "scopes": bindings,
        "finding": analyses["fault"]["findings"][0],
        "corrected_findings": [],
    }
    return value, analyses, native_events, result


class NativeHeaderLoaderTests(SimpleTestCase):
    def setUp(self):
        self.value, phases, self.events, self.result = modeled_evidence()
        self.binding = {
            "source_run_id": self.value["source_run_id"],
            "source_receipt_sha256": self.value["source_receipt_sha256"],
            "source_finished_at": (START + timedelta(seconds=19)).isoformat(),
        }
        self.proof = {
            "source_snapshot": {"source_sha256": self.value["source_sha256"]},
            "source_run_id": self.value["source_run_id"],
            "source_receipt_sha256": self.value["source_receipt_sha256"],
            "input_sha256": archive_digest(self.value),
            "phases": phases,
        }
        self.watchdog = {
            "run_id": RUN,
            "shutdown_verified": True,
            "reason": "launcher_finished",
            "stopped_component_count": 1,
            "stopped_at": (START + timedelta(seconds=39)).isoformat(),
        }
        self.receipt = {
            "schema_version": 1,
            "kind": "signalbridge-native-authenticated-zap-offline",
            "run_id": RUN,
            "source_run_id": self.value["source_run_id"],
            "status": "passed",
            **{
                key: True
                for key in (
                    "acceptance_passed",
                    "native_zap_executed",
                    "source_unchanged",
                    "source_archive_unchanged",
                    "runtime_isolation_verified",
                    "parsed_configuration_verified",
                    "main_shutdown_verified",
                    "independent_shutdown_verified",
                )
            },
            "runner_exit_code": 0,
            "image_reference": IMAGE,
            "image_id": "sha256:" + "c" * 64,
            "started_at": (START + timedelta(seconds=20)).isoformat(),
            "finished_at": self.result["executed_at"],
            "source_sha256": self.value["source_sha256"],
            "input_sha256": self.proof["input_sha256"],
            "scanner_proof": self.proof,
            "source_snapshot": self.proof["source_snapshot"],
            "source_binding": self.binding,
            "independent_shutdown": self.watchdog,
            "main_shutdown": {
                "run_id": RUN,
                "shutdown_verified": True,
                "stopped_component_count": 1,
            },
        }

    def load(self):
        def read(path, root, bound):
            self.assertLessEqual(bound, 262144)
            value = {
                "receipt.json": self.receipt,
                "watchdog.json": self.watchdog,
                "console-events.json": {"events": self.events, "cases": []},
            }[path.name]
            return copy.deepcopy(value), "b" * 64, b"modeled-only"

        with (
            patch.object(review, "read_receipt", side_effect=read),
            patch.object(review, "_manifest", return_value={"sha256": self.value["source_sha256"]}),
            patch.object(review, "validate_receipts", return_value=self.proof),
            patch.object(review, "load_completed_source", return_value=(self.value, self.binding)),
        ):
            return review.load_native_review("C:/modeled-not-read", RUN)

    def test_loader_binds_both_scopes_without_credentials_or_daemon_calls(self):
        result = self.load()
        self.assertEqual(result, self.result)
        self.assertEqual([len(result["scopes"][a]) for a in review.APPS], [6, 2])

    def test_incomplete_and_numeric_flags_are_rejected(self):
        for name in (
            "acceptance_passed",
            "native_zap_executed",
            "source_unchanged",
            "runtime_isolation_verified",
            "parsed_configuration_verified",
            "main_shutdown_verified",
            "independent_shutdown_verified",
        ):
            original = self.receipt[name]
            for value in (False, 1, "true"):
                with self.subTest(name=name, value=value):
                    self.receipt[name] = value
                    with self.assertRaises(HeaderProfileError):
                        self.load()
            self.receipt[name] = original

    def test_wrong_image_exit_run_or_source_is_rejected(self):
        for name, value in (
            ("image_reference", "unreviewed:latest"),
            ("runner_exit_code", False),
            ("run_id", "d" * 32),
            ("source_sha256", "d" * 64),
            ("input_sha256", "d" * 64),
        ):
            with self.subTest(name=name):
                original, self.receipt[name] = self.receipt[name], value
                with self.assertRaises(HeaderProfileError):
                    self.load()
                self.receipt[name] = original

    def test_changed_source_binding_or_shutdown_is_rejected(self):
        self.receipt["source_binding"] = {**self.binding, "source_receipt_sha256": "e" * 64}
        with self.assertRaises(HeaderProfileError):
            self.load()
        self.receipt["source_binding"] = self.binding
        self.watchdog["reason"] = "memory_headroom"
        with self.assertRaises(LabControlError):
            self.load()


class NativeHeaderImportTests(TestCase):
    def setUp(self):
        self.value, _, native, self.evidence = modeled_evidence()
        self.user = get_user_model().objects.create(username="header-review-analyst")
        self.apps = {a: Integration.objects.create(slug=a, name=a.title()) for a in review.APPS}
        for app in self.apps.values():
            Membership.objects.create(user=self.user, integration=app, role="analyst")
        for native_row in native:
            event = rows(
                self.apps[native_row["app"]], [native_row["payload"]], source="instrumented_lab"
            )[0]
            event.state, event.processed_by = "processed", WORKER
            event.processing_attempts = 1
            event.processed_at = timestamp(native_row["processed_at"])
            event.save()

    def test_two_scoped_records_with_one_document_finding_and_no_event_writes(self):
        runs, created = review.import_native_review(self.user, self.evidence)
        self.assertTrue(created)
        self.assertEqual([r.integration.slug for r in runs], list(review.APPS))
        self.assertEqual([len(r.result["event_bindings"]) for r in runs], [6, 2])
        self.assertEqual(runs[0].result["finding"]["plugin_id"], "10021")
        self.assertIsNone(runs[1].result["finding"])
        other_ids = {r["event"]["event_id"] for r in self.evidence["scopes"]["expenses"]}
        self.assertFalse(other_ids & {r["event_id"] for r in runs[0].result["event_bindings"]})
        self.assertEqual(Event.objects.count(), 8)
        self.assertEqual(Audit.objects.filter(action="zap_native.imported").count(), 2)

    def test_repeat_is_idempotent_and_preserves_original_import_actor(self):
        first, _ = review.import_native_review(self.user, self.evidence)
        second, created = review.import_native_review(self.user, self.evidence)
        self.assertFalse(created)
        self.assertEqual([r.pk for r in first], [r.pk for r in second])
        self.assertEqual(CheckRun.objects.count(), 2)
        self.assertEqual(Audit.objects.count(), 2)

    def test_missing_second_scope_event_rolls_back_all_writes(self):
        Event.objects.filter(integration=self.apps["expenses"]).first().delete()
        with self.assertRaises(HeaderProfileError):
            review.import_native_review(self.user, self.evidence)
        self.assertEqual(CheckRun.objects.count(), 0)
        self.assertEqual(Audit.objects.count(), 0)

    def test_role_withdrawal_in_either_scope_blocks_import(self):
        for app in self.apps.values():
            with self.subTest(app=app.slug):
                Membership.objects.filter(integration=app).update(role="viewer")
                with self.assertRaises(PermissionError):
                    review.import_native_review(self.user, self.evidence)
                Membership.objects.filter(integration=app).update(role="analyst")
        self.assertEqual(CheckRun.objects.count(), 0)

    def test_current_disabled_account_blocks_cached_user(self):
        get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
        with self.assertRaises(PermissionError):
            review.import_native_review(self.user, self.evidence)
        self.assertEqual(CheckRun.objects.count(), 0)

    def test_changed_or_unprocessed_native_event_is_rejected(self):
        event = Event.objects.first()
        for field, value in (
            ("digest", "a" * 64),
            ("source", "synthetic_demo"),
            ("state", "pending"),
            ("processed_by", "unreviewed"),
            ("actor", "b" * 64),
            ("processing_attempts", 2),
        ):
            with self.subTest(field=field):
                original = getattr(event, field)
                Event.objects.filter(pk=event.pk).update(**{field: value})
                with self.assertRaises(HeaderProfileError):
                    review.import_native_review(self.user, self.evidence)
                Event.objects.filter(pk=event.pk).update(**{field: original})
        self.assertEqual(CheckRun.objects.count(), 0)

    def test_conflicting_saved_run_is_preserved(self):
        review.import_native_review(self.user, self.evidence)
        original = CheckRun.objects.first()
        original.result = {**original.result, "conflict": "modeled modification"}
        original.save()
        with self.assertRaises(HeaderProfileError):
            review.import_native_review(self.user, self.evidence)
        original.refresh_from_db()
        self.assertIn("conflict", original.result)
        self.assertEqual(CheckRun.objects.count(), 2)

    def test_repeat_import_rejects_wrong_suite_without_repairing_retained_metadata(self):
        runs, _ = review.import_native_review(self.user, self.evidence)
        CheckRun.objects.filter(pk=runs[1].pk).update(suite="Unrelated review")
        with self.assertRaises(HeaderProfileError):
            review.import_native_review(self.user, self.evidence)
        runs[1].refresh_from_db()
        self.assertEqual(runs[1].suite, "Unrelated review")
        self.assertEqual(CheckRun.objects.count(), 2)
        self.assertEqual(Audit.objects.count(), 2)

    def test_repeat_import_requires_admission_for_each_exact_scoped_check_run(self):
        runs, _ = review.import_native_review(self.user, self.evidence)
        marker = Audit.objects.get(action="zap_native.imported", object_id=str(runs[1].pk))
        marker.object_id = str(runs[0].pk)
        marker.save(update_fields=["object_id"])
        with self.assertRaises(HeaderProfileError):
            review.import_native_review(self.user, self.evidence)
        marker.delete()
        with self.assertRaises(HeaderProfileError):
            review.import_native_review(self.user, self.evidence)
        self.assertEqual(CheckRun.objects.count(), 2)
        self.assertEqual(Audit.objects.count(), 1)

    def test_wrong_app_or_native_finding_binding_is_rejected(self):
        original = self.evidence["finding"]["source_event_id"]
        self.evidence["finding"]["source_event_id"] = str(uuid.uuid4())
        with self.assertRaises(HeaderProfileError):
            review.import_native_review(self.user, self.evidence)
        self.evidence["finding"]["source_event_id"] = original
        self.evidence["scopes"]["documents"][0]["event"]["app"] = "expenses"
        with self.assertRaises(HeaderProfileError):
            review.import_native_review(self.user, self.evidence)

    def test_dry_run_does_not_write_or_manufacture_cases(self):
        imported, created = review.import_native_review(self.user, self.evidence, dry_run=True)
        self.assertEqual(imported, [])
        self.assertFalse(created)
        self.assertEqual(CheckRun.objects.count(), 0)
        self.assertEqual(Audit.objects.count(), 0)
        self.assertEqual(Event.objects.count(), 8)

    def test_console_displays_native_header_scope_and_no_other_app_bindings(self):
        runs, _ = review.import_native_review(self.user, self.evidence)
        self.client.force_login(self.user)
        response = self.client.get("/checks/?app=documents")
        self.assertContains(response, "Historical authenticated capture and passive header review")
        self.assertContains(response, "Missing X-Content-Type-Options: nosniff")
        self.assertContains(response, "not a current connection status")
        for row in runs[1].result["event_bindings"]:
            self.assertNotContains(response, row["event_id"])
        for row in runs[0].result["event_bindings"]:
            self.assertContains(response, row["event_id"])

    def test_command_local_only_and_never_accepts_a_supplied_report(self):
        with override_settings(LOCAL=False), self.assertRaises(CommandError):
            call_command("import_zap_enterprise", run_id=RUN, user_id=self.user.pk)
        with patch(
            "bridge.management.commands.import_zap_enterprise.load_native_review",
            return_value=self.evidence,
        ) as load:
            call_command(
                "import_zap_enterprise",
                run_id=RUN,
                user_id=self.user.pk,
                dry_run=True,
                stdout=io.StringIO(),
            )
            self.assertEqual(load.call_args.args[1], RUN)
        self.assertEqual(CheckRun.objects.count(), 0)
