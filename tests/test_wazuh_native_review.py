"""Modeled native receipts and real disposable console checks; no Wazuh launch."""

import copy
import hashlib
import io
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from bridge import wazuh_native_review as review
from bridge.case_provenance import generation_record
from bridge.contract import canonical, digest, timestamp
from bridge.models import Audit, CheckRun, Event, Integration, Investigation, Membership
from integrations.wazuh_enterprise.contract import EnterpriseWazuhError, expected_rule
from tests.test_processing_efficiency import observation, rows


def modeled():
    now = timezone.now() - timedelta(seconds=5)
    run_id, source_run, snapshot = uuid.uuid4().hex, uuid.uuid4().hex, str(uuid.uuid4())
    values, scopes = {}, {}
    for app, count in (("documents", 13), ("expenses", 10)):
        payloads = [
            observation(
                index,
                now - timedelta(minutes=2),
                app=app,
                environment="lab",
                event_id=str(uuid.uuid4()),
                outcome="denied",
                reason="membership_required",
            )
            for index in range(count)
        ]
        values[app] = payloads
        observations = [
            {
                "event_id": p["event_id"],
                "event_sha256": digest(p),
                "packet": {
                    "signalbridge": {
                        "export_version": 2,
                        "app": app,
                        "source": "instrumented_lab",
                        **{
                            key: p[key]
                            for key in (
                                "event_id",
                                "environment",
                                "occurred_at",
                                "operation",
                                "outcome",
                                "reason",
                            )
                        },
                    }
                },
            }
            for p in payloads
        ]
        signals = []
        if app == "documents":
            ids = sorted(p["event_id"] for p in payloads[:2])
            signals = [
                {
                    "signalbridge_detection": {
                        "signal_version": 1,
                        "origin": "signalbridge",
                        "app": app,
                        "signal_id": str(uuid.uuid4()),
                        "case_id": str(uuid.uuid4()),
                        "case_version": 1,
                        "rule_id": "R3",
                        "rule_version": "resource-membership-v1",
                        "severity": "high",
                        "environment": "lab",
                        "source": "instrumented_lab",
                        "generated_at": (now - timedelta(seconds=30)).isoformat(),
                        "evidence_sha256": digest(
                            sorted(
                                [
                                    [p["event_id"], digest(p), "instrumented_lab"]
                                    for p in payloads[:2]
                                ]
                            )
                        ),
                        "generation_source_sha256": "e" * 64,
                        "evidence_count": 2,
                        "included_event_ids": ",".join(ids),
                        "evidence_complete": 1,
                    }
                }
            ]
        records = []
        for channel, packet in [("observation", r["packet"]) for r in observations] + [
            ("detection", p) for p in signals
        ]:
            data = next(iter(packet.values()))
            for kind in ("archive", "alert"):
                rule = expected_rule(packet)
                if kind == "alert" and rule is None:
                    continue
                records.append(
                    {
                        "kind": kind,
                        "native_id": f"1700000000.{len(records) + 1}",
                        "channel": channel,
                        "target_id": data["event_id" if channel == "observation" else "signal_id"],
                        "occurred_at": (now - timedelta(seconds=10)).isoformat(),
                        "rule_id": rule[0] if kind == "alert" else None,
                        "rule_level": rule[1] if kind == "alert" else None,
                        "record_sha256": "f" * 64,
                        "packet_sha256": digest(packet),
                    }
                )
        scopes[app] = {
            "schema_version": 1,
            "evidence_kind": review.KIND,
            "profile": review.PROFILE,
            "app": app,
            "run_id": run_id,
            "source_run_id": source_run,
            "snapshot_run_id": snapshot,
            "executed_at": now.isoformat(),
            "source_sha256": "a" * 64,
            "collector_source_sha256": "b" * 64,
            "host_receipt_sha256": "c" * 64,
            "source_receipt_sha256": "d" * 64,
            "image_reference": review.IMAGE,
            "observations": observations,
            "signals": signals,
            "records": records,
            "counts": review._counts(observations, signals, records),
            "limitations": review.LIMITATIONS,
        }
    return values, scopes


class NativeWazuhReviewShapeTests(SimpleTestCase):
    def loader_fixture(self, *, publication=False):
        payloads, scopes = modeled()
        result = scopes["documents"]
        finished = timestamp(result["executed_at"])
        started = finished - timedelta(seconds=610)
        context = {
            "context_version": 1,
            "run_id": str(uuid.UUID(result["run_id"])),
            "prepared_at": (started + timedelta(seconds=1)).isoformat(),
            "source_sha256": "b" * 64,
            "manifest_sha256": hashlib.sha256(b"modeled manifest").hexdigest(),
        }
        source_console = canonical(
            {
                "events": [
                    {"event_id": p["event_id"], "digest": digest(p)}
                    for app in review.APPS
                    for p in payloads[app]
                ]
            }
        )
        source_receipt = canonical(
            {
                "native_proof": {
                    "raw_receipt_sha256": {
                        "console-events": hashlib.sha256(source_console).hexdigest()
                    }
                }
            }
        )
        binding = {
            "native_source_run_id": result["source_run_id"],
            "snapshot_run_id": result["snapshot_run_id"],
            "native_source_receipt_sha256": hashlib.sha256(source_receipt).hexdigest(),
        }
        expected, files = {}, {}
        for app, scoped in scopes.items():
            for item in scoped["observations"]:
                expected[(app, "observation", item["event_id"])] = (
                    item["packet"],
                    "modeled-location",
                )
            for packet in scoped["signals"]:
                expected[(app, "detection", packet["signalbridge_detection"]["signal_id"])] = (
                    packet,
                    "modeled-location",
                )
        for kind in ("archive", "alert"):
            native = []
            for app, scoped in scopes.items():
                for record in scoped["records"]:
                    if record["kind"] != kind:
                        continue
                    packet = expected[(app, record["channel"], record["target_id"])][0]
                    row = {
                        "id": record["native_id"],
                        "timestamp": record["occurred_at"],
                        "data": packet,
                    }
                    if kind == "alert":
                        row["rule"] = {"id": record["rule_id"], "level": record["rule_level"]}
                    native.append(canonical(row) + b"\n")
            files[f"native-{kind}s.jsonl"] = b"".join(native)
        proof = {
            "raw_receipt_sha256": {
                name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()
            }
        }
        image = {
            "id": "sha256:" + "a" * 64,
            "os": "linux",
            "architecture": "amd64",
            "digests": [review.IMAGE],
            "environment": ["PATH=/bin"],
            "volumes": None,
        }
        watchdog = {
            "run_id": result["run_id"],
            "shutdown_verified": True,
            "reason": "launcher_finished",
            "stopped_component_count": 1,
            "stopped_at": finished.isoformat(),
        }
        host = {
            "schema_version": 1,
            "kind": "signalbridge-native-wazuh-reference-bootstrap",
            "run_id": result["run_id"],
            "status": "passed",
            "image_reference": review.IMAGE,
            "image_id": image["id"],
            "runner_exit_code": 0,
            "continuous_collection_verified": False,
            "collector_rotation_recovery_verified": False,
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "source_sha256": "a" * 64,
            "context": context,
            "native_proof": copy.deepcopy(proof),
            "source_binding": binding,
            "main_shutdown": {
                "run_id": result["run_id"],
                "shutdown_verified": True,
                "stopped_component_count": 1,
            },
            "independent_shutdown": watchdog,
            **{
                key: True
                for key in (
                    "bootstrap_acceptance_passed",
                    "native_wazuh_executed",
                    "source_unchanged",
                    "runtime_isolation_verified",
                    "main_shutdown_verified",
                    "independent_shutdown_verified",
                )
            },
        }
        files.update(
            {
                "image.json": canonical(image),
                "watchdog.json": canonical(watchdog),
                "run-context.json": canonical(context),
                "console-events.json": source_console,
            }
        )
        if publication:
            watchdog.update(
                late_operation_drain_seconds=60,
                late_operation_drain_elapsed_ms=60000,
                late_operation_drain_verified=True,
            )
            files["watchdog.json"] = canonical(watchdog)
            binding["expected_packets_sha256"] = digest(
                sorted([[*key, packet, location] for key, (packet, location) in expected.items()])
            )
            # This fixture checks loader dispatch/binding only. The native
            # output validator is modeled below, never labeled genuine proof.
            plan = {
                "run_id": result["run_id"],
                "expected_packets_sha256": binding["expected_packets_sha256"],
            }
            completion = {"published_bytes": 1234}
            files["plan.json"] = canonical(plan)
            files["publication-finished.json"] = canonical(completion)
            for key in (
                "bootstrap_acceptance_passed",
                "native_wazuh_executed",
                "source_unchanged",
                "continuous_collection_verified",
                "collector_rotation_recovery_verified",
                "context",
                "source_sha256",
            ):
                host.pop(key)
            host.update(
                kind="signalbridge-native-wazuh-ready-publication",
                acceptance_passed=True,
                native_runtime_execution_verified=True,
                continuous_delivery_verified=False,
                plan_sha256=digest(plan),
                publication={
                    **completion,
                    "existing_prefix_bytes": 0,
                    "appended_bytes_this_call": 1234,
                },
            )

        def read(path, _root, bound):
            raw = (
                canonical(host)
                if path.name == "receipt.json" and path.parent.name == result["run_id"]
                else source_receipt
                if path.name == "receipt.json"
                else files[path.name]
            )
            self.assertLessEqual(len(raw), bound)
            return raw

        def load(*, native_error=None):
            with (
                patch.object(review, "read_bytes", side_effect=read),
                patch.object(
                    review,
                    "load_binding",
                    return_value=(None, b"modeled manifest", expected, binding),
                ),
                patch(
                    "scripts.enterprise_wazuh_verify.validate_output",
                    return_value=proof,
                    side_effect=native_error,
                ) as native_reader,
            ):
                loaded = review.load_native_review("C:/modeled-workspace", result["run_id"])
                if publication:
                    self.assertEqual(native_reader.call_args.kwargs["publication_plan"], plan)
                else:
                    self.assertNotIn("publication_plan", native_reader.call_args.kwargs)
                return loaded

        return host, load

    def test_loader_revalidates_receipts_and_splits_only_allowlisted_app_records(self):
        _, load = self.loader_fixture()
        scopes = load()
        self.assertEqual([len(scopes[app]["observations"]) for app in review.APPS], [13, 10])
        self.assertEqual([len(scopes[app]["signals"]) for app in review.APPS], [1, 0])
        self.assertNotIn("data", scopes["documents"]["records"][0])
        self.assertNotIn(
            "actor", canonical(scopes["documents"]).decode().replace("actor identifiers", "")
        )

    def test_publication_loader_dispatches_native_handshake_validation_and_labels_recorded_replay(
        self,
    ):
        _, load = self.loader_fixture(publication=True)
        scopes = load()
        self.assertEqual([len(scopes[app]["observations"]) for app in review.APPS], [13, 10])
        self.assertEqual(scopes["documents"]["profile"], review.PUBLICATION_PROFILE)
        self.assertEqual(scopes["documents"]["limitations"], review.PUBLICATION_LIMITATIONS)
        self.assertEqual(scopes["documents"]["source_sha256"], "b" * 64)
        self.assertIn("Recorded replay", scopes["documents"]["limitations"][0])
        for failure in (
            "publisher_recorded_readiness",
            "publisher_recorded_completion",
            "collector_native_frozen_inputs_changed",
        ):
            with (
                self.subTest(failure=failure),
                self.assertRaisesMessage(EnterpriseWazuhError, failure),
            ):
                load(native_error=EnterpriseWazuhError(failure))

    def test_publication_loader_rejects_unknown_or_publisher_only_kinds_before_archive_access(self):
        for kind in (
            "unknown",
            "signalbridge-wazuh-frozen-publication-v1",
            "signalbridge-wazuh-ready-publication-v1",
            "signalbridge-wazuh-empty-input-ready-v1",
        ):
            host, load = self.loader_fixture(publication=True)
            host["kind"] = kind
            with (
                self.subTest(kind=kind),
                self.assertRaisesMessage(EnterpriseWazuhError, "wazuh_review_execution_incomplete"),
            ):
                load()

    def test_publication_loader_rejects_changed_plan_publication_scope_and_shutdowns(self):
        for field in ("plan", "publication", "scope", "main", "independent", "flag", "current"):
            host, load = self.loader_fixture(publication=True)
            if field == "plan":
                host["plan_sha256"] = "0" * 64
            elif field == "publication":
                host["publication"]["appended_bytes_this_call"] = 1233
            elif field == "scope":
                host["source_binding"] = {
                    **host["source_binding"],
                    "native_source_run_id": uuid.uuid4().hex,
                }
            elif field == "main":
                host["main_shutdown"]["shutdown_verified"] = False
            elif field == "independent":
                host["independent_shutdown"]["stopped_component_count"] = 2
            elif field == "flag":
                host["native_runtime_execution_verified"] = 1
            else:
                host["continuous_delivery_verified"] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                load()

    def test_loader_rejects_numeric_execution_flags_and_changed_native_proof(self):
        host, load = self.loader_fixture()
        host["native_wazuh_executed"] = 1
        with self.assertRaises(ValueError):
            load()
        host["native_wazuh_executed"] = True
        host["native_proof"] = {"raw_receipt_sha256": {}}
        with self.assertRaisesMessage(EnterpriseWazuhError, "wazuh_review_native_proof_changed"):
            load()

    def test_closed_scope_rejects_changed_counts_unknown_fields_and_cross_app_packet(self):
        _, scopes = modeled()
        result = scopes["documents"]
        review.validate_result(result, "documents")
        changed = copy.deepcopy(result)
        changed["counts"]["source_observations"] += 1
        cross_app = copy.deepcopy(result)
        cross_app["observations"][0]["packet"]["signalbridge"]["app"] = "expenses"
        for invalid in (
            changed,
            cross_app,
            {**result, "current_connection": True},
            {**result, "schema_version": True},
        ):
            with self.subTest(invalid=invalid.keys()), self.assertRaises(ValueError):
                review.validate_result(invalid, "documents")

    def test_missing_records_native_id_conflict_and_unbound_signal_are_rejected(self):
        _, scopes = modeled()
        result = scopes["documents"]
        for mutation in ("missing", "conflict", "signal", "future"):
            changed = copy.deepcopy(result)
            if mutation == "missing":
                changed["records"].pop()
            elif mutation == "conflict":
                # Same kind, native id and target with different recorded content.
                changed["records"].append({**changed["records"][0], "record_sha256": "e" * 64})
            elif mutation == "signal":
                changed["signals"][0]["signalbridge_detection"]["evidence_sha256"] = "0" * 64
            else:
                changed["records"][0]["occurred_at"] = (
                    timezone.now() + timedelta(days=1)
                ).isoformat()
            changed["counts"] = review._counts(
                changed["observations"], changed["signals"], changed["records"]
            )
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                review.validate_result(changed, "documents")

    def test_distinct_targets_may_share_a_same_second_native_id(self):
        # Wazuh ids are the second plus the alerts-file offset; native runs
        # observed 14 archived records carrying only 5 distinct ids.
        _, scopes = modeled()
        result = scopes["documents"]
        archives = [row for row in result["records"] if row["kind"] == "archive"]
        self.assertNotEqual(archives[0]["target_id"], archives[1]["target_id"])
        archives[1]["native_id"] = archives[0]["native_id"]
        result["counts"] = review._counts(
            result["observations"], result["signals"], result["records"]
        )
        review.validate_result(result, "documents")
        self.assertEqual(
            result["counts"]["distinct_archive_ids"],
            len({row["native_id"] for row in archives}),
        )

    def test_identical_native_copy_is_counted_separately_and_capped(self):
        _, scopes = modeled()
        result = scopes["documents"]
        result["records"].append(copy.deepcopy(result["records"][0]))
        result["counts"] = review._counts(
            result["observations"], result["signals"], result["records"]
        )
        review.validate_result(result, "documents")
        self.assertEqual(result["counts"]["physical_archive_copies"], 15)
        self.assertEqual(result["counts"]["distinct_archive_ids"], 14)
        result["records"].extend([copy.deepcopy(result["records"][0])] * 2)
        result["counts"] = review._counts(
            result["observations"], result["signals"], result["records"]
        )
        with self.assertRaises(ValueError):
            review.validate_result(result, "documents")

    def test_incomplete_receipt_is_rejected_before_native_reader_or_image_access(self):
        with patch.object(
            review,
            "read_bytes",
            return_value=canonical({"schema_version": 1, "status": "incomplete"}),
        ) as read:
            with self.assertRaisesMessage(
                EnterpriseWazuhError, "wazuh_review_execution_incomplete"
            ):
                review.load_native_review("C:/modeled-workspace", "a" * 32)
        self.assertEqual(read.call_count, 1)


class NativeWazuhReviewTests(TestCase):
    def setUp(self):
        self.payloads, self.scopes = modeled()
        self.app = Integration.objects.create(slug="documents", name="Synthetic documents")
        self.other = Integration.objects.create(slug="expenses", name="Synthetic expenses")
        self.user = get_user_model().objects.create_user(username="native-receipt-analyst")
        self.membership = Membership.objects.create(
            user=self.user, integration=self.app, role="analyst"
        )
        self.result = self.scopes["documents"]

    def imported(self):
        return review.import_native_review(self.user, self.result)

    def local_events(self, count=2):
        values = rows(self.app, self.payloads["documents"][:count], source="instrumented_lab")
        for event in values:
            event.state = "processed"
            event.save()
        return values

    def case(self):
        events = self.local_events()
        signal = self.result["signals"][0]["signalbridge_detection"]
        case = Investigation.objects.create(
            id=signal["case_id"],
            integration=self.app,
            rule="R3",
            correlation="f" * 64,
            title="Modeled source case",
            severity="high",
            explanation="Fixture only",
        )
        case.events.add(*events)
        source = {"process_source_sha256": "e" * 64, "disk_source_sha256": "e" * 64}
        Audit.objects.create(
            integration=self.app,
            action="case.created",
            object_id=str(case.pk),
            detail={
                "generation": generation_record(
                    case, [(e.event_id, e.digest, e.source) for e in events], source, source
                ),
            },
        )
        return case

    def test_historical_import_without_local_events_preserves_scope_and_creates_no_incidents(self):
        run, created, links = self.imported()
        self.assertTrue(created)
        self.assertEqual(links["matched_events"], 0)
        self.assertEqual(links["unmatched_events"], 13)
        self.assertFalse(Event.objects.exists())
        self.assertFalse(Investigation.objects.exists())
        foreign_ids = {p["event_id"] for p in self.payloads["expenses"]}
        self.assertFalse(any(value in canonical(run.result).decode() for value in foreign_ids))
        self.assertTrue(review.receipt_card(self.app)["verified"])
        again, created, _ = self.imported()
        self.assertFalse(created)
        self.assertEqual(again.pk, run.pk)
        self.assertEqual(Audit.objects.filter(action="wazuh_native.imported").count(), 1)

    def test_recorded_publication_is_scoped_audited_idempotent_and_never_current_health(self):
        self.result.update(
            profile=review.PUBLICATION_PROFILE, limitations=review.PUBLICATION_LIMITATIONS
        )
        case = self.case()
        run, created, links = self.imported()
        self.assertTrue(created)
        self.assertEqual(links["cases"][0]["id"], str(case.pk))
        self.assertEqual(
            Audit.objects.get(action="wazuh_native.imported").detail["profile"],
            review.PUBLICATION_PROFILE,
        )
        card = review.receipt_card(self.app)
        self.assertTrue(card["verified"])
        self.assertIn("Recorded replay", card["execution_description"])
        self.assertIn("does not establish a current connection", card["execution_description"])
        self.assertEqual(card["source_label"], "Collector verification source SHA-256")
        self.assertTrue(review.case_receipt_card(case)["verified"])
        again, created, _ = self.imported()
        self.assertEqual(again.pk, run.pk)
        self.assertFalse(created)
        self.assertEqual(Event.objects.count(), 2)
        self.assertEqual(Investigation.objects.count(), 1)
        self.client.force_login(self.user)
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get("/integrations/?app=documents")
        self.assertLessEqual(len(queries), 8)
        self.assertContains(response, "current connection unverified")
        self.assertContains(response, "Recorded replay: fixed source-bound packets")
        self.assertContains(response, "Collector verification source SHA-256")
        self.assertNotContains(response, "fixed snapshot collected for ten minutes")
        self.assertNotContains(response, "Recorded checkout SHA-256")
        Audit.objects.filter(action="wazuh_native.imported").update(
            detail={
                **Audit.objects.get(action="wazuh_native.imported").detail,
                "profile": review.PROFILE,
            }
        )
        self.assertFalse(review.receipt_card(self.app)["verified"])
        self.assertFalse(review.receipt_card(self.app, summary_only=True)["verified"])
        rejected = self.client.get("/integrations/?app=documents")
        self.assertContains(rejected, "Stored receipt could not be verified")
        self.assertNotContains(rejected, "Recorded replay: fixed source-bound packets")
        self.assertNotContains(rejected, self.result["records"][0]["native_id"])
        with self.assertRaisesMessage(EnterpriseWazuhError, "wazuh_review_missing_admission"):
            self.imported()

    def test_publication_profile_cannot_bypass_cross_app_authorization_or_replace_old_receipt(self):
        self.imported()
        self.result.update(
            profile=review.PUBLICATION_PROFILE, limitations=review.PUBLICATION_LIMITATIONS
        )
        with self.assertRaisesMessage(EnterpriseWazuhError, "wazuh_review_conflicting_import"):
            self.imported()
        foreign = self.scopes["expenses"]
        foreign.update(
            profile=review.PUBLICATION_PROFILE, limitations=review.PUBLICATION_LIMITATIONS
        )
        with self.assertRaises(PermissionError):
            review.import_native_review(self.user, foreign)
        wrong_scope = {**self.result, "app": "expenses"}
        with self.assertRaises(ValueError):
            review.validate_result(wrong_scope, "expenses")
        self.assertEqual(CheckRun.objects.count(), 1)

    def test_same_run_changed_receipt_cannot_overwrite_original(self):
        self.imported()
        self.result["host_receipt_sha256"] = "0" * 64
        with self.assertRaisesMessage(EnterpriseWazuhError, "wazuh_review_conflicting_import"):
            self.imported()
        self.assertEqual(CheckRun.objects.count(), 1)

    def test_dry_run_does_not_write_and_current_roles_are_required(self):
        run, created, _ = review.import_native_review(self.user, self.result, dry_run=True)
        self.assertIsNone(run)
        self.assertFalse(created)
        self.assertFalse(CheckRun.objects.exists())
        self.assertFalse(Audit.objects.exists())
        for role in ("viewer",):
            self.membership.role = role
            self.membership.save()
            with self.assertRaises(PermissionError):
                self.imported()
        self.membership.delete()
        with self.assertRaises(PermissionError):
            self.imported()

    def test_other_app_and_disabled_account_cannot_import(self):
        with self.assertRaises(PermissionError):
            review.import_native_review(self.user, self.scopes["expenses"])
        get_user_model().objects.filter(pk=self.user.pk).update(is_active=False)
        with self.assertRaises(PermissionError):
            self.imported()
        self.assertFalse(CheckRun.objects.exists())

    def test_conflicting_local_event_cannot_be_linked_or_imported(self):
        event = self.local_events(1)[0]
        event.reason = "owner"
        event.save()
        with self.assertRaisesMessage(EnterpriseWazuhError, "wazuh_review_local_event_conflict"):
            self.imported()
        self.assertFalse(CheckRun.objects.exists())

    def test_exact_case_link_disappears_when_evidence_changes(self):
        case = self.case()
        _, _, links = self.imported()
        self.assertEqual(links["matched_events"], 2)
        self.assertEqual(links["cases"][0]["id"], str(case.pk))
        self.assertTrue(review.case_receipt_card(case)["verified"])
        Event.objects.filter(pk=case.events.first().pk).update(digest="0" * 64)
        self.assertIsNone(review.case_receipt_card(case))
        card = review.receipt_card(self.app)
        self.assertTrue(card["verified"])
        self.assertEqual(card["links"]["conflicting_events"], 1)

    def test_missing_admission_audit_or_changed_digest_cannot_claim_native_proof(self):
        run, _, _ = self.imported()
        Audit.objects.filter(action="wazuh_native.imported").delete()
        self.assertFalse(review.receipt_card(self.app)["verified"])
        CheckRun.objects.filter(pk=run.pk).update(digest="0" * 64)
        self.assertFalse(review.receipt_card(self.app)["verified"])

    def test_admission_for_wrong_check_run_cannot_verify_batched_or_direct_card(self):
        run, _, _ = self.imported()
        Audit.objects.filter(action="wazuh_native.imported").update(object_id=str(uuid.uuid4()))
        for card in (
            review.receipt_card(self.app),
            review.receipt_card(self.app, summary_only=True),
            review.receipt_card(self.app, run),
        ):
            self.assertTrue(card["present"])
            self.assertFalse(card["verified"])
        with self.assertRaisesMessage(EnterpriseWazuhError, "wazuh_review_missing_admission"):
            self.imported()
        self.assertEqual(CheckRun.objects.count(), 1)

    def test_repeat_import_cannot_repair_or_adopt_an_unaudited_check_run(self):
        self.imported()
        Audit.objects.filter(action="wazuh_native.imported").delete()
        with self.assertRaisesMessage(EnterpriseWazuhError, "wazuh_review_missing_admission"):
            self.imported()
        self.assertEqual(CheckRun.objects.count(), 1)
        self.assertFalse(Audit.objects.exists())

    def test_console_is_scoped_readable_historical_and_not_authorization_assertions(self):
        self.imported()
        self.client.force_login(self.user)
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get("/integrations/?app=documents")
        self.assertLessEqual(len(queries), 8)
        self.assertContains(response, "Historical execution verified")
        self.assertContains(response, "shutdown recorded")
        self.assertContains(response, "current connection unverified")
        self.assertContains(response, "This was a fixed snapshot collected for ten minutes.")
        self.assertContains(response, "Recorded checkout SHA-256")
        self.assertContains(
            response,
            "The retained native logs, capture journal, original application run and shutdown receipts were rechecked before import.",
            count=1,
        )
        self.assertNotContains(response, "Recorded replay: fixed source-bound packets")
        self.assertContains(response, "13 do not have a verified local match")
        self.assertContains(response, self.result["records"][0]["native_id"])
        for payload in self.payloads["expenses"]:
            self.assertNotContains(response, payload["event_id"])
        self.assertEqual(self.client.get("/integrations/?app=expenses").status_code, 404)
        checks = self.client.get("/checks/?app=documents")
        self.assertNotContains(checks, review.SUITE)

    def test_newest_native_receipt_does_not_replace_latest_authorization_check(self):
        assurance = CheckRun.objects.create(
            integration=self.app,
            suite="Authorization controls",
            revision="0" * 64,
            digest="1" * 64,
            status="failed",
            result={"checks": [{"status": "failed"}]},
        )
        self.imported()
        self.client.force_login(self.user)
        response = self.client.get("/?app=documents")
        self.assertEqual(response.context["latest_run"].pk, assurance.pk)
        self.assertEqual(response.context["passed_checks"], 0)

    def test_command_only_accepts_loader_results_and_reports_unmatched_rows(self):
        stream = io.StringIO()
        with patch.object(review, "load_native_review", return_value=self.scopes):
            # The command binds its imported loader independently.
            with patch(
                "bridge.management.commands.import_wazuh_native.load_native_review",
                return_value=self.scopes,
            ):
                call_command(
                    "import_wazuh_native",
                    run_id=self.result["run_id"],
                    app="documents",
                    user_id=self.user.pk,
                    stdout=stream,
                )
        self.assertIn("13 unmatched", stream.getvalue())
        with patch(
            "bridge.management.commands.import_wazuh_native.load_native_review",
            side_effect=ValueError("modeled rejected"),
        ):
            with self.assertRaises(CommandError):
                call_command(
                    "import_wazuh_native",
                    run_id=self.result["run_id"],
                    app="documents",
                    user_id=self.user.pk,
                )
