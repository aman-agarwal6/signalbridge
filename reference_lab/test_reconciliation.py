"""Actual source/ingestion/worker paths in memory; never native lab proof."""

import copy
import hashlib
import json
import os
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.test import Client, TestCase, override_settings
from django.utils import timezone

from bridge.contract import digest
from bridge.models import IngestKey, Integration
from bridge.worker import drain
from integrations.enterprise.reference_host_evidence import (
    HASHED_RECEIPTS,
    validate_native,
)
from integrations.enterprise.reference_http import RESOURCES, content_observation, exercise
from integrations.enterprise.reference_native_support import console_evidence, source_evidence
from integrations.enterprise.reference_reconciliation import ReconciliationError, reconcile
from integrations.enterprise.verification import LabControlError, private_run_directory

from .collector import deliver_one
from .seed import seed_accounts, set_regression

PASSWORDS = {
    name: "nonfunctional-reconciliation-test-only-" + name
    for name in ("operator", "document_member", "expense_member", "outsider")
}


class MemoryClient:
    """Django's client runs views/middleware, with no listening socket or TLS."""

    def __init__(self):
        self.client = Client(enforce_csrf_checks=True)
        self.last_event_id = None

    @property
    def cookies(self):
        return {name: cookie.value for name, cookie in self.client.cookies.items()}

    def request(self, method, path, data=None, content_type="application/json"):
        headers = {"secure": True, "HTTP_REFERER": "https://testserver/login/"}
        if "csrftoken" in self.cookies:
            headers["HTTP_X_CSRFTOKEN"] = self.cookies["csrftoken"]
        response = getattr(self.client, method.lower())(
            path, data=data or {}, content_type=content_type, **headers
        )
        self.last_event_id = response.headers.get("X-SB-Lab-Event-ID")
        return response.status_code, response.json() if response.headers["Content-Type"].startswith(
            "application/json"
        ) else {}

    def sign_in(self, account, password):
        self.request("GET", "/login/")
        response = self.client.post(
            "/login/",
            {"username": account, "password": password},
            secure=True,
            HTTP_REFERER="https://testserver/login/",
            HTTP_X_CSRFTOKEN=self.cookies["csrftoken"],
        )
        if response.status_code != 200:
            raise ValueError("memory_login_failed")
        status, value = self.request("GET", "/identity/")
        if status != 200 or value != {"account": account, "authenticated": True}:
            raise ValueError("memory_identity_failed")

    def read(self, app):
        status, value = self.request("GET", f"/apps/{app}/resources/{RESOURCES[app]}/")
        return content_observation(status, value, app)

    def permission(self, app, subject, kind, granted):
        return self.request(
            "POST",
            f"/apps/{app}/resources/{RESOURCES[app]}/permission/",
            json.dumps({"subject": subject, "kind": kind, "granted": granted}),
        )


class ReferenceReconciliationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        environment = {
            "SB_REF_" + kind + "_" + app.upper(): "nonfunctional-reconciliation-" + kind + app
            for kind in ("PSEUDO", "DELIVERY")
            for app in RESOURCES
        }
        with patch.dict(os.environ, environment):
            seed_accounts(PASSWORDS)
            for app in RESOURCES:
                integration = Integration.objects.create(slug=app, name="Synthetic " + app)
                IngestKey.objects.create(
                    integration=integration,
                    key_id="reference-" + app + "-v1",
                    secret_env="SB_REF_DELIVERY_" + app.upper(),
                    source="instrumented_lab",
                    can_assert_membership=True,
                )
            cls.execution = exercise(
                MemoryClient, PASSWORDS, lambda enabled, seconds: set_regression(enabled, seconds)
            )
            if not cls.execution["completed"]:
                raise AssertionError(
                    "Memory HTTP controls incomplete: " + json.dumps(cls.execution)
                )

            def transport(app, body, headers):
                with override_settings(ROOT_URLCONF="config.urls"):
                    response = Client().post(
                        "/api/v1/events/" + app + "/",
                        body,
                        content_type="application/json",
                        **{
                            "HTTP_" + key.upper().replace("-", "_"): value
                            for key, value in headers.items()
                            if key != "Content-Type"
                        },
                    )
                return response.status_code, response.content

            attempts = 0
            while deliver_one(transport) is not None:
                attempts += 1
                if attempts > 80:
                    raise AssertionError("Memory delivery bound exceeded")
            drain(limit=80, worker_id="native-reference-proof")
            cls.source, cls.console = source_evidence(), console_evidence()

    def verify(self, execution=None, source=None, console=None):
        return reconcile(
            execution or self.execution, source or self.source, console or self.console
        )

    @contextmanager
    def host_receipts(self):
        """Modeled native files around actual memory-path events, never native proof."""
        from scripts.record_verification import json_bytes

        parent = Path(tempfile.gettempdir()).resolve()
        workspace = parent / ("sbr-" + uuid.uuid4().hex[:16])
        workspace.mkdir()
        run = uuid.uuid4().hex
        directory = private_run_directory(workspace, run)
        source_root = directory / "source"
        (source_root / "bridge").mkdir(parents=True)
        (directory / "evidence").mkdir()
        repository = Path(__file__).resolve().parents[1]
        source = b"# Nonfunctional host evidence test marker, never executed.\n"
        (source_root / "manage.py").write_bytes(source)
        files = {"manage.py": hashlib.sha256(source).hexdigest()}
        for name in ("engine.py", "contract.py", "worker.py"):
            raw = (repository / "bridge" / name).read_bytes()
            (source_root / "bridge" / name).write_bytes(raw)
            files["bridge/" + name] = hashlib.sha256(raw).hexdigest()
        manifest = {
            "files": files,
            "file_count": len(files),
            "sha256": hashlib.sha256(json_bytes(files)).hexdigest(),
        }
        footprint = {
            "uncompressed_bytes": 1,
            "archive_entries": 1,
            "estimated_allocation_bytes": 4608,
            "claim": "test model",
        }
        proof = self.verify()
        values = {
            "reference-execution": copy.deepcopy(self.execution),
            "source-outbox": copy.deepcopy(self.source),
            "console-events": copy.deepcopy(self.console),
            "reference-reconciliation": proof,
            "kernel-mounts": {
                "/tmp": {"filesystem": "tmpfs", "noexec": True},
                "/opt/verification-deps": {"filesystem": "tmpfs", "noexec": False},
            },
            "kernel-identity": {
                "uid": 10001,
                "gid": 10001,
                "supplementary_groups": [],
                "all_capabilities_zero": True,
                "no_new_privileges": True,
                "seccomp_filter": True,
                "cgroup_version": 2,
                "memory_bytes": 512 * 1024**2,
                "swap_bytes": 0,
                "pids": 96,
                "cpu_quota_equals_period": True,
                "read_only_root_source_wheels_secrets": True,
                "reviewed_evidence_mount_writable": True,
            },
        }
        runner = {
            "schema_version": 1,
            "run_id": run,
            "completed": True,
            "receipt_sha256": {},
            "wheel_footprint": footprint,
            "database_boundaries": {
                component: {
                    "component": component,
                    "actual_identity_verified": True,
                    "cross_database_connect_denied": True,
                    "denial_kind": "sqlstate",
                    "denial_sqlstate": "42501",
                }
                for component in ("source", "console")
            },
            "console_readiness_attempts": 1,
            "tls_readiness": True,
            "source_http_requests": 49,
            "collection": {
                "committed_claim_results": 23,
                "collector_transport_invocations": 23,
                "phase_deadline_reached": False,
            },
            "final_fault_reset": True,
            "processes_stopped": True,
            "duration_seconds": 30.0,
            "limits": ["test model" for _ in range(3)],
            "wazuh_export": None,
        }

        from integrations.enterprise.reference_native_support import publish_wazuh_evidence

        with (
            override_settings(BASE_DIR=workspace, SOC_SEGMENTED_EXPORT=True),
            patch.dict(os.environ, {"SB_SOURCE_RUN": run}, clear=False),
        ):
            exported = publish_wazuh_evidence()
        generated = workspace / "var/wazuh-enterprise/native" / exported["snapshot_run_id"]
        target = directory / "evidence/wazuh-enterprise/native" / exported["snapshot_run_id"]
        target.parent.mkdir(parents=True)
        shutil.copytree(generated, target)
        # The native /evidence mount retains both the live outbox and snapshot.
        shutil.copytree(workspace / "var/soc-delivery", directory / "evidence/soc-delivery")
        snapshot = json.loads((generated / "snapshot.json").read_bytes())
        if exported["manifest_sha256"] != snapshot["manifest_sha256"]:
            raise AssertionError("Test Wazuh snapshot identity changed")
        values["wazuh-export"] = exported
        runner["wazuh_export"] = exported

        def write():
            runner["wazuh_export"] = values["wazuh-export"]
            for name, value in values.items():
                raw = json_bytes(value)
                (directory / "evidence" / (name + ".json")).write_bytes(raw)
                if name in HASHED_RECEIPTS:
                    runner["receipt_sha256"][name] = hashlib.sha256(raw).hexdigest()
            (directory / "evidence/reference-runner.json").write_bytes(json_bytes(runner))

        (directory / "evidence/install.log").write_bytes(b"test model, no installation\n")
        (directory / "evidence/allow-source.json").write_bytes(
            json_bytes({"run_id": run, "runtime_verified": True})
        )
        write()
        try:
            yield workspace, run, manifest, footprint, values, runner, write
        finally:
            target = workspace.resolve()
            if not target.is_relative_to(parent) or workspace.is_symlink():
                raise RuntimeError("Unsafe host evidence test cleanup.")
            shutil.rmtree(target)

    def test_host_receipt_models_recompute_actual_memory_event_bindings(self):
        with self.host_receipts() as (
            workspace,
            run,
            manifest,
            footprint,
            _values,
            _runner,
            _write,
        ):
            result = validate_native(workspace, run, manifest, footprint, now=timezone.now())
            self.assertTrue(result["native_receipts_revalidated"])
            self.assertEqual(result["reconciliation"]["logical_processed_events"], 23)
            self.assertTrue(
                result["wazuh_input_binding"]["source_inputs_match_revalidated_reference_run"]
            )
            self.assertEqual(result["wazuh_input_binding"]["logical_observations"], 23)
            self.assertEqual(result["wazuh_input_binding"]["forwarded_core_signals"], 1)
            from integrations.wazuh_enterprise.collector_source_binding import load_snapshot

            directory = private_run_directory(workspace, run)
            snapshot_id = result["wazuh_input_binding"]["snapshot_run_id"]
            root, _raw_manifest, expected = load_snapshot(
                workspace, snapshot_id, source_directory=directory
            )
            self.assertEqual(root, directory / "evidence/wazuh-enterprise/native" / snapshot_id)
            self.assertEqual(len(expected), 24)
            # This verifier sees modeled files; the launcher must independently
            # establish real runtime isolation, exit, source identity and shutdown.
            self.assertNotIn("acceptance_passed", result)

    def test_wazuh_input_bytes_are_bound_to_the_native_reference_receipt(self):
        with self.host_receipts() as (
            workspace,
            run,
            _manifest,
            _footprint,
            values,
            _runner,
            write,
        ):
            directory = private_run_directory(workspace, run)
            snapshot = values["wazuh-export"]["snapshot_run_id"]
            path = (
                directory
                / "evidence/wazuh-enterprise/native"
                / snapshot
                / "input/documents/observation/observations-000.jsonl"
            )
            raw = path.read_bytes()
            path.write_bytes(raw + b"tampered")
            with self.assertRaises(ValueError):
                validate_native(workspace, run, _manifest, _footprint, now=timezone.now())
            path.write_bytes(raw)
            values["wazuh-export"]["scope_counts"]["documents/detection"] = 0
            write()
            with self.assertRaises(LabControlError):
                validate_native(workspace, run, _manifest, _footprint, now=timezone.now())

            values["wazuh-export"]["scope_counts"]["documents/detection"] = 1
            values["wazuh-export"]["forwarded_core_signals"] = True
            write()
            with self.assertRaises(LabControlError):
                validate_native(workspace, run, _manifest, _footprint, now=timezone.now())

    def test_raw_receipt_tampering_and_recomputed_wrong_evidence_fail(self):
        with self.host_receipts() as (workspace, run, manifest, footprint, values, _runner, write):
            directory = private_run_directory(workspace, run)
            (directory / "evidence/reference-execution.json").write_bytes(b"{}\n")
            with self.assertRaises(LabControlError):
                validate_native(workspace, run, manifest, footprint, now=timezone.now())
            write()
            values["reference-execution"]["steps"][4]["http_status"] = 503
            write()  # Even updating the hash cannot turn failure into valid access proof.
            with self.assertRaises(ReconciliationError):
                validate_native(workspace, run, manifest, footprint, now=timezone.now())

    def test_runner_completion_counts_reset_identity_and_limits_cannot_be_faked(self):
        changes = (
            {"run_id": "f" * 32},
            {"completed": False},
            {"schema_version": True},
            {"tls_readiness": 1},
            {"final_fault_reset": False},
            {"processes_stopped": False},
            {"console_readiness_attempts": 11},
            {"source_http_requests": 81},
            {"duration_seconds": 901},
            {"wheel_footprint": {}},
            {"database_boundaries": {}},
            {
                "collection": {
                    "committed_claim_results": 22,
                    "collector_transport_invocations": 23,
                    "phase_deadline_reached": False,
                }
            },
        )
        with self.host_receipts() as (workspace, run, manifest, footprint, _values, runner, write):
            original = copy.deepcopy(runner)
            for change in changes:
                runner.clear()
                runner.update({**copy.deepcopy(original), **change})
                write()
                with self.subTest(fields=list(change)), self.assertRaises(LabControlError):
                    validate_native(workspace, run, manifest, footprint, now=timezone.now())

    def test_selected_snapshot_requires_exact_files_and_original_bytes(self):
        with self.host_receipts() as (
            workspace,
            run,
            manifest,
            footprint,
            _values,
            _runner,
            _write,
        ):
            directory = private_run_directory(workspace, run)
            marker = directory / "source/.env"
            marker.write_text("nonfunctional-private-marker", encoding="ascii")
            with self.assertRaises(LabControlError):
                validate_native(workspace, run, manifest, footprint, now=timezone.now())
            marker.unlink()
            (directory / "source/manage.py").write_bytes(b"different nonfunctional marker")
            with self.assertRaises(LabControlError):
                validate_native(workspace, run, manifest, footprint, now=timezone.now())

    def test_partial_extra_or_duplicate_json_receipts_are_incomplete(self):
        with self.host_receipts() as (workspace, run, manifest, footprint, _values, _runner, write):
            directory = private_run_directory(workspace, run)
            marker = directory / "evidence/extra.json"
            marker.write_bytes(b"{}")
            with self.assertRaises(LabControlError):
                validate_native(workspace, run, manifest, footprint, now=timezone.now())
            marker.unlink()
            receipt = directory / "evidence/reference-runner.json"
            receipt.write_bytes(b'{"completed":false,"completed":true}')
            with self.assertRaises(LabControlError):
                validate_native(workspace, run, manifest, footprint, now=timezone.now())
            write()
            (directory / "evidence/source-outbox.json").unlink()
            with self.assertRaises(LabControlError):
                validate_native(workspace, run, manifest, footprint, now=timezone.now())

    def test_retained_outbox_must_match_snapshot_and_reject_extra_files(self):
        with self.host_receipts() as (workspace, run, manifest, footprint, *_rest):
            root = private_run_directory(workspace, run) / "evidence/soc-delivery"
            path = next(root.rglob("*.jsonl"))
            original = path.read_bytes()
            path.write_bytes(original.replace(b"signalbridge", b"xignalbridge", 1))
            with self.assertRaises(LabControlError):
                validate_native(workspace, run, manifest, footprint, now=timezone.now())
            path.write_bytes(original)
            extra = root / "unexpected.json"
            extra.write_bytes(b"{}")
            with self.assertRaises(LabControlError):
                validate_native(workspace, run, manifest, footprint, now=timezone.now())
            extra.unlink()
            self.assertTrue(
                validate_native(workspace, run, manifest, footprint, now=timezone.now())[
                    "native_receipts_revalidated"
                ]
            )

    def test_actual_memory_pipeline_reconciles_exact_read_and_regression_evidence(self):
        result = self.verify()
        self.assertTrue(result["reconciled"])
        self.assertEqual(result["http_controls"], 31)
        self.assertEqual(result["logical_source_events"], 23)
        self.assertEqual(result["logical_processed_events"], 23)
        self.assertEqual(result["per_app_events"], {"documents": 13, "expenses": 10})
        self.assertEqual(result["committed_outbox_claims"], 23)
        self.assertEqual(result["additional_outbox_claims"], 0)
        self.assertEqual(result["logical_cases"], 1)
        self.assertNotIn("SYNTHETIC-ONLY", json.dumps([self.source, self.console, self.execution]))
        self.assertNotIn("sessionid", json.dumps(self.execution))

    def test_http_response_event_headers_bind_each_observed_result_without_guessing(self):
        row = next(
            v for v in self.execution["steps"] if v["step"] == "documents_removed_member_denied"
        )
        outbox = next(v for v in self.source["events"] if v["event_id"] == row["event_id"])
        self.assertEqual(outbox["payload"]["outcome"], "denied")
        for row in self.execution["steps"]:
            if row["step"].endswith("alternate_grant_preserved"):
                self.assertIsNone(row["event_id"])

    def test_post_reset_owner_control_is_required_and_bound_to_the_owner(self):
        execution = copy.deepcopy(self.execution)
        row = next(v for v in execution["steps"] if v["step"] == "documents_reset_owner_control")
        execution["steps"].remove(row)
        with self.assertRaises(ReconciliationError):
            self.verify(execution=execution)
        source, console = copy.deepcopy(self.source), copy.deepcopy(self.console)
        for evidence in (source, console):
            event = next(v for v in evidence["events"] if v["event_id"] == row["event_id"])
            event["payload"]["actor"] = "f" * 64
            event["digest"] = digest(event["payload"])
        with self.assertRaises(ReconciliationError):
            self.verify(source=source, console=console)

    def test_modeled_host_archive_connects_actual_memory_observations_to_review(self):
        """Real memory app/worker workflow, modeled native runtime receipts only."""
        from django.contrib.auth import get_user_model

        from bridge.case_workflow import operate
        from bridge.models import CaseTask, Membership
        from bridge.reference_retest import import_retest, load_native_retest
        from scripts.record_verification import json_bytes

        with self.host_receipts() as (
            workspace,
            run,
            manifest,
            footprint,
            _values,
            _runner,
            _write,
        ):
            directory = private_run_directory(workspace, run)
            finished = timezone.now()
            started = finished - timedelta(minutes=2)
            proof = validate_native(workspace, run, manifest, footprint, now=finished)
            watchdog = {
                "run_id": run,
                "shutdown_verified": True,
                "reason": "launcher_finished",
                "stopped_component_count": 2,
                "stopped_at": finished.isoformat(),
            }
            receipt = {
                "schema_version": 1,
                "kind": "signalbridge-native-reference-access",
                "run_id": run,
                "status": "passed",
                "acceptance_passed": True,
                "source_unchanged": True,
                "runtime_isolation_verified": True,
                "parsed_configuration_verified": True,
                "main_shutdown_verified": True,
                "independent_shutdown_verified": True,
                "runner_exit_code": 0,
                "started_at": started.isoformat(),
                "finished_at": finished.isoformat(),
                "source_sha256": manifest["sha256"],
                "source_snapshot": proof["source_snapshot"],
                "native_proof": proof,
                "preparation": {"wheel_footprint": footprint},
                "main_shutdown": {
                    "run_id": run,
                    "shutdown_verified": True,
                    "stopped_component_count": 2,
                },
                "independent_shutdown": watchdog,
            }
            (directory / "receipt.json").write_bytes(json_bytes(receipt))
            (directory / "watchdog.json").write_bytes(json_bytes(watchdog))
            (directory / "wheels").mkdir()
            raw_wheel = b"nonfunctional wheel model"
            (directory / "wheels/model.whl").write_bytes(raw_wheel)
            # Fixed doubles for dependency identity/footprint only. Actual raw
            # receipt, snapshot, reconciliation and shutdown validators run.
            with (
                patch(
                    "bridge.reference_retest.wheel_manifest",
                    return_value=[{"filename": "model.whl", "size": len(raw_wheel)}],
                ),
                patch("bridge.reference_retest.wheel_expansion", return_value=footprint),
            ):
                result = load_native_retest(workspace, run)
                check, created = import_retest(result)
                self.assertTrue(created)
                User = get_user_model()
                analyst = User.objects.create(username="memory-review-analyst")
                reviewer = User.objects.create(username="memory-review-reviewer")
                app = Integration.objects.get(slug="documents")
                Membership.objects.create(user=analyst, integration=app, role="analyst")
                Membership.objects.create(user=reviewer, integration=app, role="reviewer")
                case = operate(
                    analyst,
                    result["case_id"],
                    1,
                    "task",
                    {
                        "kind": "remediation",
                        "title": "Review the native profile's correction controls",
                    },
                )
                task = CaseTask.objects.get(investigation=case)
                case = operate(
                    analyst,
                    case.pk,
                    case.version,
                    "task_state",
                    {
                        "task_id": str(task.pk),
                        "status": "awaiting_retest",
                    },
                )
                case = operate(
                    analyst,
                    case.pk,
                    case.version,
                    "submit_retest",
                    {
                        "task_id": str(task.pk),
                        "check_run_id": str(check.pk),
                    },
                )
                verification = task.verifications.get()
                operate(
                    reviewer,
                    case.pk,
                    case.version,
                    "review_retest",
                    {
                        "verification_id": str(verification.pk),
                        "decision": "approved",
                        "rationale": "The known-content regression, denial and owner read match this modeled archive.",
                    },
                )
                task.refresh_from_db()
                self.assertEqual(task.status, "verified")
                # A manually asserted green status cannot bypass a failed
                # independent shutdown, even when native payloads are valid.
                watchdog["shutdown_verified"] = False
                (directory / "watchdog.json").write_bytes(json_bytes(watchdog))
                with self.assertRaises(ValueError):
                    load_native_retest(workspace, run)

    def test_delivery_retries_are_separate_from_logical_events(self):
        source = copy.deepcopy(self.source)
        source["events"][0]["attempts"] = 3
        result = self.verify(source=source)
        self.assertEqual(
            (result["committed_outbox_claims"], result["logical_source_events"]), (25, 23)
        )
        self.assertEqual(result["additional_outbox_claims"], 2)

    def test_missing_extra_duplicate_and_unprocessed_events_cannot_pass(self):
        for change in ("missing", "extra", "duplicate", "pending", "dead"):
            console = copy.deepcopy(self.console)
            if change == "missing":
                console["events"].pop()
            elif change == "extra":
                row = copy.deepcopy(console["events"][0])
                row["event_id"] = row["payload"]["event_id"] = str(uuid.uuid4())
                row["digest"] = digest(row["payload"])
                console["events"].append(row)
            elif change == "duplicate":
                console["events"].append(copy.deepcopy(console["events"][0]))
            else:
                console["events"][0]["state"] = change
            with self.subTest(change=change), self.assertRaises(ReconciliationError):
                self.verify(console=console)

    def test_payload_digests_and_collector_provenance_cannot_be_substituted(self):
        for change in ("payload", "digest", "source", "worker", "time", "attempts"):
            console = copy.deepcopy(self.console)
            row = console["events"][0]
            if change == "payload":
                row["payload"]["outcome"] = "denied"
            elif change == "digest":
                row["digest"] = "a" * 64
            elif change == "source":
                row["source"] = "synthetic_demo"
            elif change == "worker":
                row["processed_by"] = "unexpected-worker"
            elif change == "time":
                row["processed_at"] = "2999-01-01T00:00:00+00:00"
            else:
                row["processing_attempts"] = True
            with self.subTest(change=change), self.assertRaises(ReconciliationError):
                self.verify(console=console)

    def test_changed_http_binding_or_inconclusive_status_never_becomes_a_pass(self):
        for change in (
            "missing",
            "reused",
            "wrong_app",
            "failed",
            "status",
            "type",
            "order",
            "extra",
        ):
            execution = copy.deepcopy(self.execution)
            rows = {r["step"]: r for r in execution["steps"]}
            row = rows["bounded_regression_known_content"]
            if change == "missing":
                row["event_id"] = str(uuid.uuid4())
            elif change == "reused":
                row["event_id"] = rows["documents_allowed"]["event_id"]
            elif change == "wrong_app":
                row["event_id"] = rows["expenses_allowed"]["event_id"]
            elif change == "failed":
                execution["completed"] = False
            elif change == "status":
                row["http_status"] = 503
            elif change == "type":
                row["known_content"] = 1
            elif change == "order":
                execution["steps"].reverse()
            else:
                row["cookie"] = "nonfunctional-test-only"
            with self.subTest(change=change), self.assertRaises(ReconciliationError):
                self.verify(execution=execution)

    def test_wrong_case_scope_rule_and_evidence_cannot_prove_the_regression(self):
        for change in (
            "scope",
            "rule",
            "missing",
            "foreign",
            "duplicate",
            "severity",
            "resolved",
            "extra_case",
        ):
            console = copy.deepcopy(self.console)
            row = console["cases"][0]
            if change == "scope":
                row["app"] = "expenses"
            elif change == "rule":
                row["rule"] = "R2"
            elif change == "missing":
                console["cases"] = []
            elif change == "foreign":
                row["evidence_event_ids"][0] = str(uuid.uuid4())
            elif change == "duplicate":
                row["evidence_event_ids"] = [row["evidence_event_ids"][0]] * 2
            elif change == "severity":
                row["severity"] = "medium"
            elif change == "resolved":
                row["status"] = "resolved"
            else:
                console["cases"].append(copy.deepcopy(row))
            with self.subTest(change=change), self.assertRaises(ReconciliationError):
                self.verify(console=console)

    def test_restoration_flags_pending_delivery_and_private_fields_are_rejected(self):
        for change in ("fault", "grant", "pending", "private", "oversized"):
            source = copy.deepcopy(self.source)
            if change == "fault":
                source["fault_enabled"] = True
            elif change == "grant":
                source["direct_grants"] = 1
            elif change == "pending":
                source["events"][0]["state"] = "pending"
            elif change == "private":
                source["events"][0]["payload"]["password"] = "nonfunctional-private-test-only"
            else:
                source["extra"] = "x" * 262145
            with self.subTest(change=change), self.assertRaises(ReconciliationError) as error:
                self.verify(source=source)
            self.assertNotIn("nonfunctional-private", str(error.exception))

    def test_assertion_subject_or_read_actor_changed_on_both_sides_still_fails(self):
        source, console = copy.deepcopy(self.source), copy.deepcopy(self.console)
        key = next(
            r["event_id"]
            for r in self.execution["steps"]
            if r["step"] == "documents_permission_removed"
        )
        for data in (source, console):
            row = next(r for r in data["events"] if r["event_id"] == key)
            row["payload"]["membership"]["subject"] = "f" * 64
            row["digest"] = digest(row["payload"])
        with self.assertRaises(ReconciliationError):
            self.verify(source=source, console=console)

    def test_source_exports_keep_the_declared_event_and_case_limits(self):
        with (
            patch("reference_lab.models.Outbox.objects.count", return_value=81),
            self.assertRaises(ValueError),
        ):
            source_evidence()
        with (
            patch("bridge.models.Investigation.objects.count", return_value=21),
            self.assertRaises(ValueError),
        ):
            console_evidence()

    def test_invalid_clock_and_native_receipt_flags_fail_closed(self):
        execution = copy.deepcopy(self.execution)
        execution["restoration_verified"] = 1
        with self.assertRaises(ReconciliationError):
            self.verify(execution=execution)
        with self.assertRaises(ReconciliationError):
            reconcile(
                self.execution, self.source, self.console, now=timezone.now().replace(tzinfo=None)
            )
