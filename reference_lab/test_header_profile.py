"""Actual Django authorization/capture paths in memory; no native TLS/ZAP proof."""

import hashlib
import json
import os
import shutil
import uuid
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db import DatabaseError, IntegrityError, transaction
from django.http import JsonResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.utils import timezone

from bridge.models import IngestKey, Integration
from bridge.worker import drain
from config.reference_header_verification_settings import MIDDLEWARE
from integrations.zap_enterprise.capture import (
    DOC_PATH,
    EXPENSE_PATH,
    HEADERS,
    PROFILE,
    exercise,
    render_har,
)
from integrations.zap_enterprise.source_reconciliation import reconcile
from integrations.zap_enterprise.source_support import header_evidence

from .collector import deliver_one
from .header_probe import HeaderProbe, set_header_fault
from .models import BoundedHeaderFault, Grant, Outbox
from .seed import ACCOUNTS, CONTENT, DOCUMENT_ID, seed_accounts, set_regression

PASSWORDS = {name: "nonfunctional-header-test-only-" + name for name in ACCOUNTS}


class MemoryHeaderClient:
    """Real middleware, CSRF, sessions and views; no network or TLS listener."""

    def __init__(self):
        self.client = Client(enforce_csrf_checks=True)
        self.last_response = None

    @property
    def cookies(self):
        return {name: cookie.value for name, cookie in self.client.cookies.items()}

    def request(self, method, path):
        self.last_response = None
        started = timezone.now().isoformat()
        response = self.client.get(path, secure=True)
        if path != "/login/":
            self.last_response = {
                "method": method,
                "path": path,
                "status": response.status_code,
                # The test client has no wire protocol. Model the native WSGI
                # server's response version without claiming a native execution.
                "http_version": "HTTP/1.0",
                "headers": [(k, v) for k, v in response.headers.items() if k.lower() in HEADERS],
                "body": response.content,
                "started_at": started,
            }
        return response.status_code, response.content

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
            raise ValueError("memory_login_incomplete")
        self.request("GET", "/identity/")


@override_settings(
    REFERENCE_HEADER_PROFILE=PROFILE,
    MIDDLEWARE=MIDDLEWARE,
    SECURE_CONTENT_TYPE_NOSNIFF=True,
    SESSION_COOKIE_SECURE=True,
    CSRF_COOKIE_SECURE=True,
)
class HeaderProfileTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.users = seed_accounts(PASSWORDS)

    def setUp(self):
        self.environment = patch.dict(
            os.environ,
            {
                "SB_REF_PSEUDO_" + app.upper(): "nonfunctional-header-pseudonym-test-" + app
                for app in ("documents", "expenses")
            }
            | {
                "SB_REF_DELIVERY_" + app.upper(): "nonfunctional-header-delivery-test-" + app
                for app in ("documents", "expenses")
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.member = Client()
        self.member.force_login(self.users["document_member"])
        self.owner = Client()
        self.owner.force_login(self.users["operator"])

    def source_proof(self):
        from integrations.enterprise.reference_native_support import console_evidence

        summary, phases = exercise(MemoryHeaderClient, PASSWORDS, set_header_fault)
        for app in ("documents", "expenses"):
            integration = Integration.objects.create(slug=app, name="Synthetic " + app)
            IngestKey.objects.create(
                integration=integration,
                key_id="reference-" + app + "-v1",
                secret_env="SB_REF_DELIVERY_" + app.upper(),
                source="instrumented_lab",
                can_assert_membership=True,
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

        for _ in range(9):
            if deliver_one(transport) is None:
                break
        drain(limit=10, worker_id="native-reference-proof")
        return summary, phases, header_evidence(), console_evidence()

    @contextmanager
    def header_archive(self):
        """Actual memory-path events surrounded by modeled native files; no native proof."""
        from integrations.enterprise.verification import private_run_directory
        from integrations.zap_enterprise.source_host_evidence import HASHED
        from scripts.record_verification import json_bytes

        summary, phases, source, console = self.source_proof()
        parent = Path(__file__).resolve().parents[1] / "var/tests"
        workspace = parent / ("header-native-model-" + uuid.uuid4().hex)
        run = uuid.uuid4().hex
        directory = private_run_directory(workspace, run)
        (directory / "source/integrations/zap_enterprise").mkdir(parents=True)
        (directory / "evidence").mkdir()
        files = {}
        for name in (
            "source_runner",
            "source_server",
            "source_support",
            "source_settings",
            "capture",
            "source_reconciliation",
        ):
            relative = "integrations/zap_enterprise/" + name + ".py"
            raw = b"# Nonfunctional modeled snapshot marker; never executed.\n"
            (directory / "source" / relative).write_bytes(raw)
            files[relative] = hashlib.sha256(raw).hexdigest()
        manifest = {
            "files": files,
            "file_count": len(files),
            "sha256": hashlib.sha256(json_bytes(files)).hexdigest(),
        }
        footprint = {"claim": "nonfunctional archive model"}
        proof = reconcile(summary, phases, source, console)
        values = {
            "header-execution": summary,
            "source-captures": phases,
            "source-outbox": source,
            "console-events": console,
            "header-reconciliation": proof,
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
        hashes = {}
        for name, value in values.items():
            raw = json_bytes(value)
            (directory / "evidence" / (name + ".json")).write_bytes(raw)
            hashes[name] = hashlib.sha256(raw).hexdigest()
        runner = {
            "schema_version": 1,
            "profile": PROFILE,
            "run_id": run,
            "completed": True,
            "native_zap_executed": False,
            "receipt_sha256": {name: hashes[name] for name in HASHED},
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
            "source_http_requests": 19,
            "source_readiness_requests": 1,
            "collection": {
                "committed_claim_results": 8,
                "collector_transport_invocations": 8,
                "phase_deadline_reached": False,
            },
            "final_fault_reset": True,
            "processes_stopped": True,
            "duration_seconds": 1,
            "limits": ["model" for _ in range(3)],
        }
        for name, value in (
            ("header-runner", runner),
            ("allow-source", {"run_id": run, "runtime_verified": True}),
        ):
            (directory / "evidence" / (name + ".json")).write_bytes(json_bytes(value))
        (directory / "evidence/install.log").write_bytes(
            b"Nonfunctional modeled install; nothing installed.\n"
        )
        try:
            yield workspace, run, directory, manifest, footprint, runner
        finally:
            if not workspace.resolve().is_relative_to(parent.resolve()) or workspace.is_symlink():
                raise ValueError("Unsafe header model cleanup.")
            shutil.rmtree(workspace)

    def test_closed_host_archive_rechecks_actual_memory_events_without_promoting_native_zap(self):
        from integrations.zap_enterprise.source_host_evidence import validate_native

        with self.header_archive() as (workspace, run, _, manifest, footprint, _):
            proof = validate_native(workspace, run, manifest, footprint, now=timezone.now())
            self.assertEqual(proof["reconciliation"]["logical_source_events"], 8)
            self.assertFalse(proof["native_zap_executed"])
            self.assertFalse(proof["reconciliation"]["source_capture_attested"])

    def test_header_host_archive_rejects_wrong_profile_counts_gate_snapshot_and_shutdown(self):
        import copy

        from integrations.zap_enterprise.source_host_evidence import validate_native
        from scripts.record_verification import json_bytes

        with self.header_archive() as (workspace, run, directory, manifest, footprint, runner):
            for key, value in (
                ("profile", "reference-access-v2"),
                ("source_http_requests", 18),
                ("source_readiness_requests", True),
                ("native_zap_executed", True),
                ("processes_stopped", False),
            ):
                altered = copy.deepcopy(runner)
                altered[key] = value
                (directory / "evidence/header-runner.json").write_bytes(json_bytes(altered))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    validate_native(workspace, run, manifest, footprint, now=timezone.now())
            (directory / "evidence/header-runner.json").write_bytes(json_bytes(runner))
            (directory / "source/integrations/zap_enterprise/source_runner.py").write_bytes(
                b"# Altered modeled source.\n"
            )
            with self.assertRaises(ValueError):
                validate_native(workspace, run, manifest, footprint, now=timezone.now())

    def test_eight_actual_source_events_are_signed_delivered_processed_and_exactly_reconciled(self):
        summary, phases, source, console = self.source_proof()
        proof = reconcile(summary, phases, source, console)
        self.assertEqual(proof["logical_source_events"], 8)
        self.assertEqual(proof["logical_processed_events"], 8)
        self.assertEqual(proof["logical_cases"], 0)
        self.assertFalse(proof["runtime_attested"])
        self.assertFalse(proof["source_capture_attested"])
        self.assertEqual(set(summary["restoration_event_ids"]), {"document_member", "operator"})
        self.assertTrue(
            set(summary["restoration_event_ids"].values()).isdisjoint(
                {row["event_id"] for rows in phases.values() for row in rows}
            )
        )

    def test_missing_crossed_or_reused_restoration_binding_cannot_complete_reconciliation(self):
        import copy

        summary, phases, source, console = self.source_proof()
        for change in ("missing", "crossed", "reused"):
            altered = copy.deepcopy(summary)
            if change == "missing":
                altered["restoration_event_ids"]["document_member"] = str(uuid.uuid4())
            elif change == "crossed":
                altered["restoration_event_ids"] = {
                    account: summary["restoration_event_ids"][other]
                    for account, other in (
                        ("document_member", "operator"),
                        ("operator", "document_member"),
                    )
                }
            else:
                altered["restoration_event_ids"]["document_member"] = phases["fault"][1]["event_id"]
            with self.subTest(change=change), self.assertRaises(ValueError):
                reconcile(altered, phases, source, console)

    def test_unexplained_events_cases_fault_state_or_processing_discrepancy_fail(self):
        import copy

        summary, phases, source, console = self.source_proof()
        for change in ("fault", "extra", "case", "missing", "wrong_provenance"):
            altered_source, altered_console = copy.deepcopy(source), copy.deepcopy(console)
            if change == "fault":
                altered_source["header_fault"]["enabled"] = True
            elif change == "extra":
                altered_source["events"].append(altered_source["events"][0])
            elif change == "case":
                altered_console["cases"] = [{"unexpected": "synthetic"}]
            elif change == "missing":
                altered_console["events"].pop()
            else:
                altered_console["events"][0]["source"] = "synthetic_replay"
            with self.subTest(change=change), self.assertRaises(ValueError):
                reconcile(summary, phases, altered_source, altered_console)

    def test_header_operator_inventory_requires_one_disabled_fixed_pair(self):
        set_header_fault(True)
        with self.assertRaises(ValueError):
            header_evidence()
        set_header_fault(False)
        self.assertFalse(header_evidence()["header_fault"]["enabled"])
        row = BoundedHeaderFault.objects.get()
        row.user = self.users["operator"]
        row.save(update_fields=["user"])
        with self.assertRaises(ValueError):
            header_evidence()

    def test_actual_authenticated_capture_finding_correction_and_restoration_paths(self):
        summary, phases = exercise(MemoryHeaderClient, PASSWORDS, set_header_fault)
        self.assertTrue(summary["completed"])
        self.assertFalse(summary["native_zap_executed"])
        self.assertTrue(summary["fault_disabled"])
        self.assertEqual(summary["phase_requests"], {"fault": 5, "corrected": 5})
        self.assertEqual(summary["phase_attempted_requests"], {"fault": 5, "corrected": 5})
        self.assertEqual(summary["restoration_checks"], {"document_member": True, "operator": True})
        self.assertEqual(Outbox.objects.count(), 8)
        bindings = {row["event_id"] for rows in phases.values() for row in rows if row["event_id"]}
        self.assertEqual(len(bindings), 6)
        self.assertTrue(
            set(Outbox.objects.values_list("pk", flat=True))
            >= {uuid.UUID(value) for value in bindings}
        )
        for phase, rows in phases.items():
            har = json.loads(render_har(rows, phase, summary["captured_at"]))
            self.assertEqual(len(har["log"]["entries"]), 5)
        self.assertFalse(BoundedHeaderFault.objects.get().enabled)

    def test_only_permitted_member_document_response_loses_header(self):
        set_header_fault(True)
        self.assertNotIn("X-Content-Type-Options", self.member.get(DOC_PATH, secure=True))
        for client, path, status in (
            (self.owner, DOC_PATH, 200),
            (self.member, EXPENSE_PATH, 403),
            (self.member, "/identity/", 200),
            (Client(), DOC_PATH, 302),
        ):
            with self.subTest(path=path, status=status):
                response = client.get(path, secure=True)
                self.assertEqual(response.status_code, status)
                self.assertEqual(response["X-Content-Type-Options"], "nosniff")

    def test_header_control_cannot_grant_withdrawn_access(self):
        set_header_fault(True)
        Grant.objects.filter(resource_id=DOCUMENT_ID, user=self.users["document_member"]).delete()
        response = self.member.get(DOC_PATH, secure=True)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        with self.assertRaises(ValueError):
            set_header_fault(True)
        self.assertFalse(set_header_fault(False)["enabled"])

    def test_reset_survives_account_disable_and_preserves_original_expiry(self):
        set_header_fault(True)
        original = BoundedHeaderFault.objects.get()
        get_user_model().objects.filter(pk=self.users["document_member"].pk).update(is_active=False)
        self.assertFalse(set_header_fault(False)["enabled"])
        row = BoundedHeaderFault.objects.get()
        self.assertEqual(
            (row.started_at, row.expires_at), (original.started_at, original.expires_at)
        )
        self.assertFalse(row.enabled)

    def test_expired_and_future_faults_keep_default_protection(self):
        set_header_fault(True)
        for start in (timezone.now() - timedelta(minutes=6), timezone.now() + timedelta(minutes=1)):
            with self.subTest(start=start):
                BoundedHeaderFault.objects.update(
                    started_at=start, expires_at=start + timedelta(minutes=5)
                )
                self.assertEqual(
                    self.member.get(DOC_PATH, secure=True)["X-Content-Type-Options"], "nosniff"
                )

    def test_profile_is_opt_in_and_refuses_other_application_settings(self):
        set_header_fault(True)
        with override_settings(REFERENCE_HEADER_PROFILE=None):
            self.assertEqual(
                self.member.get(DOC_PATH, secure=True)["X-Content-Type-Options"], "nosniff"
            )
            with self.assertRaises(ImproperlyConfigured):
                set_header_fault(True)
        with override_settings(ROOT_URLCONF="config.urls"), self.assertRaises(ImproperlyConfigured):
            set_header_fault(True)

    def test_fault_bound_and_database_constraints_reject_unbounded_windows(self):
        for enabled, duration in ((1, 300), (True, True), (True, 0), (True, 601)):
            with self.subTest(enabled=enabled, duration=duration), self.assertRaises(ValueError):
                set_header_fault(enabled, duration)
        set_header_fault(True)
        with self.assertRaises(IntegrityError), transaction.atomic():
            BoundedHeaderFault.objects.update(expires_at=timezone.now() + timedelta(minutes=20))

    def test_authorization_bypass_cannot_be_combined_with_header_profile(self):
        set_regression(True)
        with self.assertRaises(ValueError):
            set_header_fault(True)
        set_regression(False)
        set_header_fault(True)
        set_regression(True)
        with self.assertRaises(ValueError):
            self.member.get(DOC_PATH, secure=True)

    def test_source_database_failure_never_returns_apparently_valid_capture(self):
        set_header_fault(True)
        with (
            patch(
                "reference_lab.header_probe.effective_access",
                side_effect=DatabaseError("synthetic"),
            ),
            self.assertRaises(DatabaseError),
        ):
            self.member.get(DOC_PATH, secure=True)

    def test_header_omission_refuses_corrupted_content_or_missing_baseline_header(self):
        set_header_fault(True)
        request = RequestFactory().get(DOC_PATH, secure=True)
        request.user = self.users["document_member"]
        for body, header in (
            ({"unexpected": "SYNTHETIC"}, "nosniff"),
            (
                {
                    "app": "documents",
                    "record_id": str(DOCUMENT_ID),
                    "synthetic_content": CONTENT["documents"],
                },
                None,
            ),
        ):
            with self.subTest(body=body, header=header):
                response = JsonResponse(body)
                if header:
                    response["X-Content-Type-Options"] = header
                with self.assertRaises(ValueError):
                    HeaderProbe(lambda _, response=response: response)(request)

    def test_interrupted_capture_resets_fault_and_keeps_partial_coverage(self):
        class Interrupted(MemoryHeaderClient):
            calls = 0

            def request(self, method, path):
                self.calls += 1
                if self.calls == 4:
                    raise TimeoutError("synthetic interruption")
                return super().request(method, path)

        summary, phases = exercise(Interrupted, PASSWORDS, set_header_fault)
        self.assertFalse(summary["completed"])
        self.assertEqual(summary["failure"], "source_capture_incomplete")
        self.assertEqual(summary["phase_requests"], {"fault": 1, "corrected": 0})
        self.assertEqual(summary["phase_attempted_requests"], {"fault": 2, "corrected": 0})
        self.assertTrue(summary["fault_disabled"])
        self.assertTrue(all(summary["restoration_checks"].values()))
        self.assertFalse(BoundedHeaderFault.objects.get().enabled)
        with self.assertRaises(ValueError):
            render_har(phases["fault"], "fault", summary["captured_at"])

    def test_reset_failure_cannot_be_completed_or_leak_exception_details(self):
        def broken_reset(enabled, seconds):
            if not enabled:
                raise DatabaseError("private diagnostic must not enter summary")
            return set_header_fault(enabled, seconds)

        summary, _ = exercise(MemoryHeaderClient, PASSWORDS, broken_reset)
        self.assertFalse(summary["completed"])
        self.assertFalse(summary["fault_disabled"])
        self.assertEqual(summary["failure"], "fault_reset_failed")
        self.assertNotIn("private diagnostic", json.dumps(summary))
        set_header_fault(False)
