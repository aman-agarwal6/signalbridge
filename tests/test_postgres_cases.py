"""Native-only case concurrency and an actual killed-process transaction check."""

import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import close_old_connections, connection, connections
from django.test import Client, TransactionTestCase, tag
from django.utils import timezone

from bridge.case_workflow import evidence_binding, operate
from bridge.models import (
    Audit,
    CaseTask,
    Event,
    Integration,
    Investigation,
    Membership,
    Note,
    ServiceCredential,
    ServiceRequest,
)
from bridge.service_api import request_signature
from bridge.services import WorkflowError
from bridge.worker import drain
from tests.test_processing_efficiency import observation, rows


@tag("native_postgres")
class PostgresCaseTests(TransactionTestCase):
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql", "This gate requires genuine PostgreSQL.")
        self.app = Integration.objects.create(slug="native-case-lab", name="Synthetic native case")
        self.user = get_user_model().objects.create(username="native-analyst")
        Membership.objects.create(user=self.user, integration=self.app, role="analyst")
        self.case = Investigation.objects.create(
            integration=self.app,
            rule="R1",
            correlation="c" * 64,
            title="Synthetic native investigation",
            severity="medium",
            explanation="Lab only",
        )
        Event.objects.bulk_create(
            rows(self.app, [observation(0, timezone.now(), app=self.app.slug)])
        )
        self.case.events.add(Event.objects.get())
        self.secret = "nonfunctional-native-service-fixture-" + "x" * 48
        ServiceCredential.objects.create(
            integration=self.app,
            key_id="native-task-key",
            secret_env="SB_SERVICE_NATIVE_TASK",
            capability="create_review_task",
        )
        environment = patch.dict(os.environ, {"SB_SERVICE_NATIVE_TASK": self.secret})
        environment.start()
        self.addCleanup(environment.stop)

    def independent(self, operation):
        close_old_connections()
        try:
            return operation()
        finally:
            connections.close_all()

    def send_task(self, identifier, binding):
        path = f"/api/v1/cases/{self.case.pk}/review-task/"
        raw = json.dumps(
            {
                "case_version": 1,
                "evidence_sha256": binding,
                "idempotency_key": identifier,
                "task_kind": "review_case_evidence",
            }
        ).encode()
        at, nonce = timezone.now().isoformat(), str(uuid.uuid4())
        return (
            Client()
            .post(
                path,
                raw,
                content_type="application/json",
                **{
                    "HTTP_X_SB_SERVICE_KEY": "native-task-key",
                    "HTTP_X_SB_SERVICE_NONCE": nonce,
                    "HTTP_X_SB_SERVICE_TIME": at,
                    "HTTP_X_SB_SERVICE_SIGNATURE": request_signature(
                        self.secret,
                        "native-task-key",
                        nonce,
                        at,
                        "POST",
                        path,
                        raw,
                    ),
                },
            )
            .status_code
        )

    def test_concurrent_case_notes_have_one_version_winner(self):
        def save_note():
            try:
                operate(
                    self.user,
                    self.case.pk,
                    1,
                    "structured_note",
                    {
                        "kind": "observed_fact",
                        "note": "Synthetic retained fact.",
                    },
                )
                return "saved"
            except WorkflowError:
                return "stale"

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(self.independent, save_note) for _ in range(2)]
            self.assertEqual(
                sorted(future.result(timeout=10) for future in futures), ["saved", "stale"]
            )
        self.assertEqual(Note.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="case.structured_note").count(), 1)
        self.case.refresh_from_db()
        self.assertEqual(self.case.version, 2)

    def test_concurrent_duplicate_review_requests_create_one_logical_task(self):
        identifier, binding = str(uuid.uuid4()), evidence_binding(self.case)
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self.independent, lambda: self.send_task(identifier, binding))
                for _ in range(4)
            ]
            statuses = [future.result(timeout=10) for future in futures]
        self.assertEqual(sorted(statuses), [200, 200, 200, 201])
        self.assertEqual(CaseTask.objects.count(), 1)
        self.assertEqual(ServiceRequest.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="case.machine_review_task").count(), 1)

    def test_concurrent_distinct_review_requests_reject_stale_case(self):
        binding = evidence_binding(self.case)
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(
                    self.independent, lambda: self.send_task(str(uuid.uuid4()), binding)
                )
                for _ in range(2)
            ]
            self.assertEqual(sorted(future.result(timeout=10) for future in futures), [201, 409])
        self.assertEqual(CaseTask.objects.count(), 1)
        self.assertEqual(ServiceRequest.objects.count(), 1)


@tag("native_postgres")
class PostgresProcessCrashTests(TransactionTestCase):
    def test_killed_process_rolls_back_uncommitted_work_then_another_worker_recovers(self):
        self.assertEqual(connection.vendor, "postgresql")
        self.assertEqual(settings.SETTINGS_MODULE, "config.in_network_postgres_settings")
        self.assertEqual(connection.settings_dict["NAME"], "test_sb_enterprise_verification")
        self.assertEqual(sys.platform, "linux")
        app = Integration.objects.create(slug="native-crash-lab", name="Synthetic crash target")
        now = timezone.now().replace(second=0, microsecond=0)
        Event.objects.bulk_create(rows(app, [observation(i, now, app=app.slug) for i in range(3)]))
        with tempfile.TemporaryDirectory(prefix="sb-crash-", dir="/tmp") as directory:
            marker = Path(directory) / "ready.json"
            environment = {**os.environ, "SB_NATIVE_CRASH_CHILD": "1"}
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(settings.BASE_DIR / "integrations/enterprise/native_crash_probe.py"),
                    str(marker),
                ],
                cwd=settings.BASE_DIR,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 6
                while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(marker.is_file(), "Child did not reach uncommitted work.")
                self.assertEqual(
                    json.loads(marker.read_text()), {"state": "uncommitted", "pid": child.pid}
                )
                self.assertEqual(Event.objects.filter(state="pending").count(), 3)
                self.assertEqual(Investigation.objects.count(), 0)
                child.kill()
                child.wait(timeout=3)
                self.assertEqual(child.returncode, -9)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=3)
        self.assertEqual(drain(worker_id="pg-recovery-worker"), 3)
        self.assertEqual(Event.objects.filter(state="processed", processing_attempts=1).count(), 3)
        self.assertEqual(Investigation.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="case.created").count(), 1)
        self.assertEqual(Investigation.objects.get().events.count(), 3)
