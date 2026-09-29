"""Regression cases from the builder-operated core security/correctness review."""

import json
import os
import subprocess
import sys
import uuid
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db.models.query import QuerySet
from django.test import TestCase
from django.utils import timezone

from bridge.contract import ContractError, canonical, signature, timestamp, validate_event
from bridge.engine import detections, triage
from bridge.evaluation import evaluate
from bridge.models import Audit, Event, IngestKey, Integration, Investigation, Membership
from bridge.services import allowed, create_replay
from bridge.worker import process_one

SECRET = "synthetic-audit-key-" + "x" * 48


def observation(**changes):
    data = {
        "schema_version": 1,
        "event_id": str(uuid.uuid4()),
        "app": "bettail",
        "environment": "test",
        "occurred_at": timezone.now().isoformat(),
        "actor": "a" * 64,
        "resource": "b" * 64,
        "episode": str(uuid.uuid4()),
        "operation": "private_record.read",
        "outcome": "denied",
        "reason": "membership_required",
        "context": None,
    }
    data.update(changes)
    return data


class CoreBoundaryAuditTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="bettail", name="BetTail")
        cls.key = IngestKey.objects.create(
            integration=cls.app, key_id="audit-key", secret_env="SB_AUDIT_KEY", environment="test"
        )
        cls.author = get_user_model().objects.create_user(username="audit-analyst")
        Membership.objects.create(user=cls.author, integration=cls.app, role="analyst")

    def setUp(self):
        self.environment = patch.dict(os.environ, {"SB_AUDIT_KEY": SECRET})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def send(self, data=None, sent_at=None, authentic=True):
        raw = canonical(data or observation())
        sent_at = sent_at or timezone.now().isoformat()
        return self.client.post(
            "/api/v1/events/bettail/",
            raw,
            content_type="application/json",
            HTTP_X_SB_KEY="audit-key",
            HTTP_X_SB_TIME=sent_at,
            HTTP_X_SB_SIGNATURE=signature(SECRET, "bettail", "audit-key", sent_at, raw)
            if authentic
            else "0" * 64,
        )

    def test_unsigned_extreme_timezone_timestamp_is_a_rejection_not_server_error(self):
        for value in ("0001-01-01T00:00:00+23:59", "9999-12-31T23:59:59-23:59"):
            with self.subTest(boundary=value[:4]):
                self.assertEqual(self.send(sent_at=value, authentic=False).status_code, 401)
        self.assertFalse(Event.objects.exists())

    def test_extreme_event_or_context_timestamp_is_rejected_by_contract(self):
        invalid = "0001-01-01T00:00:00+23:59"
        with self.assertRaises(ContractError):
            timestamp(invalid)
        self.assertEqual(self.send(observation(occurred_at=invalid)).status_code, 400)
        data = observation(
            context={
                "managed_device": True,
                "reauthenticated": True,
                "valid_from": invalid,
                "valid_to": timezone.now().isoformat(),
                "known_at": timezone.now().isoformat(),
            }
        )
        self.assertEqual(self.send(data).status_code, 400)

    def test_invalid_enum_container_raises_contract_error(self):
        for field in ("operation", "outcome", "reason"):
            with self.subTest(field=field), self.assertRaises(ContractError):
                validate_event(observation(**{field: {"unexpected": "object"}}), "bettail")

    def test_inactive_principal_cannot_use_membership_services(self):
        self.author.is_active = False
        self.author.save(update_fields=["is_active"])
        self.assertFalse(allowed(self.author, self.app))
        with self.assertRaises(PermissionError):
            create_replay(self.author, self.app, "revised")

    def test_key_scope_changed_after_authentication_cannot_be_accepted_with_stale_scope(self):
        def change_scope(data, app):
            validated = validate_event(data, app)
            IngestKey.objects.filter(pk=self.key.pk).update(environment="lab")
            return validated

        with patch("bridge.ingestion.validate_event", side_effect=change_scope):
            self.assertEqual(self.send().status_code, 401)
        self.assertFalse(Event.objects.exists())


class RuleSemanticsAuditTests(TestCase):
    def test_legitimate_membership_removal_is_not_a_successful_revoked_read(self):
        event = observation(
            operation="membership.change", outcome="allowed", reason="membership_removed"
        )
        self.assertEqual(detections([event]), [])
        self.assertEqual(triage([event], "baseline"), [])

    def test_failed_session_checks_are_not_private_resource_scanning(self):
        at = timezone.now().replace(minute=0, second=1, microsecond=0).isoformat()
        events = [
            observation(
                operation="session.verify",
                reason="session_invalid",
                resource=f"{number:064x}",
                occurred_at=at,
            )
            for number in range(3)
        ]
        self.assertEqual(detections(events), [])

    def evaluate_fixture(self, events, labels):
        def fixture(value):
            raw = json.dumps(value)
            return SimpleNamespace(read_text=lambda: raw, read_bytes=lambda: raw.encode())

        with patch(
            "bridge.evaluation.fixture_paths", return_value=(fixture(events), fixture(labels))
        ):
            return evaluate("unsafe", "bettail")

    def test_duplicate_label_cannot_hide_a_required_suspicious_episode(self):
        now = timezone.now()
        unsafe = observation(
            context={
                "managed_device": True,
                "reauthenticated": True,
                "valid_from": (now - timedelta(minutes=1)).isoformat(),
                "valid_to": (now + timedelta(minutes=1)).isoformat(),
                "known_at": now.isoformat(),
            }
        )
        retained = observation(outcome="allowed", reason="membership_removed")
        labels = [
            {
                "app": "bettail",
                "episode": unsafe["episode"],
                "scenario": "required",
                "suspicious": True,
            },
            {
                "app": "bettail",
                "episode": unsafe["episode"],
                "scenario": "duplicate",
                "suspicious": False,
            },
            {
                "app": "bettail",
                "episode": retained["episode"],
                "scenario": "retained",
                "suspicious": True,
            },
        ]
        with self.assertRaises(ValueError):
            self.evaluate_fixture([unsafe, retained], labels)

    def test_one_episode_cannot_mix_actors_or_environments(self):
        first = observation()
        labels = [
            {
                "app": "bettail",
                "episode": first["episode"],
                "scenario": "required",
                "suspicious": True,
            }
        ]
        for changes in ({"actor": "c" * 64}, {"environment": "lab"}):
            second = observation(episode=first["episode"], **changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.evaluate_fixture([first, second], labels)

    def test_evaluation_rejects_duplicate_events_and_nonboolean_labels(self):
        event = observation()
        label = {
            "app": "bettail",
            "episode": event["episode"],
            "scenario": "required",
            "suspicious": True,
        }
        with self.assertRaises(ValueError):
            self.evaluate_fixture([event, event], [label])
        with self.assertRaises(ValueError):
            self.evaluate_fixture([event], [{**label, "suspicious": "false"}])


class WorkerAuditTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="bettail", name="BetTail")

    def make_event(self, resource=1, **changes):
        data = observation(
            resource=f"{resource:064x}",
            occurred_at=timezone.now().replace(minute=0, second=1, microsecond=0).isoformat(),
        )
        data.update(changes.pop("payload_changes", {}))
        row = dict(
            integration=self.app,
            event_id=data["event_id"],
            occurred_at=timestamp(data["occurred_at"]),
            actor=data["actor"],
            resource=data["resource"],
            episode=data["episode"],
            operation=data["operation"],
            outcome=data["outcome"],
            reason=data["reason"],
            environment=data["environment"],
            source="migration_lab",
            payload=data,
            digest="a" * 64,
            available_at=timezone.now(),
        )
        row.update(changes)
        return Event.objects.create(**row)

    def make_case(self):
        for resource in (1, 2, 3):
            self.make_event(resource)
        while process_one():
            pass
        return Investigation.objects.get()

    def test_late_evidence_reopens_closed_case_and_invalidates_stale_review(self):
        case = self.make_case()
        case.status = "resolved"
        case.save(update_fields=["status"])
        version = case.version
        late = self.make_event(4)
        self.assertTrue(process_one())
        case.refresh_from_db()
        self.assertEqual(case.status, "open")
        self.assertEqual(case.version, version + 1)
        self.assertTrue(case.events.filter(pk=late.pk).exists())
        self.assertTrue(
            Audit.objects.filter(object_id=str(case.pk), action="case.reopened").exists()
        )

    def test_new_evidence_invalidates_open_case_version_but_duplicate_processing_does_not(self):
        case = self.make_case()
        version = case.version
        late = self.make_event(4)
        process_one()
        case.refresh_from_db()
        self.assertEqual(case.version, version + 1)
        Event.objects.filter(pk=late.pk).update(state="pending")
        process_one()
        case.refresh_from_db()
        self.assertEqual(case.version, version + 1)

    def test_stale_candidate_uses_current_retry_attempt_count(self):
        row = self.make_event()
        original = QuerySet.first
        changed = False

        def first(queryset):
            nonlocal changed
            value = original(queryset)
            if queryset.model is Event and not changed:
                changed = True
                Event.objects.filter(pk=row.pk).update(attempts=4)
            return value

        with (
            patch.object(QuerySet, "first", first),
            patch("bridge.worker.detections", side_effect=RuntimeError("synthetic failure")),
        ):
            with self.assertRaises(RuntimeError):
                process_one()
        row.refresh_from_db()
        self.assertEqual((row.attempts, row.state), (5, "dead"))

    def test_candidate_deferred_after_selection_is_not_processed_early(self):
        row = self.make_event()
        original = QuerySet.first
        changed = False

        def first(queryset):
            nonlocal changed
            value = original(queryset)
            if queryset.model is Event and not changed:
                changed = True
                Event.objects.filter(pk=row.pk).update(
                    available_at=timezone.now() + timedelta(minutes=5)
                )
            return value

        with patch.object(QuerySet, "first", first), patch("bridge.worker.detections") as detector:
            process_one()
        detector.assert_not_called()
        row.refresh_from_db()
        self.assertEqual((row.attempts, row.state), (0, "pending"))

    def test_correlation_capacity_fails_visibly_instead_of_silently_truncating(self):
        rows = [self.make_event(resource) for resource in (1, 2, 3, 4)]
        Event.objects.filter(pk=rows[0].pk).update(attempts=4)
        with patch("bridge.worker.MAX_CORRELATION_EVENTS", 3):
            with self.assertRaisesRegex(ValueError, "capacity"):
                process_one()
        rows[0].refresh_from_db()
        self.assertEqual((rows[0].state, rows[0].error_code), ("dead", "correlation_capacity"))
        self.assertFalse(Investigation.objects.exists())

    def test_evidence_write_failure_rolls_back_case_changes_but_records_retry(self):
        for resource in (1, 2, 3):
            self.make_event(resource)
        with patch(
            "bridge.worker.Audit.objects.create",
            side_effect=RuntimeError("synthetic audit failure"),
        ):
            with self.assertRaises(RuntimeError):
                process_one()
        self.assertFalse(Investigation.objects.exists())
        self.assertEqual(Event.objects.filter(state="pending", attempts=1).count(), 1)


class DatabaseSettingsAuditTests(TestCase):
    def settings_child(self, **changes):
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.upper().startswith(("SB_", "PG"))
        }
        environment.update(
            SB_MODE="local", SB_DB_HOST="localhost", SB_DB_PASSWORD="synthetic-local-password"
        )
        environment.update(changes)
        code = "import json,os; from config import settings; db=settings.DATABASES['default']; print(json.dumps({'host':db['HOST'],'options':db.get('OPTIONS',{}),'pg_override_present':'PGHOSTADDR' in os.environ}))"
        return subprocess.run(
            [sys.executable, "-c", code],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def test_local_database_rejects_inherited_libpq_target_overrides(self):
        for name in ("PGHOSTADDR", "PGSERVICE"):
            result = self.settings_child(**{name: "synthetic-override"})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ImproperlyConfigured", result.stderr)

    def test_local_loopback_host_is_bound_to_an_explicit_network_address(self):
        result = self.settings_child()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["options"]["hostaddr"], "127.0.0.1")

    def test_nonlocal_settings_do_not_mutate_inherited_environment(self):
        result = self.settings_child(
            SB_MODE="production",
            SB_SECRET_KEY="x" * 64,
            SB_DB_HOST="database.invalid",
            PGHOSTADDR="198.51.100.50",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["pg_override_present"])
