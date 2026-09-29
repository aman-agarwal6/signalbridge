import os
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.utils import timezone

from bridge.contract import ContractError, canonical, signature, validate_event
from bridge.engine import detections, triage
from bridge.evaluation import evaluate
from bridge.models import (
    Audit,
    Event,
    IngestKey,
    Integration,
    Investigation,
    Membership,
    Note,
)
from bridge.services import WorkflowError, create_replay, decide_replay
from bridge.worker import drain

SECRET = "local-test-only-" + "x" * 50


def sample(app="bettail", **changes):
    result = {
        "schema_version": 1,
        "event_id": str(uuid.uuid4()),
        "app": app,
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
    result.update(changes)
    return result


class SecurityTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="bettail", name="BetTail")
        cls.other = Integration.objects.create(slug="netted", name="Netted")
        IngestKey.objects.create(
            integration=cls.app, key_id="test-key", secret_env="SB_TEST_KEY", environment="test"
        )
        IngestKey.objects.create(
            integration=cls.other, key_id="other-key", secret_env="SB_TEST_KEY", environment="test"
        )
        cls.users = {}
        for role in ("viewer", "analyst", "reviewer"):
            u = get_user_model().objects.create_user(
                username=role, password="long-test-password-123"
            )
            Membership.objects.create(user=u, integration=cls.app, role=role)
            cls.users[role] = u
        cls.stranger = get_user_model().objects.create_user(
            username="stranger", password="long-test-password-123"
        )
        Membership.objects.create(user=cls.stranger, integration=cls.other, role="reviewer")

    def setUp(self):
        self.env = patch.dict(os.environ, {"SB_TEST_KEY": SECRET})
        self.env.start()
        self.addCleanup(self.env.stop)

    def send(
        self,
        data=None,
        app="bettail",
        key="test-key",
        secret=SECRET,
        sent_at=None,
        raw=None,
        **extra,
    ):
        raw = raw if raw is not None else canonical(data or sample(app))
        sent_at = sent_at or timezone.now().isoformat()
        headers = {
            "HTTP_X_SB_KEY": key,
            "HTTP_X_SB_TIME": sent_at,
            "HTTP_X_SB_SIGNATURE": signature(secret, app, key, sent_at, raw),
        }
        headers.update(extra)
        return self.client.post(
            "/api/v1/events/" + app + "/",
            data=raw,
            content_type="application/json",
            **headers,
        )

    def case(self, app=None):
        return Investigation.objects.create(
            integration=app or self.app,
            rule="R1",
            correlation=uuid.uuid4().hex,
            title="Lab case",
            severity="medium",
            explanation="Lab",
        )

    def test_signed_event_accepted_and_queued(self):
        e = sample()
        r = self.send(e)
        self.assertEqual(r.status_code, 202)
        self.assertEqual(Event.objects.get().state, "pending")

    def test_forged_signature_rejected(self):
        self.assertEqual(self.send(secret="z" * 64).status_code, 401)
        self.assertEqual(Event.objects.count(), 0)

    def test_app_body_cannot_override_key_scope(self):
        self.assertEqual(self.send(sample("netted")).status_code, 400)

    def test_app_key_cannot_be_reused_at_other_endpoint(self):
        self.assertEqual(self.send(sample("netted"), app="netted").status_code, 401)

    def test_fresh_resign_preserves_duplicate_identity(self):
        e = sample()
        self.assertEqual(self.send(e).status_code, 202)
        self.assertEqual(self.send(e).json()["status"], "duplicate")
        self.assertEqual(Event.objects.count(), 1)

    def test_changed_duplicate_is_conflict(self):
        e = sample()
        self.send(e)
        e["outcome"] = "allowed"
        self.assertEqual(self.send(e).status_code, 409)
        self.assertEqual(Event.objects.get().outcome, "denied")

    def test_same_id_different_app_has_independent_namespace(self):
        e = sample()
        self.send(e)
        e["app"] = "netted"
        self.assertEqual(self.send(e, app="netted", key="other-key").status_code, 202)
        self.assertEqual(Event.objects.count(), 2)

    def test_stale_signed_request_rejected(self):
        self.assertEqual(
            self.send(sent_at=(timezone.now() - timedelta(minutes=6)).isoformat()).status_code,
            401,
        )

    def test_future_signed_request_rejected(self):
        self.assertEqual(
            self.send(sent_at=(timezone.now() + timedelta(minutes=6)).isoformat()).status_code,
            401,
        )

    def test_delayed_event_with_fresh_signature_is_accepted(self):
        self.assertEqual(
            self.send(
                sample(occurred_at=(timezone.now() - timedelta(days=2)).isoformat())
            ).status_code,
            202,
        )

    def test_too_old_event_rejected(self):
        self.assertEqual(
            self.send(
                sample(occurred_at=(timezone.now() - timedelta(days=8)).isoformat())
            ).status_code,
            400,
        )

    def test_future_event_rejected(self):
        self.assertEqual(
            self.send(
                sample(occurred_at=(timezone.now() + timedelta(minutes=2)).isoformat())
            ).status_code,
            400,
        )

    def test_extra_sensitive_fields_rejected(self):
        self.assertEqual(self.send(sample(email="person@example.test")).status_code, 400)
        self.assertEqual(Event.objects.count(), 0)

    def test_raw_identifiers_rejected(self):
        self.assertEqual(self.send(sample(actor="real-person@example.test")).status_code, 400)

    def test_invalid_enum_rejected(self):
        self.assertEqual(self.send(sample(reason="secret-token-value")).status_code, 400)

    def test_bool_schema_version_not_accepted_as_integer(self):
        self.assertEqual(self.send(sample(schema_version=True)).status_code, 400)

    def test_duplicate_json_keys_rejected(self):
        self.assertEqual(self.send(raw=b'{"app":"bettail","app":"netted"}').status_code, 400)

    def test_nonfinite_json_rejected(self):
        self.assertEqual(self.send(raw=b'{"a":NaN}').status_code, 400)

    def test_oversize_body_rejected(self):
        self.assertEqual(self.send(raw=b" " * 16385).status_code, 413)

    def test_disabled_integration_rejects(self):
        self.app.enabled = False
        self.app.save()
        self.assertEqual(self.send().status_code, 404)

    def test_revoked_key_rejects(self):
        IngestKey.objects.filter(key_id="test-key").update(active=False)
        self.assertEqual(self.send().status_code, 401)

    def test_rotated_key_accepts_without_restoring_old_key(self):
        IngestKey.objects.filter(key_id="test-key").update(active=False)
        IngestKey.objects.create(
            integration=self.app, key_id="rotated", secret_env="SB_TEST_KEY", environment="test"
        )
        self.assertEqual(self.send(key="rotated").status_code, 202)
        self.assertEqual(self.send().status_code, 401)

    def test_login_required_on_every_console_surface(self):
        for p in (
            "/",
            "/integrations/",
            "/investigations/",
            "/checks/",
            "/replay/",
            "/requirements/",
            "/export/",
        ):
            with self.subTest(path=p):
                self.assertEqual(self.client.get(p).status_code, 302)

    def test_authenticated_pages_render(self):
        self.client.force_login(self.users["viewer"])
        for p in (
            "/",
            "/integrations/",
            "/investigations/",
            "/checks/",
            "/replay/",
            "/requirements/",
        ):
            with self.subTest(path=p):
                self.assertEqual(self.client.get(p).status_code, 200)

    def test_cross_app_list_and_export_blocked(self):
        self.client.force_login(self.users["viewer"])
        for p in (
            "/",
            "/integrations/",
            "/investigations/",
            "/checks/",
            "/replay/",
            "/requirements/",
            "/export/",
        ):
            with self.subTest(path=p):
                self.assertEqual(self.client.get(p + "?app=netted").status_code, 404)

    def test_cross_app_case_read_and_mutation_blocked(self):
        case = self.case(self.other)
        self.client.force_login(self.users["analyst"])
        url = f"/investigations/{case.pk}/"
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(
            self.client.post(
                url, {"action": "note", "version": 1, "note": "intrusion"}
            ).status_code,
            404,
        )
        self.assertEqual(Note.objects.count(), 0)

    def test_viewer_cannot_mutate_case(self):
        case = self.case()
        self.client.force_login(self.users["viewer"])
        self.assertEqual(
            self.client.post(
                f"/investigations/{case.pk}/",
                {"action": "note", "version": 1, "note": "x"},
            ).status_code,
            403,
        )

    def test_csrf_required_for_case_and_replay(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.users["analyst"])
        case = self.case()
        self.assertEqual(
            client.post(
                f"/investigations/{case.pk}/",
                {"action": "note", "version": 1, "note": "x"},
            ).status_code,
            403,
        )
        self.assertEqual(
            client.post("/replay/", {"action": "create", "policy": "revised"}).status_code,
            403,
        )

    def test_analyst_note_is_escaped_and_audited(self):
        case = self.case()
        self.client.force_login(self.users["analyst"])
        url = f"/investigations/{case.pk}/"
        self.client.post(url, {"action": "note", "version": 1, "note": "<script>alert(1)</script>"})
        response = self.client.get(url)
        self.assertContains(response, "&lt;script&gt;")
        self.assertNotContains(response, "<script>alert")
        self.assertTrue(Audit.objects.filter(action="case.note").exists())

    def test_stale_case_change_does_not_overwrite(self):
        case = self.case()
        self.client.force_login(self.users["analyst"])
        url = f"/investigations/{case.pk}/"
        self.client.post(
            url,
            {
                "action": "disposition",
                "version": 1,
                "status": "resolved",
                "rationale": "Verified the retained evidence and completed this review.",
            },
        )
        self.client.post(
            url,
            {
                "action": "disposition",
                "version": 1,
                "status": "false_positive",
                "rationale": "Stale attempt must not overwrite the first decision.",
            },
        )
        case.refresh_from_db()
        self.assertEqual(case.status, "resolved")
        self.assertEqual(case.version, 2)

    def test_export_only_contains_members_app(self):
        self.client.force_login(self.users["viewer"])
        self.send(sample())
        self.send(sample("netted"), app="netted", key="other-key")
        report = self.client.get("/export/").json()
        self.assertEqual(report["application"], "bettail")
        self.assertEqual(report["counts"]["accepted_events"], 1)

    def test_worker_groups_and_deduplicates_out_of_order_events(self):
        now = timezone.now().replace(minute=0, second=0, microsecond=0)
        for i in (4, 1, 3, 2):
            self.send(
                sample(
                    resource=f"{i:064x}",
                    occurred_at=(now + timedelta(seconds=i)).isoformat(),
                )
            )
            drain()
        self.assertEqual(Investigation.objects.filter(rule="R1").count(), 1)
        self.assertEqual(Investigation.objects.get().events.count(), 4)
        self.assertEqual(Event.objects.filter(state="processed").count(), 4)
        drain()
        self.assertEqual(Investigation.objects.count(), 1)

    def test_worker_r2_independent_of_repeated_failures(self):
        self.send(sample(outcome="allowed", reason="membership_removed"))
        drain()
        self.assertEqual(Investigation.objects.get().rule, "R2")

    def test_worker_cannot_mix_apps(self):
        for i in range(2):
            self.send(sample(resource=f"{i:064x}"))
        self.send(sample("netted", resource="f" * 64), app="netted", key="other-key")
        drain()
        self.assertEqual(Investigation.objects.count(), 0)

    def test_worker_failure_rolls_back_and_records_retry(self):
        self.send(sample(outcome="allowed", reason="membership_removed"))
        with patch("bridge.worker.detections", side_effect=RuntimeError("private source error")):
            with self.assertRaises(RuntimeError):
                drain()
        event = Event.objects.get()
        self.assertEqual(event.attempts, 1)
        self.assertEqual(event.state, "pending")
        self.assertEqual(event.error_code, "processing_failed")
        self.assertEqual(Investigation.objects.count(), 0)
        Event.objects.update(available_at=timezone.now())
        drain()
        self.assertEqual(Investigation.objects.count(), 1)

    def test_repeated_processing_failure_goes_to_dead_letter(self):
        self.send()
        with patch("bridge.worker.detections", side_effect=RuntimeError()):
            for _ in range(5):
                Event.objects.update(available_at=timezone.now())
                with self.assertRaises(RuntimeError):
                    drain()
        self.assertEqual(Event.objects.get().state, "dead")

    def test_hand_calculated_fixture_results(self):
        _, _, unsafe = evaluate("unsafe", "bettail")
        _, _, revised = evaluate("revised", "bettail")
        self.assertEqual(
            (unsafe["events"], unsafe["episodes"], unsafe["baseline_cases"]), (12, 8, 7)
        )
        self.assertEqual(
            (unsafe["reviewable_cases"], unsafe["retained_suspicious_episodes"]), (2, 1)
        )
        self.assertEqual(
            (revised["reviewable_cases"], revised["retained_suspicious_episodes"]),
            (6, 5),
        )
        self.assertEqual(revised["case_reduction_percent"], 14.29)

    def test_unsafe_candidate_cannot_be_approved(self):
        proposal = create_replay(self.users["analyst"], self.app, "unsafe")
        with self.assertRaisesRegex(WorkflowError, "Approval blocked"):
            decide_replay(self.users["reviewer"], proposal.pk, "approved", 1)
        proposal.refresh_from_db()
        self.assertEqual(proposal.status, "pending")

    def test_unsafe_can_be_rejected_and_revised_approved(self):
        for policy, decision in (("unsafe", "rejected"), ("revised", "approved")):
            p = create_replay(self.users["analyst"], self.app, policy)
            decide_replay(self.users["reviewer"], p.pk, decision, 1)
            p.refresh_from_db()
            self.assertEqual(p.status, decision)

    def test_self_approval_blocked(self):
        p = create_replay(self.users["reviewer"], self.app, "revised")
        with self.assertRaisesRegex(WorkflowError, "second person"):
            decide_replay(self.users["reviewer"], p.pk, "approved", 1)

    def test_analyst_cannot_approve(self):
        p = create_replay(self.users["reviewer"], self.app, "revised")
        with self.assertRaises(PermissionError):
            decide_replay(self.users["analyst"], p.pk, "approved", 1)

    def test_other_app_reviewer_cannot_approve(self):
        p = create_replay(self.users["analyst"], self.app, "revised")
        with self.assertRaises(PermissionError):
            decide_replay(self.stranger, p.pk, "approved", 1)

    def test_replay_second_decision_is_blocked(self):
        p = create_replay(self.users["analyst"], self.app, "revised")
        decide_replay(self.users["reviewer"], p.pk, "approved", 1)
        with self.assertRaises(WorkflowError):
            decide_replay(self.users["reviewer"], p.pk, "rejected", 1)

    def test_tampered_stored_metrics_cannot_be_approved(self):
        p = create_replay(self.users["analyst"], self.app, "unsafe")
        p.result["safe"] = True
        p.save()
        with self.assertRaisesRegex(WorkflowError, "Evidence changed"):
            decide_replay(self.users["reviewer"], p.pk, "approved", 1)

    def test_changed_engine_hash_requires_new_comparison(self):
        p = create_replay(self.users["analyst"], self.app, "revised")
        p.engine_hash = "a" * 64
        p.save()
        with self.assertRaisesRegex(WorkflowError, "Evidence changed"):
            decide_replay(self.users["reviewer"], p.pk, "approved", 1)

    def test_security_headers_and_no_cache(self):
        response = self.client.get("/login/")
        self.assertIn("script-src 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_sign_in_throttles_repeated_bad_credentials(self):
        for _ in range(8):
            self.client.post("/login/", {"username": "viewer", "password": "bad"})
        response = self.client.post(
            "/login/", {"username": "viewer", "password": "long-test-password-123"}
        )
        self.assertContains(response, "Too many attempts")

    def test_unconfigured_key_fails_closed(self):
        with patch.dict(os.environ, {"SB_TEST_KEY": ""}):
            self.assertEqual(self.send().status_code, 401)

    def test_key_cannot_change_environment(self):
        self.assertEqual(self.send(sample(environment="lab")).status_code, 400)

    def test_source_provenance_is_bound_to_key_not_payload(self):
        self.send(sample())
        self.assertEqual(Event.objects.get().source, "migration_lab")
        self.assertEqual(self.send(sample(source="synthetic_demo")).status_code, 400)

    def test_different_source_cannot_reclassify_existing_event(self):
        IngestKey.objects.create(
            integration=self.app,
            key_id="synthetic",
            secret_env="SB_TEST_KEY",
            environment="test",
            source="synthetic_demo",
        )
        event = sample()
        self.send(event)
        self.assertEqual(self.send(event, key="synthetic").status_code, 409)

    def test_worker_never_combines_synthetic_and_observed_sources(self):
        IngestKey.objects.create(
            integration=self.app,
            key_id="synthetic",
            secret_env="SB_TEST_KEY",
            environment="test",
            source="synthetic_demo",
        )
        for n in (1, 2):
            self.send(sample(resource=f"{n:064x}"))
        self.send(sample(resource=f"{3:064x}"), key="synthetic")
        drain()
        self.assertEqual(Investigation.objects.count(), 0)

    def test_historical_comparison_is_labelled_after_engine_changes(self):
        proposal = create_replay(self.users["analyst"], self.app, "revised")
        proposal.engine_hash = "f" * 64
        proposal.save()
        self.client.force_login(self.users["viewer"])
        self.assertContains(self.client.get("/replay/"), "Historical comparison")

    def test_invalid_replay_identifier_is_handled_without_server_error(self):
        self.client.force_login(self.users["reviewer"])
        response = self.client.post(
            "/replay/",
            {"action": "decide", "replay": "invalid", "decision": "approved", "version": 1},
            follow=True,
        )
        self.assertContains(response, "Invalid proposal identifier")


class PureEngineTests(TestCase):
    def test_rolling_window_detects_the_former_fixed_bucket_edge(self):
        events = [
            sample(resource=f"{i:064x}", occurred_at=t)
            for i, t in enumerate(
                [
                    "2026-09-22T12:04:59+00:00",
                    "2026-09-22T12:05:00+00:00",
                    "2026-09-22T12:05:01+00:00",
                ]
            )
        ]
        result = detections(events)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rule"], "R1")
        self.assertEqual(set(result[0]["event_ids"]), {event["event_id"] for event in events})

    def test_runtime_never_uses_benchmark_labels(self):
        e = sample()
        plain = triage([e], "revised")
        e["suspicious"] = False
        self.assertEqual(triage([e], "revised"), plain)
        with self.assertRaises(ContractError):
            validate_event(e, "bettail")

    def test_future_context_does_not_suppress(self):
        now = timezone.now()
        e = sample(
            outcome="not_visible",
            reason="resource_unavailable",
            context={
                "managed_device": True,
                "reauthenticated": True,
                "valid_from": (now - timedelta(days=1)).isoformat(),
                "valid_to": (now + timedelta(days=1)).isoformat(),
                "known_at": (now + timedelta(seconds=1)).isoformat(),
            },
        )
        self.assertEqual(len(triage([e], "revised")), 1)

    def test_same_resource_retries_are_not_scanning(self):
        self.assertEqual(detections([sample() for _ in range(4)]), [])
