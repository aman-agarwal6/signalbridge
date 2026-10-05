"""Exporter denial paths and truthful operational observations; no native tools."""

import json
import math
import os
import re
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import DatabaseError, IntegrityError, transaction
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from bridge.models import (
    Event,
    Integration,
    Membership,
    MetricsScrapeState,
    SocBatch,
    SocDelivery,
    SocStream,
    WorkerHeartbeat,
)
from bridge.monitoring import MonitoringUnavailable, claim_scrape, collect
from bridge.operations import workspace_health
from bridge.worker import drain
from bridge.worker_health import worker_health
from tests.test_processing_efficiency import observation, rows

TOKEN = "nonfunctional-metrics-fixture-only-" + "x" * 32


@override_settings(MONITORED_WORKERS=("enterprise-a", "enterprise-b"))
class MonitoringTests(TestCase):
    def setUp(self):
        self.now = timezone.now().replace(microsecond=0)
        self.app = Integration.objects.create(slug="monitor-docs", name="Private synthetic title")
        self.other = Integration.objects.create(
            slug="monitor-expenses", name="Other synthetic title"
        )
        self.hidden = Integration.objects.create(slug="unselected", name="Never exported")
        self.environment = patch.dict(
            os.environ,
            {
                "SB_METRICS_ENABLED": "1",
                "SB_METRICS_APPS": self.app.slug,
                "SB_METRICS_TOKEN": TOKEN,
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.clock = patch("bridge.monitoring.timezone.now", return_value=self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.browser = Client(enforce_csrf_checks=True)

    def scrape(self, **values):
        options = {"HTTP_AUTHORIZATION": "Bearer " + TOKEN, "secure": True}
        options.update(values)
        return self.browser.get("/metrics/", **options)

    def event(self, app=None, state="pending", received=None, processed=None, **extra):
        app = app or self.app
        identifier = Event.objects.count()
        Event.objects.bulk_create(rows(app, [observation(identifier, self.now, app=app.slug)]))
        event = Event.objects.get(
            integration=app, event_id=observation(identifier, self.now, app=app.slug)["event_id"]
        )
        Event.objects.filter(pk=event.pk).update(
            state=state,
            received_at=received or self.now,
            processed_at=processed,
            available_at=self.now,
            **extra,
        )
        event.refresh_from_db()
        return event

    def text(self):
        response = self.scrape()
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_disabled_by_default_and_inherited_session_does_not_authorize(self):
        user = get_user_model().objects.create(username="synthetic-operator", is_staff=True)
        self.browser.force_login(user)
        with patch.dict(os.environ, {"SB_METRICS_ENABLED": "0"}):
            self.assertEqual(self.scrape().status_code, 404)
        self.assertEqual(self.scrape(HTTP_AUTHORIZATION="").status_code, 401)
        self.assertFalse(MetricsScrapeState.objects.exists())

    def test_wrong_malformed_overlong_and_non_ascii_credentials_are_denied(self):
        for value in (
            "Basic ignored",
            "Bearer wrong",
            "Bearer " + "z" * 129,
            "Bearer " + "é" * 64,
            "Bearer " + TOKEN + "\n",
        ):
            with self.subTest(value=value[:12]):
                self.assertEqual(self.scrape(HTTP_AUTHORIZATION=value).status_code, 401)
        self.assertFalse(MetricsScrapeState.objects.exists())

    def test_runtime_token_rotation_immediately_revokes_old_value(self):
        replacement = "nonfunctional-rotated-metrics-fixture-" + "y" * 32
        with patch.dict(os.environ, {"SB_METRICS_TOKEN": replacement}):
            self.assertEqual(self.scrape().status_code, 401)
            self.assertEqual(
                self.scrape(HTTP_AUTHORIZATION="Bearer " + replacement).status_code, 200
            )

    def test_missing_or_invalid_server_credentials_fail_closed_without_values(self):
        for value in ("", "short", "é" * 64, "x" * 129):
            with patch.dict(os.environ, {"SB_METRICS_TOKEN": value}):
                response = self.scrape()
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.content, b"Monitoring unavailable.\n")

    def test_https_required_and_forwarded_header_cannot_spoof_security(self):
        self.assertEqual(self.scrape(secure=False).status_code, 403)
        self.assertEqual(self.scrape(secure=False, HTTP_X_FORWARDED_PROTO="https").status_code, 403)
        self.assertFalse(MetricsScrapeState.objects.exists())

    def test_queries_bodies_and_write_methods_cannot_change_scope(self):
        self.assertEqual(self.scrape(QUERY_STRING="app=unselected").status_code, 400)
        response = self.browser.generic(
            "GET",
            "/metrics/",
            b"scope=unselected",
            secure=True,
            HTTP_AUTHORIZATION="Bearer " + TOKEN,
        )
        self.assertEqual(response.status_code, 400)
        for method in ("post", "put", "delete", "head"):
            self.assertNotEqual(
                getattr(self.browser, method)("/metrics/", secure=True).status_code, 200
            )
        self.assertFalse(MetricsScrapeState.objects.exists())

    def test_configuration_is_closed_bounded_and_does_not_auto_select_apps(self):
        for names in (
            "",
            "monitor-docs,monitor-docs",
            "../monitor-docs",
            "Monitor-Docs",
            " monitor-docs",
            "unprovisioned",
            ",".join("app" + str(i) for i in range(9)),
            "z" * 649,
        ):
            with patch.dict(os.environ, {"SB_METRICS_APPS": names}):
                self.assertEqual(self.scrape().status_code, 503)
            MetricsScrapeState.objects.all().delete()
        with patch.dict(os.environ, {"SB_METRICS_APPS": self.app.slug + "," + self.other.slug}):
            text = self.text()
        self.assertIn('scope="app1"', text)
        self.assertIn('scope="app2"', text)
        self.assertNotIn('scope="app3"', text)

    def test_scrape_rate_is_durable_and_clock_reversal_is_unavailable(self):
        self.assertEqual(self.scrape().status_code, 200)
        self.assertEqual(
            Client()
            .get("/metrics/", secure=True, HTTP_AUTHORIZATION="Bearer " + TOKEN)
            .status_code,
            429,
        )
        self.assertEqual(self.scrape()["Retry-After"], "5")
        self.assertEqual(MetricsScrapeState.objects.count(), 1)
        with patch("bridge.monitoring.timezone.now", return_value=self.now + timedelta(seconds=5)):
            self.assertEqual(self.scrape().status_code, 200)
        self.assertEqual(self.scrape().status_code, 503)

    def test_single_admission_row_constraint_cannot_grow_by_client(self):
        claim_scrape(self.now)
        with self.assertRaises(IntegrityError), transaction.atomic():
            MetricsScrapeState.objects.create(pk=2, last_started_at=self.now)

    def test_empty_queue_omits_latency_and_oldest_instead_of_inventing_zero(self):
        text = self.text()
        self.assertIn('signalbridge_processing_sample_count{scope="app1"} 0.000000', text)
        self.assertNotIn("signalbridge_processing_sample_p95_seconds", text)
        self.assertNotIn("signalbridge_queue_oldest_received_timestamp_seconds", text)
        self.assertIn('signalbridge_worker_state{slot="primary",state="missing"} 1.000000', text)

    def test_queue_delay_retry_and_dead_letters_remain_distinct_and_app_scoped(self):
        self.event(received=self.now - timedelta(seconds=70), processing_attempts=2, attempts=1)
        self.event(state="dead", processing_attempts=5, attempts=5)
        self.event(app=self.hidden, state="dead", processing_attempts=99, attempts=99)
        Event.objects.filter(integration=self.app, state="pending").update(
            available_at=self.now + timedelta(seconds=10)
        )
        self.app.rejected = 3
        self.app.save(update_fields=["rejected"])
        text = self.text()
        for fragment in (
            'signalbridge_retained_events{scope="app1",state="dead"} 1.000000',
            'signalbridge_queue_eligible_events{scope="app1"} 0.000000',
            'signalbridge_committed_processing_attempts{scope="app1"} 7.000000',
            'signalbridge_committed_processing_failures{scope="app1"} 6.000000',
            'signalbridge_ingestion_rejections{scope="app1"} 3.000000',
        ):
            self.assertIn(fragment, text)
        self.assertIn(f" {self.now.timestamp() - 70:.6f}", text)

    def test_sample_quantile_keeps_outage_delay_and_excludes_invalid_completions(self):
        for delay in (1, 2, 3, 4, 100):
            self.event(
                state="processed", received=self.now - timedelta(seconds=delay), processed=self.now
            )
        for received, processed in (
            (self.now, None),
            (self.now, self.now - timedelta(seconds=1)),
            (self.now, self.now + timedelta(seconds=1)),
        ):
            self.event(state="processed", received=received, processed=processed)
        self.event(
            state="processed",
            received=self.now - timedelta(hours=3),
            processed=self.now - timedelta(hours=2),
        )
        text = self.text()
        self.assertIn('signalbridge_processing_sample_count{scope="app1"} 5.000000', text)
        self.assertIn('signalbridge_processing_sample_p95_seconds{scope="app1"} 100.000000', text)
        self.assertIn('signalbridge_invalid_processing_timestamps{scope="app1"} 3.000000', text)

    def test_latency_materialization_is_bounded_and_nearest_rank_uses_actual_denominator(self):
        values = rows(self.app, [observation(i, self.now, app=self.app.slug) for i in range(1005)])
        Event.objects.bulk_create(values)
        Event.objects.filter(integration=self.app).update(
            state="processed", received_at=self.now - timedelta(seconds=8), processed_at=self.now
        )
        text = self.text()
        self.assertIn('signalbridge_processing_sample_count{scope="app1"} 1000.000000', text)
        self.assertIn('signalbridge_processing_sample_p95_seconds{scope="app1"} 8.000000', text)

    def test_local_export_stages_never_become_tool_observation(self):
        stream = SocStream.objects.create(integration=self.app)
        for state in ("staged", "file_appended"):
            event = self.event()
            batch = SocBatch.objects.create(
                stream=stream,
                body="synthetic only",
                body_sha256="c" * 64,
                start_offset=0,
                record_count=1,
                state=state,
            )
            SocDelivery.objects.create(event=event, batch=batch)
        text = self.text()
        self.assertIn(
            'signalbridge_soc_local_delivery_records{scope="app1",stage="staged"} 1.000000', text
        )
        self.assertIn(
            'signalbridge_soc_local_delivery_records{scope="app1",stage="file_appended"} 1.000000',
            text,
        )
        self.assertNotIn("signalbridge_wazuh_observed", text)

    def test_metrics_content_excludes_identifiers_notes_paths_and_credentials(self):
        event = self.event()
        text = self.text()
        for value in (
            TOKEN,
            self.app.slug,
            self.app.name,
            str(event.event_id),
            event.actor,
            event.resource,
            "SB_METRICS_TOKEN",
            "OneDrive",
            "Never exported",
        ):
            self.assertNotIn(value, text)
        self.assertTrue(text.endswith("\n"))
        response = self.scrape()
        self.assertIn("no-store", response["Cache-Control"])
        self.assertIn("version=0.0.4", response["Content-Type"])

    def test_any_database_filesystem_or_invalid_time_failure_is_not_clean_empty_metrics(self):
        for error in (
            DatabaseError("synthetic private failure"),
            OSError("synthetic private path"),
            MonitoringUnavailable(),
        ):
            with patch("bridge.monitoring.collect", side_effect=error):
                response = self.scrape()
                self.assertEqual(
                    (response.status_code, response.content), (503, b"Monitoring unavailable.\n")
                )
            MetricsScrapeState.objects.all().delete()
        self.event(received=self.now + timedelta(seconds=6))
        self.assertEqual(self.scrape().status_code, 503)

    def test_metric_types_labels_series_and_query_counts_stay_bounded(self):
        with (
            patch.dict(os.environ, {"SB_METRICS_APPS": self.app.slug + "," + self.other.slug}),
            self.assertNumQueries(8),
        ):
            text = collect(self.now, [self.app.slug, self.other.slug]).decode()
        samples = [line for line in text.splitlines() if not line.startswith("#")]
        self.assertEqual(len(samples), len(set(line.split(" ")[0] for line in samples)))
        self.assertLess(len(samples), 64)
        for line in samples:
            self.assertTrue(math.isfinite(float(line.split(" ")[-1])))
        for line in text.splitlines():
            if line.startswith("# TYPE"):
                self.assertTrue(line.endswith(" gauge"))

    def test_full_declared_scope_is_at_most_165_series_without_account_labels(self):
        apps = [self.app, self.other] + [
            Integration.objects.create(slug=f"scope-{index}", name="Synthetic monitored app")
            for index in range(6)
        ]
        for app in apps:
            self.event(app=app, received=self.now - timedelta(seconds=1))
            self.event(
                app=app,
                state="processed",
                received=self.now - timedelta(seconds=1),
                processed=self.now,
            )
        for name in ("enterprise-a", "enterprise-b"):
            WorkerHeartbeat.objects.create(name=name, last_seen=self.now)
        with patch.dict(os.environ, {"SB_METRICS_APPS": ",".join(app.slug for app in apps)}):
            text = self.text()
        samples = [line for line in text.splitlines() if not line.startswith("#")]
        self.assertEqual(len(samples), 165)
        self.assertLess(len(text.encode()), 64 * 1024)

    def test_slow_collection_is_incomplete_not_a_partial_success(self):
        with patch("bridge.monitoring.time.monotonic", side_effect=(10, 14)):
            self.assertEqual(self.scrape().status_code, 503)
        self.assertEqual(self.scrape().status_code, 429)

    def test_disk_metric_uses_only_configured_workspace_filesystem(self):
        with patch(
            "bridge.monitoring.shutil.disk_usage", return_value=SimpleNamespace(free=12345)
        ) as probe:
            text = self.text()
        self.assertIn("signalbridge_workspace_filesystem_free_bytes 12345.000000", text)
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(probe.call_args.args[0].name, "var")

    def test_named_worker_pool_is_not_masked_by_default_or_unconfigured_pulse(self):
        WorkerHeartbeat.objects.create(name="default", last_seen=self.now)
        WorkerHeartbeat.objects.create(name="enterprise-a", last_seen=self.now)
        WorkerHeartbeat.objects.create(
            name="enterprise-b", last_seen=self.now - timedelta(seconds=31)
        )
        health = worker_health(self.now)
        self.assertFalse(health["all_recent"])
        self.assertEqual([item["state"] for item in health["workers"]], ["recent", "stale"])
        text = self.text()
        self.assertIn('signalbridge_worker_state{slot="secondary",state="stale"} 1.000000', text)
        self.assertNotIn("enterprise-a", text)

    def test_future_worker_pulse_is_visible_as_clock_error_not_recent(self):
        WorkerHeartbeat.objects.create(
            name="enterprise-a", last_seen=self.now + timedelta(seconds=6)
        )
        text = self.text()
        self.assertIn(
            'signalbridge_worker_state{slot="primary",state="clock_error"} 1.000000', text
        )
        self.assertNotIn('signalbridge_worker_last_seen_timestamp_seconds{slot="primary"}', text)

    def test_invalid_worker_configuration_is_visible_and_scrape_fails(self):
        for value in ((), ("one", "one"), ("one", "two", "three"), ("../worker",), "default", (1,)):
            with override_settings(MONITORED_WORKERS=value):
                self.assertFalse(worker_health(self.now)["configuration_valid"])
                self.assertEqual(self.scrape().status_code, 503)
            MetricsScrapeState.objects.all().delete()

    def test_idle_real_drain_records_selected_pulse_without_claiming_processed_events(self):
        self.assertEqual(drain(worker_id="enterprise-a"), 0)
        self.assertEqual(worker_health(self.now)["workers"][0]["state"], "recent")
        self.assertEqual(Event.objects.count(), 0)

    def test_console_and_integration_queue_share_configured_pool_health(self):
        user = get_user_model().objects.create(username="synthetic-viewer")
        Membership.objects.create(user=user, integration=self.app, role="viewer")
        self.browser.force_login(user)
        WorkerHeartbeat.objects.create(name="enterprise-a", last_seen=self.now)
        WorkerHeartbeat.objects.create(name="enterprise-b", last_seen=self.now)
        response = self.browser.get("/", {"app": self.app.slug})
        self.assertTrue(response.context["worker_recent"])
        self.assertContains(response, "Detection pipeline health")
        self.assertContains(response, "All configured pulses recent")
        self.assertTrue(workspace_health(self.app)["queue"]["worker_recent"])
        WorkerHeartbeat.objects.filter(name="enterprise-b").delete()
        self.assertFalse(self.browser.get("/", {"app": self.app.slug}).context["worker_recent"])
        self.assertFalse(workspace_health(self.app)["queue"]["worker_recent"])

    def test_prepared_dashboard_queries_match_exporter_without_fabricated_fallback(self):
        self.event(state="processed", received=self.now - timedelta(seconds=2), processed=self.now)
        self.event()
        text = self.text()
        exported = {line.split(" ")[2] for line in text.splitlines() if line.startswith("# TYPE")}
        dashboard = json.loads(
            (settings.BASE_DIR / "integrations/monitoring/signalbridge-dashboard.json").read_text()
        )
        self.assertEqual(dashboard["links"], [])
        self.assertEqual(dashboard["templating"]["list"], [])
        self.assertIn("native", dashboard["description"].lower())
        identifiers = []
        for panel in dashboard["panels"]:
            identifiers.append(panel["id"])
            for target in panel.get("targets", []):
                names = set(re.findall(r"\bsignalbridge_[a-z0-9_]+", target["expr"]))
                self.assertTrue(names <= exported)
                self.assertNotIn("vector(0)", target["expr"])
                self.assertEqual(panel["datasource"]["uid"], "signalbridge-prometheus")
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_preparation_preserves_unfinished_native_controls_and_series_ceiling(self):
        plan = json.loads(
            (settings.BASE_DIR / "integrations/monitoring/preparation.json").read_text()
        )
        self.assertEqual(
            plan["status"], "application_exporter_implemented_native_monitoring_not_launched"
        )
        self.assertEqual(plan["bounds"]["maximum_current_exporter_series"], 165)
        self.assertEqual(plan["bounds"]["response_ceiling_bytes"], 65536)
        self.assertNotIn("token", plan.get("credentials", {}))
