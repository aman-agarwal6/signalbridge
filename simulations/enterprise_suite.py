"""Bounded in-process requests against disposable Django test storage, never live HTTP."""

import hashlib
import json
import os
import time
import uuid
from collections import Counter

from django.conf import settings
from django.db import connection
from django.test import TransactionTestCase
from django.utils import timezone

from bridge.contract import canonical, signature
from bridge.models import Event, IngestKey, Integration, Investigation
from bridge.worker import drain
from scripts.run_enterprise_lab import output_directory
from simulations.scenarios import build_scenarios


class EnterpriseSimulation(TransactionTestCase):
    def test_bounded_synthetic_matrix(self):
        self.assertEqual(settings.SETTINGS_MODULE, "config.simulation_settings")
        self.assertEqual(connection.vendor, "sqlite")
        self.assertIn("memory", connection.settings_dict["NAME"])
        secret = os.environ["SB_SIMULATION_KEY"]
        for slug in ("lab-alpha", "lab-beta", "lab-load"):
            app = Integration.objects.create(slug=slug, name=slug)
            for source in ("migration_lab", "synthetic_demo"):
                for environment in ("test", "lab"):
                    IngestKey.objects.create(
                        integration=app,
                        key_id=f"{slug}-{source}-{environment}",
                        secret_env="SB_SIMULATION_KEY",
                        source=source,
                        environment=environment,
                    )
        report = {
            "schema_version": 1,
            "kind": "signalbridge-offline-capability-simulation",
            "started_at": timezone.now().isoformat(),
            "execution_status": "failed",
            "database": "disposable in-memory SQLite",
            "transport": "Django in-process test client",
            "safety": {
                "synthetic_only": True,
                "network_guard": True,
                "child_process_guard": True,
                "production_database": False,
                "max_requests": 750,
                "max_worker_records": 700,
            },
            "scenarios": [],
            "controls": {},
            "not_tested": [
                "Endpoint or cloud inventory",
                "Live adversary exploitation",
                "Production traffic",
                "Multi-node availability",
                "PostgreSQL concurrency or crash durability",
                "Network HTTP latency",
                "Competitor products",
                "Independent blind holdout",
                "Automated external response",
            ],
        }
        started = time.perf_counter()
        requests = 0

        def send(body, source="migration_lab", tamper=False):
            nonlocal requests
            requests += 1
            self.assertLessEqual(requests, 750)
            raw = canonical(body)
            key = f"{body['app']}-{source}-{body['environment']}"
            at = timezone.now().isoformat()
            mac = signature(secret, body["app"], key, at, raw)
            if tamper:
                mac = "0" * 64
            return self.client.post(
                f"/api/v1/events/{body['app']}/",
                data=raw,
                content_type="application/json",
                HTTP_X_SB_KEY=key,
                HTTP_X_SB_TIME=at,
                HTTP_X_SB_SIGNATURE=mac,
            )

        def persist():
            report["finished_at"] = timezone.now().isoformat()
            report["duration_seconds"] = round(time.perf_counter() - started, 6)
            report["requests_executed"] = requests
            # Set only by the fixed parent; never accept an arbitrary report target.
            run_id = os.environ["SB_SIMULATION_RUN_ID"]
            self.assertRegex(run_id, r"^[0-9a-f]{32}$")
            target = output_directory(run_id) / "result.json"
            with target.open("x", encoding="utf-8") as handle:
                handle.write(json.dumps(report, indent=2) + "\n")

        try:
            scenarios = build_scenarios(timezone.now())
            for case in scenarios:
                for delivery in case["deliveries"]:
                    self.assertIn(
                        send(delivery["event"], delivery["source"]).status_code, (200, 202)
                    )
            processed = drain(limit=700)
            self.assertEqual(Event.objects.filter(state="pending").count(), 0)
            self.assertEqual(Event.objects.filter(state="dead").count(), 0)
            for case in scenarios:
                event_ids = {item["event"]["event_id"] for item in case["deliveries"]}
                actual = sorted(
                    set(
                        Investigation.objects.filter(events__event_id__in=event_ids).values_list(
                            "rule", flat=True
                        )
                    )
                )
                expected = case["expected_rule"]
                detected = bool(expected and expected in actual)
                row = {
                    "id": case["id"],
                    "expected_rule": expected,
                    "observed_rules": actual,
                    "known_limitation": case["known_gap"],
                    "coverage_met": detected if expected else not actual,
                }
                report["scenarios"].append(row)
                # A known gap is measured as a miss, never relabeled as covered.
                self.assertEqual(actual, [] if case["known_gap"] or not expected else [expected])
            positives = [r for r in report["scenarios"] if r["expected_rule"]]
            negatives = [r for r in report["scenarios"] if not r["expected_rule"]]
            tp = sum(r["coverage_met"] for r in positives)
            fp = sum(bool(r["observed_rules"]) for r in negatives)
            report["detection_quality"] = {
                "true_positive_scenarios": tp,
                "false_negative_scenarios": len(positives) - tp,
                "false_positive_scenarios": fp,
                "true_negative_scenarios": len(negatives) - fp,
                "recall": tp / len(positives),
                "precision": tp / (tp + fp) if tp + fp else None,
                "denominator": "15 declared, builder-authored synthetic scenarios; not independent production prevalence",
            }
            probe = dict(scenarios[0]["deliveries"][0]["event"], event_id=str(uuid.uuid4()))
            before = Event.objects.count()
            self.assertEqual(send(probe, tamper=True).status_code, 401)
            self.assertEqual(Event.objects.count(), before)
            report["controls"]["tampered_signature_rejected_without_event"] = True
            original = scenarios[0]["deliveries"][0]["event"]
            changed = dict(original, resource="f" * 64)
            self.assertEqual(send(changed).status_code, 409)
            report["controls"]["duplicate_content_conflict_rejected"] = True
            before_cases = Investigation.objects.count()
            latencies = []
            load_started = time.perf_counter()
            for index in range(600):
                body = dict(
                    probe,
                    app="lab-load",
                    event_id=str(uuid.uuid4()),
                    actor=hashlib.sha256(f"load/{index}".encode()).hexdigest(),
                )
                request_started = time.perf_counter()
                self.assertEqual(send(body).status_code, 202)
                latencies.append((time.perf_counter() - request_started) * 1000)
            ingest_seconds = time.perf_counter() - load_started
            self.assertLess(
                ingest_seconds,
                60,
                "Rate-window test requires all 600 deliveries within one minute.",
            )
            overflow = dict(body, event_id=str(uuid.uuid4()))
            self.assertEqual(send(overflow).status_code, 429)
            report["controls"]["configured_600_per_minute_limit"] = True
            worker_started = time.perf_counter()
            load_processed = drain(limit=700)
            worker_seconds = time.perf_counter() - worker_started
            self.assertEqual(load_processed, 600)
            self.assertEqual(Investigation.objects.count(), before_cases)
            self.assertEqual(Event.objects.filter(state="pending").count(), 0)
            ordered = sorted(latencies)
            report["bounded_load"] = {
                "accepted_events": 600,
                "processed_events": load_processed,
                "source_rate_limit": "600 per application per minute",
                "ingest_seconds": round(ingest_seconds, 6),
                "processing_seconds": round(worker_seconds, 6),
                "in_process_requests_per_second": round(600 / ingest_seconds, 2),
                "in_process_request_p50_ms": round(ordered[299], 3),
                "in_process_request_p95_ms": round(ordered[569], 3),
                "alerts_from_benign_load": Investigation.objects.count() - before_cases,
                "limits": "Single-process SQLite harness timing includes test-client overhead; not network or production capacity.",
            }
            report["scenario_records_processed"] = processed
            report["final_queue"] = dict(Counter(Event.objects.values_list("state", flat=True)))
            report["execution_status"] = (
                "completed_with_known_coverage_gap"
                if any(not row["coverage_met"] for row in report["scenarios"])
                else "completed"
            )
        finally:
            persist()
