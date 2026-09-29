"""Measure every declared challenge through signed ingestion and the real worker."""

import json
import os
import time

from django.conf import settings
from django.db import connection
from django.test import TransactionTestCase
from django.utils import timezone

from bridge.challenge_evidence import score_rows
from bridge.contract import canonical, signature
from bridge.models import Event, IngestKey, Integration, Investigation
from bridge.worker import drain
from scripts.run_enterprise_lab import output_directory
from simulations.challenge_cases import (
    MAX_REQUESTS,
    MAX_WORKER_RECORDS,
    PROFILE,
    catalog,
    declaration_sha256,
    deliveries,
)


class DetectionChallenge(TransactionTestCase):
    def test_predeclared_matrix(self):
        self.assertEqual(settings.SETTINGS_MODULE, "config.simulation_settings")
        self.assertEqual(connection.vendor, "sqlite")
        self.assertIn("memory", connection.settings_dict["NAME"])
        app = Integration.objects.create(slug="lab-challenge", name="Synthetic challenge")
        key = "challenge-key"
        IngestKey.objects.create(
            integration=app,
            key_id=key,
            secret_env="SB_SIMULATION_KEY",
            source="migration_lab",
            environment="test",
        )
        started = time.perf_counter()
        report = {
            "schema_version": 1,
            "kind": PROFILE,
            "declaration_sha256": declaration_sha256(),
            "started_at": timezone.now().isoformat(),
            "execution_status": "failed",
            "database": "disposable in-memory SQLite",
            "transport": "Django in-process test client",
            "rows": [],
            "requests_executed": 0,
            "records_processed": 0,
        }
        try:
            for case in catalog():
                accepted = duplicates = processed = 0
                ids = set()
                for body, drain_after in deliveries(case, timezone.now()):
                    ids.add(body["event_id"])
                    raw = canonical(body)
                    at = timezone.now().isoformat()
                    report["requests_executed"] += 1
                    self.assertLessEqual(report["requests_executed"], MAX_REQUESTS)
                    response = self.client.post(
                        "/api/v1/events/lab-challenge/",
                        data=raw,
                        content_type="application/json",
                        HTTP_X_SB_KEY=key,
                        HTTP_X_SB_TIME=at,
                        HTTP_X_SB_SIGNATURE=signature(
                            os.environ["SB_SIMULATION_KEY"], app.slug, key, at, raw
                        ),
                    )
                    self.assertIn(response.status_code, (200, 202))
                    accepted += response.status_code == 202
                    duplicates += response.status_code == 200
                    if drain_after:
                        processed += drain(limit=MAX_WORKER_RECORDS)
                processed += drain(limit=MAX_WORKER_RECORDS)
                self.assertEqual(processed, len(ids))
                report["records_processed"] += processed
                self.assertLessEqual(report["records_processed"], MAX_WORKER_RECORDS)
                findings = list(Investigation.objects.filter(events__event_id__in=ids).distinct())
                self.assertTrue(
                    all(
                        set(str(i) for i in finding.events.values_list("event_id", flat=True))
                        <= ids
                        for finding in findings
                    )
                )
                report["rows"].append(
                    {
                        "id": case.id,
                        "observed_rules": sorted({f.rule for f in findings}),
                        "case_count": len(findings),
                        "accepted": accepted,
                        "duplicates": duplicates,
                        "processed": processed,
                    }
                )
            self.assertEqual(Event.objects.exclude(state="processed").count(), 0)
            self.assertEqual(Event.objects.count(), report["records_processed"])
            report["summary"] = score_rows(report["rows"])
            # A miss must not short-circuit the remaining cases or be relabeled as benign.
            report["execution_status"] = "completed"
        finally:
            report["finished_at"] = timezone.now().isoformat()
            report["duration_seconds"] = round(time.perf_counter() - started, 6)
            output = output_directory(os.environ["SB_SIMULATION_RUN_ID"])
            with (output / "result.json").open("x", encoding="utf8") as handle:
                handle.write(json.dumps(report, indent=2) + "\n")
