"""Synthetic import tests; never run the simulation or read live lab credentials."""

import copy
import io
import json
import shutil
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase

from bridge import simulation_evidence as evidence
from bridge.models import Audit, CheckRun, Integration

RUN = "a" * 32


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def fixture():
    scenarios = []
    for name, expected in evidence.SCENARIOS:
        known = name == "bucket_boundary_gap"
        scenarios.append(
            {
                "id": name,
                "expected_rule": expected,
                "observed_rules": [expected] if expected and not known else [],
                "known_limitation": known,
                "coverage_met": not known,
            }
        )
    report = {
        "schema_version": 1,
        "kind": "signalbridge-offline-capability-simulation",
        "started_at": "2026-09-24T00:00:00Z",
        "finished_at": "2026-09-24T00:00:03.500000Z",
        "execution_status": "completed_with_known_coverage_gap",
        "duration_seconds": 3.5,
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
        "scenarios": scenarios,
        "controls": {key: True for key in evidence.CONTROLS},
        "not_tested": ["Synthetic fixture disclaimer"],
        "detection_quality": {
            "true_positive_scenarios": 4,
            "false_negative_scenarios": 1,
            "false_positive_scenarios": 0,
            "true_negative_scenarios": 10,
            "recall": 0.8,
            "precision": 1.0,
            "denominator": "Synthetic fixture",
        },
        "bounded_load": {
            "accepted_events": 600,
            "processed_events": 600,
            "source_rate_limit": "600 per application per minute",
            "ingest_seconds": 2.0,
            "processing_seconds": 1.0,
            "in_process_requests_per_second": 300,
            "in_process_request_p50_ms": 1.0,
            "in_process_request_p95_ms": 1.8,
            "alerts_from_benign_load": 0,
            "limits": "Synthetic fixture",
        },
        "scenario_records_processed": 34,
        "final_queue": {"processed": 634},
        "requests_executed": 639,
    }
    files = {name: evidence.digest(name.encode()) for name in evidence.CODE_FILES.values()}
    manifest = {"files": files, "file_count": len(files), "sha256": evidence.digest(encoded(files))}
    provenance = {
        "schema_version": 1,
        "run_id": RUN,
        "exit_code": 0,
        "source_before": manifest,
        "source_after": copy.deepcopy(manifest),
        "source_unchanged": True,
        "git": {"head": "b" * 40, "dirty": True, "status": "private-path-sentinel"},
        "python": "3.14.4",
        "logs": {"stdout.txt": "c" * 64, "stderr.txt": "d" * 64},
        "limits": ["private-producer-note-sentinel"],
        "execution_verified": True,
    }
    provenance["result_sha256"] = evidence.digest(encoded(report))
    return report, provenance


def validate(report, provenance):
    provenance = copy.deepcopy(provenance)
    provenance["result_sha256"] = evidence.digest(encoded(report))
    return evidence.validate_evidence(RUN, encoded(report), encoded(provenance))


class SimulationEvidenceTests(SimpleTestCase):
    def test_known_miss_is_partial_with_reconciled_counts_and_historical_identity(self):
        report, provenance = fixture()
        checked = validate(report, provenance)
        self.assertEqual(checked["status"], "partial")
        result = checked["result"]
        self.assertEqual(result["simulation"]["coverage"]["met"], 14)
        self.assertEqual(result["simulation"]["detection_quality"]["false_negative_scenarios"], 1)
        self.assertEqual(
            result["provenance"]["source_sha256"], provenance["source_before"]["sha256"]
        )
        self.assertFalse(result["provenance"]["log_bytes_verified_by_importer"])
        self.assertEqual(sum(row["status"] == "failed" for row in result["checks"]), 1)

    def test_new_full_coverage_report_is_separate_passed_result(self):
        report, provenance = fixture()
        old = validate(report, provenance)
        report["scenarios"][4].update(
            observed_rules=["R1"], known_limitation=False, coverage_met=True
        )
        report["detection_quality"].update(
            true_positive_scenarios=5, false_negative_scenarios=0, recall=1.0
        )
        report["execution_status"] = "completed"
        new = validate(report, provenance)
        self.assertEqual(new["status"], "passed")
        self.assertNotEqual(old["digest"], new["digest"])
        self.assertEqual(
            old["result"]["simulation"]["coverage"]["known_misses"], ["bucket_boundary_gap"]
        )

    def test_unexpected_alert_cannot_be_green_even_with_successful_execution(self):
        report, provenance = fixture()
        report["scenarios"][0].update(observed_rules=["R1"], coverage_met=False)
        report["detection_quality"].update(
            false_positive_scenarios=1, true_negative_scenarios=9, precision=0.8
        )
        report["execution_status"] = "completed_with_coverage_failures"
        self.assertEqual(validate(report, provenance)["status"], "failed")

    def test_status_rate_label_and_coverage_fabrications_are_rejected(self):
        mutations = (
            lambda r: r.update(execution_status="completed"),
            lambda r: r["detection_quality"].update(recall=1.0),
            lambda r: r["detection_quality"].update(precision=True),
            lambda r: r["detection_quality"].update(false_negative_scenarios=0),
            lambda r: r["scenarios"][4].update(coverage_met=True),
            lambda r: r["scenarios"][4].update(expected_rule=None),
            lambda r: r["scenarios"][0].update(known_limitation=True),
            lambda r: r["scenarios"][0].update(id="invented"),
            lambda r: r["scenarios"].pop(),
            lambda r: r["scenarios"].reverse(),
        )
        for mutate in mutations:
            report, provenance = fixture()
            mutate(report)
            with self.assertRaises(evidence.SimulationEvidenceError):
                validate(report, provenance)

    def test_requests_queue_load_and_timing_must_reconcile(self):
        mutations = (
            lambda r: r.update(requests_executed=638),
            lambda r: r.update(scenario_records_processed=35),
            lambda r: r["final_queue"].update(processed=633),
            lambda r: r["final_queue"].update(dead=1),
            lambda r: r["bounded_load"].update(processed_events=599),
            lambda r: r["bounded_load"].update(accepted_events=600.0),
            lambda r: r["bounded_load"].update(in_process_requests_per_second=10000),
            lambda r: r["bounded_load"].update(in_process_request_p95_ms=0.5),
            lambda r: r["bounded_load"].update(ingest_seconds=0),
            lambda r: r["bounded_load"].update(alerts_from_benign_load=1),
        )
        for mutate in mutations:
            report, provenance = fixture()
            mutate(report)
            with self.assertRaises(evidence.SimulationEvidenceError):
                validate(report, provenance)

    def test_unverified_execution_source_drift_and_unsafe_scope_fail(self):
        for mutate in (
            lambda p: p.update(execution_verified=False),
            lambda p: p.update(exit_code=1),
            lambda p: p.update(exit_code=False),
            lambda p: p.update(source_unchanged=False),
            lambda p: p["source_after"].update(file_count=1),
            lambda p: p["source_before"].update(sha256="0" * 64),
        ):
            report, provenance = fixture()
            mutate(provenance)
            with self.assertRaises(evidence.SimulationEvidenceError):
                validate(report, provenance)
        for field, value in (
            ("network_guard", False),
            ("production_database", True),
            ("max_requests", 10000),
        ):
            report, provenance = fixture()
            report["safety"][field] = value
            with self.assertRaises(evidence.SimulationEvidenceError):
                validate(report, provenance)

    def test_manifest_paths_are_validated_without_reading_current_source(self):
        for path in (
            "../private",
            "bridge/../secret.py",
            "bridge/.env",
            "C:/private",
            "var/key.txt",
        ):
            report, provenance = fixture()
            manifest = provenance["source_before"]
            manifest["files"][path] = "0" * 64
            manifest["file_count"] = len(manifest["files"])
            manifest["sha256"] = evidence.digest(encoded(manifest["files"]))
            provenance["source_after"] = copy.deepcopy(manifest)
            with self.assertRaises(evidence.SimulationEvidenceError):
                validate(report, provenance)

    def test_sanitization_excludes_free_text_git_status_and_manifest_filenames(self):
        report, provenance = fixture()
        report["not_tested"] = ["private-note-sentinel"]
        report["detection_quality"]["denominator"] = "private-note-sentinel"
        report["bounded_load"]["limits"] = "private-note-sentinel"
        result = json.dumps(validate(report, provenance)["result"])
        self.assertNotIn("sentinel", result)
        self.assertNotIn("bridge/engine.py", result)
        self.assertNotIn("source_before", result)

    def test_raw_hash_duplicate_fields_and_nonfinite_json_are_rejected(self):
        report, provenance = fixture()
        with self.assertRaises(evidence.SimulationEvidenceError):
            evidence.validate_evidence(RUN, encoded(report) + b" ", encoded(provenance))
        for raw in (b'{"x":1,"x":2}', b'{"x":Infinity}'):
            with self.assertRaises(evidence.SimulationEvidenceError):
                evidence.json_document(raw)


class SimulationFileTests(SimpleTestCase):
    def setUp(self):
        self.parent = settings.BASE_DIR / "var/tests"
        self.root = self.parent / ("simulation-import-" + uuid.uuid4().hex)
        self.output = self.root / "artifacts/local/simulation" / RUN
        self.output.mkdir(parents=True)
        self.addCleanup(self.cleanup_case)
        report, provenance = fixture()
        (self.output / "result.json").write_bytes(encoded(report))
        (self.output / "provenance.json").write_bytes(encoded(provenance))
        (self.output / "stdout.txt").write_text("PRIVATE LOG SENTINEL")

    def cleanup_case(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.parent.resolve()) or not target.name.startswith(
            "simulation-import-"
        ):
            raise RuntimeError("Unsafe synthetic test cleanup")
        shutil.rmtree(target)

    def test_fixed_loader_reads_only_two_evidence_files(self):
        checked = evidence.load_simulation(self.root, RUN)
        self.assertEqual(checked["status"], "partial")
        self.assertNotIn("PRIVATE LOG SENTINEL", json.dumps(checked))

    def test_paths_reparse_points_oversize_and_missing_files_fail(self):
        for value in ("../escape", "https://remote", "A" * 32, RUN + "/result.json"):
            with self.assertRaises(evidence.SimulationEvidenceError):
                evidence.load_simulation(self.root, value)
        with patch.object(
            Path,
            "lstat",
            return_value=SimpleNamespace(st_mode=evidence.stat.S_IFREG, st_file_attributes=1024),
        ):
            with self.assertRaises(evidence.SimulationEvidenceError):
                evidence.load_simulation(self.root, RUN)
        with patch.object(evidence, "MAX_BYTES", 8):
            with self.assertRaises(evidence.SimulationEvidenceError):
                evidence.load_simulation(self.root, RUN)
        (self.output / "result.json").unlink()
        with self.assertRaises(evidence.SimulationEvidenceError):
            evidence.load_simulation(self.root, RUN)

    def test_changed_bytes_during_import_are_rejected(self):
        original = evidence.read_fixed
        reads = {}

        def changing(root, run_id, filename):
            raw = original(root, run_id, filename)
            reads[filename] = reads.get(filename, 0) + 1
            return raw + b" " if filename == "result.json" and reads[filename] == 2 else raw

        with patch.object(evidence, "read_fixed", side_effect=changing):
            with self.assertRaisesRegex(
                evidence.SimulationEvidenceError, "evidence_changed_during_import"
            ):
                evidence.load_simulation(self.root, RUN)


class SimulationCommandTests(TestCase):
    def setUp(self):
        self.app = Integration.objects.create(slug="signalbridge", name="SignalBridge")
        self.other = Integration.objects.create(slug="bettail", name="BetTail")
        self.checked = validate(*fixture())
        self.loader = patch(
            "bridge.management.commands.import_simulation.load_simulation",
            return_value=self.checked,
        )
        self.loader.start()
        self.addCleanup(self.loader.stop)

    def invoke(self, **options):
        call_command("import_simulation", run_id=RUN, stdout=io.StringIO(), **options)

    def test_import_is_self_scoped_partial_audited_and_idempotent(self):
        self.invoke()
        self.invoke()
        self.assertEqual(CheckRun.objects.count(), 1)
        run = CheckRun.objects.get()
        self.assertEqual(run.integration, self.app)
        self.assertEqual(run.status, "partial")
        self.assertEqual(Audit.objects.filter(action="simulation.imported").count(), 1)
        self.assertFalse(CheckRun.objects.filter(integration=self.other).exists())

    def test_dry_run_and_invalid_evidence_write_nothing(self):
        self.invoke(dry_run=True)
        self.assertFalse(CheckRun.objects.exists())
        with patch(
            "bridge.management.commands.import_simulation.load_simulation",
            side_effect=evidence.SimulationEvidenceError("result_hash_mismatch"),
        ):
            with self.assertRaises(CommandError):
                self.invoke()
        self.assertFalse(Audit.objects.exists())

    def test_existing_digest_in_other_scope_is_rejected(self):
        CheckRun.objects.create(
            integration=self.other,
            suite="Foreign",
            revision=self.checked["revision"],
            digest=self.checked["digest"],
            status="partial",
            result=self.checked["result"],
        )
        with self.assertRaises(CommandError):
            self.invoke()
        self.assertEqual(CheckRun.objects.count(), 1)
        self.assertFalse(Audit.objects.exists())

    def test_conflicting_run_identity_is_rejected(self):
        self.invoke()
        original_digest = self.checked["digest"]
        self.checked["digest"] = "0" * 64
        with self.assertRaises(CommandError):
            self.invoke()
        self.assertEqual(CheckRun.objects.get().digest, original_digest)

    def test_missing_self_workspace_is_rejected(self):
        self.app.delete()
        with self.assertRaises(CommandError):
            self.invoke()

    def test_nonlocal_mode_is_rejected_before_import(self):
        with self.settings(LOCAL=False), self.assertRaisesRegex(CommandError, "local-only"):
            self.invoke()
        self.assertFalse(CheckRun.objects.exists())
