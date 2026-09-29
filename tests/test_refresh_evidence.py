"""Disposable evidence fixtures; no real verification, labs or user database."""

import copy
import json
import shutil
import uuid
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from bridge.contract import canonical
from scripts import portfolio
from scripts import refresh_evidence as refresh
from simulations.challenge_cases import declaration
from tests.test_detection_challenge import synthetic_result
from tests.test_simulation_evidence import RUN, encoded, fixture


class RefreshEvidenceTests(TestCase):
    def setUp(self):
        self.parent = refresh.ROOT / "var/tests"
        self.root = self.parent / ("refresh-" + uuid.uuid4().hex)
        self.directory = self.root / "artifacts/local/simulation" / RUN
        self.directory.mkdir(parents=True)
        self.addCleanup(self.cleanup)
        self.report, self.provenance = fixture()
        for name in self.provenance["source_before"]["files"]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
        self.manifest = refresh.record_verification.source_manifest(self.root)
        self.provenance["source_before"] = self.provenance["source_after"] = self.manifest
        for name in ("stdout.txt", "stderr.txt"):
            raw = b"Private raw log retained only in the fixture."
            (self.directory / name).write_bytes(raw)
            self.provenance["logs"][name] = refresh.sha(raw)
        self.save()

    def cleanup(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.parent.resolve()) or not target.name.startswith(
            "refresh-"
        ):
            raise RuntimeError("Unsafe test cleanup")
        shutil.rmtree(target)

    def save(self):
        raw = encoded(self.report)
        (self.directory / "result.json").write_bytes(raw)
        self.provenance["result_sha256"] = refresh.sha(raw)
        (self.directory / "provenance.json").write_bytes(encoded(self.provenance))

    def test_curated_receipt_preserves_partial_coverage_without_private_producer_text(self):
        filename, status = refresh.curate(self.root, RUN)
        self.assertEqual(status, "partial")
        raw = (self.root / "docs/evidence" / filename).read_text()
        for private in (
            "private-path-sentinel",
            "private-producer-note-sentinel",
            "Private raw log",
        ):
            self.assertNotIn(private, raw)
        checked = portfolio.simulation(
            self.root, filename, self.manifest, datetime.now(timezone.utc)
        )
        self.assertEqual(checked["results"]["coverage"]["met"], 14)
        before = (self.root / "docs/evidence" / filename).read_bytes()
        with self.assertRaises(FileExistsError):
            refresh.curate(self.root, RUN)
        self.assertEqual((self.root / "docs/evidence" / filename).read_bytes(), before)

    def test_challenge_preserves_unmet_probes_and_checks_declaration(self):
        self.report = synthetic_result()
        raw = canonical(declaration())
        (self.directory / "declaration.json").write_bytes(raw)
        self.provenance.update(
            coverage_status="partial",
            declaration_unchanged=True,
            declaration_sha256=refresh.sha(raw),
        )
        self.save()
        filename, status = refresh.curate(self.root, RUN, challenge=True)
        self.assertEqual(status, "partial")
        result = json.loads((self.root / "docs/evidence" / filename).read_text())
        self.assertEqual(result["results"]["summary"]["capability_probes"]["alert_observed"], 0)
        (self.directory / "declaration.json").write_bytes(b"changed")
        with self.assertRaises(refresh.RefreshError):
            refresh.curate(self.root, RUN, challenge=True)

    def test_changed_logs_result_source_and_failed_execution_withhold_summary(self):
        for fault in ("log", "result", "source", "execution"):
            with self.subTest(fault=fault):
                original = copy.deepcopy(self.provenance)
                log = self.directory / "stdout.txt"
                before = log.read_bytes()
                if fault == "log":
                    log.write_bytes(b"changed")
                elif fault == "result":
                    (self.directory / "result.json").write_bytes(b"{}")
                elif fault == "source":
                    self.provenance["source_after"] = {"changed": True}
                    (self.directory / "provenance.json").write_bytes(encoded(self.provenance))
                else:
                    self.provenance["execution_verified"] = False
                    (self.directory / "provenance.json").write_bytes(encoded(self.provenance))
                with self.assertRaises(ValueError):
                    refresh.curate(self.root, RUN)
                self.assertFalse((self.root / "docs/evidence").exists())
                self.provenance = original
                log.write_bytes(before)
                self.save()

    def test_invalid_run_paths_and_known_private_values_are_withheld(self):
        with self.assertRaises(ValueError):
            refresh.curate(self.root, "../private")
        with patch.object(refresh, "collect_secrets", return_value={RUN}):
            with self.assertRaises(refresh.RefreshError):
                refresh.curate(self.root, RUN)
        self.assertFalse((self.root / "docs/evidence").exists())

    def flow(self, passed=True):
        stack = ExitStack()
        stack.enter_context(
            patch.object(refresh.record_verification, "source_manifest", return_value=self.manifest)
        )
        stack.enter_context(
            patch.object(
                refresh.record_verification,
                "run_verification",
                return_value=({"run_id": "synthetic-core", "passed": passed}, self.directory),
            )
        )
        runner = stack.enter_context(
            patch.object(
                refresh.run_enterprise_lab,
                "run",
                return_value=({"run_id": RUN, "execution_verified": True}, self.directory),
            )
        )
        stack.enter_context(
            patch.object(
                refresh,
                "curate",
                side_effect=[("simulation.json", "passed"), ("challenge.json", "partial")],
            )
        )
        builder = stack.enter_context(patch.object(refresh.portfolio, "build", return_value={}))
        return stack, runner, builder

    def test_success_uses_fixed_profiles_and_retains_partial_challenge(self):
        stack, runner, builder = self.flow()
        with stack:
            result = refresh.refresh(self.root)
        self.assertEqual(result["challenge_coverage"], "partial")
        self.assertEqual(
            [c.kwargs for c in runner.call_args_list], [{"challenge": False}, {"challenge": True}]
        )
        builder.assert_called_once()
        self.assertFalse((self.root / "var/evidence-refresh.lock").exists())

    def test_failed_core_does_not_run_simulations_or_replace_viewer(self):
        stack, runner, builder = self.flow(passed=False)
        with stack, self.assertRaises(refresh.RefreshError):
            refresh.refresh(self.root)
        runner.assert_not_called()
        builder.assert_not_called()
        self.assertTrue((self.root / "var/evidence-refresh.lock").exists())
        summary = json.loads(
            next(self.root.glob("var/evidence-refresh/*/summary.json")).read_text()
        )
        self.assertIn("incomplete", summary["status"])

    def test_existing_marker_is_preserved_and_blocks_execution(self):
        marker = self.root / "var/evidence-refresh.lock"
        marker.parent.mkdir()
        marker.write_text("existing run")
        stack, runner, builder = self.flow()
        with stack, self.assertRaises(refresh.RefreshError):
            refresh.refresh(self.root)
        self.assertEqual(marker.read_text(), "existing run")
        runner.assert_not_called()
        builder.assert_not_called()

    def test_source_drift_and_unverified_simulation_stop_before_render(self):
        for fault in ("drift", "execution"):
            with self.subTest(fault=fault):
                marker = self.root / "var/evidence-refresh.lock"
                if marker.exists():
                    marker.unlink()  # Only this disposable test's prior marker.
                stack, runner, builder = self.flow()
                with stack:
                    if fault == "execution":
                        runner.return_value = (
                            {"run_id": RUN, "execution_verified": False},
                            self.directory,
                        )
                    else:
                        refresh.record_verification.source_manifest.side_effect = [
                            self.manifest,
                            {"changed": True},
                        ]
                    with self.assertRaises(refresh.RefreshError):
                        refresh.refresh(self.root)
                builder.assert_not_called()

    def test_retained_bytes_changing_during_curation_withhold_public_receipt(self):
        for filename in ("result.json", "provenance.json", "stdout.txt", "stderr.txt"):
            with self.subTest(filename=filename):
                path = self.directory / filename
                before = path.read_bytes()

                def changed(_root, path=path, before=before):
                    path.write_bytes(before + b" ")
                    return set()

                try:
                    with patch.object(refresh, "collect_secrets", side_effect=changed):
                        with self.assertRaises(refresh.RefreshError):
                            refresh.curate(self.root, RUN)
                    self.assertFalse(list(self.root.glob("docs/evidence/*.json")))
                finally:
                    path.write_bytes(before)

    def test_summary_write_failure_preserves_refresh_marker(self):
        original = Path.write_text

        def fail_summary(path, *args, **kwargs):
            if path.name == "summary.json":
                raise OSError("Synthetic summary write failure")
            return original(path, *args, **kwargs)

        stack, _, _ = self.flow()
        with stack, patch.object(Path, "write_text", fail_summary):
            with self.assertRaises(OSError):
                refresh.refresh(self.root)
        self.assertTrue((self.root / "var/evidence-refresh.lock").is_file())
