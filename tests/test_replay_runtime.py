"""Replay provenance stays tied to the startup source snapshot, never newer disk bytes."""

import hashlib
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from bridge import evaluation
from bridge.models import Audit, Integration, Membership, Replay
from bridge.services import create_replay, decide_replay


def changed_source(name, exception=None, enabled=lambda: True):
    original = Path.read_bytes
    target = Path(evaluation.__file__).with_name(name)

    def read(path):
        if path == target and enabled():
            if exception is not None:
                raise exception
            return original(path) + b"\n# synthetic changed source\n"
        return original(path)

    return patch.object(Path, "read_bytes", read)


class ReplayRuntimeIdentityTests(SimpleTestCase):
    def test_unchanged_source_retains_original_fingerprint_order_and_replay_behavior(self):
        directory = Path(evaluation.__file__).parent
        expected = hashlib.sha256(
            b"".join(
                (directory / name).read_bytes()
                for name in ("engine.py", "contract.py", "evaluation.py")
            )
        ).hexdigest()
        _, fingerprint, result = evaluation.evaluate("revised", "bettail")
        self.assertEqual(fingerprint, expected)
        self.assertEqual((result["baseline_cases"], result["reviewable_cases"]), (7, 6))
        self.assertEqual(result["retained_suspicious_episodes"], 5)

    def test_each_source_drift_is_rejected_before_reading_fixtures_or_running_triage(self):
        for name in ("engine.py", "contract.py", "evaluation.py"):
            with (
                self.subTest(name=name),
                changed_source(name),
                patch.object(evaluation, "fixture_paths") as fixtures,
                patch.object(evaluation, "triage") as triage,
            ):
                with self.assertRaises(ValueError) as rejected:
                    evaluation.evaluate("revised", "bettail")
                self.assertEqual(str(rejected.exception), evaluation.SOURCE_DRIFT_MESSAGE)
                fixtures.assert_not_called()
                triage.assert_not_called()

    def test_missing_or_unreadable_source_uses_fixed_safe_diagnostic(self):
        for exception in (
            FileNotFoundError("private-path-sentinel"),
            PermissionError("private-path-sentinel"),
        ):
            with (
                changed_source("engine.py", exception),
                patch.object(evaluation, "triage") as triage,
            ):
                with self.assertRaises(ValueError) as rejected:
                    evaluation.evaluate("baseline", "bettail")
                self.assertEqual(str(rejected.exception), evaluation.SOURCE_DRIFT_MESSAGE)
                self.assertNotIn("private-path-sentinel", str(rejected.exception))
                triage.assert_not_called()

    def test_unavailable_startup_snapshot_cannot_be_replaced_with_current_disk_identity(self):
        with (
            patch.object(evaluation, "_PROCESS_SOURCE_PARTS", None),
            patch.object(evaluation, "triage") as triage,
        ):
            with self.assertRaises(ValueError) as rejected:
                evaluation.evaluate("revised", "bettail")
            self.assertEqual(str(rejected.exception), evaluation.SOURCE_DRIFT_MESSAGE)
            triage.assert_not_called()

    def test_source_drift_during_triage_prevents_result_return(self):
        original = evaluation.triage
        changed = False

        def run(events, policy):
            nonlocal changed
            result = original(events, policy)
            changed = True
            return result

        with (
            changed_source("engine.py", enabled=lambda: changed),
            patch.object(evaluation, "triage", side_effect=run),
        ):
            with self.assertRaises(ValueError) as rejected:
                evaluation.evaluate("revised", "bettail")
        self.assertTrue(changed)
        self.assertEqual(str(rejected.exception), evaluation.SOURCE_DRIFT_MESSAGE)

    def test_restored_startup_bytes_keep_original_identity_without_relabelling(self):
        before = evaluation.evaluate("revised", "bettail")
        with changed_source("engine.py"), self.assertRaises(ValueError):
            evaluation.evaluate("revised", "bettail")
        self.assertEqual(evaluation.evaluate("revised", "bettail"), before)


class ReplayRuntimeWorkflowTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="bettail", name="BetTail")
        cls.author = get_user_model().objects.create_user(username="runtime-analyst")
        cls.reviewer = get_user_model().objects.create_user(username="runtime-reviewer")
        cls.viewer = get_user_model().objects.create_user(username="runtime-viewer")
        for user, role in (
            (cls.author, "analyst"),
            (cls.reviewer, "reviewer"),
            (cls.viewer, "viewer"),
        ):
            Membership.objects.create(user=user, integration=cls.app, role=role)

    def test_source_drift_prevents_proposal_and_audit_creation(self):
        with changed_source("evaluation.py"):
            with self.assertRaises(ValueError) as rejected:
                create_replay(self.author, self.app, "revised")
        self.assertEqual(str(rejected.exception), evaluation.SOURCE_DRIFT_MESSAGE)
        self.assertFalse(Replay.objects.exists())
        self.assertFalse(Audit.objects.exists())

    def test_source_drift_prevents_approval_without_changing_prior_proposal_or_audit(self):
        replay = create_replay(self.author, self.app, "revised")
        previous_audits = Audit.objects.count()
        previous_hash = replay.engine_hash
        with changed_source("contract.py"), self.assertRaises(ValueError):
            decide_replay(self.reviewer, replay.pk, "approved", replay.version)
        replay.refresh_from_db()
        self.assertEqual((replay.status, replay.version, replay.reviewer_id), ("pending", 1, None))
        self.assertEqual(replay.engine_hash, previous_hash)
        self.assertIsNone(replay.decided_at)
        self.assertEqual(Audit.objects.count(), previous_audits)

    def test_missing_source_cannot_authorize_rejection_either(self):
        replay = create_replay(self.author, self.app, "revised")
        with (
            changed_source("engine.py", FileNotFoundError("synthetic missing file")),
            self.assertRaises(ValueError),
        ):
            decide_replay(self.reviewer, replay.pk, "rejected", replay.version)
        replay.refresh_from_db()
        self.assertEqual((replay.status, replay.version), ("pending", 1))
        self.assertFalse(Audit.objects.filter(action="replay.rejected").exists())

    def test_unauthorized_user_is_denied_before_provenance_or_dataset_access(self):
        with patch.object(
            evaluation, "require_runtime_source", side_effect=AssertionError("source read")
        ):
            with self.assertRaises(PermissionError):
                create_replay(self.viewer, self.app, "revised")
        self.assertFalse(Replay.objects.exists())

    def test_drift_during_comparison_does_not_persist_partial_proposal(self):
        original = evaluation.triage
        changed = False

        def run(events, policy):
            nonlocal changed
            result = original(events, policy)
            changed = True
            return result

        with (
            changed_source("engine.py", enabled=lambda: changed),
            patch.object(evaluation, "triage", side_effect=run),
        ):
            with self.assertRaises(ValueError):
                create_replay(self.author, self.app, "revised")
        self.assertTrue(changed)
        self.assertFalse(Replay.objects.exists())
        self.assertFalse(Audit.objects.exists())
