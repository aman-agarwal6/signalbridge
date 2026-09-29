"""Historical review retains actual evidence without inventing learner work."""

import json
import shutil
import uuid
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, SimpleTestCase, TestCase

from bridge import practice, recorded_practice
from bridge.models import CheckRun, Event, Integration, Investigation, Membership, PracticeSession
from bridge.practice_catalog import digest
from scripts.portfolio_integrations import RECEIPTS

ROOT = Path(__file__).resolve().parents[1]


class ReviewedPracticeSourcesTests(SimpleTestCase):
    def setUp(self):
        self.parent = ROOT / "var/tests"
        self.root = self.parent / ("recorded-practice-" + uuid.uuid4().hex)
        self.evidence = self.root / "docs/evidence"
        self.evidence.mkdir(parents=True)
        self.addCleanup(self.cleanup)
        for name in RECEIPTS:
            shutil.copyfile(ROOT / "docs/evidence" / name, self.evidence / name)
        self.patch = patch.object(recorded_practice, "ROOT", self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def cleanup(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.parent.resolve()) or not target.name.startswith(
            "recorded-practice-"
        ):
            raise RuntimeError("Unsafe practice fixture cleanup.")
        shutil.rmtree(target)

    def load(self):
        return recorded_practice.scenario("recorded-wazuh-review", "bettail")

    def test_actual_receipts_have_record_references_and_correct_denominators(self):
        value = self.load()
        self.assertFalse(value["fictional"])
        self.assertEqual(value["evidence_kind"], "historical_local_lab")
        self.assertIn("exported=64, received=64, custom alerts=31", value["packets"][0]["text"])
        self.assertIn("33 received records", value["packets"][2]["text"])
        self.assertEqual(value["packets"][1]["reference"]["rule_id"], "100201")
        self.assertEqual(
            value["packets"][1]["reference"]["run_id"], "9432c474-f48e-4b70-87a8-9fd7d33bf51c"
        )
        records = json.loads((self.evidence / "20260925-wazuh-reviewed-records.json").read_text())
        matching = [
            row
            for row in records["observations"]
            if row["event_id"] == value["packets"][1]["reference"]["event_id"]
        ]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["rule_id"], "100201")
        self.assertEqual({row["receipt"] for row in value["receipts"]}, set(RECEIPTS))

    def test_zap_failed_and_retry_runs_retain_separate_identities(self):
        value = recorded_practice.scenario("recorded-zap-review", "signalbridge")
        self.assertIn("coverage=incomplete; accepted requests=0", value["packets"][0]["text"])
        self.assertIn("accepted 3 fixed GET requests", value["packets"][1]["text"])
        self.assertIn("reported 5 normalized findings", value["packets"][1]["text"])
        self.assertNotEqual(
            value["packets"][0]["reference"]["run_id"], value["packets"][1]["reference"]["run_id"]
        )
        self.assertIn("did not close findings", value["packets"][2]["text"])

    def test_missing_all_or_partial_receipts_cannot_become_a_recorded_assignment(self):
        for name in RECEIPTS:
            (self.evidence / name).unlink()
            with self.assertRaises(recorded_practice.RecordedEvidenceError):
                self.load()

    def test_altered_counts_or_unreviewed_text_fail_closed(self):
        path = self.evidence / "20260925-wazuh-product-backfill.json"
        original = path.read_bytes()
        for mutation in (
            {"counts": {"received": 999}},
            {"unreviewed": "Pretend this was a live production incident"},
        ):
            value = json.loads(original)
            value.update(mutation)
            path.write_text(json.dumps(value), encoding="utf-8")
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(recorded_practice.RecordedEvidenceError),
            ):
                self.load()

    def test_duplicate_json_keys_and_oversize_receipts_are_rejected(self):
        path = self.evidence / "20260925-wazuh-product-backfill.json"
        for raw in (b'{"kind":1,"kind":1}', b" " * (recorded_practice.MAX_BYTES + 1)):
            path.write_bytes(raw)
            with self.assertRaises(recorded_practice.RecordedEvidenceError):
                self.load()

    def test_line_ending_changes_preserve_canonical_review_identity(self):
        before = self.load()
        for name in RECEIPTS:
            path = self.evidence / name
            path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        after = self.load()
        self.assertEqual(
            [r["reviewed_content_sha256"] for r in before["receipts"]],
            [r["reviewed_content_sha256"] for r in after["receipts"]],
        )

    def test_unknown_receipt_names_never_read_arbitrary_files(self):
        for name in ("../../.env", "other.json", "https://example.invalid"):
            with (
                self.subTest(name=name),
                self.assertRaises(recorded_practice.RecordedEvidenceError),
            ):
                recorded_practice.read_public(self.root, name)

    def test_unknown_assignment_and_wrong_workspace_fail_closed(self):
        for key, scope in (
            ("unknown", "bettail"),
            ("recorded-zap-review", "bettail"),
            ("recorded-wazuh-review", "netted"),
        ):
            with (
                self.subTest(key=key, scope=scope),
                self.assertRaises(recorded_practice.RecordedEvidenceError),
            ):
                recorded_practice.scenario(key, scope)


class RecordedPracticeWorkflowTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="bettail", name="BetTail")
        cls.internal = Integration.objects.create(slug="signalbridge", name="SignalBridge")
        cls.other = Integration.objects.create(slug="netted", name="Netted")
        cls.author = get_user_model().objects.create_user(username="record-review-author")
        cls.peer = get_user_model().objects.create_user(username="record-review-peer")
        cls.viewer = get_user_model().objects.create_user(username="record-review-viewer")
        for app in (cls.app, cls.internal, cls.other):
            Membership.objects.create(user=cls.author, integration=app, role="analyst")
        Membership.objects.create(user=cls.peer, integration=cls.app, role="reviewer")
        Membership.objects.create(user=cls.viewer, integration=cls.app, role="viewer")

    def setUp(self):
        self.client.force_login(self.author)
        self.session = practice.start(self.author, self.app, "recorded-wazuh-review")
        self.url = f"/practice/{self.session.pk}/?app=bettail"
        self.export_url = f"/practice/{self.session.pk}/export/?app=bettail"

    def reveal(self):
        for identity in ("E1", "E2", "E3"):
            self.session, _ = practice.update(
                self.author,
                self.app,
                self.session.pk,
                self.session.version,
                "reveal",
                evidence=identity,
            )

    def decision(self, **changes):
        data = {
            "assessment": "inconclusive",
            "priority": "medium",
            "confidence": "high",
            "next_action": "corroborate_source",
            "observation": "BUILDER TEST ONLY: the retained receipt accounts for the recorded local batch.",
            "interpretation": "BUILDER TEST ONLY: receipt of a record does not independently prove its source observation.",
            "uncertainty": "BUILDER TEST ONLY: current service health and production exposure are outside this receipt.",
            "next_check": "BUILDER TEST ONLY: ask the lab operator to provide the original access evidence and controls.",
            "citations": ["E1", "E2", "E3"],
            "authorship": "builder_qa",
            "assistance": "AI-authored regression fixture; not Aman or another learner's work.",
        }
        data.update(changes)
        return data

    def submit(self, **changes):
        self.reveal()
        return self.client.post(
            self.url,
            {"action": "submit", "version": self.session.version, **self.decision(**changes)},
        )

    def test_catalog_labels_actual_evidence_and_limits_each_assignment_to_its_scope(self):
        response = self.client.get("/practice/?app=bettail")
        self.assertContains(response, "actual Wazuh collection receipt")
        self.assertNotContains(response, "actual ZAP failure and retry")
        response = self.client.get("/practice/?app=signalbridge")
        self.assertContains(response, "actual ZAP failure and retry")
        self.assertNotContains(response, "actual Wazuh collection receipt")
        self.assertNotContains(
            self.client.get("/practice/?app=netted"), "Start a private evidence review"
        )

    def test_new_note_and_authorship_start_blank_without_revealing_an_answer(self):
        response = self.client.get(self.url)
        self.assertContains(response, "HISTORICAL LAB EVIDENCE REVIEW")
        self.assertEqual(response.context["form"].initial, {})
        self.assertNotContains(response, self.session.snapshot["answer"]["explanation"])
        self.assertNotContains(response, self.session.snapshot["packets"][1]["text"])
        self.assertEqual(self.session.decision, {})

    def test_missing_evidence_blocks_creation_without_partial_session(self):
        before = PracticeSession.objects.count()
        with patch.object(recorded_practice, "load_integrations", return_value=None):
            response = self.client.post(
                "/practice/?app=bettail", {"scenario": "recorded-wazuh-review"}
            )
        self.assertContains(response, "evidence is unavailable or inconsistent")
        self.assertEqual(PracticeSession.objects.count(), before)

    def test_recorded_start_does_not_allow_wrong_app_or_unknown_scenario(self):
        for key in ("recorded-zap-review", "unlisted-case"):
            with self.assertRaises(practice.PracticeError):
                practice.start(self.author, self.app, key)
        self.assertEqual(PracticeSession.objects.count(), 1)

    def test_owner_and_membership_boundaries_apply_to_historical_evidence(self):
        for user in (self.peer, self.viewer):
            self.client.force_login(user)
            self.assertEqual(self.client.get(self.url).status_code, 404)
            self.assertEqual(self.client.get(self.export_url).status_code, 404)
        self.assertEqual(
            self.client.post(
                "/practice/?app=bettail", {"scenario": "recorded-wazuh-review"}
            ).status_code,
            403,
        )
        self.client.force_login(self.author)
        self.assertEqual(self.client.get(self.url.replace("bettail", "netted")).status_code, 404)
        Membership.objects.filter(user=self.author, integration=self.app).update(role="viewer")
        self.assertEqual(
            self.client.post(
                self.url, {"action": "reveal", "version": 1, "evidence": "E1"}
            ).status_code,
            403,
        )

    def test_csrf_required_for_recorded_assignment_creation(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.author)
        self.assertEqual(
            client.post(
                "/practice/?app=bettail", {"scenario": "recorded-wazuh-review"}
            ).status_code,
            403,
        )

    def test_authorship_and_assistance_are_required_bounded_and_have_no_default(self):
        self.reveal()
        for changes in (
            {"authorship": ""},
            {"assistance": ""},
            {"authorship": "independently_certified"},
            {"assistance": "x" * 601},
        ):
            response = self.client.post(
                self.url,
                {"action": "submit", "version": self.session.version, **self.decision(**changes)},
            )
            self.assertEqual(response.status_code, 400)
        self.session.refresh_from_db()
        self.assertEqual(self.session.status, "draft")
        self.assertEqual(self.session.decision, {})

    def test_unknown_reviewer_or_authorship_verification_fields_rejected(self):
        for name in ("reviewer", "reviewer_verified", "authorship_verified"):
            self.assertEqual(
                self.client.post(
                    self.url, {"action": "save", "version": 1, name: "claimed"}
                ).status_code,
                400,
            )

    def test_saved_disclosure_is_versioned_and_stale_tab_cannot_replace_it(self):
        data = {
            "action": "save",
            "version": 1,
            "authorship": "builder_qa",
            "assistance": "AI test fixture",
        }
        self.assertEqual(self.client.post(self.url, data).status_code, 302)
        self.client.post(self.url, {**data, "authorship": "participant"})
        self.session.refresh_from_db()
        self.assertEqual(self.session.decision["authorship"], "builder_qa")
        self.assertEqual(
            self.session.entries.get(version=2).content["assistance"], "AI test fixture"
        )

    def test_export_retains_exact_references_and_separates_authorship_from_evidence(self):
        self.assertEqual(self.submit().status_code, 302)
        response = self.client.get(self.export_url)
        self.assertContains(response, "Builder / AI quality-assurance exercise")
        self.assertContains(response, "reviewed historical local lab receipts")
        self.assertNotContains(response, "Fictional tabletop.")
        self.assertNotContains(response, self.author.username)
        self.assertContains(response, "Human reviewer checklist")
        self.assertContains(response, "Review: ____________________")
        data = self.client.get(self.export_url + "&format=json").json()
        self.assertFalse(data["fictional"])
        self.assertFalse(data["independent_assessment"])
        self.assertFalse(data["attempt"]["authorship_verified"])
        self.assertEqual(data["attempt"]["human_review_status"], "Not recorded")
        self.assertEqual(data["attempt"]["receipts"], self.session.snapshot["receipts"])
        self.assertEqual(
            data["attempt"]["packets"][1]["reference"],
            self.session.snapshot["packets"][1]["reference"],
        )
        self.assertEqual(data["history"][-1]["content"]["authorship"], "builder_qa")
        self.assertNotIn("answer", data["attempt"])
        self.assertEqual(len(data["attempt"]["review"]["checks"]), 1)

    def test_disclosure_and_notes_are_html_escaped(self):
        self.submit(
            assistance="<script>window.example='test'</script>",
            observation="BUILDER TEST ONLY: <img src=x onerror=alert(1)> escaped note.",
        )
        response = self.client.get(self.export_url)
        self.assertNotContains(response, "<script>")
        self.assertNotContains(response, "<img")
        self.assertContains(response, "&lt;script&gt;")
        self.assertContains(response, "&lt;img")

    def test_old_submitted_attempt_keeps_fictional_label_without_invented_authorship(self):
        old = practice.start(self.author, self.app, "access-review")
        old.status = "submitted"
        old.decision = {"observation": "Historical test record without an authorship declaration."}
        old.save()
        response = self.client.get(f"/practice/{old.pk}/export/?app=bettail")
        self.assertContains(response, "Fictional tabletop.")
        self.assertContains(response, "Not recorded")
        self.assertNotContains(response, "Learner-authored responses")
        data = self.client.get(f"/practice/{old.pk}/export/?app=bettail&format=json").json()
        self.assertTrue(data["fictional"])
        self.assertEqual(data["attempt"]["authorship"], "Not recorded")

    def test_snapshot_references_cannot_be_changed_without_invalidating_export(self):
        self.submit()
        self.session.refresh_from_db()
        self.session.snapshot["packets"][1]["reference"]["event_id"] = "replacement"
        self.session.save(update_fields=["snapshot"])
        self.assertNotEqual(self.session.snapshot_hash, digest(self.session.snapshot))
        self.assertEqual(self.client.get(self.export_url).status_code, 409)

    def test_existing_attempt_retains_evidence_when_source_files_later_unavailable(self):
        original = self.session.snapshot_hash
        with patch.object(
            recorded_practice, "load_integrations", side_effect=AssertionError("must not reload")
        ):
            self.assertEqual(self.submit().status_code, 302)
            response = self.client.get(self.export_url)
        self.assertEqual(response.status_code, 200)
        self.session.refresh_from_db()
        self.assertEqual(self.session.snapshot_hash, original)

    def test_historical_practice_does_not_create_operational_results(self):
        self.submit()
        self.assertEqual(Event.objects.count(), 0)
        self.assertEqual(Investigation.objects.count(), 0)
        self.assertEqual(CheckRun.objects.count(), 0)
