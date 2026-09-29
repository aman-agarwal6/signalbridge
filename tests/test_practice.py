"""Analyst tabletop boundaries and honest training evidence."""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from bridge import practice
from bridge.models import (
    CheckRun,
    Event,
    Integration,
    Investigation,
    Membership,
    PracticeEntry,
    PracticeSession,
)
from bridge.practice_catalog import CATALOG, digest, scenario


class PracticeTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="bettail", name="BetTail")
        cls.other = Integration.objects.create(slug="netted", name="Netted")
        cls.author = get_user_model().objects.create_user(username="practice-author")
        cls.peer = get_user_model().objects.create_user(username="practice-peer")
        cls.viewer = get_user_model().objects.create_user(username="practice-viewer")
        cls.admin = get_user_model().objects.create_user(
            username="practice-admin", is_superuser=True
        )
        for user, role in ((cls.author, "analyst"), (cls.peer, "reviewer"), (cls.viewer, "viewer")):
            Membership.objects.create(user=user, integration=cls.app, role=role)
        Membership.objects.create(user=cls.author, integration=cls.other, role="analyst")

    def setUp(self):
        self.client.force_login(self.author)
        self.session = practice.start(self.author, self.app, "access-review")
        self.url = f"/practice/{self.session.pk}/?app=bettail"

    def reveal(self, *identities):
        for identity in identities:
            self.session, _ = practice.update(
                self.author,
                self.app,
                self.session.pk,
                self.session.version,
                "reveal",
                evidence=identity,
            )

    def decision(self, **changes):
        value = dict(
            assessment="boundary_failure",
            priority="high",
            confidence="high",
            next_action="escalate_retest",
            observation="E3 reports the known private record after the removal committed.",
            interpretation="The fictional evidence supports one unauthorized read in the scoped training tenant.",
            uncertainty="No write, image, other-tenant or production access is established by this packet.",
            next_check="The application engineer should restore the policy and verify the former member, owner and restored membership.",
            citations=["E2", "E3", "E4"],
            authorship="builder_qa",
            assistance="AI-authored automated test fixture; not the project owner's analysis.",
        )
        value.update(changes)
        return value

    def submit(self, **changes):
        self.reveal("E2", "E3", "E4")
        return self.client.post(
            self.url,
            {"action": "submit", "version": self.session.version, **self.decision(**changes)},
        )

    def test_catalog_renders_and_contains_no_answer_key_or_unopened_packet(self):
        response = self.client.get("/practice/?app=bettail")
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, CATALOG["access-review"]["answer"]["explanation"])
        response = self.client.get(self.url)
        self.assertNotContains(response, CATALOG["access-review"]["packets"][1]["text"])
        self.assertNotContains(response, CATALOG["access-review"]["answer"]["explanation"])
        self.assertNotIn("snapshot", response.context["attempt"])
        self.assertEqual(
            response.context["attempt"]["packets"][1],
            {"id": "E2", "action": "Request membership and identity evidence", "opened": False},
        )

    def test_login_membership_owner_and_app_boundaries(self):
        for user in (self.peer, self.viewer, self.admin):
            self.client.force_login(user)
            for url in (
                self.url,
                f"/practice/{self.session.pk}/export/?app=bettail",
                f"/practice/{self.session.pk}/export/?app=bettail&format=json",
            ):
                with self.subTest(user=user.username, url=url):
                    self.assertEqual(self.client.get(url).status_code, 404)
                    if "export" not in url:
                        self.assertEqual(
                            self.client.post(
                                url, {"action": "reveal", "version": 1, "evidence": "E2"}
                            ).status_code,
                            404,
                        )
        self.client.force_login(self.author)
        self.assertEqual(self.client.get(self.url.replace("bettail", "netted")).status_code, 404)
        self.client.logout()
        self.assertEqual(self.client.get(self.url).status_code, 302)

    def test_viewer_cannot_start_and_revoked_role_cannot_write(self):
        self.client.force_login(self.viewer)
        self.assertEqual(
            self.client.post("/practice/?app=bettail", {"scenario": "access-review"}).status_code,
            403,
        )
        self.client.force_login(self.author)
        Membership.objects.filter(user=self.author, integration=self.app).update(role="viewer")
        self.assertEqual(
            self.client.post(
                self.url, {"action": "reveal", "version": 1, "evidence": "E2"}
            ).status_code,
            403,
        )
        self.session.refresh_from_db()
        self.assertEqual(self.session.version, 1)

    def test_csrf_is_required_for_all_mutations(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.author)
        self.assertEqual(
            client.post("/practice/?app=bettail", {"scenario": "access-review"}).status_code, 403
        )
        self.assertEqual(
            client.post(self.url, {"action": "reveal", "version": 1, "evidence": "E2"}).status_code,
            403,
        )

    def test_get_has_no_mutating_effect_and_other_methods_fail(self):
        self.client.get(self.url, {"action": "reveal", "evidence": "E2"})
        self.session.refresh_from_db()
        self.assertEqual(self.session.revealed, [])
        self.assertEqual(self.client.delete(self.url).status_code, 405)
        self.assertEqual(
            self.client.post(f"/practice/{self.session.pk}/export/?app=bettail").status_code, 405
        )

    def test_reveal_only_fixed_evidence_and_refuse_duplicates(self):
        for evidence in ("../../.env", "https://example.invalid", "E99"):
            with self.subTest(evidence=evidence), self.assertRaises(practice.PracticeError):
                practice.update(
                    self.author, self.app, self.session.pk, 1, "reveal", evidence=evidence
                )
        self.reveal("E2")
        self.assertContains(self.client.get(self.url), "transaction committed at 09:01:00Z")
        with self.assertRaises(practice.PracticeError):
            practice.update(
                self.author,
                self.app,
                self.session.pk,
                self.session.version,
                "reveal",
                evidence="E2",
            )

    def test_stale_tab_cannot_overwrite_newer_work(self):
        self.reveal("E2")
        response = self.client.post(
            self.url, {"action": "save", "version": 1, "observation": "Stale text"}
        )
        self.assertContains(response, "changed in another tab")
        self.session.refresh_from_db()
        self.assertEqual(self.session.revealed, ["E2"])
        self.assertEqual(self.session.decision, {})

    def test_blank_draft_allowed_but_submission_requires_reasoning_and_citations(self):
        response = self.client.post(
            self.url, {"action": "save", "version": 1, "observation": "Starting note"}
        )
        self.assertEqual(response.status_code, 302)
        self.session.refresh_from_db()
        self.assertEqual(self.session.decision["observation"], "Starting note")
        response = self.client.post(self.url, {"action": "submit", "version": self.session.version})
        self.assertEqual(response.status_code, 400)
        self.session.refresh_from_db()
        self.assertEqual(self.session.status, "draft")
        self.assertEqual(self.session.entries.count(), 2)

    def test_invalid_choices_oversize_and_unopened_citations_rejected(self):
        self.reveal("E2", "E3")
        for change in (
            dict(assessment="fixed"),
            dict(observation="x" * 2001),
            dict(citations=["E2", "E4"]),
            dict(citations=["E2", "E2"]),
            dict(citations=["E2"]),
            dict(interpretation="short"),
        ):
            with self.subTest(change=next(iter(change))):
                response = self.client.post(
                    self.url,
                    {
                        "action": "submit",
                        "version": self.session.version,
                        **self.decision(**change),
                    },
                )
                self.assertEqual(response.status_code, 400)
        self.session.refresh_from_db()
        self.assertEqual(self.session.decision, {})

    def test_unknown_and_ambiguous_post_fields_rejected(self):
        for values in (
            dict(action=["save", "submit"], version=1),
            dict(action="save", version=1, author=self.peer.pk),
            dict(action="reveal", version=1, evidence=["E1", "E2"]),
        ):
            self.assertEqual(self.client.post(self.url, values).status_code, 400)
        self.assertEqual(
            self.client.post(
                "/practice/?app=bettail", {"scenario": ["access-review", "quiet-queue"]}
            ).status_code,
            400,
        )

    def test_submission_reveals_feedback_without_grading_free_text(self):
        self.assertEqual(self.submit().status_code, 302)
        response = self.client.get(self.url)
        self.assertContains(response, "written reasoning is not automatically graded")
        self.session.refresh_from_db()
        self.assertTrue(all(check["matches"] for check in self.session.review["checks"]))
        original = self.session.decision.copy()
        self.client.post(
            self.url, {"action": "save", "version": self.session.version, "observation": "Changed"}
        )
        self.session.refresh_from_db()
        self.assertEqual(self.session.decision, original)

    def test_incorrect_answer_is_retained_and_receives_explanation(self):
        self.submit(assessment="benign", priority="low")
        self.session.refresh_from_db()
        self.assertEqual(self.session.decision["assessment"], "benign")
        self.assertFalse(self.session.review["checks"][0]["matches"])
        self.assertIn("one unauthorized read", self.session.review["explanation"])

    def test_export_is_owner_private_escaped_and_explicitly_coached(self):
        self.assertEqual(
            self.client.get(f"/practice/{self.session.pk}/export/?app=bettail").status_code, 409
        )
        self.submit(
            observation="A fictional observation with <script>alert('example')</script> text."
        )
        response = self.client.get(f"/practice/{self.session.pk}/export/?app=bettail")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment;", response["Content-Disposition"])
        self.assertIn("no-store", response["Cache-Control"])
        self.assertNotContains(response, "<script>")
        self.assertContains(response, "&lt;script&gt;")
        self.assertNotContains(response, self.author.username)
        self.assertContains(response, "Human reviewer checklist")
        data = self.client.get(
            f"/practice/{self.session.pk}/export/?app=bettail&format=json"
        ).json()
        self.assertTrue(data["fictional"])
        self.assertFalse(data["independent_assessment"])
        self.assertNotIn("answer", data["attempt"])
        self.assertNotIn("text", data["attempt"]["packets"][0])
        self.assertEqual(len(data["history"]), 5)

    def test_snapshot_and_earlier_notes_preserved(self):
        original_hash = self.session.snapshot_hash
        with patch.dict(CATALOG, {"access-review": {"title": "Changed catalog"}}):
            self.assertContains(
                self.client.get(self.url), "Private record after a membership change"
            )
        self.client.post(self.url, {"action": "save", "version": 1, "observation": "First draft"})
        self.client.post(self.url, {"action": "save", "version": 2, "observation": "Second draft"})
        self.session.refresh_from_db()
        self.assertEqual(self.session.snapshot_hash, original_hash)
        self.assertEqual(self.session.entries.get(version=2).content["observation"], "First draft")
        entry = self.session.entries.first()
        with self.assertRaises(ValueError):
            entry.save()

    def test_tampered_snapshot_blocks_changes_and_exports(self):
        self.session.snapshot["brief"] = "Altered scenario"
        self.session.save(update_fields=["snapshot"])
        response = self.client.post(self.url, {"action": "reveal", "version": 1, "evidence": "E2"})
        self.assertContains(response, "integrity check")
        self.session.status = "submitted"
        self.session.save(update_fields=["status"])
        self.assertEqual(
            self.client.get(f"/practice/{self.session.pk}/export/?app=bettail").status_code, 409
        )

    def test_attempt_and_history_limits_preserve_existing_work(self):
        with patch.object(practice, "MAX_SESSIONS", 1), self.assertRaises(practice.PracticeError):
            practice.start(self.author, self.app, "access-review")
        with patch.object(practice, "MAX_ENTRIES", 1), self.assertRaises(practice.PracticeError):
            practice.update(self.author, self.app, self.session.pk, 1, "reveal", evidence="E1")
        self.assertEqual(PracticeSession.objects.count(), 1)
        self.assertEqual(PracticeEntry.objects.count(), 1)

    def test_practice_creates_no_operational_security_evidence(self):
        self.submit()
        self.assertEqual(Event.objects.count(), 0)
        self.assertEqual(Investigation.objects.count(), 0)
        self.assertEqual(CheckRun.objects.count(), 0)

    def test_all_exercises_have_valid_consistent_teaching_reference(self):
        for key in CATALOG:
            with self.subTest(key=key):
                packet = scenario(key)
                self.assertTrue(packet["fictional"])
                self.assertEqual(len(digest(packet)), 64)
                self.assertTrue(
                    set(packet["answer"]["required"]).issubset(
                        {row["id"] for row in packet["packets"]}
                    )
                )
                session = practice.start(self.author, self.app, key)
                for row in packet["packets"]:
                    session, _ = practice.update(
                        self.author,
                        self.app,
                        session.pk,
                        session.version,
                        "reveal",
                        evidence=row["id"],
                    )
                values = self.decision(
                    **{
                        k: packet["answer"][k]
                        for k in ("assessment", "priority", "confidence", "next_action")
                    },
                    citations=packet["answer"]["required"],
                )
                session, errors = practice.update(
                    self.author, self.app, session.pk, session.version, "submit", form_data=values
                )
                self.assertIsNone(errors)
                self.assertTrue(all(check["matches"] for check in session.review["checks"]))
