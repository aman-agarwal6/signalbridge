"""Employer explanations must remain attached to actual reviewed evidence."""

import copy
import hashlib
import json
import shutil
import uuid
from html.parser import HTMLParser
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from django.template import Context, Engine

from scripts import portfolio as p
from scripts import portfolio_story as story
from scripts.portfolio_integrations import RECEIPTS, load_integrations


class Structure(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.links = []
        self.tags = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append(tag)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "a":
            self.links.append(attrs.get("href", ""))


class PortfolioIntegrationStoryTests(TestCase):
    def setUp(self):
        self.parent = p.ROOT / "var/tests"
        self.root = self.parent / ("portfolio-story-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup)
        self.paths = {story.RULE_PATH}
        self.paths.update(item[key] for item in story.CONTROLS for key in ("source", "test_source"))
        for relative in self.paths | {
            "docs/evidence/" + name for name in (*RECEIPTS, story.ROUTE_RECEIPT)
        }:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p.ROOT / relative, target)

    def cleanup(self):
        if self.root.exists():
            self.assertEqual(self.root.resolve().parent, self.parent.resolve())
            self.assertTrue(self.root.name.startswith("portfolio-story-"))
            shutil.rmtree(self.root)

    def load(self):
        integrations = load_integrations(self.root, p.read_public, p.require)
        return integrations, story.load_story(self.root, integrations, p.read_public, p.require)

    def test_predicates_reconcile_all_records_and_distinguish_source_trust(self):
        integrations, result = self.load()
        self.assertEqual(result["rules"]["reconciled_records"], 64)
        examples = result["rules"]["examples"]
        self.assertEqual(len(examples), 6)
        observed, synthetic = examples[:2]
        self.assertEqual((observed["rule_id"], observed["level"]), ("100201", 12))
        self.assertEqual((synthetic["rule_id"], synthetic["level"]), ("100202", 5))
        self.assertTrue(all(check["matches"] for check in observed["checks"]))
        legacy = next(row for row in examples if row["source"] == "legacy_unclassified")
        failed = [check["field"] for check in legacy["checks"] if not check["matches"]]
        self.assertEqual(failed, ["source"])
        self.assertIsNone(legacy["rule_id"])
        known_no_alert = examples[-1]
        self.assertTrue(known_no_alert["base_matches"])
        self.assertIsNone(known_no_alert["rule_id"])
        self.assertEqual(sum(bool(row["rule_id"]) for row in integrations["wazuh"]["records"]), 31)

    def test_record_source_outcome_or_level_change_cannot_keep_original_rule_explanation(self):
        integrations, _ = self.load()
        original = integrations["wazuh"]["records"]
        raw = (self.root / story.RULE_PATH).read_bytes()
        for field, value in (("source", "synthetic_demo"), ("outcome", "denied"), ("level", 3)):
            with self.subTest(field=field):
                rows = copy.deepcopy(original)
                row = next(row for row in rows if row["rule_id"] == "100201")
                row[field] = value
                with self.assertRaisesRegex(p.PortfolioError, "disagree"):
                    story.explain_records(raw, rows, p.require)

    def test_changed_xml_is_rejected_before_parsing_and_newline_conversion_preserves_binding(self):
        integrations, _ = self.load()
        path = self.root / story.RULE_PATH
        raw = path.read_bytes()
        for changed in (raw.replace(b'level="12"', b'level="15"'), b"<!DOCTYPE xml>" + raw):
            with self.subTest(changed=changed[:24]):
                with patch.object(story.ET, "fromstring") as parse:
                    with self.assertRaisesRegex(p.PortfolioError, "historical XML"):
                        story.explain_records(changed, integrations["wazuh"]["records"], p.require)
                    parse.assert_not_called()
        path.write_bytes(raw.replace(b"\n", b"\r\n"))
        _, result = self.load()
        identity = next(item for item in result["sources"] if item["path"] == story.RULE_PATH)
        self.assertEqual(identity["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(result["rules"]["executed_sha256"], story.RULE_EXECUTED_SHA)
        backfill, _ = p.read_public(self.root, next(iter(RECEIPTS)))
        self.assertEqual(
            story.RULE_EXECUTED_SHA,
            backfill["provenance"]["receipt_sha256"]["source/signalbridge_rules.xml"],
        )

    def test_authorization_keeps_authentication_denial_visibility_and_restoration_separate(self):
        _, result = self.load()
        auth = result["authorization"]
        checks = {check["id"]: check for stage in auth["stages"] for check in stage["checks"]}
        self.assertEqual(auth["counts"]["stages"], {"setup": 4, "assertion": 16, "restoration": 3})
        session = checks["removed_member_same_session_still_auth_valid"]
        self.assertEqual(
            (session["http_status"], session["outcome"]), (200, "same_session_authenticated")
        )
        state = checks["removed_member_same_cookie_next_state_denied"]
        self.assertEqual((state["http_status"], state["outcome"]), (403, "denied"))
        image = checks["removed_member_same_cookie_next_image_hidden"]
        self.assertEqual((image["http_status"], image["outcome"]), (404, "not_visible"))
        before = checks["member_next_exact_image_visible"]["content_digest"]
        self.assertEqual(before, checks["owner_next_image_survives_removal"]["content_digest"])
        self.assertEqual(before, checks["restored_member_next_image_visible"]["content_digest"])
        self.assertEqual(checks["restored_member_next_state_visible"]["stage"], "restoration")
        self.assertIn("not the same events", auth["limits"])

    def test_changed_authorization_status_or_unreviewed_text_fails_before_presentation(self):
        path = self.root / "docs/evidence" / story.ROUTE_RECEIPT
        original = json.loads(path.read_text())
        for field, value in (("status", "failed"), ("unreviewed_note", "private-value-sentinel")):
            with self.subTest(field=field):
                changed = {**original, field: value}
                path.write_text(json.dumps(changed), encoding="utf8")
                with self.assertRaisesRegex(p.PortfolioError, "not reviewed"):
                    self.load()

    def test_optional_story_does_not_expand_the_four_receipt_practice_requirement(self):
        for relative in self.paths | {"docs/evidence/" + story.ROUTE_RECEIPT}:
            (self.root / relative).unlink()
        integrations, result = self.load()
        self.assertEqual(len(RECEIPTS), 4)
        self.assertEqual(len(integrations["wazuh"]["records"]), 64)
        self.assertEqual(
            result,
            {
                "rules": None,
                "authorization": None,
                "engineering": [],
                "receipts": [],
                "sources": [],
            },
        )
        self.assertEqual(story.load_story(self.root, None, p.read_public, p.require), result)

    def test_implementation_reference_disappearance_blocks_a_stale_control_claim(self):
        path = self.root / "tests/test_soc_delivery.py"
        raw = path.read_text(encoding="utf8")
        path.write_text(
            raw.replace("def test_partial_write_recovers_exactly_once(", "def renamed_test("),
            encoding="utf8",
        )
        with self.assertRaisesRegex(p.PortfolioError, "reference is missing"):
            self.load()
        path.unlink()
        with self.assertRaisesRegex(p.PortfolioError, "every source/test"):
            self.load()

    def test_linked_and_oversized_source_refused_without_import_or_execution(self):
        target = self.root / story.RULE_PATH
        real_lstat = Path.lstat

        class Linked:
            st_mode = 0
            st_file_attributes = 1024

        def fake(path, *args, **kwargs):
            return Linked() if path == target else real_lstat(path, *args, **kwargs)

        with patch.object(Path, "lstat", fake):
            with self.assertRaisesRegex(p.PortfolioError, "must not be links"):
                story.read_source(self.root, story.RULE_PATH, p.require)
        target.write_bytes(b"x" * (story.MAX_SOURCE_BYTES + 1))
        with self.assertRaisesRegex(p.PortfolioError, "exceeds"):
            story.read_source(self.root, story.RULE_PATH, p.require)

    def test_rendered_examples_point_to_real_record_anchors_and_actual_source_symbols(self):
        integrations, result = self.load()
        html = (
            Engine()
            .from_string((p.ROOT / "templates/portfolio.html").read_text(encoding="utf8"))
            .render(Context({"integrations": integrations, "story": result}, use_l10n=False))
        )
        structure = Structure()
        structure.feed(html)
        self.assertEqual(len(structure.ids), len(set(structure.ids)))
        self.assertEqual(sum(key.startswith("record-") for key in structure.ids), 64)
        for example in result["rules"]["examples"]:
            self.assertIn(example["anchor"], structure.ids)
            self.assertIn("#" + example["anchor"], structure.links)
        self.assertIn("authorization-proof", structure.ids)
        self.assertIn("A 404 alone does not prove authorization denial", html)
        self.assertIn("modified copied snapshot", html)
        self.assertNotIn("script", structure.tags)
        self.assertNotIn("form", structure.tags)
        for control in result["engineering"]:
            for key in ("implementation", "regression"):
                reference = control[key]
                self.assertIn("../" + reference["path"], structure.links)
                self.assertIn(reference["symbol"], html)
                actual = (
                    (self.root / reference["path"])
                    .read_text(encoding="utf8")
                    .splitlines()[reference["line"] - 1]
                )
                self.assertIn("def " + reference["symbol"] + "(", actual)
