"""Read-only pilot receipts cannot become cross-application coverage claims."""

import copy
import hashlib
import json
import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from bridge.models import Audit, CheckRun, Event, Integration, Membership
from bridge.soc_presentation import pilot_cards
from tests.test_soc_pilot_evidence import SocPilotEvidenceTests, bound_wazuh_fixture


def receipt(tool="wazuh"):
    counts = (
        {
            "logtest_cases": 27,
            "collection_inputs": 19,
            "fixture_inputs": 18,
            "tail_sentinels": 1,
            "alerts": 12,
            "negative_controls": 7,
        }
        if tool == "wazuh"
        else {
            "requests": 3,
            "header_positive_paths": 2,
            "header_negative_paths": 1,
            "reported_findings": 4,
        }
    )
    return {
        "evidence_kind": "soc_pilot",
        "tool": tool,
        "app": "signalbridge",
        "status": "passed",
        "pilot": {
            "run_id": str(uuid.uuid4()),
            "recorded_at": "2026-09-24T12:00:00Z",
            "runtime_version": "4.14.8" if tool == "wazuh" else "2.17.0",
            "scope": "synthetic_fixture",
            "source_app_assessed": False,
            "continuous_connection": False,
            "stopped_at_end": True,
            "counts": counts,
            "provenance": {
                "verification": "builder_local_receipt_consistency_and_fresh_stopped_gate",
                "fresh_stopped_gate_required": True,
                "source_sha256": "a" * 64,
                "receipt_sha256": {},
                "containers": [],
            },
        },
    }


class SocPilotConsoleTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.lab = Integration.objects.create(
            slug="signalbridge", name="SignalBridge", enabled=False
        )
        cls.app = Integration.objects.create(slug="bettail", name="BetTail")
        cls.other = Integration.objects.create(slug="netted", name="Netted")
        cls.viewer = get_user_model().objects.create_user(username="soc-proof-viewer")
        cls.restricted = get_user_model().objects.create_user(username="soc-app-only")
        for app in (cls.lab, cls.app):
            Membership.objects.create(user=cls.viewer, integration=app, role="viewer")
        Membership.objects.create(user=cls.restricted, integration=cls.app, role="viewer")

    def setUp(self):
        self.client.force_login(self.viewer)

    def make_run(self, tool="wazuh", status="passed", result=None, integration=None):
        result = receipt(tool) if result is None else result
        return CheckRun.objects.create(
            integration=integration or self.lab,
            suite="Synthetic SOC pilot",
            revision="a" * 64,
            digest=hashlib.sha256(
                json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            status=status,
            result=result,
        )

    def test_no_receipt_does_not_claim_verification(self):
        response = self.client.get("/integrations/?app=signalbridge")
        self.assertContains(response, "Pilot not verified", count=2)
        self.assertNotContains(response, "Local pilot verified")
        self.assertNotContains(response, "3 not integrated")

    def test_verified_receipts_show_counts_and_historical_scope(self):
        self.make_run()
        self.make_run("zap")
        response = self.client.get("/integrations/?app=signalbridge")
        self.assertContains(response, "Local pilot verified", count=2)
        for text in (
            "Latest imported receipt",
            "Stopped at the end of the test",
            "27 real Wazuh rule checks",
            "19-input",
            "three fixed GET requests",
            "No BetTail or Netted assessment",
            "Failed raw attempts may exist outside this imported history",
            "4.14.8",
            "2.17.0",
            "Receipt SHA-256",
        ):
            self.assertContains(response, text)
        self.assertTrue(response.context["wazuh_pilot"]["verified"])

    def test_newest_failed_receipt_never_falls_back_to_prior_pass(self):
        self.make_run()
        self.make_run(status="failed")
        response = self.client.get("/integrations/?app=signalbridge")
        self.assertContains(response, "Latest receipt failed")
        self.assertNotContains(response, "Local pilot verified")
        self.assertNotContains(response, "27 real Wazuh rule checks")

    def test_bound_observations_are_readable_and_legacy_receipts_are_not_upgraded(self):
        legacy = self.make_run()
        response = self.client.get("/integrations/?app=signalbridge")
        self.assertContains(response, "Legacy receipt")
        self.assertNotContains(response, "Explore the 12 observed signals")
        legacy.delete()
        data, source, fresh, _ = bound_wazuh_fixture()
        checked = SocPilotEvidenceTests().load("wazuh", data=data, source=source, fresh=fresh)
        run = self.make_run(result=checked["result"])
        run.revision = checked["revision"]
        run.save(update_fields=["revision"])
        response = self.client.get("/integrations/?app=signalbridge")
        self.assertContains(response, "Explore the 12 observed signals")
        self.assertContains(response, "can indicate that the control worked")
        self.assertContains(response, 'class="pilot-observation"', count=12)
        self.assertNotContains(response, "Legacy receipt")
        self.assertNotContains(
            self.client.get("/integrations/?app=bettail"), "Explore the 12 observed signals"
        )
        # Corrupt binding plus recomputed content digest still cannot receive a badge.
        run.result["pilot"]["run_binding"]["context_sha256"] = "0" * 64
        run.digest = hashlib.sha256(
            json.dumps(run.result, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        run.save(update_fields=["result", "digest"])
        response = self.client.get("/integrations/?app=signalbridge")
        self.assertContains(response, "Receipt needs review")
        self.assertNotContains(response, "Explore the 12 observed signals")

    def test_changed_content_or_digest_cannot_retain_verified_badge(self):
        for change in ("content", "digest"):
            with self.subTest(change=change):
                run = self.make_run("zap")
                if change == "content":
                    # This is a semantically valid count but no longer the imported receipt.
                    run.result["pilot"]["counts"]["reported_findings"] += 1
                    run.save(update_fields=["result"])
                else:
                    run.digest = "0" * 64
                    run.save(update_fields=["digest"])
                response = self.client.get("/integrations/?app=signalbridge")
                self.assertContains(response, "Receipt needs review")
                self.assertNotContains(response, "Local pilot verified")
                run.delete()

    def test_source_binding_and_canonical_v4_identity_are_required(self):
        for change in ("revision", "missing_source", "mismatched_source", "uuid_version"):
            with self.subTest(change=change):
                value = receipt()
                if change == "missing_source":
                    del value["pilot"]["provenance"]["source_sha256"]
                elif change == "mismatched_source":
                    value["pilot"]["provenance"]["source_sha256"] = "b" * 64
                elif change == "uuid_version":
                    value["pilot"]["run_id"] = "aaaaaaaa-1111-1111-8111-aaaaaaaaaaaa"
                run = self.make_run(result=value)
                if change == "revision":
                    run.revision = ""
                    run.save(update_fields=["revision"])
                response = self.client.get("/integrations/?app=signalbridge")
                self.assertContains(response, "Receipt needs review")
                self.assertNotContains(response, "Local pilot verified")
                run.delete()

    def test_malformed_or_broadened_passed_receipt_fails_closed(self):
        for field, value in (
            ("stopped_at_end", False),
            ("source_app_assessed", True),
            ("continuous_connection", True),
            ("runtime_version", "<script>private-sentinel</script>"),
            ("counts", {"logtest_cases": True}),
        ):
            with self.subTest(field=field):
                value_result = receipt()
                value_result["pilot"][field] = value
                run = self.make_run(result=value_result)
                response = self.client.get("/integrations/?app=signalbridge")
                self.assertContains(response, "Receipt needs review")
                self.assertNotContains(response, "Local pilot verified")
                self.assertNotContains(response, "private-sentinel")
                run.delete()

    def test_source_workspace_never_queries_or_displays_lab_receipts(self):
        self.make_run()
        with CaptureQueriesContext(connection) as queries:
            cards = pilot_cards(self.app)
        self.assertEqual(len(queries), 0)
        self.assertFalse(cards["wazuh_pilot"]["has_receipt"])
        response = self.client.get("/integrations/?app=bettail")
        self.assertContains(response, "No application assessment", count=2)
        self.assertContains(response, "Inspect authorized lab pilot evidence")
        self.assertNotContains(response, "Local pilot verified")
        self.assertNotContains(response, "27 real Wazuh rule checks")

    def test_membership_is_required_for_proof_link_and_self_workspace(self):
        self.make_run()
        self.client.force_login(self.restricted)
        response = self.client.get("/integrations/?app=bettail")
        self.assertNotContains(response, "Inspect authorized lab pilot evidence")
        self.assertNotContains(response, "Receipt SHA-256")
        self.assertEqual(self.client.get("/integrations/?app=signalbridge").status_code, 404)

    def test_foreign_workspace_receipt_cannot_supply_self_assurance_status(self):
        self.make_run(integration=self.other)
        response = self.client.get("/integrations/?app=signalbridge")
        self.assertNotContains(response, "Local pilot verified")
        self.assertFalse(response.context["wazuh_pilot"]["has_receipt"])

    def test_reading_receipts_does_not_run_tools_or_mutate_evidence(self):
        self.make_run()
        before = (CheckRun.objects.count(), Audit.objects.count(), Event.objects.count())
        with patch(
            "subprocess.Popen", side_effect=AssertionError("No processes during receipt viewing")
        ):
            response = self.client.get("/integrations/?app=signalbridge")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            before, (CheckRun.objects.count(), Audit.objects.count(), Event.objects.count())
        )

    def test_untrusted_raw_result_fields_are_not_rendered(self):
        value = copy.deepcopy(receipt())
        value["private"] = "DO-NOT-DISPLAY-PRIVATE-SENTINEL"
        value["pilot"]["provenance"]["containers"] = [
            {"image_reference": "https://example.invalid/DO-NOT-DISPLAY-PRIVATE-SENTINEL"}
        ]
        self.make_run(result=value)
        response = self.client.get("/integrations/?app=signalbridge")
        self.assertNotContains(response, "DO-NOT-DISPLAY-PRIVATE-SENTINEL")
