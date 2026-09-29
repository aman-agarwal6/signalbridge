"""Coverage must not turn missing, foreign, or contradictory evidence green."""

import copy
import re
import uuid
from pathlib import Path
from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from bridge.access_coverage import HTTP, HTTP_SUITE, SQL, SQL_SUITE, coverage_for_run
from bridge.assurance import SPECS, validate_bundle
from bridge.models import CheckRun, Integration, Membership
from tests.test_assurance import bundle_fixture


def sql_run(app="bettail"):
    identifiers = {key for row in SQL[app] for key in row["required_checks"]}
    identifiers.add("ordinary-role-is-not-superuser")
    return SimpleNamespace(
        pk=uuid.uuid4(),
        digest="a" * 64,
        suite=SQL_SUITE,
        status="passed",
        result={
            "app": app,
            "status": "passed",
            "checks": [{"id": key, "status": "passed"} for key in sorted(identifiers)],
        },
    )


def http_run():
    evidence = validate_bundle(bundle_fixture())
    return SimpleNamespace(
        pk=uuid.uuid4(),
        digest=evidence["digest"],
        suite=HTTP_SUITE,
        status=evidence["status"],
        result=evidence["result"],
    )


class CoverageTests(SimpleTestCase):
    def test_ci_runs_every_recorded_node_suite_and_is_bound_into_source_manifest(self):
        from bridge.simulation_evidence import SOURCE_FILES as ALLOWED
        from scripts.record_verification import NODE_TEST_TARGETS, SOURCE_FILES

        workflow = ".github/workflows/checks.yml"
        self.assertIn(workflow, SOURCE_FILES)
        self.assertIn(workflow, ALLOWED)
        text = (Path(__file__).resolve().parents[1] / workflow).read_text(encoding="utf8")
        for target in NODE_TEST_TARGETS.values():
            self.assertIn(f"node --test --test-isolation=none --test-reporter=tap {target}", text)

    def test_catalog_references_real_harness_checks_and_stages(self):
        http = {(spec[1], spec[0]) for spec in SPECS}
        for row in HTTP:
            self.assertTrue(all((row["stage"], key) in http for key in row["required_checks"]))
        harness = (Path(__file__).resolve().parents[1] / "integrations/check-apps.mjs").read_text(
            encoding="utf8"
        )
        identifiers = set(re.findall(r'check\("([\w-]+)"', harness))
        for catalog in SQL.values():
            self.assertEqual(len({row["id"] for row in catalog}), len(catalog))
            self.assertTrue(
                all(key in identifiers for row in catalog for key in row["required_checks"])
            )

    def test_service_matrix_separates_restoration_from_assertions(self):
        run = http_run()
        before = copy.deepcopy(run.result)
        matrix = coverage_for_run(run, "bettail")
        self.assertEqual(matrix["counts"]["passed"], 9)
        self.assertEqual(matrix["rows"][-1]["stage"], "restoration")
        self.assertEqual(run.result, before)
        self.assertEqual(matrix["report_sha256"], run.digest)

    def test_sql_matrix_never_claims_genuine_login(self):
        for app in SQL:
            matrix = coverage_for_run(sql_run(app), app)
            self.assertEqual(matrix["counts"]["passed"], 7)
            self.assertIn("supplied identity", matrix["layer"])

    def test_missing_check_never_counts_as_passed(self):
        run = sql_run()
        run.result["checks"] = [
            row for row in run.result["checks"] if row["id"] != "member-real-snapshot-rpc"
        ]
        self.assertEqual(coverage_for_run(run, "bettail")["rows"][0]["status"], "not_recorded")

    def test_missing_ordinary_role_control_withholds_all_sql_support(self):
        run = sql_run()
        run.result["checks"] = [
            row for row in run.result["checks"] if row["id"] != "ordinary-role-is-not-superuser"
        ]
        self.assertEqual(coverage_for_run(run, "bettail")["counts"]["not_recorded"], 7)

    def test_failed_assertion_does_not_mark_the_entire_catalog_passed(self):
        run = sql_run()
        run.status = run.result["status"] = "failed"
        next(row for row in run.result["checks"] if row["id"] == "member-real-snapshot-rpc")[
            "status"
        ] = "failed"
        matrix = coverage_for_run(run, "bettail")
        self.assertEqual(matrix["rows"][0]["status"], "failed")
        self.assertEqual(matrix["counts"]["passed"], 6)

    def test_duplicate_and_misstaged_checks_are_inconsistent(self):
        for modification in ("duplicate", "stage", "status", "mismatch", "shape", "oversized"):
            run = sql_run()
            if modification == "duplicate":
                run.result["checks"].append(dict(run.result["checks"][0]))
            elif modification == "stage":
                run.result["checks"][0]["stage"] = "setup"
            elif modification == "status":
                run.result["checks"][0]["status"] = "skipped"
            elif modification == "mismatch":
                run.result["status"] = "failed"
            elif modification == "shape":
                run.result["checks"] = "malformed"
            else:
                run.result["checks"] *= 20
            with self.subTest(modification=modification):
                self.assertEqual(coverage_for_run(run, "bettail")["counts"]["inconsistent"], 7)

    def test_foreign_and_unknown_scopes_get_no_mapping(self):
        run = http_run()
        self.assertIsNone(coverage_for_run(run, "netted"))
        run.suite = "Unrecognized suite"
        self.assertIsNone(coverage_for_run(run, "bettail"))
        run = sql_run()
        run.result["evidence_kind"] = "unknown"
        self.assertIsNone(coverage_for_run(run, "bettail"))

    def test_service_outage_cannot_masquerade_as_denial(self):
        run = http_run()
        next(row for row in run.result["checks"] if row["id"] == "removed_member_snapshot_denied")[
            "http_status"
        ] = 503
        self.assertEqual(coverage_for_run(run, "bettail")["counts"]["inconsistent"], 9)

    def test_service_wrong_content_or_outcome_invalidates_support(self):
        for field, value in (("content_digest", "0" * 64), ("outcome", "not_visible")):
            run = http_run()
            next(
                row for row in run.result["checks"] if row["id"] == "member_attached_image_visible"
            )[field] = value
            self.assertEqual(coverage_for_run(run, "bettail")["counts"]["inconsistent"], 9)

    def test_service_cannot_hide_missing_restoration_or_setup(self):
        for key in ("setup_checks", "restoration_checks"):
            run = http_run()
            run.result[key] = []
            self.assertEqual(coverage_for_run(run, "bettail")["counts"]["inconsistent"], 9)

    def test_failed_partial_service_run_leaves_unexecuted_objectives_unrecorded(self):
        run = http_run()
        run.status = run.result["status"] = "failed"
        run.result["setup_checks"] = run.result["setup_checks"][:7]
        run.result["checks"] = [
            {
                "id": "owner_exact_row_visible",
                "stage": "assertion",
                "status": "failed",
                "duration_ms": 1,
                "error_code": "local_http_check_failed",
            }
        ]
        run.result["restoration_checks"] = []
        run.result["restoration"] = {"required": False, "attempted": False, "status": "not_needed"}
        matrix = coverage_for_run(run, "bettail")
        self.assertEqual(matrix["rows"][0]["status"], "failed")
        self.assertEqual(matrix["counts"]["not_recorded"], 8)


class CoverageConsoleTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="bettail", name="BetTail")
        cls.other = Integration.objects.create(slug="netted", name="Netted")
        cls.viewer = get_user_model().objects.create_user(username="matrix-viewer")
        Membership.objects.create(user=cls.viewer, integration=cls.app, role="viewer")
        source = http_run()
        cls.check_run = CheckRun.objects.create(
            integration=cls.app,
            suite=source.suite,
            revision="a" * 40,
            digest=source.digest,
            result=source.result,
            status=source.status,
        )
        CheckRun.objects.create(
            integration=cls.other,
            suite="foreign-matrix-sentinel",
            revision="b" * 40,
            digest="f" * 64,
            result=sql_run("netted").result,
            status="passed",
        )

    def setUp(self):
        self.client.force_login(self.viewer)

    def test_viewer_can_read_disclosures_and_practice_without_mutation(self):
        response = self.client.get("/checks/?app=bettail")
        self.assertContains(response, "Who should be able to do what?")
        self.assertContains(response, "Still authenticated")
        self.assertContains(response, "503")
        self.assertNotContains(response, "foreign-matrix-sentinel")
        self.assertNotContains(response, "<script")
        self.assertEqual(response.context["runs"][0].access_coverage["counts"]["passed"], 9)

    def test_export_includes_same_app_scoped_machine_readable_matrix(self):
        report = self.client.get("/export/?app=bettail").json()
        self.assertEqual(len(report["authorization_matrices"]), 1)
        self.assertEqual(report["authorization_matrices"][0]["run_id"], str(self.check_run.pk))
        self.assertEqual(report["authorization_matrices"][0]["app"], "bettail")
        self.assertEqual(self.client.get("/checks/?app=netted").status_code, 404)
        self.assertEqual(self.client.get("/export/?app=netted").status_code, 404)

    def test_login_is_required(self):
        self.client.logout()
        self.assertEqual(self.client.get("/checks/?app=bettail").status_code, 302)

    def test_unknown_report_remains_visible_without_inferred_coverage(self):
        self.check_run.suite = "unknown-suite"
        self.check_run.save(update_fields=["suite"])
        response = self.client.get("/checks/?app=bettail")
        self.assertContains(response, "No coverage mapping for this report")
        self.assertNotContains(response, "Supported in this run")
