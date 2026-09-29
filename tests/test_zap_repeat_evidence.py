"""Synthetic bundles, mocked native reads and disposable DB; no scanner launch."""

import copy
import io
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase, override_settings

from bridge import zap_repeat_evidence as e
from bridge.models import Audit, CheckRun, Finding, Integration, Membership, ScanRun
from bridge.zap_repeat_presentation import repeat_cards
from tests.test_soc_pilot_evidence import receipt_fixture
from tests.test_zap_controller import RUN, failed_report, ready_log, repeat_fixture

BASE = Path("var/soc/pilot") / RUN


def bundle(unavailable=False):
    data, inventory = {}, {}
    for name in e.runner.FILES:
        original = Path("integrations/zap") / name
        raw = (settings.BASE_DIR / original).read_bytes()
        data[original] = data[BASE / "source" / name] = raw
        if original.suffix != ".md":
            inventory[original.as_posix()] = e.digest(raw)
    for name in e.DEPENDENCIES:
        raw = (settings.BASE_DIR / name).read_bytes()
        data[Path(name)] = raw
        inventory[name] = e.digest(raw)
    execution = {
        "files": inventory,
        "file_count": len(inventory),
        "sha256": e.digest(e.json_bytes(inventory)),
    }
    data[BASE / "execution-source.json"] = execution
    files = {name: e.digest(data[BASE / "source" / name]) for name in e.runner.FILES}
    data[BASE / "source-manifest.json"] = files
    names = e.gate.profile_names("zap-repeat", RUN)
    mode = "unavailable-target" if unavailable else "normal"
    data[BASE / "plan.json"] = {
        "run_id": RUN,
        "mode": mode,
        "names": list(names),
        "network": e.gate.network_name("zap-repeat", RUN),
        "limits": e.runner.LIMITS,
        "prepared_at": "2026-09-24T09:59:59+00:00",
    }
    for state, moment in zip(e.gate.STATES, ("10:00:00", "10:00:05", "10:02:00"), strict=True):
        data[BASE / (state + "-gate.json")] = {
            "checked_at": "2026-09-24T" + moment + "+00:00",
            "errors": [],
            "topology": repeat_fixture(state),
        }
    data[BASE / "route-samples.json"] = [{"default_ipv4": 0, "default_ipv6": 0}] * 2
    states = [
        {"status": "exited", "exit_code": 1 if unavailable else 0, "oom": False},
        {"status": "exited", "exit_code": 137, "oom": False},
    ]
    if unavailable:
        report = failed_report()
        report.update(
            started_at="2026-09-24T10:00:10+00:00", finished_at="2026-09-24T10:01:30+00:00"
        )
        data[BASE / "target-unavailable.json"] = {
            "target_id": "2" * 64,
            "observed_at": "2026-09-24T10:00:06+00:00",
            "state": states[1],
        }
        raw = None
        log = ready_log()
    else:
        old, _, _, path = receipt_fixture("zap")
        report, raw = old[path], old[path.parent / "zap-report.json"]
        data[BASE / "zap/zap-report.json"] = raw
        log = (
            ready_log()
            + "\n"
            + "\n".join(
                e.canonical({"request_ordinal": n, "accepted": True}).decode() for n in (1, 2, 3)
            )
        )
    data[BASE / "zap/pilot-result.json"] = report
    data[BASE / "target.log"] = log.encode()
    times = [e.timestamp(data[BASE / (s + "-gate.json")]["checked_at"]) for s in e.gate.STATES]
    data[BASE / "host-result.json"] = {
        "schema_version": 1,
        "kind": "signalbridge-zap-repeat",
        "run_id": RUN,
        "mode": mode,
        "failure": None,
        "observation": e.runner.classify(report, raw, times, states, log, unavailable=unavailable),
        "containers": {
            name: {"id": str(i) * 64, "state": s}
            for i, (name, s) in enumerate(zip(names, states, strict=True), 1)
        },
        "source_sha256": execution["sha256"],
        "package_sha256": e.digest(e.gate.base.canonical(files)),
        "duration_seconds": 120.1,
        "finished_at": "2026-09-24T10:02:01+00:00",
        "limits": e.runner.LIMITS,
    }
    return data


def load(data, *, fresh=None, state=None, reader=None):
    def read(root, path):
        value = data[path]
        return value if isinstance(value, bytes) else e.canonical(value)

    names = e.gate.profile_names("zap-repeat", RUN)
    states = {
        str(i) * 64: data[BASE / "host-result.json"]["containers"][name]["state"]
        for i, name in enumerate(names, 1)
    }
    with (
        patch.object(e, "read_private", side_effect=reader or read),
        patch.object(e.gate, "gather_topology", return_value=fresh or repeat_fixture("exited")),
        patch.object(e.runner, "state", side_effect=state or (lambda cid: states[cid])),
    ):
        return e.load_zap_repeat(settings.BASE_DIR, RUN)


class ZapRepeatEvidenceTests(SimpleTestCase):
    def test_complete_fixture_and_verified_outage_stay_distinct(self):
        good, outage = load(bundle()), load(bundle(True))
        self.assertEqual(good["status"], "passed")
        self.assertEqual(good["result"]["counts"]["requests"], 3)
        self.assertEqual(outage["status"], "failed")
        self.assertTrue(outage["result"]["exercise_verified"])
        self.assertEqual(outage["result"]["coverage"], "incomplete")
        self.assertIsNone(outage["result"]["counts"])
        self.assertEqual(outage["result"]["target_accepted"], 0)
        self.assertNotEqual(good["digest"], outage["digest"])
        self.assertEqual(good["digest"], load(bundle())["digest"])

    def test_source_manifest_snapshot_and_validator_changes_rejected(self):
        for path in (Path(e.DEPENDENCIES[0]), BASE / "source/fixture.py"):
            data = bundle()
            data[path] += b"changed"
            with self.subTest(path=path), self.assertRaises(e.EvidenceError):
                load(data)
        data = bundle()
        data[BASE / "execution-source.json"]["file_count"] = True
        with self.assertRaises(e.EvidenceError):
            load(data)

    def test_isolation_identity_times_routes_and_foreign_mount_rejected(self):
        mutations = [
            ("running-gate.json", lambda r: r["topology"]["containers"][0].update(Id="f" * 64)),
            ("running-gate.json", lambda r: r.update(checked_at="2026-09-24T09:59:00+00:00")),
            (
                "created-gate.json",
                lambda r: r["topology"]["containers"][0]["HostConfig"].update(Privileged=True),
            ),
            ("exited-gate.json", lambda r: r["topology"]["networks"][0].update(Internal=False)),
            (
                "running-gate.json",
                lambda r: r["topology"]["containers"][0]["Mounts"][0].update(Source="C:/elsewhere"),
            ),
            ("route-samples.json", lambda r: r[0].update(default_ipv4=True)),
            ("plan.json", lambda r: r.update(run_id="bad")),
        ]
        for path, change in mutations:
            data = bundle()
            change(data[BASE / path])
            with self.subTest(path=path), self.assertRaises(e.EvidenceError):
                load(data)

    def test_fresh_inspection_cannot_rebind_container_or_changed_exit(self):
        fresh = repeat_fixture("exited")
        fresh["containers"][0]["Id"] = "f" * 64
        with self.assertRaises(e.EvidenceError):
            load(bundle(), fresh=fresh)
        with self.assertRaises(e.EvidenceError):
            load(bundle(), state=lambda cid: {"status": "exited", "exit_code": 1, "oom": False})

    def test_failed_scan_cannot_claim_pass_counts_or_successful_report(self):
        for change in (
            lambda h: h["observation"].update(scan_status="passed"),
            lambda h: h["observation"].update(counts={"reported_findings": 0}),
            lambda h: h["containers"][e.gate.profile_names("zap-repeat", RUN)[0]]["state"].update(
                exit_code=0
            ),
            lambda h: h.update(failure="parent_deadline"),
        ):
            data = bundle(True)
            change(data[BASE / "host-result.json"])
            with self.assertRaises(e.EvidenceError):
                load(data)
        with patch.object(Path, "lstat", return_value=object()), self.assertRaises(e.EvidenceError):
            load(bundle(True))

    def test_failed_target_identity_timing_requests_and_runtime_types(self):
        for path, change in (
            ("target-unavailable.json", lambda r: r.update(target_id="f" * 64)),
            (
                "target-unavailable.json",
                lambda r: r.update(observed_at="2026-09-24T10:02:00+00:00"),
            ),
            ("zap/pilot-result.json", lambda r: r.update(schema_version=True)),
            ("zap/pilot-result.json", lambda r: r.update(zap_exit_code=False)),
            ("zap/pilot-result.json", lambda r: r.update(errors=["unrelated_failure"])),
            ("zap/pilot-result.json", lambda r: r.update(requests=[])),
        ):
            data = bundle(True)
            change(data[BASE / path])
            with self.subTest(path=path), self.assertRaises(e.EvidenceError):
                load(data)

    def test_raw_report_hash_and_request_body_are_reconciled(self):
        data = bundle()
        data[BASE / "route-samples.json"] = (
            e.canonical(data[BASE / "route-samples.json"]) + b',"extra":true'
        )
        with self.assertRaises(e.EvidenceError):
            load(data)
        data = bundle()
        data[BASE / "zap/zap-report.json"] += b" "
        with self.assertRaises(e.EvidenceError):
            load(data)
        data = bundle()
        data[BASE / "zap/pilot-result.json"]["requests"][0]["body_sha256"] = "f" * 64
        with self.assertRaises(e.EvidenceError):
            load(data)

    def test_evidence_drift_during_fresh_read_rejected(self):
        data = bundle()
        reads = {}

        def read(root, path):
            reads[path] = reads.get(path, 0) + 1
            raw = data[path] if isinstance(data[path], bytes) else e.canonical(data[path])
            return raw + b" " if reads[path] > 1 and path.name == "host-result.json" else raw

        with self.assertRaises(e.EvidenceError):
            load(data, reader=read)

    def test_invalid_uuid_fails_before_io(self):
        with patch.object(e, "read_private", side_effect=AssertionError("must not read")):
            for value in ("../other", RUN.upper(), "not-a-uuid", None):
                with self.assertRaises(e.EvidenceError):
                    e.load_zap_repeat(settings.BASE_DIR, value)


class ZapRepeatConsoleTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(
            slug="signalbridge", name="SignalBridge", enabled=False
        )
        cls.other = Integration.objects.create(slug="bettail", name="BetTail")
        cls.user = get_user_model().objects.create_user(username="zap-viewer")
        Membership.objects.create(integration=cls.app, user=cls.user, role="viewer")
        Membership.objects.create(integration=cls.other, user=cls.user, role="viewer")

    def setUp(self):
        self.evidence = load(bundle(True))
        self.client.force_login(self.user)

    def command(self, **kwargs):
        with patch(
            "bridge.management.commands.import_zap_repeat.load_zap_repeat",
            return_value=self.evidence,
        ):
            call_command("import_zap_repeat", run_id=RUN, stdout=io.StringIO(), **kwargs)

    def test_dry_run_idempotency_audit_and_no_findings_or_coverage_write(self):
        self.command(dry_run=True)
        self.assertFalse(CheckRun.objects.exists())
        self.command()
        self.command()
        self.assertEqual(CheckRun.objects.count(), 1)
        self.assertEqual(CheckRun.objects.get().status, "failed")
        self.assertEqual(Audit.objects.filter(action="zap_repeat.imported").count(), 1)
        self.assertFalse(ScanRun.objects.exists())
        self.assertFalse(Finding.objects.exists())

    def test_conflicting_uuid_digest_and_foreign_scope_preserve_original(self):
        self.command()
        run = CheckRun.objects.get()
        run.status = "passed"
        run.save()
        with self.assertRaises(CommandError):
            self.command()
        run.status = "failed"
        run.result["counts"] = {"reported_findings": 0}
        run.save()
        with self.assertRaises(CommandError):
            self.command()
        run.result = self.evidence["result"]
        run.integration = self.other
        run.save()
        with self.assertRaises(CommandError):
            self.command()
        self.assertEqual(CheckRun.objects.count(), 1)

    def test_nonlocal_enabled_invalid_import_and_audit_failure_roll_back(self):
        with override_settings(LOCAL=False), self.assertRaises(CommandError):
            self.command()
        with patch(
            "bridge.management.commands.import_zap_repeat.load_zap_repeat",
            side_effect=e.EvidenceError("rejected"),
        ):
            with self.assertRaises(CommandError):
                call_command("import_zap_repeat", run_id=RUN)
        with (
            patch.object(Audit.objects, "create", side_effect=RuntimeError("audit fault")),
            self.assertRaises(RuntimeError),
        ):
            self.command()
        self.assertFalse(CheckRun.objects.exists())
        self.app.enabled = True
        self.app.save()
        with self.assertRaises(CommandError):
            self.command()

    def test_viewer_sees_failure_and_reason_without_native_io_or_cross_app_leak(self):
        self.command()
        with (
            patch.object(e.gate, "gather_topology", side_effect=AssertionError("no Docker")),
            patch.object(e, "read_private", side_effect=AssertionError("no files")),
        ):
            response = self.client.get("/integrations/?app=signalbridge")
        for text in (
            "Scan failed",
            "coverage incomplete",
            "Target outage preserved as failure",
            RUN,
            "do not record",
            "No result here establishes security coverage",
        ):
            self.assertContains(response, text)
        self.assertNotContains(self.client.get("/integrations/?app=bettail"), RUN)
        self.assertEqual(repeat_cards(self.other), [])
        Membership.objects.filter(integration=self.app).delete()
        self.assertEqual(self.client.get("/integrations/?app=signalbridge").status_code, 404)
        self.client.logout()
        self.assertEqual(self.client.get("/integrations/?app=signalbridge").status_code, 302)

    def test_receipt_never_becomes_an_authorization_check(self):
        self.command()
        self.assertEqual(self.client.get("/?app=signalbridge").status_code, 302)
        CheckRun.objects.update(integration=self.other)
        self.assertIsNone(self.client.get("/?app=bettail").context["latest_run"])
        self.assertIsNone(self.client.get("/checks/?app=bettail").context["latest_run"])

    def test_rehashed_false_claims_and_unknown_text_cannot_display_as_verified(self):
        self.command()
        run = CheckRun.objects.get()
        for change in (
            lambda r: r.update(status="passed"),
            lambda r: r.update(target_accepted=True),
            lambda r: r.update(coverage="complete"),
            lambda r: r.update(continuous_connection=True),
            lambda r: r.update(mode="<script>bad()</script>"),
            lambda r: r.update(extra="untrusted"),
            lambda r: r["provenance"].update(container_ids=["a" * 64] * 2),
        ):
            result = copy.deepcopy(run.result)
            change(result)
            CheckRun.objects.filter(pk=run.pk).update(
                result=result, digest=e.digest(e.canonical(result))
            )
            response = self.client.get("/integrations/?app=signalbridge")
            self.assertContains(response, "Receipt needs review")
            self.assertNotContains(response, "Target outage preserved as failure")
            self.assertNotContains(response, "<script>bad()")

    def test_complete_receipt_and_bounded_history_keep_invalid_newest_visible(self):
        self.evidence = load(bundle())
        self.command()
        response = self.client.get("/integrations/?app=signalbridge")
        self.assertContains(response, "Fixed fixture scan completed")
        self.assertContains(response, "Two positive paths")
        for i in range(7):
            CheckRun.objects.create(
                integration=self.app,
                suite="damaged",
                revision="x",
                digest=str(i) * 64,
                status="passed",
                result={"evidence_kind": e.KIND},
            )
        cards = repeat_cards(self.app)
        self.assertEqual(len(cards), 6)
        self.assertTrue(all(not c["verified"] for c in cards))
