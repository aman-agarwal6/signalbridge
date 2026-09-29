"""Synthetic receipts and mocked Docker metadata; never uses private runtime evidence."""

import copy
import io
import json
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase, override_settings

from bridge import wazuh_backfill_evidence as e
from bridge.models import Audit, CheckRun, Integration, Membership
from bridge.wazuh_backfill_presentation import backfill_card
from tests.test_wazuh_backfill import RUN, manifest, observed, packet, topology

BASE = Path("var/soc/pilot") / RUN
OUT = BASE / "wazuh-backfill"


def bundle():
    data, files, inventory = {}, {}, {}
    for name, original in e.PACKAGE.items():
        raw = (settings.BASE_DIR / original).read_bytes()
        data[Path(original)] = data[BASE / "source" / name] = raw
        files[name] = inventory[original] = e.digest(raw)
    for saved, original in (
        ("executed-controller.py", "scripts/run_wazuh_backfill.py"),
        ("executed-inspection.py", "integrations/wazuh_backfill/inspect_ledger.py"),
    ):
        raw = (settings.BASE_DIR / original).read_bytes()
        data[Path(original)] = data[BASE / saved] = raw
        inventory[original] = e.digest(raw)
    m, raw = manifest([packet(), packet(outcome="denied"), packet(source="legacy_unclassified")])
    data[BASE / "input/events.jsonl"] = raw
    data[BASE / "source/backfill-input.json"] = e.canonical(m)
    files["backfill-input.json"] = e.digest(data[BASE / "source/backfill-input.json"])
    source_digest = e.digest(e.canonical(files))
    data[BASE / "source-manifest.json"] = {"files": files, "sha256": source_digest}
    data[BASE / "execution-source.json"] = {
        "files": inventory,
        "file_count": len(inventory),
        "sha256": e.digest((json.dumps(inventory, sort_keys=True, indent=2) + "\n").encode()),
    }
    for state, second in (("created", 1), ("running", 3), ("exited", 15)):
        data[BASE / (state + "-gate.json")] = {
            "state": state,
            "errors": [],
            "source_sha256": source_digest,
            "observed_at": f"2026-09-24T10:00:{second:02d}+00:00",
            "topology": topology(state),
        }
    data[OUT / "run-context.json"] = e.canonical(
        {
            "schema_version": 1,
            "kind": "signalbridge-wazuh-run-context",
            "run_id": RUN,
            "prepared_at": "2026-09-24T10:00:00+00:00",
            "source_sha256": source_digest,
        }
    )
    config = (
        data[BASE / "source/manager-lab.conf"]
        .replace(b"<logall_json>no</logall_json>", b"<logall_json>yes</logall_json>")
        .replace(
            b"<only-future-events>yes</only-future-events>",
            b'<only-future-events max-size="1MB">no</only-future-events>',
        )
    )
    data[OUT / "effective-config.xml"] = config
    data[OUT / "version.log"] = b"Wazuh v4.14.8"
    cases = json.loads(data[BASE / "source/fixtures/expectations.json"])["cases"]
    rows = []
    for index, case in enumerate(cases, 1):
        body = "**Phase 2: Completed decoding.\n name: 'json'\n"
        if case["expected_rule"]:
            body += f"**Phase 3: Completed filtering.\n id: '{case['expected_rule']}'\n level: '{case['expected_level']}'\n"
        data[OUT / f"logtest-{index:02d}.log"] = body.encode()
        rows.append(
            {
                "id": case["id"],
                "status": "passed",
                "expected_rule": case["expected_rule"],
                "expected_level": case["expected_level"],
                "observed_rule": case["expected_rule"],
                "observed_level": case["expected_level"],
                "decoder": "json",
            }
        )
    archives, alerts = [], []
    for p in m["packets"].values():
        for target, alert in ((archives, False), (alerts, True)):
            if alert and p["signalbridge"]["event_id"] not in m["expected_alerts"]:
                continue
            row = observed(p, alert=alert)
            row.update(
                timestamp="2026-09-24T10:00:08+00:00",
                manager={"name": e.gate.profile_names("wazuh-backfill", RUN)[0]},
            )
            target.append(e.canonical(row) + b"\n")
    data[OUT / "archives.jsonl"], data[OUT / "alerts.jsonl"] = b"".join(archives), b"".join(alerts)
    data[OUT / "backfill-result.json"] = {
        "schema_version": 2,
        "kind": "signalbridge-wazuh-ledger-backfill",
        "tool": "wazuh",
        "runtime_version": "4.14.8",
        "status": "passed",
        "scope": "retained_local_lab_metadata",
        "synthetic_only": False,
        "transport": "read_only_ledger_snapshot_to_fresh_collector_spool",
        "failure_code": None,
        "collection_verified": True,
        "handoff_verified": True,
        "logtest_verified": True,
        "owned_processes_stopped": True,
        "collector": {"verified": False},
        "recovery_phases": [],
        "input_count": 3,
        "archived_records": 3,
        "expected_alert_count": 2,
        "alerts": 2,
        "nonalert_records": 1,
        "duplicates": 0,
        "quiet_seconds": 3,
        "expected_logtest_case_count": 27,
        "logtest_cases": rows,
        "source_counts": {"synthetic_demo": 2, "legacy_unclassified": 1},
        "input_sha256": m["sha256"],
        "source_sha256": {k: files[k] for k in e.SOURCE_FILES},
        "duration_seconds": 10,
        "run_id": RUN,
        "input_manifest_sha256": files["backfill-input.json"],
        "context_sha256": e.digest(data[OUT / "run-context.json"]),
        "effective_config_sha256": e.digest(config),
        "started_at": "2026-09-24T10:00:02+00:00",
        "finished_at": "2026-09-24T10:00:12+00:00",
        "archives_sha256": e.digest(data[OUT / "archives.jsonl"]),
        "alerts_sha256": e.digest(data[OUT / "alerts.jsonl"]),
    }
    data[BASE / "host-result.json"] = {
        "run_id": RUN,
        "container_id": topology("exited")["containers"][0]["Id"],
        "stopped": True,
        "failure": None,
        "state": {"status": "exited", "exit_code": 0, "oom": False},
        "free_bytes_after": 30 * 1024**3,
        "source_sha256": source_digest,
    }
    return data


def load_fixture(data, fresh=None, reader=None):
    def read(_root, relative):
        value = data[Path(relative)]
        return value if type(value) is bytes else e.canonical(value)

    with (
        patch.object(e, "read_private", side_effect=reader or read),
        patch.object(e.gate, "gather_topology", return_value=fresh or topology("exited")),
    ):
        return e.load_backfill(settings.BASE_DIR, RUN)


class BackfillEvidenceTests(SimpleTestCase):
    def test_complete_fixture_is_stable_and_preserves_unknown_provenance(self):
        data = bundle()
        first, second = load_fixture(data), load_fixture(data)
        self.assertEqual(first["digest"], second["digest"])
        self.assertEqual(
            first["result"]["counts"],
            {
                "inputs": 3,
                "received": 3,
                "alerts": 2,
                "nonalerts": 1,
                "missing": 0,
                "duplicates": 0,
                "rule_cases": 27,
            },
        )
        self.assertEqual(first["result"]["source_counts"]["legacy_unclassified"], 1)
        self.assertFalse(first["result"]["source_app_assessed"])

    def test_runtime_flags_counts_versions_and_binding_fail_closed(self):
        for key, value in (
            ("status", "failed"),
            ("scope", "production"),
            ("synthetic_only", True),
            ("duplicates", 1),
            ("alerts", 3),
            ("input_count", True),
            ("runtime_version", "9"),
            ("duration_seconds", float("nan")),
            ("run_id", "another"),
            ("started_at", "2026-09-24T09:59:00Z"),
            ("collector", {"verified": True}),
        ):
            data = bundle()
            data[OUT / "backfill-result.json"][key] = value
            with self.subTest(key=key), self.assertRaises(e.EvidenceError):
                load_fixture(data)

    def test_missing_duplicate_foreign_and_stale_records_fail_even_with_updated_hash(self):
        for filename, mutation in (
            ("archives.jsonl", "missing"),
            ("archives.jsonl", "duplicate"),
            ("alerts.jsonl", "foreign"),
            ("alerts.jsonl", "time"),
            ("alerts.jsonl", "rule"),
            ("archives.jsonl", "manager"),
        ):
            data = bundle()
            rows = [json.loads(line) for line in data[OUT / filename].splitlines()]
            if mutation == "missing":
                rows.pop()
            elif mutation == "duplicate":
                rows.append(rows[0])
            elif mutation == "foreign":
                rows[0]["data"]["signalbridge"]["app"] = "netted"
            elif mutation == "time":
                rows[0]["timestamp"] = "2026-09-24T09:00:00Z"
            elif mutation == "rule":
                rows[0]["rule"]["level"] = 15
            elif mutation == "manager":
                rows[0]["manager"]["name"] = "other-run"
            data[OUT / filename] = b"".join(e.canonical(row) + b"\n" for row in rows)
            data[OUT / "backfill-result.json"][filename.replace(".jsonl", "_sha256")] = e.digest(
                data[OUT / filename]
            )
            with self.subTest(mutation=mutation), self.assertRaises(e.EvidenceError):
                load_fixture(data)

    def test_source_config_logtest_and_host_state_tampering_rejected(self):
        for path in (
            BASE / "source/run_backfill.py",
            BASE / "input/events.jsonl",
            BASE / "executed-controller.py",
            OUT / "effective-config.xml",
            OUT / "logtest-01.log",
        ):
            data = bundle()
            if path.name == "logtest-01.log":
                data[path] = data[path].replace(b"id: '100201'", b"id: '100205'")
            else:
                data[path] += b"changed"
            with self.subTest(path=path), self.assertRaises(e.EvidenceError):
                load_fixture(data)
        for key, value in (
            ("failure", "timeout"),
            ("stopped", False),
            ("free_bytes_after", 0),
            ("container_id", "f" * 64),
            ("state", {"status": "exited", "exit_code": 137, "oom": True}),
        ):
            data = bundle()
            data[BASE / "host-result.json"][key] = value
            with self.subTest(key=key), self.assertRaises(e.EvidenceError):
                load_fixture(data)

    def test_stored_and_fresh_isolation_failures_and_wrong_identity_rejected(self):
        data = bundle()
        data[BASE / "running-gate.json"]["topology"]["containers"][0]["HostConfig"][
            "NetworkMode"
        ] = "host"
        with self.assertRaises(e.EvidenceError):
            load_fixture(data)
        for fresh in (topology("running"), topology("exited")):
            fresh["containers"][0]["Id"] = "f" * 64
            with self.assertRaises(e.EvidenceError):
                load_fixture(bundle(), fresh)

    def test_invalid_run_never_reads_files_or_docker_and_mid_validation_change_rejected(self):
        with (
            patch.object(e, "read_private") as read,
            patch.object(e.gate, "gather_topology") as gather,
        ):
            with self.assertRaises(e.EvidenceError):
                e.load_backfill(settings.BASE_DIR, "../foreign")
            read.assert_not_called()
            gather.assert_not_called()
        data, seen = bundle(), {}

        def changing(_root, relative):
            seen[relative] = seen.get(relative, 0) + 1
            item = data[relative]
            raw = item if type(item) is bytes else e.canonical(item)
            return (
                raw + b" " if relative == BASE / "host-result.json" and seen[relative] > 1 else raw
            )

        with self.assertRaises(e.EvidenceError):
            load_fixture(data, reader=changing)


class BackfillImportAndConsoleTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.app = Integration.objects.create(slug="bettail", name="BetTail")
        cls.other = Integration.objects.create(slug="netted", name="Netted")
        cls.user = get_user_model().objects.create_user(username="backfill-viewer")
        Membership.objects.create(integration=cls.app, user=cls.user, role="viewer")
        Membership.objects.create(integration=cls.other, user=cls.user, role="viewer")

    def setUp(self):
        self.evidence = load_fixture(bundle())
        self.client.force_login(self.user)

    def command(self, **kwargs):
        with patch(
            "bridge.management.commands.import_wazuh_backfill.load_backfill",
            return_value=self.evidence,
        ):
            call_command("import_wazuh_backfill", run_id=RUN, stdout=io.StringIO(), **kwargs)

    def test_dry_run_idempotent_import_and_audit(self):
        self.command(dry_run=True)
        self.assertEqual(CheckRun.objects.count(), 0)
        self.command()
        self.command()
        self.assertEqual(CheckRun.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="wazuh_backfill.imported").count(), 1)
        self.assertEqual(CheckRun.objects.get().integration, self.app)

    def test_conflicting_uuid_or_foreign_digest_cannot_replace_evidence(self):
        self.command()
        run = CheckRun.objects.get()
        run.result["counts"]["alerts"] = 99
        run.save()
        with self.assertRaises(CommandError):
            self.command()
        self.assertEqual(CheckRun.objects.get().result["counts"]["alerts"], 99)
        run.result = self.evidence["result"]
        run.integration = self.other
        run.save()
        with self.assertRaises(CommandError):
            self.command()
        self.assertEqual(CheckRun.objects.count(), 1)

    def test_import_refuses_nonlocal_disabled_or_invalid_bundle(self):
        with override_settings(LOCAL=False), self.assertRaises(CommandError):
            self.command()
        self.app.enabled = False
        self.app.save()
        with self.assertRaises(CommandError):
            self.command()
        with patch(
            "bridge.management.commands.import_wazuh_backfill.load_backfill",
            side_effect=e.EvidenceError("invalid"),
        ):
            with self.assertRaises(CommandError):
                call_command("import_wazuh_backfill", run_id=RUN, stdout=io.StringIO())
        self.assertFalse(CheckRun.objects.exists())

    def test_console_shows_reconciled_counts_without_files_processes_or_cross_app_leak(self):
        self.command()
        with (
            patch.object(e.gate, "gather_topology", side_effect=AssertionError("no Docker")),
            patch.object(e, "read_private", side_effect=AssertionError("no files")),
        ):
            response = self.client.get("/integrations/?app=bettail")
        for text in (
            "Backfill verified",
            "What Wazuh actually received",
            "not a benign verdict",
            "legacy unclassified",
            "Rule 100202",
            "Archived; no custom alert",
            RUN,
        ):
            self.assertContains(response, text)
        self.assertNotContains(self.client.get("/integrations/?app=netted"), RUN)
        self.assertFalse(backfill_card(self.other)["has_receipt"])
        self.client.logout()
        self.assertEqual(self.client.get("/integrations/?app=bettail").status_code, 302)

    def test_receipt_never_counts_as_an_authorization_run(self):
        old = CheckRun.objects.create(
            integration=self.app,
            suite="Existing authorization",
            revision="a" * 40,
            digest="c" * 64,
            status="passed",
            result={"checks": [{"status": "passed"}]},
        )
        self.command()
        response = self.client.get("/checks/?app=bettail")
        self.assertEqual(response.context["latest_run"], old)
        self.assertNotContains(response, "Wazuh retained lab metadata backfill")
        self.assertEqual(self.client.get("/?app=bettail").context["latest_run"], old)

    def test_damaged_latest_receipt_never_falls_back_to_green(self):
        self.command()
        original = CheckRun.objects.get()
        for field, value in (("digest", "0" * 64), ("revision", "0" * 64), ("status", "failed")):
            CheckRun.objects.filter(pk=original.pk).update(**{field: value})
            self.assertFalse(backfill_card(self.app, CheckRun.objects.get())["verified"])
            CheckRun.objects.filter(pk=original.pk).update(**{field: getattr(original, field)})
        for mutate in (
            lambda r: r.update(app="netted"),
            lambda r: r["counts"].update(received=99),
            lambda r: r.update(continuous_connection=True),
            lambda r: r["observations"][0].update(level=15),
            lambda r: r["source_counts"].update(legacy_unclassified=0),
        ):
            result = copy.deepcopy(original.result)
            mutate(result)
            CheckRun.objects.filter(pk=original.pk).update(
                result=result, digest=e.digest(e.canonical(result))
            )
            response = self.client.get("/integrations/?app=bettail")
            self.assertContains(response, "Receipt needs review")
            self.assertNotContains(response, "Backfill verified")
