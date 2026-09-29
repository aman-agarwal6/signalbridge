"""Synthetic evidence tests; no live Docker, Supabase or production connections."""

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

from bridge import assurance as evidence
from bridge.models import Audit, CheckRun, Integration

RUN_ID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
SOURCE_BYTES = {
    "harness": b"// synthetic harness fixture\n",
    "lab_config_sha256": b"project_id = 'synthetic'\n",
    "relay_source_sha256": b"// synthetic relay fixture\n",
    "verifier_source_sha256": b"# synthetic verifier fixture\n",
}
PATHS = {
    "http": f"var/labs/bettail/http-runs/{RUN_ID}.json",
    "state": "var/labs/bettail/lab-state.json",
    "migration": "var/labs/bettail/migration-runs/synthetic.json",
    "receipt": "docs/evidence/synthetic-bettail-supabase.json",
    "before": "artifacts/local/isolation/20260924T000901000000Z-aaaaaaaa.json",
    "after": "artifacts/local/isolation/20260924T001003000000Z-bbbbbbbb.json",
    "harness": "integrations/supabase-http.mjs",
    "lab_config_sha256": "var/labs/bettail/supabase/config.toml",
    "relay_source_sha256": "integrations/supabase/loopback-relay.mjs",
    "verifier_source_sha256": "scripts/verify_supabase_isolation.py",
}


def refresh_receipt(bundle):
    report = bundle["http"]
    bundle["receipt"]["http"] = {key: copy.deepcopy(report[key]) for key in evidence.HTTP_EXPORT}
    bundle["receipt"]["check_stage_counts"] = {
        stage: sum(row["stage"] == stage for row in report["checks"])
        for stage in ("setup", "assertion", "restoration")
    }
    bundle["raw_hashes"]["http"] = evidence.digest(evidence.json_bytes(report))
    bundle["receipt"]["http_report_sha256"] = bundle["raw_hashes"]["http"]
    bundle["raw_hashes"]["receipt"] = evidence.digest(evidence.json_bytes(bundle["receipt"]))


def bundle_fixture():
    files = [
        {"file": "202609080001_synthetic.sql", "sha256": "a" * 64},
        {"file": "202609080002_synthetic.sql", "sha256": "b" * 64},
    ]
    migration_digest = evidence.digest(evidence.json_bytes(files))
    state = {
        "schema_version": 1,
        "app": "bettail",
        "isolation_verified": True,
        "snapshot_digest": "c" * 64,
        "migrations": {
            "status": "passed",
            "count": 2,
            "files": files,
            "source_revision": "d" * 40,
            "digest": migration_digest,
        },
    }
    migration = {
        "schema_version": 1,
        "app": "bettail",
        "status": "passed",
        "started_at": "2026-09-24T00:08:00Z",
        "finished_at": "2026-09-24T00:08:01Z",
        "files": copy.deepcopy(files),
        "applied": copy.deepcopy(files),
        "source_revision": "d" * 40,
        "source_dirty": True,
        "snapshot_digest": "c" * 64,
    }
    hashes = {key: evidence.digest(raw) for key, raw in SOURCE_BYTES.items()}
    hashes.update(
        state=evidence.digest(evidence.json_bytes(state)),
        migration=evidence.digest(evidence.json_bytes(migration)),
    )
    rows = []
    for identifier, stage, outcome, http, code, content in evidence.SPECS:
        row = {
            "id": identifier,
            "stage": stage,
            "status": "passed",
            "duration_ms": 5,
            "outcome": outcome,
        }
        if http is not None:
            row["http_status"] = (
                400 if http == "storage" else http[0] if isinstance(http, tuple) else http
            )
        if code:
            row["response_code"] = "NoSuchKey" if code == "storage" else code
        if content:
            row["content_digest"] = evidence.FIXTURE_DIGEST
        rows.append(row)
    report = {
        "schema_version": 1,
        "app": "bettail",
        "environment": "isolated_supabase_http",
        "run_id": RUN_ID,
        "status": "passed",
        "started_at": "2026-09-24T00:10:00Z",
        "finished_at": "2026-09-24T00:10:01Z",
        "duration_ms": 1000,
        "source": {
            "migration_digest": migration_digest,
            "harness_sha256": hashes["harness"],
            "lab_state_sha256": hashes["state"],
            "harness_unchanged": True,
            "lab_state_unchanged": True,
        },
        "runtime": {"node_version": "v24.14.1"},
        "checks": rows,
        "restoration": {"required": True, "attempted": True, "status": "restored_and_retested"},
        "limitations": ["Synthetic test fixture only."],
    }
    containers = []
    for name in evidence.CONTAINERS:
        relay = name == evidence.RELAY
        containers.append(
            {
                "name": name,
                "id": evidence.digest(name.encode()),
                "image_id": "sha256:" + "e" * 64,
                "networks": [evidence.PROJECT, evidence.EDGE] if relay else [evidence.PROJECT],
                "ports": {
                    f"{port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(port)}]
                    for port in (55321, 55322, 55324)
                }
                if relay
                else {},
            }
        )
    isolation = {
        "schema_version": 1,
        "project": evidence.PROJECT,
        "status": "passed",
        "errors": [],
        "source_hashes": {key: hashes[key] for key in SOURCE_BYTES if key != "harness"},
        "topology_sha256": "f" * 64,
        "topology": {
            "containers": containers,
            "networks": [
                {"name": evidence.PROJECT, "id": "1" * 64, "internal": True},
                {"name": evidence.EDGE, "id": "2" * 64, "internal": False},
            ],
        },
        "runtime": {
            "ipv4_default_route": False,
            "ipv6_default_route": False,
            "external_tcp": "blocked",
            "cron_launch_active_jobs": "off",
        },
    }
    before, after = copy.deepcopy(isolation), copy.deepcopy(isolation)
    before.update(started_at="2026-09-24T00:09:00Z", finished_at="2026-09-24T00:09:01Z")
    after.update(started_at="2026-09-24T00:10:02Z", finished_at="2026-09-24T00:10:03Z")
    hashes.update(
        before=evidence.digest(evidence.json_bytes(before)),
        after=evidence.digest(evidence.json_bytes(after)),
    )
    receipt = {
        "schema_version": 1,
        "kind": "signalbridge-isolated-supabase-receipt",
        "app": "bettail",
        "migration_count": 2,
        "migration_report_sha256": hashes["migration"],
        "migrations": {
            key: migration[key]
            for key in (
                "status",
                "started_at",
                "finished_at",
                "snapshot_digest",
                "source_revision",
                "source_dirty",
            )
        },
        "isolation": {
            side + "_http": {
                "receipt": Path(PATHS[side]).name,
                "sha256": hashes[side],
                **{
                    key: record[key]
                    for key in (
                        "started_at",
                        "finished_at",
                        "status",
                        "source_hashes",
                        "topology_sha256",
                        "runtime",
                    )
                },
            }
            for side, record in (("before", before), ("after", after))
        },
        "images": [{"container": row["name"], "image_id": row["image_id"]} for row in containers],
    }
    bundle = {
        "receipt": receipt,
        "http": report,
        "state": state,
        "migration": migration,
        "before": before,
        "after": after,
        "raw_hashes": hashes,
    }
    refresh_receipt(bundle)
    return bundle


class AssuranceValidationTests(SimpleTestCase):
    def test_valid_evidence_counts_only_eighteen_assertions_and_retains_provenance(self):
        checked = evidence.validate_bundle(bundle_fixture())
        result = checked["result"]
        self.assertEqual(len(result["checks"]), 18)
        self.assertEqual(result["stage_counts"], {"setup": 10, "assertion": 18, "restoration": 4})
        self.assertTrue(result["working_tree_dirty"])
        self.assertFalse(result["full_m1_complete"])
        self.assertEqual(checked["digest"], result["provenance"]["http_report_sha256"])

    def test_outage_expired_token_wrong_code_and_unexpected_success_never_pass_negative(self):
        for change in (
            {"http_status": 503},
            {"http_status": 401},
            {"response_code": "InvalidJWT"},
            {"http_status": 200},
            {"response_code": "NoSuchBucket"},
        ):
            with self.subTest(change=change):
                bundle = bundle_fixture()
                row = next(
                    row
                    for row in bundle["http"]["checks"]
                    if row["id"] == "member_unattached_draft_hidden"
                )
                row.update(change)
                refresh_receipt(bundle)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.validate_bundle(bundle)

    def test_duplicate_unknown_skipped_missing_and_reordered_checks_fail(self):
        mutations = (
            lambda rows: rows.append(copy.deepcopy(rows[0])),
            lambda rows: rows[0].update(id="invented_check"),
            lambda rows: rows[0].update(status="skipped"),
            lambda rows: rows.pop(),
            lambda rows: rows.reverse(),
            lambda rows: rows[0].update(duration_ms=True),
        )
        for mutate in mutations:
            bundle = bundle_fixture()
            mutate(bundle["http"]["checks"])
            refresh_receipt(bundle)
            with self.assertRaises(evidence.EvidenceError):
                evidence.validate_bundle(bundle)

    def test_failed_run_requires_real_failed_check_and_does_not_invent_unexecuted_checks(self):
        bundle = bundle_fixture()
        report = bundle["http"]
        report["checks"] = report["checks"][:18]
        report["checks"][-1] = {
            key: report["checks"][-1][key] for key in ("id", "stage", "duration_ms")
        }
        report["checks"][-1].update(status="failed", error_code="private_sentinel_error")
        report.update(
            status="failed",
            restoration={"required": False, "attempted": False, "status": "not_needed"},
        )
        refresh_receipt(bundle)
        result = evidence.validate_bundle(bundle)["result"]
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(result["checks"]), 10)
        self.assertEqual(result["restoration_checks"], [])
        self.assertNotIn("private_sentinel_error", json.dumps(result))

    def test_missing_restoration_and_fabricated_pass_rejected(self):
        for change in ({"required": False}, {"attempted": False}, {"status": "not_needed"}):
            bundle = bundle_fixture()
            bundle["http"]["restoration"].update(change)
            refresh_receipt(bundle)
            with self.assertRaises(evidence.EvidenceError):
                evidence.validate_bundle(bundle)

    def test_altered_stale_or_unreconciled_migrations_are_rejected(self):
        mutations = (
            lambda b: b["migration"]["applied"].pop(),
            lambda b: b["state"]["migrations"].update(count=1),
            lambda b: b["state"]["migrations"]["files"][0].update(sha256="0" * 64),
            lambda b: b["state"]["migrations"].update(source_revision="0" * 40),
            lambda b: b["raw_hashes"].update(state="0" * 64),
            lambda b: b["raw_hashes"].update(harness="0" * 64),
            lambda b: b["http"]["source"].update(harness_unchanged=False),
        )
        for mutate in mutations:
            bundle = bundle_fixture()
            mutate(bundle)
            refresh_receipt(bundle)
            with self.assertRaises(evidence.EvidenceError):
                evidence.validate_bundle(bundle)

    def test_isolation_requires_matching_recent_samples_and_effective_loopback(self):
        mutations = (
            lambda b: b["before"].update(finished_at="2026-09-24T00:11:00Z"),
            lambda b: b["before"].update(
                started_at="2026-09-23T00:00:00Z", finished_at="2026-09-23T00:00:01Z"
            ),
            lambda b: b["after"]["runtime"].update(cron_launch_active_jobs="on"),
            lambda b: b["after"]["runtime"].update(external_tcp="reachable"),
            lambda b: b["after"].update(topology_sha256="0" * 64),
            lambda b: b["before"]["topology"]["containers"][-1]["ports"]["55322/tcp"][0].update(
                HostIp="0.0.0.0"
            ),
        )
        for mutate in mutations:
            bundle = bundle_fixture()
            mutate(bundle)
            with self.assertRaises(evidence.EvidenceError):
                evidence.validate_bundle(bundle)

    def test_allowlist_never_imports_identity_hashes_free_text_or_private_metadata(self):
        bundle = bundle_fixture()
        bundle["http"]["identities"] = {"owner": "9" * 64}
        bundle["http"]["limitations"] = ["private-token-sentinel"]
        bundle["migration"]["private_note"] = "private-source-path-sentinel"
        refresh_receipt(bundle)
        result = json.dumps(evidence.validate_bundle(bundle)["result"])
        self.assertNotIn("9" * 64, result)
        self.assertNotIn("sentinel", result)
        bundle["http"]["actors"] = {"owner": {"token": "private-token-sentinel"}}
        refresh_receipt(bundle)
        with self.assertRaises(evidence.EvidenceError):
            evidence.validate_bundle(bundle)

    def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected(self):
        for raw in (b'{"status":"failed","status":"passed"}', b'{"duration":NaN}'):
            with self.assertRaises(evidence.EvidenceError):
                evidence._json(raw)


class AssuranceFileTests(SimpleTestCase):
    def setUp(self):
        self.parent = settings.BASE_DIR / "var/tests"
        self.root = self.parent / ("assurance-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup_case)
        bundle = bundle_fixture()
        for key, relative in PATHS.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = SOURCE_BYTES[key] if key in SOURCE_BYTES else evidence.json_bytes(bundle[key])
            path.write_bytes(raw)
            if key in {"before", "after"}:
                path.with_suffix(".sha256").write_text(evidence.digest(raw) + "\n")
        private = self.root / f"var/labs/bettail/http-runs/{RUN_ID}.private.json"
        private.write_text("PRIVATE SENTINEL: invalid JSON must never be opened")

    def cleanup_case(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.parent.resolve()) or not target.name.startswith(
            "assurance-"
        ):
            raise RuntimeError("Unsafe synthetic fixture cleanup")
        shutil.rmtree(target)

    def test_fixed_local_loader_validates_bytes_without_private_actor_file(self):
        result = evidence.load_assurance(self.root, RUN_ID)
        self.assertEqual(result["status"], "passed")
        self.assertNotIn("PRIVATE SENTINEL", json.dumps(result))

    def test_altered_bytes_and_arbitrary_paths_rejected(self):
        path = self.root / PATHS["http"]
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(evidence.EvidenceError):
            evidence.load_assurance(self.root, RUN_ID)
        for target in ("../private", "https://remote", "bettail", ""):
            with self.assertRaises(evidence.EvidenceError):
                evidence.load_assurance(self.root, target)

    def test_conflicting_receipts_and_checksum_changes_fail(self):
        receipt = self.root / PATHS["receipt"]
        other = receipt.with_name("conflicting.json")
        other.write_bytes(receipt.read_bytes())
        with self.assertRaises(evidence.EvidenceError):
            evidence.load_assurance(self.root, RUN_ID)
        other.unlink()
        checksum = (self.root / PATHS["before"]).with_suffix(".sha256")
        checksum.write_text("0" * 64)
        with self.assertRaises(evidence.EvidenceError):
            evidence.load_assurance(self.root, RUN_ID)

    def test_reparse_points_and_changed_second_read_are_rejected(self):
        with patch.object(
            Path,
            "lstat",
            return_value=SimpleNamespace(
                st_mode=evidence.stat.S_IFREG,
                st_file_attributes=evidence.stat.FILE_ATTRIBUTE_REPARSE_POINT,
            ),
        ):
            with self.assertRaises(evidence.EvidenceError):
                evidence._bounded_path(self.root, Path(PATHS["http"]))
        original_read = evidence._read
        reads = {}

        def changing_read(root, relative, retained):
            raw = original_read(root, relative, retained)
            key = str(relative).replace("\\", "/")
            reads[key] = reads.get(key, 0) + 1
            return raw + b" " if key == PATHS["http"] and reads[key] == 2 else raw

        with patch.object(evidence, "_read", side_effect=changing_read):
            with self.assertRaisesRegex(evidence.EvidenceError, "evidence_changed_during_import"):
                evidence.load_assurance(self.root, RUN_ID)


class AssuranceCommandTests(TestCase):
    def setUp(self):
        self.app = Integration.objects.create(slug="bettail", name="BetTail")
        self.checked = evidence.validate_bundle(bundle_fixture())
        self.loader = patch(
            "bridge.management.commands.import_assurance.load_assurance", return_value=self.checked
        )
        self.loader.start()
        self.addCleanup(self.loader.stop)

    def run_import(self, **kwargs):
        call_command("import_assurance", run_id=RUN_ID, stdout=io.StringIO(), **kwargs)

    def test_import_is_scoped_idempotent_and_audited_once(self):
        self.run_import()
        self.run_import()
        self.assertEqual(CheckRun.objects.count(), 1)
        self.assertEqual(Audit.objects.filter(action="assurance.imported").count(), 1)
        run = CheckRun.objects.get()
        self.assertEqual(run.integration, self.app)
        self.assertEqual(len(run.result["checks"]), 18)

    def test_dry_run_creates_no_database_records(self):
        self.run_import(dry_run=True)
        self.assertFalse(CheckRun.objects.exists())
        self.assertFalse(Audit.objects.exists())

    def test_conflicting_run_identity_does_not_replace_history(self):
        self.run_import()
        old_digest = CheckRun.objects.get().digest
        self.checked["digest"] = "0" * 64
        with self.assertRaises(CommandError):
            self.run_import()
        self.assertEqual(CheckRun.objects.get().digest, old_digest)
        self.assertEqual(Audit.objects.count(), 1)

    def test_invalid_evidence_never_writes_partial_record(self):
        with patch(
            "bridge.management.commands.import_assurance.load_assurance",
            side_effect=evidence.EvidenceError("report_checksum_mismatch"),
        ):
            with self.assertRaises(CommandError):
                self.run_import()
        self.assertFalse(CheckRun.objects.exists())
        self.assertFalse(Audit.objects.exists())
