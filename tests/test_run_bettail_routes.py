"""Mock-only parent-runner checks; no Docker or service request is executed."""

import copy
import io
import json
import subprocess
from contextlib import nullcontext
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, mock_open, patch

from scripts import run_bettail_routes as runner

RUN_ID = "12345678-1234-4234-8234-123456789abc"
PROVENANCE = {
    "migration_digest": "a" * 64,
    "snapshot_digest": "b" * 64,
    "source_revision": "c" * 40,
}
INPUTS = {
    "provenance": PROVENANCE,
    "source_dirty": True,
    "migration_count": 68,
    "reviewed_harness_sha256": {name: "d" * 64 for name in runner.HARNESS},
    "lab_state_sha256": "e" * 64,
    "runner_sha256": "f" * 64,
    "runtime_contract_sha256": "1" * 64,
}
ISOLATION = {
    "status": "passed",
    "errors": [],
    "topology_sha256": "2" * 64,
    "source_hashes": {"safe": "3" * 64},
}
KEYS = {
    "publishableKey": "sb_publishable_" + "synthetic_" * 3,
    "secretKey": "sb_secret_" + "synthetic_" * 3,
}
KEY_BYTES = (
    f"SUPABASE_AUTH_PUBLISHABLE_KEY={KEYS['publishableKey']}\n"
    f"SUPABASE_AUTH_SECRET_KEY='{KEYS['secretKey']}'\n"
).encode()
CHILD = {"exit_code": 0, "timed_out": False, "logs_complete": True, "log_overflow": False}


def child_report(stages, environment, provenance):
    return {
        "schema_version": 1,
        "app": "bettail",
        "run_id": RUN_ID,
        "environment": environment,
        "status": "passed",
        "source": dict(provenance),
        "checks": [
            {"id": name, "stage": stage, "status": "passed", "duration_ms": 1}
            for name, stage in stages.items()
        ],
        "restoration": {"required": True, "attempted": True, "status": "restored_and_retested"},
    }


def result_objects():
    route = child_report(runner.ROUTE_STEPS, "isolated_next_routes", PROVENANCE)
    route["source"].update(
        {
            "harness_sha256": "d" * 64,
            "service_harness_sha256": "d" * 64,
            "harness_sha256_unchanged": True,
            "service_harness_sha256_unchanged": True,
        }
    )
    route["runtime"] = {
        "node_version": "v24.20.0",
        "supabase_ssr_version": "0.12.7",
        "next_mode": "development",
    }
    route["request_count"] = 110
    route["service_setup"] = {
        "status": "passed",
        "executed": 32,
        "passed": 32,
        "restoration": "restored_and_retested",
    }
    service = child_report(
        runner.SERVICE_STEPS,
        "isolated_supabase_http",
        {"migration_digest": PROVENANCE["migration_digest"]},
    )
    private = {
        "schema_version": 1,
        "run_id": RUN_ID,
        "restore_required": False,
        "route_restore_required": False,
        "service": {"run_id": RUN_ID, "restore_required": False},
        "sessions": {"private": "private-sentinel"},
    }
    return route, service, private


class RunnerInputTests(TestCase):
    def test_keys_parse_only_two_exact_formats_and_never_interpolate(self):
        self.assertEqual(runner.parse_keys(KEY_BYTES), KEYS)
        for raw in (
            KEY_BYTES + KEY_BYTES,
            b"",
            b"SUPABASE_AUTH_SECRET_KEY=private-sentinel",
            KEY_BYTES.replace(b"sb_secret_", b"$sb_secret_"),
            KEY_BYTES.replace(b"sb_secret_", b"https://"),
            KEY_BYTES.replace(b"SUPABASE_AUTH_SECRET_KEY=", b"export SUPABASE_AUTH_SECRET_KEY="),
            b"x" * 65537,
        ):
            with self.subTest(raw_length=len(raw)), self.assertRaises(runner.RunError) as error:
                runner.parse_keys(raw)
            self.assertNotIn("private-sentinel", str(error.exception))

    def test_migration_manifest_and_copied_harness_binding_must_match_before_keys(self):
        files = {"supabase/migrations/001_example.sql": "a" * 64, "src/app.ts": "e" * 64}
        migration_files = [{"file": "001_example.sql", "sha256": "a" * 64}]
        digest = runner.gate.base.sha256(
            json.dumps(migration_files, separators=(",", ":")).encode()
        )
        state = {
            "schema_version": 1,
            "app": "bettail",
            "isolation_verified": True,
            "snapshot_digest": "b" * 64,
            "migrations": {
                "status": "passed",
                "count": 1,
                "files": migration_files,
                "source_revision": "c" * 40,
                "digest": digest,
            },
        }
        contract = {
            "snapshot_digest": "b" * 64,
            "harness_files": {
                name: runner.gate.base.sha256(b"reviewed") for name in runner.HARNESS
            },
        }
        metadata = {
            "app": "bettail",
            "snapshot_digest": "b" * 64,
            "source_revision": "c" * 40,
            "source_dirty": True,
            "files": files,
        }
        with (
            patch.object(runner, "read_json", return_value=(state, "d" * 64)),
            patch.object(runner.gate, "read_contract", return_value=contract),
            patch.object(runner.gate.snapshot_app, "verify_snapshot", return_value=metadata),
            patch.object(runner, "read_bytes", return_value=b"reviewed") as read,
        ):
            verified = runner.verify_inputs()
            self.assertEqual(verified["migration_count"], 1)
            self.assertEqual(verified["provenance"]["source_revision"], "c" * 40)
            self.assertFalse(any(call.args[0] == runner.ENV for call in read.call_args_list))
            for field, bad in (
                ("digest", "f" * 64),
                ("source_revision", "f" * 40),
                ("count", 2),
                ("status", "failed"),
            ):
                original = state["migrations"][field]
                state["migrations"][field] = bad
                with self.assertRaisesRegex(runner.RunError, "migration_source_mismatch"):
                    runner.verify_inputs()
                state["migrations"][field] = original
            contract["harness_files"]["runtime.mjs"] = "0" * 64
            with self.assertRaisesRegex(
                runner.RunError, "mounted_harness_differs_from_reviewed_source"
            ):
                runner.verify_inputs()

    def test_warmup_has_only_two_fixed_anonymous_get_routes_and_time_bounds(self):
        with patch.object(
            runner.gate.base, "docker", return_value='{"statuses":[401,401]}'
        ) as docker:
            self.assertEqual(runner.warmup()["status"], "passed")
        arguments = docker.call_args.args[0]
        self.assertEqual(arguments[:4], ["exec", runner.gate.NEXT, "node", "-e"])
        for expected in (
            "http://127.0.0.1:3101",
            "/api/state",
            "/api/chat-image?comment_id=",
            "120000",
            "method:'GET'",
            "redirect:'error'",
        ):
            self.assertIn(expected, arguments[-1])
        self.assertNotIn("Cookie", arguments[-1])
        with (
            patch.object(runner.gate.base, "docker", return_value='{"statuses":[200,401]}'),
            self.assertRaisesRegex(runner.RunError, "anonymous_warmup_failed"),
        ):
            runner.warmup()


class ResultValidationTests(TestCase):
    def test_exact_counts_and_public_metadata_do_not_copy_private_values(self):
        route, service, private = result_objects()
        with patch.object(
            runner,
            "read_json",
            side_effect=[(route, "a" * 64), (service, "b" * 64), (private, "c" * 64)],
        ):
            result = runner.read_results(RUN_ID, INPUTS)
        self.assertEqual(
            result["route"],
            {
                "executed": 23,
                "passed": 23,
                "stages": {"setup": 4, "assertion": 16, "restoration": 3},
            },
        )
        self.assertEqual(
            result["service"]["stages"], {"setup": 10, "assertion": 18, "restoration": 4}
        )
        self.assertNotIn("private-sentinel", json.dumps(result))

    def test_missing_duplicate_failed_wrong_stage_or_wrong_source_cannot_pass(self):
        modifications = (
            lambda value: value["checks"].pop(),
            lambda value: value["checks"].__setitem__(0, copy.deepcopy(value["checks"][1])),
            lambda value: value["checks"][0].update({"status": "failed"}),
            lambda value: value["checks"][0].update({"stage": "assertion"}),
            lambda value: value["checks"][0].update({"duration_ms": True}),
            lambda value: value["source"].update({"source_revision": "f" * 40}),
            lambda value: value.update({"status": "failed"}),
            lambda value: value["restoration"].update({"status": "not_needed"}),
        )
        for modify in modifications:
            value = result_objects()[0]
            modify(value)
            with self.assertRaises(runner.RunError):
                runner.validate_report(
                    value,
                    run_id=RUN_ID,
                    provenance=PROVENANCE,
                    stages=runner.ROUTE_STEPS,
                    environment="isolated_next_routes",
                )

    def test_uncertain_private_recovery_state_never_counts_as_restored(self):
        route, service, private = result_objects()
        for bad in (True, None, 0):
            private["restore_required"] = bad
            with patch.object(
                runner,
                "read_json",
                side_effect=[(route, "a" * 64), (service, "b" * 64), (private, "c" * 64)],
            ):
                with self.assertRaisesRegex(runner.RunError, "recovery_state_not_verified"):
                    runner.read_results(RUN_ID, INPUTS)


class RecoveryGuardTests(TestCase):
    def test_existing_lock_refuses_without_overwriting_or_deleting(self):
        with (
            patch.object(runner.gate, "_safe"),
            patch.object(runner.Path, "open", side_effect=FileExistsError),
            patch.object(runner.Path, "unlink") as delete,
        ):
            with self.assertRaisesRegex(runner.RunError, "route_execution_locked"):
                runner.acquire_lock(RUN_ID)
            delete.assert_not_called()

    def test_release_deletes_only_unchanged_owned_lock(self):
        with (
            patch.object(runner, "read_bytes", return_value=b"other"),
            patch.object(runner.Path, "unlink") as delete,
        ):
            with self.assertRaisesRegex(runner.RunError, "execution_lock_changed"):
                runner.release_lock(b"ours")
            delete.assert_not_called()
        with (
            patch.object(runner, "read_bytes", return_value=b"ours"),
            patch.object(runner.Path, "unlink") as delete,
        ):
            runner.release_lock(b"ours")
            delete.assert_called_once_with()

    def test_pending_unknown_partial_or_linked_evidence_blocks_preflight(self):
        for names in ([RUN_ID + ".private.json"], [RUN_ID + ".pending"], ["unknown.json"]):
            entries = [SimpleNamespace(path=str(runner.EVIDENCE / name)) for name in names]
            with (
                patch.object(runner.gate, "_safe"),
                patch.object(runner.os, "scandir", return_value=nullcontext(iter(entries))),
                self.assertRaises(runner.RunError),
            ):
                runner.recovery_preflight()
        with patch.object(runner.gate, "_safe", side_effect=runner.gate.VerificationError("link")):
            with self.assertRaises(runner.gate.VerificationError):
                runner.recovery_preflight()

    def test_complete_inventory_checks_every_run_and_enforces_bound(self):
        names = [RUN_ID + suffix for suffix in (".json", ".private.json", ".service.json")]
        entries = [SimpleNamespace(path=str(runner.EVIDENCE / name)) for name in names]
        with (
            patch.object(runner.gate, "_safe"),
            patch.object(runner.os, "scandir", return_value=nullcontext(iter(entries))),
            patch.object(runner, "recovery_clear", return_value=True) as clear,
        ):
            self.assertEqual(
                runner.recovery_preflight(), {"prior_runs_checked": 1, "unresolved": 0}
            )
            clear.assert_called_once_with(RUN_ID)
        with (
            patch.object(runner, "MAX_EVIDENCE_FILES", 2),
            patch.object(runner.gate, "_safe"),
            patch.object(runner.os, "scandir", return_value=nullcontext(iter(entries))),
        ):
            with self.assertRaisesRegex(runner.RunError, "prior_evidence_inventory_limit"):
                runner.recovery_preflight()

    @patch.object(runner, "verify_run_inventory")
    def test_starting_true_missing_or_failed_restoration_is_unresolved(self, _):
        route, service, private = result_objects()
        for mutation in (
            {"state": "starting"},
            {"restore_required": True},
            {"restore_required": None},
            {"route_restore_required": True},
        ):
            with patch.object(
                runner, "read_json", side_effect=[({**private, **mutation}, "a" * 64)]
            ):
                with self.assertRaisesRegex(runner.RunError, "prior_recovery_unresolved"):
                    runner.recovery_clear(RUN_ID)
        route["restoration"]["status"] = "restore_or_retest_failed"
        with patch.object(
            runner, "read_json", side_effect=[(private, "a" * 64), (route, "a" * 64)]
        ):
            with self.assertRaisesRegex(runner.RunError, "prior_recovery_unresolved"):
                runner.recovery_clear(RUN_ID)
        route["restoration"]["status"] = "restored_and_retested"
        route["status"] = "failed"  # A failed assertion may still have verified restoration.
        with patch.object(
            runner,
            "read_json",
            side_effect=[(private, "a" * 64), (route, "a" * 64), (service, "a" * 64)],
        ):
            self.assertTrue(runner.recovery_clear(RUN_ID))

    def test_pending_replacement_blocks_old_false_recovery_marker_before_read(self):
        names = [RUN_ID + suffix for suffix in (".json", ".private.json", ".service.json")]
        for pending in (
            RUN_ID + ".14811900-1234-4234-8234-123456789abc.pending",
            RUN_ID + ".unknown",
        ):
            entries = [
                SimpleNamespace(path=str(runner.EVIDENCE / name)) for name in [*names, pending]
            ]
            with (
                patch.object(runner.gate, "_safe"),
                patch.object(runner.os, "scandir", return_value=nullcontext(iter(entries))),
                patch.object(
                    runner, "read_json", return_value=({"restore_required": False}, "a" * 64)
                ) as read,
            ):
                with self.assertRaisesRegex(
                    runner.RunError, "recovery_replacement_pending_or_unknown"
                ):
                    runner.recovery_clear(RUN_ID)
                read.assert_not_called()

    def test_run_inventory_is_bounded_and_demands_all_three_final_files(self):
        names = [RUN_ID + suffix for suffix in (".json", ".private.json", ".service.json")]
        for subset, limit, expected in (
            (names, 3, None),
            (names, 2, "recovery_inventory_limit"),
            (names[:2], 3, "recovery_evidence_incomplete"),
        ):
            entries = [SimpleNamespace(path=str(runner.EVIDENCE / name)) for name in subset]
            with (
                patch.object(runner.gate, "_safe"),
                patch.object(runner, "MAX_EVIDENCE_FILES", limit),
                patch.object(runner.os, "scandir", return_value=nullcontext(iter(entries))),
            ):
                if expected:
                    with self.assertRaisesRegex(runner.RunError, expected):
                        runner.verify_run_inventory(RUN_ID)
                else:
                    runner.verify_run_inventory(RUN_ID)


class ExecutionTests(TestCase):
    def execute(
        self,
        *,
        inputs=None,
        gates=None,
        child=None,
        results=None,
        warmup_error=None,
        preflight_error=None,
        lock_error=None,
        recovery_error=None,
    ):
        with (
            patch.object(runner.uuid, "uuid4", return_value=RUN_ID),
            patch.object(runner, "mkdir_private"),
            patch.object(runner, "acquire_lock", return_value=b"lock", side_effect=lock_error),
            patch.object(runner, "verify_lock"),
            patch.object(runner, "release_lock"),
            patch.object(
                runner,
                "recovery_preflight",
                return_value={"prior_runs_checked": 0, "unresolved": 0},
                side_effect=preflight_error,
            ),
            patch.object(
                runner,
                "recovery_clear",
                return_value=not isinstance(results, Exception),
                side_effect=recovery_error,
            ),
            patch.object(runner.Path, "mkdir"),
            patch.object(runner.gate, "_safe"),
            patch.object(
                runner, "verify_inputs", side_effect=inputs or [INPUTS, INPUTS, INPUTS]
            ) as source,
            patch.object(
                runner.gate, "run_verification", side_effect=gates or [ISOLATION, ISOLATION]
            ) as gate,
            patch.object(runner, "write_receipt", return_value="a" * 64) as receipts,
            patch.object(
                runner, "warmup", side_effect=warmup_error, return_value={"status": "passed"}
            ),
            patch.object(runner, "read_bytes", return_value=KEY_BYTES) as keys,
            patch.object(runner, "run_child", return_value=child or CHILD) as run_child,
            patch.object(
                runner, "read_results", side_effect=results, return_value={"route": {"passed": 23}}
            ),
        ):
            report, _ = runner.run()
        return report, source, gate, keys, run_child, receipts

    def test_success_has_before_after_gate_stable_source_and_immutable_receipt(self):
        report, source, gate, keys, child, receipts = self.execute()
        self.assertEqual(report["status"], "passed")
        self.assertFalse(report["restore_required"])
        self.assertFalse(report["lock_retained"])
        self.assertEqual(gate.call_count, 2)
        self.assertEqual(source.call_count, 3)
        keys.assert_called_once_with(runner.ENV, 65536)
        self.assertEqual(
            child.call_args.args[0], {**KEYS, "provenance": PROVENANCE, "runId": RUN_ID}
        )
        self.assertEqual(receipts.call_args_list[-1].args[1], "execution.json")
        self.assertNotIn(KEYS["secretKey"], json.dumps(report))

    def test_unsafe_before_gate_runs_after_gate_but_never_reads_keys_or_runs_fixtures(self):
        report, _, gate, keys, child, _ = self.execute(
            gates=[{"status": "failed", "errors": ["unsafe"]}, ISOLATION]
        )
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["restore_required"])
        self.assertEqual(gate.call_count, 2)
        keys.assert_not_called()
        child.assert_not_called()

    def test_warmup_failure_and_source_drift_prevent_credential_read_and_fixture_run(self):
        report, _, gate, keys, child, _ = self.execute(
            warmup_error=runner.RunError("warmup_failed")
        )
        self.assertEqual(report["status"], "failed")
        self.assertEqual(gate.call_count, 2)
        keys.assert_not_called()
        child.assert_not_called()
        changed = {**INPUTS, "lab_state_sha256": "0" * 64}
        report, _, _, keys, child, _ = self.execute(inputs=[INPUTS, changed, changed])
        self.assertIn("source_changed_during_warmup", report["errors"])
        keys.assert_not_called()
        child.assert_not_called()

    def test_timeout_or_unreadable_reports_retains_recovery_flag_and_after_gate(self):
        report, _, gate, _, _, _ = self.execute(
            child={**CHILD, "timed_out": True, "exit_code": None, "logs_complete": False}
        )
        self.assertEqual(report["status"], "failed")
        self.assertTrue(report["restore_required"])
        self.assertTrue(report["lock_retained"])
        self.assertIn("child_timeout_recovery_required", report["errors"])
        self.assertEqual(gate.call_count, 2)

    def test_existing_lock_or_unresolved_prior_run_blocks_every_service_operation(self):
        for options in (
            {"lock_error": runner.RunError("route_execution_locked_recovery_review_required")},
            {"preflight_error": runner.RunError("prior_recovery_unresolved")},
        ):
            report, source, gate, keys, child, _ = self.execute(**options)
            self.assertEqual(report["status"], "failed")
            self.assertTrue(report["restore_required"])
            self.assertTrue(report["lock_retained"])
            source.assert_not_called()
            gate.assert_not_called()
            keys.assert_not_called()
            child.assert_not_called()

    def test_pending_replacement_after_completed_child_retains_lock_and_review_flag(self):
        report, _, gate, _, _, _ = self.execute(
            child={**CHILD, "exit_code": 1},
            results=runner.RunError("child_report_failed"),
            recovery_error=runner.RunError("recovery_replacement_pending_or_unknown"),
        )
        self.assertEqual(report["status"], "failed")
        self.assertTrue(report["restore_required"])
        self.assertTrue(report["lock_retained"])
        self.assertIn("recovery_review_required", report["errors"])
        self.assertEqual(gate.call_count, 2)
        report, _, gate, _, _, _ = self.execute(results=OSError("private-sentinel"))
        self.assertTrue(report["restore_required"])
        self.assertNotIn("private-sentinel", json.dumps(report))
        self.assertEqual(gate.call_count, 2)

    def test_after_gate_failure_or_cross_run_topology_change_fails_completed_checks(self):
        for after in (
            {"status": "failed", "errors": ["unsafe"]},
            {**ISOLATION, "topology_sha256": "f" * 64},
        ):
            report, _, _, _, _, _ = self.execute(gates=[ISOLATION, after])
            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["restore_required"])

    def test_unknown_cli_targets_are_refused_before_execution(self):
        with (
            patch.object(runner, "run") as run,
            patch.object(runner.sys, "stderr", io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                runner.main(["--target", "remote"])
            run.assert_not_called()

    def test_child_timeout_does_not_kill_and_keys_are_only_on_stdin(self):
        process = MagicMock()
        process.stdout = io.BytesIO(b"safe stdout")
        process.stderr = io.BytesIO(b"safe stderr")
        process.wait.side_effect = subprocess.TimeoutExpired("fixed", 210)
        with (
            patch.object(runner.Path, "open", mock_open()),
            patch.object(
                runner,
                "docker_command",
                return_value=[
                    "docker.exe",
                    "--host",
                    runner.gate.base.PIPE,
                    "exec",
                    "-i",
                    runner.gate.NEXT,
                    "node",
                    "/lab/bettail-routes.mjs",
                ],
            ),
            patch.object(runner.subprocess, "Popen", return_value=process) as popen,
        ):
            result = runner.run_child(
                {**KEYS, "provenance": PROVENANCE, "runId": RUN_ID}, runner.EXECUTIONS / RUN_ID
            )
        self.assertTrue(result["timed_out"])
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        self.assertNotIn(KEYS["secretKey"], repr(popen.call_args))
        sent = json.loads(process.stdin.write.call_args.args[0])
        self.assertEqual(sent["secretKey"], KEYS["secretKey"])
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertFalse(
            any(
                name.startswith(("SUPABASE_", "DOCKER_", "NODE_"))
                for name in popen.call_args.kwargs["env"]
            )
        )
