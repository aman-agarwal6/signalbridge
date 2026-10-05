"""Modeled daemon replies and real bounded files; no native execution proof."""

import copy
import hashlib
import subprocess
import time
from datetime import timedelta
from unittest.mock import Mock, patch

from django.test import SimpleTestCase
from django.utils import timezone

from bridge.contract import canonical
from integrations.enterprise import preserved_workloads as inventory
from integrations.enterprise import verification as base
from integrations.wazuh_enterprise import collector_host_controls as host
from integrations.wazuh_enterprise import execution_policy as policy
from integrations.wazuh_enterprise import preservation_profile as preserved
from integrations.wazuh_enterprise.contract import EnterpriseWazuhError
from scripts import enterprise_wazuh_live_verify as live
from tests.test_soc_delivery import disposable_root

RUN, EXISTING, OWNED = "a" * 32, "b" * 64, "c" * 64


class ExecutionPolicyTests(SimpleTestCase):
    def setUp(self):
        for target, name in ((base, "docker_result"), (subprocess, "Popen")):
            barrier = self.enterContext(
                patch.object(target, name, side_effect=AssertionError("Native execution forbidden"))
            )
            self.addCleanup(barrier.assert_not_called)
        self.workspace = disposable_root(self)
        self.directory = base.private_run_directory(self.workspace, RUN)
        self.directory.mkdir(parents=True)
        self.now = timezone.now()
        for relative in policy.REVIEWED_FILES:
            path = self.workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"non-executable source identity fixture\n")
        self.plan = {
            "schema_version": 1,
            "controls": policy.CONTROLS,
            "reviewed_files": {
                relative: hashlib.sha256((self.workspace / relative).read_bytes()).hexdigest()
                for relative in policy.REVIEWED_FILES
            },
            "review_notes": ["Modeled profile only; never native launch authority."],
        }
        path = self.workspace / policy.PLAN
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical(self.plan))
        self.plan_digest = hashlib.sha256(canonical(self.plan)).hexdigest()
        envelope = {
            "id": EXISTING,
            "running": True,
            "started_at": "2026-10-02T12:00:00Z",
            "restart_count": 0,
            "mounts": [],
            "privileged": False,
            "pid_mode": "",
            "ipc_mode": "private",
            "uts_mode": "",
            "cgroupns_mode": "private",
            "network_mode": "reference_default",
            "memory": 0,
            "memory_swap": 0,
            "nano_cpus": 0,
            "pids_limit": None,
            "networks": {"reference_default": "d" * 64},
        }

        def request(arguments, *, timeout):
            self.assertEqual(timeout, 3)
            if arguments == preserved.INFO_ARGUMENTS:
                return canonical({"id": "modeled-engine", "os_type": "linux"}).decode()
            if arguments == inventory.RUNNING_ARGUMENTS:
                return EXISTING
            self.assertEqual(
                arguments,
                ("container", "inspect", EXISTING, "--format", preserved.ENVELOPE_TEMPLATE),
            )
            return canonical(envelope).decode()

        self.request = request
        self.baseline, self.public = preserved.capture(
            request, RUN, self.directory, self.plan_digest
        )
        for name, value in (
            ("preservation.json", self.baseline),
            ("reviewed-stage-plan.json", self.plan),
        ):
            (self.directory / name).write_bytes(canonical(value))
        self.final = preserved.checkpoint(
            request,
            self.baseline,
            RUN,
            self.directory,
            self.plan_digest,
            (OWNED,),
            expected_digest=self.public["preservation_digest"],
        )
        self.receipt = {
            "run_id": RUN,
            "execution_policy": policy.POLICY,
            "reviewed_plan_sha256": self.plan_digest,
            "preservation_digest": self.public["preservation_digest"],
            "preserved_count": 1,
            "preservation_verified": True,
            "preservation_final": self.final,
            "stage_growth_ceiling_bytes": host.GROWTH,
        }
        self.watchdog = {
            "run_id": RUN,
            "shutdown_verified": True,
            "reason": "launcher_finished",
            "stopped_component_count": 1,
            "stopped_at": self.now.isoformat(),
            "late_operation_drain_seconds": 60,
            "late_operation_drain_elapsed_ms": 60000,
            "late_operation_drain_verified": True,
            "preservation_verified": True,
            "preservation_final": self.final,
        }
        self.main = {"run_id": RUN, "shutdown_verified": True, "stopped_component_count": 1}

    def test_changed_plan_source_or_digest_rejects_before_daemon_access(self):
        self.assertEqual(policy.read_plan(self.workspace)[1], self.plan_digest)
        with self.assertRaises(EnterpriseWazuhError):
            policy.read_plan(self.workspace, "0" * 64)
        (self.workspace / policy.REVIEWED_FILES[0]).write_bytes(b"changed implementation")
        with self.assertRaises(EnterpriseWazuhError):
            policy.read_plan(self.workspace)

    def test_acl_diagnostic_dependency_cannot_be_omitted_or_changed(self):
        dependency = "integrations/enterprise/private_acl_diagnostics.py"
        self.assertIn(dependency, policy.REVIEWED_FILES)
        omitted = copy.deepcopy(self.plan)
        del omitted["reviewed_files"][dependency]
        with self.assertRaisesMessage(EnterpriseWazuhError, "collector_review_plan_invalid"):
            policy.validate_plan(omitted)
        (self.workspace / dependency).write_bytes(b"changed non-executable diagnostic fixture")
        with self.assertRaisesMessage(
            EnterpriseWazuhError, "collector_reviewed_implementation_changed"
        ):
            policy.read_plan(self.workspace)

    def test_acl_helper_cannot_be_omitted_or_changed_before_launch_admission(self):
        helper = "integrations/enterprise/reference-private-acl.ps1"
        self.assertIn(helper, policy.REVIEWED_FILES)
        omitted = copy.deepcopy(self.plan)
        del omitted["reviewed_files"][helper]
        with self.assertRaisesMessage(EnterpriseWazuhError, "collector_review_plan_invalid"):
            policy.validate_plan(omitted)
        (self.workspace / helper).write_bytes(b"changed non-executable ACL fixture")
        with (
            patch.object(live, "ROOT", self.workspace),
            patch.object(live, "private_acl") as acl,
            patch.object(policy, "capture") as capture,
            patch.object(host, "inspect_image") as image,
            patch.object(live, "arm_guard") as guard,
            self.assertRaisesMessage(
                EnterpriseWazuhError, "collector_reviewed_implementation_changed"
            ),
        ):
            live.launch(
                "modeled",
                "modeled-not-authority",
                RUN,
                RUN,
                execution_policy=policy.POLICY,
                reviewed_plan_sha256=self.plan_digest,
            )
        for blocked in (acl, capture, image, guard):
            blocked.assert_not_called()

    def test_capacity_revision_requires_its_separate_named_and_hash_bound_plan(self):
        alternative = copy.deepcopy(self.plan)
        alternative["controls"] = policy.controls_for(policy.CAPACITY_PLAN)
        path = self.workspace / policy.CAPACITY_PLAN
        path.write_bytes(canonical(alternative))
        expected = hashlib.sha256(canonical(alternative)).hexdigest()
        self.assertEqual(
            policy.read_plan(self.workspace, expected, plan_name=policy.CAPACITY_PLAN)[1], expected
        )
        self.assertEqual(policy.read_plan(self.workspace)[1], self.plan_digest)
        with self.assertRaises(EnterpriseWazuhError):
            policy.read_plan(self.workspace, expected)
        with self.assertRaises(EnterpriseWazuhError):
            policy.read_plan(self.workspace, self.plan_digest, plan_name=policy.CAPACITY_PLAN)
        with self.assertRaises(EnterpriseWazuhError):
            policy.validate_plan(alternative)
        for name in (True, "../reviewed-stage-plan.json", "unreviewed.json"):
            with self.subTest(name=name), self.assertRaises(EnterpriseWazuhError):
                policy.read_plan(self.workspace, plan_name=name)
        for value in (True, 30.0 * base.GIB, 31 * base.GIB, 13 * base.GIB):
            changed = copy.deepcopy(alternative)
            changed["controls"]["cumulative_disk_growth_guard_bytes"] = value
            with self.subTest(value=value), self.assertRaises(EnterpriseWazuhError):
                policy.validate_plan(changed, plan_name=policy.CAPACITY_PLAN)

    def test_retained_plan_not_free_capacity_parameter_controls_main_and_watchdog(self):
        alternative = copy.deepcopy(self.plan)
        alternative["controls"] = policy.controls_for(policy.CAPACITY_PLAN)
        expected = hashlib.sha256(canonical(alternative)).hexdigest()
        baseline, public = preserved.capture(self.request, RUN, self.directory, expected)
        (self.directory / "reviewed-stage-plan.json").write_bytes(canonical(alternative))
        (self.directory / "preservation.json").write_bytes(canonical(baseline))
        (self.workspace / policy.CAPACITY_PLAN).write_bytes(canonical(alternative))
        with patch.object(preserved, "bind_request", return_value=self.request):
            context = policy.load(
                "modeled",
                RUN,
                self.workspace,
                public["preservation_digest"],
                expected,
                plan_name=policy.CAPACITY_PLAN,
            )
        self.assertEqual(context.growth_ceiling, 30 * base.GIB)
        self.assertEqual(context.public_binding()["stage_plan"], policy.CAPACITY_PLAN)
        with patch.object(preserved, "bind_request", return_value=self.request):
            with self.assertRaises(EnterpriseWazuhError):
                policy.load("modeled", RUN, self.workspace, public["preservation_digest"], expected)
        changed = copy.deepcopy(alternative)
        changed["review_notes"].append("Unreviewed change")
        (self.directory / "reviewed-stage-plan.json").write_bytes(canonical(changed))
        with self.assertRaises(EnterpriseWazuhError):
            policy.PreservationPolicy(
                "modeled",
                RUN,
                self.workspace,
                baseline,
                public["preservation_digest"],
                expected,
                plan_name=policy.CAPACITY_PLAN,
            )

    def test_exclusive_launch_cannot_select_capacity_revision(self):
        with self.assertRaises(EnterpriseWazuhError):
            live.launch(
                "modeled", "modeled-not-authority", RUN, RUN, stage_plan=policy.CAPACITY_PLAN
            )

    def test_historical_exclusive_receipts_cannot_claim_the_capacity_revision(self):
        policy.verify_recorded(self.directory, {}, {})
        policy.verify_recorded(
            self.directory,
            {"stage_plan": policy.PLAN, "stage_growth_ceiling_bytes": host.GROWTH},
            {},
        )
        for declaration in (
            {"stage_plan": policy.CAPACITY_PLAN},
            {"stage_plan": "unknown"},
            {"stage_growth_ceiling_bytes": host.REVIEWED_CAPACITY_GROWTH},
            {"stage_growth_ceiling_bytes": True},
            {"stage_growth_ceiling_bytes": None},
        ):
            with self.subTest(declaration=declaration), self.assertRaises(EnterpriseWazuhError):
                policy.verify_recorded(self.directory, declaration, {})

    def test_guard_command_carries_exact_plan_name_and_digest_without_a_budget_integer(self):
        context = Mock()
        context.digest, context.plan_digest = "b" * 64, "d" * 64
        context.plan_name = policy.CAPACITY_PLAN
        with patch.object(live.subprocess, "Popen") as process:
            live.arm_guard("modeled", RUN, context)
        arguments = process.call_args.args[0]
        self.assertEqual(arguments[arguments.index("--stage-plan") + 1], policy.CAPACITY_PLAN)
        self.assertEqual(
            arguments[arguments.index("--reviewed-plan-sha256") + 1], context.plan_digest
        )
        self.assertNotIn("--growth-ceiling", arguments)

    def test_recorded_binding_is_engine_bound_and_closed(self):
        policy.verify_recorded(self.directory, self.receipt, self.watchdog)
        for value in (True, host.REVIEWED_CAPACITY_GROWTH, None):
            with self.subTest(value=value), self.assertRaises(EnterpriseWazuhError):
                policy.verify_recorded(
                    self.directory,
                    {**self.receipt, "stage_growth_ceiling_bytes": value},
                    self.watchdog,
                )
        for field, value in (
            ("engine_digest", "e" * 64),
            ("owned_running_count", 1),
            ("running_count", 2),
            ("running_digest", "e" * 64),
            ("preserved_count", True),
            ("unexpected", 1),
        ):
            receipt, watchdog = copy.deepcopy(self.receipt), copy.deepcopy(self.watchdog)
            receipt["preservation_final"][field] = value
            watchdog["preservation_final"][field] = value
            with self.subTest(field=field), self.assertRaises(EnterpriseWazuhError):
                policy.verify_recorded(self.directory, receipt, watchdog)

    def test_unbound_unknown_or_changed_private_baseline_cannot_be_admitted(self):
        with self.assertRaises(EnterpriseWazuhError):
            policy.verify_recorded(self.directory, {"execution_policy": "unknown"}, {})
        with self.assertRaises(EnterpriseWazuhError):
            policy.verify_recorded(self.directory, {"preservation_digest": "e" * 64}, {})
        changed = copy.deepcopy(self.baseline)
        changed["engine"]["id"] = "replaced-engine"
        (self.directory / "preservation.json").write_bytes(canonical(changed))
        with self.assertRaises(base.LabControlError):
            policy.verify_recorded(self.directory, self.receipt, self.watchdog)

    def test_shutdown_extensions_are_checked_without_relaxing_other_profiles(self):
        window = {
            "started": self.now - timedelta(seconds=2),
            "finished": self.now + timedelta(seconds=2),
        }
        self.assertTrue(
            policy.publication_shutdown(self.main, self.watchdog, RUN, shared=True, **window)[
                "independent_shutdown_verified"
            ]
        )
        exclusive = {
            key: value
            for key, value in self.watchdog.items()
            if not key.startswith("preservation_")
        }
        policy.publication_shutdown(self.main, exclusive, RUN, **window)
        for update in (
            {"late_operation_drain_verified": False},
            {"late_operation_drain_seconds": True},
            {"late_operation_drain_elapsed_ms": 1000},
            {"preservation_verified": False},
            {"unexpected": True},
        ):
            with self.subTest(update=update), self.assertRaises(EnterpriseWazuhError):
                policy.publication_shutdown(
                    self.main, {**self.watchdog, **update}, RUN, shared=True, **window
                )

    def test_cleanup_ignores_preserved_drift_but_refuses_a_replaced_engine(self):
        with patch.object(preserved, "bind_request", return_value=self.request):
            context = policy.PreservationPolicy(
                "modeled",
                RUN,
                self.workspace,
                self.baseline,
                self.public["preservation_digest"],
                self.plan_digest,
            )
        with patch.object(host, "owned", return_value=[OWNED]):
            self.assertTrue(context.admit_stop(OWNED))
            self.assertFalse(context.admit_stop(EXISTING))
            with patch.object(
                preserved, "engine", return_value={"id": "different-engine", "os_type": "linux"}
            ):
                self.assertFalse(context.admit_stop(OWNED))

    def test_preservation_checkpoint_has_a_total_budget(self):
        with patch.object(preserved, "bind_request", return_value=self.request):
            context = policy.PreservationPolicy(
                "modeled",
                RUN,
                self.workspace,
                self.baseline,
                self.public["preservation_digest"],
                self.plan_digest,
            )
        with patch.object(policy.time, "monotonic", side_effect=[0, 19]):
            with self.assertRaises(base.LabControlError):
                context.checkpoint((OWNED,))
        self.assertTrue(context.failed)
        context.checkpoint((OWNED,))
        self.assertTrue(context.failed)

    def test_guard_latches_transient_preserved_failure_but_keeps_owned_shutdown_result(self):
        (self.directory / "launcher-finished.json").write_bytes(canonical({"run_id": RUN}))
        preservation = Mock()
        preservation.checkpoint.side_effect = [
            base.LabControlError("modeled drift"),
            self.final,
            self.final,
        ]
        writes = {}
        with (
            patch.object(
                host,
                "read_json",
                side_effect=lambda path, *a: (
                    self.main if path.name == "launcher-finished.json" else {}
                ),
            ),
            patch.object(host, "image_identity"),
            patch.object(host, "check_capacity"),
            patch.object(host, "owned", return_value=[OWNED]),
            patch.object(host, "verify_runtime"),
            patch.object(host, "stop_scope", return_value=1) as stop,
            patch.object(
                host, "write_control", side_effect=lambda w, r, n, v: writes.update({n: v})
            ),
            patch.object(host.time, "monotonic", side_effect=[0, 0, 0, 61, 61]),
        ):
            result = host.watchdog(
                "modeled",
                RUN,
                self.workspace,
                time.time() + 120,
                lambda: 8 * base.GIB,
                publication=True,
                preservation=preservation,
            )
        self.assertTrue(result["shutdown_verified"])
        self.assertFalse(result["preservation_verified"])
        self.assertEqual(result["reason"], "control_error")
        self.assertTrue(
            all(
                call.kwargs["admit_stop"] is preservation.admit_stop for call in stop.call_args_list
            )
        )

    def test_exclusive_admission_remains_the_default_and_shared_is_explicit(self):
        with (
            patch.object(host, "owned", return_value=[OWNED]),
            patch.object(live, "no_foreign_running") as exclusive,
        ):
            live.admission("modeled", RUN)
            exclusive.assert_called_once_with("modeled", [OWNED])
            context = Mock()
            live.admission("modeled", RUN, context)
            context.checkpoint.assert_called_once_with([OWNED])
            self.assertEqual(exclusive.call_count, 1)

    def test_stop_refuses_a_preserved_id_after_fresh_ownership_check(self):
        with (
            patch.object(host, "owned", return_value=[EXISTING]),
            patch.object(host, "role"),
            patch.object(host, "request") as native,
        ):
            with self.assertRaises(EnterpriseWazuhError):
                host.stop_scope(
                    "modeled",
                    RUN,
                    self.workspace,
                    publication=True,
                    admit_stop=lambda identifier: False,
                )
        native.assert_not_called()

    def test_guard_rechecks_a_late_owned_arrival_during_the_drain(self):
        (self.directory / "launcher-finished.json").write_bytes(canonical({"run_id": RUN}))
        writes = {}
        with (
            patch.object(
                host,
                "read_json",
                side_effect=lambda path, *a: (
                    {"run_id": RUN} if path.name == "launcher-finished.json" else {}
                ),
            ),
            patch.object(host, "image_identity"),
            patch.object(host, "check_capacity"),
            patch.object(host, "owned", return_value=[]),
            patch.object(host, "stop_scope", side_effect=[0, 1, 1]) as stop,
            patch.object(
                host, "write_control", side_effect=lambda w, r, n, v: writes.update({n: v})
            ),
            patch.object(host.time, "monotonic", side_effect=[0, 0, 0, 0, 1, 2, 60, 61, 61]),
            patch.object(host.time, "sleep"),
        ):
            result = host.watchdog(
                "modeled",
                RUN,
                self.workspace,
                time.time() + 120,
                lambda: 8 * base.GIB,
                publication=True,
            )
        self.assertEqual(stop.call_count, 3)
        self.assertEqual(result["stopped_component_count"], 1)
        self.assertTrue(result["late_operation_drain_verified"])
        self.assertTrue(result["shutdown_verified"])

    def test_guard_reports_permanent_peer_failure_separately_from_own_cleanup(self):
        (self.directory / "launcher-finished.json").write_bytes(canonical({"run_id": RUN}))
        preservation = Mock()
        preservation.checkpoint.side_effect = base.LabControlError(
            "modeled missing preserved workload"
        )
        with (
            patch.object(host, "read_json", return_value={}),
            patch.object(host, "image_identity"),
            patch.object(host, "check_capacity"),
            patch.object(host, "owned", return_value=[OWNED]),
            patch.object(host, "stop_scope", return_value=1),
            patch.object(host, "write_control"),
            patch.object(host.time, "monotonic", side_effect=[0, 0, 0, 0, 1, 61, 61]),
            patch.object(host.time, "sleep"),
        ):
            result = host.watchdog(
                "modeled",
                RUN,
                self.workspace,
                time.time() + 120,
                lambda: 8 * base.GIB,
                publication=True,
                preservation=preservation,
            )
        self.assertTrue(result["shutdown_verified"])
        self.assertFalse(result["preservation_verified"])

    def test_guard_wait_retries_timeouts_only_inside_its_absolute_budget(self):
        guard = Mock()
        guard.wait.side_effect = [subprocess.TimeoutExpired("modeled", 10), None]
        with patch.object(live.time, "monotonic", side_effect=[0, 0, 10]):
            live.await_guard(guard)
        self.assertEqual([call.kwargs["timeout"] for call in guard.wait.call_args_list], [10, 10])
        guard = Mock()
        with patch.object(live.time, "monotonic", side_effect=[0, 241]):
            with self.assertRaises(EnterpriseWazuhError):
                live.await_guard(guard)
        guard.wait.assert_not_called()
