"""Offline filesystem/control tests; native observations are explicitly modeled."""

import copy
import hashlib
import shutil
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, call, patch

from django.test import SimpleTestCase
from django.utils import timezone

from bridge.contract import canonical, digest, parse_json, timestamp
from integrations.enterprise import verification as base
from integrations.wazuh_enterprise import collector_host_controls as host
from integrations.wazuh_enterprise import native_collector as core
from integrations.wazuh_enterprise import ready_publisher as publisher
from integrations.wazuh_enterprise.collector_profile import INTERNAL_OPTIONS
from integrations.wazuh_enterprise.contract import EnterpriseWazuhError
from integrations.wazuh_enterprise.native_live_collector import KIND, SOURCE_FILES, LiveCollector
from integrations.wazuh_enterprise.native_reconciliation import expected_exports
from scripts import enterprise_wazuh_live_verify as live
from scripts import enterprise_wazuh_verify as retained
from tests import test_wazuh_host_controller as modeled_host
from tests import test_wazuh_ready_publisher as modeled_publisher


class LiveCollectorTests(SimpleTestCase):
    def setUp(self):
        modeled_publisher.ReadyPublisherTests.setUp(self)
        # Defense in depth: accidental unmocked Docker/process calls fail
        # immediately, even when a future test changes a controller branch.
        for target, name in ((base, "docker_result"), (live.subprocess, "Popen")):
            barrier = patch.object(
                target, name, side_effect=AssertionError("Offline test forbids native execution")
            )
            barrier.start()
            self.addCleanup(barrier.stop)
        self.image = {
            "id": "sha256:" + "a" * 64,
            "os": "linux",
            "architecture": "amd64",
            "digests": [host.IMAGE],
            "environment": ["PATH=/usr/bin:/bin"],
            "volumes": None,
        }
        self.identifier = "b" * 64
        self.evidence = self.directory / "evidence"
        self.evidence.mkdir()

    def stage_readiness(self):
        raw = canonical(self.state) + b"\n"
        ready = publisher.empty_readiness(self.plan, raw, observed_at=timezone.now())
        for name, value in (
            ("kernel-observed.json", canonical(modeled_host.kernel()) + b"\n"),
            ("effective-config.xml", publisher.delivery_configuration(self.plan)),
            ("effective-internal-options.conf", INTERNAL_OPTIONS),
            ("collector-ready-state.json", raw),
            ("collector-ready.json", canonical(ready) + b"\n"),
        ):
            (self.evidence / name).write_bytes(value)
        return ready

    def test_new_profile_preserves_resource_controls_but_cannot_match_old_runtime(self):
        observed = modeled_host.WazuhHostControllerTests.runtime(self, self.directory)
        with self.assertRaises(EnterpriseWazuhError):
            host.validate_runtime(observed, self.image, self.run, self.directory, publication=True)
        args = host.create_arguments(self.image, self.run, self.directory, publication=True)
        self.assertIn("org.signalbridge.enterprise.scope=wazuh-ready-publication", args)
        self.assertEqual(args[-1], "integrations.wazuh_enterprise.native_live_collector")
        self.assertEqual(args[args.index("--memory") + 1], str(host.MEMORY))
        self.assertEqual(args[args.index("--network") + 1], "none")
        observed["command"] = args[-3:]
        self.assertTrue(
            host.validate_runtime(observed, self.image, self.run, self.directory, publication=True)[
                "effective_runtime_verified"
            ]
        )
        with self.assertRaises(EnterpriseWazuhError):
            host.validate_runtime(observed, self.image, self.run, self.directory)
        observed["mounts"][2]["RW"] = True
        with self.assertRaises(EnterpriseWazuhError):
            host.validate_runtime(observed, self.image, self.run, self.directory, publication=True)

    def test_preparation_keeps_monitored_files_empty_and_freezes_separate_expectations(self):
        # Only synthetic scratch input and reviewed source files are copied.
        source = Path(__file__).resolve().parents[1]
        workspace = source / "var" / ("wp-" + uuid.uuid4().hex[:8])
        workspace.mkdir()
        self.assertTrue(workspace.resolve().is_relative_to((source / "var").resolve()))
        self.addCleanup(shutil.rmtree, workspace)
        for name in SOURCE_FILES:
            if name.startswith("delivery/"):
                continue
            target = workspace / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((source / name).read_bytes())
        snapshot = workspace / "snapshot"
        shutil.copytree(self.frozen, snapshot / "input")
        expected = expected_exports(self.frozen, self.manifest)
        run = uuid.uuid4().hex
        directory = base.private_run_directory(workspace, run)
        directory.mkdir(parents=True)
        with patch.object(live, "ROOT", workspace), patch.object(live, "private_acl"):
            context, plan = live.prepare(run, directory, snapshot, self.manifest, expected)
        self.assertEqual(
            set(parse_json((directory / "evidence/source-manifest.json").read_bytes())["files"]),
            set(SOURCE_FILES),
        )
        self.assertEqual(
            expected_exports(directory / "source/delivery/frozen-input", self.manifest), expected
        )
        for row in plan["files"]:
            self.assertEqual((directory / "input" / row["relative"]).read_bytes(), b"")
        self.assertEqual(context["run_id"], str(uuid.UUID(run)))
        self.assertFalse(plan["native_execution_verified"])

    def test_native_ready_handshake_publishes_exact_bytes_and_retains_false_attestation_flags(self):
        ready = self.stage_readiness()
        with patch.object(live, "ROOT", self.workspace):
            result = live.publish_ready(self.run, self.directory, self.plan)
        self.assertEqual(result["published_records"], 2)
        self.assertFalse(result["native_execution_verified"])
        self.assertFalse(result["tool_receipt_verified"])
        proof = publisher.validate_recorded_publication(self.directory, self.plan)
        self.assertEqual(proof["readiness_sha256"], live.digest(ready))
        altered = parse_json((self.evidence / "publication-complete.json").read_bytes())
        altered["run_id"] = uuid.uuid4().hex
        (self.evidence / "publication-complete.json").write_bytes(canonical(altered))
        with self.assertRaises(EnterpriseWazuhError):
            publisher.validate_recorded_publication(self.directory, self.plan)

    def test_output_validator_recomputes_recorded_publication_and_rejects_tampered_artifacts(self):
        # Reuse modeled native logs and a real sealed capture journal. No
        # controller, daemon, process or runtime API is called by this fixture.
        fixture = modeled_host.WazuhHostControllerTests()
        fixture.setUp()
        # Keep nested retained-source paths within Windows' path length limit.
        workspace = live.ROOT / "var" / ("wv-" + uuid.uuid4().hex[:8])
        workspace.mkdir()
        self.assertTrue(workspace.resolve().is_relative_to((live.ROOT / "var").resolve()))
        self.addCleanup(shutil.rmtree, workspace)
        with self.settings(BASE_DIR=workspace, LOCAL=True):
            directory = base.private_run_directory(workspace, fixture.run)
            directory.mkdir(parents=True)
            context, values, _native = fixture.output(directory)
            inputs, frozen = directory / "input", directory / "frozen-input"
            self.assertTrue(inputs.resolve().is_relative_to(workspace.resolve()))
            self.assertTrue(frozen.parent.resolve().is_relative_to(workspace.resolve()))
            self.assertFalse(frozen.exists())
            inputs.rename(frozen)
            plan = publisher.prepare(
                workspace,
                fixture.run,
                values["manifest.json"],
                now=timestamp(context["prepared_at"]),
            )
            for app in ("documents", "expenses"):
                for channel in ("observation", "detection"):
                    (inputs / app / channel).mkdir(parents=True, exist_ok=True)
            observed = fixture.now - timedelta(seconds=1)
            raw_state = (
                canonical(
                    {
                        "global": {
                            "files": [
                                {
                                    "location": row["location"],
                                    "events": 0,
                                    "bytes": 0,
                                    "targets": [{"name": "agent", "drops": 0}],
                                }
                                for row in plan["files"]
                            ]
                        },
                        "interval": {"files": []},
                    }
                )
                + b"\n"
            )
            ready = publisher.empty_readiness(plan, raw_state, observed_at=observed)
            publisher.publish(workspace, fixture.run, ready, raw_state, now=observed)
            evidence = directory / "evidence"
            (evidence / "collector-ready-state.json").write_bytes(raw_state)
            (evidence / "collector-ready.json").write_bytes(canonical(ready) + b"\n")
            (evidence / "publication-complete.json").write_bytes(
                (directory / "publisher/publication-finished.json").read_bytes()
            )
            generated = {
                "delivery/plan.json": canonical(plan) + b"\n",
                "delivery/manager-lab.conf": publisher.delivery_configuration(plan),
            }
            sources = {}
            for name in SOURCE_FILES:
                raw = generated[name] if name in generated else (live.ROOT / name).read_bytes()
                path = directory / "source" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                sources[name] = hashlib.sha256(raw).hexdigest()
            shutil.copytree(frozen, directory / "source/delivery/frozen-input")
            context["source_sha256"] = digest(sources)
            raw_context = canonical(context) + b"\n"
            (evidence / "run-context.json").write_bytes(raw_context)
            (evidence / "source-manifest.json").write_bytes(canonical({"files": sources}))
            (evidence / "effective-config.xml").write_bytes(generated["delivery/manager-lab.conf"])
            handshake = publisher.validate_recorded_publication(directory, plan)
            report = parse_json(values["native-report.json"])
            report.update(
                kind=KIND,
                context_sha256=hashlib.sha256(raw_context).hexdigest(),
                source_sha256=context["source_sha256"],
                configuration_sha256=hashlib.sha256(
                    generated["delivery/manager-lab.conf"]
                ).hexdigest(),
                **handshake,
            )
            (evidence / "native-report.json").write_bytes(canonical(report))
            proof = retained.validate_output(
                directory, context, now=fixture.now, publication_plan=plan
            )
            self.assertTrue(proof["coverage"]["bootstrap_counts_match"])
            self.assertTrue(proof["durable_capture_revalidated"])
            self.assertFalse(proof["native_runtime_execution_verified"])
            self.assertFalse(proof["continuous_delivery_verified"])
            for name, invalid in (
                ("collector-ready-state.json", raw_state.replace(b'"events":0', b'"events":1')),
                ("publication-complete.json", canonical({})),
                ("native-report.json", canonical({**report, "readiness_sha256": "0" * 64})),
                (
                    "native-report.json",
                    canonical({**report, "native_runtime_execution_verified": True}),
                ),
            ):
                path = evidence / name
                original = path.read_bytes()
                path.write_bytes(invalid)
                with self.subTest(name=name), self.assertRaises(EnterpriseWazuhError):
                    retained.validate_output(
                        directory, context, now=fixture.now, publication_plan=plan
                    )
                path.write_bytes(original)

    def test_missing_native_file_or_changed_configuration_never_publishes(self):
        self.stage_readiness()
        original = (self.evidence / "collector-ready-state.json").read_bytes()
        changed = copy.deepcopy(self.state)
        changed["global"]["files"].pop()
        (self.evidence / "collector-ready-state.json").write_bytes(canonical(changed) + b"\n")
        with patch.object(live, "ROOT", self.workspace), self.assertRaises(EnterpriseWazuhError):
            live.publish_ready(self.run, self.directory, self.plan)
        self.assertFalse((self.directory / "publisher/publication-start.json").exists())
        (self.evidence / "collector-ready-state.json").write_bytes(original)
        (self.evidence / "effective-config.xml").write_bytes(b"<ossec_config/>")
        with patch.object(live, "ROOT", self.workspace), self.assertRaises(EnterpriseWazuhError):
            live.publish_ready(self.run, self.directory, self.plan)
        self.assertTrue(
            all(
                (self.directory / "input" / row["relative"]).stat().st_size == 0
                for row in self.plan["files"]
            )
        )

    def test_partial_publication_has_no_completion_then_exact_prefix_resumes_without_replay(self):
        self.stage_readiness()
        actual = publisher._append
        calls = 0

        def interrupted(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("modeled host interruption after complete record")
            return actual(*args, **kwargs)

        with (
            patch.object(live, "ROOT", self.workspace),
            patch.object(publisher, "_append", side_effect=interrupted),
            self.assertRaises(OSError),
        ):
            live.publish_ready(self.run, self.directory, self.plan)
        self.assertFalse((self.evidence / "publication-complete.json").exists())
        with patch.object(live, "ROOT", self.workspace):
            result = live.publish_ready(self.run, self.directory, self.plan)
        self.assertGreater(result["existing_prefix_bytes"], 0)
        self.assertEqual(
            result["existing_prefix_bytes"] + result["appended_bytes_this_call"],
            result["published_bytes"],
        )
        publisher.validate_recorded_publication(self.directory, self.plan)

    def test_dead_watchdog_prevents_container_creation(self):
        with (
            patch.object(live, "private_acl"),
            patch.object(live, "check_capacity"),
            patch.object(
                live, "require_guard", side_effect=base.LabControlError("modeled dead guard")
            ),
            patch.object(host, "request") as docker,
        ):
            with self.assertRaises(base.LabControlError):
                live.execute("modeled", self.run, self.directory, self.image, object(), self.plan)
        docker.assert_not_called()

    def test_private_acl_verify_failure_before_start_has_fixed_phase_and_never_starts(self):
        diagnostics = live.PhaseDiagnostics()
        private = "synthetic-private-stderr-token-and-path"
        with (
            patch.object(live, "private_acl", side_effect=[None, OSError(private)]),
            patch.object(live, "check_capacity"),
            patch.object(live, "require_guard"),
            patch.object(live, "admission"),
            patch.object(host, "owned", side_effect=[[], [self.identifier]]),
            patch.object(host, "verify_runtime"),
            patch.object(host, "request", side_effect=[self.identifier, "created"]) as request,
            self.assertRaises(OSError),
        ):
            live.execute(
                "modeled",
                self.run,
                self.directory,
                self.image,
                object(),
                self.plan,
                diagnostics=diagnostics,
            )
        self.assertEqual([row.args[3][0] for row in request.call_args_list], ["create", "inspect"])
        self.assertEqual(
            diagnostics.snapshot(),
            {
                "phase": "execute_private_acl_before_start",
                "code": "collector_private_acl_failed",
                "acl_mode": "Verify",
            },
        )
        self.assertNotIn(private.encode(), canonical(diagnostics.snapshot()))

    def test_unknown_diagnostic_phase_is_rejected_without_echoing_private_input(self):
        diagnostics = live.PhaseDiagnostics()
        with self.assertRaisesMessage(EnterpriseWazuhError, "collector_diagnostic_phase"):
            diagnostics.enter("synthetic-private-path-and-token")
        self.assertEqual(diagnostics.snapshot()["phase"], "preparation")

    def test_native_handshake_waits_for_complete_host_ack_before_reading_input(self):
        state = self.workspace / "modeled-wazuh-logcollector.state"
        state.write_bytes(canonical(self.state) + b"\n")
        for app in ("documents", "expenses"):
            for channel in ("observation", "detection"):
                (self.directory / "input" / app / channel).mkdir(parents=True, exist_ok=True)
        pilot = LiveCollector()
        pilot.plan, pilot.raw_manifest = self.plan, self.manifest
        pilot.expected = expected_exports(self.frozen, self.manifest)
        pilot.evidence_bound = True

        def host_reply(_seconds):
            ready = parse_json((self.evidence / "collector-ready.json").read_bytes())
            raw = (self.evidence / "collector-ready-state.json").read_bytes()
            publisher.publish(self.workspace, self.run, ready, raw)
            (self.evidence / "publication-complete.json").write_bytes(
                (self.directory / "publisher/publication-finished.json").read_bytes()
            )

        with (
            patch.object(core, "EVIDENCE", self.evidence),
            patch.object(core, "INPUT", self.directory / "input"),
            patch.object(core.base, "COLLECTOR_STATE", state),
            patch.object(pilot, "check_budget"),
            patch.object(core.time, "sleep", side_effect=host_reply),
        ):
            pilot.on_started()
        self.assertIn("readiness_sha256", pilot.report)
        self.assertIn("publication_sha256", pilot.report)
        self.assertFalse(pilot.report["native_runtime_execution_verified"])

    def test_failed_execution_keeps_incomplete_receipt_and_stops_only_new_scope_twice(self):
        run = uuid.uuid4().hex
        directory = base.private_run_directory(self.workspace, run)
        docker = self.workspace / "modeled-docker-executable"
        docker.write_bytes(b"non-executable synthetic fixture")
        guard = Mock()
        guard.poll.return_value = None

        def arm(*args):
            (directory / "watchdog-ready.json").write_bytes(
                canonical({"run_id": run, "armed": True})
            )
            return guard

        def finish(*args, **kwargs):
            (directory / "watchdog.json").write_bytes(
                canonical(
                    {
                        "run_id": run,
                        "shutdown_verified": True,
                        "reason": "launcher_finished",
                        "stopped_component_count": 1,
                        "late_operation_drain_seconds": 60,
                        "late_operation_drain_elapsed_ms": 60000,
                        "late_operation_drain_verified": True,
                        "stopped_at": timezone.now().isoformat(),
                    }
                )
            )

        guard.wait.side_effect = finish
        with (
            patch.object(live, "ROOT", self.workspace),
            patch.object(live, "private_acl"),
            patch.object(live, "check_capacity", return_value={}),
            patch.object(live, "no_foreign_running"),
            patch.object(
                live,
                "load_binding",
                return_value=(self.workspace, self.manifest, {}, {"modeled": True}),
            ),
            patch.object(live, "prepare", return_value=({}, self.plan)),
            patch.object(live.uuid, "uuid4", return_value=uuid.UUID(run)),
            patch.object(host, "inspect_image", return_value=self.image),
            patch.object(live, "arm_guard", side_effect=arm),
            patch.object(live, "execute", side_effect=OSError("modeled failed publication")),
            patch.object(host, "stop_scope", return_value=1) as stop,
        ):
            _, passed = live.launch(
                docker, "modeled-authorization-not-a-native-run", self.run, self.run
            )
        stop.assert_called_once_with(docker, run, self.workspace, publication=True)
        receipt = parse_json((directory / "receipt.json").read_bytes())
        self.assertFalse(passed)
        self.assertFalse(receipt["native_runtime_execution_verified"])
        self.assertEqual(receipt["status"], "incomplete")
        self.assertEqual(
            receipt["failure_diagnostic"],
            {"phase": "execution", "code": "collector_phase_failed"},
        )
        self.assertTrue(receipt["main_shutdown_verified"])
        self.assertTrue(receipt["independent_shutdown_verified"])

    def test_secure_empty_failure_retains_only_fixed_diagnostics_before_child_directories(self):
        run = uuid.uuid4().hex
        directory = base.private_run_directory(self.workspace, run)
        docker = self.workspace / "modeled-docker-executable"
        docker.write_bytes(b"non-executable synthetic fixture")
        private = "synthetic-private-exception-stderr-token-and-path"
        private_failure = type(private, (base.LabControlError,), {})

        def acl(identity, mode):
            if identity == self.run and mode == "Verify":
                return None
            self.assertEqual((identity, mode), (run, "SecureEmpty"))
            self.assertEqual(list(directory.iterdir()), [])
            raise private_failure(private)

        with (
            patch.object(live, "ROOT", self.workspace),
            patch.object(live, "private_acl", side_effect=acl) as private_acl,
            patch.object(live, "check_capacity", return_value={}),
            patch.object(live, "no_foreign_running"),
            patch.object(
                live,
                "load_binding",
                return_value=(self.workspace, self.manifest, {}, {"modeled": True}),
            ),
            patch.object(live.uuid, "uuid4", return_value=uuid.UUID(run)),
            patch.object(live.policy, "capture") as capture,
            patch.object(host, "inspect_image") as image,
            patch.object(live, "arm_guard") as guard,
            patch.object(live, "execute") as execute,
            patch.object(host, "request") as request,
            patch.object(host, "stop_scope", side_effect=private_failure(private)) as stop,
        ):
            _, passed = live.launch(
                docker, "modeled-authorization-not-a-native-run", self.run, self.run
            )
        self.assertEqual(
            private_acl.call_args_list, [call(self.run, "Verify"), call(run, "SecureEmpty")]
        )
        stop.assert_called_once_with(docker, run, self.workspace, publication=True)
        for blocked in (capture, image, guard, execute, request):
            blocked.assert_not_called()
        raw = (directory / "receipt.json").read_bytes()
        receipt = parse_json(raw)
        self.assertFalse(passed)
        self.assertEqual({path.name for path in directory.iterdir()}, {"receipt.json"})
        self.assertEqual(receipt["status"], "incomplete")
        self.assertFalse(receipt["acceptance_passed"])
        self.assertFalse(receipt["native_runtime_execution_verified"])
        self.assertEqual(receipt["error_class"], "LabControlError")
        self.assertEqual(receipt["main_shutdown"]["shutdown_error_class"], "LabControlError")
        self.assertFalse(receipt["main_shutdown"]["shutdown_verified"])
        self.assertNotIn("independent_shutdown", receipt)
        self.assertEqual(
            receipt["failure_diagnostic"],
            {
                "phase": "prepare_private_acl",
                "code": "collector_private_acl_failed",
                "acl_mode": "SecureEmpty",
            },
        )
        self.assertEqual(
            receipt["main_shutdown_failure_diagnostic"],
            {"phase": "main_shutdown", "code": "collector_phase_failed"},
        )
        self.assertNotIn(private.encode(), raw)

    def test_native_completion_needs_matching_observations_and_quiet_drain_interval(self):
        pilot = LiveCollector()
        with patch.object(core.time, "monotonic", side_effect=[10, 10, 11, 12]):
            self.assertFalse(pilot.collection_complete({"bootstrap_counts_match": False}))
            self.assertFalse(pilot.collection_complete({"bootstrap_counts_match": True}))
            self.assertFalse(pilot.collection_complete({"bootstrap_counts_match": True}))
            self.assertTrue(pilot.collection_complete({"bootstrap_counts_match": True}))
