"""Closed 24-hour reliability stage controls with modeled runtimes; no Docker or launch."""

import copy
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from integrations.enterprise import reference_host_controls as host
from integrations.enterprise import reliability_runner as runner
from integrations.enterprise import reliability_services as services
from integrations.enterprise import reliability_wazuh as wazuh
from integrations.enterprise.reference_controls import expected_config, verify_compose_config
from integrations.enterprise.reliability import DAY_MS, INTERRUPTIONS
from integrations.enterprise.reliability_source import WorkloadError
from integrations.enterprise.reliability_workload import SharedClock
from integrations.enterprise.verification import LabControlError
from scripts import enterprise_reference_verify as reference
from scripts import enterprise_reliability_verify as stage

RUN = "a" * 32
IMAGES = {"database": "sha256:" + "d" * 64, "runner": "sha256:" + "e" * 64}
RELIABILITY_IMAGES = {**IMAGES, "wazuh": "sha256:" + "f" * 64}
DIRECTORY = Path(__file__).resolve().parents[1] / "var/enterprise/preparation/closed-reliability"


class ReliabilityRecipeTests(SimpleTestCase):
    def test_actual_offline_compose_output_matches_the_fixed_recipe_and_isolation(self):
        fixture = Path(__file__).resolve().parent / "fixtures/reliability-compose.json"
        value = json.loads(fixture.read_text(encoding="utf8"))
        images = {role: config["image"] for role, config in value["services"].items()}
        verify_compose_config(value, images, RUN, "/reference-proof-profile", profile="reliability")
        self.assertTrue(value["networks"]["reference"]["internal"])
        services = value["services"]
        self.assertTrue(all(services[name]["read_only"] for name in ("database", "runner")))
        self.assertEqual(services["wazuh"]["network_mode"], "none")
        inputs = [
            m for m in services["wazuh"]["volumes"] if m["target"].startswith("/signalbridge")
        ]
        self.assertTrue(inputs and all(m["read_only"] for m in inputs))
        self.assertTrue(all("ports" not in service for service in value["services"].values()))
        with self.assertRaises(LabControlError):
            verify_compose_config(value, images, RUN, "/reference-proof-profile")
        with self.assertRaises(LabControlError):
            verify_compose_config(
                value,
                images,
                RUN,
                "/reference-proof-profile",
                profile="reliability",
                rehearsal_ms=600_000,
            )

    def test_profile_changes_only_runner_limits_command_and_opt_in(self):
        expected = copy.deepcopy(expected_config(IMAGES, RUN, DIRECTORY))
        expected["services"]["runner"].update(
            mem_limit="1610612736", memswap_limit="1610612736", cpus=2, pids_limit=256
        )
        expected["services"]["runner"]["environment"].update(
            SB_RELIABILITY_RUNTIME="1", SB_RELIABILITY_REHEARSAL_MS="0"
        )
        expected["services"]["runner"]["command"] = [
            "python",
            "-B",
            "-m",
            "integrations.enterprise.reliability_runner",
        ]
        expected["services"]["runner"]["volumes"].append(
            {
                "type": "bind",
                "source": DIRECTORY.as_posix() + "/clock",
                "target": "/clock",
                "bind": {},
            }
        )
        expected["services"]["wazuh"] = wazuh.service(RELIABILITY_IMAGES, RUN, DIRECTORY.as_posix())
        from integrations.enterprise.reference_controls import reliability_subnet

        expected["networks"]["reference"]["ipam"] = {
            "config": [{"subnet": reliability_subnet(RUN)}]
        }
        actual = expected_config(RELIABILITY_IMAGES, RUN, DIRECTORY, profile="reliability")
        self.assertEqual(actual, expected)
        with self.assertRaises(LabControlError):
            expected_config(IMAGES, RUN, DIRECTORY, profile="reliability")

    def test_rehearsal_length_is_only_accepted_by_the_reliability_profile(self):
        for profile in ("access", "header"):
            with self.subTest(profile=profile), self.assertRaises(LabControlError):
                expected_config(IMAGES, RUN, DIRECTORY, profile=profile, rehearsal_ms=600_000)
        for value in (-1, 1.5, "600000"):
            with self.subTest(value=value), self.assertRaises(LabControlError):
                expected_config(
                    RELIABILITY_IMAGES, RUN, DIRECTORY, profile="reliability", rehearsal_ms=value
                )

    def test_changed_limits_ports_and_network_are_rejected(self):
        for change in ("memory", "cpus", "port", "network", "command", "manager"):
            value = expected_config(RELIABILITY_IMAGES, RUN, DIRECTORY, profile="reliability")
            target = value["services"]["runner"]
            if change == "memory":
                target["mem_limit"] = str(int(target["mem_limit"]) * 2)
            elif change == "cpus":
                target["cpus"] = 4
            elif change == "port":
                target["ports"] = [{"target": 18841, "published": "18841"}]
            elif change == "network":
                value["networks"]["reference"]["internal"] = False
            elif change == "manager":
                value["services"]["wazuh"]["network_mode"] = "bridge"
            else:
                target["command"] = ["python", "-c", "print('arbitrary')"]
            with self.subTest(change=change), self.assertRaises(LabControlError):
                verify_compose_config(
                    value, RELIABILITY_IMAGES, RUN, DIRECTORY, profile="reliability"
                )

    def test_reliability_network_uses_a_run_derived_benchmark_subnet(self):
        from integrations.enterprise.reference_controls import reliability_subnet

        value = expected_config(RELIABILITY_IMAGES, RUN, DIRECTORY, profile="reliability")
        subnet = value["networks"]["reference"]["ipam"]["config"][0]["subnet"]
        self.assertEqual(subnet, reliability_subnet(RUN))
        self.assertTrue(subnet.startswith(("198.18.", "198.19.")) and subnet.endswith(".0/24"))
        self.assertNotEqual(subnet, reliability_subnet("b" * 32))
        self.assertEqual(
            expected_config(IMAGES, RUN, DIRECTORY)["networks"]["reference"]["ipam"], {}
        )
        with patch.object(
            stage.base, "docker_result", side_effect=["lab", '[{"Subnet":"' + subnet + '"}]']
        ):
            with self.assertRaises(LabControlError):
                stage.subnet_free(Path("docker.exe"), subnet)

    def test_launcher_selects_its_own_recipe(self):
        command = reference.compose_command(
            Path("docker.exe"), RUN, DIRECTORY, profile="reliability"
        )
        self.assertTrue(str(command[-1]).endswith("compose.reliability.yaml"))
        with self.assertRaises(LabControlError):
            reference.compose_command(Path("docker.exe"), RUN, DIRECTORY, profile="arbitrary")


class ReliabilityWatchdogTests(SimpleTestCase):
    def test_only_the_fixed_reliability_ceiling_extends_the_guard(self):
        later = time.time() + host.RELIABILITY_SECONDS - 60
        for maximum in (None, 3600, host.RELIABILITY_SECONDS + 1):
            with self.subTest(maximum=maximum), self.assertRaises(LabControlError):
                host.watchdog(Path("docker.exe"), RUN, DIRECTORY, later, lambda: 0, maximum=maximum)

    def test_disk_guard_is_launch_relative_and_keeps_the_free_floor(self):
        gib = 1024**3
        free = {"value": 60 * gib}
        usage = lambda _path: type("Usage", (), {"free": free["value"]})()  # noqa: E731
        with (
            patch.object(stage, "LAUNCH_FREE_DISK", None),
            patch.object(stage.shutil, "disk_usage", usage),
            patch.object(stage.reference, "available_memory", return_value=16 * gib),
        ):
            self.assertEqual(stage.check_capacity()["free_disk_bytes"], 60 * gib)
            self.assertEqual(stage.LAUNCH_FREE_DISK, 60 * gib)
            free["value"] = 50 * gib
            stage.check_capacity()
            free["value"] = 47 * gib  # 13 GiB grown since launch
            with self.assertRaises(LabControlError):
                stage.check_capacity()
        with (
            patch.object(stage, "LAUNCH_FREE_DISK", None),
            patch.object(
                stage.shutil, "disk_usage", lambda _p: type("U", (), {"free": 30 * gib})()
            ),
            patch.object(stage.reference, "available_memory", return_value=16 * gib),
            self.assertRaises(LabControlError),
        ):
            stage.check_capacity()  # below the 25 GiB floor plus the ceiling
        self.assertEqual(host.RELIABILITY_GROWTH, 12 * gib)

    def test_rehearsal_bounds_are_refused_before_any_docker_or_file_access(self):
        with (
            patch.object(stage, "check_capacity") as capacity,
            patch.object(stage, "keep_awake") as awake,
        ):
            for minutes in (0, 4, 91, 24 * 60):
                with self.subTest(minutes=minutes), self.assertRaises(LabControlError):
                    stage.launch(
                        Path(r"C:\docker.exe"), "approved-1", "b" * 32, Path("python"), minutes
                    )
        capacity.assert_not_called()
        awake.assert_not_called()


class ReliabilityRunnerTests(SimpleTestCase):
    def test_runner_windows_follow_the_declared_profile_and_scale_for_rehearsal(self):
        declared = {name: (start, end) for name, start, end, _ in INTERRUPTIONS}
        rows = runner.windows()
        self.assertEqual({row[3] for row in rows}, set(runner.RUNNER_WINDOWS))
        for at, action, roles, name in rows:
            self.assertEqual(at, declared[name][0 if action == "stop" else 1])
            self.assertEqual(roles, runner.RUNNER_WINDOWS[name])
        short = runner.windows(4_200_000 / DAY_MS)
        self.assertTrue(all(0 < row[0] < 4_200_000 for row in short))
        self.assertEqual([row[1:] for row in short], [row[1:] for row in rows])

    def test_rehearsal_length_environment_is_closed(self):
        for raw, valid in (("0", True), ("4200000", True), ("299999", False), ("5400001", False)):
            with (
                self.subTest(raw=raw),
                patch.dict("os.environ", {"SB_RELIABILITY_REHEARSAL_MS": raw}),
            ):
                if valid:
                    self.assertEqual(runner.rehearsal_ms(), int(raw))
                else:
                    with self.assertRaises(runner.ReliabilityError):
                        runner.rehearsal_ms()
        for raw in ("", "-1", "1e6", "60000000000"):
            with (
                self.subTest(raw=raw),
                patch.dict("os.environ", {"SB_RELIABILITY_REHEARSAL_MS": raw}),
            ):
                with self.assertRaises(runner.ReliabilityError):
                    runner.rehearsal_ms()

    def test_lab_servers_outlive_the_day_only_in_the_reliability_runtime(self):
        from integrations.enterprise import reference_native_server as server

        with patch.dict("os.environ", {"SB_RELIABILITY_RUNTIME": ""}):
            self.assertEqual(server.lifetime(), 360)
        with patch.dict("os.environ", {"SB_RELIABILITY_RUNTIME": "1"}):
            self.assertGreater(server.lifetime(), (DAY_MS + 600_000) // 1000)
            self.assertLessEqual(server.lifetime(), host.RELIABILITY_SECONDS)

    def test_runner_receipts_are_a_closed_inventory(self):
        with self.assertRaises(runner.ReliabilityError):
            runner.write("../outside", {})

    def test_collector_attempt_outcomes_are_closed(self):
        self.assertEqual(services.attempt_result(202, b""), "accepted")
        self.assertEqual(services.attempt_result(200, b""), "duplicate")
        for status in (400, 401, 403, 404, 409, 413, 422):
            self.assertEqual(services.attempt_result(status, b""), "rejected")
        for status in (500, 502, 503, 301, 0):
            self.assertEqual(services.attempt_result(status, b""), "retry")


class SharedClockTests(SimpleTestCase):
    def lab(self, seconds_ahead):
        from integrations.enterprise.lab_clock import LabClock

        lead = int(seconds_ahead * 1e9)
        return LabClock(
            datetime.now(timezone.utc) + timedelta(seconds=seconds_ahead),
            time.monotonic_ns() + lead,
        )

    def test_future_origin_waits_before_the_first_slot(self):
        clock = SharedClock(self.lab(0.3))
        before = time.monotonic()
        clock.wait_until(0, lambda: False)
        self.assertGreaterEqual(time.monotonic() - before, 0.2)
        self.assertGreaterEqual(clock.elapsed_ms(), 0)

    def test_stop_is_honored_while_waiting_for_the_origin(self):
        clock = SharedClock(self.lab(30))
        with self.assertRaises(WorkloadError):
            clock.wait_until(0, lambda: True)

    def test_origin_outside_the_reviewed_lead_or_lag_is_refused(self):
        for seconds in (-121, 121):
            with self.subTest(seconds=seconds), self.assertRaises(WorkloadError):
                SharedClock(self.lab(seconds))

    def test_wall_clock_steps_never_move_the_lab_timeline(self):
        clock = SharedClock(self.lab(-1))
        first = clock.elapsed_ms()
        stepped = datetime.now(timezone.utc) - timedelta(seconds=3)
        with patch("integrations.enterprise.reliability_workload.datetime") as fake:
            fake.now.return_value = stepped
            second = clock.elapsed_ms()
        self.assertGreaterEqual(second, first)
        self.assertGreaterEqual(clock.maximum_drift_ms, 2900)


class LabClockTests(SimpleTestCase):
    def test_clock_file_shape_and_timeline(self):
        from integrations.enterprise.lab_clock import ClockError, parse

        origin = datetime(2026, 10, 4, tzinfo=timezone.utc)
        raw = json.dumps(
            {"run_id": RUN, "origin_utc": origin.isoformat(), "origin_monotonic_ns": 5}
        ).encode()
        _, clock = parse(raw)
        with patch("integrations.enterprise.lab_clock.time.monotonic_ns", return_value=2_000_005):
            self.assertEqual(clock.offset_ms(), 2)
            self.assertEqual(clock.now(), origin + timedelta(milliseconds=2))
        for broken in ({"run_id": RUN, "origin_utc": origin.isoformat()}, {"x": 1}):
            with self.subTest(broken=broken), self.assertRaises(ClockError):
                parse(json.dumps(broken).encode())

    def test_install_points_django_now_at_the_lab_clock_and_is_restorable(self):
        import tempfile

        from django.utils import timezone as django_timezone

        from integrations.enterprise.lab_clock import install

        original = django_timezone.now
        origin = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "clock.json"
            path.write_text(
                json.dumps(
                    {
                        "run_id": RUN,
                        "origin_utc": origin.isoformat(),
                        "origin_monotonic_ns": time.monotonic_ns(),
                    }
                ),
                encoding="ascii",
            )
            try:
                install(path)
                self.assertLess(abs((django_timezone.now() - origin).total_seconds()), 5)
            finally:
                django_timezone.now = original

    def test_wall_timestamps_map_across_drift_and_a_backward_step(self):
        from integrations.enterprise.lab_clock import WallMapping

        # Wall runs 50 ms behind by t=10 s, then steps back by 1.1 s at t=20 s.
        samples = [(t * 1000, t * 1000 - 5 * t) for t in range(0, 20)]
        samples += [(t * 1000, t * 1000 - 5 * t - 1100) for t in range(20, 40)]
        mapping = WallMapping(samples)
        self.assertEqual(mapping.lab_ms(10_000 - 50), 10_000)
        self.assertAlmostEqual(mapping.lab_ms(30_000 - 150 - 1100), 30_000, delta=5)
        # Inside the stepped-over interval the error stays within one step.
        self.assertLessEqual(abs(mapping.lab_ms(19_000) - 19_100), 1200)


class ReliabilityMeasurementTests(SimpleTestCase):
    def evidence(self, root, origin):
        evidence = root / "evidence"
        (root / "clock").mkdir()
        for name in ("reliability-source", "reliability-collector"):
            (evidence / name).mkdir(parents=True)
        event = "0b0e3e64-9b9d-4b38-9a8c-6f0d9d1f2a11"
        key = {"app": "documents", "event_id": event, "digest": "a" * 64}
        rows = {
            "../clock/reliability-clock.json": {
                "run_id": RUN,
                "origin_utc": origin.isoformat(),
                "origin_monotonic_ns": 1,
            },
            "reliability-runner.json": {"run_id": RUN, "completed": False},
        }
        for name, value in rows.items():
            (evidence / name).write_text(json.dumps(value), encoding="ascii")
        lines = {
            "reliability-source/source.jsonl": [{"kind": "source", "slot": 0, "at_ms": 10, **key}],
            "reliability-source/requests.jsonl": [{"kind": "read_started", "slot": 0, "at_ms": 0}],
            "reliability-collector/attempts-000000000000-1.jsonl": [
                {"phase": "start", "start_ms": 20, **key},
                {"phase": "end", "start_ms": 20, "end_ms": 40, "result": "accepted", **key},
            ],
            "reliability-stored.jsonl": [
                {
                    "kind": "stored",
                    "accepted_ms": 35,
                    "processed_ms": 60,
                    "worker": "worker-1",
                    **key,
                }
            ],
        }
        for name, values in lines.items():
            raw = "".join(json.dumps(value) + "\n" for value in values)
            (evidence / name).write_text(raw, encoding="ascii")

    def test_rehearsal_measurement_is_never_a_24_hour_result(self):
        import tempfile

        from integrations.enterprise.reliability_measure import evaluate

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.evidence(root, datetime(2026, 10, 4, tzinfo=timezone.utc))
            result = evaluate(root, rehearsal_ms=600_000)
        self.assertEqual(result["measurement"]["status"], "rehearsal_not_a_24_hour_result")
        self.assertEqual(result["ledger_counts"], {"source": 1, "attempt": 1, "stored": 1})
        self.assertEqual(result["measurement"]["missing_tool_observation"], 1)

    def test_missing_evidence_fails_closed(self):
        import tempfile

        from integrations.enterprise.reliability_measure import evaluate

        with tempfile.TemporaryDirectory() as folder, self.assertRaises(LabControlError):
            evaluate(Path(folder), rehearsal_ms=600_000)


class ReliabilityManagerTests(SimpleTestCase):
    def effective(self):
        """A modeled `docker inspect` of the expected manager container."""
        expected = wazuh.service(RELIABILITY_IMAGES, RUN, DIRECTORY.as_posix())
        return {
            "image": RELIABILITY_IMAGES["wazuh"],
            "memory": 1536 * 1024**2,
            "swap": 1536 * 1024**2,
            "cpu": 10**9,
            "pids": 256,
            "shm": 16777216,
            "init": True,
            "readonly": False,
            "privileged": False,
            "cap_drop": ["ALL"],
            "cap_add": ["CAP_SETUID", "CAP_SETGID", "CAP_SYS_CHROOT"],
            "security": ["no-new-privileges:true"],
            "restart": "no",
            "network_mode": "none",
            "networks": {"none": {}},
            "port_bindings": {},
            "mounts": [
                {
                    "Type": "bind",
                    "Destination": item["target"],
                    "Source": item["source"],
                    "RW": item.get("read_only") is not True,
                }
                for item in expected["volumes"]
            ],
            "user": "0:0",
            "devices": [],
            "pid_mode": "",
            "ipc_mode": "private",
            "cgroup_mode": "private",
            "entrypoint": expected["entrypoint"],
            "command": expected["command"],
            "workdir": "/workspace",
            "environment": ["PATH=/usr/bin"]
            + [k + "=" + v for k, v in expected["environment"].items()],
        }

    def verify(self, data):
        return wazuh.verify_effective(data, RELIABILITY_IMAGES, RUN, DIRECTORY, str)

    def test_stream_identities_are_deterministic_distinct_and_run_bound(self):
        documents, expenses = (wazuh.stream_id(RUN, app) for app in ("documents", "expenses"))
        self.assertEqual(documents, wazuh.stream_id(RUN, "documents"))
        self.assertNotEqual(documents, expenses)
        self.assertNotEqual(documents, wazuh.stream_id("b" * 32, "documents"))
        with self.assertRaises(LabControlError):
            wazuh.stream_id(RUN, "bettail")

    def test_manager_reads_only_the_two_live_streams_and_empty_detection_folders(self):
        sources = wazuh.input_sources(DIRECTORY, RUN)
        self.assertEqual(len(sources), 4)
        for target, source in sources.items():
            app, channel = target.split("/")[-2:]
            if channel == "observation":
                self.assertEqual(source.name, wazuh.stream_id(RUN, app))
                self.assertIn("soc-delivery", source.parts)
            else:
                self.assertEqual(source.parts[-4:], ("wazuh", "idle", app, channel))

    def test_all_monitored_segments_are_precreated_inside_the_run(self):
        files = wazuh.segment_files(DIRECTORY, RUN)
        self.assertEqual(len(set(files)), 32)
        self.assertTrue(all(DIRECTORY in path.parents for path in files))
        names = {path.name for path in files}
        self.assertIn("observations-007.jsonl", names)
        self.assertIn("detections-000.jsonl", names)

    def test_effective_manager_must_match_every_closed_control(self):
        self.assertEqual(self.verify(self.effective())["network"], "none")
        raw_capabilities = ["CAP_SETUID", "CAP_SETGID", "CAP_SYS_CHROOT", "CAP_NET_RAW"]
        changes = {
            "network": ("network_mode", "bridge"),
            "privileged": ("privileged", True),
            "capability": ("cap_add", raw_capabilities),
            "memory": ("memory", 4 * 1024**3),
            "user": ("user", "1000:1000"),
            "command": ("command", ["-c", "pass"]),
            "ports": ("port_bindings", {"1514/tcp": [{"HostPort": "1514"}]}),
        }
        for name, (key, value) in changes.items():
            data = self.effective()
            data[key] = value
            with self.subTest(change=name), self.assertRaises(LabControlError):
                self.verify(data)
        writable = self.effective()
        writable["mounts"][3]["RW"] = True
        extra = self.effective()
        extra["mounts"].append(
            {"Type": "bind", "Destination": "/host", "Source": "C:/Users", "RW": False}
        )
        for name, data in (("writable_input", writable), ("extra_mount", extra)):
            with self.subTest(change=name), self.assertRaises(LabControlError):
                self.verify(data)

    def test_only_reliability_admits_a_manager_runtime(self):
        with (
            patch.object(host, "role", return_value="wazuh"),
            patch.object(host.base, "docker_result") as docker,
        ):
            with self.assertRaises(LabControlError):
                host.verify_runtime(Path("docker.exe"), "c" * 64, RUN, DIRECTORY, IMAGES)
        docker.assert_not_called()

    def test_three_components_are_admitted_only_by_the_reliability_launcher(self):
        targets = ["1" * 64, "2" * 64, "3" * 64]
        with patch.object(stage.base, "docker_result", return_value="\n".join(targets)):
            stage.no_foreign_running(Path("docker.exe"), targets)
            with self.assertRaises(LabControlError):
                stage.no_foreign_running(Path("docker.exe"), targets[:2])
        four = [*targets, "4" * 64]
        with patch.object(stage.base, "docker_result", return_value="\n".join(four)):
            with self.assertRaises(LabControlError):
                stage.no_foreign_running(Path("docker.exe"), four)

    def test_shutdown_count_is_closed(self):
        from integrations.enterprise.reference_host_evidence import validate_shutdown

        now = datetime.now(timezone.utc)
        main = {"run_id": RUN, "shutdown_verified": True, "stopped_component_count": 3}
        independent = {
            "run_id": RUN,
            "shutdown_verified": True,
            "reason": "launcher_finished",
            "stopped_component_count": 3,
            "stopped_at": now.isoformat(),
        }
        window = {"started": now - timedelta(minutes=1), "finished": now + timedelta(minutes=1)}
        result = validate_shutdown(main, independent, RUN, components=3, **window)
        self.assertTrue(result["independent_shutdown_verified"])
        for components in (2, 4):
            with self.subTest(components=components), self.assertRaises(LabControlError):
                validate_shutdown(main, independent, RUN, components=components, **window)


class ContinuousPlanTests(SimpleTestCase):
    def plan(self, scale=1.0):
        return wazuh.window_plan(RUN, scale)

    def test_manager_window_plan_matches_the_declared_profile(self):
        from integrations.wazuh_enterprise.native_continuous_collector import validate_plan

        run_id = str(uuid.UUID(RUN))
        for scale in (1.0, 4_200_000 / DAY_MS):
            raw = json.dumps(self.plan(scale)).encode()
            with self.subTest(scale=scale):
                self.assertEqual(len(validate_plan(raw, run_id)["windows"]), 4)

    def test_changed_or_reordered_windows_are_refused(self):
        from integrations.wazuh_enterprise.contract import EnterpriseWazuhError
        from integrations.wazuh_enterprise.native_continuous_collector import validate_plan

        run_id = str(uuid.UUID(RUN))
        extra = self.plan()
        extra["windows"].append({"component": "workers", "action": "stop", "at_ms": 1})
        reordered = self.plan()
        for window in reordered["windows"]:
            if window["component"] == "wazuh_connector":
                window["at_ms"] = 70_000_000 if window["action"] == "stop" else 60_000_000
        other_run = self.plan()
        other_run["run_id"] = str(uuid.uuid4())
        for value in (extra, reordered, other_run):
            with self.subTest(value=value), self.assertRaises(EnterpriseWazuhError):
                validate_plan(json.dumps(value).encode(), run_id)


class LedgerNativeIdentityTests(SimpleTestCase):
    def test_shared_wazuh_ids_stay_distinct_physical_records(self):
        from integrations.enterprise.reliability_ledger import tool_rows

        origin = datetime(2026, 10, 4, tzinfo=timezone.utc)
        events = [str(uuid.uuid4()) for _ in range(2)]
        sources = {("documents", e): {"digest": "a" * 64, "event_id": e} for e in events}
        archive = [
            {
                "id": "1791011099.1488",
                "timestamp": "2026-10-04T00:00:01.000+0000",
                "data": {"signalbridge": {"app": "documents", "event_id": event}},
            }
            for event in [*events, events[0]]
        ]
        rows = tool_rows(archive, sources, origin)
        self.assertEqual(len({row["native_id"] for row in rows}), 3)
        self.assertEqual([row["event_id"] for row in rows], [*events, events[0]])


class ContinuousHeartbeatTests(SimpleTestCase):
    def test_locked_heartbeat_is_counted_not_fatal_and_writes_are_sparse(self):
        import tempfile

        from integrations.wazuh_enterprise import native_collector as core
        from integrations.wazuh_enterprise import native_continuous_collector as continuous

        collector = object.__new__(continuous.ContinuousCollector)
        collector.report, collector.last_heartbeat, collector.heartbeat_failures = {}, None, 0
        with tempfile.TemporaryDirectory() as folder:
            stale = Path(folder) / "heartbeat-next.json"
            stale.write_text("{}", encoding="ascii")
            with (
                patch.object(core, "EVIDENCE", Path(folder)),
                patch.object(
                    core.NativeCollector, "heartbeat", side_effect=PermissionError()
                ) as write,
            ):
                collector.heartbeat({})
                collector.heartbeat({})
            self.assertFalse(stale.exists())
        self.assertEqual(write.call_count, 1)
        self.assertEqual(collector.report["heartbeat_failures"], 1)


class ContinuousLogDirectoryTests(SimpleTestCase):
    def test_a_day_of_rotated_archives_is_accepted_and_the_bound_still_holds(self):
        import os
        import tempfile

        from integrations.wazuh_enterprise import native_collector as core
        from integrations.wazuh_enterprise import native_continuous_collector as continuous

        with tempfile.TemporaryDirectory() as folder:
            wazuh = Path(folder) / "ossec"
            month = wazuh / "logs/archives/2026/Oct"
            month.mkdir(parents=True)
            for number in range(300):
                (month / f"ossec-archive-04-{number:03}.json.gz").write_bytes(b"x")
            daily = month / "ossec-archive-05.json"
            daily.write_bytes(b"{}\n")
            os.link(daily, wazuh / "logs/archives/archives.json")
            with (
                patch.object(core, "WAZUH", wazuh),
                patch.object(core, "_directory", lambda _p: None),
            ):
                identity = continuous.current_native_file("archive")
                self.assertEqual(identity[1], daily.stat().st_ino)
                with patch.object(continuous, "LOG_DIRECTORY_ENTRIES", 64):
                    with self.assertRaisesMessage(
                        Exception, "native_collector_log_directory_limit"
                    ):
                        continuous.current_native_file("archive")
