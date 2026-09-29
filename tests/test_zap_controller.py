"""Disposable metadata/receipt tests; no Docker daemon or external network."""

import contextlib
import copy
import io
import json
import shutil
import unittest
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from scripts import run_zap_pilot as runner
from scripts import verify_soc_pilot as gate
from scripts.local_backup import safe
from tests.test_soc_pilot import RUN, fixture


def repeat_fixture(state="running"):
    payload = fixture("zap", state)
    names = gate.profile_names("zap-repeat", RUN)
    rename = dict(zip(gate.NAMES["zap"], names, strict=True))
    network = gate.network_name("zap-repeat", RUN)
    for row in payload["containers"]:
        old = row["Name"][1:]
        name = rename[old]
        expected = gate.profiles(RUN)[name]
        row["Name"] = "/" + name
        row["Hostname"] = "signalbridge-zap-target" if old == gate.TARGET else name
        row["HostConfig"]["NetworkMode"] = network
        row["Networks"] = {network: row["Networks"][gate.NETWORK]}
        row["Mounts"] = [
            {
                "Type": "bind",
                "Source": str(source),
                "Destination": destination,
                "RW": writable,
                "Propagation": "rprivate",
            }
            for destination, (source, writable) in expected["mounts"].items()
        ]
    payload["active"] = [rename[name] for name in payload["active"]]
    payload["networks"][0]["Name"] = network
    for row in payload["networks"][0]["Containers"].values():
        row["Name"] = rename[row["Name"]]
    return payload


def failed_report():
    return {
        "schema_version": 1,
        "kind": "signalbridge-zap-synthetic-pilot",
        "target_kind": "synthetic-fixture-not-signalbridge-application",
        "profile": "signalbridge-disposable-web-v1",
        "status": "failed",
        "zap_version": "2.17.0",
        "zap_exit_code": 0,
        "errors": ["unexpected_http_status"],
        "requests": [{"method": "GET", "path": "/", "status": "attempted"}],
        "started_at": "2026-09-25T08:00:01+00:00",
        "finished_at": "2026-09-25T08:01:00+00:00",
    }


def ready_log():
    return json.dumps({"fixture": "ready", "synthetic_only": True, "request_budget": 3})


class ZapRepeatProfileTests(unittest.TestCase):
    def test_snapshot_omits_only_original_interpreter_cache_and_rejects_other_files(self):
        files = {name: "a" * 64 for name in runner.FILES}
        with patch.object(
            gate, "_tree", return_value=files | {"__pycache__/fixture.cpython-314.pyc": "b" * 64}
        ):
            self.assertEqual(runner.package_files(runner.ROOT), files)
            with self.assertRaises(runner.PilotError):
                runner.package_files(runner.ROOT, snapshot=True)
        for extra in ("extra.py", ".env", "__pycache__/injected.py", "__pycache__/nested/code.pyc"):
            with (
                patch.object(gate, "_tree", return_value=files | {extra: "b" * 64}),
                self.assertRaises(runner.PilotError),
            ):
                runner.package_files(runner.ROOT)

    def test_all_states_use_fresh_fixed_profiles_without_mutating_legacy(self):
        original = copy.deepcopy(gate.NAMES)
        for state in gate.STATES:
            self.assertEqual(
                gate.verify_topology(repeat_fixture(state), "zap-repeat", RUN, state=state), []
            )
        self.assertEqual(gate.NAMES, original)
        first = gate.profile_names("zap-repeat", RUN)
        self.assertFalse(set(first) & set(gate.profile_names("zap-repeat", str(uuid.uuid4()))))
        profiles = gate.profiles(RUN)
        self.assertEqual(sum(profiles[n]["memory"] for n in first), 2816 * gate.MIB)
        self.assertEqual(sum(profiles[n]["cpus"] for n in first), 2_000_000_000)

    def test_invalid_run_and_external_profile_cannot_select_resources(self):
        for run in (None, "../other", RUN.upper(), str(uuid.uuid1())):
            with self.subTest(run=run), self.assertRaises(gate.VerificationError):
                gate.profile_names("zap-repeat", run)
        with self.assertRaises(gate.VerificationError):
            gate.profile_names("external", RUN)

    def test_cross_run_mount_network_image_alias_and_port_changes_fail(self):
        mutators = (
            lambda p: p["containers"][0]["Mounts"][0].update(Source=str(runner.ROOT)),
            lambda p: p["networks"][0].update(Name=gate.NETWORK),
            lambda p: p["containers"][0].update(ConfiguredImage="zaproxy/zap-stable:latest"),
            lambda p: p["containers"][1]["Networks"][gate.network_name("zap-repeat", RUN)].update(
                Aliases=["foreign"]
            ),
            lambda p: p["containers"][0]["HostConfig"].update(
                PortBindings={"8080/tcp": [{"HostPort": "8080"}]}
            ),
            lambda p: p["active"].append("another-project"),
        )
        for mutate in mutators:
            payload = repeat_fixture()
            mutate(payload)
            self.assertTrue(gate.verify_topology(payload, "zap-repeat", RUN))

    def test_gather_selects_only_run_owned_names_and_pinned_images(self):
        calls = []

        def inspect(kind, names, template):
            calls.append((kind, names, template))
            return []

        with (
            patch.object(gate.base, "inspect_objects", side_effect=inspect),
            patch.object(gate.base, "docker", return_value=""),
        ):
            gate.gather_topology("zap-repeat", RUN)
        self.assertEqual(calls[0][1], gate.profile_names("zap-repeat", RUN))
        self.assertEqual(calls[1][1], (gate.IMAGES[gate.ZAP], gate.IMAGES[gate.TARGET]))
        self.assertEqual(calls[2][1], (gate.network_name("zap-repeat", RUN),))
        self.assertNotIn(".Config.Env", str(calls))


class ZapResultClassificationTests(unittest.TestCase):
    def classify(self, report=None, raw=None, states=None):
        return runner.classify(
            report or failed_report(),
            raw,
            [datetime(2026, 9, 25, 8, n, tzinfo=timezone.utc) for n in (0, 0, 2)],
            states
            or [
                {"status": "exited", "exit_code": 1, "oom": False},
                {"status": "exited", "exit_code": 137, "oom": False},
            ],
            ready_log(),
            unavailable=True,
        )

    def test_expected_outage_never_becomes_successful_scan_or_coverage(self):
        result = self.classify()
        self.assertTrue(result["exercise_verified"])
        self.assertEqual(
            (result["scan_status"], result["coverage"], result["counts"]),
            ("failed", "incomplete", None),
        )

    def test_unrelated_failure_or_forged_success_cannot_verify_outage(self):
        for changed in (
            {"errors": ["zap_startup_timeout"]},
            {"status": "passed"},
            {"controls": {}},
            {"report_sha256": "a" * 64},
            {"requests": []},
            {"zap_exit_code": 137},
            {"profile": "foreign"},
        ):
            report = failed_report() | changed
            with self.subTest(changed=changed), self.assertRaises(runner.PilotError):
                self.classify(report)
        with self.assertRaises(runner.PilotError):
            self.classify(raw=b"{}")

    def test_oom_running_or_timeout_is_not_expected_outage(self):
        for changed in ({"status": "running"}, {"oom": True}, {"exit_code": 0}):
            states = [
                {"status": "exited", "exit_code": 1, "oom": False} | changed,
                {"status": "exited", "exit_code": 137, "oom": False},
            ]
            with self.subTest(changed=changed), self.assertRaises(runner.PilotError):
                self.classify(states=states)
        with self.assertRaises(runner.PilotError):
            self.classify(failed_report() | {"finished_at": "2026-09-25T09:00:00+00:00"})

    def test_success_requires_actual_report_validator_and_both_stopped(self):
        log = (
            ready_log()
            + "\n"
            + "\n".join(json.dumps({"request_ordinal": n, "accepted": True}) for n in (1, 2, 3))
        )
        with patch.object(
            runner, "zap_result", return_value=("2.17.0", {"requests": 3})
        ) as validate:
            result = runner.classify(
                {"sentinel": True},
                b"bounded report",
                [],
                [{"status": "exited", "exit_code": 0, "oom": False}] * 2,
                log,
            )
        validate.assert_called_once_with({"sentinel": True}, b"bounded report", [])
        self.assertEqual(result["scan_status"], "passed")
        self.assertEqual(result["target_accepted"], 3)

    def test_target_accounting_rejects_duplicates_missing_entries_and_boolean_aliases(self):
        for log in (
            "",
            ready_log() + "\n" + ready_log(),
            ready_log().replace("true", "1"),
            "x" * 4097,
        ):
            with self.subTest(log=log[:20]), self.assertRaises((runner.PilotError, ValueError)):
                runner.fixture_log(log, unavailable=True)
        with self.assertRaises(runner.PilotError):
            runner.fixture_log(ready_log())


class ZapControllerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.parent = runner.ROOT / "artifacts/local"
        self.root = self.parent / ("zap-controller-" + uuid.uuid4().hex)
        (self.root / "var/soc/pilot").mkdir(parents=True)
        self.addCleanup(self.cleanup)
        self.lock = self.root / "var/soc/zap-pilot.lock"

    def cleanup(self):
        safe(self.parent, self.root, directory=True)
        for child in self.root.rglob("*"):
            safe(self.root, child, directory=child.is_dir())
        shutil.rmtree(self.root)

    def invoke(self, action, argv=()):
        with (
            patch.object(runner, "ROOT", self.root),
            patch.object(runner.sys, "argv", ["runner", *argv]),
            patch.object(runner, "execute", side_effect=action) as execute,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = runner.main()
        return result, execute.call_count

    def test_existing_lock_preserved_without_execution(self):
        self.lock.write_bytes(b"original")
        self.assertEqual(self.invoke(lambda *a, **k: 0), (1, 0))
        self.assertEqual(self.lock.read_bytes(), b"original")

    def test_failed_attempt_retains_lock_verified_exercise_releases_only_own(self):
        self.assertEqual(self.invoke(lambda *a, **k: 1), (1, 1))
        self.assertTrue(self.lock.exists())
        self.lock.unlink()  # Disposable mocked attempt, no native execution.
        self.assertEqual(self.invoke(lambda *a, **k: 0, ("--unavailable-target",)), (0, 1))
        self.assertFalse(self.lock.exists())

    def test_changed_lock_and_exception_preserve_evidence(self):
        def change(*a, **k):
            self.lock.write_bytes(b"different")
            return 0

        self.assertEqual(self.invoke(change), (1, 1))
        self.assertEqual(self.lock.read_bytes(), b"different")
        self.lock.unlink()

        def fail(*a, **k):
            raise RuntimeError("private diagnostic")

        self.assertEqual(self.invoke(fail), (1, 1))
        self.assertTrue(self.lock.exists())

    def test_disk_floor_and_growth_are_checked_without_native_changes(self):
        for free, initial in (
            (runner.FREE_FLOOR - 1, runner.FREE_FLOOR),
            (runner.FREE_FLOOR, runner.FREE_FLOOR + runner.GROWTH + 1),
        ):
            with (
                patch.object(runner.shutil, "disk_usage", return_value=SimpleNamespace(free=free)),
                self.assertRaises(runner.PilotError),
            ):
                runner.capacity(initial)

    def test_existing_workload_stops_before_native_creation(self):
        with (
            patch.object(runner, "capacity", return_value=runner.FREE_FLOOR),
            patch.object(runner, "docker", return_value="existing") as native,
        ):
            with self.assertRaisesRegex(runner.PilotError, "another_container_active"):
                runner.execute(RUN)
        native.assert_called_once_with("ps", "-q")

    def test_creation_cannot_pull_publish_restart_or_mount_other_source(self):
        directory = runner.ROOT / "var/soc/pilot" / RUN
        with patch.object(runner, "safe"):
            args = runner.create_args(RUN, gate.profile_names("zap-repeat", RUN)[0], directory)
        self.assertIn("--pull=never", args)
        self.assertIn("--read-only", args)
        self.assertIn("--restart=no", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertNotIn("--publish", args)
        self.assertNotIn("--env", args)
        mounts = [args[i + 1] for i, item in enumerate(args) if item == "--mount"]
        self.assertEqual(len(mounts), 2)
        self.assertTrue(any("dst=/pilot,readonly" in item for item in mounts))
        with self.assertRaises(runner.PilotError):
            runner.create_args(RUN, "other-project", directory)

    def test_owned_id_checks_run_label_and_never_recovers_by_name(self):
        directory = self.root / "var/soc/pilot" / RUN
        directory.mkdir()
        cid = "a" * 64
        (directory / "scanner.cid").write_text(cid)
        name = gate.profile_names("zap-repeat", RUN)[0]
        with (
            patch.object(runner, "ROOT", self.root),
            patch.object(
                runner,
                "docker",
                return_value=json.dumps({"id": cid, "name": "/" + name, "run": "different"}),
            ) as native,
        ):
            with self.assertRaisesRegex(runner.PilotError, "owned_identity_changed"):
                runner.owned_id(RUN, name, directory)
        self.assertEqual(native.call_args.args[:2], ("inspect", cid))

    def test_cleanup_stops_immutable_id_and_falls_back_to_kill(self):
        cid = "b" * 64
        with (
            patch.object(
                runner, "state", side_effect=[{"status": "running"}, {"status": "exited"}]
            ),
            patch.object(
                runner, "docker", side_effect=[gate.VerificationError("timeout"), ""]
            ) as native,
        ):
            runner.stop_owned(cid)
        self.assertEqual(native.call_args_list[0].args, ("stop", "--timeout", "3", cid))
        self.assertEqual(native.call_args_list[1].args, ("kill", cid))

    def test_already_stopped_resources_are_not_restarted_or_removed(self):
        with (
            patch.object(runner, "state", return_value={"status": "exited"}),
            patch.object(runner, "docker") as native,
        ):
            runner.stop_owned("a" * 64)
        native.assert_not_called()
