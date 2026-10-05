"""Real scratch artifacts and modeled host/kernel facts; never native execution."""

import copy
import hashlib
import json
import time
import uuid
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase
from django.utils import timezone

from bridge.contract import canonical, digest
from integrations.enterprise import verification as base
from integrations.wazuh_enterprise import collector_host_controls as host
from integrations.wazuh_enterprise.capture_journal import EMPTY, CaptureJournal
from integrations.wazuh_enterprise.collector_kernel import verify_kernel
from integrations.wazuh_enterprise.collector_profile import INTERNAL_OPTIONS, configuration
from integrations.wazuh_enterprise.collector_source_binding import bind_expected, load_snapshot
from integrations.wazuh_enterprise.contract import EnterpriseWazuhError
from integrations.wazuh_enterprise.export_snapshot import EMPTY_SHA256, inspect_exports
from integrations.wazuh_enterprise.native_collector import SOURCE_FILES
from integrations.wazuh_enterprise.native_reconciliation import reconcile
from scripts import enterprise_wazuh_verify as launcher
from tests import test_wazuh_native_bootstrap as modeled
from tests.test_soc_delivery import disposable_root


@contextmanager
def scratch(test):
    # Existing helper owns the resolved workspace root and registers cleanup.
    yield disposable_root(test)


def kernel():
    status = "\n".join(
        f"{k}:\t{v}"
        for k, v in {
            "Uid": "0 0 0 0",
            "Gid": "0 0 0 0",
            "Groups": "0",
            "CapInh": "0000000000000000",
            "CapPrm": "00000000000400c0",
            "CapEff": "00000000000400c0",
            "CapBnd": "00000000000400c0",
            "CapAmb": "0000000000000000",
            "NoNewPrivs": "1",
            "Seccomp": "2",
        }.items()
    )
    paths = {
        "/": "rw",
        "/workspace": "ro",
        "/evidence": "rw",
        **{
            f"/signalbridge/input/{app}/{channel}": "ro"
            for app in ("documents", "expenses")
            for channel in ("observation", "detection")
        },
    }
    return {
        "status": status,
        "cgroups": {
            "memory.max": str(host.MEMORY),
            "memory.swap.max": "0",
            "pids.max": "256",
            "cpu.max": "100000 100000",
        },
        "mountinfo": "\n".join(
            f"1 2 0:1 / {name} {mode} - ext4 device {mode}" for name, mode in paths.items()
        ),
        "interfaces": ["lo"],
    }


class WazuhHostControllerTests(SimpleTestCase):
    def test_retired_snapshot_launcher_refuses_before_any_preparation_or_docker_access(self):
        with (
            patch.object(launcher, "prepare") as source,
            patch.object(host, "request") as docker,
            patch.object(launcher.subprocess, "Popen") as process,
        ):
            with self.assertRaisesMessage(base.LabControlError, "launcher is retired"):
                launcher.launch(None, "prior-approval-is-not-a-new-attempt", None, None)
            self.assertFalse(hasattr(launcher, "_retained_snapshot_launch"))
            source.assert_not_called()
            docker.assert_not_called()
            process.assert_not_called()

    def setUp(self):
        self.run = uuid.uuid4().hex
        self.now = timezone.now()
        self.image = {
            "id": "sha256:" + "a" * 64,
            "os": "linux",
            "architecture": "amd64",
            "digests": [host.IMAGE],
            "environment": ["PATH=/usr/bin:/bin"],
            "volumes": None,
        }
        self.identifier = "b" * 64

    def runtime(self, directory):
        return {
            "image": self.image["id"],
            "memory": host.MEMORY,
            "swap": host.MEMORY,
            "cpu": 1000000000,
            "pids": 256,
            "readonly": False,
            "privileged": False,
            "cap_drop": ["ALL"],
            "cap_add": ["SETGID", "SETUID", "SYS_CHROOT"],
            "security": ["no-new-privileges:true"],
            "restart": "no",
            "user": "0:0",
            "pid_mode": "",
            "ipc_mode": "private",
            "uts_mode": "",
            "cgroup_mode": "private",
            "log": {"Type": "json-file", "Config": {"max-size": "2m", "max-file": "2"}},
            "command": ["-B", "-m", "integrations.wazuh_enterprise.native_collector"],
            "entrypoint": ["/var/ossec/framework/python/bin/python3"],
            "workdir": "/workspace",
            "network_mode": "none",
            "init": True,
            "shm": 16777216,
            "devices": None,
            "device_requests": None,
            "port_bindings": {},
            "ports": {"1514/tcp": None},
            "networks": {"none": {"IPAddress": "", "Gateway": "", "MacAddress": ""}},
            "environment": [
                "PATH=/usr/bin:/bin",
                "SB_WAZUH_ENTERPRISE_RUN=" + str(uuid.UUID(self.run)),
                "PYTHONDONTWRITEBYTECODE=1",
                "PYTHONUTF8=1",
            ],
            "tmpfs": None,
            "health": {"Test": ["NONE"]},
            "mounts": [
                {
                    "Type": "bind",
                    "Source": str(path),
                    "Destination": target,
                    "RW": not readonly,
                    "Propagation": "rprivate",
                }
                for target, (path, readonly) in host.mounts(directory).items()
            ],
        }

    def test_image_requires_pinned_platform_no_implicit_volumes_or_preload(self):
        self.assertEqual(host.image_identity(self.image), self.image["id"])
        for update in (
            {"digests": ["wazuh/wazuh-manager:latest"]},
            {"architecture": "arm64"},
            {"volumes": {"/var/ossec": {}}},
            {"environment": ["LD_PRELOAD=unreviewed"]},
            {"environment": ["PATH=a", "PATH=b"]},
        ):
            with self.subTest(update=update), self.assertRaises(EnterpriseWazuhError):
                host.image_identity({**self.image, **update})

    def test_create_uses_structured_space_containing_paths_without_pulls_or_stock_init(self):
        with scratch(self) as root:
            directory = root / "path with spaces"
            args = host.create_arguments(self.image, self.run, directory)
            self.assertEqual(args[0], "create")
            self.assertIn("--pull=never", args)
            self.assertNotIn("/init", args)
            self.assertNotIn("--privileged", args)
            self.assertEqual(args.count("--mount"), 6)
            self.assertTrue(any("path with spaces" in arg for arg in args))
            with self.assertRaisesMessage(EnterpriseWazuhError, "collector_mount_path"):
                host.create_arguments(self.image, self.run, root / "bad,readonly=false")

    def test_runtime_rejects_privilege_ports_environment_network_and_wrong_mounts(self):
        with scratch(self) as directory:
            original = self.runtime(directory)
            self.assertTrue(
                host.validate_runtime(original, self.image, self.run, directory)[
                    "effective_runtime_verified"
                ]
            )
            # Docker reports the same reviewed capabilities with CAP_ prefixes.
            prefixed = {**original, "cap_add": ["CAP_SETUID", "CAP_SETGID", "CAP_SYS_CHROOT"]}
            self.assertTrue(
                host.validate_runtime(prefixed, self.image, self.run, directory)[
                    "effective_runtime_verified"
                ]
            )
            changes = [
                {"privileged": True},
                {"memory": True},
                {"memory": float(host.MEMORY)},
                {"cap_add": ["SYS_ADMIN"]},
                {"cap_add": ["CAP_SETUID", "CAP_SETGID", "CAP_SYS_ADMIN"]},
                {"port_bindings": {"1514/tcp": [{"HostPort": "1514"}]}},
                {"environment": original["environment"] + ["TOKEN=unreviewed"]},
                {"network_mode": "host"},
                {"networks": {"bridge": {"IPAddress": "172.1.1.2"}}},
                {"restart": "always"},
                {"readonly": True},
                {"entrypoint": ["/init"]},
                {"health": {"Test": ["CMD", "unreviewed"]}},
            ]
            for change in changes:
                with self.subTest(change=change), self.assertRaises(EnterpriseWazuhError):
                    host.validate_runtime({**original, **change}, self.image, self.run, directory)
            for index in (0, 2):
                wrong = copy.deepcopy(original)
                wrong["mounts"][index]["RW"] = True
                with self.assertRaises(EnterpriseWazuhError):
                    host.validate_runtime(wrong, self.image, self.run, directory)
            wrong = copy.deepcopy(original)
            wrong["mounts"][1]["Source"] = str(directory / "other-project")
            with self.assertRaises(EnterpriseWazuhError):
                host.validate_runtime(wrong, self.image, self.run, directory)
            for propagation in (None, "shared", "rshared", "private"):
                wrong = copy.deepcopy(original)
                wrong["mounts"][0]["Propagation"] = propagation
                with self.assertRaises(EnterpriseWazuhError):
                    host.validate_runtime(wrong, self.image, self.run, directory)

    def test_kernel_requires_effective_caps_identity_limits_network_and_readonly_inputs(self):
        original = kernel()
        self.assertEqual(verify_kernel(original)["memory_bytes"], host.MEMORY)
        variants = [
            {**original, "interfaces": ["lo", "eth0"]},
            {**original, "status": original["status"].replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")},
            {
                **original,
                "status": original["status"].replace("00000000000400c0", "00000000000400c1"),
            },
            {**original, "status": original["status"] + "\nUid: 0 0 0 0"},
            {**original, "cgroups": {**original["cgroups"], "memory.swap.max": "max"}},
            {**original, "cgroups": {**original["cgroups"], "cpu.max": "200000 100000"}},
            {
                **original,
                "mountinfo": original["mountinfo"].replace("/workspace ro", "/workspace rw"),
            },
        ]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(EnterpriseWazuhError):
                verify_kernel(value)

    def test_capacity_preserves_host_headroom_and_whole_stage_consumption(self):
        host.check_capacity(host.INITIAL_DISK - 10 * base.GIB, 4 * base.GIB)
        with self.assertRaises(EnterpriseWazuhError):
            host.check_capacity(host.INITIAL_DISK - 10 * base.GIB, 4 * base.GIB, launching=True)
        host.check_capacity(
            host.INITIAL_DISK - 10 * base.GIB, 4 * base.GIB + host.MEMORY, launching=True
        )
        for disk, memory in (
            (host.INITIAL_DISK - host.GROWTH, 8 * base.GIB),
            (24 * base.GIB, 8 * base.GIB),
            (host.INITIAL_DISK, True),
        ):
            with self.assertRaises(EnterpriseWazuhError):
                host.check_capacity(disk, memory)

    def test_capacity_revision_keeps_original_baseline_reserves_and_default(self):
        disk = host.INITIAL_DISK - 28 * base.GIB
        memory = base.MIN_FREE_MEMORY + host.MEMORY
        with self.assertRaises(EnterpriseWazuhError):
            host.check_capacity(disk, memory, launching=True)
        host.check_capacity(
            disk, memory, launching=True, growth_ceiling=host.REVIEWED_CAPACITY_GROWTH
        )
        for candidate in (True, 30.0 * base.GIB, 31 * base.GIB, 13 * base.GIB):
            with self.subTest(candidate=candidate), self.assertRaises(EnterpriseWazuhError):
                host.check_capacity(disk, memory, growth_ceiling=candidate)
        for disk, memory in (
            (host.INITIAL_DISK - host.REVIEWED_CAPACITY_GROWTH, 8 * base.GIB),
            (24 * base.GIB, 8 * base.GIB),
            (host.INITIAL_DISK - 28 * base.GIB, base.MIN_FREE_MEMORY - 1),
        ):
            with self.subTest(disk=disk, memory=memory), self.assertRaises(EnterpriseWazuhError):
                host.check_capacity(disk, memory, growth_ceiling=host.REVIEWED_CAPACITY_GROWTH)
        with self.assertRaises(EnterpriseWazuhError):
            host.check_capacity(26 * base.GIB, 8 * base.GIB, growth_ceiling=30 * base.GIB)

    def test_shutdown_rechecks_exact_owned_scope_before_mutation(self):
        labels = {
            "org.signalbridge.enterprise.run": self.run,
            "org.signalbridge.enterprise.scope": host.SCOPE,
            "org.signalbridge.enterprise.component": "collector",
        }

        def respond(_docker, _run, _workspace, args, **kwargs):
            if args[0] == "ps":
                return self.identifier
            if args[0] == "stop":
                return self.identifier
            if args[-1] == "{{.State.Running}}":
                return "false"
            return canonical({"labels": labels, "name": "/" + host.PREFIX + self.run}).decode()

        with patch.object(host, "request", side_effect=respond) as request:
            self.assertEqual(host.stop_scope("modeled", self.run, Path.cwd()), 1)
            self.assertEqual(sum(c.args[3][0] == "stop" for c in request.call_args_list), 1)
        labels["org.signalbridge.enterprise.scope"] = "another-project"
        with (
            patch.object(host, "request", side_effect=respond) as request,
            self.assertRaises(EnterpriseWazuhError),
        ):
            host.stop_scope("modeled", self.run, Path.cwd())
        self.assertFalse(any(c.args[3][0] == "stop" for c in request.call_args_list))

    def test_dead_guard_prevents_create(self):
        with (
            scratch(self) as directory,
            patch.object(launcher, "private_acl"),
            patch.object(launcher, "check_capacity"),
            patch.object(
                launcher, "require_guard", side_effect=base.LabControlError("modeled dead guard")
            ),
            patch.object(host, "request") as request,
        ):
            with self.assertRaises(base.LabControlError):
                launcher.execute("modeled", self.run, directory, self.image, object())
            request.assert_not_called()

    def test_created_runtime_failure_prevents_start(self):
        with (
            scratch(self) as directory,
            patch.object(launcher, "private_acl"),
            patch.object(launcher, "check_capacity"),
            patch.object(launcher, "require_guard"),
            patch.object(launcher, "no_foreign_running"),
            patch.object(host, "owned", side_effect=[[], [self.identifier]]),
            patch.object(
                host, "verify_runtime", side_effect=EnterpriseWazuhError("changed runtime")
            ),
            patch.object(host, "request", return_value=self.identifier) as request,
        ):
            with self.assertRaises(EnterpriseWazuhError):
                launcher.execute("modeled", self.run, directory, self.image, object())
            self.assertEqual(len(request.call_args_list), 1)
            self.assertEqual(request.call_args.args[3][0], "create")

    def test_independent_guard_aborts_on_runtime_failure_and_retains_failed_reason(self):
        with scratch(self) as workspace:
            directory = base.private_run_directory(workspace, self.run)
            directory.mkdir(parents=True)
            (directory / "launcher-finished.json").write_bytes(b"{}")
            writes = {}
            with (
                patch.object(host, "read_json", return_value=self.image),
                patch.object(
                    host,
                    "write_control",
                    side_effect=lambda _w, _r, name, value: writes.update({name: value}),
                ),
                patch.object(host, "check_capacity"),
                patch.object(host, "owned", return_value=[self.identifier]),
                patch.object(
                    host,
                    "verify_runtime",
                    side_effect=EnterpriseWazuhError("modeled changed runtime"),
                ),
                patch.object(host, "stop_scope", return_value=1) as stop,
            ):
                result = host.watchdog(
                    "modeled",
                    self.run,
                    workspace,
                    time.time() + 5,
                    lambda: 8 * base.GIB,
                )
            self.assertEqual(result["reason"], "control_error")
            self.assertTrue(result["shutdown_verified"])
            self.assertEqual(stop.call_count, 2)
            self.assertIn("watchdog-abort.json", writes)
            self.assertEqual(writes["watchdog.json"], result)

    def source_rows(self):
        console, expected = {"events": [], "cases": []}, {}
        for index in range(23):
            app, event_id = ("documents" if index < 12 else "expenses"), str(uuid.uuid4())
            payload = {
                "environment": "lab",
                "occurred_at": (self.now - timedelta(minutes=2)).isoformat(),
                "operation": "private_record.read",
                "outcome": "denied",
                "reason": "membership_required",
            }
            event = {
                "event_id": event_id,
                "app": app,
                "payload": payload,
                "digest": digest(payload),
                "state": "processed",
                "source": "instrumented_lab",
            }
            console["events"].append(event)
            expected[(app, "observation", event_id)] = (
                {
                    "signalbridge": {
                        "export_version": 2,
                        "app": app,
                        "event_id": event_id,
                        "source": "instrumented_lab",
                        **payload,
                    }
                },
                "modeled-location",
            )
        evidence = sorted(e["event_id"] for e in console["events"][:2])
        case = {
            "case_id": str(uuid.uuid4()),
            "app": "documents",
            "rule": "R3",
            "version": 1,
            "evidence_event_ids": evidence,
        }
        console["cases"].append(case)
        checksums = {e["event_id"]: e["digest"] for e in console["events"]}
        row = {
            "signal_version": 1,
            "origin": "signalbridge",
            "app": "documents",
            "signal_id": str(uuid.uuid4()),
            "case_id": case["case_id"],
            "case_version": 1,
            "rule_id": "R3",
            "rule_version": "resource-membership-v1",
            "severity": "high",
            "environment": "lab",
            "source": "instrumented_lab",
            "generated_at": (self.now - timedelta(minutes=1)).isoformat(),
            "evidence_sha256": digest(
                sorted([[k, checksums[k], "instrumented_lab"] for k in evidence])
            ),
            "generation_source_sha256": "e" * 64,
            "evidence_count": 2,
            "included_event_ids": ",".join(evidence),
            "evidence_complete": 1,
        }
        expected[("documents", "detection", row["signal_id"])] = (
            {"signalbridge_detection": row},
            "modeled-location",
        )
        result = {
            "case_id": case["case_id"],
            "run_id": self.run,
            "source_sha256": "f" * 64,
            "host_receipt_sha256": "a" * 64,
        }
        return expected, console, result

    def test_source_binding_requires_complete_observations_and_specific_native_r3_evidence(self):
        expected, console, result = self.source_rows()
        checked = bind_expected(expected, console, result, "e" * 64, now=self.now)
        self.assertEqual(checked["logical_observations"], 23)
        self.assertFalse(checked["independent_wazuh_r3_rediscovery"])
        for change in (
            "missing",
            "crossapp",
            "changedreason",
            "caseversion",
            "digest",
            "generation",
            "future",
        ):
            wrong = copy.deepcopy(expected)
            signal = next(
                packet["signalbridge_detection"]
                for packet, _ in wrong.values()
                if "signalbridge_detection" in packet
            )
            observation = next(
                packet["signalbridge"] for packet, _ in wrong.values() if "signalbridge" in packet
            )
            if change == "missing":
                wrong.pop(next(iter(wrong)))
            elif change == "crossapp":
                observation["app"] = "expenses"
            elif change == "changedreason":
                observation["reason"] = "member"
            elif change == "caseversion":
                signal["case_version"] = 2
            elif change == "digest":
                signal["evidence_sha256"] = "0" * 64
            elif change == "generation":
                signal["generation_source_sha256"] = "0" * 64
            else:
                signal["generated_at"] = (self.now + timedelta(seconds=1)).isoformat()
            with self.subTest(change=change), self.assertRaises(EnterpriseWazuhError):
                bind_expected(wrong, console, result, "e" * 64, now=self.now)

    def snapshot(self, root, fixture):
        streams = []
        for app in ("documents", "expenses"):
            for channel in ("observation", "detection"):
                folder = root / app / channel
                folder.mkdir(parents=True)
                packets = [
                    packet
                    for (scope, kind, _key), (packet, _location) in fixture.expected.items()
                    if scope == app and kind == channel
                ]
                raw = b"".join(canonical(packet) + b"\n" for packet in packets)
                segments = []
                if raw:
                    (folder / "observations-000.jsonl").write_bytes(raw)
                    segments = [
                        {
                            "number": 0,
                            "start_offset": 0,
                            "bytes": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest(),
                            "sealed": False,
                        }
                    ]
                streams.append(
                    {
                        "app": app,
                        "channel": channel,
                        "stream_id": str(uuid.uuid4()) if raw else None,
                        "offset": len(raw),
                        "prefix_sha256": hashlib.sha256(raw).hexdigest() if raw else EMPTY_SHA256,
                        "segments": segments,
                    }
                )
        return canonical({"manifest_version": 1, "streams": streams}) + b"\n"

    def output(self, directory):
        fixture = modeled.NativeBootstrapControls()
        fixture.setUp()
        self.now = fixture.now + timedelta(seconds=1)
        evidence = directory / "evidence"
        evidence.mkdir()
        raw_manifest = self.snapshot(directory / "input", fixture)
        sources = {}
        for name in SOURCE_FILES:
            raw = (launcher.ROOT / name).read_bytes()
            path = directory / "source" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            sources[name] = hashlib.sha256(raw).hexdigest()
        context = {
            "context_version": 1,
            "run_id": str(uuid.UUID(self.run)),
            "prepared_at": (fixture.now - timedelta(minutes=11)).isoformat(),
            "source_sha256": hashlib.sha256(canonical(sources)).hexdigest(),
            "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
        }
        archives = fixture.bytes([fixture.native(i) for i in range(2)])
        alerts = fixture.bytes([fixture.native(i, kind="alert") for i in range(2)])
        counts = reconcile(archives, alerts, fixture.expected, now=self.now, final=True)
        raw_kernel = canonical(kernel()) + b"\n"
        raw_context = canonical(context) + b"\n"
        report = {
            "kind": "signalbridge-wazuh-native-bootstrap-v1",
            "status": "counts_matched_pending_host_verification",
            "failure_code": None,
            "owned_processes_stopped": True,
            "native_runtime_execution_verified": False,
            "genuine_source_execution_verified": False,
            "continuous_delivery_verified": False,
            "run_id": context["run_id"],
            "context_sha256": hashlib.sha256(raw_context).hexdigest(),
            "source_sha256": context["source_sha256"],
            "manifest_sha256": context["manifest_sha256"],
            "kernel_sha256": hashlib.sha256(raw_kernel).hexdigest(),
            "kernel_controls": verify_kernel(kernel()),
            "configuration_sha256": hashlib.sha256(configuration()).hexdigest(),
            "internal_options_sha256": hashlib.sha256(INTERNAL_OPTIONS).hexdigest(),
            "coverage": counts,
            "finished_at": fixture.now.isoformat(),
            "duration_seconds": 600.0,
        }
        heartbeat = {
            "run_id": context["run_id"],
            "sequence": 600,
            "observed_at": fixture.now.isoformat(),
            "supervisor_children_alive": True,
            "coverage": counts,
            "native_runtime_execution_verified": False,
        }
        values = {
            "run-context.json": raw_context,
            "source-manifest.json": canonical({"files": sources}),
            "manifest.json": raw_manifest,
            "kernel-observed.json": raw_kernel,
            "effective-config.xml": configuration(),
            "effective-internal-options.conf": INTERNAL_OPTIONS,
            "native-archives.jsonl": archives,
            "native-alerts.jsonl": alerts,
            "native-report.json": canonical(report),
            "heartbeat.json": canonical(heartbeat),
        }
        values.update(
            {
                name: b""
                for name in (
                    "analysisd-config.log",
                    "wazuh-db.log",
                    "wazuh-analysisd.log",
                    "wazuh-logcollector.log",
                )
            }
        )
        for name, raw in values.items():
            (evidence / name).write_bytes(raw)
        journal = CaptureJournal(evidence, context["run_id"], create=True)
        try:
            for kind, raw in (("archive", archives), ("alert", alerts)):
                source = journal.begin(kind, "1:1")
                journal.append(source[0], 0, raw, prefix_digest=EMPTY)
                journal.seal(source[0], len(raw), hashlib.sha256(raw).hexdigest())
        finally:
            journal.close()
        values["capture.sqlite3"] = (evidence / "capture.sqlite3").read_bytes()
        return context, values, fixture

    def test_host_recomputes_actual_scratch_receipts_without_attesting_execution(self):
        with scratch(self) as directory:
            context, _values, _fixture = self.output(directory)
            proof = launcher.validate_output(directory, context, now=self.now)
            self.assertTrue(proof["coverage"]["bootstrap_counts_match"])
            self.assertFalse(proof["native_runtime_execution_verified"])
            self.assertFalse(proof["continuous_delivery_verified"])
            self.assertTrue(proof["durable_capture_revalidated"])

    def test_output_missing_partial_tampered_or_false_shutdown_remains_incomplete(self):
        with scratch(self) as directory:
            context, values, _fixture = self.output(directory)
            for name, raw in (
                ("native-archives.jsonl", values["native-archives.jsonl"][:-1]),
                (
                    "native-report.json",
                    canonical(
                        {
                            **json.loads(values["native-report.json"]),
                            "owned_processes_stopped": False,
                        }
                    ),
                ),
                (
                    "heartbeat.json",
                    canonical({**json.loads(values["heartbeat.json"]), "sequence": True}),
                ),
                ("effective-internal-options.conf", b"logcollector.remote_commands=1\n"),
            ):
                (directory / "evidence" / name).write_bytes(raw)
                with self.subTest(name=name), self.assertRaises(EnterpriseWazuhError):
                    launcher.validate_output(directory, context, now=self.now)
                (directory / "evidence" / name).write_bytes(values[name])
            (directory / "evidence/extra.json").write_bytes(b"{}")
            with self.assertRaises(EnterpriseWazuhError):
                launcher.validate_output(directory, context, now=self.now)

    def test_unsealed_or_changed_capture_cannot_certify_matching_final_json(self):
        with scratch(self) as directory:
            context, values, _fixture = self.output(directory)
            journal = CaptureJournal(directory / "evidence", context["run_id"])
            with journal.db:
                journal.db.execute("UPDATE sources SET sealed=0 WHERE kind='archive'")
            journal.close()
            with self.assertRaisesMessage(
                EnterpriseWazuhError, "collector_native_capture_unsealed"
            ):
                launcher.validate_output(directory, context, now=self.now)
            (directory / "evidence/capture.sqlite3").write_bytes(values["capture.sqlite3"])
            journal = CaptureJournal(directory / "evidence", context["run_id"])
            with journal.db:
                journal.db.execute(
                    "UPDATE chunks SET body=? WHERE source=(SELECT sequence FROM sources WHERE kind='archive')",
                    (b"changed\n",),
                )
            journal.close()
            with self.assertRaisesMessage(EnterpriseWazuhError, "capture_checkpoint_digest"):
                launcher.validate_output(directory, context, now=self.now)

    def test_completed_snapshot_is_rechecked_and_typed_unverified_flags_preserved(self):
        fixture = modeled.NativeBootstrapControls()
        fixture.setUp()
        with scratch(self) as workspace:
            snapshot_id = str(uuid.uuid4())
            directory = workspace / "var/wazuh-enterprise/native" / snapshot_id
            raw = self.snapshot(directory / "input", fixture)
            (directory / "manifest.json").write_bytes(raw)
            report = {
                **inspect_exports(directory / "input", raw),
                "run_id": snapshot_id,
                "private_host_acl_verified": False,
                "snapshot_live_after_capture": False,
            }
            (directory / "snapshot.json").write_bytes(canonical(report))
            _root, actual, expected = load_snapshot(workspace, snapshot_id)
            self.assertEqual(actual, raw)
            self.assertEqual(expected, fixture.expected)
            (directory / "snapshot.json").write_bytes(
                canonical({**report, "private_host_acl_verified": 0})
            )
            with self.assertRaisesMessage(
                EnterpriseWazuhError, "collector_binding_snapshot_changed"
            ):
                load_snapshot(workspace, snapshot_id)
