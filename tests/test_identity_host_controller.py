"""Closed host controls without Docker, optional crypto, launches or downloads."""

import copy
import hashlib
import json
import unittest
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from integrations.identity import native_certificates as certificates
from integrations.identity import native_host as host
from scripts import enterprise_identity_verify as controller

PROJECT = Path(__file__).resolve().parents[1]
RUN = "a" * 32
KEYCLOAK_ID = "b" * 64
NETWORK_ID = "d" * 64
DATABASE_ID, RUNNER_ID, FOREIGN_ID = (char * 64 for char in ("1", "2", "f"))
DIRECTORY = PROJECT / "var/enterprise/runs" / RUN
VOLUME_PATH = "/var/lib/docker/volumes/" + host.PREFIX + RUN + "/_data"
CREATED = "2026-10-02T00:00:00Z"
TARGETS = {DATABASE_ID: "database", KEYCLOAK_ID: "keycloak", RUNNER_ID: "runner"}


def binding():
    return {
        "network": {"name": host.NETWORK + RUN, "id": NETWORK_ID, "created": CREATED},
        "volume": {"name": host.PREFIX + RUN, "created": CREATED, "mountpoint": VOLUME_PATH},
    }


def resource_rows(targets=TARGETS):
    return {
        "network": {
            "Name": host.NETWORK + RUN,
            "Id": NETWORK_ID,
            "Created": CREATED,
            "Labels": host.labels(RUN),
            "Options": {},
            "Internal": True,
            "Ingress": False,
            "Driver": "bridge",
            "EnableIPv6": False,
            "Containers": {
                identifier: {} for identifier, component in targets.items() if component != "runner"
            },
        },
        "volume": {
            "Name": host.PREFIX + RUN,
            "CreatedAt": CREATED,
            "Mountpoint": VOLUME_PATH,
            "Labels": host.labels(RUN),
            "Options": None,
            "Driver": "local",
            "Scope": "local",
        },
    }


def image(component):
    return {
        "id": "sha256:" + "c" * 64,
        "entrypoint": ["/entrypoint"],
        "environment": ["PATH=/usr/bin"],
        "workdir": "/default",
    }


def effective(component):
    fixed = host.ROLES[component]
    value = {
        "image": image(component)["id"],
        "memory": fixed["memory"],
        "swap": fixed["memory"],
        "cpu": 10**9,
        "pids": fixed["pids"],
        "readonly": fixed["readonly"],
        "privileged": False,
        "cap_drop": ["ALL"],
        "security": ["no-new-privileges:true"],
        "restart": "no",
        "user": fixed["user"],
        "pid_mode": "",
        "ipc_mode": "private",
        "uts_mode": "",
        "cgroup_mode": "private",
        "command": host.COMMANDS[component],
        "entrypoint": ["/entrypoint"],
        "workdir": "/workspace" if component in host.SHARED_NAMESPACE else "/default",
        "network_mode": "container:" + KEYCLOAK_ID
        if component in host.SHARED_NAMESPACE
        else host.NETWORK + RUN,
        "log": {"Type": "json-file", "Config": {"max-file": "2", "max-size": "2m"}},
        "health": {"Test": ["NONE"]},
        "shm": 64 * 1024**2,
        "cap_add": None,
        "devices": [],
        "device_requests": None,
        "port_bindings": {},
        "ports": {"5432/tcp": None} if component == "database" else {},
        "networks": {}
        if component in host.SHARED_NAMESPACE
        else {host.NETWORK + RUN: {"NetworkID": NETWORK_ID}},
        "environment": [
            "PATH=/usr/bin",
            *(key + "=" + value for key, value in host.env(component, RUN).items()),
        ],
        "tmpfs": host.TMPFS[component] or None,
        "mounts": [
            {
                "Destination": target,
                "Type": "bind",
                "Source": str(source),
                "RW": writable,
                "Propagation": "rprivate",
            }
            for target, (source, writable) in host.mounts(component, DIRECTORY).items()
        ],
    }
    if component == "database":
        value["mounts"].append(
            {
                "Destination": "/var/lib/postgresql/data",
                "Type": "volume",
                "RW": True,
                "Name": host.PREFIX + RUN,
                "Source": VOLUME_PATH,
            }
        )
    return value


def kernel():
    fields = {
        "Uid": "10001\t10001\t10001\t10001",
        "Gid": "10001\t10001\t10001\t10001",
        "Groups": "10001",
        "NoNewPrivs": "1",
        "Seccomp": "2",
        **{key: "0000000000000000" for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
    }
    mounts = {
        target: not writable
        for target, (_, writable) in host.mounts("runner", Path("unused")).items()
    }
    mounts["/"] = True
    rows = [
        f"{index + 1} 0 0:1 / {target} {'ro' if readonly else 'rw'},relatime - overlay overlay rw"
        for index, (target, readonly) in enumerate(mounts.items())
    ]
    rows.extend(
        [
            "90 0 0:2 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=65536k",
            "91 0 0:3 / /opt/identity-deps rw,nosuid,nodev - tmpfs tmpfs rw,size=262144k,mode=700,uid=10001,gid=10001",
        ]
    )
    return {
        "status": "\n".join(key + ":\t" + value for key, value in fields.items()),
        "cgroups": {
            "memory.max": str(512 * 1024**2),
            "memory.swap.max": "0",
            "pids.max": "96",
            "cpu.max": "100000 100000",
        },
        "mountinfo": "\n".join(rows),
    }


class IdentityHostControllerTests(unittest.TestCase):
    def setUp(self):
        # Every case is code-only even if a mock boundary is accidentally missed.
        stack = ExitStack()
        self.addCleanup(stack.close)
        for primitive in ("subprocess.run", "subprocess.Popen", "socket.socket"):
            stack.enter_context(
                patch(primitive, side_effect=AssertionError("Native primitive forbidden"))
            )
        stack.enter_context(
            patch.object(host.base, "docker_result", side_effect=AssertionError("Docker forbidden"))
        )
        stack.enter_context(
            patch.object(
                controller, "invoke", side_effect=AssertionError("Native invocation forbidden")
            )
        )

    def test_certificate_directory_junction_rejected_before_key_generation(self):
        parent = MagicMock()
        directory = parent.__truediv__.return_value
        directory.is_dir.return_value = True
        directory.is_symlink.return_value = False
        directory.lstat.return_value = SimpleNamespace(st_file_attributes=0x400)
        with (
            patch.object(certificates, "private_run_directory", return_value=parent),
            patch.object(
                certificates.argparse.ArgumentParser,
                "parse_args",
                return_value=SimpleNamespace(workspace=PROJECT, run=RUN),
            ),
            patch.object(certificates, "material") as generate,
            self.assertRaises(ValueError),
        ):
            certificates.main()
        generate.assert_not_called()

    def test_runtime_snapshot_retains_validated_facts_and_returns_content_hash(self):
        facts = {"runner": {"container_id": "b" * 64, "effective": effective("runner")}}
        resources = {"network": {"Internal": True}, "volume": {"Driver": "local"}}
        with (
            patch.object(
                host,
                "verify_runtime",
                side_effect=lambda *_, capture, binding: capture.update(facts),
            ),
            patch.object(
                host,
                "resources",
                side_effect=lambda *_, capture, binding: capture.update(resources),
            ),
            patch.object(controller, "resource_binding", return_value=binding()),
            patch.object(controller, "write") as write,
            patch.object(Path, "read_bytes", return_value=b"synthetic retained facts"),
        ):
            digest = controller.runtime_snapshot("docker", RUN, DIRECTORY, {}, {}, "created")
        path, retained = write.call_args.args
        self.assertEqual(path.name, "identity-runtime-created.json")
        self.assertEqual(retained["components"], facts)
        self.assertEqual(retained["resources"], resources)
        self.assertEqual(digest, hashlib.sha256(b"synthetic retained facts").hexdigest())

    def test_malformed_watchdog_context_still_stops_scope_and_retains_receipt(self):
        receipt, stops = self.watchdog_case(malformed=True)
        self.assertEqual(receipt["reason"], "guard_failure")
        self.assertIs(receipt["shutdown_verified"], True)
        self.assertTrue(receipt["drain_completed"])
        self.assertGreater(len(stops), 1)

    def test_acknowledged_empty_inventory_waits_for_late_targets(self):
        receipt, stops = self.watchdog_case(late=True)
        self.assertEqual(receipt["reason"], "launcher_finished")
        self.assertTrue(receipt["shutdown_verified"])
        self.assertEqual(receipt["stopped_components"], ["runner", "keycloak", "database"])
        self.assertTrue(any(20 <= instant < 60 for instant in stops))
        self.assertGreaterEqual(max(stops), 60)

    def test_unreachable_daemon_does_not_claim_shutdown(self):
        receipt, stops = self.watchdog_case(unreachable=True)
        self.assertFalse(receipt["shutdown_verified"])
        self.assertTrue(receipt["deadline_exhausted"])
        self.assertEqual(receipt["shutdown_error_class"], "OSError")
        self.assertGreater(len(stops), 1)

    def watchdog_case(self, malformed=False, late=False, unreachable=False):
        clock, stops, written = [0], [], {}
        deadline = 1030 if unreachable else 1120
        context = {
            "run_id": RUN,
            "deadline": "malformed" if malformed else deadline,
            "baseline_free_disk": 60 * 1024**3,
            "images": {},
        }

        def read(path, *_):
            return {"run_id": RUN} if path.name == "launcher-finished.json" else context

        def exists(path):
            return (
                path.name in written
                or path.name == "launcher-finished.json"
                and (not malformed or clock[0] >= 1)
            )

        def record(_root, _run, name, value):
            written[name] = copy.deepcopy(value)

        def stop(*_):
            stops.append(clock[0])
            if unreachable:
                raise OSError("synthetic unreachable daemon")
            return [] if late and clock[0] < 20 else ["runner", "keycloak", "database"]

        with (
            patch.object(controller.base, "private_run_directory", return_value=DIRECTORY),
            patch.object(controller, "private_acl"),
            patch.object(controller, "read_json", side_effect=read),
            patch.object(controller, "write_control", side_effect=record),
            patch.object(controller, "revoke_gate"),
            patch.object(controller.time, "time", side_effect=lambda: 1000 + clock[0]),
            patch.object(controller.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(
                controller.time,
                "sleep",
                side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
            ),
            patch.object(Path, "exists", autospec=True, side_effect=exists),
            patch.object(host, "stop_scope", side_effect=stop),
        ):
            receipt = controller.watchdog("docker", RUN, deadline)
        self.assertEqual(written["watchdog.json"], receipt)
        if malformed:
            self.assertNotIn("watchdog-ready.json", written)
            self.assertIn("watchdog-abort.json", written)
        return receipt, stops

    def test_resources_retain_stable_identity_and_exact_owned_membership(self):
        rows, capture = resource_rows(), {}
        with patch.object(
            host, "request", side_effect=lambda *args, **_: json.dumps([rows[args[3][0]]])
        ):
            self.assertEqual(
                host.resources("docker", RUN, PROJECT, TARGETS, capture=capture, binding=binding()),
                binding(),
            )
        self.assertEqual(capture, rows)

    def test_docker_default_network_address_options_only(self):
        defaults = {
            "com.docker.network.enable_ipv4": "true",
            "com.docker.network.enable_ipv6": "false",
        }
        for kind, options, accepted in (
            ("network", defaults, True),
            ("network", {**defaults, "com.docker.network.enable_ipv6": "true"}, False),
            ("network", {**defaults, "com.docker.network.bridge.name": "br0"}, False),
            ("volume", defaults, False),
        ):
            rows = resource_rows()
            rows[kind]["Options"] = options
            with (
                self.subTest(kind=kind, options=options),
                patch.object(
                    host,
                    "request",
                    side_effect=lambda *args, rows=rows, **_: json.dumps([rows[args[3][0]]]),
                ),
            ):
                if accepted:
                    host.resources("docker", RUN, PROJECT, TARGETS, binding=binding())
                else:
                    with self.assertRaises(host.base.LabControlError):
                        host.resources("docker", RUN, PROJECT, TARGETS, binding=binding())

    def test_resources_reject_foreign_stopped_member_and_replaced_owned_metadata(self):
        changes = (
            lambda rows: rows["network"]["Containers"].update({FOREIGN_ID: {}}),
            lambda rows: rows["network"]["Containers"].update({RUNNER_ID: {}}),
            lambda rows: rows["network"].update(Id="e" * 64),
            lambda rows: rows["network"].update(Created="2026-10-02T00:00:01Z"),
            lambda rows: rows["volume"].update(CreatedAt="2026-10-02T00:00:01Z"),
            lambda rows: rows["volume"].update(
                Mountpoint="/other/volumes/" + host.PREFIX + RUN + "/_data"
            ),
            lambda rows: rows["network"].update(Internal=False),
            lambda rows: rows["network"].update(Containers=[]),
            lambda rows: rows["volume"].update(Options={"device": "/foreign"}),
            lambda rows: rows["volume"]["Labels"].update({"foreign": "other"}),
        )
        for index, change in enumerate(changes):
            rows = resource_rows()
            change(rows)
            with (
                self.subTest(change=index),
                patch.object(
                    host,
                    "request",
                    side_effect=lambda *args, rows=rows, **_: json.dumps([rows[args[3][0]]]),
                ),
                self.assertRaises(ValueError),
            ):
                host.resources("docker", RUN, PROJECT, TARGETS, binding=binding())

    def test_resource_inspection_rejects_duplicate_or_oversized_json(self):
        raw = json.dumps([resource_rows({})["network"]])
        for value in (
            raw.replace('"Internal": true', '"Internal": false, "Internal": true'),
            " " * 65537,
        ):
            with (
                self.subTest(size=len(value)),
                patch.object(host, "request", return_value=value),
                self.assertRaises(ValueError),
            ):
                host.resources("docker", RUN, PROJECT, {})

    def test_invalid_resource_binding_rejected_before_inspection(self):
        changes = (
            lambda data: data.update(extra=True),
            lambda data: data["network"].update(id="short"),
            lambda data: data["network"].update(name=host.NETWORK + "0" * 32),
            lambda data: data["volume"].update(created="2026-02-30T00:00:00Z"),
            lambda data: data["volume"].update(created="2026-10-02T00:00:00"),
            lambda data: data["volume"].update(
                mountpoint="/foreign/../volumes/" + host.PREFIX + RUN + "/_data"
            ),
            lambda data: data["volume"].update(mountpoint="/" + "a" * 1025 + VOLUME_PATH),
        )
        for index, change in enumerate(changes):
            value = binding()
            change(value)
            with (
                self.subTest(change=index),
                patch.object(host, "request") as invoke,
                self.assertRaises(ValueError),
            ):
                host.resources("docker", RUN, PROJECT, TARGETS, binding=value)
            invoke.assert_not_called()

    def test_container_runtime_binds_network_id_and_database_volume_source(self):
        for component, mutate in (
            (
                "database",
                lambda value: value["networks"][host.NETWORK + RUN].update(NetworkID="e" * 64),
            ),
            (
                "keycloak",
                lambda value: value["networks"][host.NETWORK + RUN].update(NetworkID="e" * 64),
            ),
            ("database", lambda value: value["mounts"][-1].update(Source="/foreign/data")),
        ):
            identifier = next(key for key, role in TARGETS.items() if role == component)
            value = effective(component)
            with (
                patch.object(host.base, "private_run_directory", return_value=DIRECTORY),
                patch.object(host, "role", return_value=component),
                patch.object(
                    host, "request", side_effect=lambda *_, value=value, **__: json.dumps(value)
                ),
            ):
                host.verify_runtime(
                    "docker",
                    RUN,
                    PROJECT,
                    {component: image(component)},
                    {identifier: component},
                    binding=binding(),
                )
                mutate(value)
                with self.subTest(component=component), self.assertRaises(ValueError):
                    host.verify_runtime(
                        "docker",
                        RUN,
                        PROJECT,
                        {component: image(component)},
                        {identifier: component},
                        binding=binding(),
                    )

    def test_runtime_precommit_accepts_only_explicit_empty_inventory(self):
        with (
            patch.object(host.base, "private_run_directory", return_value=DIRECTORY),
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "is_symlink", return_value=False),
            patch.object(host, "owned", return_value={}) as owned,
            patch.object(host, "no_foreign_running"),
            patch.object(host, "resources") as resources,
            patch.object(host, "verify_runtime") as verify,
        ):
            with self.assertRaises(ValueError):
                controller.runtime("docker", RUN, {})
            self.assertEqual(controller.runtime("docker", RUN, {}, allow_precommit=True), {})
            owned.return_value = {DATABASE_ID: "database"}
            with self.assertRaises(ValueError):
                controller.runtime("docker", RUN, {}, allow_precommit=True)
        resources.assert_not_called()
        verify.assert_not_called()

    def test_committed_binding_cannot_disappear_or_be_changed(self):
        with (
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "is_symlink", return_value=False),
            self.assertRaises(ValueError),
        ):
            controller.resource_binding(DIRECTORY, RUN, binding(), allow_precommit=True)
        changed = binding()
        changed["volume"]["created"] = "2026-10-02T00:00:01Z"
        for value in (
            {"run_id": "0" * 32, "resources": binding()},
            {"run_id": RUN, "resources": changed},
            {"run_id": RUN, "resources": binding(), "extra": True},
        ):
            with (
                patch.object(Path, "exists", return_value=True),
                patch.object(controller, "safe_path"),
                patch.object(controller, "read_json", return_value=value),
                self.assertRaises(ValueError),
            ):
                controller.resource_binding(DIRECTORY, RUN, binding(), allow_precommit=True)

    def test_fresh_resource_creation_commits_after_both_inspections(self):
        result, stored, operations = self.creation_case()
        self.assertEqual(result, binding())
        self.assertEqual(
            stored["identity-resource-binding.json"], {"run_id": RUN, "resources": binding()}
        )
        self.assertNotIn("identity-resource-binding.tmp", stored)
        self.assertEqual(
            operations[-3:],
            [
                ("inspect", "volume"),
                ("write", "identity-resource-binding.tmp"),
                ("commit", "identity-resource-binding.json"),
            ],
        )

    def test_interrupted_foreign_or_nonfresh_resource_creation_never_commits(self):
        for failure in (
            "volume_create",
            "volume_inspect",
            "foreign",
            "network_replaced",
            "old_volume",
            "preexisting",
        ):
            with self.subTest(failure=failure):
                _result, stored, operations = self.creation_case(failure)
                self.assertEqual(stored, {})
                self.assertFalse(
                    any(row[0] in {"write", "commit", "start", "stop"} for row in operations)
                )

    def test_interrupted_resource_creation_never_reaches_container_creation(self):
        with (
            patch.object(controller, "require_guard"),
            patch.object(host, "owned", return_value={}),
            patch.object(host, "no_foreign_running"),
            patch.object(
                controller,
                "create_resources",
                side_effect=OSError("Synthetic interrupted creation"),
            ),
            patch.object(host, "request") as invoke,
            patch.object(host, "create_arguments") as create,
            self.assertRaises(OSError),
        ):
            controller.execute("docker", RUN, DIRECTORY, {}, MagicMock(), 60 * 1024**3)
        invoke.assert_not_called()
        create.assert_not_called()

    def creation_case(self, failure=None):
        stored, operations, rows = {}, [], resource_rows({})
        if failure == "foreign":
            rows["network"]["Containers"][FOREIGN_ID] = {}
        if failure == "network_replaced":
            rows["network"]["Id"] = "e" * 64
        if failure == "old_volume":
            rows["volume"]["CreatedAt"] = "2026-10-01T00:00:00Z"

        def request(_docker, _run, _workspace, arguments, **_):
            kind, action = arguments[:2]
            operations.append((action, kind))
            if action == "ls":
                return host.NETWORK + RUN if failure == "preexisting" else ""
            if failure == kind + "_" + action:
                raise OSError("Synthetic interrupted resource request")
            if action == "create":
                return NETWORK_ID if kind == "network" else host.PREFIX + RUN
            if action == "inspect":
                return json.dumps([rows[kind]])
            raise AssertionError("Unexpected modeled resource operation")

        def write(path, value):
            operations.append(("write", path.name))
            stored[path.name] = copy.deepcopy(value)

        def commit(source, destination):
            operations.append(("commit", destination.name))
            stored[destination.name] = stored.pop(source.name)

        with (
            patch.object(host.base, "private_run_directory", return_value=DIRECTORY),
            patch.object(host, "request", side_effect=request),
            patch.object(
                controller.time, "time", return_value=datetime.fromisoformat(CREATED).timestamp()
            ),
            patch.object(
                Path, "exists", autospec=True, side_effect=lambda path: path.name in stored
            ),
            patch.object(Path, "is_symlink", return_value=False),
            patch.object(Path, "replace", autospec=True, side_effect=commit),
            patch.object(controller, "safe_path"),
            patch.object(controller, "write", side_effect=write),
            patch.object(
                controller,
                "read_json",
                side_effect=lambda path, *_: copy.deepcopy(stored[path.name]),
            ),
        ):
            if failure:
                with self.assertRaises((ValueError, OSError)):
                    controller.create_resources("docker", RUN)
                result = None
            else:
                result = controller.create_resources("docker", RUN)
        return result, stored, operations

    def test_watchdog_empty_precommit_then_committed_runtime_is_valid(self):
        receipt, calls, written = self.resource_watchdog_case()
        self.assertEqual(receipt["reason"], "launcher_finished")
        self.assertTrue(receipt["shutdown_verified"])
        self.assertNotIn("watchdog-abort.json", written)
        self.assertTrue(any(args[:2] == ["network", "inspect"] for args in calls))
        self.assertTrue(any(args[:2] == ["volume", "inspect"] for args in calls))

    def test_watchdog_foreign_attachment_aborts_and_stops_only_current_containers(self):
        receipt, calls, written = self.resource_watchdog_case("foreign")
        self.assertEqual(receipt["reason"], "guard_failure")
        self.assertTrue(receipt["shutdown_verified"])
        self.assertIn("watchdog-abort.json", written)
        stopped = [args[-1] for args in calls if args[0] == "stop"]
        self.assertEqual(set(stopped), set(TARGETS))
        self.assertNotIn(FOREIGN_ID, stopped)
        self.assertEqual(stopped[:3], [RUNNER_ID, KEYCLOAK_ID, DATABASE_ID])

    def test_watchdog_replaced_network_or_volume_and_missing_commit_abort(self):
        for change in ("network", "volume", "lost_marker", "changed_marker"):
            with self.subTest(change=change):
                receipt, calls, written = self.resource_watchdog_case(change)
                self.assertEqual(receipt["reason"], "guard_failure")
                self.assertIn("watchdog-abort.json", written)
                self.assertTrue(receipt["shutdown_verified"])
                self.assertEqual({args[-1] for args in calls if args[0] == "stop"}, set(TARGETS))

    def test_watchdog_precommit_deadline_expires_without_workload_or_native_mutation(self):
        receipt, calls, written = self.resource_watchdog_case("never_commit")
        self.assertEqual(receipt["reason"], "guard_failure")
        self.assertIn("watchdog-abort.json", written)
        self.assertTrue(receipt["shutdown_verified"])
        self.assertFalse(
            any(
                args[0] in {"start", "stop", "create", "exec", "network", "volume"}
                for args in calls
            )
        )

    def resource_watchdog_case(self, change=None):
        clock, written, calls = [0], {}, []
        deadline = 1200
        context = {
            "run_id": RUN,
            "deadline": deadline,
            "baseline_free_disk": 60 * 1024**3,
            "images": {role: image(role) for role in host.ROLES},
        }

        def exists(path):
            if path.name == "identity-resource-binding.json":
                return (
                    clock[0] >= 1
                    and change != "never_commit"
                    and not (change == "lost_marker" and clock[0] >= 2)
                )
            if path.name == "launcher-finished.json":
                return "watchdog-abort.json" in written or (change is None and clock[0] >= 4)
            return path.name in written

        def read(path, *_):
            if path.name == "identity-host-context.json":
                return context
            if path.name == "launcher-finished.json":
                return {"run_id": RUN}
            if path.name == "identity-resource-binding.json":
                expected = binding()
                if change == "changed_marker" and clock[0] >= 2:
                    expected["network"]["id"] = "e" * 64
                return {"run_id": RUN, "resources": expected}
            raise AssertionError("Unexpected modeled control read")

        def request(_docker, _run, _workspace, arguments, **_):
            calls.append(arguments)
            if arguments[0] == "ps":
                return "\n".join(TARGETS) if clock[0] >= 1 and change != "never_commit" else ""
            if arguments[:2] in (["network", "inspect"], ["volume", "inspect"]):
                rows = resource_rows()
                if clock[0] >= 2:
                    if change == "foreign":
                        rows["network"]["Containers"][FOREIGN_ID] = {}
                    elif change == "network":
                        rows["network"]["Id"] = "e" * 64
                    elif change == "volume":
                        rows["volume"]["CreatedAt"] = "2026-10-02T00:00:01Z"
                return json.dumps([rows[arguments[0]]])
            if arguments[0] == "inspect":
                identifier, template = arguments[1], arguments[-1]
                self.assertIn(identifier, TARGETS)
                if template == "{{.State.Running}}":
                    return "false"
                if '"labels"' in template:
                    component = TARGETS[identifier]
                    return json.dumps(
                        {
                            "labels": host.labels(RUN, component),
                            "name": "/" + host.PREFIX + RUN + "-" + component,
                        }
                    )
                return json.dumps(effective(TARGETS[identifier]))
            if arguments[0] == "stop":
                self.assertIn(arguments[-1], TARGETS)
                return ""
            raise AssertionError("Unexpected modeled watchdog operation")

        with (
            patch.object(host.base, "private_run_directory", return_value=DIRECTORY),
            patch.object(host, "request", side_effect=request),
            patch.object(controller, "private_acl"),
            patch.object(controller, "capacity"),
            patch.object(controller, "safe_path"),
            patch.object(controller, "read_json", side_effect=read),
            patch.object(
                controller,
                "write_control",
                side_effect=lambda _root, _run, name, value: written.__setitem__(
                    name, copy.deepcopy(value)
                ),
            ),
            patch.object(controller, "revoke_gate"),
            patch.object(controller.time, "time", side_effect=lambda: 1000 + clock[0]),
            patch.object(controller.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(
                controller.time,
                "sleep",
                side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
            ),
            patch.object(Path, "exists", autospec=True, side_effect=exists),
            patch.object(Path, "is_symlink", return_value=False),
        ):
            receipt = controller.watchdog("docker", RUN, deadline)
        self.assertEqual(receipt, written["watchdog.json"])
        return receipt, calls, written

    def test_all_three_effective_profiles_and_absent_optional_maps(self):
        for component in host.ROLES:
            with self.subTest(component=component):
                self.assertTrue(
                    host.validate_runtime(
                        effective(component),
                        component,
                        image(component),
                        RUN,
                        DIRECTORY,
                        KEYCLOAK_ID,
                    )
                )
        self.assertIn('index .HostConfig "Tmpfs"', host.runtime_template())
        self.assertIn('index .Config "Healthcheck"', host.runtime_template())

    def test_escaped_mount_port_privilege_and_cross_namespace_rejected(self):
        alterations = [
            ("privileged", True),
            ("memory", 0),
            ("network_mode", "host"),
            ("restart", "always"),
            ("port_bindings", {"443/tcp": [{"HostPort": "443"}]}),
            ("environment", ["PATH=/usr/bin", "LD_PRELOAD=/evil"]),
        ]
        for key, value in alterations:
            data = effective("runner")
            data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                host.validate_runtime(data, "runner", image("runner"), RUN, DIRECTORY, KEYCLOAK_ID)
        for component in host.ROLES:
            data = effective(component)
            data["mounts"][0]["Source"] = str(PROJECT.parent / "other-project")
            with self.assertRaises(ValueError):
                host.validate_runtime(
                    data, component, image(component), RUN, DIRECTORY, KEYCLOAK_ID
                )

    def test_actual_kernel_parser_rejects_missing_sandbox_controls(self):
        self.assertTrue(host.verify_kernel(kernel())["cgroup_v2_limits_verified"])
        for change in (
            lambda data: data["cgroups"].update({"memory.max": "max"}),
            lambda data: data.update(
                status=data["status"].replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")
            ),
            lambda data: data.update(
                mountinfo=data["mountinfo"].replace("rw,nosuid,nodev,noexec", "rw,nosuid,nodev")
            ),
            lambda data: data.update(
                mountinfo=data["mountinfo"].replace("size=262144k", "size=524288k")
            ),
        ):
            value = kernel()
            change(value)
            with self.assertRaises(ValueError):
                host.verify_kernel(value)

    def test_direct_commands_never_pull_or_publish_and_bound_memory(self):
        for component in host.ROLES:
            arguments = host.create_arguments(
                component, image(component), RUN, DIRECTORY, KEYCLOAK_ID
            )
            self.assertIn("--pull=never", arguments)
            self.assertNotIn("--publish", arguments)
            self.assertNotIn("-p", arguments)
            self.assertNotIn("--privileged", arguments)
            self.assertIn("--no-healthcheck", arguments)
            self.assertEqual(
                arguments[arguments.index("--memory") + 1], str(host.ROLES[component]["memory"])
            )
        with self.assertRaises(ValueError):
            host.create_arguments("runner", image("runner"), RUN, DIRECTORY, "wrong")

    def test_shutdown_attempts_other_owned_components_when_one_owner_fails(self):
        identifiers = ["1" * 64, "2" * 64, "3" * 64]

        def ownership(_docker, _run, _workspace, identifier):
            if identifier == identifiers[0]:
                raise ValueError("Synthetic ownership mismatch")
            return "database" if identifier == identifiers[1] else "runner"

        def call(_docker, _run, _workspace, arguments, **_kwargs):
            return "false" if arguments[0] == "inspect" else ""

        with (
            patch.object(host, "inventory", return_value=identifiers),
            patch.object(host, "role", side_effect=ownership),
            patch.object(host, "request", side_effect=call) as invoke,
        ):
            with self.assertRaises(ValueError):
                host.stop_scope("docker", RUN, PROJECT)
            stopped = [
                item.args[3][-1] for item in invoke.call_args_list if item.args[3][0] == "stop"
            ]
            self.assertEqual(stopped, [identifiers[2], identifiers[1]])

    def test_receipt_cannot_promote_partial_or_forged_shape(self):
        rows = [{"control": name, "passed": True} for name in sorted(controller.CONTROLS)]
        next(row for row in rows if row["control"] == "real_session_expiry_denied").update(
            lifetime_seconds=900, clock_or_database_time_changed=False
        )
        next(
            row for row in rows if row["control"] == "provider_signing_key_rotation_admitted"
        ).update(
            provider_component_status=201,
            new_signing_key_active=True,
            new_key_absent_from_startup_jwks=True,
            bounded_jwks_refresh_required=True,
        )
        next(row for row in rows if row["control"] == "http_cookie_and_header_policy").update(
            session_cookie={"secure": True, "http_only": True, "same_site": "None"},
            csrf_cookie={"secure": True, "http_only": False, "same_site": "Strict"},
            browser_engine=False,
        )
        value = {
            "run_id": RUN,
            "passed": True,
            "native_keycloak": True,
            "server_stopped": True,
            "phase": "complete",
            "execution": {
                "passed": True,
                "native_keycloak": True,
                "requests": 112,
                "case_evidence_source": "synthetic_demo",
                "remediation_verification_exercised": False,
                "browser_automation": False,
                "mocked_token_responses": False,
                "host_trust_changed": False,
                "controls": rows,
            },
        }
        with patch.object(
            controller,
            "read_json",
            side_effect=lambda path, *_: kernel() if path.name == "identity-kernel.json" else value,
        ):
            self.assertEqual(
                controller.native_receipt(DIRECTORY, RUN)["execution"], value["execution"]
            )
        for transform in (
            lambda data: data.update(passed=False),
            lambda data: data["execution"].update(mocked_token_responses=True),
            lambda data: data["execution"]["controls"].pop(),
            lambda data: data["execution"].update(requests=201),
            lambda data: next(
                row
                for row in data["execution"]["controls"]
                if row["control"] == "provider_signing_key_rotation_admitted"
            ).update(new_key_absent_from_startup_jwks=False),
            lambda data: next(
                row
                for row in data["execution"]["controls"]
                if row["control"] == "http_cookie_and_header_policy"
            ).update(session_cookie={"secure": True, "http_only": False, "same_site": "None"}),
            lambda data: next(
                row
                for row in data["execution"]["controls"]
                if row["control"] == "http_cookie_and_header_policy"
            ).update(browser_engine=True),
        ):
            bad = copy.deepcopy(value)
            transform(bad)
            with (
                patch.object(
                    controller,
                    "read_json",
                    side_effect=lambda path, *_, bad=bad: (
                        kernel() if path.name == "identity-kernel.json" else bad
                    ),
                ),
                self.assertRaises(ValueError),
            ):
                controller.native_receipt(DIRECTORY, RUN)

    def test_capacity_preserves_headroom_and_stage_growth(self):
        with (
            patch.object(controller.shutil, "disk_usage") as disk,
            patch.object(controller, "available_memory", return_value=6 * 1024**3),
        ):
            disk.return_value.free = 50 * 1024**3
            with self.assertRaises(ValueError):
                controller.capacity(before_launch=True)
        with (
            patch.object(controller.shutil, "disk_usage") as disk,
            patch.object(controller, "available_memory", return_value=8 * 1024**3),
        ):
            disk.return_value.free = 40 * 1024**3
            with self.assertRaises(ValueError):
                controller.capacity(45 * 1024**3)


class ContainerdImageInspection(unittest.TestCase):
    """Docker's containerd store omits empty config keys and reports target digests."""

    def inspection(self, component, image_id):
        reference = host.IMAGES[component]
        return json.dumps(
            {
                "id": image_id,
                "os": "linux",
                "architecture": "amd64",
                "digests": [reference],
                "entrypoint": ["/opt/keycloak/bin/kc.sh"] if component == "keycloak" else None,
                "environment": ["PATH=/usr/local/bin:/usr/bin"],
                "workdir": None,
                "volumes": {"/var/lib/postgresql/data": {}} if component == "database" else None,
            }
        )

    def run_inspection(self, keycloak_id):
        pinned = {
            name: "sha256:" + ref.rsplit("@sha256:", 1)[1] for name, ref in host.IMAGES.items()
        }
        replies = {
            ref: self.inspection(name, keycloak_id if name == "keycloak" else pinned[name])
            for name, ref in host.IMAGES.items()
        }
        templates = []

        def request(docker, run, workspace, arguments, timeout=10):
            templates.append(arguments[-1])
            return replies[arguments[2]]

        with patch.object(host, "request", side_effect=request):
            result = host.inspect_images(Path("docker.exe"), RUN, PROJECT)
        self.assertTrue(all('index .Config "Entrypoint"' in value for value in templates))
        self.assertTrue(all('index .Config "WorkingDir"' in value for value in templates))
        return result

    def test_pinned_target_digest_and_reviewed_config_digest_are_accepted(self):
        target = "sha256:" + host.IMAGES["keycloak"].rsplit("@sha256:", 1)[1]
        config = "sha256:43ebe9d4e97c2e5483b7637edf474e6adc1bbf4832a7396686cf90259c396d42"
        for image_id in (target, config):
            with self.subTest(image_id=image_id):
                self.assertEqual(self.run_inspection(image_id)["keycloak"]["id"], image_id)

    def test_other_keycloak_identity_is_rejected(self):
        with self.assertRaises(host.base.LabControlError):
            self.run_inspection("sha256:" + "9" * 64)


if __name__ == "__main__":
    unittest.main()


class RealBrowserReceipt(unittest.TestCase):
    def setUp(self):
        import shutil
        import uuid

        self.root = PROJECT / "var/tests" / ("identity-browser-" + uuid.uuid4().hex)
        (self.root / "evidence").mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.root)

    def value(self):
        rows = [{"control": name, "passed": True} for name in controller.BROWSER_CONTROLS]
        rows[0].update(
            keyboard_activation=True,
            typed_credentials=True,
            tls_verified_by_spki_pin=True,
            factors=["password", "totp"],
        )
        rows[1].update(
            cookies={
                "session": {"secure": True, "http_only": True, "same_site": "None"},
                "csrf": {"secure": True, "http_only": False, "same_site": "Strict"},
            },
            session_hidden_from_script=True,
        )
        return {
            "schema_version": 1,
            "run_id": RUN,
            "passed": True,
            "browser_engine": "chromium",
            "browser_version": "153.0.8010.12",
            "controls": rows,
        }

    def check(self, value, recorded=None):
        raw = json.dumps(value).encode()
        (self.root / "evidence/identity-browser.json").write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        return controller.browser_receipt(
            self.root, RUN, recorded or {"passed": True, "sha256": digest}
        )

    def test_closed_browser_result_is_bound_to_the_runner_digest(self):
        self.assertTrue(self.check(self.value())["passed"])
        with self.assertRaises(ValueError):
            self.check(self.value(), {"passed": True, "sha256": "0" * 64})
        for change in (
            lambda v: v["controls"].pop(),
            lambda v: v["controls"][2].update(passed=False),
            lambda v: v["controls"][0].update(tls_verified_by_spki_pin=False),
            lambda v: v["controls"][1].update(session_hidden_from_script=False),
            lambda v: v["controls"][1]["cookies"]["session"].update(http_only=False),
            lambda v: v.update(run_id="b" * 32),
            lambda v: v.update(browser_engine="modeled"),
        ):
            value = self.value()
            change(value)
            with self.assertRaises(ValueError):
                self.check(value)
