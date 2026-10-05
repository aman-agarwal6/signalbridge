"""Offline restoration profile and evidence checks; these do not launch containers."""

import hashlib
import json
import shutil
import uuid
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from integrations.enterprise import restoration_controls as controls
from integrations.enterprise import verification as base
from integrations.enterprise.restoration_runner import RestorationError, load_plan

RUN, SOURCE, TOOL = "a" * 32, "b" * 32, "c" * 32
IMAGE = "sha256:" + "d" * 64
ROOT = Path(__file__).resolve().parents[1]


def plan(profile="access"):
    return {
        "run_id": RUN,
        "profile": profile,
        "source_run": SOURCE,
        "tool_run": TOOL,
        "console_events_sha256": "e" * 64,
        "tool_scope_sha256": "f" * 64 if profile == "access" else None,
    }


def archive():
    return {"events": [{}] * 23, "cases": [{}]}


def runner(profile="access"):
    workflow = (
        {
            "retest_check_runs": 1,
            "self_review_denied": True,
            "independent_review": "approved",
            "task_status": "verified",
            "wazuh_case_linked": True,
            "case_page_status": 200,
        }
        if profile == "access"
        else {
            "scoped_check_runs": 2,
            "documents_finding_plugin": "10021",
            "expenses_finding": None,
            "event_bindings": {"documents": 6, "expenses": 2},
        }
    )
    return {
        "passed": True,
        "phase": "complete",
        "run_id": RUN,
        "profile": profile,
        "restored": {"events": 23, "cases": 1, "archive_sha256": "e" * 64},
        "pending_migrations": ["bridge.0042_example"],
        "workflow": workflow,
    }


def parsed():
    labels = {
        "org.signalbridge.enterprise.run": RUN,
        "org.signalbridge.enterprise.scope": controls.SCOPE,
    }
    service = {"read_only": True, "cap_drop": ["ALL"], "labels": labels}
    return {
        "services": {
            "database": {**service, "image": IMAGE},
            "runner": {**service, "image": "sha256:" + "f" * 64},
        },
        "networks": {
            "restoration": {"internal": True, "name": controls.PREFIX + "internal-" + RUN}
        },
        "volumes": {"restored_data": {"name": controls.PREFIX + RUN}},
    }


class RestorationControlTests(SimpleTestCase):
    def setUp(self):
        self.test_root = ROOT / "var/tests"
        self.root = self.test_root / ("enterprise-restoration-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.test_root.resolve()) or not target.name.startswith(
            "enterprise-restoration-"
        ):
            raise RuntimeError("Unsafe test cleanup target.")
        shutil.rmtree(target)

    def test_retained_copy_is_byte_exact_and_excludes_private_credentials(self):
        source = self.root / "retained"
        for relative, raw in (
            ("receipt.json", b"{}"),
            ("evidence/capture.sqlite3", bytes(range(256))),
            ("secrets/console-password", b"synthetic-private-value"),
            ("docker-config/config.json", b"{}"),
        ):
            (source / relative).parent.mkdir(parents=True, exist_ok=True)
            (source / relative).write_bytes(raw)
        result = controls.copy_retained(source, self.root / "copy")
        self.assertEqual(result["files"], 2)
        self.assertEqual(result["bytes"], 2 + 256)
        self.assertEqual(
            (self.root / "copy/evidence/capture.sqlite3").read_bytes(), bytes(range(256))
        )
        self.assertFalse((self.root / "copy/secrets").exists())
        self.assertFalse((self.root / "copy/docker-config").exists())
        again = controls.copy_retained(source, self.root / "copy-2")
        self.assertEqual(again["tree_sha256"], result["tree_sha256"])
        expected = hashlib.sha256()
        for relative in ("evidence/capture.sqlite3", "receipt.json"):
            checksum = hashlib.sha256((source / relative).read_bytes()).hexdigest()
            expected.update(relative.encode() + b"\x00" + checksum.encode() + b"\n")
        self.assertEqual(result["tree_sha256"], expected.hexdigest())
        with self.assertRaises(base.LabControlError):
            controls.copy_retained(source, self.root / "copy")

    def test_copy_and_backup_helpers_never_write_the_original_or_use_a_network(self):
        copy = controls.copy_arguments(RUN, SOURCE, IMAGE)
        self.assertIn(
            "type=volume,src=sb-enterprise-reference-" + SOURCE + ",dst=/from,readonly", copy
        )
        self.assertIn(
            "type=volume,src=" + controls.copy_volume(RUN) + ",dst=/var/lib/postgresql/data", copy
        )
        for arguments in (copy, controls.backup_arguments(RUN, self.root, IMAGE)):
            self.assertEqual(arguments[arguments.index("--network") + 1], "none")
            self.assertIn("--read-only", arguments)
            self.assertEqual(arguments[arguments.index("--cap-drop") + 1], "ALL")
            self.assertEqual(arguments[arguments.index("--user") + 1], "postgres")
            self.assertNotIn("--publish", arguments)
            self.assertNotIn("-p", arguments)
            self.assertNotIn(
                "type=volume,src=sb-enterprise-reference-"
                + SOURCE
                + ",dst=/var/lib/postgresql/data",
                arguments,
            )
        backup = controls.backup_arguments(RUN, self.root, IMAGE)
        self.assertIn("listen_addresses=", backup)
        with self.assertRaises(ValueError):
            controls.copy_arguments("../" + RUN, SOURCE, IMAGE)

    def test_parsed_compose_must_stay_internal_unpublished_and_owned(self):
        images = {"database": IMAGE, "runner": "sha256:" + "f" * 64}
        controls.verify_compose_config(parsed(), images, RUN, self.root)
        for mutate in (
            lambda d: d["services"]["runner"].update(ports=["127.0.0.1:8000:8000"]),
            lambda d: d["services"]["database"].update(read_only=False),
            lambda d: d["services"]["runner"].update(privileged=True),
            lambda d: d["services"].update(extra={}),
            lambda d: d["networks"]["restoration"].update(internal=False),
            lambda d: d["volumes"]["restored_data"].update(
                name="sb-enterprise-reference-" + SOURCE
            ),
            lambda d: d["services"]["runner"]["labels"].update(
                {"org.signalbridge.enterprise.run": SOURCE}
            ),
        ):
            changed = deepcopy(parsed())
            mutate(changed)
            with self.assertRaises(base.LabControlError):
                controls.verify_compose_config(changed, images, RUN, self.root)

    def test_capacity_keeps_reserve_growth_and_memory_headroom(self):
        gib = base.GIB
        controls.check_capacity(60 * gib, 8 * gib, 60 * gib)
        for disk, memory, initial in (
            (30 * gib, 8 * gib, 30 * gib),
            (52 * gib, 8 * gib, 60 * gib),
            (60 * gib, 4 * gib, 60 * gib),
        ):
            with self.subTest(disk=disk, memory=memory), self.assertRaises(base.LabControlError):
                controls.check_capacity(disk, memory, initial)

    def test_source_volume_must_carry_its_run_labels_and_be_unused(self):
        name = "sb-enterprise-reference-" + SOURCE
        good = {
            "Name": name,
            "Driver": "local",
            "Scope": "local",
            "Labels": {
                "org.signalbridge.enterprise.run": SOURCE,
                "org.signalbridge.enterprise.scope": controls.SOURCE_SCOPE,
            },
        }

        def answers(volume, running=""):
            return lambda docker, arguments, timeout=15: (
                json.dumps(volume) if arguments[0] == "volume" else running
            )

        with patch.object(controls.base, "docker_result", side_effect=answers(good)):
            self.assertTrue(controls.verify_source_volume("docker", SOURCE)["labels_verified"])
        foreign = deepcopy(good)
        foreign["Labels"]["org.signalbridge.enterprise.run"] = TOOL
        for value, running in ((foreign, ""), (good, "e" * 64)):
            with (
                patch.object(controls.base, "docker_result", side_effect=answers(value, running)),
                self.assertRaises(base.LabControlError),
            ):
                controls.verify_source_volume("docker", SOURCE)

    def test_only_exactly_labelled_components_are_owned(self):
        identifier = "e" * 64

        def labels(value):
            return lambda docker, arguments, timeout=15: json.dumps(value)

        owned = {**controls.labels(RUN, "backup")}
        with patch.object(controls.base, "docker_result", side_effect=labels(owned)):
            self.assertEqual(controls.role_of("docker", identifier, RUN), "backup")
        for value in (
            {**owned, "org.signalbridge.enterprise.scope": "reference-access-verification"},
            {**owned, "org.signalbridge.enterprise.run": SOURCE},
            {**owned, "org.signalbridge.enterprise.role": "scanner"},
        ):
            with (
                patch.object(controls.base, "docker_result", side_effect=labels(value)),
                self.assertRaises(base.LabControlError),
            ):
                controls.role_of("docker", identifier, RUN)

    def test_runner_evidence_needs_exact_counts_and_completed_workflow(self):
        for profile in ("access", "header"):
            controls.validate_runner(runner(profile), plan(profile), archive())
        cases = [
            lambda v: v.update(passed=False),
            lambda v: v.update(profile="header"),
            lambda v: v["restored"].update(events=22),
            lambda v: v["restored"].update(archive_sha256="0" * 64),
            lambda v: v.update(pending_migrations=["bridge; DROP TABLE"]),
            lambda v: v["workflow"].update(self_review_denied=False),
            lambda v: v["workflow"].update(independent_review="rejected"),
            lambda v: v["workflow"].update(wazuh_case_linked=False),
        ]
        for mutate in cases:
            value = runner()
            mutate(value)
            with self.assertRaises(base.LabControlError):
                controls.validate_runner(value, plan(), archive())
        value = runner("header")
        value["workflow"]["expenses_finding"] = {"plugin_id": "10021"}
        with self.assertRaises(base.LabControlError):
            controls.validate_runner(value, plan("header"), archive())

    def test_runner_plan_is_closed(self):
        self.assertEqual(load_plan(json.dumps(plan())), plan())
        for value in (
            {**plan(), "extra": 1},
            {**plan(), "profile": "production"},
            {**plan(), "source_run": "../" + SOURCE[3:]},
            {**plan(), "console_events_sha256": "z" * 64},
            {**plan(), "tool_scope_sha256": None},
            {**plan("header"), "tool_scope_sha256": "f" * 64},
        ):
            with self.assertRaises(RestorationError):
                load_plan(json.dumps(value))

    def test_compose_profile_text_has_no_published_ports_and_an_internal_network(self):
        text = (ROOT / "integrations/enterprise/compose.restoration.yaml").read_text(
            encoding="utf8"
        )
        self.assertNotIn("ports:", text)
        self.assertIn("internal: true", text)
        self.assertNotIn("sb-enterprise-reference-", text)
        self.assertEqual(text.count("read_only: true"), 2)
        self.assertEqual(text.count("cap_drop: [ALL]"), 2)


class RestorationRuntimeTests(SimpleTestCase):
    directory = Path("C:/lab/var/enterprise/runs") / RUN

    def mounts(self, secrets=("console_password", "restoration_plan", "tool_scope"), rw=False):
        def bind(source, destination, writable):
            return {
                "Type": "bind",
                "Source": str(source),
                "Destination": destination,
                "RW": writable,
            }

        rows = [
            bind(self.directory / "source", "/workspace", False),
            bind(self.directory / "wheels", "/wheels", False),
            bind(self.directory / "evidence", "/evidence", True),
            bind(self.directory / "r/s", "/workspace/var/enterprise/runs/" + SOURCE, False),
            bind(self.directory / "r/t", "/workspace/var/enterprise/runs/" + TOOL, False),
        ]
        rows += [
            bind(self.directory / "secrets" / name, "/run/secrets/" + name, rw) for name in secrets
        ]
        return rows

    def inspect(self, mounts):
        fields = {
            "image": IMAGE,
            "memory": 512 * 1024**2,
            "pids": 96,
            "readonly": True,
            "privileged": False,
            "caps": ["ALL"],
            "security": ["no-new-privileges:true"],
            "ports": {},
            "networks": {controls.PREFIX + "internal-" + RUN: {}},
            "network_mode": controls.PREFIX + "internal-" + RUN,
            "mounts": mounts,
            "user": "10001:10001",
        }
        labels = {**controls.labels(RUN, "copy"), "org.signalbridge.enterprise.role": "runner"}

        def answer(docker, arguments, timeout=15):
            if arguments[:1] == ["network"]:
                return "true"
            if "{{json .Config.Labels}}" in arguments:
                return json.dumps(labels)
            return json.dumps(fields)

        return answer

    def test_runner_accepts_only_its_exact_read_only_secrets(self):
        identifier = "e" * 64
        with patch.object(controls.base, "docker_result", side_effect=self.inspect(self.mounts())):
            self.assertTrue(
                controls.verify_runtime("docker", identifier, RUN, self.directory, IMAGE, "runner")
            )
        for mounts in (
            self.mounts(secrets=("console_password", "restoration_plan")),
            self.mounts(secrets=("console_password", "restoration_plan", "tool_scope", "extra")),
            self.mounts(rw=True),
        ):
            with (
                patch.object(controls.base, "docker_result", side_effect=self.inspect(mounts)),
                self.assertRaises(base.LabControlError),
            ):
                controls.verify_runtime("docker", identifier, RUN, self.directory, IMAGE, "runner")
