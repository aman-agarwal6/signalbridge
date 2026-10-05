"""Shuffle lab dispatcher, receiver seed profile and host isolation checks; no VM or Docker."""

import importlib.util
import json
import os
import re
import sys
import types
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase

from bridge.service_api import request_signature

LAB = Path(__file__).resolve().parents[1] / "integrations/shuffle/lab"


def load(name):
    if name == "dispatcher" and "requests" not in sys.modules:
        sys.modules["requests"] = types.ModuleType("requests")
    spec = importlib.util.spec_from_file_location("shuffle_lab_" + name, LAB / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DispatcherTests(SimpleTestCase):
    def setUp(self):
        self.dispatcher = load("dispatcher")
        self.secret = "nonfunctional-shuffle-lab-fixture-" + "x" * 40

    def test_signatures_match_the_receiver_verifier_exactly(self):
        with patch.dict(os.environ, {"SB_SERVICE_SHUFFLE_TASK": self.secret}):
            argument, headers = self.dispatcher.task_request(
                "11111111-2222-4333-8444-555555555555",
                1,
                "a" * 64,
                "21111111-2222-4333-8444-555555555555",
            )
        path = "/api/v1/cases/11111111-2222-4333-8444-555555555555/review-task/"
        expected = request_signature(
            self.secret,
            headers["X-SB-Service-Key"],
            headers["X-SB-Service-Nonce"],
            headers["X-SB-Service-Time"],
            "POST",
            path,
            argument["body"].encode(),
        )
        self.assertEqual(headers["X-SB-Service-Signature"], expected)
        self.assertEqual(argument["url"], "http://signalbridge:8000" + path)

    def test_task_body_is_the_closed_review_request(self):
        with patch.dict(os.environ, {"SB_SERVICE_SHUFFLE_TASK": self.secret}):
            argument, _ = self.dispatcher.task_request(
                "c" * 8 + "-cccc-4ccc-8ccc-" + "c" * 12,
                3,
                "b" * 64,
                "d" * 8 + "-dddd-4ddd-8ddd-" + "d" * 12,
            )
        body = json.loads(argument["body"])
        self.assertEqual(
            set(body), {"case_version", "evidence_sha256", "idempotency_key", "task_kind"}
        )
        self.assertEqual(body["task_kind"], "review_case_evidence")
        self.assertEqual(argument["timeout"], "3")

    def test_signed_body_is_exactly_what_shuffles_http_app_sends(self):
        # The pinned HTTP app sends json.dumps(ast.literal_eval(body)); the signature covers
        # the body bytes, so the signed form must survive that rewrite unchanged.
        import ast

        with patch.dict(os.environ, {"SB_SERVICE_SHUFFLE_TASK": self.secret}):
            argument, headers = self.dispatcher.task_request(
                "c" * 8 + "-cccc-4ccc-8ccc-" + "c" * 12,
                3,
                "b" * 64,
                "d" * 8 + "-dddd-4ddd-8ddd-" + "d" * 12,
            )
        sent = json.dumps(ast.literal_eval(argument["body"]))
        self.assertEqual(sent, argument["body"])
        path = "/api/v1/cases/" + "c" * 8 + "-cccc-4ccc-8ccc-" + "c" * 12 + "/review-task/"
        expected = request_signature(
            self.secret,
            "shuffle-task",
            headers["X-SB-Service-Nonce"],
            headers["X-SB-Service-Time"],
            "POST",
            path,
            sent.encode(),
        )
        self.assertEqual(headers["X-SB-Service-Signature"], expected)

    def test_replayed_headers_reuse_the_exact_nonce(self):
        with patch.dict(os.environ, {"SB_SERVICE_SHUFFLE_TASK": self.secret}):
            _, first = self.dispatcher.task_request(
                "e" * 8 + "-eeee-4eee-8eee-" + "e" * 12,
                1,
                "a" * 64,
                "f" * 8 + "-ffff-4fff-8fff-" + "f" * 12,
            )
            replay, again = self.dispatcher.task_request(
                "e" * 8 + "-eeee-4eee-8eee-" + "e" * 12,
                1,
                "a" * 64,
                "f" * 8 + "-ffff-4fff-8fff-" + "f" * 12,
                headers=first,
            )
        self.assertIs(again, first)
        self.assertIn("X-SB-Service-Nonce: " + first["X-SB-Service-Nonce"], replay["headers"])


class ReceiverSeedTests(TestCase):
    def test_seed_creates_scoped_keys_without_printing_secrets(self):
        from io import StringIO

        from bridge.models import Investigation, ServiceCredential

        seed = load("receiver_seed")
        output = StringIO()
        secrets = {
            "SB_SERVICE_SHUFFLE_READ": "nonfunctional-read-fixture-" + "r" * 32,
            "SB_SERVICE_SHUFFLE_TASK": "nonfunctional-task-fixture-" + "t" * 32,
        }
        with (
            patch.dict(os.environ, secrets),
            patch("django.core.management.call_command"),
            patch("sys.stdout", output),
        ):
            seed.main()
        facts = json.loads(output.getvalue())["cases"]
        self.assertEqual(set(facts), {"documents", "expenses"})
        self.assertEqual(Investigation.objects.count(), 2)
        keys = ServiceCredential.objects.order_by("key_id")
        self.assertEqual(
            [(k.key_id, k.capability, k.integration.slug) for k in keys],
            [
                ("shuffle-read", "read_case_evidence", "documents"),
                ("shuffle-task", "create_review_task", "documents"),
            ],
        )
        for value in secrets.values():
            self.assertNotIn(value, output.getvalue())


class HostIsolationTests(SimpleTestCase):
    def setUp(self):
        self.host = load("host_controller")
        self.info = {"VMState": "poweroff", **{f"nic{n}": "none" for n in range(1, 9)}}

    def test_powered_off_vm_without_adapters_or_shares_is_accepted(self):
        self.host.assert_isolated(self.info, "poweroff")

    def test_network_adapter_shared_folder_or_running_vm_is_refused(self):
        for change in (
            {"nic3": "nat"},
            {"SharedFolderNameMachineMapping1": "host"},
            {"VMState": "running"},
        ):
            with self.subTest(change=change), self.assertRaises(self.host.HostError):
                self.host.assert_isolated({**self.info, **change}, "poweroff")

    def test_boot_disk_must_sit_on_the_ahci_controller(self):
        ahci = {
            "storagecontrollername0": "IDE",
            "storagecontrollertype0": "PIIX4",
            "storagecontrollername1": "SATA",
            "storagecontrollertype1": "IntelAhci",
            "SATA-0-0": "C:\\lab\\vm\\" + self.host.BOOT_DISK,
        }
        self.host.assert_boot_disk(ahci)
        lsi = {
            "storagecontrollername1": "SCSI",
            "storagecontrollertype1": "LsiLogic",
            "SCSI-0-0": "C:\\lab\\vm\\" + self.host.BOOT_DISK,
        }
        for info in (lsi, {**ahci, "SATA-0-0": "none"}):
            with self.subTest(info=info), self.assertRaises(self.host.HostError):
                self.host.assert_boot_disk(info)

    def test_guest_reports_started_before_any_other_step(self):
        source = (LAB / "guest_workflow.py").read_text()
        body = source[source.index("def main():") :]
        self.assertLess(body.index('serial({"kind": "started"})'), body.index("unpack()"))
        self.assertLess(self.host.BOOT_SECONDS, self.host.RUN_SECONDS)

    def boot_with(self, reports_on_attempt):
        """Run host.boot with VirtualBox mocked; the guest reports on the given attempt."""
        import threading

        calls, lines, receipt = [], [], {}

        def vbox(*args, **kwargs):
            calls.append(args[0] if args[0] == "startvm" else args[2])
            if args[0] == "startvm" and calls.count("startvm") == reports_on_attempt:
                lines.append({"kind": "started"})

        with (
            patch.object(self.host, "vbox", vbox),
            patch.object(self.host, "vm_info", lambda: self.info),
            patch.object(self.host, "BOOT_SECONDS", 0),
        ):
            try:
                self.host.boot(lines, threading.Event(), receipt)
            except self.host.HostError as error:
                return calls, receipt, str(error)
        return calls, receipt, None

    def test_a_stalled_boot_is_powered_off_and_retried(self):
        calls, receipt, error = self.boot_with(reports_on_attempt=2)
        self.assertEqual(calls, ["startvm", "poweroff", "startvm"])
        self.assertEqual(receipt["boot_attempts"], 2)
        self.assertIsNone(error)

    def test_boot_gives_up_after_the_bounded_attempts(self):
        calls, receipt, error = self.boot_with(reports_on_attempt=99)
        self.assertEqual(calls, ["startvm", "poweroff"] * self.host.BOOT_ATTEMPTS)
        self.assertEqual(error, "guest_not_started")
        self.assertLess(
            self.host.BOOT_ATTEMPTS * (self.host.BOOT_SECONDS + 60), self.host.RUN_SECONDS
        )

    def test_side_loaded_receiver_image_is_the_host_pin_found_by_id(self):
        source = (LAB / "guest_workflow.py").read_text()
        self.assertIn('"python": "' + self.host.PYTHON_IMAGE + '"', source)
        self.assertIn('require(inventory["python"] == PYTHON_ID, "image_identity_python")', source)
        self.assertNotIn('IMAGES["python"],', source)

    def test_every_named_guest_container_is_cleared_before_a_rerun(self):
        source = (LAB / "guest_workflow.py").read_text()
        names = set(re.findall(r'"--name",\s*"([a-z-]+)"', source))
        own = re.search(r"OWN_CONTAINERS = \(([^)]*)\)", source).group(1)
        self.assertEqual(names, set(re.findall(r'"([a-z-]+)"', own)))
        self.assertEqual(len(names), 5)

    def test_seed_keeps_network_disabled_and_powers_off_after_the_run(self):
        self.assertIn("network:\n  config: disabled", self.host.USER_DATA)
        self.assertIn("ExecStopPost=/usr/bin/systemctl --no-block poweroff", self.host.USER_DATA)
        self.assertNotIn("/var/run/docker.sock", self.host.USER_DATA)

    def test_serial_records_are_parsed_from_noisy_bounded_output(self):
        raw = b'boot noise\n\x00\x00{"kind": "summary", "status": "completed"}\nnot json {\n{"kind": "end"}\n'
        rows = self.host.parse_serial(raw)
        self.assertEqual([row["kind"] for row in rows], ["summary", "end"])
        self.assertEqual(self.host.parse_serial(b"x" * (self.host.SERIAL_LIMIT + 10)), [])


class ReadOnlyReceiverSettingsTests(SimpleTestCase):
    """The guest receiver mounts the source read-only and supplies SB_SECRET_KEY."""

    def load(self, **env):
        import shutil
        import subprocess
        import tempfile

        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder, True)
        (folder / "config").mkdir()
        (folder / "config/__init__.py").write_text("", encoding="utf-8")
        shutil.copy2(LAB.parents[2] / "config/settings.py", folder / "config/settings.py")
        clean = {k: v for k, v in os.environ.items() if not k.startswith(("SB_", "DJANGO_"))}
        result = subprocess.run(
            [sys.executable, "-B", "-c", "import config.settings"],
            cwd=folder,
            env={**clean, **env, "PYTHONPATH": str(folder)},
            capture_output=True,
            timeout=60,
        )
        return result, folder / "var/django-secret"

    def test_a_supplied_key_needs_no_local_key_file(self):
        result, key_file = self.load(SB_SECRET_KEY="k" * 64)
        self.assertEqual(result.returncode, 0, result.stderr.decode()[-300:])
        self.assertFalse(key_file.exists())

    def test_without_a_supplied_key_the_local_key_file_is_still_created(self):
        result, key_file = self.load()
        self.assertEqual(result.returncode, 0, result.stderr.decode()[-300:])
        self.assertTrue(key_file.exists())


class GuestRedactionTests(SimpleTestCase):
    """Diagnostics leave the VM over the serial port; credentials must not."""

    def test_credential_values_are_removed_from_guest_diagnostics(self):
        import ast

        source = (LAB / "guest_workflow.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        function = next(n for n in tree.body if getattr(n, "name", "") == "redact")
        namespace = {"re": re}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "guest", "exec"), namespace)
        text = "start\nAuthorization: Bearer abc\nSHUFFLE_APIKEY=k1\nSB_SERVICE_SHUFFLE_TASK secret=s2\nend"
        cleaned = namespace["redact"](text)
        for value in ("abc", "k1", "s2"):
            self.assertNotIn(value, cleaned)
        self.assertTrue(cleaned.startswith("start\n") and cleaned.endswith("\nend"))


class GuestOrborusTests(SimpleTestCase):
    def test_orborus_runs_plain_worker_containers_not_swarm(self):
        # The offline guest is not a swarm manager; swarm mode left every execution unrun.
        source = (LAB / "guest_workflow.py").read_text(encoding="utf-8")
        self.assertNotIn('"SHUFFLE_SWARM_CONFIG=run"', source)
        self.assertIn('"SHUFFLE_AUTO_IMAGE_DOWNLOAD=false"', source)


class DispatcherRecordTests(SimpleTestCase):
    def test_scenarios_arrive_as_separate_lines_and_are_reassembled(self):
        host = load("host_controller")
        raw = (
            b'{"kind": "dispatcher", "workflow_id": "w1", "first_task_id": "t1"}\n'
            b'noise\n{"kind": "scenario", "name": "first", "http_status": 201, "task_id": "t1"}\n'
            b'{"kind": "scenario", "name": "replayed_request", "http_status": 409}\n'
        )
        record = host.dispatcher_record(host.parse_serial(raw))
        self.assertEqual(record["workflow_id"], "w1")
        self.assertEqual(record["scenarios"]["first"], {"http_status": 201, "task_id": "t1"})
        self.assertEqual(record["scenarios"]["replayed_request"]["http_status"], 409)
        self.assertIsNone(host.dispatcher_record([]))
