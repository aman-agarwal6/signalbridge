"""Native lifecycle isolation with fake HTTP/processes and synthetic runtime files only."""

import errno
import importlib.util
import json
import os
import shutil
import stat
import sys
import urllib.error
import uuid
from contextlib import contextmanager, redirect_stdout
from io import StringIO
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from bridge.runtime_identity import runtime_file, workspace_id
from scripts import sb, serve


def forbidden(*args, **kwargs):
    raise AssertionError("Lifecycle tests must never open real connections or processes.")


class FakeResponse:
    def __init__(self, body, *, status=200, url=sb.HEALTH_URL):
        self.body = body
        self.status = status
        self.url = url
        self.reads = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def geturl(self):
        return self.url

    def read(self, limit):
        self.reads.append(limit)
        return self.body[:limit]


class LifecycleTests(TestCase):
    def setUp(self):
        self.test_root = sb.ROOT / "var/tests"
        self.root = self.test_root / ("lifecycle-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup)
        self.patches = [
            patch.object(sb, "ROOT", self.root),
            patch.object(serve, "ROOT", self.root),
            patch.dict(os.environ, {}, clear=True),
            patch("socket.socket", forbidden),
            patch.object(sb.subprocess, "Popen", forbidden),
            patch.object(sb.subprocess, "run", forbidden),
            patch.object(sb.time, "sleep", forbidden),
        ]
        for guard in self.patches:
            guard.start()
            self.addCleanup(guard.stop)

    def cleanup(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.test_root.resolve()) or not target.name.startswith(
            "lifecycle-"
        ):
            raise RuntimeError("Unsafe lifecycle test cleanup target.")
        shutil.rmtree(target)

    def healthy(self, **changes):
        value = {
            "service": "signalbridge",
            "status": "running",
            "workspace_id": workspace_id(self.root),
        }
        value.update(changes)
        return FakeResponse(json.dumps(value).encode("utf-8"))

    def probe(self, response):
        opener = Mock()
        if isinstance(response, BaseException):
            opener.open.side_effect = response
        else:
            opener.open.return_value = response
        return patch.object(sb.urllib.request, "build_opener", return_value=opener), opener

    @contextmanager
    def fake_server_dependencies(self, create_server):
        modules = {}
        for name, members in (
            ("django", {"setup": Mock()}),
            ("django.conf", {"settings": SimpleNamespace(LOCAL=True)}),
            ("django.contrib.staticfiles.handlers", {"StaticFilesHandler": lambda app: app}),
            ("django.db", {"close_old_connections": Mock()}),
            ("waitress", {"create_server": create_server}),
            ("bridge.worker", {"drain": forbidden}),
            ("config.wsgi", {"application": object()}),
        ):
            module = ModuleType(name)
            module.__dict__.update(members)
            modules[name] = module
        with patch.dict(sys.modules, modules):
            yield

    def test_workspace_identity_is_stable_but_fresh_checkout_location_differs(self):
        copy = self.root / "other-checkout"
        copy.mkdir()
        first = workspace_id(self.root)
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertEqual(first, workspace_id(self.root / "."))
        self.assertNotEqual(first, workspace_id(copy))
        self.assertNotIn(str(self.root), first)

    def test_matching_health_is_bounded_closed_and_uses_no_proxy_or_redirect_handler(self):
        response = self.healthy()
        fake, opener = self.probe(response)
        with fake as factory:
            self.assertTrue(sb.probe_server())
        handlers = factory.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], sb.NoHealthRedirect)
        self.assertEqual(opener.open.call_args.args[0].full_url, sb.HEALTH_URL)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 3)
        self.assertEqual(response.reads, [sb.MAX_HEALTH_BYTES + 1])
        self.assertTrue(response.closed)

    def test_connection_refused_is_the_only_absent_server_state(self):
        error = urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, "refused"))
        fake, _ = self.probe(error)
        with fake:
            self.assertFalse(sb.probe_server())

    def test_timeout_unknown_network_error_and_http_error_refuse_startup(self):
        errors = (
            TimeoutError("private-sentinel"),
            urllib.error.URLError(TimeoutError("private-sentinel")),
            urllib.error.URLError("private-sentinel"),
            urllib.error.HTTPError(sb.HEALTH_URL, 404, "private-sentinel", {}, None),
        )
        for error in errors:
            fake, _ = self.probe(error)
            with self.subTest(error=type(error).__name__), fake:
                with self.assertRaises(SystemExit) as rejected:
                    sb.up()
                self.assertNotIn("private-sentinel", str(rejected.exception))
        self.assertFalse((self.root / "var").exists())

    def test_foreign_or_legacy_service_is_never_reused_or_replaced(self):
        responses = (
            self.healthy(workspace_id="a" * 64),
            FakeResponse(b'{"service":"signalbridge","status":"running"}'),
            self.healthy(service="another-service"),
            self.healthy(status="starting"),
        )
        for response in responses:
            fake, _ = self.probe(response)
            with self.subTest(body=response.body), fake, self.assertRaises(SystemExit):
                sb.up()
        self.assertFalse((self.root / "var").exists())

    def test_malformed_oversized_redirected_and_nonobject_health_fail_closed(self):
        responses = (
            FakeResponse(b"x" * (sb.MAX_HEALTH_BYTES + 50)),
            FakeResponse(b"not JSON"),
            FakeResponse(b"[]"),
            FakeResponse(b"null"),
            FakeResponse(b"\xff"),
            FakeResponse(b"{}", status=302),
            FakeResponse(self.healthy().body, url="http://remote.invalid/health/"),
        )
        for response in responses:
            fake, _ = self.probe(response)
            with self.subTest(status=response.status, size=len(response.body)), fake:
                with self.assertRaises(SystemExit):
                    sb.up()
            self.assertTrue(response.closed)
            self.assertTrue(all(size <= sb.MAX_HEALTH_BYTES + 1 for size in response.reads))

    def test_redirect_handler_refuses_without_following_destination(self):
        request = sb.urllib.request.Request(sb.HEALTH_URL)
        with self.assertRaises(urllib.error.HTTPError) as error:
            sb.NoHealthRedirect().redirect_request(
                request, None, 302, "redirect", {}, "http://remote.invalid/"
            )
        error.exception.close()

    def test_matching_existing_workspace_returns_without_launching_a_process(self):
        fake, _ = self.probe(self.healthy())
        output = StringIO()
        with fake, redirect_stdout(output):
            sb.up()
        self.assertIn("This SignalBridge checkout", output.getvalue())
        self.assertFalse((self.root / "var").exists())

    def test_startup_requires_own_health_and_uses_only_local_child(self):
        process = Mock()
        process.poll.return_value = None
        output = StringIO()
        with (
            patch.object(sb, "probe_server", side_effect=[False, True]),
            patch.object(sb.subprocess, "Popen", return_value=process) as launch,
            redirect_stdout(output),
        ):
            sb.up()
        self.assertEqual(launch.call_args.args[0], [sb.sys.executable, "-B", "scripts/serve.py"])
        self.assertEqual(launch.call_args.kwargs["cwd"], self.root)
        self.assertEqual(launch.call_args.kwargs["env"]["SB_MODE"], "local")
        self.assertTrue(launch.call_args.kwargs["stdout"].closed)
        self.assertIn("Open http://127.0.0.1:8741/", output.getvalue())
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

    def test_foreign_service_appearing_during_startup_is_not_reported_ready_or_killed(self):
        refused = urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, "refused"))
        opener = Mock()
        opener.open.side_effect = [refused, self.healthy(workspace_id="a" * 64)]
        process = Mock()
        process.poll.return_value = None
        output = StringIO()
        with (
            patch.object(sb.urllib.request, "build_opener", return_value=opener),
            patch.object(sb.subprocess, "Popen", return_value=process),
            redirect_stdout(output),
        ):
            with self.assertRaises(SystemExit):
                sb.up()
        self.assertNotIn("Open http://", output.getvalue())
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

    def test_dead_child_never_reports_success(self):
        process = Mock()
        process.poll.return_value = 1
        with (
            patch.object(sb, "probe_server", return_value=False),
            patch.object(sb.subprocess, "Popen", return_value=process),
        ):
            with self.assertRaisesRegex(SystemExit, "did not start"):
                sb.up()

    def test_polling_is_bounded_and_does_not_claim_health_after_timeout(self):
        process = Mock()
        process.poll.return_value = None
        with (
            patch.object(sb, "probe_server", return_value=False) as probe,
            patch.object(sb.subprocess, "Popen", return_value=process),
            patch.object(sb.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(SystemExit, "not confirmed"):
                sb.up()
        self.assertEqual(probe.call_count, 41)
        self.assertEqual(sleep.call_count, 40)
        process.kill.assert_not_called()

    def test_down_only_creates_current_checkouts_marker_and_preserves_existing_data(self):
        other = self.root / "other-checkout/var"
        other.mkdir(parents=True)
        sentinel = other / "stop.request"
        sentinel.write_text("unrelated", encoding="utf-8")
        with patch.object(sb, "probe_server", forbidden), redirect_stdout(StringIO()):
            sb.down()
        self.assertTrue((self.root / "var/stop.request").is_file())
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "unrelated")
        (self.root / "var/stop.request").write_text("existing request", encoding="utf-8")
        with redirect_stdout(StringIO()):
            sb.down()
        self.assertEqual(
            (self.root / "var/stop.request").read_text(encoding="utf-8"), "existing request"
        )
        self.assertFalse((self.root / "var/server.pid").exists())

    def test_down_rejects_linked_runtime_directory_before_writing(self):
        original = Path.is_symlink
        linked = self.root / "var"
        with patch.object(Path, "is_symlink", lambda path: path == linked or original(path)):
            with self.assertRaisesRegex(SystemExit, "redirected"):
                sb.down()
        self.assertFalse(linked.exists())

    def test_stop_marker_and_server_log_links_are_rejected_before_mutation(self):
        (self.root / "var").mkdir()
        original = Path.is_symlink
        for name, operation in (("stop.request", sb.down), ("server.log", sb.up)):
            target = self.root / "var" / name
            target.write_text("sentinel", encoding="utf-8")
            with (
                self.subTest(name=name),
                patch.object(
                    Path, "is_symlink", lambda path, target=target: path == target or original(path)
                ),
            ):
                with self.assertRaises(SystemExit):
                    operation()
            self.assertEqual(target.read_text(encoding="utf-8"), "sentinel")

    def test_runtime_reparse_attributes_and_unexpected_file_types_are_rejected(self):
        directory = self.root / "var"
        directory.mkdir()
        original = Path.lstat

        def metadata(path, *args, **kwargs):
            if path == directory:
                return SimpleNamespace(st_file_attributes=1024, st_mode=stat.S_IFDIR)
            return original(path, *args, **kwargs)

        with patch.object(Path, "lstat", metadata), self.assertRaisesRegex(ValueError, "reparse"):
            runtime_file(self.root, "stop.request")
        (directory / "stop.request").mkdir()
        with self.assertRaisesRegex(ValueError, "file type"):
            runtime_file(self.root, "stop.request")

    def test_runtime_helper_accepts_only_fixed_names_and_does_not_create_on_inspection(self):
        for name in ("../outside", "server.pid", "database.sqlite3", "arbitrary"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                runtime_file(self.root, name, create_directory=True)
        self.assertEqual(runtime_file(self.root, "stop.request"), self.root / "var/stop.request")
        self.assertFalse((self.root / "var").exists())

    def test_server_import_has_no_startup_side_effects(self):
        specification = importlib.util.spec_from_file_location("serve_import_audit", serve.__file__)
        module = importlib.util.module_from_spec(specification)
        with (
            patch.object(serve.threading, "Thread", forbidden),
            patch.object(Path, "read_text", forbidden),
            patch.object(Path, "unlink", forbidden),
        ):
            specification.loader.exec_module(module)
        self.assertTrue(callable(module.main))
        self.assertFalse((self.root / "var").exists())

    def test_server_rejects_redirected_paths_before_django_or_key_reads(self):
        original = Path.is_symlink
        linked = self.root / "var"
        with (
            patch.object(Path, "is_symlink", lambda path: path == linked or original(path)),
            patch.object(Path, "read_text", forbidden),
        ):
            with self.assertRaisesRegex(SystemExit, "redirected"):
                serve.main()
        self.assertFalse(linked.exists())

    def test_server_rejects_nonlocal_overrides_before_runtime_mutation(self):
        for environment in (
            {"SB_MODE": "production"},
            {"SB_DB_HOST": "remote.invalid"},
            {"DJANGO_SETTINGS_MODULE": "foreign.settings"},
            {"SB_PORT": "8742"},
        ):
            with self.subTest(environment=environment), patch.dict(os.environ, environment):
                with self.assertRaises(SystemExit):
                    serve.main()
        self.assertFalse((self.root / "var").exists())

    def test_server_only_clears_or_observes_its_own_plain_stop_marker(self):
        marker = runtime_file(self.root, "stop.request", create_directory=True)
        marker.write_text("synthetic stop", encoding="utf-8")
        self.assertTrue(serve.stop_requested())
        serve.clear_stop_request()
        self.assertFalse(serve.stop_requested())
        marker.write_text("sentinel", encoding="utf-8")
        original = Path.is_symlink
        with patch.object(Path, "is_symlink", lambda path: path == marker or original(path)):
            with self.assertRaises(SystemExit):
                serve.clear_stop_request()
            with self.assertRaises(SystemExit):
                serve.stop_requested()
        self.assertEqual(marker.read_text(encoding="utf-8"), "sentinel")

    def test_failed_server_port_bind_does_not_clear_existing_stop_request(self):
        marker = runtime_file(self.root, "stop.request", create_directory=True)
        marker.write_text("pending stop", encoding="utf-8")
        create = Mock(side_effect=OSError("synthetic occupied port"))
        with (
            self.fake_server_dependencies(create),
            patch.object(serve.threading, "Thread", forbidden),
        ):
            with self.assertRaises(OSError):
                serve.main()
        self.assertEqual(marker.read_text(encoding="utf-8"), "pending stop")
        self.assertEqual(create.call_args.kwargs["host"], "127.0.0.1")
        self.assertEqual(create.call_args.kwargs["port"], 8741)

    def test_redirected_marker_after_bind_closes_only_just_created_server(self):
        server = Mock()
        with (
            self.fake_server_dependencies(Mock(return_value=server)),
            patch.object(serve, "clear_stop_request", side_effect=SystemExit("redirected marker")),
            patch.object(serve.threading, "Thread", forbidden),
        ):
            with self.assertRaises(SystemExit):
                serve.main()
        server.close.assert_called_once_with()
        server.run.assert_not_called()
