"""Native runner guard/failure controls with mocks; no subprocesses or services."""

import json
import os
import subprocess
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from integrations.enterprise.reference_native_support import (
    verify_database_boundary,
    verify_database_identity,
)
from integrations.enterprise.reference_runner import (
    ReadinessFailure,
    component_environment,
    operate,
    runtime_gate,
    stop_processes,
    validate_wazuh_export,
    wait_for_tls,
)


class ReferenceRunnerTests(SimpleTestCase):
    def readiness(
        self,
        *,
        ready_after=0,
        response_status=200,
        response_body=None,
        source_reply=None,
        exited=False,
    ):
        clock = [0.0]
        client = Mock()
        client.getresponse.return_value = Mock(
            status=response_status,
            read=Mock(
                return_value=response_body
                or b'{"service":"signalbridge","status":"running","workspace_id":"synthetic"}'
            ),
        )

        def connect():
            if clock[0] < ready_after:
                raise ConnectionRefusedError("nonfunctional-private-error")

        client.connect.side_effect = connect
        source = Mock()
        source.request.return_value = source_reply or (200, {"csrf_cookie_received": True})
        process = Mock()
        process.poll.return_value = 1 if exited else None
        budget = Mock(deadline=90)
        with (
            patch(
                "integrations.enterprise.reference_runner.time.monotonic",
                side_effect=lambda: clock[0],
            ),
            patch(
                "integrations.enterprise.reference_runner.time.sleep",
                side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
            ),
            patch(
                "integrations.enterprise.reference_runner.ClosedHTTPSClient", return_value=source
            ),
            patch("integrations.enterprise.reference_runner.lab_context"),
            patch(
                "integrations.enterprise.reference_runner.BoundedHTTPSConnection",
                return_value=client,
            ),
        ):
            try:
                result = wait_for_tls(budget, [process, process])
            except ReadinessFailure as error:
                result = error
        self.assertEqual(budget.deadline, 90)
        return result, clock[0], client

    def test_readiness_allows_child_startup_within_declared_twenty_second_budget(self):
        result, elapsed, client = self.readiness(ready_after=3)
        self.assertEqual(result, {"console_readiness_attempts": 3, "tls_readiness": True})
        self.assertEqual(elapsed, 4)
        self.assertEqual(client.finish.call_count, 3)

    def test_readiness_exhaustion_stays_bounded_and_has_safe_diagnostics(self):
        result, elapsed, client = self.readiness(ready_after=30)
        self.assertIsInstance(result, ReadinessFailure)
        self.assertEqual(elapsed, 20)
        self.assertEqual(client.connect.call_count, 10)
        self.assertEqual(result.facts["reason"], "connection_refused")
        self.assertNotIn("nonfunctional-private", json.dumps(result.facts))

    def test_readiness_preserves_denial_status_without_response_contents(self):
        for options, phase in (
            (
                {
                    "response_status": 503,
                    "response_body": b'{"private":"nonfunctional-private-body"}',
                },
                "console",
            ),
            ({"source_reply": (403, {"private": "nonfunctional-private-body"})}, "source"),
        ):
            with self.subTest(phase=phase):
                result, elapsed, _ = self.readiness(**options)
                self.assertIsInstance(result, ReadinessFailure)
                self.assertEqual(result.facts["phase"], phase)
                self.assertEqual(result.facts["reason"], "response_predicate")
                self.assertLessEqual(elapsed, 20)
                self.assertNotIn("nonfunctional-private", json.dumps(result.facts))

    def test_readiness_exited_child_fails_before_any_connection(self):
        result, elapsed, client = self.readiness(exited=True)
        self.assertEqual(result.facts["reason"], "child_exited")
        self.assertEqual(result.facts["child_exit_codes"], [1, 1])
        self.assertEqual(elapsed, 0)
        client.connect.assert_not_called()

    def test_wazuh_export_requires_exact_integer_counts_and_bound_snapshot(self):
        run = "a" * 32
        scopes = {
            "documents/observation": 12,
            "documents/detection": 1,
            "expenses/observation": 11,
            "expenses/detection": 0,
        }
        export = {
            "run_id": run,
            "snapshot_run_id": "12345678-1234-4234-8234-123456789abc",
            "logical_observations": 23,
            "forwarded_core_signals": 1,
            "scope_counts": scopes,
            "manifest_sha256": "b" * 64,
            "snapshot_verified": True,
        }
        self.assertEqual(validate_wazuh_export(export, run, 23, scopes), export)
        for field, malformed in (
            ("logical_observations", 23.0),
            ("forwarded_core_signals", True),
        ):
            with self.subTest(field=field):
                candidate = {**export, field: malformed}
                with self.assertRaises(ValueError):
                    validate_wazuh_export(candidate, run, 23, scopes)

    def test_windows_or_unreviewed_runner_cannot_reach_install_or_secrets(self):
        with (
            patch("integrations.enterprise.reference_runner.sys.platform", "win32"),
            patch("integrations.enterprise.reference_runner.profile") as credentials,
        ):
            with self.assertRaises(ValueError):
                runtime_gate()
            credentials.assert_not_called()

    def test_operation_scope_and_credentials_are_not_command_arguments(self):
        fake = Mock(
            returncode=0, stdout=b'{"fault_enabled":false,"maximum_seconds":120}', stderr=b""
        )
        environment = {
            "SB_SOURCE_RUN": "a" * 32,
            "SB_REF_PRIVATE": "not-a-real-secret",
            "PGHOST": "outside.example",
            "SSLKEYLOGFILE": "unexpected.log",
            "PYTHONPATH": "/opt/verification-deps/runtime:/workspace",
        }
        with patch(
            "integrations.enterprise.reference_runner.subprocess.run", return_value=fake
        ) as run:
            value = operate(environment, "source", "fault-off")
            self.assertFalse(value["fault_enabled"])
            arguments, settings = run.call_args.args[0], run.call_args.kwargs
            self.assertEqual(arguments[-1], "fault-off")
            self.assertFalse(any("not-a-real-secret" in arg for arg in arguments))
            self.assertNotIn("PGHOST", settings["env"])
            self.assertNotIn("SSLKEYLOGFILE", settings["env"])
            self.assertNotIn("SB_REF_PRIVATE", settings["env"])
            self.assertEqual(settings["timeout"], 15)
            self.assertEqual(settings["stdin"], subprocess.DEVNULL)
            for action in ("shell", "clean", "contain", "inspect;unexpected"):
                with self.assertRaises(ValueError):
                    operate(environment, "source", action)
            run.assert_called_once()

    def test_failures_and_oversized_operation_output_are_not_propagated(self):
        for result in (
            Mock(
                returncode=1,
                stdout=b"nonfunctional-private-error",
                stderr=b"nonfunctional-private-error",
            ),
            Mock(returncode=0, stdout=b"x" * 262145, stderr=b""),
            Mock(returncode=0, stdout=b"{}", stderr=b"x" * 65537),
        ):
            with (
                self.subTest(result=result),
                patch(
                    "integrations.enterprise.reference_runner.subprocess.run", return_value=result
                ),
            ):
                with self.assertRaises(ValueError) as error:
                    operate({}, "console", "inspect")
                self.assertNotIn("nonfunctional-private", str(error.exception))

    def test_duplicate_json_field_is_rejected(self):
        fake = Mock(returncode=0, stdout=b'{"completed":false,"completed":true}', stderr=b"")
        with (
            patch("integrations.enterprise.reference_runner.subprocess.run", return_value=fake),
            self.assertRaises(ValueError),
        ):
            operate({}, "console", "inspect")

    def test_stop_uses_exact_handles_and_kills_only_a_stalled_child(self):
        stopped, stalled = Mock(), Mock()
        stopped.poll.return_value = 0
        stalled.poll.side_effect = [None, -9]
        stalled.wait.side_effect = [subprocess.TimeoutExpired("fixed-process", 5), -9]
        self.assertTrue(stop_processes([stopped, stalled]))
        stopped.terminate.assert_not_called()
        stopped.kill.assert_not_called()
        stalled.terminate.assert_called_once()
        stalled.kill.assert_called_once()
        self.assertEqual([call.kwargs["timeout"] for call in stalled.wait.call_args_list], [5, 5])

    def test_stop_failure_remains_incomplete_and_other_children_still_stop(self):
        failed, other = Mock(), Mock()
        failed.poll.return_value = None
        failed.terminate.side_effect = OSError("private-process-failure")
        failed.wait.side_effect = subprocess.TimeoutExpired("fixed-process", 5)
        failed.kill.side_effect = OSError("private-process-failure")
        other.poll.side_effect = [None, 0]
        self.assertFalse(stop_processes([failed, other]))
        other.terminate.assert_called_once()
        other.wait.assert_called_once_with(timeout=5)

    def test_component_inventory_is_closed(self):
        with self.assertRaises(ValueError):
            component_environment(os.environ, "production")

    def connection(self, rows):
        connection = Mock(
            vendor="postgresql", settings_dict={"NAME": "sb_reference", "USER": "sb_reference"}
        )
        connection.cursor.return_value.__enter__ = Mock()
        connection.cursor.return_value.__exit__ = Mock(return_value=False)
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.side_effect = rows
        connection.get_connection_params.return_value = {
            "dbname": "sb_reference",
            "password": "nonfunctional-boundary-test-only",
        }
        return connection

    def test_actual_identity_must_match_the_configured_database_and_user(self):
        for identity in (("sb_reference", "postgres"), ("other_project", "sb_reference")):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                verify_database_identity(self.connection([identity]), "source")

    def test_network_failure_never_establishes_cross_database_permission_denial(self):
        import psycopg

        connection = self.connection([("sb_reference", "sb_reference"), (False,) * 5, (False,)])
        with (
            patch(
                "psycopg.connect",
                side_effect=psycopg.OperationalError("nonfunctional-private-connection-error"),
            ),
            self.assertRaises(ValueError) as error,
        ):
            verify_database_boundary(connection, "source")
        self.assertNotIn("nonfunctional-private", str(error.exception))

    def test_boundary_requires_both_privilege_inventory_and_actual_server_denial(self):
        import psycopg

        connection = self.connection([("sb_reference", "sb_reference"), (False,) * 5, (False,)])
        with patch(
            "psycopg.connect",
            side_effect=psycopg.errors.InsufficientPrivilege("nonfunctional-test-only"),
        ) as connect:
            value = verify_database_boundary(connection, "source")
            self.assertTrue(value["cross_database_connect_denied"])
            self.assertEqual(value["denial_sqlstate"], "42501")
            self.assertEqual(connect.call_args.kwargs["dbname"], "sb_enterprise_access")
            self.assertEqual(connect.call_args.kwargs["connect_timeout"], 3)
            self.assertNotIn("password", json.dumps(value))

    def test_admin_role_or_connect_grant_is_rejected_before_a_connection_attempt(self):
        for flags, grant in (((True, False, False, False, False), False), ((False,) * 5, True)):
            connection = self.connection([("sb_reference", "sb_reference"), flags, (grant,)])
            with patch("psycopg.connect") as connect, self.assertRaises(ValueError):
                verify_database_boundary(connection, "source")
            connect.assert_not_called()

    def test_libpq_startup_denial_with_no_sqlstate_requires_the_exact_server_message(self):
        import psycopg

        from integrations.enterprise.reference_native_support import connect_denial

        target = "sb_enterprise_access"
        expected = (
            'connection failed: FATAL:  permission denied for database "'
            + target
            + '"\nDETAIL:  User does not have CONNECT privilege.\n'
        )
        self.assertEqual(
            connect_denial(psycopg.OperationalError(expected), target),
            {"denial_kind": "server_connect_privilege_message", "denial_sqlstate": None},
        )
        for message in (
            "timeout expired",
            "connection refused",
            "password authentication failed",
            expected.replace(target, "other-project"),
            expected.replace("DETAIL:", "OTHER:"),
            expected + "timeout expired",
            "x" * 8193,
        ):
            with self.subTest(kind=message[:20]):
                self.assertIsNone(connect_denial(psycopg.OperationalError(message), target))
