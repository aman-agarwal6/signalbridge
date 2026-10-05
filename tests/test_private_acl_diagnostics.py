"""Closed helper error-channel and controller receipts; no native execution."""

import json
from subprocess import CompletedProcess
from unittest.mock import patch

from django.test import SimpleTestCase

from integrations.enterprise.private_acl_diagnostics import KIND, PrivateACLFailure, failure
from integrations.enterprise.verification import LabControlError
from scripts import enterprise_reference_verify as source
from scripts import enterprise_wazuh_live_verify as collector


class PrivateACLDiagnosticTests(SimpleTestCase):
    def setUp(self):
        for target in (
            "subprocess.Popen",
            "subprocess.run",
            "os.system",
            "socket.socket",
            "socket.create_connection",
        ):
            guard = patch(target, side_effect=AssertionError("Unexpected native or network call."))
            guard.start()
            self.addCleanup(guard.stop)

    def raw(self, **changes):
        return json.dumps(
            {"kind": KIND, "mode": "SecureEmpty", "phase": 8, "checked_count": 0, **changes}
        ).encode()

    def test_valid_helper_branch_has_no_native_message_or_private_identity(self):
        for mode in ("SecureEmpty", "Verify"):
            for phase in range(1, 18):
                with self.subTest(mode=mode, phase=phase):
                    error = failure(self.raw(mode=mode, phase=phase), mode)
                    self.assertIs(type(error), PrivateACLFailure)
                    self.assertEqual(
                        error.metadata(mode),
                        {"kind": KIND, "mode": mode, "phase": phase, "checked_count": 0},
                    )
                    self.assertNotIn(KIND, str(error))

    def test_malformed_or_unbounded_native_details_are_discarded(self):
        for raw in (
            b"",
            b"x" * 1025,
            b"synthetic-private-native-message-path-token",
            b"\xff",
            b'[{"mode":"SecureEmpty"}]',
            b'{"kind":"first","kind":"second"}',
            self.raw(kind="synthetic-private-kind"),
            self.raw(mode="Verify"),
            self.raw(mode=True),
            self.raw(phase=True),
            self.raw(phase=0),
            self.raw(phase=18),
            self.raw(phase=1.0),
            self.raw(checked_count=True),
            self.raw(checked_count=-1),
            self.raw(checked_count=2502),
            self.raw(path="synthetic-private-path"),
            self.raw(message="synthetic-private-native-message"),
            self.raw(phase="synthetic-private-phase"),
        ):
            with self.subTest(raw_length=len(raw)):
                self.assertIsNone(failure(raw, "SecureEmpty"))
        self.assertIsNone(failure(self.raw().decode(), "SecureEmpty"))
        self.assertIsNone(failure(self.raw(), "synthetic-private-mode"))

    def test_phase8_accepts_only_null_or_signed_int32_numeric_status(self):
        for mode in ("SecureEmpty", "Verify"):
            for status in (None, -(2**31), -2147024891, -1, 0, 1, 2**31 - 1):
                with self.subTest(mode=mode, status=status):
                    error = failure(self.raw(mode=mode, api_hresult=status), mode)
                    self.assertIs(type(error), PrivateACLFailure)
                    self.assertEqual(
                        error.metadata(mode),
                        {
                            "kind": KIND,
                            "mode": mode,
                            "phase": 8,
                            "checked_count": 0,
                            "api_hresult": status,
                        },
                    )
                    self.assertNotIn(str(status), str(error))

    def test_numeric_field_is_rejected_at_every_other_phase_even_when_null(self):
        for phase in range(1, 18):
            if phase == 8:
                continue
            for status in (None, 0, -2147024891):
                with self.subTest(phase=phase, status=status):
                    self.assertIsNone(
                        failure(self.raw(phase=phase, api_hresult=status), "SecureEmpty")
                    )
                    with self.assertRaises(LabControlError):
                        PrivateACLFailure("SecureEmpty", phase, 0, api_hresult=status)

    def test_numeric_protocol_rejects_coercions_unsigned_overflow_and_extra_fields(self):
        for status in (
            True,
            False,
            0.0,
            -2147024891.0,
            "0",
            "null",
            "synthetic-private-status",
            -(2**31) - 1,
            2**31,
            0x80070005,
            [],
            {"code": 5},
        ):
            with self.subTest(status_type=type(status).__name__):
                self.assertIsNone(failure(self.raw(api_hresult=status), "SecureEmpty"))
                with self.assertRaises(LabControlError):
                    PrivateACLFailure("SecureEmpty", 8, 0, api_hresult=status)
        self.assertIsNone(
            failure(self.raw(api_hresult=0, message="synthetic-private-error"), "SecureEmpty")
        )
        for raw in (
            b'{"kind":"signalbridge-private-acl-failure","mode":"SecureEmpty",'
            b'"phase":8,"checked_count":0,"api_hresult":0,"api_hresult":0}',
            b'{"kind":"signalbridge-private-acl-failure","mode":"SecureEmpty",'
            b'"phase":7,"phase":8,"checked_count":0,"api_hresult":null}',
        ):
            self.assertIsNone(failure(raw, "SecureEmpty"))

    def test_mutated_numeric_metadata_is_revalidated_before_receipt_publication(self):
        diagnostic = collector.PhaseDiagnostics()
        diagnostic.enter("prepare_private_acl")
        error = PrivateACLFailure("SecureEmpty", 8, 0, api_hresult=-2147024891)
        for status in (True, 0.0, "synthetic-private-status", 2**31, -(2**31) - 1, {}):
            error._api_hresult = status
            raw = json.dumps(diagnostic.snapshot(error))
            self.assertNotIn("helper", raw)
            self.assertNotIn("synthetic-private", raw)
        error._api_hresult = None
        error._branch = ("SecureEmpty", 7, 0)
        self.assertNotIn("helper", diagnostic.snapshot(error))
        error._branch = ("SecureEmpty", 8, 0)
        self.assertIsNone(diagnostic.snapshot(error)["helper"]["api_hresult"])

    def test_numeric_transport_and_collector_receipt_keep_only_exact_safe_metadata(self):
        result = CompletedProcess([], 1, stdout=b"", stderr=self.raw(api_hresult=-2147024891))
        with self.assertRaises(PrivateACLFailure) as raised:
            self.invoke(result)
        diagnostic = collector.PhaseDiagnostics()
        diagnostic.enter("prepare_private_acl")
        self.assertEqual(
            diagnostic.snapshot(raised.exception)["helper"],
            {
                "kind": KIND,
                "mode": "SecureEmpty",
                "phase": 8,
                "checked_count": 0,
                "api_hresult": -2147024891,
            },
        )
        for code, output in ((2, b""), (1, b"synthetic-private-output")):
            with self.subTest(code=code), self.assertRaises(LabControlError) as error:
                self.invoke(CompletedProcess([], code, stdout=output, stderr=result.stderr))
            self.assertIs(type(error.exception), LabControlError)

    def invoke(self, result, *, mode="SecureEmpty"):
        with patch.object(source.subprocess, "run", return_value=result) as execute:
            try:
                return source.invoke(["modeled-helper"], {}, 30, 1024, acl_mode=mode)
            finally:
                if mode in ("SecureEmpty", "Verify"):
                    self.assertFalse(execute.call_args.kwargs["shell"])

    def test_exact_failed_channel_retains_only_valid_branch(self):
        result = CompletedProcess([], 1, stdout=b"", stderr=self.raw())
        with self.assertRaises(PrivateACLFailure) as raised:
            self.invoke(result)
        self.assertEqual(raised.exception.metadata("SecureEmpty")["phase"], 8)

    def test_other_exit_codes_or_mixed_channels_cannot_claim_helper_branch(self):
        for code, stdout, stderr in (
            (2, b"", self.raw()),
            (True, b"", self.raw()),
            (1, b"unexpected success-channel data", self.raw()),
            (1, b"", self.raw(mode="Verify")),
            (1, b"", b"synthetic-private-native-message"),
            (1, b"", self.raw() + b"x" * 1024),
        ):
            with (
                self.subTest(code=code, stdout=bool(stdout)),
                self.assertRaises(LabControlError) as raised,
            ):
                self.invoke(CompletedProcess([], code, stdout=stdout, stderr=stderr))
            self.assertIs(type(raised.exception), LabControlError)
            self.assertNotIn("synthetic-private", str(raised.exception))

    def test_success_channel_cannot_ignore_failure_stderr(self):
        output = b'{"private_acl_verified":true,"inherited_public_access_removed":true}'
        with self.assertRaises(LabControlError):
            self.invoke(CompletedProcess([], 0, stdout=output, stderr=self.raw()))
        self.assertEqual(self.invoke(CompletedProcess([], 0, stdout=output, stderr=b"")), output)

    def test_invalid_mode_is_rejected_before_invocation(self):
        with patch.object(source.subprocess, "run") as execute:
            with self.assertRaises(LabControlError):
                source.invoke([], {}, 30, 1024, acl_mode="synthetic-private-mode")
            execute.assert_not_called()

    def test_private_acl_explicitly_selects_the_closed_protocol(self):
        output = b'{"private_acl_verified":true,"inherited_public_access_removed":true}'
        with (
            patch.object(source.sys, "platform", "win32"),
            patch.object(source, "invoke", return_value=output) as execute,
        ):
            source.private_acl("a" * 32, "Verify")
        self.assertEqual(execute.call_args.kwargs, {"acl_mode": "Verify"})

    def test_collector_receipt_binds_branch_to_actual_acl_phase_and_mode(self):
        diagnostic = collector.PhaseDiagnostics()
        diagnostic.enter("prepare_private_acl")
        error = failure(self.raw(), "SecureEmpty")
        receipt = diagnostic.snapshot(error)
        self.assertEqual(receipt["helper"], error.metadata("SecureEmpty"))
        self.assertNotIn("helper", diagnostic.snapshot(PrivateACLFailure("Verify", 14, 1)))
        diagnostic.enter("main_shutdown")
        self.assertNotIn("helper", diagnostic.snapshot(error))

    def test_exception_subclasses_or_mutated_metadata_are_not_serialized(self):
        diagnostic = collector.PhaseDiagnostics()
        diagnostic.enter("prepare_private_acl")

        class UntrustedException(PrivateACLFailure):
            pass

        self.assertNotIn("helper", diagnostic.snapshot(UntrustedException("SecureEmpty", 8, 0)))
        error = PrivateACLFailure("SecureEmpty", 8, 0)
        for branch in (
            "synthetic-private-diagnostic",
            ("SecureEmpty",),
            ("synthetic-private-mode", 8, 0),
            ("SecureEmpty", True, 0),
            ("SecureEmpty", 8, True),
            ("SecureEmpty", 8, 2502),
        ):
            error._branch = branch
            self.assertNotIn("helper", diagnostic.snapshot(error))
        del error._branch
        self.assertNotIn("helper", diagnostic.snapshot(error))
        uninitialized = PrivateACLFailure.__new__(PrivateACLFailure)
        self.assertNotIn("helper", diagnostic.snapshot(uninitialized))

    def test_generic_process_failures_cannot_acquire_acl_metadata(self):
        diagnostic = collector.PhaseDiagnostics()
        diagnostic.enter("prepare_private_acl")
        error = RuntimeError("synthetic-private-native-message-path-token")
        error.helper = {"message": "synthetic-private-message"}
        raw = json.dumps(diagnostic.snapshot(error))
        self.assertNotIn("synthetic-private", raw)
        self.assertNotIn("helper", raw)
