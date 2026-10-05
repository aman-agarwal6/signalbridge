"""Trust-boundary preservation tests; every process/network primitive is forbidden."""

import copy
import importlib
import json
import os
import socket
import subprocess
import unittest
import urllib.request
from unittest.mock import Mock, patch

from integrations.enterprise import preserved_workloads as control

RUN, OTHER_RUN = "a" * 32, "b" * 32
PRESERVED = [f"{number:064x}" for number in range(1, 9)]
OWNED = ["c" * 64, "d" * 64]
UNKNOWN = "e" * 64


def output(ids, newline="\n"):
    return newline.join(ids) + (newline if ids else "")


class PreservedWorkloadTests(unittest.TestCase):
    def setUp(self):
        self.forbidden = []
        for target, name in (
            (subprocess, "run"),
            (subprocess, "Popen"),
            (os, "system"),
            (socket, "socket"),
            (socket, "create_connection"),
            (urllib.request, "urlopen"),
        ):
            self.forbidden.append(
                self.enterContext(
                    patch.object(
                        target, name, side_effect=AssertionError("Unexpected process/network IO")
                    )
                )
            )

    def tearDown(self):
        for boundary in self.forbidden:
            boundary.assert_not_called()

    def baseline(self, ids=PRESERVED, profile="preserve-baseline", run=RUN):
        request = Mock(return_value=output(ids))
        baseline, public = control.capture(request, run, profile=profile)
        request.assert_called_once_with(control.RUNNING_ARGUMENTS, timeout=3)
        return baseline, public["preserved_digest"]

    def test_import_is_inert_under_forbidden_process_network_boundaries(self):
        importlib.reload(control)

    def test_eight_existing_workloads_stay_private_and_only_owned_arrivals_pass(self):
        baseline, digest = self.baseline()
        self.assertEqual(baseline["preserved_ids"], sorted(PRESERVED))
        self.assertEqual(control.validate_baseline(baseline, RUN, digest), tuple(sorted(PRESERVED)))
        for active_owned in ([], OWNED[:1], OWNED):
            request = Mock(return_value=output(PRESERVED + active_owned))
            public = control.compare(request, baseline, RUN, OWNED, expected_digest=digest)
            request.assert_called_once_with(("ps", "--quiet", "--no-trunc"), timeout=3)
            self.assertEqual(public["preserved_count"], 8)
            self.assertEqual(public["owned_count"], 2)
            self.assertEqual(public["owned_running_count"], len(active_owned))
            self.assertEqual(public["running_count"], 8 + len(active_owned))
            self.assertEqual(public["preserved_digest"], digest)
            self.assertTrue(all(type(value) in (int, str) for value in public.values()))
            self.assertFalse(
                any(identifier in json.dumps(public) for identifier in PRESERVED + OWNED)
            )

    def test_exclusive_default_refuses_existing_foreign_inventory(self):
        request = Mock(return_value=output(PRESERVED))
        with self.assertRaisesRegex(control.LabControlError, "Exclusive profile"):
            control.capture(request, RUN)
        empty = Mock(return_value="")
        baseline, public = control.capture(empty, RUN)
        self.assertEqual(baseline["profile"], "exclusive")
        self.assertEqual(public["preserved_count"], 0)
        for running in ([], OWNED[:1], OWNED):
            admitted = control.compare(
                Mock(return_value=output(running)),
                baseline,
                RUN,
                OWNED,
                expected_digest=public["preserved_digest"],
            )
            self.assertEqual(admitted["owned_running_count"], len(running))
        with self.assertRaisesRegex(control.LabControlError, "unexpected"):
            control.compare(
                Mock(return_value=output(OWNED + [UNKNOWN])),
                baseline,
                RUN,
                OWNED,
                expected_digest=public["preserved_digest"],
            )

    def test_profile_or_run_typo_refuses_before_inventory_request(self):
        for run, profile in (
            (RUN, "shared"),
            (RUN, "preserve_baseline"),
            (RUN, True),
            (OTHER_RUN[:-1], "preserve-baseline"),
            ("$(synthetic)", "preserve-baseline"),
        ):
            request = Mock()
            with self.subTest(run=run, profile=profile), self.assertRaises(control.LabControlError):
                control.capture(request, run, profile=profile)
            request.assert_not_called()

    def test_missing_preserved_id_detects_stop_removal_or_recreation(self):
        baseline, digest = self.baseline()
        for running in (PRESERVED[:-1], PRESERVED[:-1] + OWNED, PRESERVED[:-1] + [UNKNOWN]):
            with (
                self.subTest(running_count=len(running)),
                self.assertRaisesRegex(
                    control.LabControlError, "preserved running workload is missing"
                ),
            ):
                control.compare(
                    Mock(return_value=output(running)), baseline, RUN, OWNED, expected_digest=digest
                )

    def test_unknown_arrival_cannot_be_admitted_by_partial_id_or_similarity(self):
        baseline, digest = self.baseline()
        similar = OWNED[0][:-1] + "b"
        for arrival in (UNKNOWN, similar):
            with (
                self.subTest(arrival=arrival),
                self.assertRaisesRegex(control.LabControlError, "unexpected"),
            ):
                control.compare(
                    Mock(return_value=output(PRESERVED + OWNED + [arrival])),
                    baseline,
                    RUN,
                    OWNED,
                    expected_digest=digest,
                )

    def test_caller_cannot_relabel_a_preserved_id_as_owned(self):
        baseline, digest = self.baseline()
        request = Mock()
        with self.assertRaisesRegex(control.LabControlError, "overlap"):
            control.compare(request, baseline, RUN, [PRESERVED[0]], expected_digest=digest)
        request.assert_not_called()
        with self.assertRaisesRegex(control.LabControlError, "overlap"):
            control.capture(
                Mock(return_value=output(PRESERVED)),
                RUN,
                [PRESERVED[0]],
                profile="preserve-baseline",
            )

    def test_malformed_inventory_fails_closed_instead_of_treating_it_as_empty(self):
        invalid = (
            None,
            b"",
            [],
            0,
            "\n",
            " ",
            OWNED[0][:12],
            OWNED[0].upper(),
            " " + OWNED[0],
            OWNED[0] + " ",
            OWNED[0] + "\x00",
            OWNED[0] + "\v",
            OWNED[0] + "\r",
            output([OWNED[0], OWNED[0]]),
            output([OWNED[0]]) + "\n",
            output([OWNED[0]]) + "synthetic warning",
            "x" * (control.MAX_RAW_BYTES + 1),
        )
        for raw in invalid:
            with self.subTest(
                type=type(raw).__name__, length=len(raw) if hasattr(raw, "__len__") else None
            ):
                request = Mock(return_value=raw)
                with self.assertRaises(control.LabControlError):
                    control.capture(request, RUN, profile="preserve-baseline")
                request.assert_called_once()

    def test_count_bound_and_full_windows_line_endings(self):
        hundred = [f"{number:064x}" for number in range(100)]
        baseline, public = control.capture(
            Mock(return_value=output(hundred, "\r\n")), RUN, profile="preserve-baseline"
        )
        self.assertEqual(public["preserved_count"], 100)
        self.assertEqual(
            len(control.validate_baseline(baseline, RUN, public["preserved_digest"])), 100
        )
        with self.assertRaises(control.LabControlError):
            control.capture(
                Mock(return_value=output(hundred + [UNKNOWN])), RUN, profile="preserve-baseline"
            )
        request = Mock()
        with self.assertRaises(control.LabControlError):
            control.compare(
                request, baseline, RUN, OWNED[:1], expected_digest=public["preserved_digest"]
            )
        request.assert_not_called()

    def test_inventory_failure_is_bounded_single_request_and_redacts_exception(self):
        for error in (
            OSError("synthetic-private-detail"),
            TimeoutError("synthetic-private-detail"),
        ):
            request = Mock(side_effect=error)
            with self.assertRaises(control.LabControlError) as raised:
                control.capture(request, RUN, profile="preserve-baseline")
            self.assertNotIn("synthetic-private-detail", str(raised.exception))
            self.assertTrue(raised.exception.__suppress_context__)
            request.assert_called_once_with(control.RUNNING_ARGUMENTS, timeout=3)

    def test_owned_allowlist_is_bounded_full_unique_ids_before_read_or_mutation(self):
        baseline, digest = self.baseline()
        for owned in (
            OWNED[0],
            [OWNED[0][:12]],
            [OWNED[0], OWNED[0]],
            [True],
            iter(OWNED),
            [f"{number:064x}" for number in range(101)],
        ):
            request = Mock()
            with (
                self.subTest(type=type(owned).__name__),
                self.assertRaises(control.LabControlError),
            ):
                control.compare(request, baseline, RUN, owned, expected_digest=digest)
            request.assert_not_called()

    def test_canonical_baseline_and_inventory_digests_ignore_inventory_order(self):
        first, digest = self.baseline()
        second, reordered_digest = self.baseline(list(reversed(PRESERVED)))
        self.assertEqual(first, second)
        self.assertEqual(digest, reordered_digest)
        self.assertEqual(
            control.inventory_digest(PRESERVED), control.inventory_digest(list(reversed(PRESERVED)))
        )
        self.assertNotEqual(
            control.inventory_digest(PRESERVED), control.inventory_digest(PRESERVED[:-1])
        )
        _, another_run_digest = self.baseline(run=OTHER_RUN)
        self.assertNotEqual(digest, another_run_digest)

    def test_private_baseline_tamper_wrong_run_and_recomputed_hash_are_rejected(self):
        baseline, digest = self.baseline()
        for field, changed in (
            ("schema_version", True),
            ("schema_version", 2),
            ("kind", "other"),
            ("profile", "shared"),
            ("profile", "exclusive"),
            ("run_id", OTHER_RUN),
            ("preserved_ids", list(reversed(PRESERVED))),
            ("preserved_ids", PRESERVED[:-1]),
            ("preserved_ids", PRESERVED + [PRESERVED[0]]),
            ("sha256", "f" * 64),
        ):
            tampered = copy.deepcopy(baseline)
            tampered[field] = changed
            with self.subTest(field=field), self.assertRaises(control.LabControlError):
                control.validate_baseline(tampered, RUN, digest)
        replacement, replacement_digest = self.baseline(PRESERVED[:-1] + [UNKNOWN])
        self.assertNotEqual(replacement_digest, digest)
        with self.assertRaises(control.LabControlError):
            control.validate_baseline(replacement, RUN, digest)
        with self.assertRaises(control.LabControlError):
            control.validate_baseline(baseline, OTHER_RUN, digest)
        extra = {**baseline, "ignored_owner": OTHER_RUN}
        with self.assertRaises(control.LabControlError):
            control.validate_baseline(extra, RUN, digest)

    def test_private_serialization_roundtrip_and_duplicate_or_oversized_input_denied(self):
        baseline, digest = self.baseline()
        raw = control.private_bytes(baseline, RUN, expected_digest=digest)
        restored = control.load_private(raw, RUN, expected_digest=digest)
        self.assertEqual(restored, baseline)
        duplicate = raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')
        for hostile in (duplicate, b"", b"{", b"\xff", b"x" * 8193, raw.decode("ascii")):
            with (
                self.subTest(type=type(hostile).__name__),
                self.assertRaises(control.LabControlError),
            ):
                control.load_private(hostile, RUN, expected_digest=digest)

    def test_mutation_admission_denies_preserved_unknown_and_other_run_targets(self):
        baseline, digest = self.baseline()
        for candidate, observed_run, owned in (
            (PRESERVED[0], RUN, OWNED),
            (PRESERVED[0], RUN, OWNED + [PRESERVED[0]]),
            (UNKNOWN, RUN, OWNED),
            (OWNED[0], OTHER_RUN, OWNED),
            (OWNED[0], "", OWNED),
            (OWNED[0][:12], RUN, OWNED),
            ("$(synthetic)", RUN, OWNED),
        ):
            with self.subTest(candidate=candidate, run=observed_run):
                self.assertFalse(
                    control.mutation_admitted(
                        candidate, observed_run, baseline, RUN, owned, expected_digest=digest
                    )
                )
        for owned in OWNED:
            self.assertTrue(
                control.mutation_admitted(owned, RUN, baseline, RUN, OWNED, expected_digest=digest)
            )

    def test_mutation_admission_fails_closed_on_corrupted_private_record(self):
        baseline, digest = self.baseline()
        baseline["preserved_ids"].remove(PRESERVED[0])
        self.assertFalse(
            control.mutation_admitted(OWNED[0], RUN, baseline, RUN, OWNED, expected_digest=digest)
        )


if __name__ == "__main__":
    unittest.main()
