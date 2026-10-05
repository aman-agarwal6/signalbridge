"""Synthetic measurement regressions; no native clock, source or tool execution."""

import copy
import io
import json
import uuid
from collections import Counter
from contextlib import redirect_stdout
from unittest.mock import patch

from django.test import SimpleTestCase

from integrations.enterprise.reliability import (
    APPS,
    BURST_STARTS,
    DAY_MS,
    EXPECTED_EVENTS,
    INTERRUPTIONS,
    LedgerError,
    declaration,
    declaration_hash,
    json_lines,
    measure,
    schedule,
)
from scripts.enterprise_reliability import HashedReader, ledger_path, main


def event_rows(slot):
    common = {"app": slot.app, "event_id": str(uuid.UUID(int=slot.index + 1)), "digest": "a" * 64}
    return [
        {
            "kind": "source",
            **common,
            "slot": slot.index,
            "sent_ms": slot.due_ms,
            "at_ms": slot.due_ms,
        },
        {
            "kind": "attempt",
            **common,
            "start_ms": slot.due_ms + 5,
            "end_ms": slot.due_ms + 105,
            "result": "accepted",
        },
        {
            "kind": "stored",
            **common,
            "accepted_ms": slot.due_ms + 50,
            "processed_ms": slot.due_ms + 200,
            "worker": "worker-1" if slot.index % 2 else "worker-2",
        },
        {"kind": "tool", **common, "native_id": f"1.{slot.index}", "at_ms": slot.due_ms + 250},
    ]


def full_fixture(change=None):
    for slot in schedule():
        rows = event_rows(slot)
        yield from change(slot, rows) if change else rows


def report(rows, elapsed=DAY_MS):
    return measure(rows, elapsed_ms=elapsed, profile_sha256=declaration_hash())


class ReliabilityScheduleTests(SimpleTestCase):
    def test_exact_balanced_population_and_no_overlapping_cadences(self):
        slots = tuple(schedule())
        self.assertEqual(len(slots), EXPECTED_EVENTS)
        self.assertEqual(Counter(slot.app for slot in slots), dict.fromkeys(APPS, 23880))
        self.assertEqual(Counter(slot.phase for slot in slots), {"steady": 42960, "burst": 4800})
        self.assertEqual([slot.index for slot in slots], list(range(EXPECTED_EVENTS)))
        self.assertEqual(len(set(slot.due_ms for slot in slots)), EXPECTED_EVENTS)
        self.assertEqual(slots[-1].due_ms, DAY_MS - 2000)
        self.assertTrue(all(a.due_ms < b.due_ms for a, b in zip(slots, slots[1:], strict=False)))
        for start in BURST_STARTS:
            burst = [slot for slot in slots if start <= slot.due_ms < start + 60000]
            self.assertEqual(len(burst), 600)
            self.assertTrue(all(slot.phase == "burst" for slot in burst))
            self.assertEqual([slot.due_ms - start for slot in burst], list(range(0, 60000, 100)))

    def test_profile_is_stable_copy_and_changed_targets_cannot_use_old_hash(self):
        original = declaration_hash()
        proposal = declaration()
        proposal["interruptions"][0]["recover_by_ms"] += 60000
        self.assertEqual(declaration_hash(), original)
        with self.assertRaisesMessage(LedgerError, "profile_changed"):
            measure([], elapsed_ms=DAY_MS, profile_sha256="0" * 64)
        self.assertIn("unapproved", declaration()["status"])
        self.assertEqual(len(INTERRUPTIONS), 5)


class ReliabilityMeasurementsTests(SimpleTestCase):
    def test_full_accelerated_fixture_meets_only_ledger_targets_never_native_gate(self):
        result = report(full_fixture())
        self.assertEqual(result["status"], "ledger_targets_met")
        self.assertEqual(result["native_acceptance"], "not_established_by_this_measurement")
        self.assertEqual(result["accepted_logical_events"], EXPECTED_EVENTS)
        self.assertEqual(result["processed_logical_events"], EXPECTED_EVENTS)
        self.assertEqual(result["tool_observed_logical_events"], EXPECTED_EVENTS)
        self.assertEqual(result["ingestion_all_periods"]["p95_ms"], 100)
        self.assertEqual(result["processing_all_periods"]["p95_ms"], 150)
        self.assertLess(result["processing_outside_fixed_windows"]["samples"], EXPECTED_EVENTS)
        self.assertFalse(any(result["anomalies"].values()))
        self.assertTrue(all(row["late_or_missing"] == 0 for row in result["recovery"]))

    def test_missing_observation_is_not_excused_by_low_latency(self):
        result = report(full_fixture(lambda slot, rows: [] if slot.index == 50 else rows))
        self.assertEqual(result["status"], "ledger_targets_not_met")
        self.assertEqual(result["missing_slots"], 1)
        self.assertEqual(result["ingestion_all_periods"]["p95_ms"], 100)

    def test_retries_and_native_duplicates_remain_separate_from_logical_counts(self):
        rows = event_rows(next(schedule()))
        retry = {**rows[1], "result": "unknown", "end_ms": 40}
        duplicate = {**rows[1], "start_ms": 300, "end_ms": 400, "result": "duplicate"}
        second_tool = {**rows[3], "native_id": "second", "at_ms": 401}
        result = report([*rows, retry, duplicate, rows[3], second_tool])
        self.assertEqual(result["accepted_logical_events"], 1)
        self.assertEqual(result["physical_transport_calls"], 3)
        self.assertEqual(result["additional_transport_calls"], 2)
        self.assertEqual(result["tool_observed_logical_events"], 1)
        self.assertEqual(result["tool_distinct_native_ids"], 2)
        self.assertEqual(result["tool_additional_physical_records"], 2)
        self.assertEqual(result["transport_and_tool_outcomes"]["unknown"], 1)
        self.assertEqual(result["ingestion_all_periods"]["samples"], 1)
        self.assertEqual(result["transport_all_periods"]["samples"], 3)
        self.assertFalse(any(result["anomalies"].values()))

    def test_fast_retries_cannot_dilute_logical_ingestion_latency(self):
        rows = event_rows(next(schedule()))
        rows[1]["end_ms"] = 605
        retries = [
            {
                **rows[1],
                "start_ms": 700 + index * 10,
                "end_ms": 701 + index * 10,
                "result": "duplicate",
            }
            for index in range(30)
        ]
        result = report([*rows, *retries])
        self.assertEqual(result["transport_all_periods"]["p95_ms"], 1)
        self.assertEqual(result["ingestion_all_periods"]["p95_ms"], 600)
        self.assertEqual(result["ingestion_all_periods"]["samples"], 1)

    def test_lost_reply_can_recover_but_absent_acknowledgement_remains_incomplete(self):
        rows = event_rows(next(schedule()))
        rows[1]["result"] = "unknown"
        missing = report(rows)
        self.assertEqual(missing["missing_acknowledgements"], 1)
        self.assertIsNone(missing["ingestion_all_periods"]["p95_ms"])
        recovered = report(
            [*rows, {**rows[1], "result": "duplicate", "start_ms": 400, "end_ms": 450}]
        )
        self.assertEqual(recovered["missing_acknowledgements"], 0)
        self.assertEqual(recovered["ingestion_all_periods"]["p95_ms"], 50)
        self.assertEqual(recovered["additional_transport_calls"], 1)

    def test_duplicate_database_rows_and_conflicts_are_visible(self):
        rows = event_rows(next(schedule()))
        result = report([*rows, rows[0], rows[2], {**rows[2], "digest": "b" * 64}])
        self.assertEqual(result["anomalies"]["duplicate_logical_database_rows"], 2)
        self.assertEqual(result["anomalies"]["duplicate_source_identities"], 1)
        self.assertEqual(result["anomalies"]["duplicate_slots"], 1)
        self.assertEqual(result["anomalies"]["conflicting_digests"], 1)

    def test_cross_app_records_do_not_satisfy_delivery(self):
        rows = event_rows(next(schedule()))
        rows[2]["app"] = "expenses"
        rows[3]["app"] = "expenses"
        result = report(rows)
        self.assertEqual(result["missing_acceptance"], 1)
        self.assertEqual(result["missing_processing"], 1)
        self.assertEqual(result["missing_tool_observation"], 1)
        self.assertEqual(result["anomalies"]["unexpected_database_identities"], 1)
        self.assertEqual(result["anomalies"]["unexpected_tool_identities"], 1)

    def test_late_recovery_fails_even_when_excluded_from_normal_latency(self):
        slot = next(slot for slot in schedule() if slot.due_ms == INTERRUPTIONS[0][1])
        rows = event_rows(slot)
        rows[2]["processed_ms"] = INTERRUPTIONS[0][3] + 1
        result = report(rows)
        self.assertEqual(result["processing_outside_fixed_windows"]["samples"], 0)
        self.assertGreater(result["processing_all_periods"]["p95_ms"], 5000)
        self.assertEqual(result["recovery"][0]["late_or_missing"], 1)

    def test_exception_windows_are_half_open_and_not_result_dependent(self):
        start, deadline = INTERRUPTIONS[0][1], INTERRUPTIONS[0][3]
        slots = [slot for slot in schedule() if slot.due_ms in (start - 2000, start, deadline)]
        rows = [row for slot in slots for row in event_rows(slot)]
        result = report(rows)
        self.assertEqual(result["ingestion_all_periods"]["samples"], 3)
        self.assertEqual(result["ingestion_outside_fixed_windows"]["samples"], 2)
        self.assertEqual(result["processing_outside_fixed_windows"]["samples"], 2)

    def test_nearest_rank_and_strict_thresholds(self):
        def boundary(_slot, rows):
            rows[1]["end_ms"] = rows[1]["start_ms"] + 500
            rows[2]["processed_ms"] = rows[2]["accepted_ms"] + 5000
            return rows

        result = report(full_fixture(boundary), elapsed=DAY_MS + 5000)
        self.assertEqual(result["status"], "ledger_targets_not_met")
        self.assertEqual(result["ingestion_outside_fixed_windows"]["p95_ms"], 500)
        self.assertEqual(result["processing_outside_fixed_windows"]["p95_ms"], 5000)

    def test_missing_completion_attempt_and_tool_are_not_zero_latency(self):
        rows = event_rows(next(schedule()))
        rows[2].update(processed_ms=None, worker="")
        result = report([rows[0], rows[2]])
        self.assertEqual(result["missing_processing"], 1)
        self.assertEqual(result["missing_transport_evidence"], 1)
        self.assertEqual(result["missing_tool_observation"], 1)
        self.assertIsNone(result["processing_all_periods"]["p95_ms"])
        self.assertIsNone(result["ingestion_all_periods"]["p95_ms"])

    def test_slow_source_response_is_reported_not_counted_as_off_schedule(self):
        rows = event_rows(next(schedule()))
        rows[0]["at_ms"] = 672
        rows[1].update(start_ms=680, end_ms=760)
        rows[2].update(accepted_ms=700, processed_ms=900)
        rows[3]["at_ms"] = 950
        result = report(rows)
        self.assertEqual(result["anomalies"].get("off_schedule_observations", 0), 0)
        self.assertEqual(result["source_response"]["maximum_ms"], 672)
        before = event_rows(next(schedule()))
        before[0]["sent_ms"] = 20
        self.assertEqual(report(before)["anomalies"]["source_time_before_request"], 1)

    def test_impossible_timing_unknown_execution_and_changed_scope_fail_closed(self):
        rows = event_rows(next(schedule()))
        rows[0].update(sent_ms=251, at_ms=251)
        rows[1].update(result="unknown", end_ms=None)
        result = report(rows)
        for name in (
            "off_schedule_observations",
            "unfinished_physical_attempts",
            "attempt_before_source",
            "acceptance_before_source",
        ):
            self.assertEqual(result["anomalies"][name], 1)
        with self.assertRaisesMessage(LedgerError, "observations_after_end"):
            report(event_rows(next(schedule())), elapsed=249)
        result = report([], elapsed=1000)
        self.assertEqual(result["status"], "ledger_targets_not_met")


class ReliabilityInputTests(SimpleTestCase):
    def test_closed_schema_types_and_bounded_content(self):
        source, attempt, stored, tool = event_rows(next(schedule()))
        invalid = [
            {**source, "password": "not-a-real-password"},
            {**source, "slot": True},
            {**source, "slot": EXPECTED_EVENTS},
            {**source, "app": "bettail"},
            {**source, "event_id": "bad"},
            {**source, "digest": "x" * 64},
            {**source, "at_ms": float("nan")},
            {**source, "at_ms": -1},
            {**attempt, "end_ms": 4},
            {**attempt, "end_ms": None},
            {**attempt, "result": "success"},
            {**stored, "worker": "arbitrary-worker"},
            {**stored, "processed_ms": None},
            {**tool, "native_id": "x" * 81},
        ]
        for row in invalid:
            with self.subTest(row_fields=sorted(row)), self.assertRaises(LedgerError):
                report([row])

    def test_jsonl_rejects_duplicate_keys_partial_lines_size_and_nonfinite_numbers(self):
        row = event_rows(next(schedule()))[0]
        valid = json.dumps(row).encode() + b"\n"
        self.assertEqual(list(json_lines(io.BytesIO(valid))), [row])
        bad = [
            valid.rstrip(),
            valid.replace(b'"slot": 0', b'"slot": 0, "slot": 1'),
            b" " * 1025,
            b'{"value": NaN}\n',
            b"\xff\n",
        ]
        for raw in bad:
            with self.subTest(length=len(raw)), self.assertRaises(LedgerError):
                list(json_lines(io.BytesIO(raw)))
        with (
            patch("integrations.enterprise.reliability.MAX_ROWS", 1),
            self.assertRaises(LedgerError),
        ):
            list(json_lines(io.BytesIO(valid * 2)))
        with (
            patch("integrations.enterprise.reliability.MAX_BYTES", 10),
            self.assertRaises(LedgerError),
        ):
            list(json_lines(io.BytesIO(valid)))

    def test_no_raw_ids_or_content_are_in_result_and_input_is_unchanged(self):
        rows = event_rows(next(schedule()))
        before = copy.deepcopy(rows)
        result = json.dumps(report(rows))
        self.assertNotIn(rows[0]["event_id"], result)
        self.assertNotIn(rows[0]["digest"], result)
        self.assertEqual(rows, before)

    def test_cli_proposal_has_no_launch_and_path_rejects_other_locations(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["declaration"]), 0)
        self.assertEqual(json.loads(output.getvalue())["sha256"], declaration_hash())
        for path in (
            "README.md",
            "var/enterprise/reliability/../other.jsonl",
            "var/enterprise/reliability/example.txt",
        ):
            with self.subTest(path=path), self.assertRaises(LedgerError):
                ledger_path(path)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "measure",
                        "--ledger",
                        "README.md",
                        "--elapsed-ms",
                        "1000",
                        "--profile-sha256",
                        declaration_hash(),
                    ]
                ),
                2,
            )

    def test_reader_hashes_exact_bytes_not_reencoded_rows(self):
        import hashlib

        raw = json.dumps(event_rows(next(schedule()))[0], separators=(",", ":")).encode() + b"\n"
        reader = HashedReader(io.BytesIO(raw))
        self.assertEqual(len(list(json_lines(reader))), 1)
        self.assertEqual(reader.digest.hexdigest(), hashlib.sha256(raw).hexdigest())
