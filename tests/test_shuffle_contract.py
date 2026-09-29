"""Offline contract checks only; no Shuffle engine is exercised."""

import copy
import json
from datetime import UTC, datetime, timedelta
from unittest import TestCase

from integrations.shuffle import handoff_contract as contract

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def fixture():
    return {
        "schema_version": 1,
        "kind": "signalbridge.analyst-review.request",
        "app": "bettail",
        "environment": "lab",
        "source": "synthetic_demo",
        "event_id": "00000000-0000-4000-8000-000000000001",
        "case_id": "00000000-0000-4000-8000-000000000002",
        "case_version": 1,
        "evidence_sha256": "a" * 64,
        "requested_at": "2026-09-24T12:00:00Z",
    }


class HandoffContractTests(TestCase):
    def request(self, value=None, now=NOW):
        return contract.validate(json.dumps(value or fixture()).encode(), now=now)

    def test_synthetic_scope_has_deterministic_immutable_identity_and_body(self):
        first = self.request()
        second = contract.validate(json.dumps(fixture(), indent=2).encode(), now=NOW)
        self.assertEqual(first, second)
        self.assertIsInstance(first.canonical_body, bytes)
        self.assertEqual(contract.delivery_decision(first, None), "enqueue")

    def test_raw_content_destinations_credentials_and_other_scope_are_rejected(self):
        changes = (
            {"webhook_url": "https://external.invalid"},
            {"token": "private-sentinel"},
            {"raw_event": "private-sentinel"},
            {"app": "netted"},
            {"environment": "production"},
            {"source": "legacy_unclassified"},
            {"kind": "disable_account"},
            {"case_version": True},
            {"case_version": 0},
            {"event_id": "../other"},
            {"case_id": "00000000000040008000000000000002"},
            {"schema_version": True},
            {"evidence_sha256": "invalid"},
            {"requested_at": "2026-09-99T12:00:00Z"},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(contract.ContractError) as error:
                self.request({**fixture(), **change})
            self.assertNotIn("private-sentinel", str(error.exception))

    def test_duplicate_malformed_oversize_or_missing_data_are_not_accepted(self):
        for raw in (
            b"{}",
            b"[]",
            b"null",
            b"{",
            b"\xff",
            b"x" * 4097,
            b'{"schema_version":1,"schema_version":1}',
        ):
            with self.assertRaises(contract.ContractError):
                contract.validate(raw, now=NOW)

    def test_stale_future_and_naive_clocks_fail_without_untrusted_error_text(self):
        for now in (
            NOW + timedelta(seconds=301),
            NOW - timedelta(seconds=31),
            NOW.replace(tzinfo=None),
        ):
            with self.assertRaises(contract.ContractError):
                self.request(now=now)
        self.request(now=NOW + timedelta(seconds=300))
        self.request(now=NOW - timedelta(seconds=30))

    def test_same_identity_changed_evidence_is_a_conflict_not_a_second_task(self):
        first = self.request()
        changed = self.request({**fixture(), "evidence_sha256": "b" * 64})
        self.assertEqual(first.idempotency_key, changed.idempotency_key)
        receipt = {
            "idempotency_key": first.idempotency_key,
            "payload_sha256": first.payload_sha256,
            "state": "pending",
            "task_id": None,
        }
        self.assertEqual(contract.delivery_decision(changed, receipt), "conflict")
        for state, expected in (
            ("pending", "wait"),
            ("failed", "review_required"),
            ("completed", "already_completed"),
        ):
            receipt.update(
                state=state, task_id=fixture()["case_id"] if state == "completed" else None
            )
            self.assertEqual(contract.delivery_decision(first, receipt), expected)

    def test_new_case_version_has_new_identity_and_receipts_are_strict(self):
        first = self.request()
        self.assertNotEqual(
            first.idempotency_key, self.request({**fixture(), "case_version": 2}).idempotency_key
        )
        receipt = {
            "idempotency_key": first.idempotency_key,
            "payload_sha256": first.payload_sha256,
            "state": "pending",
            "task_id": None,
        }
        for change in (
            {"idempotency_key": "b" * 64},
            {"state": "unknown"},
            {"state": []},
            {"state": {}},
            {"task_id": "unknown"},
            {"extra": True},
        ):
            bad = copy.deepcopy(receipt)
            bad.update(change)
            with self.assertRaises(contract.ContractError):
                contract.delivery_decision(first, bad)
