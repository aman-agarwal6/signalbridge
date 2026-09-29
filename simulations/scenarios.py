"""Declared synthetic truth, kept outside every event delivered to the collector."""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone


def build_scenarios(now):
    base = datetime.fromtimestamp(int(now.timestamp()) // 300 * 300 - 600, timezone.utc)

    def event(case, index, **changes):
        body = {
            "schema_version": 1,
            "event_id": str(
                uuid.uuid5(uuid.NAMESPACE_URL, f"signalbridge-simulation/{case}/{index}")
            ),
            "app": "lab-alpha",
            "environment": "test",
            "occurred_at": (base + timedelta(seconds=10 + index)).isoformat(),
            "actor": hashlib.sha256(case.encode()).hexdigest(),
            "resource": hashlib.sha256(f"resource/{index}".encode()).hexdigest(),
            "episode": str(uuid.uuid5(uuid.NAMESPACE_URL, f"signalbridge-simulation/{case}")),
            "operation": "private_record.read",
            "outcome": "denied",
            "reason": "membership_required",
            "context": None,
        }
        body.update(changes)
        return {"source": "migration_lab", "event": body}

    cases = []

    def add(name, entries, expected_rule=None, known_gap=False):
        cases.append(
            {
                "id": name,
                "expected_rule": expected_rule,
                "known_gap": known_gap,
                "deliveries": entries,
            }
        )

    add("authorized_read", [event("authorized_read", 0, outcome="allowed", reason="member")])
    add(
        "distinct_private_failures", [event("distinct_private_failures", i) for i in range(3)], "R1"
    )
    add(
        "same_resource_retries",
        [event("same_resource_retries", i, resource="a" * 64) for i in range(3)],
    )
    add("below_threshold", [event("below_threshold", i) for i in range(2)])
    add(
        "bucket_boundary_gap",
        [
            event(
                "bucket_boundary_gap",
                i,
                occurred_at=(base + timedelta(seconds=299 + i)).isoformat(),
            )
            for i in range(3)
        ],
        "R1",
        False,
    )
    add(
        "revoked_read_allowed",
        [event("revoked_read_allowed", 0, outcome="allowed", reason="membership_removed")],
        "R2",
    )
    add(
        "controlled_policy_fault",
        [event("controlled_policy_fault", 0, outcome="allowed", reason="policy_regression")],
        "R2",
    )
    add(
        "successful_membership_change",
        [
            event(
                "successful_membership_change",
                0,
                operation="membership.change",
                outcome="allowed",
                reason="membership_removed",
            )
        ],
    )
    add(
        "session_errors_not_private_reads",
        [
            event(
                "session_errors_not_private_reads",
                i,
                operation="session.verify",
                reason="session_invalid",
            )
            for i in range(3)
        ],
    )
    add(
        "dependency_errors",
        [
            event("dependency_errors", i, outcome="error", reason="dependency_unavailable")
            for i in range(3)
        ],
    )
    mixed = [event("mixed_sources", i) for i in range(3)]
    mixed[-1]["source"] = "synthetic_demo"
    add("mixed_sources", mixed)
    add(
        "cross_application",
        [
            event("cross_application", i, app="lab-beta" if i == 2 else "lab-alpha")
            for i in range(3)
        ],
    )
    add(
        "mixed_environments",
        [event("mixed_environments", i, environment="lab" if i == 2 else "test") for i in range(3)],
    )
    add("out_of_order", [event("out_of_order", i) for i in (2, 0, 1)], "R1")
    duplicate = event("duplicate_delivery", 0)
    add("duplicate_delivery", [duplicate, duplicate, duplicate])
    return cases
