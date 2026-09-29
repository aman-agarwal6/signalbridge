"""Predeclared builder-authored challenges; oracle fields never enter collector events.

This catalog is deliberately separate from the 15 development scenarios. Its
authors know the rules: it is not an independent or blind evaluation set.
"""

import hashlib
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

from bridge.contract import canonical

PROFILE = "detection-challenge-v1"
MAX_REQUESTS = 150
MAX_WORKER_RECORDS = 150


@dataclass(frozen=True)
class Reading:
    at: int = 0
    resource: str = "a"
    actor: str = "one"
    operation: str = "private_record.read"
    outcome: str = "denied"
    reason: str = "membership_required"
    episode: str = "one"
    context: bool = False
    repeat: int | None = None
    drain_after: bool = False


@dataclass(frozen=True)
class Challenge:
    id: str
    title: str
    purpose: str
    readings: tuple[Reading, ...]
    rules: tuple[str, ...] = ()
    cases: int = 0
    category: str = "rule_contract"


def catalog():
    """Return a fresh immutable catalog, with expectations fixed before execution."""
    return (
        Challenge(
            "C01",
            "Exactly five minutes",
            "The 300-second boundary is inclusive.",
            (Reading(0, "a"), Reading(149, "b"), Reading(300, "c")),
            ("R1",),
            1,
        ),
        Challenge(
            "C02",
            "One second outside",
            "Three resources span 301 seconds: no R1 window contains all three.",
            (Reading(0, "a"), Reading(149, "b"), Reading(301, "c")),
        ),
        Challenge(
            "C03",
            "Mixed failure outcomes",
            "Denied and not-visible reads both contribute to R1.",
            (Reading(0, "a"), Reading(1, "b", outcome="not_visible"), Reading(2, "c")),
            ("R1",),
            1,
        ),
        Challenge(
            "C04",
            "Simultaneous observations",
            "Three distinct resources at one timestamp still qualify.",
            (Reading(0, "a"), Reading(0, "b"), Reading(0, "c")),
            ("R1",),
            1,
        ),
        Challenge(
            "C05",
            "Repeated delivery below threshold",
            "Replaying two event identities cannot create a third resource.",
            (Reading(0, "a"), Reading(repeat=0), Reading(1, "b"), Reading(repeat=2)),
        ),
        Challenge(
            "C06",
            "Two actor boundary",
            "Two reads by one actor and one by another do not meet R1.",
            (Reading(0, "a"), Reading(1, "b"), Reading(2, "c", actor="two")),
        ),
        Challenge(
            "C07",
            "Episode changes",
            "Changing an episode does not reset the live actor window.",
            (Reading(0, "a"), Reading(1, "b", episode="two"), Reading(2, "c", episode="three")),
            ("R1",),
            1,
        ),
        Challenge(
            "C08",
            "Managed-device context",
            "Advisory replay suppression must not suppress the live baseline.",
            tuple(
                Reading(
                    i, str(i), outcome="not_visible", reason="resource_unavailable", context=True
                )
                for i in range(3)
            ),
            ("R1",),
            1,
        ),
        Challenge(
            "C09",
            "Revoked read denied",
            "A single denied read after removal is not allowed access (R2).",
            (Reading(reason="membership_removed"),),
        ),
        Challenge(
            "C10",
            "Policy regression allowed",
            "An allowed read tagged policy_regression produces R2.",
            (Reading(outcome="allowed", reason="policy_regression"),),
            ("R2",),
            1,
        ),
        Challenge(
            "C11",
            "Revoked read service error",
            "An error is not evidence of allowed access and must not produce R2.",
            (Reading(outcome="error", reason="membership_removed"),),
        ),
        Challenge(
            "C12",
            "Late middle event",
            "After two events are processed, a late arrival fills the qualifying window.",
            (Reading(0, "a"), Reading(300, "c", drain_after=True), Reading(150, "b")),
            ("R1",),
            1,
        ),
        Challenge(
            "C13",
            "R2 replay after processing",
            "An acknowledged duplicate cannot produce a second investigation.",
            (
                Reading(outcome="allowed", reason="membership_removed", drain_after=True),
                Reading(repeat=0),
            ),
            ("R2",),
            1,
        ),
        Challenge(
            "C14",
            "Sustained activity across buckets",
            "Qualifying endpoints in two UTC buckets intentionally form two cases.",
            tuple(Reading(i * 120, str(i)) for i in range(4)),
            ("R1",),
            2,
        ),
        Challenge(
            "C15",
            "Allowed read is not a failure",
            "Two failures and a legitimate allowed read do not meet R1.",
            (Reading(0, "a"), Reading(1, "b"), Reading(2, "c", outcome="allowed", reason="member")),
        ),
        Challenge(
            "C16",
            "Distinct R2 events",
            "Two distinct allowed-after-removal observations each retain a case.",
            (
                Reading(0, "a", outcome="allowed", reason="membership_removed"),
                Reading(1, "b", outcome="allowed", reason="membership_removed"),
            ),
            ("R2",),
            2,
        ),
        Challenge(
            "P01",
            "Slow enumeration",
            "Desired coverage: three resources over six minutes. The existing five-minute window may miss this pattern.",
            (Reading(0, "a"), Reading(180, "b"), Reading(360, "c")),
            category="capability_probe",
        ),
        Challenge(
            "P02",
            "Distributed probing",
            "Desired coverage: one read by each of three actors. The existing per-actor rule may miss coordinated activity.",
            (Reading(0, "a"), Reading(1, "b", actor="two"), Reading(2, "c", actor="three")),
            category="capability_probe",
        ),
        Challenge(
            "P03",
            "Missing revocation context",
            "Desired coverage: a membership-change observation followed by an allowed read labeled member. Current metadata lacks an authoritative affected-member relationship; this tests the need for richer source context, not proof of unauthorized access.",
            (
                Reading(
                    operation="membership.change", outcome="allowed", reason="membership_removed"
                ),
                Reading(1, "a", outcome="allowed", reason="member"),
            ),
            category="capability_probe",
        ),
    )


def declaration():
    return {
        "profile": PROFILE,
        "independent_holdout": False,
        "cases": [asdict(c) for c in catalog()],
    }


def declaration_sha256():
    return hashlib.sha256(canonical(declaration())).hexdigest()


def deliveries(case, now):
    """Construct only closed-contract observations, without titles or desired outcomes."""
    base = datetime.fromtimestamp(int(now.timestamp()) // 300 * 300 - 1200, timezone.utc)
    bodies = []
    for index, reading in enumerate(case.readings):
        if reading.repeat is not None:
            if not 0 <= reading.repeat < index:
                raise ValueError("Replay must name an earlier reading.")
            body = bodies[reading.repeat]
        else:
            at = base + timedelta(seconds=reading.at)
            identity = f"signalbridge/{PROFILE}/{case.id}"
            body = {
                "schema_version": 1,
                "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"{identity}/{index}")),
                "app": "lab-challenge",
                "environment": "test",
                "occurred_at": at.isoformat(),
                "actor": hashlib.sha256(f"{identity}/actor/{reading.actor}".encode()).hexdigest(),
                "resource": hashlib.sha256(f"resource/{reading.resource}".encode()).hexdigest(),
                "episode": str(
                    uuid.uuid5(uuid.NAMESPACE_URL, f"{identity}/episode/{reading.episode}")
                ),
                "operation": reading.operation,
                "outcome": reading.outcome,
                "reason": reading.reason,
                "context": {
                    "managed_device": True,
                    "reauthenticated": True,
                    "valid_from": base.isoformat(),
                    "valid_to": (base + timedelta(seconds=900)).isoformat(),
                    "known_at": base.isoformat(),
                }
                if reading.context
                else None,
            }
        bodies.append(body)
        yield body, reading.drain_after
