"""Offline contract preparation, not a Shuffle client or operational integration.

No network, credentials, task creation or durable queue exists in this module.
An authenticated receiver must additionally re-resolve these references in its
app-scoped database and implement transactional uniqueness before side effects.
"""

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

MAX_BYTES = 4096
MAX_AGE_SECONDS = 300
FUTURE_TOLERANCE_SECONDS = 30
FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "app",
        "environment",
        "source",
        "event_id",
        "case_id",
        "case_version",
        "evidence_sha256",
        "requested_at",
    }
)


class ContractError(ValueError):
    """A fixed reason, never untrusted request content."""


@dataclass(frozen=True)
class ValidatedHandoff:
    canonical_body: bytes
    idempotency_key: str
    payload_sha256: str


def require(condition, code):
    if not condition:
        raise ContractError(code)


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate_field")
        result[name] = value
    return result


def uuid_string(value):
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
        return str(parsed) == value and parsed.version in {1, 2, 3, 4, 5, 6, 7, 8}
    except (ValueError, AttributeError):
        return False


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate(raw, *, now):
    """Validate the initial synthetic BetTail/lab scope; reject dynamic destinations."""
    require(isinstance(raw, bytes) and 1 <= len(raw) <= MAX_BYTES, "request_size")
    require(
        isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None,
        "clock_required",
    )
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError("invalid_json") from None
    require(isinstance(value, dict) and set(value) == FIELDS, "field_inventory")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1, "schema_version")
    require(
        value["kind"] == "signalbridge.analyst-review.request"
        and value["app"] == "bettail"
        and value["environment"] == "lab"
        and value["source"] == "synthetic_demo",
        "scope_not_allowed",
    )
    require(uuid_string(value["event_id"]) and uuid_string(value["case_id"]), "reference_format")
    require(
        type(value["case_version"]) is int and 1 <= value["case_version"] <= 2147483647,
        "case_version",
    )
    require(digest(value["evidence_sha256"]), "evidence_digest")
    require(
        isinstance(value["requested_at"], str)
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value["requested_at"]),
        "request_time",
    )
    try:
        requested = datetime.strptime(value["requested_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=UTC
        )
    except ValueError:
        raise ContractError("request_time") from None
    age = (now.astimezone(UTC) - requested).total_seconds()
    require(-FUTURE_TOLERANCE_SECONDS <= age <= MAX_AGE_SECONDS, "request_stale_or_future")
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    identity = {
        key: value[key]
        for key in (
            "kind",
            "app",
            "environment",
            "source",
            "event_id",
            "case_id",
            "case_version",
        )
    }
    identity_bytes = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return ValidatedHandoff(
        body, hashlib.sha256(identity_bytes).hexdigest(), hashlib.sha256(body).hexdigest()
    )


def delivery_decision(request, existing):
    """A pure decision contract; the future receiver must serialize durable writes."""
    require(isinstance(request, ValidatedHandoff), "validated_request_required")
    if existing is None:
        return "enqueue"
    require(
        isinstance(existing, dict)
        and set(existing)
        == {
            "idempotency_key",
            "payload_sha256",
            "state",
            "task_id",
        },
        "receipt_shape",
    )
    require(
        existing["idempotency_key"] == request.idempotency_key
        and digest(existing["payload_sha256"]),
        "receipt_identity",
    )
    require(
        isinstance(existing["state"], str)
        and existing["state"] in {"pending", "completed", "failed"},
        "receipt_state",
    )
    require(
        (existing["state"] == "completed" and uuid_string(existing["task_id"]))
        or (existing["state"] != "completed" and existing["task_id"] is None),
        "receipt_task",
    )
    if existing["payload_sha256"] != request.payload_sha256:
        return "conflict"
    return {"pending": "wait", "completed": "already_completed", "failed": "review_required"}[
        existing["state"]
    ]
