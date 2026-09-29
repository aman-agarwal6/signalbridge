"""Versioned, metadata-only wire contract. Never accept arbitrary source payloads."""

import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timedelta, timezone

FIELDS = {
    "schema_version",
    "event_id",
    "app",
    "environment",
    "occurred_at",
    "actor",
    "resource",
    "episode",
    "operation",
    "outcome",
    "reason",
    "context",
}
OPERATIONS = {"private_record.read", "membership.change", "session.verify"}
OUTCOMES = {"allowed", "denied", "not_visible", "error"}
REASONS = {
    "member",
    "owner",
    "membership_required",
    "membership_removed",
    "resource_unavailable",
    "session_invalid",
    "mfa_required",
    "dependency_unavailable",
    "policy_regression",
}
CONTEXT_FIELDS = {
    "managed_device",
    "reauthenticated",
    "valid_from",
    "valid_to",
    "known_at",
}


class ContractError(ValueError):
    pass


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ContractError("Invalid timestamp.")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ContractError("Invalid timestamp.") from None
    if result.tzinfo is None or result.utcoffset() is None:
        raise ContractError("Timezone required.")
    try:
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ContractError("Timestamp cannot be represented in UTC.") from None


def validate_event(data, expected_app, now=None):
    now = now or datetime.now(timezone.utc)
    if not isinstance(data, dict) or set(data) != FIELDS:
        raise ContractError("Unknown or missing event fields.")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ContractError("Unsupported schema.")
    if data["app"] != expected_app or data["environment"] not in ("lab", "test"):
        raise ContractError("App or environment mismatch.")
    for key in ("event_id", "episode"):
        try:
            if str(uuid.UUID(data[key])) != data[key]:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise ContractError("Invalid identifier.") from None
    for key in ("actor", "resource"):
        if not isinstance(data[key], str) or not re.fullmatch("[a-f0-9]{64}", data[key]):
            raise ContractError("Use app-scoped pseudonymous identifiers.")
    if (
        any(not isinstance(data[field], str) for field in ("operation", "outcome", "reason"))
        or data["operation"] not in OPERATIONS
        or data["outcome"] not in OUTCOMES
        or data["reason"] not in REASONS
    ):
        raise ContractError("Unknown observation.")
    occurred = timestamp(data["occurred_at"])
    age = now - occurred
    if age < -timedelta(seconds=60) or age > timedelta(days=7):
        raise ContractError("Event outside seven-day delivery window.")
    context = data["context"]
    if context is not None:
        if not isinstance(context, dict) or set(context) != CONTEXT_FIELDS:
            raise ContractError("Invalid context.")
        for k in ("managed_device", "reauthenticated"):
            if type(context[k]) is not bool:
                raise ContractError("Invalid context flag.")
        start, end, known = (timestamp(context[k]) for k in ("valid_from", "valid_to", "known_at"))
        if end <= start:
            raise ContractError("Invalid context interval.")
    return data


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(data):
    return hashlib.sha256(canonical(data)).hexdigest()


def signature(secret, app, key_id, sent_at, body):
    prefix = f"signalbridge.v1\n{app}\n{key_id}\n{sent_at}\n".encode()
    return hmac.new(secret.encode(), prefix + body, hashlib.sha256).hexdigest()


def parse_json(raw):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ContractError("Duplicate JSON field.")
            result[k] = v
        return result

    try:
        return json.loads(
            raw,
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ContractError("Invalid number.")),
        )
    except (ValueError, UnicodeError, RecursionError):
        raise ContractError("Invalid JSON.") from None
