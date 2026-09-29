"""Bounded interpretation of case-generation records; no historical backfilling."""

import re

from .contract import digest, timestamp
from .models import Audit

ACTIONS = ("case.created", "case.evidence_added", "case.reopened")
FIELDS = {
    "schema_version",
    "rule",
    "correlation",
    "case_version",
    "event_count",
    "evidence_sha256",
    "process_source_sha256",
    "disk_source_sha256_before",
    "disk_source_sha256_after",
}
LIMIT = (
    "Source bytes captured at catalog import, with disk checks around evaluation; assumes coherent "
    "startup. This is not loaded-bytecode attestation, independent source truth or protection "
    "against a database administrator."
)


def evidence_fingerprint(bindings):
    # Source is assigned by the collector key, not stored in the signed wire payload.
    return digest(
        sorted([[str(identifier), checksum, source] for identifier, checksum, source in bindings])
    )


def generation_record(case, bindings, before, after):
    """Called in the worker transaction, only when new evidence is attached."""
    if before["process_source_sha256"] != after["process_source_sha256"]:
        raise ValueError("Process source identity changed during evaluation.")
    return {
        "schema_version": 1,
        "rule": case.rule,
        "correlation": case.correlation,
        "case_version": case.version,
        "event_count": len(bindings),
        "evidence_sha256": evidence_fingerprint(bindings),
        "process_source_sha256": before["process_source_sha256"],
        "disk_source_sha256_before": before["disk_source_sha256"],
        "disk_source_sha256_after": after["disk_source_sha256"],
    }


def _hash(value, nullable=False):
    return (nullable and value is None) or (
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    )


def _consistent(case, event):
    """Check retained contents once, before either provenance or rule comparison."""
    try:
        payload = event.payload
        return (
            isinstance(payload, dict)
            and digest(payload) == event.digest
            and event.integration_id == case.integration_id
            and all(
                payload.get(name) == getattr(event, name)
                for name in ("actor", "resource", "environment", "operation", "outcome", "reason")
            )
            and payload.get("app") == case.integration.slug
            and payload.get("event_id") == str(event.event_id)
            and payload.get("episode") == str(event.episode)
            and timestamp(payload["occurred_at"]) == event.occurred_at
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def case_generation(case, events, current_engine, *, complete=True):
    """Latest evidence-producing audit only. Missing/malformed records remain explicit."""
    result = {
        "status": "unrecorded",
        "message": "No generation snapshot was recorded for this historical case.",
        "record": None,
        "evidence_matches": False,
        "same_current_engine": False,
        "integrity_errors": sum(not _consistent(case, event) for event in events),
        "limit": LIMIT,
    }
    audit = (
        Audit.objects.filter(
            integration_id=case.integration_id,
            object_id=str(case.pk),
            action__in=ACTIONS,
            actor__isnull=True,
        )
        .only("id", "created_at", "detail")
        .order_by("-id")
        .first()
    )
    if audit is None or not isinstance(audit.detail, dict) or "generation" not in audit.detail:
        return result
    record = audit.detail["generation"]
    valid = (
        isinstance(record, dict)
        and set(record) == FIELDS
        and type(record["schema_version"]) is int
        and record["schema_version"] == 1
        and record["rule"] == case.rule
        and record["correlation"] == case.correlation
        and type(record["case_version"]) is int
        and 1 <= record["case_version"] <= case.version
        and type(record["event_count"]) is int
        and 1 <= record["event_count"] <= 2**31 - 1
        and _hash(record["evidence_sha256"])
        and all(
            _hash(record[key], nullable=True)
            for key in (
                "process_source_sha256",
                "disk_source_sha256_before",
                "disk_source_sha256_after",
            )
        )
    )
    if not valid:
        return {
            **result,
            "status": "invalid",
            "message": "Generation record is malformed or does not bind this case.",
        }
    result.update(
        record=record,
        recorded_at=audit.created_at.isoformat(),
        audit_id=audit.pk,
        same_current_engine=bool(
            current_engine and record["process_source_sha256"] == current_engine
        ),
    )
    if not complete:
        return {
            **result,
            "status": "partial",
            "message": "Generation snapshot retained; the displayed evidence is incomplete, so its binding was not verified.",
        }
    match = record["event_count"] == len(events) and record[
        "evidence_sha256"
    ] == evidence_fingerprint([(event.event_id, event.digest, event.source) for event in events])
    if not match:
        return {
            **result,
            "status": "evidence_changed",
            "message": "Linked evidence no longer matches the latest recorded generation snapshot.",
        }
    if result["integrity_errors"]:
        return {
            **result,
            "status": "evidence_inconsistent",
            "message": "Recorded hashes match, but retained payloads or indexed fields are inconsistent. The evidence binding is not verified.",
        }
    result["evidence_matches"] = True
    identities = [
        record[key]
        for key in (
            "process_source_sha256",
            "disk_source_sha256_before",
            "disk_source_sha256_after",
        )
    ]
    if None in identities:
        return {
            **result,
            "status": "source_unavailable",
            "message": "Evidence binding matches; readable source identity was unavailable during generation.",
        }
    if len(set(identities)) != 1:
        return {
            **result,
            "status": "source_changed",
            "message": "Evidence binding matches; disk source differed from the process snapshot during generation.",
        }
    return {
        **result,
        "status": "recorded",
        "message": "Generation snapshot and retained evidence binding match. Review the source-snapshot limits.",
    }
