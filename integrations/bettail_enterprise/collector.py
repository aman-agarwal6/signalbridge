"""Finite delivery of the copied app's transactional outbox; imports do no IO.

The caller supplies an already reviewed dedicated DB connection and TLS context.
No DSN, arbitrary URL, local service startup or credential discovery is provided.
"""

import http.client
import uuid
from datetime import datetime, timezone

from bridge.contract import canonical, parse_json, signature, validate_event
from integrations.enterprise.https_deadline import BoundedHTTPSConnection

KEY_ID = "bettail-access-v1"


def receipt(event_id, status, raw):
    if type(status) is not int or not isinstance(raw, bytes) or len(raw) > 1024:
        return "pending", "invalid_acknowledgement"
    if status in (200, 202):
        try:
            value = parse_json(raw)
        except (ValueError, UnicodeError):
            return "pending", "invalid_acknowledgement"
        if value != {
            "event_id": event_id,
            "status": "accepted" if status == 202 else "duplicate",
        }:
            return "pending", "invalid_acknowledgement"
        return "acknowledged", ""
    if status == 409:
        return "dead", "event_conflict"
    if 300 <= status < 400:
        return "dead", "redirect_rejected"
    if status in (400, 401, 403, 404, 413, 422):
        return "dead", "delivery_rejected"
    return "pending", "collector_unavailable"


class ConsoleTransport:
    """Fixed loopback TLS console; no ambient proxies, redirects or DNS."""

    def __init__(self, context):
        self.context = context

    def __call__(self, body, headers):
        client = BoundedHTTPSConnection(18841, seconds=5, context=self.context)
        try:
            client.start()
            client.connect()
            client.request("POST", "/api/v1/events/bettail/", body=body, headers=headers)
            response = client.getresponse()
            raw = response.read(1025)
            client.remaining()
            return response.status, raw
        finally:
            client.finish()


def deliver_one(connection, signing_key, transport):
    """A lost reply keeps the same logical event; a conflict is never accepted.

    connection must be a dedicated autocommit psycopg connection with only the
    sb_bettail_delivery role, so the row lease commits *before* network IO.
    Finite retries/backoff and body immutability are enforced by the SQL functions.
    """
    if getattr(connection, "autocommit", None) is not True:
        raise ValueError("Delivery requires a dedicated autocommit connection.")
    if not isinstance(signing_key, str) or not 32 <= len(signing_key) <= 256:
        raise ValueError("A separate bounded ingestion signing key is required.")
    lease = uuid.uuid4()
    with connection.cursor() as cursor:
        cursor.execute("select sb_bettail.claim(%s)", (lease,))
        payload = cursor.fetchone()[0]
    if payload is None:
        return None
    # The private DB function returns one immutable, bounded source payload.
    # Never put payloads, keys, source UUIDs or exception strings in a receipt.
    identifier = payload.get("event_id") if isinstance(payload, dict) else None
    try:
        validate_event(payload, "bettail")
        body = canonical(payload)
        if payload["environment"] != "lab" or len(body) > 4096:
            raise ValueError("Invalid copied-lab record.")
    except (ValueError, TypeError, KeyError):
        if identifier is None:
            raise ValueError("Unidentifiable copied-lab outbox record.") from None
        result, error = "dead", "invalid_outbox_record"
    else:
        at = datetime.now(timezone.utc).isoformat()
        headers = {
            "Content-Type": "application/json",
            "X-SB-Key": KEY_ID,
            "X-SB-Time": at,
            "X-SB-Signature": signature(signing_key, "bettail", KEY_ID, at, body),
        }
        try:
            result, error = receipt(identifier, *transport(body, headers))
        except (OSError, http.client.HTTPException, ValueError, TypeError):
            result, error = "pending", "transport_failed"
    with connection.cursor() as cursor:
        cursor.execute("select sb_bettail.finish(%s,%s,%s,%s)", (identifier, lease, result, error))
        finished = cursor.fetchone()[0]
    if finished is None:
        return {"event_id": identifier, "state": "lease_lost", "error": error}
    expected = {"event_id": identifier, "state": result, "error": error}
    exhausted = {"event_id": identifier, "state": "dead", "error": "retry_exhausted"}
    if finished != expected and not (result == "pending" and finished == exhausted):
        raise ValueError("Invalid copied-lab delivery completion receipt.")
    return finished
