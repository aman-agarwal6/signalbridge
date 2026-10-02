"""Durable source delivery to one fixed TLS loopback console.

No URL input, proxy inheritance, redirects, source-data changes or case response.
An acknowledgement means accepted ingestion, not completed detection or Wazuh delivery.
"""

import http.client
import json
import os
import socket
import ssl
import threading
import uuid
from datetime import timedelta
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from django.db import connection, transaction
from django.db.models import Q
from django.utils import timezone

from bridge.contract import canonical, digest, signature, validate_event

from .models import Outbox
from .seed import require_isolated_database

LEASE_SECONDS = 30
TIMEOUT_SECONDS = 5
MAX_RESPONSE_BYTES = 1024
MAX_EVENT_BYTES = 4096
APP_KEYS = {app: "reference-" + app + "-v1" for app in ("documents", "expenses")}


class DeliveryError(ValueError):
    pass


class NativeTransport:
    """Verify the reviewed lab certificate without modifying a host trust store."""

    def __init__(self):
        certificate = os.environ.get("SB_REF_DELIVERY_CA", "")
        if not certificate or not Path(certificate).is_file():
            raise ImproperlyConfigured("Explicit reference collector CA trust is required.")
        self.context = ssl.create_default_context(cafile=certificate)

    def __call__(self, app, body, headers):
        if app not in APP_KEYS or len(body) > MAX_EVENT_BYTES:
            raise DeliveryError("invalid_scope")
        client = http.client.HTTPSConnection(
            "127.0.0.1", 18841, timeout=TIMEOUT_SECONDS, context=self.context
        )
        timer = None
        try:
            client.connect()
            channel = client.sock

            def interrupt():
                # A peer sending occasional bytes must not extend a delivery
                # indefinitely. Retain this socket even if HTTP detaches it.
                try:
                    channel.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(TIMEOUT_SECONDS, interrupt)
            timer.daemon = True
            timer.start()
            client.request("POST", f"/api/v1/events/{app}/", body=body, headers=headers)
            response = client.getresponse()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise DeliveryError("response_too_large")
            return response.status, raw
        finally:
            if timer is not None:
                timer.cancel()
            client.close()


def claim(now):
    """Commit a finite lease before network IO; PostgreSQL consumers skip held rows."""
    with transaction.atomic():
        query = Outbox.objects.filter(state="pending", available_at__lte=now).filter(
            Q(leased_until__isnull=True) | Q(leased_until__lte=now)
        )
        query = query.select_for_update(
            skip_locked=connection.features.has_select_for_update_skip_locked
        )
        row = query.order_by("available_at", "created_at", "pk").first()
        if row is None:
            return None
        row.attempts += 1
        row.lease_token = uuid.uuid4()
        row.leased_until = now + timedelta(seconds=LEASE_SECONDS)
        row.error_code = ""
        row.save(update_fields=["attempts", "lease_token", "leased_until", "error_code"])
        return row


def finish(row, result, error_code=""):
    with transaction.atomic():
        now = timezone.now()
        current = Outbox.objects.select_for_update().get(pk=row.pk)
        if (
            current.state != "pending"
            or current.lease_token != row.lease_token
            or current.leased_until is None
            or current.leased_until <= now
        ):
            return "lease_lost"
        current.lease_token = None
        current.leased_until = None
        if current.digest != row.digest or current.payload != row.payload or current.app != row.app:
            result, error_code = "dead", "outbox_changed"
        current.error_code = error_code
        if result == "acknowledged":
            current.state = "acknowledged"
            current.acknowledged_at = now
        elif result == "dead":
            current.state = "dead"
        else:
            current.available_at = now + timedelta(seconds=min(300, 2 ** min(current.attempts, 8)))
        current.save(
            update_fields=[
                "lease_token",
                "leased_until",
                "error_code",
                "state",
                "acknowledged_at",
                "available_at",
            ]
        )
        return current.state


def response_result(row, status, body):
    if type(status) is not int or not isinstance(body, bytes) or len(body) > MAX_RESPONSE_BYTES:
        return "pending", "invalid_response"
    if status in (200, 202):
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError):
            return "pending", "invalid_acknowledgement"
        expected = "accepted" if status == 202 else "duplicate"
        if (
            not isinstance(data, dict)
            or set(data) != {"status", "event_id"}
            or data["status"] != expected
            or data["event_id"] != str(row.pk)
        ):
            return "pending", "invalid_acknowledgement"
        return "acknowledged", ""
    if status == 409:
        return "dead", "event_conflict"
    if 300 <= status < 400:
        return "dead", "redirect_rejected"
    if status in (400, 401, 403, 404, 413, 422):
        return "dead", "delivery_rejected"
    return "pending", "collector_unavailable"


def deliver_one(transport=None):
    require_isolated_database()
    keys = {app: os.environ.get("SB_REF_DELIVERY_" + app.upper(), "") for app in APP_KEYS}
    if any(len(key) < 32 for key in keys.values()) or len(set(keys.values())) != len(keys):
        raise ImproperlyConfigured("Separate reference delivery signing keys are required.")
    transport = NativeTransport() if transport is None else transport
    row = claim(timezone.now())
    if row is None:
        return None
    try:
        validate_event(row.payload, row.app)
        body = canonical(row.payload)
        if (
            row.app not in APP_KEYS
            or len(body) > MAX_EVENT_BYTES
            or row.digest != digest(row.payload)
            or row.payload["event_id"] != str(row.pk)
        ):
            raise DeliveryError("invalid_outbox_record")
    except (ValueError, KeyError, TypeError):
        return finish(row, "dead", "invalid_outbox_record")
    at, key_id = timezone.now().isoformat(), APP_KEYS[row.app]
    headers = {
        "Content-Type": "application/json",
        "X-SB-Key": key_id,
        "X-SB-Time": at,
        "X-SB-Signature": signature(keys[row.app], row.app, key_id, at, body),
    }
    try:
        status, response = transport(row.app, body, headers)
        result, error = response_result(row, status, response)
    except (OSError, http.client.HTTPException, DeliveryError, ValueError, TypeError):
        result, error = "pending", "transport_failed"
    return finish(row, result, error)
