"""Closed metadata derived by the source; content and credentials never enter it."""

import hashlib
import hmac
import os
import uuid

from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from bridge.contract import digest, validate_event

from .models import Outbox


def pseudonym(app, category, value):
    if app not in ("documents", "expenses") or category not in ("account", "resource"):
        raise ValueError("Unsupported reference scope.")
    key = os.environ.get("SB_REF_PSEUDO_" + app.upper(), "")
    if len(key) < 32:
        raise ImproperlyConfigured("A dedicated stable reference pseudonym key is required.")
    return hmac.new(key.encode(), f"{app}:{category}:{value}".encode(), hashlib.sha256).hexdigest()


def emit(resource, actor, outcome, reason, membership=None):
    now, identifier = timezone.now(), uuid.uuid4()
    value = {
        "schema_version": 2 if membership else 1,
        "event_id": str(identifier),
        "app": resource.app,
        "environment": "lab",
        "occurred_at": now.isoformat(),
        "actor": pseudonym(resource.app, "account", actor.pk),
        "resource": pseudonym(resource.app, "resource", resource.pk),
        "episode": str(uuid.uuid5(uuid.NAMESPACE_URL, resource.app + ":" + str(resource.pk))),
        "operation": "membership.change" if membership else "private_record.read",
        "outcome": outcome,
        "reason": reason,
        "context": None,
    }
    if membership:
        value["membership"] = {
            "subject": pseudonym(resource.app, "account", membership[0].pk),
            "state": membership[1],
        }
    validate_event(value, resource.app, now=now)
    return Outbox.objects.create(
        id=identifier, app=resource.app, payload=value, digest=digest(value), available_at=now
    )
