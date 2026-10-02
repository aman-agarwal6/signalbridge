import hmac
import os
import re
from datetime import timedelta

from django.db import transaction
from django.db.models import F
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .contract import (
    ContractError,
    digest,
    parse_json,
    signature,
    timestamp,
    validate_event,
)
from .models import Event, IngestKey, Integration


@csrf_exempt
@require_POST
def ingest(request, app):
    integration = Integration.objects.filter(slug=app, enabled=True).first()

    def reject(message, status):
        if integration:
            Integration.objects.filter(pk=integration.pk).update(rejected=F("rejected") + 1)
        return JsonResponse({"error": message}, status=status)

    if not integration:
        return reject("Unknown integration.", 404)
    if request.content_type != "application/json":
        return reject("JSON required.", 415)
    try:
        length = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        return reject("Invalid length.", 400)
    if length < 0:
        return reject("Invalid length.", 400)
    if length > 16384:
        return reject("Payload too large.", 413)
    raw = request.body
    if len(raw) > 16384:
        return reject("Payload too large.", 413)
    key_id = request.headers.get("X-SB-Key", "")
    key = IngestKey.objects.filter(key_id=key_id, integration=integration, active=True).first()
    secret = os.environ.get(key.secret_env, "") if key else ""
    supplied = request.headers.get("X-SB-Signature", "")
    sent_at = request.headers.get("X-SB-Time", "")
    if len(secret) < 32 or not re.fullmatch("[a-f0-9]{64}", supplied):
        return reject("Invalid authentication.", 401)
    try:
        if abs((timezone.now() - timestamp(sent_at)).total_seconds()) > 300:
            raise ContractError()
    except ContractError:
        return reject("Invalid authentication.", 401)
    if not hmac.compare_digest(signature(secret, app, key_id, sent_at, raw), supplied):
        return reject("Invalid authentication.", 401)
    try:
        data = validate_event(parse_json(raw), app)
        if data["environment"] != key.environment:
            raise ContractError("Credential environment mismatch.")
    except (ContractError, TypeError):
        return reject("Invalid event contract.", 400)
    if data["schema_version"] == 2 and not key.can_assert_membership:
        return reject("Credential cannot assert membership state.", 403)
    if key.source not in {value for value, _ in IngestKey._meta.get_field("source").choices}:
        return reject("Invalid authentication.", 401)
    with transaction.atomic():
        # Serializes this app's acceptance/rate check on PostgreSQL.
        integration = Integration.objects.select_for_update().get(pk=integration.pk)
        if not integration.enabled:
            return reject("Unknown integration.", 404)
        current_key = (
            IngestKey.objects.select_for_update()
            .filter(pk=key.pk, integration=integration, active=True)
            .first()
        )
        if (
            current_key is None
            or any(
                getattr(current_key, field) != getattr(key, field)
                for field in (
                    "key_id",
                    "secret_env",
                    "environment",
                    "source",
                    "can_assert_membership",
                )
            )
            or not hmac.compare_digest(
                os.environ.get(current_key.secret_env, "").encode(), secret.encode()
            )
        ):
            return reject("Invalid authentication.", 401)
        existing = (
            Event.objects.filter(integration=integration, event_id=data["event_id"])
            .only("event_id", "digest", "source")
            .first()
        )
        if existing:
            if existing.digest != digest(data) or existing.source != key.source:
                return reject("Event ID already has different content.", 409)
            return JsonResponse({"status": "duplicate", "event_id": str(existing.event_id)})
        if (
            Event.objects.filter(
                integration=integration,
                received_at__gte=timezone.now() - timedelta(minutes=1),
            ).count()
            >= 600
        ):
            return reject("Delivery rate exceeded.", 429)
        event = Event.objects.create(
            integration=integration,
            event_id=data["event_id"],
            occurred_at=timestamp(data["occurred_at"]),
            actor=data["actor"],
            membership_subject=(
                data["membership"]["subject"] if data["schema_version"] == 2 else ""
            ),
            resource=data["resource"],
            episode=data["episode"],
            operation=data["operation"],
            outcome=data["outcome"],
            reason=data["reason"],
            environment=data["environment"],
            source=key.source,
            payload=data,
            digest=digest(data),
            available_at=timezone.now(),
        )
        integration.last_seen = timezone.now()
        integration.save(update_fields=["last_seen"])
    return JsonResponse({"status": "accepted", "event_id": str(event.event_id)}, status=202)
