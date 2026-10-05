"""Two app-scoped machine capabilities with replay and idempotency controls.

Independent from browser sessions. These endpoints cannot close investigations,
change source accounts, send messages or perform containment.
"""

import hashlib
import hmac
import json
import os
import re
import uuid
from datetime import timedelta

from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .case_workflow import evidence_binding
from .contract import parse_json, timestamp
from .models import (
    Audit,
    CaseTask,
    Integration,
    Investigation,
    ServiceCredential,
    ServiceNonce,
    ServiceRequest,
)
from .services import WorkflowError

MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 128 * 1024


class ServiceError(ValueError):
    def __init__(self, code, status=400):
        self.code, self.status = code, status
        super().__init__(code)


def request_signature(secret, key_id, nonce, at, method, path, body):
    value = "\n".join(
        ("SB-SERVICE/1", key_id, nonce, at, method, path, hashlib.sha256(body).hexdigest())
    )
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def uuid_value(value):
    try:
        identifier = uuid.UUID(value)
        if str(identifier) != value:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ServiceError("invalid_request") from None
    return identifier


def authenticate_request(request, capability):
    """Caller owns the transaction for authentication, request and task commit."""
    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Machine authentication requires a transaction.")
    if request.META.get("QUERY_STRING") or len(request.body) > MAX_REQUEST_BYTES:
        raise ServiceError("request_bound_exceeded", 413)
    key_id = request.headers.get("X-SB-Service-Key", "")
    nonce = request.headers.get("X-SB-Service-Nonce", "")
    at = request.headers.get("X-SB-Service-Time", "")
    supplied = request.headers.get("X-SB-Service-Signature", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key_id) or not re.fullmatch(
        r"[a-f0-9]{64}", supplied
    ):
        raise ServiceError("invalid_authentication", 401)
    try:
        nonce_id = uuid_value(nonce)
        sent_at = timestamp(at)
    except ValueError:
        raise ServiceError("invalid_authentication", 401) from None
    now = timezone.now()
    if abs((now - sent_at).total_seconds()) > 60:
        raise ServiceError("invalid_authentication", 401)
    initial = ServiceCredential.objects.filter(key_id=key_id, active=True).first()
    if initial is None or not re.fullmatch(r"SB_SERVICE_[A-Z0-9_]{1,80}", initial.secret_env):
        raise ServiceError("invalid_authentication", 401)
    secret = os.environ.get(initial.secret_env, "")
    if len(secret) < 32 or not hmac.compare_digest(
        supplied,
        request_signature(secret, key_id, nonce, at, request.method, request.path, request.body),
    ):
        raise ServiceError("invalid_authentication", 401)
    app = Integration.objects.select_for_update().get(pk=initial.integration_id)
    credential = ServiceCredential.objects.select_for_update().get(pk=initial.pk)
    if (
        not app.enabled
        or not credential.active
        or credential.integration_id != app.pk
        or credential.key_id != initial.key_id
        or credential.secret_env != initial.secret_env
        or credential.capability != capability
        or not hmac.compare_digest(secret, os.environ.get(credential.secret_env, ""))
    ):
        raise ServiceError("insufficient_scope", 403)
    ServiceNonce.objects.filter(
        credential=credential, created_at__lt=now - timedelta(minutes=5)
    ).delete()
    if ServiceNonce.objects.filter(credential=credential, nonce=nonce_id).exists():
        raise ServiceError("request_replayed", 409)
    if (
        ServiceNonce.objects.filter(
            credential=credential, created_at__gte=now - timedelta(minutes=1)
        ).count()
        >= 60
    ):
        raise ServiceError("request_rate_exceeded", 429)
    ServiceNonce.objects.create(credential=credential, nonce=nonce_id)
    return credential


def scoped_case(credential, case_id):
    case = (
        Investigation.objects.select_related("integration")
        .select_for_update()
        .filter(
            pk=case_id,
            integration_id=credential.integration_id,
        )
        .first()
    )
    if case is None:
        raise ServiceError("case_unavailable", 404)
    return case


def bounded_response(value, status=200):
    if len(json.dumps(value, separators=(",", ":")).encode()) > MAX_RESPONSE_BYTES:
        raise ServiceError("evidence_bound_exceeded", 413)
    response = JsonResponse(value, status=status)
    response["Cache-Control"] = "no-store"
    return response


def error_response(error):
    response = JsonResponse({"error": error.code}, status=error.status)
    response["Cache-Control"] = "no-store"
    return response


def authenticated_operation(request, capability, operation):
    try:
        with transaction.atomic():
            credential = authenticate_request(request, capability)
            # Valid authentication consumes its nonce/rate slot even if a case
            # operation fails. Only the operation's writes roll back.
            try:
                with transaction.atomic():
                    return operation(credential)
            except ServiceError as error:
                return error_response(error)
            except WorkflowError:
                return error_response(ServiceError("evidence_unavailable", 409))
            except (ValueError, KeyError, TypeError):
                return error_response(ServiceError("invalid_request"))
    except ServiceError as error:
        return error_response(error)


@require_GET
def read_evidence(request, case_id):
    def operation(credential):
        case = scoped_case(credential, case_id)
        events = list(
            case.events.filter(integration_id=case.integration_id).order_by("event_id")[:101]
        )
        if len(events) > 100:
            raise ServiceError("evidence_bound_exceeded", 413)
        value = {
            "schema_version": 1,
            "application": case.integration.slug,
            "case_id": str(case.pk),
            "case_version": case.version,
            "evidence_sha256": evidence_binding(case),
            "rule": case.rule,
            "severity": case.severity,
            "disposition": case.status,
            "events": [
                {
                    "event_id": str(e.event_id),
                    "source": e.source,
                    "payload": e.payload,
                    "payload_sha256": e.digest,
                }
                for e in events
            ],
            "limits": [
                "Signed metadata does not independently attest source truth. Free-text analyst notes are excluded."
            ],
        }
        response = bounded_response(value)
        Audit.objects.create(
            integration=case.integration,
            action="case.machine_evidence_read",
            object_id=str(case.pk),
            detail={"credential_id": credential.key_id, "case_version": case.version},
        )
        return response

    return authenticated_operation(request, "read_case_evidence", operation)


@csrf_exempt
@require_POST
def create_review_task(request, case_id):
    if request.content_type != "application/json":
        return error_response(ServiceError("bounded_json_required", 415))

    def operation(credential):
        value = parse_json(request.body)
        if (
            not isinstance(value, dict)
            or set(value) != {"case_version", "evidence_sha256", "idempotency_key", "task_kind"}
            or type(value["case_version"]) is not int
            or value["case_version"] < 1
            or not isinstance(value["evidence_sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", value["evidence_sha256"])
            or value["task_kind"] != "review_case_evidence"
        ):
            raise ServiceError("invalid_request")
        identifier = uuid_value(value["idempotency_key"])
        request_hash = hashlib.sha256(request.path.encode() + b"\n" + request.body).hexdigest()
        previous = ServiceRequest.objects.filter(
            credential=credential, idempotency_key=identifier
        ).first()
        if previous and previous.request_sha256 != request_hash:
            raise ServiceError("idempotency_conflict", 409)
        case = scoped_case(credential, case_id)
        binding = evidence_binding(case)
        expected_version = previous.response["case_version"] if previous else value["case_version"]
        if case.version != expected_version or binding != value["evidence_sha256"]:
            raise ServiceError("case_evidence_changed", 409)
        if previous:
            if previous.task.investigation_id != case.pk:
                raise ServiceError("idempotency_conflict", 409)
            return bounded_response({**previous.response, "duplicate": True})
        case.version += 1
        task = CaseTask.objects.create(
            investigation=case,
            kind="review",
            title="Review current case evidence",
            case_version=case.version,
            evidence_sha256=binding,
        )
        case.save(update_fields=["version"])
        result = {
            "task_id": str(task.pk),
            "case_id": str(case.pk),
            "case_version": case.version,
            "evidence_sha256": binding,
            "idempotency_key": str(identifier),
            "duplicate": False,
        }
        ServiceRequest.objects.create(
            credential=credential,
            idempotency_key=identifier,
            request_sha256=request_hash,
            task=task,
            response=result,
        )
        Audit.objects.create(
            integration_id=case.integration_id,
            action="case.machine_review_task",
            object_id=str(case.pk),
            detail={
                "credential_id": credential.key_id,
                "task_id": str(task.pk),
                "case_version": case.version,
            },
        )
        return bounded_response(result, 201)

    return authenticated_operation(request, "create_review_task", operation)
