import hashlib
import re
from datetime import timedelta
from datetime import timezone as datetime_timezone

from django.db import connection, transaction
from django.db.models import Exists, OuterRef, Q, Subquery
from django.utils import timezone

from .case_provenance import generation_record
from .detection_catalog import engine_source_state
from .engine import (
    MEMBERSHIP_WINDOW_SECONDS,
    R1_WINDOW_SECONDS,
    R4_WINDOW_SECONDS,
    R5_WINDOW_SECONDS,
    detections,
    membership_evaluations,
)
from .models import Audit, Event, Integration, Investigation, WorkerHeartbeat

MAX_CORRELATION_EVENTS = 10000
HEARTBEAT_SECONDS = 10


def validate_worker_id(worker_id):
    if not isinstance(worker_id, str) or not re.fullmatch(
        r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,39}", worker_id
    ):
        raise ValueError(
            "Worker identity must contain 1–40 letters, digits, dots, dashes or underscores."
        )
    return worker_id


class CorrelationCapacityError(ValueError):
    pass


def _relevant_events(event):
    if event.operation == "private_record.read" and event.outcome == "allowed":
        # A read needs the latest strictly preceding assertion, including all
        # assertions tied at that instant. Loading every other read over 48 hours
        # made routine sustained access needlessly hit the correlation ceiling.
        assertions = Event.objects.filter(
            integration_id=event.integration_id,
            resource=event.resource,
            environment=event.environment,
            source=event.source,
            operation="membership.change",
            membership_subject=event.actor,
            payload__schema_version=2,
            occurred_at__gte=event.occurred_at - timedelta(seconds=MEMBERSHIP_WINDOW_SECONDS),
            occurred_at__lt=event.occurred_at,
        )
        latest = assertions.order_by("-occurred_at").values_list("occurred_at", flat=True).first()
        if latest is None:
            return [event]
        relevant = list(
            assertions.filter(occurred_at=latest)
            .only("id", "event_id", "payload", "digest", "source")
            .order_by("event_id")[:MAX_CORRELATION_EVENTS]
        )
        relevant.append(event)
        if len(relevant) > MAX_CORRELATION_EVENTS:
            raise CorrelationCapacityError(
                "Membership correlation exceeds the supported event capacity."
            )
        return relevant
    if event.operation == "membership.change" and event.payload.get("schema_version") == 2:
        window = timedelta(seconds=MEMBERSHIP_WINDOW_SECONDS)
        subject = event.membership_subject
        relevant = list(
            Event.objects.filter(
                integration_id=event.integration_id,
                resource=event.resource,
                environment=event.environment,
                source=event.source,
                operation__in=("membership.change", "private_record.read"),
                outcome="allowed",
                occurred_at__gte=event.occurred_at - window,
                occurred_at__lte=event.occurred_at + window,
            )
            .filter(
                Q(operation="membership.change", membership_subject=subject)
                | Q(operation="private_record.read", actor=subject)
            )
            .only("id", "event_id", "payload", "digest", "source")
            .order_by("occurred_at", "event_id")[: MAX_CORRELATION_EVENTS + 1]
        )
        if len(relevant) > MAX_CORRELATION_EVENTS:
            raise CorrelationCapacityError(
                "Membership correlation exceeds the supported event capacity."
            )
        return relevant
    if event.operation != "private_record.read" or event.outcome not in ("denied", "not_visible"):
        return [event]
    at = event.occurred_at.astimezone(datetime_timezone.utc)
    window = timedelta(
        seconds=R4_WINDOW_SECONDS if event.outcome == "denied" else R1_WINDOW_SECONDS
    )
    scopes = Q(actor=event.actor)
    if event.outcome == "denied":
        distributed_window = timedelta(seconds=R5_WINDOW_SECONDS)
        scopes |= Q(
            resource=event.resource,
            outcome="denied",
            occurred_at__gte=at - distributed_window,
            occurred_at__lte=at + distributed_window,
        )
    relevant = list(
        Event.objects.filter(
            integration_id=event.integration_id,
            environment=event.environment,
            source=event.source,
            operation="private_record.read",
            outcome__in=("denied", "not_visible"),
            occurred_at__gte=at - window,
            occurred_at__lte=at + window,
        )
        .filter(scopes)
        .only("id", "event_id", "payload", "digest", "source")
        .order_by("occurred_at", "event_id")[: MAX_CORRELATION_EVENTS + 1]
    )
    if len(relevant) > MAX_CORRELATION_EVENTS:
        raise CorrelationCapacityError(
            "Correlation lookaround exceeds the supported event capacity."
        )
    return relevant


def _attach_finding(event, finding, relevant, source_before):
    correlation = hashlib.sha256((event.source + "|" + finding["correlation"]).encode()).hexdigest()
    case, created = Investigation.objects.select_for_update().get_or_create(
        integration_id=event.integration_id,
        rule=finding["rule"],
        correlation=correlation,
        defaults={key: finding[key] for key in ("severity", "title", "explanation")},
    )
    evidence = [relevant[identifier] for identifier in finding["event_ids"]]
    retained = list(case.events.values_list("pk", "event_id", "digest", "source"))
    attached = {row[0] for row in retained}
    additions = [record for record in evidence if record.pk not in attached]
    if not additions:
        return
    previous_status = case.status
    case.events.add(*additions)
    if not created:
        case.status = "open"
        case.version += 1
        if finding["rule"] == "R3":
            for field in ("severity", "title", "explanation"):
                setattr(case, field, finding[field])
        case.save(update_fields=["status", "version", "severity", "title", "explanation"])
    action = (
        "case.created"
        if created
        else "case.reopened"
        if previous_status != "open"
        else "case.evidence_added"
    )
    bindings = [(identifier, checksum, source) for _, identifier, checksum, source in retained]
    bindings.extend((record.event_id, record.digest, record.source) for record in additions)
    Audit.objects.create(
        integration_id=event.integration_id,
        action=action,
        object_id=str(case.pk),
        detail={
            "rule": case.rule,
            "source": event.source,
            "previous_status": previous_status,
            "evidence_added": len(additions),
            "version": case.version,
            "generation": generation_record(case, bindings, source_before, engine_source_state()),
        },
    )


def _claim_event(now):
    """Acquire the app first, matching ingestion's lock order.

    PostgreSQL skips apps another consumer owns, then skips locked event rows.
    SQLite has no row locks and remains a single-worker development backend.
    Call only inside the transaction that commits evidence and completion.
    """
    eligible = Event.objects.filter(state="pending", available_at__lte=now)
    if connection.features.has_select_for_update_skip_locked:
        app_events = eligible.filter(integration_id=OuterRef("pk"))
        app = (
            Integration.objects.filter(Exists(app_events))
            .annotate(
                oldest_pending=Subquery(
                    app_events.order_by("received_at", "pk").values("received_at")[:1]
                )
            )
            .order_by("oldest_pending", "pk")
            .select_for_update(skip_locked=True)
            .first()
        )
        if app is None:
            return None
        return (
            eligible.filter(integration_id=app.pk)
            .order_by("received_at", "pk")
            .select_for_update(skip_locked=True)
            .first()
        )
    candidate = eligible.only("id", "integration_id").order_by("received_at", "pk").first()
    if candidate is None:
        return None
    Integration.objects.select_for_update().get(pk=candidate.integration_id)
    event = Event.objects.select_for_update().get(pk=candidate.pk)
    if event.state != "pending" or event.available_at > now:
        return None
    return event


def process_one(worker_id="default"):
    worker_id = validate_worker_id(worker_id)
    failure = None
    with transaction.atomic():
        event = _claim_event(timezone.now())
        if event is None:
            return False
        event.processing_attempts += 1
        event.processing_started_at = timezone.now()
        event.save(update_fields=["processing_attempts", "processing_started_at"])
        try:
            # A processing error rolls back its evidence writes but retains the locks.
            with transaction.atomic():
                relevant = _relevant_events(event)
                by_id = {str(record.event_id): record for record in relevant}
                source_before = (
                    engine_source_state()
                    if any(record.payload.get("schema_version") == 2 for record in relevant)
                    or event.outcome in ("denied", "not_visible")
                    or event.reason in ("membership_removed", "policy_regression")
                    else None
                )
                window_seconds = (
                    MEMBERSHIP_WINDOW_SECONDS
                    if event.operation == "membership.change" or event.outcome == "allowed"
                    else R4_WINDOW_SECONDS
                    if event.outcome == "denied"
                    else R1_WINDOW_SECONDS
                )
                for finding in detections(
                    [record.payload for record in relevant],
                    endpoint_from=event.occurred_at,
                    endpoint_to=event.occurred_at + timedelta(seconds=window_seconds),
                ):
                    _attach_finding(event, finding, by_id, source_before)
                # Late grants or conflicting timestamps must not leave an old
                # alert appearing unqualified. Keep its history and reopen for review.
                for finding in membership_evaluations(
                    [record.payload for record in relevant],
                    endpoint_from=event.occurred_at,
                    endpoint_to=event.occurred_at + timedelta(seconds=window_seconds),
                ):
                    correlation = hashlib.sha256(
                        (event.source + "|" + finding["correlation"]).encode()
                    ).hexdigest()
                    if (
                        not finding["matches"]
                        and Investigation.objects.filter(
                            integration_id=event.integration_id,
                            rule="R3",
                            correlation=correlation,
                        ).exists()
                    ):
                        _attach_finding(event, finding, by_id, source_before)
                event.state = "processed"
                event.error_code = ""
                event.processed_at = timezone.now()
                event.processed_by = worker_id
                event.save(update_fields=["state", "error_code", "processed_at", "processed_by"])
        except Exception as error:
            failure = error
            attempts = event.attempts + 1
            Event.objects.filter(pk=event.pk, state="pending").update(
                attempts=attempts,
                state="dead" if attempts >= 5 else "pending",
                error_code="correlation_capacity"
                if isinstance(error, CorrelationCapacityError)
                else "processing_failed",
                available_at=timezone.now() + timedelta(seconds=min(2**attempts, 300)),
            )
    if failure is not None:
        raise failure
    return True


def drain(limit=500, worker_id="default"):
    worker_id = validate_worker_id(worker_id)
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise ValueError("Drain limit must be between 1 and 10000.")
    processed = 0
    last_heartbeat = timezone.now()
    WorkerHeartbeat.objects.update_or_create(name=worker_id, defaults={"last_seen": last_heartbeat})
    while processed < limit and process_one(worker_id=worker_id):
        processed += 1
        now = timezone.now()
        if (now - last_heartbeat).total_seconds() >= HEARTBEAT_SECONDS:
            WorkerHeartbeat.objects.update_or_create(name=worker_id, defaults={"last_seen": now})
            last_heartbeat = now
    return processed
