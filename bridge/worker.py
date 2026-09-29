import hashlib
from datetime import timedelta
from datetime import timezone as datetime_timezone

from django.db import transaction
from django.utils import timezone

from .case_provenance import generation_record
from .detection_catalog import engine_source_state
from .engine import R1_WINDOW_SECONDS, detections
from .models import Audit, Event, Integration, Investigation, WorkerHeartbeat

MAX_CORRELATION_EVENTS = 10000


class CorrelationCapacityError(ValueError):
    pass


def _relevant_events(event):
    if event.operation != "private_record.read" or event.outcome not in ("denied", "not_visible"):
        return [event]
    at = event.occurred_at.astimezone(datetime_timezone.utc)
    window = timedelta(seconds=R1_WINDOW_SECONDS)
    relevant = list(
        Event.objects.filter(
            integration_id=event.integration_id,
            actor=event.actor,
            environment=event.environment,
            source=event.source,
            operation="private_record.read",
            outcome__in=("denied", "not_visible"),
            occurred_at__gte=at - window,
            occurred_at__lte=at + window,
        )
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
        case.save(update_fields=["status", "version"])
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


def process_one():
    candidate = (
        Event.objects.filter(state="pending", available_at__lte=timezone.now())
        .only("id", "integration_id")
        .order_by("received_at")
        .first()
    )
    if candidate is None:
        return False
    failure = None
    with transaction.atomic():
        # Keep retry state and processing decisions under the same app/event locks.
        Integration.objects.select_for_update().get(pk=candidate.integration_id)
        event = Event.objects.select_for_update().get(pk=candidate.pk)
        if event.state != "pending" or event.available_at > timezone.now():
            return True
        try:
            # A processing error rolls back its evidence writes but retains the locks.
            with transaction.atomic():
                relevant = _relevant_events(event)
                by_id = {str(record.event_id): record for record in relevant}
                source_before = (
                    engine_source_state()
                    if event.operation == "private_record.read"
                    and (
                        event.outcome in ("denied", "not_visible")
                        or (
                            event.outcome == "allowed"
                            and event.reason in ("membership_removed", "policy_regression")
                        )
                    )
                    else None
                )
                for finding in detections(
                    [record.payload for record in relevant],
                    endpoint_from=event.occurred_at,
                    endpoint_to=event.occurred_at + timedelta(seconds=R1_WINDOW_SECONDS),
                ):
                    _attach_finding(event, finding, by_id, source_before)
                event.state = "processed"
                event.error_code = ""
                event.save(update_fields=["state", "error_code"])
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


def drain(limit=500):
    processed = 0
    WorkerHeartbeat.objects.update_or_create(name="default", defaults={"last_seen": timezone.now()})
    while processed < limit and process_one():
        processed += 1
    return processed
