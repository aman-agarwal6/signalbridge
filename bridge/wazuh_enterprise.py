"""Durable forwarded signals and sanitized native-format links; no tool startup."""

import uuid
from types import SimpleNamespace

from django.db import transaction
from django.utils import timezone

from integrations.wazuh_enterprise.contract import (
    MAX_INCLUDED_IDS,
    validate_observation,
    validate_signal,
)

from .case_provenance import _consistent, case_generation
from .contract import canonical, digest, parse_json, validate_event
from .detection_catalog import RULES, engine_source_state
from .models import Audit, ForwardedDetection, Investigation, SocBatch
from .soc_delivery import (
    MAX_BATCH_BYTES,
    MAX_RECORDS,
    MAX_STREAM_BYTES,
    _app,
    _append,
    _locked_stream,
    collector_path,
    require,
    sha256,
)


def observation_packet(event, app):
    """Preserve minimal metadata; no actor, resource, claims or private content."""
    require(event.integration_id == app.pk and event.state == "processed", "event_scope_mismatch")
    require(
        _consistent(SimpleNamespace(integration_id=app.pk, integration=app), event),
        "event_integrity_mismatch",
    )
    validate_event(event.payload, app.slug, now=event.occurred_at)
    row = {
        "signalbridge": {
            "export_version": 2,
            "app": app.slug,
            "environment": event.environment,
            "event_id": str(event.event_id),
            "occurred_at": event.occurred_at.isoformat(),
            "operation": event.operation,
            "outcome": event.outcome,
            "reason": event.reason,
            "source": event.source,
        }
    }
    validate_observation(row)
    return row


def signal_snapshot(case):
    events = list(case.events.order_by("event_id")[:1001])
    require(1 <= len(events) <= 1000, "case_evidence_bound")
    engine = engine_source_state()
    require(not engine["restart_required"], "engine_restart_required")
    generation = case_generation(case, events, engine["process_source_sha256"])
    require(
        generation["status"] == "recorded" and generation["same_current_engine"],
        "case_generation_unverified",
    )
    require(
        case.rule in RULES and case.severity == RULES[case.rule]["severity"],
        "unsupported_core_rule",
    )
    require(
        len({e.environment for e in events}) == 1 and len({e.source for e in events}) == 1,
        "mixed_case_scope",
    )
    source = generation["record"]["process_source_sha256"]
    fingerprint = generation["record"]["evidence_sha256"]
    row = {
        "signalbridge_detection": {
            "signal_version": 1,
            "origin": "signalbridge",
            "app": case.integration.slug,
            "signal_id": str(uuid.uuid4()),
            "case_id": str(case.pk),
            "case_version": case.version,
            "rule_id": case.rule,
            "rule_version": RULES[case.rule]["version"],
            "severity": case.severity,
            "environment": events[0].environment,
            "source": events[0].source,
            "generated_at": timezone.now().isoformat(),
            "evidence_sha256": fingerprint,
            "generation_source_sha256": source,
            "evidence_count": len(events),
            "included_event_ids": ",".join(str(e.event_id) for e in events[:MAX_INCLUDED_IDS]),
            "evidence_complete": int(len(events) <= MAX_INCLUDED_IDS),
        }
    }
    validate_signal(row)
    return row


def stage_signals(app):
    """Select at most 25 open cases; evidence changes produce a new logical signal."""
    _app(app)
    with transaction.atomic(durable=True):
        stream = _locked_stream(app, create=True, channel="detection")
        pending = SocBatch.objects.filter(stream=stream, state="staged").first()
        if pending:
            return pending
        packets, values = [], []
        cases = (
            Investigation.objects.select_for_update()
            .filter(
                integration=app,
                status="open",
                rule__in=RULES,
            )
            .select_related("integration")
            .order_by("pk")
        )
        if stream.selection_after:
            cases = cases.filter(pk__gt=stream.selection_after)
        cases = list(cases[:25])
        # A persistent bounded sweep avoids permanently reselecting the first
        # already-exported cases. A later evidence update is seen on the next sweep.
        stream.selection_after = cases[-1].pk if len(cases) == 25 else None
        stream.save(update_fields=["selection_after"])
        for case in cases:
            packet = signal_snapshot(case)
            row = packet["signalbridge_detection"]
            key = {
                "investigation": case,
                "evidence_sha256": row["evidence_sha256"],
                "generation_source_sha256": row["generation_source_sha256"],
                "rule_version": row["rule_version"],
            }
            if ForwardedDetection.objects.filter(**key).exists():
                continue
            packets.append(packet)
            values.append(
                {
                    **key,
                    "id": row["signal_id"],
                    "case_version": case.version,
                    "packet": packet,
                    "packet_sha256": digest(packet),
                }
            )
        if not packets:
            return None
        body = b"".join(canonical(packet) + b"\n" for packet in packets)
        require(
            len(body) <= MAX_BATCH_BYTES and stream.offset + len(body) <= MAX_STREAM_BYTES,
            "signal_capacity_reached",
        )
        from .soc_rotation import reserve_segment

        segment = reserve_segment(stream, body)
        batch = SocBatch.objects.create(
            stream=stream,
            segment=segment,
            body=body.decode("ascii"),
            body_sha256=sha256(body),
            start_offset=stream.offset,
            record_count=len(values),
        )
        ForwardedDetection.objects.bulk_create(
            [ForwardedDetection(batch=batch, **value) for value in values]
        )
        Audit.objects.create(
            integration=app,
            action="wazuh.signals_staged",
            object_id=str(batch.pk),
            detail={
                "signals": len(values),
                "body_sha256": batch.body_sha256,
                "native_observed": False,
            },
        )
        return batch


def signal_body(batch, app):
    require(
        batch.stream.integration_id == app.pk and batch.stream.channel == "detection",
        "signal_stream_scope_mismatch",
    )
    body = batch.body.encode("ascii")
    require(
        0 < len(body) <= MAX_BATCH_BYTES and sha256(body) == batch.body_sha256,
        "signal_batch_digest_mismatch",
    )
    signals = {
        str(row.pk): row
        for row in ForwardedDetection.objects.filter(batch=batch).select_related("investigation")[
            : MAX_RECORDS + 1
        ]
    }
    lines = body.splitlines(keepends=True)
    require(
        0 < len(signals) == len(lines) == batch.record_count <= MAX_RECORDS,
        "signal_ledger_mismatch",
    )
    seen = set()
    for line in lines:
        require(line.endswith(b"\n"), "signal_batch_incomplete")
        packet = parse_json(line)
        row = validate_signal(packet)
        signal = signals.get(row["signal_id"])
        require(signal is not None and row["signal_id"] not in seen, "signal_ledger_mismatch")
        require(
            signal.investigation.integration_id == app.pk and row["app"] == app.slug,
            "signal_scope_mismatch",
        )
        require(
            signal.packet == packet
            and signal.packet_sha256 == digest(packet)
            and canonical(packet) + b"\n" == line,
            "signal_packet_changed",
        )
        require(
            signal.evidence_sha256 == row["evidence_sha256"]
            and signal.case_version == row["case_version"]
            and signal.rule_version == row["rule_version"]
            and signal.generation_source_sha256 == row["generation_source_sha256"],
            "signal_binding_changed",
        )
        seen.add(row["signal_id"])
    return body


def publish_signals(app):
    _app(app)
    with transaction.atomic(durable=True):
        stream = _locked_stream(app, create=False, channel="detection")
        batch = SocBatch.objects.filter(stream=stream, state="staged").first()
        if batch is None:
            return None
        require(batch.start_offset == stream.offset, "signal_offset_changed")
        body = signal_body(batch, app)
        if stream.segmented_export:
            from .soc_rotation import append_segment

            stream.offset, stream.prefix_sha256, resumed = append_segment(stream, batch, body)
        else:
            require(batch.segment_id is None, "unexpected_signal_segment")
            stream.offset, stream.prefix_sha256, resumed = _append(
                collector_path(stream), stream, body
            )
        stream.save(update_fields=["offset", "prefix_sha256"])
        batch.state, batch.appended_at = "file_appended", timezone.now()
        batch.save(update_fields=["state", "appended_at"])
        Audit.objects.create(
            integration=app,
            action="wazuh.signals_appended",
            object_id=str(batch.pk),
            detail={
                "signals": batch.record_count,
                "recovered_bytes": resumed,
                "native_observed": False,
            },
        )
        return batch
