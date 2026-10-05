"""Historical native receipts, never a live connector or source-event importer.

Only the local operator loader admits execution proof. Retained hashes check
consistency under the trusted local administrator boundary, not attestation.
"""

import hashlib
import re
import uuid
from collections import Counter
from datetime import timedelta
from types import SimpleNamespace

from django.conf import settings
from django.db import transaction
from django.db.models import OuterRef, Subquery
from django.db.models.fields.json import KT
from django.utils import timezone

from integrations.enterprise.reference_host_controls import same
from integrations.enterprise.verification import private_run_directory, validate_identity
from integrations.wazuh_enterprise.collector_host_controls import image_identity
from integrations.wazuh_enterprise.collector_profile import IMAGE
from integrations.wazuh_enterprise.collector_source_binding import load_binding, read_bytes
from integrations.wazuh_enterprise.contract import (
    expected_rule,
    identifier,
    require,
    validate_observation,
    validate_signal,
)
from integrations.zap_enterprise.scanner_host_controls import validate_shutdown

from .case_provenance import _consistent, case_generation
from .contract import canonical, digest, parse_json, timestamp
from .models import Audit, CheckRun, Event, Integration, Investigation
from .native_receipts import admission_audits, matches_result
from .services import write_membership

KIND = "native_wazuh_reference_bootstrap"
PROFILE = "reference-bootstrap-v1"
PUBLICATION_PROFILE = "ready-publication-v1"
HOST_KINDS = {
    "signalbridge-native-wazuh-reference-bootstrap": PROFILE,
    "signalbridge-native-wazuh-ready-publication": PUBLICATION_PROFILE,
}
SUITE = "Native Wazuh collection"
APPS = ("documents", "expenses")
LIMITATIONS = [
    "Historical ten-minute snapshot execution; the collector was stopped. No current connection or continuous delivery is established.",
    "Input and output hashes, executable snapshot, native capture journal and shutdown receipts were revalidated by the trusted local operator; this is not independent attestation.",
    "Source observations and SignalBridge findings forwarded to Wazuh are separate. A forwarded R3 alert is not independent Wazuh rediscovery.",
    "Only matching existing local evidence can be linked. This import creates no source events, investigations or remediation decisions.",
    "Native rotation recovery, a 24-hour run, the indexer/dashboard and production coverage are outside this receipt.",
]
PUBLICATION_LIMITATIONS = [
    "Recorded replay of fixed source-bound packets published after native empty-file readiness; shutdown was verified at the end of the recorded run. No current connection or continuous delivery is established.",
    *LIMITATIONS[1:],
]


def profile_limits(profile):
    require(profile in (PROFILE, PUBLICATION_PROFILE), "wazuh_review_profile")
    return LIMITATIONS if profile == PROFILE else PUBLICATION_LIMITATIONS


RESULT_FIELDS = {
    "schema_version",
    "evidence_kind",
    "profile",
    "app",
    "run_id",
    "source_run_id",
    "snapshot_run_id",
    "executed_at",
    "source_sha256",
    "collector_source_sha256",
    "host_receipt_sha256",
    "source_receipt_sha256",
    "image_reference",
    "observations",
    "signals",
    "records",
    "counts",
    "limitations",
}
RECORD_FIELDS = {
    "kind",
    "native_id",
    "channel",
    "target_id",
    "occurred_at",
    "rule_id",
    "rule_level",
    "record_sha256",
    "packet_sha256",
}


def _hash(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value), "wazuh_review_digest")


def _counts(observations, signals, records):
    archives = [r for r in records if r["kind"] == "archive"]
    alerts = [r for r in records if r["kind"] == "alert"]
    return {
        "source_observations": len(observations),
        "forwarded_signals": len(signals),
        "archived_logical_inputs": len({(r["channel"], r["target_id"]) for r in archives}),
        "alerted_logical_inputs": len({(r["channel"], r["target_id"]) for r in alerts}),
        "physical_archive_copies": len(archives),
        "physical_alert_copies": len(alerts),
        "distinct_archive_ids": len({r["native_id"] for r in archives}),
        "distinct_alert_ids": len({r["native_id"] for r in alerts}),
        "observation_alerts": sum(r["channel"] == "observation" for r in alerts),
        "forwarded_alerts": sum(r["channel"] == "detection" for r in alerts),
    }


def validate_result(result, app):
    """Closed display/import shape. This alone cannot establish execution."""
    require(type(result) is dict and set(result) == RESULT_FIELDS, "wazuh_review_fields")
    require(
        type(result["schema_version"]) is int
        and result["schema_version"] == 1
        and result["evidence_kind"] == KIND
        and result["profile"] in (PROFILE, PUBLICATION_PROFILE)
        and app in APPS
        and result["app"] == app
        and result["image_reference"] == IMAGE
        and result["limitations"] == profile_limits(result["profile"]),
        "wazuh_review_scope",
    )
    require(len(canonical(result)) <= 131072, "wazuh_review_size")
    for key in ("run_id", "source_run_id"):
        validate_identity(result[key])
    identifier(result["snapshot_run_id"])
    for key in (
        "source_sha256",
        "collector_source_sha256",
        "host_receipt_sha256",
        "source_receipt_sha256",
    ):
        _hash(result[key])
    finished = timestamp(result["executed_at"])
    require(finished <= timezone.now() + timedelta(seconds=5), "wazuh_review_time")
    packets, observation_ids = {}, set()
    observations, signals, records = (result[k] for k in ("observations", "signals", "records"))
    require(type(observations) is list and len(observations) == (13 if app == "documents" else 10))
    require(type(signals) is list and len(signals) == (1 if app == "documents" else 0))
    require(type(records) is list and 1 <= len(records) <= 96)
    for item in observations:
        require(type(item) is dict and set(item) == {"event_id", "event_sha256", "packet"})
        row = validate_observation(item["packet"])
        require(row["event_id"] == item["event_id"] and row["app"] == app)
        require(row["source"] == "instrumented_lab" and row["environment"] == "lab")
        require(
            timestamp(row["occurred_at"]) <= finished and item["event_id"] not in observation_ids
        )
        _hash(item["event_sha256"])
        observation_ids.add(item["event_id"])
        packets[("observation", item["event_id"])] = item["packet"]
    for packet in signals:
        row = validate_signal(packet)
        ids = row["included_event_ids"].split(",")
        require(
            row["app"] == app
            and row["rule_id"] == "R3"
            and row["source"] == "instrumented_lab"
            and row["environment"] == "lab"
            and row["evidence_complete"] == 1
            and row["evidence_count"] == 2
            and set(ids) <= observation_ids
            and timestamp(row["generated_at"]) <= finished,
            "wazuh_review_signal",
        )
        bindings = {item["event_id"]: item for item in observations}
        require(
            row["evidence_sha256"]
            == digest(
                sorted(
                    [
                        [event_id, bindings[event_id]["event_sha256"], "instrumented_lab"]
                        for event_id in ids
                    ]
                )
            ),
            "wazuh_review_signal_binding",
        )
        packets[("detection", row["signal_id"])] = packet
    seen, copies = {}, Counter()
    for row in records:
        require(type(row) is dict and set(row) == RECORD_FIELDS)
        require(
            row["kind"] in ("archive", "alert") and row["channel"] in ("observation", "detection")
        )
        require(
            isinstance(row["native_id"], str)
            and re.fullmatch(r"[0-9]{1,20}\.[0-9]{1,20}", row["native_id"])
        )
        key = row["channel"], identifier(row["target_id"])
        require(key in packets and row["packet_sha256"] == digest(packets[key]))
        _hash(row["record_sha256"])
        packet_row = next(iter(packets[key].values()))
        source_time = packet_row["occurred_at" if key[0] == "observation" else "generated_at"]
        require(timestamp(source_time) <= timestamp(row["occurred_at"]) <= finished)
        if row["kind"] == "alert":
            rule = expected_rule(packets[key])
            require(
                rule is not None
                and row["rule_id"] == rule[0]
                and type(row["rule_level"]) is int
                and row["rule_level"] == rule[1]
            )
        else:
            require(row["rule_id"] is None and row["rule_level"] is None)
        # Wazuh derives ids from the second plus the alerts-file offset, so
        # distinct same-second records can share one; identity includes target.
        native_key = row["kind"], row["native_id"], *key
        require(
            native_key not in seen or same(seen[native_key], row), "wazuh_review_native_conflict"
        )
        seen[native_key] = row
        copies[(row["kind"], *key)] += 1
        require(copies[(row["kind"], *key)] <= 3)
    require(
        {key[1:] for key in copies if key[0] == "archive"} == set(packets),
        "wazuh_review_missing_archive",
    )
    require(
        {key[1:] for key in copies if key[0] == "alert"}
        == {key for key, packet in packets.items() if expected_rule(packet) is not None},
        "wazuh_review_missing_alert",
    )
    require(same(result["counts"], _counts(observations, signals, records)), "wazuh_review_counts")
    return result


def load_native_review(workspace, run_id):
    """Revalidate a completed fixed run, including native bytes and original source."""
    from scripts.enterprise_wazuh_verify import validate_output

    validate_identity(run_id)
    directory = private_run_directory(workspace, run_id)
    raw = read_bytes(directory / "receipt.json", directory, 262144)
    receipt = parse_json(raw)
    require(type(receipt) is dict, "wazuh_review_host_receipt")
    profile = HOST_KINDS.get(receipt.get("kind"))
    required_flags = (
        ("bootstrap_acceptance_passed", "native_wazuh_executed", "source_unchanged")
        if profile == PROFILE
        else ("acceptance_passed", "native_runtime_execution_verified")
    )
    unavailable_claims = (
        ("continuous_collection_verified", "collector_rotation_recovery_verified")
        if profile == PROFILE
        else ("continuous_delivery_verified",)
    )
    require(
        type(receipt.get("schema_version")) is int
        and receipt["schema_version"] == 1
        and profile in (PROFILE, PUBLICATION_PROFILE)
        and receipt.get("run_id") == run_id
        and receipt.get("status") == "passed"
        and receipt.get("image_reference") == IMAGE
        and type(receipt.get("runner_exit_code")) is int
        and receipt["runner_exit_code"] == 0
        and all(
            receipt.get(key) is True
            for key in (
                *required_flags,
                "runtime_isolation_verified",
                "main_shutdown_verified",
                "independent_shutdown_verified",
            )
        )
        and all(receipt.get(key) is False for key in unavailable_claims),
        "wazuh_review_execution_incomplete",
    )
    started, finished = timestamp(receipt["started_at"]), timestamp(receipt["finished_at"])
    require(started < finished <= timezone.now() + timedelta(seconds=5))
    require(finished - started <= timedelta(seconds=960))
    image = parse_json(read_bytes(directory / "image.json", directory, 65536))
    require(image_identity(image) == receipt.get("image_id"), "wazuh_review_image")
    context = parse_json(read_bytes(directory / "evidence/run-context.json", directory, 4096))
    require(context["run_id"] == str(uuid.UUID(run_id)))
    require(started <= timestamp(context["prepared_at"]) < finished)
    if profile == PROFILE:
        require(same(context, receipt.get("context")))
        proof = validate_output(directory, context, now=finished)
        source_sha256 = receipt["source_sha256"]
    else:
        # Only the completed host execution path can reach this branch. A
        # publisher completion file is not a native receipt or an admission.
        plan = parse_json(read_bytes(directory / "publisher/plan.json", directory, 32768))
        require(
            plan.get("run_id") == run_id and digest(plan) == receipt.get("plan_sha256"),
            "wazuh_review_publication_plan_changed",
        )
        proof = validate_output(directory, context, now=finished, publication_plan=plan)
        completion = parse_json(
            read_bytes(directory / "publisher/publication-finished.json", directory, 32768)
        )
        if "recovery" in plan:
            # A recovery run records its rotation/backlog completion verbatim;
            # validate_output already rechecked the stop record and bytes.
            require(
                receipt.get("profile") == "recovery_rotation"
                and same(receipt.get("publication"), completion),
                "wazuh_review_publication_changed",
            )
        else:
            require(
                same(
                    receipt.get("publication"),
                    {
                        **completion,
                        "existing_prefix_bytes": 0,
                        "appended_bytes_this_call": completion["published_bytes"],
                    },
                ),
                "wazuh_review_publication_changed",
            )
        # This profile records the exact selected collector verification files,
        # including its frozen plan/config; it makes no checkout-wide hash claim.
        source_sha256 = context["source_sha256"]
    require(same(proof, receipt.get("native_proof")), "wazuh_review_native_proof_changed")
    source_binding = receipt.get("source_binding")
    require(type(source_binding) is dict)
    source_run, snapshot_run = (
        source_binding["native_source_run_id"],
        source_binding["snapshot_run_id"],
    )
    _, manifest, expected, binding = load_binding(workspace, snapshot_run, source_run, now=finished)
    require(same(binding, source_binding), "wazuh_review_source_binding_changed")
    require(hashlib.sha256(manifest).hexdigest() == context["manifest_sha256"])
    if profile == PUBLICATION_PROFILE:
        require(
            plan["expected_packets_sha256"] == binding["expected_packets_sha256"],
            "wazuh_review_publication_source_changed",
        )
    watchdog = parse_json(read_bytes(directory / "watchdog.json", directory, 4096))
    require(same(watchdog, receipt.get("independent_shutdown")))
    if profile == PUBLICATION_PROFILE:
        from integrations.wazuh_enterprise.execution_policy import (
            publication_shutdown,
            verify_recorded,
        )

        publication_shutdown(
            receipt.get("main_shutdown"),
            watchdog,
            run_id,
            started=started,
            finished=finished,
            shared=receipt.get("execution_policy", "exclusive") != "exclusive",
        )
        verify_recorded(directory, receipt, watchdog)
    else:
        validate_shutdown(
            receipt.get("main_shutdown"), watchdog, run_id, started=started, finished=finished
        )
    source_directory = private_run_directory(workspace, source_run)
    source_receipt_raw = read_bytes(source_directory / "receipt.json", source_directory, 262144)
    require(
        hashlib.sha256(source_receipt_raw).hexdigest() == binding["native_source_receipt_sha256"]
    )
    source_console_raw = read_bytes(
        source_directory / "evidence/console-events.json", source_directory, 262144
    )
    require(
        hashlib.sha256(source_console_raw).hexdigest()
        == parse_json(source_receipt_raw)["native_proof"]["raw_receipt_sha256"]["console-events"]
    )
    source_raw = parse_json(source_console_raw)
    event_hashes = {row["event_id"]: row["digest"] for row in source_raw["events"]}
    scopes = {}
    for app in APPS:
        scoped = {key: value for key, value in expected.items() if key[0] == app}
        observations = [
            {"event_id": key[2], "event_sha256": event_hashes[key[2]], "packet": packet}
            for key, (packet, _) in scoped.items()
            if key[1] == "observation"
        ]
        signals = [packet for key, (packet, _) in scoped.items() if key[1] == "detection"]
        records = []
        for kind in ("archive", "alert"):
            native_raw = read_bytes(
                directory / f"evidence/native-{kind}s.jsonl", directory, 4 * 1024**2
            )
            require(
                hashlib.sha256(native_raw).hexdigest()
                == proof["raw_receipt_sha256"][f"native-{kind}s.jsonl"]
            )
            for line in native_raw.splitlines():
                native = parse_json(line)
                decoded = next(iter(native["data"].values()))
                if decoded["app"] != app:
                    continue
                channel = (
                    "detection" if "signalbridge_detection" in native["data"] else "observation"
                )
                target = decoded["signal_id" if channel == "detection" else "event_id"]
                packet = scoped[(app, channel, target)][0]
                records.append(
                    {
                        "kind": kind,
                        "native_id": native["id"],
                        "channel": channel,
                        "target_id": target,
                        "occurred_at": native["timestamp"],
                        "rule_id": native["rule"]["id"] if kind == "alert" else None,
                        "rule_level": native["rule"]["level"] if kind == "alert" else None,
                        "record_sha256": digest(native),
                        "packet_sha256": digest(packet),
                    }
                )
        result = {
            "schema_version": 1,
            "evidence_kind": KIND,
            "profile": profile,
            "app": app,
            "run_id": run_id,
            "source_run_id": source_run,
            "snapshot_run_id": snapshot_run,
            "executed_at": finished.isoformat(),
            "source_sha256": source_sha256,
            "collector_source_sha256": context["source_sha256"],
            "host_receipt_sha256": hashlib.sha256(raw).hexdigest(),
            "source_receipt_sha256": binding["native_source_receipt_sha256"],
            "image_reference": IMAGE,
            "observations": observations,
            "signals": signals,
            "records": records,
            "counts": _counts(observations, signals, records),
            "limitations": profile_limits(profile),
        }
        scopes[app] = validate_result(result, app)
    return scopes


def local_links(app, result, *, locked=False):
    """Link exact local contents only; absence and conflicts remain visible."""
    bindings = {row["event_id"]: row for row in result["observations"]}
    query = Event.objects.filter(integration=app, event_id__in=bindings)
    if locked:
        query = query.select_for_update()
    matched, conflicts = {}, []
    scope = SimpleNamespace(integration=app, integration_id=app.pk)
    for event in query:
        binding = bindings[str(event.event_id)]
        row = binding["packet"]["signalbridge"]
        if (
            event.digest == binding["event_sha256"]
            and event.source == "instrumented_lab"
            and event.state == "processed"
            and _consistent(scope, event)
            and all(
                getattr(event, key) == row[key]
                for key in ("environment", "operation", "outcome", "reason")
            )
        ):
            matched[str(event.event_id)] = event
        else:
            conflicts.append(str(event.event_id))
    cases = []
    for packet in result["signals"]:
        signal = packet["signalbridge_detection"]
        query = Investigation.objects.filter(integration=app, pk=signal["case_id"])
        if locked:
            query = query.select_for_update()
        case = query.first()
        if case is None:
            continue
        evidence = list(case.events.select_related("integration").order_by("event_id")[:1001])
        ids = set(signal["included_event_ids"].split(","))
        generation = case_generation(
            case, evidence, signal["generation_source_sha256"], complete=len(evidence) <= 1000
        )
        if (
            case.rule == signal["rule_id"]
            and ids <= matched.keys()
            and {str(e.event_id) for e in evidence} == ids
            and generation["status"] == "recorded"
            and generation["same_current_engine"]
            and generation["record"]["evidence_sha256"] == signal["evidence_sha256"]
        ):
            cases.append({"id": str(case.pk), "rule": case.rule, "signal_id": signal["signal_id"]})
    return {
        "matched_events": len(matched),
        "unmatched_events": len(bindings) - len(matched),
        "conflicting_events": len(conflicts),
        "cases": cases,
    }


@transaction.atomic
def import_native_review(user, result, *, dry_run=False):
    """CLI-only admission; the command supplies results solely from the loader."""
    require(settings.LOCAL, "wazuh_review_local_only")
    app = Integration.objects.get(slug=result.get("app"), enabled=True)
    write_membership(user, app)
    # Serialize imports for this scope, including first import and role withdrawal.
    require(Integration.objects.filter(pk=app.pk, enabled=True).update(enabled=True) == 1)
    validate_result(result, app.slug)
    links = local_links(app, result, locked=True)
    require(not links["conflicting_events"], "wazuh_review_local_event_conflict")
    checksum = digest(result)
    prior = list(
        CheckRun.objects.filter(
            integration=app, result__evidence_kind=KIND, result__run_id=result["run_id"]
        )[:2]
    )
    require(
        len(prior) <= 1
        and (not prior or prior[0].digest == checksum and same(prior[0].result, result)),
        "wazuh_review_conflicting_import",
    )
    if dry_run:
        transaction.set_rollback(True)
        return None, False, links
    run, created = CheckRun.objects.get_or_create(
        digest=checksum,
        defaults={
            "integration": app,
            "suite": SUITE,
            "revision": result["source_sha256"],
            "result": result,
            "status": "passed",
        },
    )
    require(matches_result(run, app.pk, SUITE, result["source_sha256"], result, checksum=checksum))
    if created:
        Audit.objects.create(
            integration=app,
            actor=user,
            action="wazuh_native.imported",
            object_id=str(run.pk),
            detail={
                "digest": checksum,
                "run_id": result["run_id"],
                "profile": result["profile"],
                "matched_local_events": links["matched_events"],
                "unmatched_local_events": links["unmatched_events"],
                "matched_case_ids": [row["id"] for row in links["cases"]],
            },
        )
    else:
        require(
            admission_audits(run, "wazuh_native.imported", result["profile"]).exists(),
            "wazuh_review_missing_admission",
        )
    return run, created, links


def with_admission(query):
    """Fold the scoped admission audit into the existing receipt read.

    JSON keys compare as text: PostgreSQL has no jsonb = varchar operator, so a
    raw key-to-column comparison only ever worked on SQLite.
    """
    query = query.annotate(admission_profile_key=KT("result__profile"))
    audit = (
        Audit.objects.annotate(
            admitted_digest=KT("detail__digest"), admitted_profile=KT("detail__profile")
        )
        .filter(
            integration_id=OuterRef("integration_id"),
            action="wazuh_native.imported",
            admitted_digest=OuterRef("digest"),
            admitted_profile=OuterRef("admission_profile_key"),
        )
        .order_by("id")
    )
    return query.annotate(
        wazuh_admission=Subquery(audit.values("detail")[:1]),
        wazuh_admission_object_id=Subquery(audit.values("object_id")[:1]),
    )


def receipt_card(app, run=None, *, lookup=True, summary_only=False):
    if run is None and lookup:
        run = (
            with_admission(CheckRun.objects.filter(integration=app, result__evidence_kind=KIND))
            .order_by("-created_at", "-id")
            .first()
        )
    if run is None:
        return {"present": False, "verified": False}
    result = {"present": True, "verified": False, "run": run}
    try:
        require(run.integration_id == app.pk and run.status == "passed" and run.suite == SUITE)
        value = validate_result(run.result, app.slug)
        require(run.digest == digest(value) and run.revision == value["source_sha256"])
        # A saved report alone cannot elevate itself to execution proof.
        admission = getattr(run, "wazuh_admission", None)
        admission_object_id = getattr(run, "wazuh_admission_object_id", None)
        if not hasattr(run, "wazuh_admission"):
            audit = admission_audits(run, "wazuh_native.imported", value["profile"]).first()
            admission = audit.detail if audit else None
            admission_object_id = audit.object_id if audit else None
        require(
            type(admission) is dict
            and admission_object_id == str(run.pk)
            and admission.get("run_id") == value["run_id"]
            and admission.get("digest") == run.digest
            and admission.get("profile") == value["profile"]
        )
        if summary_only:
            matched, unmatched = (
                admission.get(key) for key in ("matched_local_events", "unmatched_local_events")
            )
            require(
                type(matched) is int
                and type(unmatched) is int
                and 0 <= matched <= len(value["observations"])
                and unmatched == len(value["observations"]) - matched
            )
            case_ids = admission.get("matched_case_ids")
            require(type(case_ids) is list and len(case_ids) <= 1)
            cases = [
                {
                    "id": row["signalbridge_detection"]["case_id"],
                    "rule": "R3",
                    "signal_id": row["signalbridge_detection"]["signal_id"],
                }
                for row in value["signals"]
                if row["signalbridge_detection"]["case_id"] in case_ids
            ]
            require(len(cases) == len(case_ids))
            links = {
                "matched_events": matched,
                "unmatched_events": unmatched,
                "conflicting_events": 0,
                "cases": cases,
                "at_import": True,
            }
        else:
            links = local_links(app, value)
        result.update(
            verified=True,
            executed_at=timestamp(value["executed_at"]),
            counts=value["counts"],
            records=value["records"],
            observations=value["observations"],
            signals=value["signals"],
            links=links,
            result=value,
            execution_description=(
                "Recorded replay: fixed source-bound packets published after native empty-file readiness; shutdown was verified at the end of the recorded run. This does not establish a current connection or continuous delivery."
                if value["profile"] == PUBLICATION_PROFILE
                else "This was a fixed snapshot collected for ten minutes. It does not establish a current connection."
            ),
            source_label=(
                "Collector verification source SHA-256"
                if value["profile"] == PUBLICATION_PROFILE
                else "Recorded checkout SHA-256"
            ),
        )
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        pass
    return result


def case_receipt_card(case):
    """The fixed bootstrap forwards one R3 case; no fuzzy ID/title matching."""
    if case.integration.slug != "documents" or case.rule != "R3":
        return None
    run = (
        with_admission(
            CheckRun.objects.filter(
                integration=case.integration,
                result__evidence_kind=KIND,
                result__signals__0__signalbridge_detection__case_id=str(case.pk),
            )
        )
        .order_by("-created_at", "-id")
        .first()
    )
    if run is None:
        return None
    card = receipt_card(case.integration, run)
    if card["verified"] and any(row["id"] == str(case.pk) for row in card["links"]["cases"]):
        return card
    return None
