"""Fixed native header review import; no scanner launch or event fabrication.

The local archive/database operator remains trusted. Recomputed files and host
receipts describe a historical lab execution, not independent attestation or
current connectivity. The import cannot close cases or verify authorization fixes.
"""

from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from integrations.enterprise.reference_host_controls import same
from integrations.enterprise.reference_reconciliation import WORKER, _events
from integrations.enterprise.verification import private_run_directory, validate_identity
from integrations.zap_enterprise.capture import PROFILE, require
from integrations.zap_enterprise.scanner_contract import IMAGE, digest, hex_value
from integrations.zap_enterprise.scanner_host_controls import MAX_GUARD_SECONDS, validate_shutdown
from integrations.zap_enterprise.scanner_host_evidence import read_receipt, validate_receipts
from integrations.zap_enterprise.source_transfer import load_completed_source

from .contract import digest as event_digest
from .contract import timestamp, validate_event
from .models import Audit, CheckRun, Event, Integration
from .native_receipts import admission_audits, matches_result
from .reference_retest import _manifest
from .services import write_membership

KIND = "native_authenticated_header_review"
SUITE = "Native authenticated header review"
APPS = ("documents", "expenses")


def load_native_review(workspace, run_id):
    """Read only the fixed retained runs; never accept report-supplied provenance."""
    validate_identity(run_id)
    directory = private_run_directory(workspace, run_id)
    receipt, receipt_hash, _ = read_receipt(directory / "receipt.json", directory, 262144)
    require(isinstance(receipt, dict))
    require(
        type(receipt.get("schema_version")) is int
        and receipt["schema_version"] == 1
        and receipt.get("kind") == "signalbridge-native-authenticated-zap-offline"
        and receipt.get("run_id") == run_id
        and receipt.get("status") == "passed"
        and all(
            receipt.get(key) is True
            for key in (
                "acceptance_passed",
                "native_zap_executed",
                "source_unchanged",
                "source_archive_unchanged",
                "runtime_isolation_verified",
                "parsed_configuration_verified",
                "main_shutdown_verified",
                "independent_shutdown_verified",
            )
        )
        and type(receipt.get("runner_exit_code")) is int
        and receipt["runner_exit_code"] == 0
        and receipt.get("image_reference") == IMAGE
    )
    require(isinstance(receipt.get("image_id"), str))
    hex_value(receipt["image_id"].removeprefix("sha256:"))
    require(receipt["image_id"].startswith("sha256:"))
    started, finished = timestamp(receipt.get("started_at")), timestamp(receipt.get("finished_at"))
    require(started < finished <= timezone.now())
    require(finished - started <= timedelta(seconds=MAX_GUARD_SECONDS + 60))
    manifest = _manifest(directory / "source")
    require(receipt.get("source_sha256") == manifest["sha256"])
    proof = validate_receipts(workspace, run_id, manifest, now=finished)
    require(same(proof, receipt.get("scanner_proof")))
    require(same(proof["source_snapshot"], receipt.get("source_snapshot")))
    require(receipt.get("input_sha256") == proof["input_sha256"])
    source_run = receipt.get("source_run_id")
    value, binding = load_completed_source(workspace, source_run, manifest, now=finished)
    require(same(binding, receipt.get("source_binding")))
    require(digest(value) == proof["input_sha256"])
    require(proof["source_run_id"] == source_run)
    require(proof["source_receipt_sha256"] == binding["source_receipt_sha256"])
    require(timestamp(binding["source_finished_at"]) <= started)
    watchdog, _, _ = read_receipt(directory / "watchdog.json", directory, 4096)
    require(same(watchdog, receipt.get("independent_shutdown")))
    validate_shutdown(
        receipt.get("main_shutdown"), watchdog, run_id, started=started, finished=finished
    )
    source_directory = private_run_directory(workspace, source_run)
    raw_events, _, _ = read_receipt(
        source_directory / "evidence/console-events.json", source_directory, 262144
    )
    require(isinstance(raw_events, dict) and set(raw_events) == {"events", "cases"})
    require(raw_events["cases"] == [])
    events = _events(raw_events["events"], source=False, now=finished)
    require(len(events) == 8)
    scopes = {app: [] for app in APPS}
    for phase in ("fault", "corrected"):
        for row in value["phases"][phase]:
            if row["event_id"] is not None:
                app = "expenses" if row["http_status"] == 403 else "documents"
                event = events[row["event_id"]]
                require(event["app"] == app)
                scopes[app].append(
                    {
                        "phase": phase,
                        "ordinal": row["ordinal"],
                        "native_message_id": proof["phases"][phase]["history"]["message_ids"][
                            row["ordinal"]
                        ],
                        "event": event,
                    }
                )
    for name, identifier in value["execution"]["restoration_event_ids"].items():
        event = events[identifier]
        require(event["app"] == "documents")
        scopes["documents"].append(
            {"phase": "restoration", "ordinal": name, "native_message_id": None, "event": event}
        )
    require(len(scopes["documents"]) == 6 and len(scopes["expenses"]) == 2)
    require(len({row["event"]["event_id"] for rows in scopes.values() for row in rows}) == 8)
    return {
        "schema_version": 1,
        "evidence_kind": KIND,
        "profile": PROFILE,
        "run_id": run_id,
        "source_run_id": source_run,
        "source_sha256": manifest["sha256"],
        "scanner_host_receipt_sha256": receipt_hash,
        "source_host_receipt_sha256": binding["source_receipt_sha256"],
        "executed_at": finished.isoformat(),
        "scopes": scopes,
        "finding": proof["phases"]["fault"]["findings"][0],
        "corrected_findings": proof["phases"]["corrected"]["findings"],
    }


def _matching_events(app, bindings, finished):
    require(isinstance(bindings, list) and len(bindings) == (6 if app.slug == "documents" else 2))
    ids = [row["event"]["event_id"] for row in bindings]
    require(len(ids) == len(set(ids)))
    events = {
        str(e.event_id): e
        for e in Event.objects.select_for_update()
        .filter(integration=app, event_id__in=ids)
        .order_by("event_id")
    }
    require(set(events) == set(ids), "Import requires the existing matching native events.")
    rows = []
    for binding in bindings:
        expected = binding["event"]
        event = events[expected["event_id"]]
        validate_event(event.payload, app.slug, now=finished)
        require(
            expected["app"] == app.slug
            and same(event.payload, expected["payload"])
            and event.digest == expected["digest"] == event_digest(event.payload)
            and event.source == "instrumented_lab"
            and event.environment == "lab"
            and event.state == "processed"
            and event.processed_by == WORKER
            and event.processed_at == timestamp(expected["processed_at"])
            and event.processed_at <= finished
            and event.processing_attempts == expected["processing_attempts"]
        )
        for field in ("actor", "resource", "operation", "outcome", "reason", "environment"):
            require(getattr(event, field) == event.payload[field])
        require(str(event.episode) == event.payload["episode"])
        require(event.occurred_at == timestamp(event.payload["occurred_at"]))
        rows.append(
            {
                "phase": binding["phase"],
                "ordinal": binding["ordinal"],
                "native_message_id": binding["native_message_id"],
                "event_id": str(event.event_id),
                "digest": event.digest,
                "outcome": event.outcome,
                "reason": event.reason,
            }
        )
    return rows


@transaction.atomic
def import_native_review(user, evidence, *, dry_run=False):
    """Import only after trusted loader verification; current roles and rows must match.

    The CLI supplies evidence exclusively from load_native_review. No browser or
    machine endpoint accepts this internal dictionary or native provenance claims.
    Both scope permissions are required, but each saved result contains only that
    scope's event identifiers. No events/findings/cases/tasks are manufactured.
    """
    require(isinstance(evidence, dict) and evidence.get("evidence_kind") == KIND)
    require(evidence.get("profile") == PROFILE and set(evidence["scopes"]) == set(APPS))
    finished = timestamp(evidence["executed_at"])
    require(finished <= timezone.now())
    validate_identity(evidence["run_id"])
    validate_identity(evidence["source_run_id"])
    for key in ("source_sha256", "scanner_host_receipt_sha256", "source_host_receipt_sha256"):
        hex_value(evidence[key])
    require(evidence["corrected_findings"] == [])
    finding = evidence["finding"]
    require(isinstance(finding, dict) and finding.get("plugin_id") == "10021")
    apps = list(Integration.objects.select_for_update().filter(slug__in=APPS).order_by("slug"))
    require(tuple(a.slug for a in apps) == APPS)
    for app in apps:
        write_membership(user, app)
    results = []
    for app in apps:
        rows = _matching_events(app, evidence["scopes"][app.slug], finished)
        if app.slug == "documents":
            observed = [r for r in rows if r["phase"] == "fault" and r["ordinal"] == 1]
            require(
                len(observed) == 1
                and observed[0]["event_id"] == finding["source_event_id"]
                and observed[0]["native_message_id"] == finding["native_message_id"]
            )
        result = {
            "schema_version": 1,
            "evidence_kind": KIND,
            "profile": PROFILE,
            "app": app.slug,
            "run_id": evidence["run_id"],
            "source_run_id": evidence["source_run_id"],
            "source_sha256": evidence["source_sha256"],
            "scanner_host_receipt_sha256": evidence["scanner_host_receipt_sha256"],
            "source_host_receipt_sha256": evidence["source_host_receipt_sha256"],
            "executed_at": finished.isoformat(),
            "event_bindings": rows,
            "finding": finding if app.slug == "documents" else None,
            "correction_in_recorded_lab": app.slug == "documents",
            "limitations": [
                "Historical fixed trusted-operator lab proof; not current connectivity or independent attestation.",
                "Only passive header rule 10021 was tested; source login was separate from offline ZAP capture analysis.",
                "A corrected header does not verify authorization remediation, close a case or establish complete application security.",
                "No missing event is created by this import. Other application event details are excluded from this scoped record.",
            ],
        }
        identity = digest(result)
        existing = list(
            CheckRun.objects.filter(
                integration=app, result__evidence_kind=KIND, result__run_id=evidence["run_id"]
            )[:2]
        )
        require(
            len(existing) <= 1
            and (
                not existing
                or (existing[0].digest == identity and same(existing[0].result, result))
            )
        )
        results.append((app, result, identity))
    if dry_run:
        return [], False
    imported, created_any = [], False
    for app, result, identity in results:
        run, created = CheckRun.objects.get_or_create(
            digest=identity,
            defaults={
                "integration": app,
                "suite": SUITE,
                "revision": evidence["source_sha256"],
                "result": result,
                "status": "passed",
            },
        )
        require(
            matches_result(run, app.pk, SUITE, evidence["source_sha256"], result, checksum=identity)
        )
        if created:
            Audit.objects.create(
                integration=app,
                actor=user,
                action="zap_native.imported",
                object_id=str(run.pk),
                detail={"digest": identity, "run_id": evidence["run_id"], "profile": PROFILE},
            )
        else:
            require(admission_audits(run, "zap_native.imported", PROFILE).exists())
        imported.append(run)
        created_any |= created
    return imported, created_any
