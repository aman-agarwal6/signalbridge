"""Permission-checked scanner imports and optimistic, audited triage."""

import hashlib
import json
import re
from datetime import datetime
from pathlib import PurePosixPath

from django.db import transaction
from django.db.models import F
from django.utils import timezone

from .models import Audit, Finding, FindingObservation, ScanRun
from .scanner_reports import ReportError, parse_report
from .services import WorkflowError, allowed, write_membership

MAX_REPORT_BYTES = 2 * 1024 * 1024
DETAIL_FIELDS = (
    "severity",
    "rule_id",
    "title",
    "path",
    "line",
    "package",
    "package_version",
    "fix_versions",
)


def _hash(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _provenance(source_revision, manifest, execution):
    if not isinstance(source_revision, str) or (
        source_revision
        and not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", source_revision)
    ):
        raise WorkflowError("Source revision must be a complete commit hash.")
    manifest = {} if manifest is None else manifest
    if not isinstance(manifest, dict) or len(manifest) > 5000:
        raise WorkflowError("Invalid source manifest.")
    for path, digest in manifest.items():
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 500
            or "\\" in path
            or ":" in path
            or any(char in path for char in "?#%")
            or PurePosixPath(path).is_absolute()
            or any(part in ("", ".", "..") for part in path.split("/"))
            or any(not char.isprintable() for char in path)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise WorkflowError("Manifest entries require relative paths and SHA-256 hashes.")
    if execution is None:
        if source_revision or manifest:
            raise WorkflowError("Source provenance is recorded only by the local runner.")
        return "claimed_report", {}, {}
    fields = {"runner", "returncode", "duration_ms", "started_at", "finished_at", "original_digest"}
    if not isinstance(execution, dict) or set(execution) != fields:
        raise WorkflowError("Invalid local execution record.")
    if (
        execution["runner"] not in ("signalbridge-ruff", "signalbridge-pip-audit")
        or type(execution["returncode"]) is not int
        or execution["returncode"] not in (0, 1)
        or type(execution["duration_ms"]) is not int
        or not 0 <= execution["duration_ms"] <= 3600000
        or not isinstance(execution["original_digest"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", execution["original_digest"])
        or not source_revision
        or not manifest
    ):
        raise WorkflowError("Incomplete local execution evidence.")
    try:
        started = datetime.fromisoformat(execution["started_at"])
        finished = datetime.fromisoformat(execution["finished_at"])
        if started.tzinfo is None or finished.tzinfo is None or finished < started:
            raise ValueError()
    except (TypeError, ValueError):
        raise WorkflowError("Invalid execution timestamps.") from None
    return "local_execution", dict(manifest), dict(execution)


def import_scan(user, integration, raw, format, source_revision="", manifest=None, execution=None):
    """Import metadata only. Execution evidence is supplied only by trusted local code.

    The CLI intentionally has no provenance override. A JSON report's own execution
    fields never establish local execution or a binding to the source manifest.
    """
    if not user.is_active or not allowed(user, integration, ("analyst", "reviewer")):
        raise PermissionError()
    if format == "zap" and integration.slug != "signalbridge":
        raise ReportError("The fixed ZAP lab profile belongs only to the SignalBridge workspace.")
    if not isinstance(raw, bytes) or len(raw) > MAX_REPORT_BYTES:
        raise ReportError("Report must be at most 2 MiB.")
    provenance, manifest, execution = _provenance(source_revision, manifest, execution)
    report = parse_report(raw, format)
    if provenance == "local_execution":
        expected = {
            "signalbridge-ruff": ("sarif", "ruff"),
            "signalbridge-pip-audit": ("pip-audit", "pip-audit"),
        }[execution["runner"]]
        if (report.format, report.tool.casefold()) != expected:
            raise WorkflowError("Local runner identity does not match the report format and tool.")
        if report.format == "sarif" and any(
            not item.path or item.path not in manifest for item in report.findings
        ):
            raise WorkflowError("Local source findings must name a file in the recorded manifest.")
        if report.format == "pip-audit" and set(manifest) != {"requirements.txt"}:
            raise WorkflowError(
                "The dependency runner records only the fixed requirements manifest."
            )
    digest = hashlib.sha256(raw).hexdigest()
    identity = _hash(
        {
            "integration": integration.pk,
            "format": report.format,
            "digest": digest,
            "provenance": provenance,
            "source_revision": source_revision,
            "manifest": manifest,
            "execution": execution,
        }
    )
    with transaction.atomic():
        # Parsing can be expensive. Do not rely on membership or account state
        # observed before it when starting the import's write transaction.
        write_membership(user, integration)
        run, created = ScanRun.objects.get_or_create(
            identity_digest=identity,
            defaults=dict(
                integration=integration,
                format=report.format,
                tool=report.tool,
                tool_version=report.version,
                digest=digest,
                provenance=provenance,
                source_revision=source_revision,
                manifest=manifest,
                execution=execution,
                coverage_status=report.coverage_status,
                input_count=report.input_count,
                skipped_count=report.skipped_count,
                suppressed_count=report.suppressed_count,
                finding_count=len({item.fingerprint for item in report.findings}),
                imported_by=user,
            ),
        )
        if not created:
            return run, False
        seen = set()
        observations = []
        for item in report.findings:
            # A repeated result is one observation, not a second review item.
            if item.fingerprint in seen:
                continue
            seen.add(item.fingerprint)
            details = {field: getattr(item, field) for field in DETAIL_FIELDS}
            details["fix_versions"] = list(details["fix_versions"])
            finding, new = Finding.objects.get_or_create(
                integration=integration,
                tool=report.tool,
                fingerprint=item.fingerprint,
                defaults=details,
            )
            if not new:
                Finding.objects.filter(pk=finding.pk).update(
                    **details, last_seen=timezone.now(), version=F("version") + 1
                )
            observations.append(
                FindingObservation(
                    scan_run=run,
                    finding=finding,
                    suppressed=item.suppressed,
                    suppression_statuses=list(getattr(item, "suppression_statuses", ())),
                    **details,
                )
            )
        # Only new immutable observations are batched. Finding updates retain
        # their atomic version increments and review state; conflicts roll the
        # entire import back instead of silently omitting evidence.
        FindingObservation.objects.bulk_create(observations, batch_size=100)
        Audit.objects.create(
            integration=integration,
            actor=user,
            action="scan.imported",
            object_id=str(run.pk),
            detail={
                "digest": digest,
                "tool": report.tool,
                "provenance": provenance,
                "coverage_status": report.coverage_status,
                "finding_count": run.finding_count,
            },
        )
    return run, True


def evidence_binding(observation):
    """Bind a decision to immutable normalized evidence, without reading live source files."""
    run = observation.scan_run
    return {
        "observation_id": observation.pk,
        "observation_digest": _hash(observation.snapshot),
        "scan_run": str(run.pk),
        "report_digest": run.digest,
        "provenance": run.provenance,
        "source_revision": run.source_revision,
        "manifest_digest": _hash(run.manifest) if run.manifest else "",
        "source_path": observation.path,
        "source_file_digest": run.manifest.get(observation.path, ""),
        "current_source_checked": False,
    }


def triage(user, finding_id, status, version, rationale):
    with transaction.atomic():
        finding = Finding.objects.select_related("integration").get(pk=finding_id)
        # Match import's lock order: membership/account, then finding. Holding
        # a finding while waiting on its importer's membership would invert it.
        write_membership(user, finding.integration)
        finding = (
            Finding.objects.select_for_update()
            .filter(pk=finding_id, integration_id=finding.integration_id)
            .first()
        )
        if finding is None:
            raise PermissionError()
        if status not in dict(Finding.STATUS_CHOICES):
            raise WorkflowError("Choose a supported review status.")
        if not isinstance(rationale, str) or not 1 <= len(rationale.strip()) <= 2000:
            raise WorkflowError("A review rationale of 1–2000 characters is required.")
        if type(version) is not int or finding.version != version:
            raise WorkflowError("This finding changed. Reload before reviewing.")
        observation = (
            FindingObservation.objects.filter(
                finding=finding, scan_run__integration=finding.integration
            )
            .select_related("scan_run")
            .order_by("-pk")
            .first()
        )
        if observation is None:
            raise WorkflowError("A review requires a recorded observation.")
        previous = finding.status
        updated = Finding.objects.filter(pk=finding.pk, version=version).update(
            status=status, version=version + 1
        )
        if updated != 1:
            raise WorkflowError("Another analyst already changed this finding.")
        Audit.objects.create(
            integration=finding.integration,
            actor=user,
            action="finding.triaged",
            object_id=str(finding.pk),
            detail={
                "previous_status": previous,
                "status": status,
                "version": version + 1,
                "rationale": rationale.strip(),
                "finding_version_reviewed": version,
                "evidence": evidence_binding(observation),
            },
        )
        finding.refresh_from_db()
    return finding
