"""Run a fixed, read-only Ruff security scan of this repository's own Python sources."""

import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from bridge.findings import MAX_REPORT_BYTES, import_scan
from bridge.models import Integration
from bridge.scanner_reports import MAX_FINDINGS, ReportError, _load, parse_report
from bridge.services import WorkflowError, allowed


def source_manifest(root):
    paths = sorted(
        {
            *(root / "bridge").rglob("*.py"),
            *(root / "config").rglob("*.py"),
            *(root / "scripts").rglob("*.py"),
            root / "manage.py",
        }
    )
    manifest = {}
    for path in paths:
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise CommandError("Source allowlist contains an external link.")
        manifest[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return manifest


def normalize_locations(report, root, manifest):
    """Only the fixed runner may relativize file URIs, after exact allowlist checks."""
    try:
        runs = report["runs"]
        if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
            raise ValueError()
        run = runs[0]
        results = run["results"]
        if not isinstance(results, list) or len(results) > MAX_FINDINGS:
            raise ValueError()
        for result in results:
            if not isinstance(result, dict):
                raise ValueError()
            locations = result.get("locations", [])
            if not isinstance(locations, list) or len(locations) > 1:
                raise ValueError()
            for location in locations:
                artifact = location["physicalLocation"]["artifactLocation"]
                if not isinstance(artifact, dict) or not isinstance(artifact.get("uri"), str):
                    raise ValueError()
                if "uriBaseId" in artifact or "index" in artifact:
                    raise CommandError("Ruff returned an unsupported artifact reference.")
                uri = urlsplit(artifact["uri"])
                if uri.scheme != "file" or uri.netloc or uri.query or uri.fragment:
                    raise CommandError("Ruff returned an unexpected source location.")
                value = unquote(uri.path, errors="strict")
                if sys.platform == "win32" and value.startswith("/"):
                    value = value[1:]
                path = Path(value).resolve()
                if not path.is_relative_to(root):
                    raise CommandError("Ruff returned a location outside this repository.")
                relative = path.relative_to(root).as_posix()
                if relative not in manifest:
                    raise CommandError("Ruff returned an unscanned source location.")
                artifact.clear()
                artifact["uri"] = relative
    except (KeyError, TypeError, ValueError, OSError):
        raise CommandError(
            "Ruff returned an invalid report structure; nothing was imported."
        ) from None
    # These optional fields can embed the user's absolute checkout location.
    run.pop("originalUriBaseIds", None)
    run.pop("artifacts", None)
    return json.dumps(report, separators=(",", ":")).encode("utf-8")


def source_revision(git, root):
    try:
        revision = subprocess.check_output(
            [git, "rev-parse", "HEAD"], cwd=root, text=True, timeout=10, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.SubprocessError):
        raise CommandError("The source revision could not be recorded.") from None
    if not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", revision):
        raise CommandError("A complete source commit hash is required.")
    return revision


class Command(BaseCommand):
    help = "Scan SignalBridge's Python allowlist with local Ruff S rules; never scan sibling apps or fix files."

    def add_arguments(self, parser):
        parser.add_argument("--user", required=True)

    def handle(self, *args, **options):
        if not settings.LOCAL:
            raise CommandError("The fixed source runner is local-only.")
        root = Path(settings.BASE_DIR).resolve()
        try:
            user = get_user_model().objects.get(username=options["user"], is_active=True)
            app = Integration.objects.get(slug="signalbridge", enabled=False)
        except (get_user_model().DoesNotExist, Integration.DoesNotExist) as error:
            raise CommandError("Provision the scanner workspace and an operator first.") from error
        if not allowed(user, app, ("analyst", "reviewer")):
            raise CommandError("Analyst or reviewer access is required.")
        scanner = Path(sys.executable).parent / ("ruff.exe" if sys.platform == "win32" else "ruff")
        if not scanner.is_file():
            raise CommandError(
                "Install the pinned development requirements in this environment first."
            )
        git = shutil.which("git")
        if not git:
            raise CommandError("Git is required to record source revision.")
        revision = source_revision(git, root)
        manifest = source_manifest(root)
        started = timezone.now()
        clock = time.monotonic()
        try:
            result = subprocess.run(
                [
                    str(scanner),
                    "check",
                    "--isolated",
                    "--select",
                    "S",
                    "--no-cache",
                    "--output-format",
                    "sarif",
                    *manifest,
                ],
                cwd=root,
                capture_output=True,
                timeout=60,
                stdin=subprocess.DEVNULL,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise CommandError("Scanner timed out; no successful run was recorded.") from None
        except OSError:
            raise CommandError("Scanner could not start; no successful run was recorded.") from None
        if result.returncode not in (0, 1):
            raise CommandError("Scanner failed; no successful run was recorded.")
        if not isinstance(result.stdout, bytes) or len(result.stdout) > MAX_REPORT_BYTES:
            raise CommandError(
                "Scanner output was invalid or exceeded 2 MiB; nothing was imported."
            )
        if manifest != source_manifest(root) or revision != source_revision(git, root):
            raise CommandError("The source changed during the scan; retry after edits finish.")
        try:
            # Reuse the importer's bounded, duplicate-rejecting JSON decoder before
            # normalization; plain json.loads would erase ambiguous duplicate keys.
            normalized = normalize_locations(_load(result.stdout), root, manifest)
            report = parse_report(normalized, "sarif")
        except ReportError:
            raise CommandError("Ruff returned an invalid report; nothing was imported.") from None
        if report.tool.casefold() != "ruff":
            raise CommandError("The scanner identity did not match Ruff; nothing was imported.")
        if any(finding.path not in manifest for finding in report.findings):
            raise CommandError(
                "Ruff findings must name a scanned source file; nothing was imported."
            )
        if report.coverage_status not in ("complete", "unknown"):
            raise CommandError(
                "Ruff reported failed or incomplete execution; nothing was imported."
            )
        if (result.returncode == 0) != (not report.findings):
            raise CommandError("Scanner exit status and findings disagree; nothing was imported.")
        try:
            run, _created = import_scan(
                user,
                app,
                normalized,
                "sarif",
                source_revision=revision,
                manifest=manifest,
                execution={
                    "runner": "signalbridge-ruff",
                    "returncode": result.returncode,
                    "duration_ms": round((time.monotonic() - clock) * 1000),
                    "started_at": started.isoformat(),
                    "finished_at": timezone.now().isoformat(),
                    "original_digest": hashlib.sha256(result.stdout).hexdigest(),
                },
            )
        except (PermissionError, ReportError, WorkflowError):
            raise CommandError(
                "Scan import validation failed; no successful run was recorded."
            ) from None
        self.stdout.write(
            f"Recorded Ruff security scan: {len(manifest)} source files; {run.finding_count} findings for review. Run {run.pk}."
        )
