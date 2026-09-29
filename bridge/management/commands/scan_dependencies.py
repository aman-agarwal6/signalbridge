"""Audit only SignalBridge's pinned public dependencies, with an explicit network opt-in."""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from bridge.findings import MAX_REPORT_BYTES, import_scan
from bridge.models import Integration
from bridge.scanner_reports import ReportError, parse_report
from bridge.services import allowed

PUBLIC_PACKAGES = frozenset(
    {"django", "psycopg", "psycopg-binary", "waitress", "asgiref", "sqlparse", "tzdata"}
)
PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)(\[binary\])?==([0-9][A-Za-z0-9.!+_-]{0,99})\Z")


def _canonical(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def dependency_source(root):
    """Return the exact content hash and inventory; never resolve/install dependencies."""
    path = root / "requirements.txt"
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise CommandError("The dependency manifest must be a regular file in this repository.")
    try:
        with path.open("rb") as handle:
            raw = handle.read(65537)
        if len(raw) > 65536:
            raise ValueError()
        text = raw.decode("utf-8")
    except (OSError, ValueError):
        raise CommandError("The fixed dependency manifest is missing or invalid.") from None
    pins = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = PIN.fullmatch(line)
        if not match:
            raise CommandError("The manifest must contain only explicit exact public-package pins.")
        name, extra, version = match.groups()
        name = _canonical(name)
        if name not in PUBLIC_PACKAGES or name in pins or (extra and name != "psycopg"):
            raise CommandError(
                "The dependency manifest differs from the fixed public-package scope."
            )
        pins[name] = version
    if set(pins) != PUBLIC_PACKAGES:
        raise CommandError("The manifest must explicitly pin every allowed runtime dependency.")
    return {"requirements.txt": hashlib.sha256(raw).hexdigest()}, pins


def _revision(git, root):
    try:
        value = subprocess.check_output(
            [git, "rev-parse", "HEAD"], cwd=root, text=True, timeout=10, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.SubprocessError):
        raise CommandError("The source revision could not be recorded.") from None
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
        raise CommandError("A complete source commit hash is required.")
    return value


def _environment():
    """Ignore alternate package services, Python injection and credential-bearing proxies."""
    excluded = {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    }
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(("PIP", "PYTHON")) and key.upper() not in excluded
    }
    environment["PIP_CONFIG_FILE"] = os.devnull
    return environment


class Command(BaseCommand):
    help = (
        "Audit SignalBridge's exact public dependency pins with pip-audit; "
        "requires explicit permission to fetch public advisories, never installs or fixes packages."
    )

    def add_arguments(self, parser):
        parser.add_argument("--user", required=True)
        parser.add_argument(
            "--fetch-advisories",
            action="store_true",
            help="Allow requests to PyPI for the fixed public package names and versions.",
        )

    def handle(self, *args, **options):
        if not settings.LOCAL:
            raise CommandError("The fixed dependency runner is local-only.")
        if not options["fetch_advisories"]:
            raise CommandError(
                "Add --fetch-advisories to explicitly allow public advisory queries."
            )
        try:
            user = get_user_model().objects.get(username=options["user"], is_active=True)
            app = Integration.objects.get(slug="signalbridge", enabled=False)
        except (get_user_model().DoesNotExist, Integration.DoesNotExist):
            raise CommandError("Provision the scanner workspace and an operator first.") from None
        if not allowed(user, app, ("analyst", "reviewer")):
            raise CommandError("Analyst or reviewer access is required.")
        root = Path(settings.BASE_DIR).resolve()
        interpreter = (
            root / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        )
        if not interpreter.is_file():
            raise CommandError("Install pinned development requirements in the project venv first.")
        git = shutil.which("git")
        if not git:
            raise CommandError("Git is required to record source revision.")
        revision = _revision(git, root)
        manifest, expected_pins = dependency_source(root)
        cache = root / "var" / "advisory-cache"
        if not cache.resolve().is_relative_to(root / "var"):
            raise CommandError("The advisory cache must stay inside this workspace.")
        try:
            cache.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise CommandError("The local advisory cache could not be prepared.") from None
        started = timezone.now()
        clock = time.monotonic()
        try:
            result = subprocess.run(
                [
                    str(interpreter),
                    "-I",
                    "-m",
                    "pip_audit",
                    "--no-deps",
                    "--disable-pip",
                    "--strict",
                    "-r",
                    "requirements.txt",
                    "--format",
                    "json",
                    "--progress-spinner",
                    "off",
                    "--vulnerability-service",
                    "pypi",
                    "--desc",
                    "off",
                    "--aliases",
                    "off",
                    "--timeout",
                    "15",
                    "--cache-dir",
                    str(cache),
                ],
                cwd=root,
                env=_environment(),
                capture_output=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise CommandError(
                "Advisory lookup timed out; no successful scan was recorded."
            ) from None
        except OSError:
            raise CommandError(
                "pip-audit could not run; no successful scan was recorded."
            ) from None
        finished = timezone.now()
        duration_ms = round((time.monotonic() - clock) * 1000)
        if result.returncode not in (0, 1):
            raise CommandError("Dependency audit failed; no successful scan was recorded.")
        if not isinstance(result.stdout, bytes) or len(result.stdout) > MAX_REPORT_BYTES:
            raise CommandError("Dependency audit output was invalid or exceeded 2 MiB.")
        if dependency_source(root) != (manifest, expected_pins) or _revision(git, root) != revision:
            raise CommandError("Source changed during the audit; no scan was imported.")
        try:
            report = parse_report(result.stdout, "pip-audit")
        except ReportError:
            raise CommandError(
                "Dependency audit returned an invalid report; nothing was imported."
            ) from None
        if report.coverage_status != "complete":
            raise CommandError("The audit skipped dependencies; no complete scan was imported.")
        # The generic adapter cannot know which inputs were intended; this fixed runner can.
        reported_pins = {
            _canonical(item["name"]): item["version"]
            for item in json.loads(result.stdout)["dependencies"]
        }
        if reported_pins != expected_pins:
            raise CommandError("The report does not cover the exact requested dependency pins.")
        if (result.returncode == 0) != (not report.findings):
            raise CommandError("Audit exit status and findings disagree; nothing was imported.")
        run, _created = import_scan(
            user,
            app,
            result.stdout,
            "pip-audit",
            source_revision=revision,
            manifest=manifest,
            execution={
                "runner": "signalbridge-pip-audit",
                "returncode": result.returncode,
                "duration_ms": duration_ms,
                "started_at": started.isoformat(),
                "finished_at": finished.isoformat(),
                "original_digest": hashlib.sha256(result.stdout).hexdigest(),
            },
        )
        self.stdout.write(
            f"Recorded dependency audit: {len(expected_pins)} explicit public package pins; "
            f"{run.finding_count} advisory findings. Run {run.pk}. "
            "Only the listed pins were audited; runtime exploitability was not tested."
        )
