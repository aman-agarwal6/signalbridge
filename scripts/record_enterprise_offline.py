"""Retain revision-bound offline checks; never launch a lab or install dependencies."""

import argparse
import json
import secrets
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from integrations.enterprise.verification import private_run_directory
from scripts.record_verification import (
    capture_small,
    child_environment,
    git_state,
    parse_django_summary,
    parse_node_tap_summary,
    receipt_path,
    run_check,
    source_manifest,
)


def checks(python):
    targets = [
        "bridge",
        "reference_lab",
        "config",
        "tests",
        "scripts",
        "simulations",
        "integrations",
        "manage.py",
    ]
    manage = [str(python), "-B", "manage.py"]
    return [
        (
            "django-tests",
            "django",
            [
                *manage,
                "test",
                "tests",
                "--exclude-tag",
                "offline_simulation",
                "--exclude-tag",
                "native_postgres",
                "--verbosity",
                "1",
                "--noinput",
            ],
            300,
        ),
        (
            "offline-fault-tests",
            "django",
            [
                *manage,
                "test",
                "tests",
                "--tag",
                "offline_simulation",
                "--settings",
                "config.simulation_settings",
                "--verbosity",
                "1",
                "--noinput",
            ],
            60,
        ),
        (
            "reference-app-tests",
            "django",
            [
                *manage,
                "test",
                "reference_lab",
                "--settings",
                "config.reference_verification_settings",
                "--verbosity",
                "1",
                "--noinput",
            ],
            120,
        ),
        ("django-check", None, [*manage, "check"], 60),
        ("migration-drift", None, [*manage, "makemigrations", "--check", "--dry-run"], 60),
        (
            "source-migration-drift",
            None,
            [
                *manage,
                "makemigrations",
                "--check",
                "--dry-run",
                "--settings",
                "config.reference_verification_settings",
            ],
            60,
        ),
        ("ruff-check", None, [str(python), "-B", "-m", "ruff", "check", *targets], 60),
        ("ruff-format", None, [str(python), "-B", "-m", "ruff", "format", "--check", *targets], 60),
        ("publication-scan", None, [str(python), "-B", "scripts/check_publication.py"], 120),
        *[
            (
                name,
                "node",
                ["node", "--test", "--test-isolation=none", "--test-reporter=tap", target],
                60,
            )
            for name, target in (
                ("node-courier-tests", "integrations/sender.test.mjs"),
                ("node-http-harness-mock-tests", "integrations/supabase-http.test.mjs"),
                ("node-bettail-route-mock-tests", "integrations/bettail-routes.test.mjs"),
            )
        ],
    ]


def record(python):
    run_id = uuid.uuid4().hex
    directory = private_run_directory(ROOT, run_id)
    directory.mkdir(parents=True, exist_ok=False)
    env = child_environment()
    for name in list(env):
        if name.startswith(("PG", "SB_REF_", "SB_ENTERPRISE_", "SB_SERVICE_")) or name in (
            "PYTHONHOME",
            "PYTHONPATH",
            "PYTHONINSPECT",
            "PYTHONSTARTUP",
        ):
            env.pop(name)
    env["SB_SECRET_KEY"] = secrets.token_urlsafe(64)
    before = source_manifest(ROOT)
    git_before = git_state(ROOT, env)
    started, clock = datetime.now(timezone.utc).isoformat(), time.monotonic()
    results = []
    versions = {
        "python": capture_small([str(python), "--version"], ROOT, env),
        "django": capture_small([str(python), "-m", "django", "--version"], ROOT, env),
        "node": capture_small(["node", "--version"], ROOT, env),
    }
    for name, kind, command, timeout in checks(python):
        result = run_check(name, command, timeout, ROOT, directory, env)
        if kind is not None:
            stdout = (directory / (name + ".stdout.txt")).read_text(
                encoding="utf8", errors="replace"
            )
            stderr = (directory / (name + ".stderr.txt")).read_text(
                encoding="utf8", errors="replace"
            )
            summary = (
                parse_django_summary(stdout + "\n" + stderr)
                if kind == "django"
                else parse_node_tap_summary(stdout)
            )
            result["tests"] = summary
            denied = (
                ("skipped", "failures", "errors", "expected_failures", "unexpected_successes")
                if kind == "django"
                else ("failures", "cancelled", "skipped", "todo")
            )
            result["passed"] = bool(
                result["passed"]
                and summary
                and summary["successful_summary"]
                and summary["tests_run"] > 0
                and not any(summary[key] for key in denied)
            )
        results.append(result)
        print(name + ": " + ("passed" if result["passed"] else "failed"), flush=True)
    after = source_manifest(ROOT)
    git_after = git_state(ROOT, env)
    unchanged = before == after and git_before["head"] == git_after["head"]
    report = {
        "schema_version": 1,
        "kind": "signalbridge-enterprise-offline-verification",
        "run_id": run_id,
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(time.monotonic() - clock, 3),
        "tool_versions": versions,
        "revision": git_before["head"],
        "working_tree_dirty": git_before["dirty"],
        "source_sha256": before["sha256"],
        "source_file_count": before["file_count"],
        "source_unchanged": unchanged,
        "checks": [
            {
                **{key: row[key] for key in ("name", "passed", "exit_code", "duration_seconds")},
                "log_sha256": {
                    stream: row["logs"][stream]["sha256"] for stream in ("stdout", "stderr")
                },
                **({"tests": row["tests"]} if "tests" in row else {}),
            }
            for row in results
        ],
        "limits": [
            "The courier suite imports persistence tests; they run once here rather than again as a separate group.",
            "Builder-operated disposable SQLite regression checks; not an independent audit or personal competence assessment.",
            "Reference HTTP-client tests use Django's client and transport doubles; no native source server, TLS or PostgreSQL acceptance proof.",
            "Node suites simulate upstream services; filesystem persistence checks do not establish sustained native delivery.",
            "No new detection evaluation, native Wazuh/ZAP/Shuffle, Keycloak, remote CI, dependency advisory certification or 24-hour run.",
            "Test counts describe executed test methods, not detection accuracy, enterprise coverage or business savings.",
        ],
    }
    report["passed"] = (
        unchanged and len(results) == len(checks(python)) and all(r["passed"] for r in results)
    )
    (directory / "source-manifest.json").write_text(
        json.dumps(before, indent=2) + "\n", encoding="utf8"
    )
    (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf8")
    public_id = "20261001-enterprise-offline-" + run_id
    public = receipt_path(ROOT, "docs/evidence/" + public_id + ".json", public_id)
    with public.open("x", encoding="utf8") as output:
        output.write(json.dumps(report, indent=2) + "\n")
    print("Receipt: " + str(public))
    return report["passed"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python",
        type=Path,
        required=True,
        help="Existing trusted interpreter; never installs packages.",
    )
    options = parser.parse_args()
    if not options.python.is_absolute() or not options.python.is_file():
        parser.error("An absolute existing trusted interpreter path is required.")
    raise SystemExit(0 if record(options.python) else 1)
