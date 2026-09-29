"""Run a fixed, offline core check set and preserve revision-bound private evidence."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = (
    "simulations",
    "bridge",
    "config",
    "integrations",
    "scripts",
    "tests",
    "templates",
    "static",
    "fixtures",
)
SOURCE_FILES = (
    ".github/workflows/checks.yml",
    "manage.py",
    "requirements.txt",
    "requirements-dev.txt",
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "compose.yaml",
    "Dockerfile",
    ".dockerignore",
    ".gitignore",
    "Makefile",
    "start-signalbridge.cmd",
    "stop-signalbridge.cmd",
)
IGNORED_SUFFIXES = {".pyc", ".pyo", ".md", ".rst"}
PRIVATE_PARTS = {
    "var",
    "artifacts",
    ".git",
    ".venv",
    "node_modules",
    "private-source",
    "__pycache__",
}
LIMITS = [
    "Builder-operated local core verification; not an independent audit.",
    "Node courier, HTTP-harness and BetTail route suites use mocks; they do not contact real services.",
    "No real Supabase auth, source-app HTTP/storage, PostgreSQL concurrency or container tests.",
    "No dependency advisory lookup, remote CI, deployment or production validation.",
    "Hashes identify content; a filesystem administrator can replace logs and receipts.",
    "Documentation and generated evidence are excluded from the source digest.",
]
NODE_TEST_TARGETS = {
    "node-courier-tests": "integrations/sender.test.mjs",
    "node-http-harness-mock-tests": "integrations/supabase-http.test.mjs",
    "node-bettail-route-mock-tests": "integrations/bettail-routes.test.mjs",
}
DJANGO_SUMMARY_FIELDS = (
    "tests_run",
    "successful_summary",
    "skipped",
    "failures",
    "errors",
    "expected_failures",
    "unexpected_successes",
)
TAP_SUMMARY_FIELDS = (
    "tests_run",
    "successful_summary",
    "passed_tests",
    "failures",
    "cancelled",
    "skipped",
    "todo",
    "suites",
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf8")


def safe_file(root, path):
    """Never follow a source symlink/reparse point into private or external files."""
    relative = path.relative_to(root)
    if any(part in PRIVATE_PARTS or part.startswith(".env") for part in relative.parts):
        return False
    for candidate in (path, *path.parents):
        if candidate == root:
            break
        if candidate.is_symlink() or (
            hasattr(candidate, "is_junction") and candidate.is_junction()
        ):
            raise ValueError("Source links are not allowed in a verification manifest.")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Source path escapes the repository.")
    return path.is_file()


def source_manifest(root):
    def fail_walk(error):
        raise error

    files = {}
    candidates = [root / name for name in SOURCE_FILES]
    for name in SOURCE_DIRS:
        directory = root / name
        if directory.is_symlink() or (
            hasattr(directory, "is_junction") and directory.is_junction()
        ):
            raise ValueError("Source directories must not be links.")
        if directory.exists():
            for parent, directories, filenames in os.walk(
                directory, followlinks=False, onerror=fail_walk
            ):
                for child in list(directories):
                    target = Path(parent) / child
                    if child in PRIVATE_PARTS or child.startswith(".env"):
                        directories.remove(child)
                    elif target.is_symlink() or (
                        hasattr(target, "is_junction") and target.is_junction()
                    ):
                        raise ValueError("Source directories must not be links.")
                candidates.extend(
                    Path(parent) / filename
                    for filename in filenames
                    if Path(filename).suffix.lower() not in IGNORED_SUFFIXES
                    and filename != ".DS_Store"
                )
    for path in sorted(candidates):
        if safe_file(root, path):
            files[path.relative_to(root).as_posix()] = sha256(path.read_bytes())
    if not files:
        raise ValueError("No source files found.")
    return {"files": files, "sha256": sha256(json_bytes(files)), "file_count": len(files)}


def child_environment():
    env = os.environ.copy()
    # This runner proves SQLite core behavior. Never inherit a hosted/test DB target.
    for key in list(env):
        if key.startswith("SB_DB_"):
            del env[key]
    # Fixed Node unit tests must not inherit module preloads, alternate module
    # search paths or coverage-output destinations from the caller's environment.
    for key in ("NODE_OPTIONS", "NODE_PATH", "NODE_V8_COVERAGE"):
        env.pop(key, None)
    env.update(
        SB_MODE="local",
        DJANGO_SETTINGS_MODULE="config.settings",
        PYTHONUTF8="1",
        PYTHONDONTWRITEBYTECODE="1",
        GIT_OPTIONAL_LOCKS="0",
    )
    return env


def capture_small(argv, root, env):
    result = subprocess.run(
        argv, cwd=root, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=20
    )
    if result.returncode:
        raise ValueError("A required provenance command failed.")
    return result.stdout.decode("utf8", errors="replace").strip()


def git_state(root, env):
    head = capture_small(["git", "rev-parse", "HEAD"], root, env)
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
        raise ValueError("A full Git revision is required.")
    status = capture_small(["git", "status", "--porcelain", "--untracked-files=all"], root, env)
    return {"head": head, "dirty": bool(status), "status": status}


def fixed_checks(root):
    python = root / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    ruff = root / ".venv" / ("Scripts/ruff.exe" if os.name == "nt" else "bin/ruff")
    targets = ["bridge", "config", "tests", "scripts", "simulations", "integrations", "manage.py"]
    return [
        ("django-tests", [str(python), "manage.py", "test", "tests", "--verbosity", "1"], 300),
        ("django-check", [str(python), "manage.py", "check"], 60),
        (
            "migration-drift",
            [str(python), "manage.py", "makemigrations", "--check", "--dry-run"],
            60,
        ),
        ("ruff-check", [str(ruff), "check", *targets], 60),
        ("ruff-format", [str(ruff), "format", "--check", *targets], 60),
        ("publication-scan", [str(python), "scripts/check_publication.py"], 60),
        *(
            (
                name,
                ["node", "--test", "--test-isolation=none", "--test-reporter=tap", target],
                60,
            )
            for name, target in NODE_TEST_TARGETS.items()
        ),
    ]


def parse_django_summary(output):
    """Only executed unittest summaries count; 'Found N tests' is discovery, not execution."""
    ran = re.findall(r"^Ran (\d+) tests? in [0-9.]+s\s*$", output, re.MULTILINE)
    outcomes = re.findall(r"^(OK|FAILED)(?: \(([^\r\n]*)\))?\s*$", output, re.MULTILINE)
    if len(ran) != 1 or len(outcomes) != 1:
        return None
    status, detail = outcomes[0]
    counts = {}
    if detail:
        for part in detail.split(", "):
            match = re.fullmatch(
                r"(skipped|failures|errors|expected failures|unexpected successes)=(\d+)", part
            )
            if not match:
                return None
            name, count = match.groups()
            if name in counts:
                return None
            counts[name] = int(count)
    return {
        "tests_run": int(ran[0]),
        "successful_summary": status == "OK",
        **{
            name.replace(" ", "_"): counts.get(name, 0)
            for name in (
                "skipped",
                "failures",
                "errors",
                "expected failures",
                "unexpected successes",
            )
        },
    }


def parse_node_tap_summary(output):
    """Reconcile Node's flat TAP results, final plan and counters; reject other TAP shapes.

    These two fixed suites contain top-level tests, not nested suites. A suite added
    later needs explicit parser support rather than ambiguous/double-counted evidence.
    TAP's tests total includes skipped/todo/cancelled results; none may pass the gate.
    """
    lines = output.splitlines()
    counters = ("tests", "suites", "pass", "fail", "cancelled", "skipped", "todo")
    if len(lines) < 10 or lines[0] != "TAP version 13":
        return None
    if lines.count("TAP version 13") != 1:
        return None
    if any(
        re.match(r"^\s*Bail out!", line, re.IGNORECASE) or re.match(r"^\s+(?:not )?ok\b", line)
        for line in lines
    ):
        return None
    plan = re.fullmatch(r"1\.\.(\d+)", lines[-9])
    if not plan or sum(bool(re.match(r"^\d+\.\.\d+", line)) for line in lines) != 1:
        return None
    counts = {}
    for name, line in zip(counters, lines[-8:-1], strict=True):
        match = re.fullmatch(rf"# {name} (\d+)", line)
        if not match or sum(bool(re.match(rf"^# {name}\b", item)) for item in lines) != 1:
            return None
        counts[name] = int(match[1])
    if (
        not re.fullmatch(r"# duration_ms \d+(?:\.\d+)?", lines[-1])
        or sum(line.startswith("# duration_ms ") for line in lines) != 1
        or counts["suites"] != 0
    ):
        return None
    records = []
    for line in lines[1:-9]:
        match = re.fullmatch(r"(ok|not ok) ([1-9]\d*) - (.+)", line)
        if match:
            status, number, title = match.groups()
            directive = re.search(r" # (SKIP|TODO)(?:\s.*)?$", title, re.IGNORECASE)
            records.append((int(number), status, directive[1].lower() if directive else None))
        elif re.match(r"^(?:not )?ok\b", line):
            return None
    if (
        len(records) != counts["tests"]
        or int(plan[1]) != counts["tests"]
        or [record[0] for record in records] != list(range(1, len(records) + 1))
        or sum(counts[name] for name in ("pass", "fail", "cancelled", "skipped", "todo"))
        != counts["tests"]
        or sum(status == "ok" and directive is None for _, status, directive in records)
        != counts["pass"]
        or sum(status == "not ok" and directive is None for _, status, directive in records)
        != counts["fail"] + counts["cancelled"]
        or sum(directive == "skip" for _, _, directive in records) != counts["skipped"]
        or sum(directive == "todo" for _, _, directive in records) != counts["todo"]
    ):
        return None
    return {
        "tests_run": counts["tests"],
        "successful_summary": all(
            counts[name] == 0 for name in ("fail", "cancelled", "skipped", "todo")
        ),
        "passed_tests": counts["pass"],
        "failures": counts["fail"],
        **{name: counts[name] for name in ("cancelled", "skipped", "todo", "suites")},
    }


def run_check(name, argv, timeout, root, output, env):
    started = utc_now()
    clock = time.perf_counter()
    stdout_path, stderr_path = output / f"{name}.stdout.txt", output / f"{name}.stderr.txt"
    exit_code, error = None, None
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        try:
            result = subprocess.run(
                argv,
                cwd=root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                shell=False,
            )
            exit_code = result.returncode
        except subprocess.TimeoutExpired:
            error = "timeout"
            stderr.write(b"\nVerification runner: check exceeded its fixed timeout.\n")
        except OSError:
            error = "could_not_start"
            stderr.write(b"\nVerification runner: check executable could not start.\n")
    logs = {
        key: {"file": path.name, "sha256": sha256(path.read_bytes())}
        for key, path in (("stdout", stdout_path), ("stderr", stderr_path))
    }
    result = {
        "name": name,
        "argv": argv,
        "started_at": started,
        "finished_at": utc_now(),
        "duration_seconds": round(time.perf_counter() - clock, 3),
        "exit_code": exit_code,
        "error": error,
        "passed": exit_code == 0 and error is None,
        "logs": logs,
    }
    if name == "django-tests":
        text = stdout_path.read_text(encoding="utf8", errors="replace") + "\n"
        text += stderr_path.read_text(encoding="utf8", errors="replace")
        summary = parse_django_summary(text)
        result["tests"] = summary
        result["passed"] = bool(
            result["passed"]
            and summary
            and summary["successful_summary"]
            and summary["tests_run"] > 0
            and all(
                summary[field] == 0
                for field in (
                    "skipped",
                    "failures",
                    "errors",
                    "expected_failures",
                    "unexpected_successes",
                )
            )
        )
    elif name in NODE_TEST_TARGETS:
        # Node's selected TAP reporter writes stdout. Stderr is retained, never
        # treated as an alternative source for a missing or truncated TAP report.
        summary = parse_node_tap_summary(stdout_path.read_text(encoding="utf8", errors="replace"))
        result["tests"] = summary
        result["passed"] = bool(
            result["passed"]
            and summary
            and summary["successful_summary"]
            and summary["tests_run"] > 0
        )
    return result


def public_receipt(report):
    """Construct a strict allowlist; never copy raw logs, commands, paths or Git status."""
    receipt_checks = []
    for check in report["checks"]:
        item = {key: check[key] for key in ("name", "exit_code", "duration_seconds", "passed")}
        item["log_sha256"] = {name: check["logs"][name]["sha256"] for name in ("stdout", "stderr")}
        if check["name"] == "django-tests" or check["name"] in NODE_TEST_TARGETS:
            summary = check.get("tests")
            fields = (
                DJANGO_SUMMARY_FIELDS if check["name"] == "django-tests" else TAP_SUMMARY_FIELDS
            )
            item["tests"] = {key: summary[key] for key in fields} if summary else None
        receipt_checks.append(item)
    return {
        "schema_version": 1,
        "kind": "signalbridge-core-verification-receipt",
        "run_id": report["run_id"],
        "started_at": report["started_at"],
        "finished_at": report["finished_at"],
        "duration_seconds": report["duration_seconds"],
        "revision": report.get("git_before", {}).get("head"),
        "working_tree_dirty": report.get("git_before", {}).get("dirty"),
        "source_sha256": report.get("source_before", {}).get("sha256"),
        "source_file_count": report.get("source_before", {}).get("file_count"),
        "source_unchanged": report.get("source_unchanged", False),
        "passed": report["passed"],
        "checks": receipt_checks,
        "coverage_limits": LIMITS,
    }


def receipt_path(root, requested, run_id):
    target = Path(requested)
    if not target.is_absolute():
        target = root / target
    directory = root / "docs" / "evidence"
    if target.name != f"{run_id}.json" or target.parent.resolve() != directory.resolve():
        raise ValueError("Public receipt must be docs/evidence/<this-run-id>.json.")
    for candidate in (directory, root / "docs"):
        if candidate.is_symlink() or (
            hasattr(candidate, "is_junction") and candidate.is_junction()
        ):
            raise ValueError("Public receipt directory must not be a link.")
    if not target.resolve().is_relative_to(root.resolve()) or target.exists():
        raise ValueError("Public receipt must be a new file inside docs/evidence.")
    return target


def run_verification(root=ROOT, export_public=False):
    root = root.resolve()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8]
    output = root / "artifacts" / "local" / "verification" / run_id
    # Verify ignored artifact parents too; a junction could otherwise redirect private logs.
    for parent in (root / "artifacts", root / "artifacts/local", output.parent):
        if parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction()):
            raise ValueError("Private evidence directories must not be links.")
    output.mkdir(parents=True, exist_ok=False)
    env = child_environment()
    started = time.perf_counter()
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "started_at": utc_now(),
        "checks": [],
        "passed": False,
        "coverage_limits": LIMITS,
    }
    try:
        report["git_before"] = git_state(root, env)
        report["source_before"] = source_manifest(root)
        checks = fixed_checks(root)
        versions = {}
        for name, command in (
            ("python", [checks[0][1][0], "--version"]),
            ("django", [checks[0][1][0], "-m", "django", "--version"]),
            ("ruff", [checks[3][1][0], "--version"]),
            ("git", ["git", "--version"]),
            ("node", ["node", "--version"]),
        ):
            try:
                versions[name] = capture_small(command, root, env)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                versions[name] = None
        report["tool_versions"] = versions
        for name, argv, timeout in checks:
            report["checks"].append(run_check(name, argv, timeout, root, output, env))
        report["source_after"] = source_manifest(root)
        report["git_after"] = git_state(root, env)
        report["source_unchanged"] = (
            report["source_before"] == report["source_after"]
            and report["git_before"]["head"] == report["git_after"]["head"]
        )
        report["passed"] = (
            report["source_unchanged"]
            and all(versions.values())
            and len(report["checks"]) == len(checks)
            and all(check["passed"] for check in report["checks"])
        )
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        report["runner_error"] = type(error).__name__
    report["finished_at"] = utc_now()
    report["duration_seconds"] = round(time.perf_counter() - started, 3)
    (output / "report.json").write_bytes(json_bytes(report))
    if export_public:
        target = receipt_path(root, root / "docs/evidence" / f"{run_id}.json", run_id)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(json_bytes(public_receipt(report)))
    return report, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--public-receipt",
        action="store_true",
        help="Also write a sanitized, reviewable docs/evidence/<run-id>.json (never publish it).",
    )
    args = parser.parse_args()
    try:
        report, output = run_verification(export_public=args.public_receipt)
    except (OSError, ValueError):
        print("Verification could not safely create its evidence files.")
        return 2
    print(("PASS" if report["passed"] else "FAIL") + " fixed local core verification.")
    print("Private evidence: " + str(output))
    if args.public_receipt:
        print("Reviewable receipt: docs/evidence/" + report["run_id"] + ".json")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
