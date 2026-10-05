"""Render reviewed public receipts without app settings, private files or a database."""

import argparse
import hashlib
import json
import math
import re
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.simulation_evidence import json_document, stamp, validate_result
from scripts.portfolio_integrations import load_integrations
from scripts.portfolio_story import load_story
from scripts.record_verification import (
    DJANGO_SUMMARY_FIELDS,
    LIMITS,
    NODE_TEST_TARGETS,
    TAP_SUMMARY_FIELDS,
    fixed_checks,
    source_manifest,
)

MAX_BYTES = 2 * 1024 * 1024
CORE_KIND = "signalbridge-core-verification-receipt"
CORE_ID = re.compile(r"[0-9]{8}T[0-9]{12}Z-[0-9a-f]{8}\Z")
BASELINE = "20260924-offline-simulation.json"
CURRENT = "20260924-offline-simulation-analyst.json"
SHA = re.compile(r"[0-9a-f]{64}\Z")
REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class PortfolioError(ValueError):
    """A fixed diagnostic never containing report content or private paths."""


def require(condition, message):
    if not condition:
        raise PortfolioError(message)


def checksum(raw):
    return hashlib.sha256(raw).hexdigest()


def valid_hash(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 1_000_000


def finite(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 86400


def unlinked(root, path):
    require(path.is_relative_to(root), "Artifact path is outside this checkout.")
    current = root
    for part in path.relative_to(root).parts:
        current /= part
        if not current.exists() and not current.is_symlink():
            continue
        info = current.lstat()
        require(
            not stat.S_ISLNK(info.st_mode)
            and not getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024),
            "Evidence and output paths must not be links.",
        )


def read_public(root, filename):
    require(
        isinstance(filename, str) and re.fullmatch(r"[A-Za-z0-9_-]+\.json", filename),
        "Choose a receipt filename inside docs/evidence.",
    )
    path = root / "docs/evidence" / filename
    unlinked(root, path)
    require(path.is_file() and path.stat().st_size <= MAX_BYTES, "Receipt missing or too large.")
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "Receipt too large.")
    try:
        report = json_document(raw)
        pending = [(report, 0)]
        while pending:
            value, depth = pending.pop()
            require(depth <= 24, "Receipt exceeds the nesting limit.")
            if isinstance(value, dict):
                pending.extend((item, depth + 1) for item in value.values())
            elif isinstance(value, list):
                pending.extend((item, depth + 1) for item in value)
    except (ValueError, TypeError, RecursionError) as error:
        raise PortfolioError("Invalid receipt JSON.") from error
    return report, checksum(raw)


def source_identity(report, current=None):
    require(
        valid_hash(report["source_sha256"])
        and integer(report["source_file_count"], 1)
        and report["source_unchanged"] is True,
        "Receipt does not identify unchanged source content.",
    )
    if current is not None:
        require(
            report["source_sha256"] == current["sha256"]
            and report["source_file_count"] == current["file_count"],
            "Receipt is stale for this checkout. Record new verification before building.",
        )


def validate_core(report, current, now):
    require(
        set(report)
        == {
            "schema_version",
            "kind",
            "run_id",
            "started_at",
            "finished_at",
            "duration_seconds",
            "revision",
            "working_tree_dirty",
            "source_sha256",
            "source_file_count",
            "source_unchanged",
            "passed",
            "checks",
            "coverage_limits",
        }
        and type(report["schema_version"]) is int
        and report["schema_version"] == 1
        and report["kind"] == CORE_KIND,
        "Unsupported public core receipt.",
    )
    source_identity(report, current)
    require(
        isinstance(report["run_id"], str)
        and CORE_ID.fullmatch(report["run_id"])
        and isinstance(report["revision"], str)
        and REVISION.fullmatch(report["revision"])
        and type(report["working_tree_dirty"]) is bool,
        "Core execution identity is incomplete.",
    )
    start, end = stamp(report["started_at"]), stamp(report["finished_at"])
    require(
        start <= end <= now
        and finite(report["duration_seconds"])
        and abs((end - start).total_seconds() - report["duration_seconds"]) <= 0.1,
        "Core execution dates or duration are inconsistent.",
    )
    checks = report["checks"]
    expected = {name for name, _, _ in fixed_checks(ROOT)}
    require(
        isinstance(checks, list)
        and len(checks) == len(expected)
        and all(isinstance(item, dict) for item in checks)
        and {item.get("name") for item in checks} == expected,
        "Core receipt must contain every fixed verification check exactly once.",
    )
    require(report["passed"] is True, "Core verification did not pass.")
    for item in checks:
        fields = {"name", "exit_code", "duration_seconds", "passed", "log_sha256"}
        is_tests = item["name"] == "django-tests" or item["name"] in NODE_TEST_TARGETS
        require(set(item) == fields | ({"tests"} if is_tests else set()), "Invalid check fields.")
        require(
            item["passed"] is True
            and type(item["exit_code"]) is int
            and item["exit_code"] == 0
            and finite(item["duration_seconds"])
            and set(item["log_sha256"]) == {"stdout", "stderr"}
            and all(valid_hash(value) for value in item["log_sha256"].values()),
            "A verification check is failed or incomplete.",
        )
        if is_tests:
            tests = item["tests"]
            django = item["name"] == "django-tests"
            fields = DJANGO_SUMMARY_FIELDS if django else TAP_SUMMARY_FIELDS
            require(
                isinstance(tests, dict)
                and set(tests) == set(fields)
                and tests["successful_summary"] is True
                and integer(tests["tests_run"], 1)
                and all(integer(tests[key]) for key in fields if key != "successful_summary")
                and all(
                    tests[key] == 0
                    for key in fields
                    if key not in {"tests_run", "successful_summary", "passed_tests"}
                )
                and (django or tests["passed_tests"] == tests["tests_run"]),
                "Test summary contains missing, skipped, failed or unreconciled checks.",
            )
    require(report["coverage_limits"] == LIMITS, "Core coverage limits are unsupported.")
    return {**report, "coverage_limits": list(LIMITS)}


def select_core(root, current, now, filename=None):
    if filename:
        report, digest = read_public(root, filename)
    else:
        directory = root / "docs/evidence"
        unlinked(root, directory)
        require(
            directory.is_dir(), "No public evidence directory. Record a public core receipt first."
        )
        paths = sorted(directory.glob("*.json"))
        require(len(paths) <= 250, "Too many receipts; select one explicitly.")
        matching = []
        for path in paths:
            if not CORE_ID.fullmatch(path.stem):
                continue
            candidate, candidate_digest = read_public(root, path.name)
            if candidate.get("source_sha256") == current["sha256"]:
                matching.append((path.name, candidate, candidate_digest))
        require(
            matching,
            "No core receipt matches this source. Run scripts/record_verification.py --public-receipt first.",
        )
        # Do not hide the newest matching failed execution behind an older passing run.
        filename, report, digest = max(matching, key=lambda item: item[0])
    clean = validate_core(report, current, now)
    require(filename == clean["run_id"] + ".json", "Receipt filename and execution ID disagree.")
    return {**clean, "receipt": filename, "receipt_sha256": digest}


def simulation(root, filename, current, now, *, challenge=False):
    path = root / "docs/evidence" / filename
    unlinked(root, path)
    if not path.exists():
        return None
    report, digest = read_public(root, filename)
    require(
        set(report)
        == {
            "schema_version",
            "kind",
            "run_id",
            "execution_verified",
            "source_sha256",
            "source_file_count",
            "source_unchanged",
            "git_head_at_execution",
            "working_tree_dirty_at_execution",
            "python",
            "exit_code",
            "result_sha256",
            "provenance_sha256",
            "log_sha256",
            "results",
            "limits",
        }
        and type(report["schema_version"]) is int
        and report["schema_version"] == 1
        and report["kind"]
        == (
            "signalbridge-detection-challenge-receipt"
            if challenge
            else "signalbridge-offline-simulation-receipt"
        )
        and report["execution_verified"] is True
        and type(report["exit_code"]) is int
        and report["exit_code"] == 0,
        "Unsupported or unverified simulation receipt.",
    )
    source_identity(report, current)
    require(
        isinstance(report["run_id"], str)
        and re.fullmatch(r"[a-f0-9]{32}", report["run_id"])
        and isinstance(report["git_head_at_execution"], str)
        and REVISION.fullmatch(report["git_head_at_execution"])
        and type(report["working_tree_dirty_at_execution"]) is bool
        and isinstance(report["python"], str)
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", report["python"])
        and valid_hash(report["result_sha256"])
        and valid_hash(report["provenance_sha256"])
        and set(report["log_sha256"]) == {"stdout.txt", "stderr.txt"}
        and all(valid_hash(value) for value in report["log_sha256"].values()),
        "Simulation execution identity is incomplete.",
    )
    validator = validate_result
    if challenge:
        from bridge.challenge_evidence import validate_result as validate_challenge

        validator = validate_challenge
    status, result = validator(report["results"])
    require(stamp(result["finished_at"]) <= now, "Simulation date is in the future.")
    return {
        "receipt": filename,
        "receipt_sha256": digest,
        "run_id": report["run_id"],
        "source_sha256": report["source_sha256"],
        "source_file_count": report["source_file_count"],
        "revision": report["git_head_at_execution"],
        "working_tree_dirty": report["working_tree_dirty_at_execution"],
        "python": report["python"],
        "result_sha256": report["result_sha256"],
        "provenance_sha256": report["provenance_sha256"],
        "status": status,
        "matches_current_source": current is not None,
        "results": result,
    }


def declarations(run):
    return [(row["id"], row["expected_rule"]) for row in run["results"]["scenarios"]]


def reconstruct_metrics(
    root,
    current,
    now,
    core_receipt=None,
    core_only=False,
    simulation_receipt=None,
    challenge_receipt=None,
):
    """Read selected public receipts and derive every presentation field without writes."""
    try:
        require(not (core_only and simulation_receipt), "Choose core-only or a simulation receipt.")
        require(not (core_only and challenge_receipt), "Core-only excludes challenge evidence.")
        core = select_core(root, current, now, core_receipt)
        baseline = None if core_only else simulation(root, BASELINE, None, now)
        latest = (
            None if core_only else simulation(root, simulation_receipt or CURRENT, current, now)
        )
        challenge_run = None
        if challenge_receipt:
            challenge_run = simulation(root, challenge_receipt, current, now, challenge=True)
            require(challenge_run is not None, "Requested challenge receipt is missing.")
        comparison = bool(baseline and latest)
        if comparison:
            require(
                declarations(baseline) == declarations(latest)
                and baseline["run_id"] != latest["run_id"]
                and stamp(baseline["results"]["finished_at"])
                <= stamp(latest["results"]["started_at"]),
                "Simulation executions cannot form a comparable before/after pair.",
            )
        metrics = {
            "schema_version": 2,
            "kind": "signalbridge-public-portfolio",
            "generated_at": now.isoformat(),
            "core": core,
            "historical_baseline": baseline,
            "current_simulation": latest,
            "detection_challenge": challenge_run,
            "same_declared_scenarios": comparison,
            "integrations": load_integrations(root, read_public, require),
            "limits": [
                "Builder-operated evidence, not an independent audit or an enterprise benchmark.",
                "Core verification and synthetic simulation are different executions with separate dates.",
                "The current source is compared with the core and current simulation receipts at generation only.",
                "Public receipts are reviewed summaries, not signatures or independently attested executions.",
                "Receipt bytes are hashed here; original private logs, raw results and provenance are not reread.",
                "A matching source digest does not verify runtime configuration, dependencies or deployment.",
                "No runtime AI, live attacker exercise, production capacity or competitor superiority is measured.",
            ],
        }
        metrics["story"] = load_story(root, metrics["integrations"], read_public, require)
        return metrics
    except (
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
        OverflowError,
        RecursionError,
    ) as error:
        if isinstance(error, PortfolioError):
            raise
        raise PortfolioError("Evidence is incomplete or inconsistent.") from error


def verify_metrics(root, current, now, metrics):
    """Reconstruct a full handoff from receipts; supplied claims are never rendering authority."""
    try:
        generated = stamp(metrics["generated_at"])
        require(generated <= now, "Portfolio generation date is in the future.")
        latest, challenge = metrics["current_simulation"], metrics["detection_challenge"]
        require(
            latest is not None and challenge is not None, "Handoff needs both simulation profiles."
        )
        # Select the newest current core receipt rather than accepting a supplied older success.
        expected = reconstruct_metrics(
            root,
            current,
            generated,
            simulation_receipt=latest["receipt"],
            challenge_receipt=challenge["receipt"],
        )
        expected["generated_at"] = generated.isoformat()
        require(
            json.dumps(metrics, sort_keys=True, allow_nan=False)
            == json.dumps(expected, sort_keys=True, allow_nan=False),
            "Portfolio metrics differ from the complete reviewed evidence.",
        )
        return expected
    except (
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
        OverflowError,
        RecursionError,
    ) as error:
        if isinstance(error, PortfolioError):
            raise
        raise PortfolioError("Portfolio metrics are incomplete or inconsistent.") from error


def load_stylesheet(root, name):
    """Inline a fixed local asset so the portable viewer needs no network access."""
    require(name in {"portfolio.css", "access-walkthrough.css"}, "Unknown portfolio stylesheet.")
    path = root / "static" / name
    unlinked(root, path)
    require(path.stat().st_size <= 65536, "Portfolio stylesheet exceeds its size limit.")
    with path.open("rb") as handle:
        raw = handle.read(65537)
    require(len(raw) <= 65536, "Portfolio stylesheet exceeds its size limit.")
    value = raw.decode("utf8")
    require("</style" not in value.lower(), "Portfolio stylesheet contains an HTML boundary.")
    return value


def render_portfolio(root, metrics):
    """Render validated metrics using the tracked template; no settings, database or writes."""
    from django.template import Context, Engine

    core = metrics["core"]
    test_checks = [item for item in core["checks"] if "tests" in item]
    challenge_rows, challenge_limits = [], []
    if metrics["detection_challenge"]:
        from bridge.challenge_evidence import LIMITS as CHALLENGE_LIMITS
        from bridge.challenge_evidence import display_rows

        challenge_rows = display_rows(metrics["detection_challenge"]["results"])
        challenge_limits = CHALLENGE_LIMITS
    context = {
        **metrics,
        "portfolio_css": load_stylesheet(root, "portfolio.css"),
        "check_count": len(core["checks"]),
        "test_count": sum(item["tests"]["tests_run"] for item in test_checks),
        "test_checks": test_checks,
        "runs": [
            metrics[key] for key in ("current_simulation", "historical_baseline") if metrics[key]
        ],
        "challenge_rows": challenge_rows,
        "challenge_limits": challenge_limits,
    }
    template_path = root / "templates/portfolio.html"
    unlinked(root, template_path)
    require(template_path.stat().st_size <= MAX_BYTES, "Portfolio template exceeds its size limit.")
    with template_path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "Portfolio template exceeds its size limit.")
    template = Engine(debug=False).from_string(raw.decode("utf8"))
    return template.render(Context(context, use_l10n=False, use_tz=False))


def recheck_evidence(root, metrics):
    """Ensure the receipts and reviewed source excerpts stayed stable through rendering."""
    receipts = [
        metrics[key]
        for key in ("core", "current_simulation", "historical_baseline", "detection_challenge")
        if metrics[key]
    ]
    for collection in (metrics["integrations"], metrics["story"]):
        if collection:
            receipts.extend(collection["receipts"])
    for receipt in receipts:
        _, digest = read_public(root, receipt["receipt"])
        require(digest == receipt["receipt_sha256"], "Receipt changed while building.")
    if metrics["story"]:
        for source in metrics["story"]["sources"]:
            path = root / source["path"]
            unlinked(root, path)
            require(path.stat().st_size <= MAX_BYTES, "Story source exceeds its size limit.")
            with path.open("rb") as handle:
                raw = handle.read(MAX_BYTES + 1)
            require(
                len(raw) <= MAX_BYTES and checksum(raw) == source["sha256"],
                "Story source changed while building.",
            )


def build(
    root=ROOT,
    core_receipt=None,
    now=None,
    core_only=False,
    simulation_receipt=None,
    challenge_receipt=None,
):
    """Validate, render in isolation, then write two fixed public artifacts."""
    root = Path(root).resolve()
    now = now or datetime.now(timezone.utc)
    try:
        current = source_manifest(root)
        metrics = reconstruct_metrics(
            root, current, now, core_receipt, core_only, simulation_receipt, challenge_receipt
        )
        html = render_portfolio(root, metrics)
        encoded = json.dumps(metrics, indent=2, allow_nan=False) + "\n"
        require(
            source_manifest(root) == current,
            "Source changed while building; record verification again.",
        )
        recheck_evidence(root, metrics)
        output = root / "portfolio"
        for target in (output, output / "index.html", output / "metrics.json"):
            unlinked(root, target)
        output.mkdir(exist_ok=True)
        (output / "index.html").write_text(html, encoding="utf8", newline="\n")
        (output / "metrics.json").write_text(encoded, encoding="utf8", newline="\n")
        return metrics
    except (
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
        OverflowError,
        RecursionError,
    ) as error:
        if isinstance(error, PortfolioError):
            raise
        raise PortfolioError(
            "Evidence is incomplete or inconsistent; no new portfolio was built."
        ) from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--core-receipt", help="Filename in docs/evidence; defaults to newest matching execution."
    )
    parser.add_argument(
        "--core-only", action="store_true", help="Explicitly omit all simulation evidence."
    )
    parser.add_argument(
        "--simulation-receipt",
        help="Reviewed filename in docs/evidence for the current simulation.",
    )
    parser.add_argument(
        "--challenge-receipt", help="Reviewed filename for the fixed detection challenge."
    )
    args = parser.parse_args(argv)
    try:
        build(
            core_receipt=args.core_receipt,
            core_only=args.core_only,
            simulation_receipt=args.simulation_receipt,
            challenge_receipt=args.challenge_receipt,
        )
    except (PortfolioError, OSError) as error:
        print(
            str(error)
            if isinstance(error, PortfolioError)
            else "Unable to read or write portfolio evidence.",
            file=sys.stderr,
        )
        return 2
    print("Built portfolio/index.html and metrics.json from source-matched public receipts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
