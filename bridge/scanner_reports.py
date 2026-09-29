"""Bounded, offline adapters for untrusted scanner reports, never proof of execution."""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import unquote

MAX_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 2000
MAX_INPUTS = 20000
MAX_DEPTH = 32
MAX_NODES = 100000
LEVELS = ("none", "note", "warning", "error")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!:/-]{0,127}\Z")
_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_TOOL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,79}\Z")


class ReportError(ValueError):
    """A safe, non-payload-bearing error suitable for showing to the importer."""


@dataclass(frozen=True)
class ParsedFinding:
    fingerprint: str
    severity: str
    rule_id: str
    title: str
    path: str = ""
    line: int | None = None
    package: str = ""
    package_version: str = ""
    fix_versions: tuple[str, ...] = ()
    suppressed: bool = False
    suppression_statuses: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParsedReport:
    format: str
    tool: str
    version: str
    coverage_status: str
    input_count: int
    skipped_count: int
    suppressed_count: int
    findings: tuple[ParsedFinding, ...]


def _fail(message):
    raise ReportError(message)


def _object(value, label):
    if not isinstance(value, dict):
        _fail(f"Invalid {label}: expected an object.")
    return value


def _list(value, label, maximum=MAX_FINDINGS):
    if not isinstance(value, list) or len(value) > maximum:
        _fail(f"Invalid {label}: expected a bounded list.")
    return value


def _token(value, label, pattern=_TOKEN, maximum=128):
    if not isinstance(value, str) or len(value) > maximum or not pattern.fullmatch(value):
        _fail(f"Invalid {label}.")
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("Duplicate JSON keys are not supported.")
        result[key] = value
    return result


def _reject_constant(_value):
    _fail("Non-finite JSON numbers are not supported.")


def _load(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BYTES:
        _fail("Supply a JSON report no larger than 2 MiB.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        _fail("The report must contain UTF-8 JSON.")
    # Check depth before the JSON decoder allocates deeply nested structures.
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                _fail("The report exceeds the JSON nesting limit.")
        elif char in "]}":
            depth -= 1
    try:
        data = json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, ReportError):
            raise
        _fail("The report is not valid JSON.")
    pending, nodes = [data], 0
    while pending:
        value = pending.pop()
        nodes += 1
        if nodes > MAX_NODES:
            _fail("The report exceeds the JSON item limit.")
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, float) and not (-float("inf") < value < float("inf")):
            _fail("Non-finite JSON numbers are not supported.")
    return _object(data, "report")


def _fingerprint(rule, path="", line=None, package="", version=""):
    values = [rule, path, line, package, version]
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def _relative_path(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 500:
        _fail("Invalid relative artifact path.")
    try:
        value = unquote(value, encoding="utf-8", errors="strict").replace("\\", "/")
    except UnicodeDecodeError:
        _fail("Invalid relative artifact path.")
    if (
        value.startswith("/")
        or ":" in value
        or "%" in value
        or "?" in value
        or "#" in value
        or any(not char.isprintable() for char in value)
        or ".." in value.split("/")
    ):
        _fail("Artifact locations must be relative paths without traversal or URI schemes.")
    path = str(PurePosixPath(value))
    if path == "." or len(path) > 500:
        _fail("Invalid relative artifact path.")
    return path


def _pip_audit(data):
    dependencies = _list(data.get("dependencies"), "dependencies", MAX_INPUTS)
    if not dependencies:
        _fail("An empty dependency list does not establish audit coverage.")
    _list(data.get("fixes", []), "fixes", MAX_INPUTS)
    findings, skipped, seen = [], 0, set()
    for dependency in dependencies:
        dep = _object(dependency, "dependency")
        name = _token(dep.get("name"), "package name", _PACKAGE)
        name = re.sub(r"[-_.]+", "-", name).lower()
        if name in seen:
            _fail("Duplicate dependencies are not supported.")
        seen.add(name)
        if "skip_reason" in dep:
            if (
                not isinstance(dep["skip_reason"], str)
                or not dep["skip_reason"].strip()
                or "vulns" in dep
            ):
                _fail("Invalid skipped dependency.")
            skipped += 1
            continue
        version = _token(dep.get("version"), "package version", maximum=100)
        vulnerabilities = _list(dep.get("vulns"), "vulnerabilities")
        ids = set()
        for vulnerability in vulnerabilities:
            vuln = _object(vulnerability, "vulnerability")
            rule = _token(vuln.get("id"), "vulnerability identifier")
            if rule in ids:
                _fail("Duplicate vulnerability identifiers in a dependency.")
            ids.add(rule)
            fixes = tuple(
                sorted(
                    {
                        _token(item, "fix version", maximum=100)
                        for item in _list(vuln.get("fix_versions"), "fix versions", 100)
                    }
                )
            )
            # Descriptions and aliases are deliberately not retained in this adapter.
            findings.append(
                ParsedFinding(
                    fingerprint=_fingerprint(rule, package=name, version=version),
                    severity="unknown",
                    rule_id=rule,
                    title=f"Reported dependency advisory {rule}",
                    package=name,
                    package_version=version,
                    fix_versions=fixes,
                )
            )
            if len(findings) > MAX_FINDINGS:
                _fail("The report exceeds 2,000 findings.")
    return ParsedReport(
        format="pip-audit",
        tool="pip-audit",
        version="",
        coverage_status="incomplete" if skipped else "complete",
        input_count=len(dependencies),
        skipped_count=skipped,
        suppressed_count=0,
        findings=tuple(findings),
    )


def _sarif_location(result):
    locations = _list(result.get("locations", []), "locations", 1)
    if not locations:
        return "", None
    location = _object(locations[0], "location")
    physical = _object(location.get("physicalLocation"), "physical location")
    artifact = _object(physical.get("artifactLocation"), "artifact location")
    if "index" in artifact:
        _fail("Indexed SARIF artifact references are not supported.")
    if "uriBaseId" in artifact:
        _fail("SARIF artifact base references require normalization before import.")
    path = _relative_path(artifact.get("uri"))
    region = _object(physical.get("region", {}), "region")
    line = region.get("startLine")
    if line is not None and (type(line) is not int or not 1 <= line <= 10000000):
        _fail("Invalid artifact line number.")
    return path, line


def _sarif_suppressions(result):
    statuses = set()
    for item in _list(result.get("suppressions", []), "suppressions", 20):
        suppression = _object(item, "suppression")
        if suppression.get("kind") not in ("inSource", "external"):
            _fail("Invalid SARIF suppression kind.")
        status = suppression.get("status", "unspecified")
        if status not in ("accepted", "underReview", "rejected", "unspecified"):
            _fail("Invalid SARIF suppression status.")
        statuses.add(status)
    return bool(statuses & {"accepted", "unspecified"}), tuple(sorted(statuses))


def _sarif_coverage(run):
    if "invocations" not in run:
        return "unknown"
    invocations = _list(run["invocations"], "invocations", 100)
    if not invocations:
        return "unknown"
    incomplete, failed = False, False
    for item in invocations:
        invocation = _object(item, "invocation")
        success = invocation.get("executionSuccessful")
        if type(success) is not bool:
            _fail("SARIF invocations must declare executionSuccessful.")
        failed = failed or not success
        for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
            for notification in _list(invocation.get(key, []), "notifications", 2000):
                _object(notification, "notification")
                level = notification.get("level", "warning")
                if level not in LEVELS:
                    _fail("Invalid SARIF notification level.")
                if level in ("warning", "error"):
                    incomplete = True
    return "failed" if failed else "incomplete" if incomplete else "complete"


def _sarif(data):
    if data.get("version") != "2.1.0":
        _fail("Only SARIF 2.1.0 is supported.")
    if "inlineExternalProperties" in data:
        _fail("External SARIF property references are not supported.")
    runs = _list(data.get("runs"), "runs", 1)
    if len(runs) != 1:
        _fail("Supply exactly one SARIF run.")
    run = _object(runs[0], "run")
    if "externalPropertyFileReferences" in run:
        _fail("External SARIF property references are not supported.")
    tool = _object(run.get("tool"), "tool")
    driver = _object(tool.get("driver"), "driver")
    name = _token(driver.get("name"), "tool name", _TOOL)
    version = driver.get("semanticVersion", driver.get("version", ""))
    if version:
        version = _token(version, "tool version", maximum=80)
    elif not isinstance(version, str):
        _fail("Invalid tool version.")
    rules = {}
    for item in _list(driver.get("rules", []), "rules", 10000):
        rule = _object(item, "rule")
        rule_id = _token(rule.get("id"), "rule identifier")
        if rule_id in rules:
            _fail("Duplicate SARIF rule identifiers.")
        config = _object(rule.get("defaultConfiguration", {}), "rule configuration")
        level = config.get("level", "warning")
        if level not in LEVELS:
            _fail("Invalid default SARIF level.")
        rules[rule_id] = level
    results = _list(run.get("results"), "results")
    rule_order = list(rules)
    findings, fingerprints = [], set()
    for item in results:
        result = _object(item, "result")
        if result.get("kind", "fail") not in ("fail", "review"):
            _fail("Only actionable SARIF fail or review results are supported.")
        if "baselineState" in result and result["baselineState"] not in (
            "new",
            "unchanged",
            "updated",
        ):
            _fail("Only current SARIF baseline results are supported.")
        rule_id = _token(result.get("ruleId"), "rule identifier")
        if "ruleIndex" in result:
            index = result["ruleIndex"]
            if (
                type(index) is not int
                or not 0 <= index < len(rule_order)
                or rule_order[index] != rule_id
            ):
                _fail("SARIF rule index and identifier must refer to the same inline rule.")
        if "rule" in result:
            _fail("Indirect SARIF rule references are not supported.")
        message = _object(result.get("message"), "result message")
        if not isinstance(message.get("text"), str) or not message["text"].strip():
            _fail("SARIF result messages must provide nonempty text.")
        # Do not store tool messages: they can echo source code, credentials or HTTP data.
        level = result.get("level", rules.get(rule_id, "warning"))
        if level not in LEVELS:
            _fail("Invalid SARIF result level.")
        path, line = _sarif_location(result)
        suppressed, statuses = _sarif_suppressions(result)
        fingerprint = _fingerprint(rule_id, path=path, line=line)
        if fingerprint in fingerprints:
            _fail("Duplicate SARIF findings require a normalized report.")
        fingerprints.add(fingerprint)
        findings.append(
            ParsedFinding(
                fingerprint=fingerprint,
                severity=level,
                rule_id=rule_id,
                title=f"{name} reported rule {rule_id}",
                path=path,
                line=line,
                suppressed=suppressed,
                suppression_statuses=statuses,
            )
        )
    artifacts = _list(run.get("artifacts", []), "artifacts", MAX_INPUTS)
    for artifact in artifacts:
        _object(artifact, "artifact")
    return ParsedReport(
        format="sarif",
        tool=name,
        version=version,
        coverage_status=_sarif_coverage(run),
        input_count=len(artifacts),
        skipped_count=0,
        suppressed_count=sum(finding.suppressed for finding in findings),
        findings=tuple(findings),
    )


def parse_report(raw: bytes, format: str) -> ParsedReport:
    """Read approved metadata only. This function performs no I/O or code execution."""
    if format == "zap":
        from .zap_report import parse_zap_report

        return parse_zap_report(raw)
    if format not in ("pip-audit", "sarif"):
        _fail("Choose the pip-audit, sarif or zap report format.")
    data = _load(raw)
    return _pip_audit(data) if format == "pip-audit" else _sarif(data)
