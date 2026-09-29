"""Sanitize untrusted ZAP reports for one declared disposable target; never execute ZAP."""

import hashlib
import json
import re

from .scanner_reports import ParsedFinding, ParsedReport, ReportError, _load

TARGET_PROFILE = "signalbridge-disposable-web-v1"
TARGET_ORIGIN = "http://signalbridge-zap-target:8000"
TARGET_HOST = "signalbridge-zap-target"
TARGET_PORT = "8000"
APPROVED_PATHS = ("/", "/login/", "/health/")
APPROVED_URLS = {TARGET_ORIGIN + path: path for path in APPROVED_PATHS}
MAX_ALERTS = 250
MAX_INSTANCES_PER_ALERT = 50
MAX_TOTAL_INSTANCES = 2000
MAX_TEXT = 65536
RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}
CONFIDENCE = {"0": "false positive", "1": "low", "2": "medium", "3": "high", "4": "confirmed"}
_VERSION = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){1,3}\Z")
_ID = re.compile(r"[1-9][0-9]{0,6}\Z")
_REFERENCE = re.compile(r"[1-9][0-9]{0,6}(?:-[0-9]{1,4})?\Z")
_ROOT = {"@programName", "@version", "@generated", "created", "site", "insights", "sequences"}
_SITE = {"@name", "@host", "@port", "@ssl", "alerts"}
_ALERT_TEXT = {
    "alert",
    "name",
    "riskdesc",
    "desc",
    "solution",
    "otherinfo",
    "reference",
    "cweid",
    "wascid",
    "sourceid",
}
_ALERT = _ALERT_TEXT | {
    "pluginid",
    "alertRef",
    "riskcode",
    "confidence",
    "instances",
    "count",
    "systemic",
    "tags",
}
_INSTANCE_TEXT = {
    "nodeName",
    "param",
    "attack",
    "evidence",
    "otherinfo",
    "request-header",
    "request-body",
    "response-header",
    "response-body",
}
_INSTANCE = _INSTANCE_TEXT | {"id", "uri", "method"}
_INSIGHT = {"level", "reason", "site", "key", "description", "statistic"}


def _fail(message):
    raise ReportError(message)


def _closed(value, allowed, label):
    if not isinstance(value, dict) or not set(value) <= allowed:
        _fail(f"Unsupported ZAP {label} structure.")
    return value


def _items(value, maximum, label):
    if not isinstance(value, list) or len(value) > maximum:
        _fail(f"Invalid bounded ZAP {label} list.")
    return value


def _text(value, maximum=MAX_TEXT):
    if not isinstance(value, str) or len(value) > maximum:
        _fail("Invalid bounded ZAP text field.")
    return value


def _decimal(value, maximum):
    # Traditional JSON uses decimal strings. Also accept exact JSON integers,
    # never booleans, floats, signs, whitespace or noncanonical leading zeroes.
    if type(value) is int and 0 <= value <= maximum:
        return str(value)
    if (
        not isinstance(value, str)
        or len(value) > 8
        or not re.fullmatch(r"0|[1-9][0-9]*", value)
        or int(value) > maximum
    ):
        _fail("Invalid ZAP numeric metadata.")
    return value


def _response_header(value):
    """Reject explicitly recorded redirects; never expose the header or its values."""
    header = _text(value)
    if not header:
        return
    lines = header.splitlines()
    status = re.fullmatch(r"HTTP/[12](?:\.[01])? ([1-5][0-9]{2})(?: .*)?", lines[0])
    if not status:
        _fail("Invalid ZAP response status metadata.")
    if status[1].startswith("3") or any(
        re.match(r"\s*location\s*:", line, re.IGNORECASE) for line in lines[1:]
    ):
        _fail("Redirect evidence is outside the fixed ZAP profile.")


def _instance_path(item):
    instance = _closed(item, _INSTANCE, "instance")
    uri = instance.get("uri")
    # Exact comparison deliberately rejects URL normalization aliases, query
    # strings, fragments, encoded traversal, credentials and all other origins.
    if not isinstance(uri, str) or uri not in APPROVED_URLS:
        _fail("ZAP instance URL is outside the fixed disposable target.")
    if instance.get("method") != "GET":
        _fail("Only explicit GET instances belong to the fixed ZAP profile.")
    if "id" in instance and not re.fullmatch(r"[1-9][0-9]{0,8}", _text(instance["id"], 9)):
        _fail("Invalid bounded ZAP instance identity.")
    for name in _INSTANCE_TEXT & instance.keys():
        _text(instance[name])
    if "response-header" in instance:
        _response_header(instance["response-header"])
    return APPROVED_URLS[uri]


def parse_zap_report(raw: bytes) -> ParsedReport:
    """Read traditional JSON metadata only; no filesystem, network, DB or process I/O.

    Returns the existing scanner import contract. Input count stays zero because
    alert instances are not the number of requests or pages actually scanned.
    Coverage is always unknown; even a structurally valid empty report cannot
    demonstrate a completed scan. Runtime provenance belongs to a separate runner.
    """
    data = _closed(_load(raw), _ROOT, "report")
    if "@programName" in data and _text(data["@programName"], 32) != "ZAP":
        _fail("Unsupported ZAP report program name.")
    if data.get("sequences", []) != []:
        _fail("Sequences are outside the fixed ZAP profile.")
    version = _text(data.get("@version"), 24)
    if not _VERSION.fullmatch(version):
        _fail("Only numeric ZAP release version metadata is supported.")
    for name in ("@generated", "created"):
        if name in data:
            _text(data[name], 128)
    for item in _items(data.get("insights", []), 100, "insights"):
        insight = _closed(item, _INSIGHT, "insight")
        # Traditional reports also contain session-wide insights with an empty
        # site. They are discarded, not attributed as target coverage.
        if insight.get("site") not in ("", TARGET_ORIGIN):
            _fail("ZAP insight site is outside the fixed disposable target.")
        for value in insight.values():
            _text(value, 4096)
    sites = _items(data.get("site"), 1, "sites")
    if len(sites) != 1:
        _fail("Supply exactly one fixed ZAP lab site.")
    site = _closed(sites[0], _SITE, "site")
    if (
        site.get("@name") != TARGET_ORIGIN
        or site.get("@host") != TARGET_HOST
        or site.get("@port") != TARGET_PORT
        or site.get("@ssl") != "false"
    ):
        _fail("ZAP site metadata does not match the fixed disposable target.")
    findings, seen_rules, instance_count = [], set(), 0
    for item in _items(site.get("alerts"), MAX_ALERTS, "alerts"):
        alert = _closed(item, _ALERT, "alert")
        plugin = _text(alert.get("pluginid"), 7)
        reference = _text(alert.get("alertRef", plugin), 12)
        if (
            not _ID.fullmatch(plugin)
            or not _REFERENCE.fullmatch(reference)
            or reference.split("-", 1)[0] != plugin
        ):
            _fail("Invalid or inconsistent ZAP rule identity.")
        if reference in seen_rules:
            _fail("Duplicate ZAP alert identities require a normalized report.")
        seen_rules.add(reference)
        risk = _decimal(alert.get("riskcode"), 3)
        confidence = _decimal(alert.get("confidence"), 4)
        for name in _ALERT_TEXT & alert.keys():
            _text(alert[name])
        if "systemic" in alert and type(alert["systemic"]) is not bool:
            _fail("Invalid ZAP systemic flag.")
        if "tags" in alert:
            tags = alert["tags"]
            if not isinstance(tags, dict) or len(tags) > 100:
                _fail("Invalid bounded ZAP tags.")
            for name, value in tags.items():
                _text(name, 4096)
                _text(value, 4096)
        instances = _items(alert.get("instances"), MAX_INSTANCES_PER_ALERT, "instances")
        if not instances or int(_decimal(alert.get("count"), MAX_INSTANCES_PER_ALERT)) != len(
            instances
        ):
            _fail("ZAP alert count must match its nonempty instance list.")
        instance_count += len(instances)
        if instance_count > MAX_TOTAL_INSTANCES:
            _fail("ZAP report exceeds the total instance limit.")
        # Several cookies/parameters may generate the same rule at one endpoint.
        # Validate every instance, then consolidate without retaining their values.
        paths = sorted({_instance_path(instance) for instance in instances})
        for path in paths:
            identity = [TARGET_PROFILE, TARGET_ORIGIN, reference, "GET", path]
            fingerprint = hashlib.sha256(
                json.dumps(identity, separators=(",", ":")).encode()
            ).hexdigest()
            findings.append(
                ParsedFinding(
                    fingerprint=fingerprint,
                    severity=RISK[risk],
                    rule_id=reference,
                    title=(
                        f"ZAP reported rule {reference} on GET {path} "
                        f"(reported confidence: {CONFIDENCE[confidence]})"
                    ),
                )
            )
    return ParsedReport(
        format="zap",
        tool="ZAP",
        version=version,
        coverage_status="unknown",
        input_count=0,
        skipped_count=0,
        suppressed_count=0,
        findings=tuple(sorted(findings, key=lambda finding: finding.fingerprint)),
    )
