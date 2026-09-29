"""Bounded ZAP pilot inside the reviewed scanner container; no Docker access."""

import hashlib
import http.client
import json
import math
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

if __package__:
    from .contract import (
        BODY_HASHES,
        BODY_LIMIT,
        EXPECTED_RULE,
        HOST,
        LOG_LIMIT,
        ORIGIN,
        PASSIVE_SECONDS,
        PATHS,
        PROFILE,
        REPORT_LIMIT,
        REQUEST_TIMEOUT,
        STARTUP_SECONDS,
        TOTAL_SECONDS,
    )
else:
    sys.path.insert(0, "/pilot")  # Fixed read-only reviewed mount; works with Python -I.
    from contract import (
        BODY_HASHES,
        BODY_LIMIT,
        EXPECTED_RULE,
        HOST,
        LOG_LIMIT,
        ORIGIN,
        PASSIVE_SECONDS,
        PATHS,
        PROFILE,
        REPORT_LIMIT,
        REQUEST_TIMEOUT,
        STARTUP_SECONDS,
        TOTAL_SECONDS,
    )

EVIDENCE = Path("/evidence")
RUNTIME = Path("/tmp/signalbridge-zap-pilot")
API_HOST, API_PORT = "127.0.0.1", 8080
_API_ROUTES = {
    ("core", "view", "version"),
    ("core", "view", "mode"),
    ("core", "view", "urls"),
    ("core", "view", "messages"),
    ("core", "view", "numberOfMessages"),
    ("core", "action", "setMode"),
    ("core", "action", "shutdown"),
    ("context", "action", "newContext"),
    ("context", "action", "includeInContext"),
    ("context", "action", "setContextInScope"),
    ("pscan", "action", "setScanOnlyInScope"),
    ("pscan", "action", "setMaxAlertsPerRule"),
    ("pscan", "action", "setMaxBodySizeInBytes"),
    ("pscan", "action", "enableAllScanners"),
    ("pscan", "view", "recordsToScan"),
    ("pscan", "view", "currentTasks"),
    ("pscan", "view", "scanOnlyInScope"),
    ("pscan", "view", "scanners"),
}


class PilotError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise PilotError(code)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "ambiguous_json")
        result[key] = value
    return result


def decode(raw):
    def reject_constant(_value):
        raise PilotError("nonfinite_api_json")

    def finite_float(value):
        number = float(value)
        require(math.isfinite(number), "nonfinite_api_json")
        return number

    try:
        return json.loads(
            raw, object_pairs_hook=pairs, parse_constant=reject_constant, parse_float=finite_float
        )
    except (ValueError, UnicodeError, RecursionError):
        raise PilotError("invalid_api_json") from None


def network_alarm(_signum, _frame):
    raise PilotError("network_wall_deadline")


@contextmanager
def network_deadline(seconds):
    """Linux main-thread wall deadline, including slow response-body consumption."""
    require(sys.platform == "linux", "linux_network_deadline_required")
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "nested_network_deadline")
    previous = signal.signal(signal.SIGALRM, network_alarm)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def safe_directory(path):
    require(path.is_dir() and path.resolve() == path, "unsafe_private_directory")
    require(
        not any(part.is_symlink() for part in (path, *path.parents)), "linked_private_directory"
    )


def private_write(path, raw):
    safe_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
        stream.write(raw)


class Client:
    def __init__(self, key, deadline):
        self.key = key
        self.deadline = deadline
        self.calls = 0
        self.target_requests = []

    def request(self, url, headers, maximum):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "total_deadline")
        require(self.calls < 400, "api_call_budget")
        self.calls += 1
        connection = http.client.HTTPConnection(
            API_HOST, API_PORT, timeout=min(REQUEST_TIMEOUT, remaining)
        )
        try:
            # http.client returns a redirect response as-is: it has no follow loop,
            # cookie jar, environment proxy handling, browser or content renderer.
            with network_deadline(min(REQUEST_TIMEOUT, remaining)):
                connection.request("GET", url, headers={**headers, "Connection": "close"})
                response = connection.getresponse()
                raw = response.read(maximum + 1)
                require(len(raw) <= maximum, "response_size_limit")
                require(not 300 <= response.status <= 399, "redirect_refused")
                require(response.getheader("Location") is None, "redirect_header_refused")
                require(response.status == 200, "unexpected_http_status")
                return raw, response
        finally:
            connection.close()

    def api(self, component, kind, name, **parameters):
        require((component, kind, name) in _API_ROUTES, "api_route_refused")
        path = f"/JSON/{component}/{kind}/{name}/"
        if parameters:
            path += "?" + urlencode(parameters)
        raw, _ = self.request(path, {"X-ZAP-API-Key": self.key}, REPORT_LIMIT)
        value = decode(raw)
        require(isinstance(value, dict) and "code" not in value, "api_rejected")
        return value

    def target(self, path):
        ordinal = len(self.target_requests) + 1
        require(ordinal <= 3 and path == PATHS[ordinal - 1], "target_sequence_refused")
        self.target_requests.append({"method": "GET", "path": path, "status": "attempted"})
        raw, response = self.request(ORIGIN + path, {"Host": HOST}, BODY_LIMIT)
        require(response.getheader("X-SignalBridge-Fixture") == PROFILE, "wrong_fixture_identity")
        require(
            response.getheader("X-SignalBridge-Request-Ordinal") == str(ordinal),
            "request_count_mismatch",
        )
        require(hashlib.sha256(raw).hexdigest() == BODY_HASHES[path], "fixture_body_mismatch")
        expected_nosniff = "nosniff" if path == "/health/" else None
        require(
            response.getheader("X-Content-Type-Options") == expected_nosniff,
            "fixture_control_mismatch",
        )
        self.target_requests[-1].update(
            status="passed", http_status=200, body_sha256=BODY_HASHES[path]
        )

    def report(self):
        raw, _ = self.request(
            "/OTHER/core/other/jsonreport/", {"X-ZAP-API-Key": self.key}, REPORT_LIMIT
        )
        require(self.key.encode() not in raw, "api_key_in_report")
        return raw


def configure(client):
    require(
        client.api("core", "action", "setMode", mode="safe").get("Result") == "OK",
        "safe_mode_rejected",
    )
    require(client.api("core", "view", "mode").get("mode") == "safe", "safe_mode_unverified")
    require(client.api("core", "view", "urls").get("urls") == [], "nonempty_zap_session")
    require(
        client.api("core", "view", "numberOfMessages").get("numberOfMessages") == "0",
        "nonempty_zap_history",
    )
    client.api("context", "action", "newContext", contextName=PROFILE)
    require(
        client.api(
            "context",
            "action",
            "includeInContext",
            contextName=PROFILE,
            regex=r"^http://signalbridge-zap-target:8000/(?:login/|health/)?$",
        ).get("Result")
        == "OK",
        "context_rejected",
    )
    require(
        client.api(
            "context", "action", "setContextInScope", contextName=PROFILE, booleanInScope="true"
        ).get("Result")
        == "OK",
        "context_scope_rejected",
    )
    for name, values in (
        ("setScanOnlyInScope", {"onlyInScope": "true"}),
        ("setMaxAlertsPerRule", {"maxAlerts": "50"}),
        ("setMaxBodySizeInBytes", {"maxSize": str(BODY_LIMIT)}),
        ("enableAllScanners", {}),
    ):
        require(
            client.api("pscan", "action", name, **values).get("Result") == "OK",
            "passive_config_rejected",
        )
    require(
        client.api("pscan", "view", "scanOnlyInScope").get("scanOnlyInScope") == "true",
        "passive_scope_unverified",
    )
    scanners = client.api("pscan", "view", "scanners").get("scanners")
    require(isinstance(scanners, list), "passive_rules_missing")
    require(
        any(
            item.get("id") == EXPECTED_RULE and item.get("enabled") == "true"
            for item in scanners
            if isinstance(item, dict)
        ),
        "control_rule_unavailable",
    )


def wait_passive(client):
    deadline = min(client.deadline, time.monotonic() + PASSIVE_SECONDS)
    empty_samples = 0
    while time.monotonic() < deadline:
        queue = client.api("pscan", "view", "recordsToScan").get("recordsToScan")
        require(
            isinstance(queue, str) and re.fullmatch(r"[0-9]{1,7}", queue), "invalid_passive_queue"
        )
        tasks = client.api("pscan", "view", "currentTasks").get("currentTasks")
        require(isinstance(tasks, list), "invalid_passive_tasks")
        empty_samples = empty_samples + 1 if queue == "0" and not tasks else 0
        if empty_samples >= 2:
            return
        time.sleep(0.25)
    raise PilotError("passive_queue_incomplete")


def history_headers(value):
    require(isinstance(value, str) and len(value) <= 8192, "history_header_bound")
    require(value.endswith("\r\n\r\n") and "\x00" not in value, "history_header_shape")
    lines = value[:-4].split("\r\n")
    headers = {}
    for line in lines[1:]:
        require(":" in line and not line.startswith((" ", "\t")), "history_header_shape")
        name, content = line.split(":", 1)
        require(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name), "history_header_shape")
        headers.setdefault(name.lower(), []).append(content.strip())
    return lines[0], headers


def numeric_observation(value):
    kind = "string" if isinstance(value, str) else "integer" if type(value) is int else "other"
    if type(value) is int and 0 <= value <= 1_000_000:
        return {"type": kind, "value": value}
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,6}", value):
        return {"type": kind, "value": int(value)}
    return {"type": kind, "value": "not_bounded_numeric"}


def target_observation(value):
    if not isinstance(value, str) or len(value) > 2048:
        return {"category": "invalid_or_oversized"}
    if value == ORIGIN:
        return {"category": "fixed_origin_without_path"}
    for ordinal, path in enumerate(PATHS, 1):
        if value == ORIGIN + path:
            return {"category": "approved_path", "ordinal": ordinal}
    return {"category": "unexpected", "sha256": hashlib.sha256(value.encode()).hexdigest()}


def collect_diagnostics(client):
    """Read bounded metadata only; never include raw HTTP, URLs, tokens or bodies."""
    reads = (
        ("count", "core", "numberOfMessages", {}),
        ("history", "core", "messages", {"start": "0", "count": "8"}),
        ("urls", "core", "urls", {}),
        ("mode", "core", "mode", {}),
        ("scope", "pscan", "scanOnlyInScope", {}),
        ("rules", "pscan", "scanners", {}),
    )
    values, unavailable = {}, []
    for label, component, name, parameters in reads:
        try:
            values[label] = client.api(component, "view", name, **parameters)
        except (PilotError, OSError, http.client.HTTPException):
            unavailable.append(label)
    summary = {
        "kind": "bounded-zap-api-diagnostics",
        "unavailable_reads": unavailable,
        "message_count": numeric_observation(values.get("count", {}).get("numberOfMessages")),
        "safe_mode": values.get("mode", {}).get("mode") == "safe",
        "passive_only_in_scope": values.get("scope", {}).get("scanOnlyInScope") == "true",
    }
    messages = values.get("history", {}).get("messages")
    summary["messages_list"] = isinstance(messages, list)
    summary["message_inventory_length"] = len(messages) if isinstance(messages, list) else None
    summary["message_inventory"] = []
    for message in messages[:8] if isinstance(messages, list) else []:
        if not isinstance(message, dict):
            summary["message_inventory"].append({"category": "invalid_record"})
            continue
        header = message.get("requestHeader")
        response_header = message.get("responseHeader")
        response_header_bounded = isinstance(response_header, str) and len(response_header) <= 8192
        line = header.split("\r\n", 1)[0] if isinstance(header, str) and len(header) <= 8192 else ""
        parts = line.split(" ")
        summary["message_inventory"].append(
            {
                "id": numeric_observation(message.get("id")),
                "history_type": numeric_observation(message.get("type")),
                "method_is_get": len(parts) == 3 and parts[0] == "GET",
                "target": target_observation(parts[1] if len(parts) == 3 else None),
                "empty_default_response": message.get("responseHeader") == "HTTP/1.0 0\r\n\r\n"
                and message.get("responseBody") == "",
                "response_header_length": len(response_header) if response_header_bounded else None,
                "response_header_sha256": hashlib.sha256(response_header.encode()).hexdigest()
                if response_header_bounded
                else None,
                "empty_response_body": message.get("responseBody") == "",
                "zero_timing": message.get("timestamp") == "0" and message.get("rtt") == "0",
            }
        )
    urls = values.get("urls", {}).get("urls")
    summary["site_tree_length"] = len(urls) if isinstance(urls, list) else None
    summary["site_tree_entries"] = (
        [target_observation(value) for value in urls[:16]] if isinstance(urls, list) else []
    )
    rules = values.get("rules", {}).get("scanners")
    summary["header_rule_enabled"] = isinstance(rules, list) and any(
        isinstance(item, dict) and item.get("id") == EXPECTED_RULE and item.get("enabled") == "true"
        for item in rules
    )
    return values, summary


def verify_history(client, observations=None):
    """Reconcile three proxied requests and three unsent ancestor records.

    Pinned ZAP 2.17.0 SiteMap.createReference clones a request into a type-0
    ancestor with no response or timing. CoreAPI includes those records, but
    excludes images. This fixture has no images or rendering client; target
    ordinals independently constrain actual requests. Raw HTTP stays in memory.
    """
    count = (
        client.api("core", "view", "numberOfMessages")
        if observations is None
        else observations.get("count", {})
    )
    require(
        count.get("numberOfMessages") == "6",
        "unexpected_zap_message_count",
    )
    # No baseurl filter: an unexpected record must not disappear through filtering.
    payload = (
        client.api("core", "view", "messages", start="0", count="8")
        if observations is None
        else observations.get("history", {})
    )
    require(
        set(payload) == {"messages"}
        and isinstance(payload["messages"], list)
        and len(payload["messages"]) == 6,
        "unexpected_zap_message_inventory",
    )
    fields = {
        "id",
        "type",
        "timestamp",
        "rtt",
        "cookieParams",
        "note",
        "requestHeader",
        "requestBody",
        "responseHeader",
        "responseBody",
        "tags",
    }
    ancestor_paths = tuple(path.rstrip("/") for path in PATHS)
    requests, ancestors, seen_ids = {}, {}, set()
    for message in payload["messages"]:
        require(isinstance(message, dict) and set(message) == fields, "history_message_shape")
        identifier = message["id"]
        require(
            isinstance(identifier, str)
            and re.fullmatch(r"[1-9][0-9]{0,8}", identifier)
            and identifier not in seen_ids,
            "history_message_identity",
        )
        seen_ids.add(identifier)
        request_line, request_headers = history_headers(message["requestHeader"])
        require(message["type"] in ("0", "1"), "history_message_type")
        allowed_paths = PATHS if message["type"] == "1" else ancestor_paths
        inventory = requests if message["type"] == "1" else ancestors
        candidates = [
            path for path in allowed_paths if request_line == f"GET {ORIGIN}{path} HTTP/1.1"
        ]
        require(len(candidates) == 1 and candidates[0] not in inventory, "history_request_scope")
        path = candidates[0]
        inventory[path] = request_headers
        require(
            request_headers.get("host") == [HOST]
            and message["requestBody"] == ""
            and message["cookieParams"] == ""
            and not {
                "cookie",
                "authorization",
                "proxy-authorization",
                "x-zap-api-key",
                "transfer-encoding",
            }.intersection(request_headers),
            "history_request_credentials_or_body",
        )
        if message["type"] == "0":
            # HttpMessage.cloneRequest retains no response, timing, note or tags.
            # HttpHeader/HttpResponseHeader serialize its empty default as below.
            require(
                message["responseHeader"] == "HTTP/1.0 0\r\n\r\n"
                and message["responseBody"] == ""
                and message["timestamp"] == "0"
                and message["rtt"] == "0"
                and message["note"] == ""
                and message["tags"] == [],
                "history_internal_record_not_empty",
            )
            continue
        response_line, response_headers = history_headers(message["responseHeader"])
        require(
            re.fullmatch(r"HTTP/1\.1 200(?: .*)?", response_line)
            and "location" not in response_headers
            and "set-cookie" not in response_headers,
            "history_response_status",
        )
        require(
            response_headers.get("x-signalbridge-fixture") == [PROFILE]
            and response_headers.get("x-signalbridge-request-ordinal")
            == [str(PATHS.index(path) + 1)],
            "history_response_fixture",
        )
        require(
            isinstance(message["responseBody"], str)
            and hashlib.sha256(message["responseBody"].encode()).hexdigest() == BODY_HASHES[path],
            "history_response_body",
        )
    require(set(requests) == set(PATHS), "history_request_scope")
    require(set(ancestors) == set(ancestor_paths), "history_ancestor_scope")
    for path in PATHS:
        # SiteMap removes only these two entity headers from its cloned request.
        expected = {
            name: values
            for name, values in requests[path].items()
            if name not in {"content-type", "content-length"}
        }
        require(ancestors[path.rstrip("/")] == expected, "history_ancestor_headers")
    return {
        "history_verified": True,
        "history_message_count": 6,
        "history_proxied_count": 3,
        "history_internal_count": 3,
        "history_request_paths": list(PATHS),
        "history_internal_ancestor_paths": list(ancestor_paths),
    }


def failure_report_summary(raw):
    """Retain actual report observations after failure, never passing provenance."""
    data = decode(raw)
    require(
        isinstance(data, dict) and isinstance(data.get("site"), list) and len(data["site"]) == 1,
        "failure_report_shape",
    )
    site = data["site"][0]
    require(
        isinstance(site, dict)
        and site.get("@name") == ORIGIN
        and isinstance(site.get("alerts"), list)
        and len(site["alerts"]) <= 250,
        "failure_report_scope",
    )
    alerts = []
    for alert in site["alerts"]:
        require(
            isinstance(alert, dict)
            and isinstance(alert.get("instances"), list)
            and len(alert["instances"]) <= 50,
            "failure_report_alert_bound",
        )
        paths = set()
        for row in alert["instances"]:
            require(
                isinstance(row, dict)
                and row.get("method") == "GET"
                and row.get("uri") in {ORIGIN + path for path in PATHS},
                "failure_report_scope",
            )
            paths.add(row["uri"][len(ORIGIN) :])
        alerts.append(
            {
                "rule": numeric_observation(alert.get("pluginid")),
                "risk": numeric_observation(alert.get("riskcode")),
                "confidence": numeric_observation(alert.get("confidence")),
                "paths": sorted(paths),
                "instance_count": len(alert["instances"]),
            }
        )
    return {
        "kind": "failed-zap-report-diagnostic",
        "status": "failed",
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "alerts": alerts,
        "scope": "fixed_synthetic_fixture",
        "execution_provenance": "none",
    }


def control_results(raw):
    data = decode(raw)
    require(isinstance(data, dict) and isinstance(data.get("site"), list), "invalid_report_sites")
    sites = data["site"]
    require(
        len(sites) == 1 and isinstance(sites[0], dict) and sites[0].get("@name") == ORIGIN,
        "report_target_mismatch",
    )
    alerts = sites[0].get("alerts")
    require(isinstance(alerts, list) and len(alerts) <= 250, "invalid_report_alerts")
    missing_header_paths = set()
    for alert in alerts:
        require(
            isinstance(alert, dict) and isinstance(alert.get("instances"), list),
            "invalid_alert_instances",
        )
        for instance in alert["instances"]:
            require(
                isinstance(instance, dict)
                and instance.get("method") == "GET"
                and instance.get("uri") in {ORIGIN + path for path in PATHS},
                "report_instance_outside_scope",
            )
            if alert.get("pluginid") == EXPECTED_RULE:
                missing_header_paths.add(instance["uri"][len(ORIGIN) :])
    require(missing_header_paths == {"/", "/login/"}, "header_controls_not_observed")
    return {
        "rule_id": EXPECTED_RULE,
        "positive_paths": ["/", "/login/"],
        "negative_path": "/health/",
        "status": "passed",
    }


def collect_log(stream, path, overflow, api_key):
    try:
        retained = bytearray()
        while block := stream.read(8192):
            if len(retained) + len(block) > LOG_LIMIT:
                overflow.set()
            retained.extend(block[: max(0, LOG_LIMIT - len(retained))])
        # If truncation cuts a key in half, discard the entire possible trailing
        # fragment before redacting complete keys. Overflow already fails the run.
        if overflow.is_set():
            del retained[-len(api_key) :]
        sanitized = bytes(retained).replace(api_key.encode(), b"[redacted-api-key]")
        private_write(path, sanitized)
    except (OSError, ValueError):
        overflow.set()
    finally:
        stream.close()


def run():
    require(
        sys.platform == "linux"
        and os.getuid() != 0
        and Path("/.dockerenv").is_file()
        and Path(__file__).resolve() == Path("/pilot/run_passive.py"),
        "reviewed_container_required",
    )
    overall_deadline = time.monotonic() + TOTAL_SECONDS
    os.umask(0o077)
    safe_directory(EVIDENCE)
    RUNTIME.mkdir(mode=0o700)
    safe_directory(RUNTIME)
    api_key = secrets.token_hex(16)
    config = RUNTIME / "private.properties"
    private_write(
        config,
        (
            f"api.key={api_key}\napi.disablekey=false\napi.addrs.addr.name=127.0.0.1\n"
            "api.addrs.addr.regex=false\nstart.checkForUpdates=false\nstart.checkAddonUpdates=false\n"
            "start.downloadNewRelease=false\nstart.installAddonUpdates=false\nstart.installScannerRules=false\n"
        ).encode(),
    )
    report = {
        "schema_version": 1,
        "kind": "signalbridge-zap-synthetic-pilot",
        "target_kind": "synthetic-fixture-not-signalbridge-application",
        "profile": PROFILE,
        "status": "failed",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "errors": [],
        "limits": [
            "Builder-operated synthetic HTTP fixture only; not an application security assessment.",
            "No spider, active scan, authentication, cookies or redirect following.",
            "Parent must separately verify image, network, mounts, resource bounds and shutdown.",
            "Imported report coverage/provenance remain unknown/claimed_report.",
        ],
    }
    child, collector, client = None, None, None
    overflow = threading.Event()
    try:
        environment = {
            key: os.environ[key] for key in ("PATH", "JAVA_HOME", "LANG") if key in os.environ
        }
        environment.update(HOME=str(RUNTIME), JAVA_OPTS="-Xmx1536m -Djava.awt.headless=true")
        child = subprocess.Popen(
            [
                "/zap/zap.sh",
                "-daemon",
                "-silent",
                "-host",
                API_HOST,
                "-port",
                str(API_PORT),
                "-dir",
                str(RUNTIME / "zap-home"),
                "-configfile",
                str(config),
                "-loglevel",
                "WARN",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            shell=False,
            start_new_session=True,
        )
        collector = threading.Thread(
            target=collect_log,
            args=(child.stdout, EVIDENCE / "zap-process.log", overflow, api_key),
            daemon=True,
        )
        collector.start()
        # Reserve time for graceful shutdown and bounded owned-process cleanup.
        client = Client(api_key, overall_deadline - 30)
        startup_deadline = time.monotonic() + STARTUP_SECONDS
        while time.monotonic() < startup_deadline:
            require(child.poll() is None, "zap_exited_before_ready")
            try:
                version = client.api("core", "view", "version").get("version")
                require(
                    version == "2.17.0",
                    "unexpected_zap_version",
                )
                report["zap_version"] = version
                break
            except (ConnectionError, TimeoutError, http.client.HTTPException):
                time.sleep(0.5)
        else:
            raise PilotError("zap_startup_timeout")
        configure(client)
        for path in PATHS:
            client.target(path)
        wait_passive(client)
        observations, diagnostics = collect_diagnostics(client)
        private_write(
            EVIDENCE / "diagnostics.json",
            (json.dumps(diagnostics, sort_keys=True, indent=2) + "\n").encode(),
        )
        report.update(verify_history(client, observations))
        raw = client.report()
        report["controls"] = control_results(raw)
        require(not overflow.is_set(), "private_log_overflow")
        private_write(EVIDENCE / "zap-report.json", raw)
        report.update(
            report_sha256=hashlib.sha256(raw).hexdigest(),
            passive_queue_complete=True,
            request_count=3,
            redirects_followed=False,
            safe_mode=True,
        )
    except PilotError as exc:
        report["errors"].append(str(exc))
    except (OSError, ValueError, TypeError, KeyError, http.client.HTTPException):
        report["errors"].append("pilot_operation_failed")
    finally:
        if client is not None:
            report["requests"] = client.target_requests
        if report["errors"] and client is not None and child is not None and child.poll() is None:
            # Read-only observation within the original call/time budget. Failure
            # cannot become success, and no additional target request is issued.
            try:
                summary = failure_report_summary(client.report())
                private_write(
                    EVIDENCE / "failure-report-summary.json",
                    (json.dumps(summary, sort_keys=True, indent=2) + "\n").encode(),
                )
                report["failure_report_diagnostic"] = "retained_sanitized_summary"
            except (PilotError, OSError, ValueError, TypeError, http.client.HTTPException):
                report["failure_report_diagnostic"] = "unavailable_or_outside_fixed_scope"
        if child is not None:
            if child.poll() is None and client is not None:
                try:
                    client.api("core", "action", "shutdown")
                except (PilotError, OSError, http.client.HTTPException):
                    pass
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                report["errors"].append("zap_forced_shutdown")
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=5)
            report["zap_exit_code"] = child.returncode
            if child.returncode != 0:
                report["errors"].append("zap_nonzero_exit")
        if collector is not None:
            collector.join(timeout=3)
            if collector.is_alive() or overflow.is_set():
                report["errors"].append("private_log_incomplete")
        report["status"] = "passed" if not report["errors"] and report.get("controls") else "failed"
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        private_write(
            EVIDENCE / "pilot-result.json",
            (json.dumps(report, sort_keys=True, indent=2) + "\n").encode(),
        )
    return report


def main():
    if len(sys.argv) != 1:
        print("This fixed pilot accepts no arguments.")
        return 2
    try:
        report = run()
    except (PilotError, OSError, ValueError):
        print("ZAP pilot could not initialize its fixed private workspace.")
        return 1
    print(
        json.dumps({"status": report["status"], "errors": report["errors"], "synthetic_only": True})
    )
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
