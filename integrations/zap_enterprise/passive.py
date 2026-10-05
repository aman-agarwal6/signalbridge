"""Closed offline HAR analysis through an already-reviewed local ZAP process.

No tool startup, target requests, arbitrary API actions or report publication.
Validated API observations remain distinct from source/runtime attestation.
"""

import hashlib
import http.client
import re
import time
from urllib.parse import urlencode

from integrations.enterprise.reference_http import ORIGIN
from integrations.zap.run_passive import decode, history_headers, network_deadline

from .capture import BODY_BYTES, HAR_BYTES, PROFILE, STEPS, render_har, require, validate_rows

API_BYTES = 2 * 1024 * 1024
PASSIVE_SECONDS = 60
MAX_CALLS = 160
ALERT_LIMIT = 50
HOST = "127.0.0.1:18842"
PATHS = frozenset(path for _, path, _ in STEPS)
# Every slash-free prefix, including "" for ZAP's site-root node, which its
# SiteMap serializes as "GET https://127.0.0.1:18842 HTTP/1.1" with no path.
ANCESTORS = frozenset(
    path[:offset] for path in PATHS for offset, char in enumerate(path) if char == "/"
)
SCOPE = "^(?:" + "|".join(re.escape(ORIGIN + path) for path in sorted(PATHS)) + ")$"
GET_ROUTES = {
    ("autoupdate", "view", "installedAddons"): {},
    ("core", "view", "version"): {},
    ("core", "view", "mode"): {},
    ("core", "view", "urls"): {},
    ("core", "view", "numberOfMessages"): {},
    ("core", "view", "messages"): {"start": "0", "count": "32"},
    ("core", "action", "setMode"): {"mode": "safe"},
    ("context", "action", "newContext"): {"contextName": PROFILE},
    ("context", "action", "includeInContext"): {"contextName": PROFILE, "regex": SCOPE},
    ("context", "action", "setContextInScope"): {"contextName": PROFILE, "booleanInScope": "true"},
    ("pscan", "action", "setScanOnlyInScope"): {"onlyInScope": "true"},
    ("pscan", "action", "setMaxAlertsPerRule"): {"maxAlerts": "10"},
    ("pscan", "action", "setMaxBodySizeInBytes"): {"maxSize": str(BODY_BYTES)},
    ("pscan", "action", "disableAllScanners"): {},
    ("pscan", "action", "enableScanners"): {"ids": "10021"},
    ("pscan", "view", "scanOnlyInScope"): {},
    ("pscan", "view", "scanners"): {},
    ("pscan", "view", "recordsToScan"): {},
    ("pscan", "view", "currentTasks"): {},
    ("alert", "view", "alerts"): {"start": "0", "count": str(ALERT_LIMIT)},
    ("alert", "view", "numberOfAlerts"): {},
}
MESSAGE_FIELDS = {
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
ALERT_FIELDS = {
    "id",
    "pluginId",
    "alertRef",
    "alert",
    "name",
    "nodeName",
    "description",
    "risk",
    "confidence",
    "url",
    "method",
    "other",
    "param",
    "attack",
    "evidence",
    "inputVector",
    "reference",
    "cweid",
    "wascid",
    "sourceid",
    "solution",
    "messageId",
    "sourceMessageId",
    "tags",
}


def numeric(value, maximum=1_000_000):
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,6}", value) is not None)
    result = int(value)
    require(result <= maximum)
    return result


def validate_request(method, path, body):
    allowed = {
        f"/JSON/{component}/{kind}/{name}/" + ("?" + urlencode(parameters) if parameters else "")
        for (component, kind, name), parameters in GET_ROUTES.items()
    }
    require(
        (method == "GET" and path in allowed and body is None)
        or (
            method == "POST"
            and path == "/JSON/exim/action/importHar/"
            and isinstance(body, bytes)
            and 0 < len(body) <= 3 * HAR_BYTES
        )
    )


class Client:
    """Linux container loopback API only; the HAR is a POST body, never a URL."""

    def __init__(self, key, deadline):
        require(isinstance(key, str) and re.fullmatch(r"[0-9a-f]{64}", key) is not None)
        require(
            type(deadline) in (float, int) and time.monotonic() < deadline <= time.monotonic() + 240
        )
        self.key, self.deadline, self.calls = key, deadline, 0

    def request(self, method, path, body=None):
        validate_request(method, path, body)
        remaining = self.deadline - time.monotonic()
        require(remaining > 0 and self.calls < MAX_CALLS)
        self.calls += 1
        connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=min(5, remaining))
        try:
            with network_deadline(min(5, remaining)):
                connection.request(
                    method,
                    path,
                    body=body,
                    headers={
                        "X-ZAP-API-Key": self.key,
                        "Connection": "close",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                response = connection.getresponse()
                raw = response.read(API_BYTES + 1)
                require(
                    len(raw) <= API_BYTES
                    and response.status == 200
                    and response.getheader("Location") is None
                )
                require(self.key.encode() not in raw)
                value = decode(raw)
                require(isinstance(value, dict) and "code" not in value)
                require(time.monotonic() < self.deadline)
                return value
        finally:
            connection.close()

    def api(self, component, kind, name, **parameters):
        route = (component, kind, name)
        require(route in GET_ROUTES and parameters == GET_ROUTES[route])
        path = f"/JSON/{component}/{kind}/{name}/"
        if parameters:
            path += "?" + urlencode(parameters)
        return self.request("GET", path)

    def import_capture(self, rows, phase, captured_at):
        # Render from closed rows here: callers cannot supply an arbitrary HAR,
        # file path, request URL or sendRequests option.
        har = render_har(rows, phase, captured_at)
        require(len(har) <= HAR_BYTES)
        body = urlencode(
            {"data": har.decode("ascii"), "sendRequests": "false", "maxMessages": "5"}
        ).encode("ascii")
        require(len(body) <= 3 * HAR_BYTES)
        value = self.request("POST", "/JSON/exim/action/importHar/", body)
        require(value == {"Result": "OK"})
        return hashlib.sha256(har).hexdigest()


def configure(client):
    require(client.api("core", "view", "version") == {"version": "2.17.0"})
    require(client.api("core", "action", "setMode", mode="safe") == {"Result": "OK"})
    require(client.api("core", "view", "mode") == {"mode": "safe"})
    require(client.api("core", "view", "urls") == {"urls": []})
    require(client.api("core", "view", "numberOfMessages") == {"numberOfMessages": "0"})
    require(client.api("alert", "view", "numberOfAlerts") == {"numberOfAlerts": "0"})
    result = client.api("context", "action", "newContext", contextName=PROFILE)
    require(set(result) == {"contextId"} and numeric(result["contextId"]) > 0)
    for route in (
        ("context", "action", "includeInContext"),
        ("context", "action", "setContextInScope"),
        ("pscan", "action", "setScanOnlyInScope"),
        ("pscan", "action", "setMaxAlertsPerRule"),
        ("pscan", "action", "setMaxBodySizeInBytes"),
        ("pscan", "action", "disableAllScanners"),
        ("pscan", "action", "enableScanners"),
    ):
        require(client.api(*route, **GET_ROUTES[route]) == {"Result": "OK"})
    require(client.api("pscan", "view", "scanOnlyInScope") == {"scanOnlyInScope": "true"})
    scanners = client.api("pscan", "view", "scanners").get("scanners")
    require(isinstance(scanners, list) and len(scanners) <= 200)
    require(
        all(
            isinstance(item, dict) and item.get("enabled") in ("true", "false") for item in scanners
        )
    )
    enabled = [item.get("id") for item in scanners if item["enabled"] == "true"]
    require(enabled == ["10021"])


def wait_passive(client, *, pause=None):
    pause = time.sleep if pause is None else pause
    deadline = min(client.deadline, time.monotonic() + PASSIVE_SECONDS)
    empty = 0
    while time.monotonic() < deadline:
        queue = client.api("pscan", "view", "recordsToScan")
        tasks = client.api("pscan", "view", "currentTasks")
        require(set(queue) == {"recordsToScan"} and set(tasks) == {"currentTasks"})
        count = numeric(queue["recordsToScan"], 100)
        require(isinstance(tasks["currentTasks"], list) and len(tasks["currentTasks"]) <= 100)
        empty = empty + 1 if count == 0 and not tasks["currentTasks"] else 0
        if empty >= 2:
            return
        pause(0.25)
    require(False, "The passive queue did not complete within its declared bound.")


def validate_history(payload, rows, phase, count):
    """Unfiltered inventory: five imported messages plus bounded empty tree ancestors."""
    validate_rows(rows, phase)
    require(isinstance(payload, dict) and set(payload) == {"messages"})
    messages = payload["messages"]
    require(isinstance(messages, list) and len(messages) == numeric(count, 31))
    require(5 <= len(messages) <= len(ANCESTORS) + 5)
    seen_ids, ancestors, bindings = set(), set(), {}
    for message in messages:
        require(isinstance(message, dict) and set(message) == MESSAGE_FIELDS)
        identifier = message["id"]
        require(numeric(identifier) > 0 and identifier not in seen_ids)
        seen_ids.add(identifier)
        request_line, headers = history_headers(message["requestHeader"])
        require(message["requestBody"] == message["cookieParams"] == message["note"] == "")
        if message["type"] == "0":
            # SiteMap clones drop the entity headers and are never passively tagged.
            require(headers == {"host": [HOST]} and message["tags"] == [])
            candidates = [
                path for path in ANCESTORS if request_line == f"GET {ORIGIN}{path} HTTP/1.1"
            ]
            require(len(candidates) == 1 and candidates[0] not in ancestors)
            ancestors.add(candidates[0])
            require(
                message["responseHeader"] == "HTTP/1.0 0\r\n\r\n"
                and message["responseBody"] == ""
                and message["timestamp"] == message["rtt"] == "0"
            )
            continue
        require(message["type"] == "15")  # ZAP TYPE_ZAP_USER, used by the native HAR importer.
        require(set(headers) <= {"host", "content-type", "content-length"})
        require(
            headers.get("host") == [HOST] and headers.get("content-type") == ["application/json"]
        )
        require(headers.get("content-length", ["0"]) == ["0"])
        # Every captured response is application/json; history is read only after
        # the passive queue drains, so ZAP's built-in JSON tag is always present.
        require(message["tags"] == ["JSON"])
        response_line, response_headers = history_headers(message["responseHeader"])
        require(
            set(response_headers)
            <= set(rows[0]["headers"]) | {"x-sb-lab-event-id", "content-length"}
        )
        candidates = []
        for row in rows:
            if (
                request_line != f"GET {ORIGIN}{row['path']} HTTP/1.1"
                or message["responseBody"] != row["body"]
            ):
                continue
            expected = {name: [value] for name, value in row["headers"].items()}
            supplied = {
                name: value for name, value in response_headers.items() if name != "content-length"
            }
            if supplied == expected and re.fullmatch(
                re.escape(row["http_version"]) + f" {row['http_status']}(?: [^\\r\\n]*)?",
                response_line,
            ):
                candidates.append(row)
        require(len(candidates) == 1 and candidates[0]["ordinal"] not in bindings)
        row = candidates[0]
        require(
            response_headers.get("content-length", [str(len(row["body"].encode()))])
            == [str(len(row["body"].encode()))]
        )
        bindings[row["ordinal"]] = identifier
    require(set(bindings) == set(range(5)))
    return {
        "imported_messages": 5,
        "physical_history_records": len(messages),
        "empty_tree_records": len(ancestors),
        "message_ids": bindings,
    }


def validate_alerts(payload, rows, bindings, phase, count):
    validate_rows(rows, phase)
    require(isinstance(payload, dict) and set(payload) == {"alerts"})
    alerts = payload["alerts"]
    require(isinstance(alerts, list) and len(alerts) == numeric(count, ALERT_LIMIT - 1))
    require(len(alerts) == (1 if phase == "fault" else 0))
    retained = []
    for alert in alerts:
        require(isinstance(alert, dict) and set(alert) == ALERT_FIELDS)
        require(
            all(
                isinstance(value, str) and len(value) <= 16384
                for key, value in alert.items()
                if key not in {"tags", "sourceMessageId"}
            )
        )
        require(isinstance(alert["tags"], dict) and len(alert["tags"]) <= 32)
        require(alert["sourceMessageId"] is None or type(alert["sourceMessageId"]) is int)
        numeric(alert["id"])  # ZAP numbers alerts from 0 in a fresh session.
        # The pinned 10021 rule reports its plain ref and the lowercase header name.
        require(alert["pluginId"] == alert["alertRef"] == "10021")
        require(
            alert["risk"] == "Low" and alert["confidence"] == "Medium" and alert["cweid"] == "693"
        )
        require(
            alert["method"] == "GET"
            and alert["url"] == ORIGIN + rows[1]["path"]
            and alert["messageId"] == bindings[1]
        )
        require(
            alert["param"] == "x-content-type-options"
            and alert["attack"] == alert["evidence"] == ""
        )
        retained.append(
            {
                "native_alert_id": alert["id"],
                "native_message_id": alert["messageId"],
                "plugin_id": "10021",
                "ordinal": 1,
                "source_event_id": rows[1]["event_id"],
                "risk": "Low",
                "confidence": "Medium",
            }
        )
    return retained


def analyze_phase(client, rows, phase, captured_at, *, pause=None):
    """Analyze one phase in a fresh process/session; no provenance promotion here."""
    validate_rows(rows, phase)
    configure(client)
    capture_digest = client.import_capture(rows, phase, captured_at)
    wait_passive(client, pause=pause)
    require(client.api("core", "view", "mode") == {"mode": "safe"})
    inventory = client.api("core", "view", "messages", start="0", count="32")
    counts = client.api("core", "view", "numberOfMessages")
    require(set(counts) == {"numberOfMessages"})
    history = validate_history(inventory, rows, phase, counts["numberOfMessages"])
    alerts = client.api("alert", "view", "alerts", start="0", count=str(ALERT_LIMIT))
    alert_count = client.api("alert", "view", "numberOfAlerts")
    require(set(alert_count) == {"numberOfAlerts"})
    findings = validate_alerts(
        alerts, rows, history["message_ids"], phase, alert_count["numberOfAlerts"]
    )
    return {
        "profile": PROFILE,
        "phase": phase,
        "api_observations_validated": True,
        "runtime_attested": False,
        "source_capture_attested": False,
        "har_sha256": capture_digest,
        "history": history,
        "findings": findings,
        "passive_rule_scope": ["10021"],
        "api_calls": client.calls,
    }
