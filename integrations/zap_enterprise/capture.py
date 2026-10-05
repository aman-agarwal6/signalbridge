"""Fixed authenticated source response capture; no ZAP or lab process startup.

Only known synthetic responses qualify. Password requests are excluded. HAR
request credentials are omitted; response security headers and exact synthetic
bodies remain. A capture is not evidence that native ZAP executed.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone

from bridge.contract import parse_json
from integrations.enterprise.reference_http import ACCOUNTS, CONTENT, ORIGIN, RESOURCES

PROFILE = "signalbridge-reference-authenticated-headers-v1"
BODY_BYTES = 8192
HAR_BYTES = 128 * 1024
DOC_PATH = f"/apps/documents/resources/{RESOURCES['documents']}/"
EXPENSE_PATH = f"/apps/expenses/resources/{RESOURCES['expenses']}/"
STEPS = (
    ("document_member", "/identity/", 200),
    ("document_member", DOC_PATH, 200),
    ("document_member", EXPENSE_PATH, 403),
    ("operator", "/identity/", 200),
    ("operator", DOC_PATH, 200),
)
HEADERS = {
    "content-type",
    "x-content-type-options",
    "x-sb-lab-event-id",
    "content-security-policy",
    "x-frame-options",
    "cache-control",
    "pragma",
    "strict-transport-security",
    "referrer-policy",
}
EXCHANGE = {"method", "path", "status", "http_version", "headers", "body", "started_at"}
ROW = {
    "ordinal",
    "account",
    "method",
    "path",
    "http_status",
    "http_version",
    "headers",
    "body",
    "event_id",
    "started_at",
}


class HeaderProfileError(ValueError):
    pass


def require(condition, message="Authenticated header profile rejected inconsistent evidence."):
    if not condition:
        raise HeaderProfileError(message)


def identifier(value):
    try:
        require(isinstance(value, str) and str(uuid.UUID(value)) == value)
    except (ValueError, TypeError, AttributeError):
        raise HeaderProfileError(
            "The protected source response needs a canonical event identity."
        ) from None
    return value


def known_body(account, path):
    if path == "/identity/":
        return {"account": account, "authenticated": True}
    if path == EXPENSE_PATH:
        return {"error": "Access denied."}
    require(path == DOC_PATH)
    return {
        "app": "documents",
        "record_id": str(RESOURCES["documents"]),
        "synthetic_content": CONTENT["documents"],
    }


def observation_time(value):
    require(isinstance(value, str) and len(value) <= 40)
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        raise HeaderProfileError("The source response needs an aware timestamp.") from None
    require(result.tzinfo is not None and result.utcoffset().total_seconds() == 0)
    return result


def captured_row(exchange, account, ordinal, phase, secrets=()):
    require(
        isinstance(phase, str)
        and phase in {"fault", "corrected"}
        and type(ordinal) is int
        and 0 <= ordinal < len(STEPS)
    )
    expected_account, path, status = STEPS[ordinal]
    require(
        account == expected_account and isinstance(exchange, dict) and set(exchange) == EXCHANGE
    )
    require(
        exchange["method"] == "GET"
        and exchange["path"] == path
        and type(exchange["status"]) is int
        and exchange["status"] == status
    )
    require(exchange["http_version"] in ("HTTP/1.0", "HTTP/1.1"))
    raw = exchange["body"]
    require(isinstance(raw, bytes) and 0 < len(raw) <= BODY_BYTES)
    try:
        text = raw.decode("utf8")
        body = parse_json(raw)
    except (ValueError, UnicodeError):
        raise HeaderProfileError(
            "The fixed source response was not the expected synthetic JSON."
        ) from None
    require(body == known_body(account, path))
    require(all(type(body[key]) is type(value) for key, value in known_body(account, path).items()))
    observation_time(exchange["started_at"])
    supplied = exchange["headers"]
    require(isinstance(supplied, (list, tuple)) and len(supplied) <= len(HEADERS))
    headers = {}
    for item in supplied:
        require(isinstance(item, (list, tuple)) and len(item) == 2)
        name, value = item
        require(isinstance(name, str) and isinstance(value, str))
        name = name.lower()
        require(
            name in HEADERS
            and name not in headers
            and 0 < len(value) <= 2048
            and value.isascii()
            and not any(c in value for c in "\r\n\x00")
        )
        headers[name] = value
    require(headers.get("content-type") == "application/json")
    require(
        headers.get("x-content-type-options")
        == (None if phase == "fault" and ordinal == 1 else "nosniff")
    )
    event = headers.get("x-sb-lab-event-id")
    if path == "/identity/":
        require(event is None)
    else:
        identifier(event)
    require(all(isinstance(secret, str) and len(secret) >= 16 for secret in secrets))
    require(
        not any(
            secret in text or any(secret in value for value in headers.values())
            for secret in secrets
        ),
        "Credential material must not enter a scan capture.",
    )
    return {
        "ordinal": ordinal,
        "account": account,
        "method": "GET",
        "path": path,
        "http_status": status,
        "http_version": exchange["http_version"],
        "headers": headers,
        "body": text,
        "event_id": event,
        "started_at": exchange["started_at"],
    }


def validate_rows(rows, phase):
    require(isinstance(rows, list) and len(rows) == len(STEPS))
    ids = set()
    times = []
    for ordinal, row in enumerate(rows):
        require(isinstance(row, dict) and set(row) == ROW)
        require(type(row["ordinal"]) is int and row["ordinal"] == ordinal)
        require(isinstance(row["headers"], dict) and isinstance(row["body"], str))
        parsed = captured_row(
            {
                "method": row["method"],
                "path": row["path"],
                "status": row["http_status"],
                "http_version": row["http_version"],
                "headers": list(row["headers"].items()),
                "body": row["body"].encode("utf8"),
                "started_at": row["started_at"],
            },
            row["account"],
            ordinal,
            phase,
        )
        require(parsed == row)
        times.append(observation_time(row["started_at"]))
        if row["event_id"]:
            require(row["event_id"] not in ids)
            ids.add(row["event_id"])
    require(len(ids) == 3)
    require(times == sorted(times) and (times[-1] - times[0]).total_seconds() <= 180)
    return rows


def validate_pair(phases):
    require(isinstance(phases, dict) and set(phases) == {"fault", "corrected"})
    before = validate_rows(phases["fault"], "fault")
    after = validate_rows(phases["corrected"], "corrected")
    require(observation_time(after[0]["started_at"]) >= observation_time(before[-1]["started_at"]))
    before_ids = {row["event_id"] for row in before if row["event_id"]}
    after_ids = {row["event_id"] for row in after if row["event_id"]}
    require(before_ids.isdisjoint(after_ids))
    for original, corrected in zip(before, after, strict=True):
        for field in ("account", "method", "path", "http_status", "http_version", "body"):
            require(original[field] == corrected[field])
        omitted = {"x-sb-lab-event-id"}
        if original["ordinal"] == 1:
            omitted.add("x-content-type-options")
        require(
            {k: v for k, v in original["headers"].items() if k not in omitted}
            == {k: v for k, v in corrected["headers"].items() if k not in omitted}
        )
    return phases


def render_har(rows, phase, captured_at):
    """Sanitized requests and real captured responses; never resend these requests."""
    validate_rows(rows, phase)
    when = observation_time(captured_at)
    require(when >= observation_time(rows[-1]["started_at"]))
    entries = []
    for row in rows:
        raw = row["body"].encode("utf8")
        entries.append(
            {
                "startedDateTime": row["started_at"],
                "time": 0,
                "request": {
                    "method": "GET",
                    "url": ORIGIN + row["path"],
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [
                        {"name": "Host", "value": "127.0.0.1:18842"},
                        {"name": "Content-Type", "value": "application/json"},
                    ],
                    "queryString": [],
                    "headersSize": -1,
                    "bodySize": 0,
                },
                "response": {
                    "status": row["http_status"],
                    "statusText": "OK" if row["http_status"] == 200 else "Forbidden",
                    "httpVersion": row["http_version"],
                    "cookies": [],
                    "headers": [
                        {"name": name, "value": value}
                        for name, value in sorted(row["headers"].items())
                    ],
                    "content": {
                        "size": len(raw),
                        "mimeType": "application/json",
                        "text": row["body"],
                    },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": len(raw),
                },
                "cache": {},
                "timings": {"send": 0, "wait": 0, "receive": 0},
                "comment": "Authenticated source capture; request credentials omitted. Analyze the recorded response only, without resending requests. Timing fields are placeholders, not performance measurements.",
            }
        )
    value = {
        "log": {
            "version": "1.2",
            "creator": {"name": "SignalBridge", "version": PROFILE},
            "entries": entries,
        }
    }
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
        "ascii"
    )
    require(len(raw) <= HAR_BYTES)
    return raw


def collect_phase(clients, phase, progress, secrets, attempts):
    for ordinal, (account, path, _) in enumerate(STEPS):
        client = clients[account]
        attempts[phase] += 1
        client.request("GET", path)
        progress.append(captured_row(client.last_response, account, ordinal, phase, secrets))
    return validate_rows(progress, phase)


def exercise(client_factory, passwords, control):
    """Finite source-side profile, with cleanup even when login/capture fails.

    The caller owns the reviewed runtime and shared transport budget. This function
    neither installs nor starts it and cannot claim a native scanner execution.
    Private rows are separate from the public, predicate-only summary.
    """
    require(
        isinstance(passwords, dict)
        and {"document_member", "operator"} <= passwords.keys()
        and passwords.keys() <= ACCOUNTS
    )
    require(all(isinstance(v, str) and 32 <= len(v) <= 128 for v in passwords.values()))
    clients, phases = {}, {"fault": [], "corrected": []}
    attempts = {"fault": 0, "corrected": 0}
    summary = {
        "profile": PROFILE,
        "completed": False,
        "native_zap_executed": False,
        "failure": "",
        "fault_disabled": False,
        "restoration_checks": {},
        "restoration_event_ids": {},
        "phase_requests": {},
    }
    try:
        for account in ("document_member", "operator"):
            client = client_factory()
            clients[account] = client
            client.sign_in(account, passwords[account])
        secrets = (
            *passwords.values(),
            *(value for client in clients.values() for value in client.cookies.values()),
        )
        state = control(True, 300)
        require(isinstance(state, dict) and state.get("enabled") is True)
        collect_phase(clients, "fault", phases["fault"], secrets, attempts)
        state = control(False, 300)
        require(isinstance(state, dict) and state.get("enabled") is False)
        collect_phase(clients, "corrected", phases["corrected"], secrets, attempts)
        validate_pair(phases)
        summary["completed"] = True
    except Exception:
        summary["failure"] = "source_capture_incomplete"
    finally:
        try:
            state = control(False, 300)
            summary["fault_disabled"] = isinstance(state, dict) and state.get("enabled") is False
        except Exception:
            summary["failure"] = "fault_reset_failed"
        for account, ordinal in (("document_member", 1), ("operator", 4)):
            try:
                client = clients[account]
                client.request("GET", DOC_PATH)
                restored = captured_row(
                    client.last_response,
                    account,
                    ordinal,
                    "corrected",
                    (*passwords.values(), *client.cookies.values()),
                )
                summary["restoration_checks"][account] = True
                summary["restoration_event_ids"][account] = restored["event_id"]
            except Exception:
                summary["restoration_checks"][account] = False
                summary["restoration_event_ids"][account] = None
    summary["completed"] = bool(
        summary["completed"]
        and summary["fault_disabled"]
        and all(summary["restoration_checks"].values())
    )
    summary["phase_requests"] = {key: len(rows) for key, rows in phases.items()}
    summary["phase_attempted_requests"] = attempts
    summary["captured_at"] = datetime.now(timezone.utc).isoformat()
    summary["response_digests"] = {
        key: [hashlib.sha256(row["body"].encode()).hexdigest() for row in rows]
        for key, rows in phases.items()
    }
    return summary, phases
