"""Fixed native reference-app requests; imports perform no network operations.

The transport is for a reviewed, isolated lab only. It cannot accept a URL,
follow redirects, inherit proxies, disable certificate checks or send telemetry
to an arbitrary target. Receipts contain predicates, never cookie values.
"""

import json
import re
import time
import uuid
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode

from .https_deadline import BoundedHTTPSConnection, lab_context

ORIGIN = "https://127.0.0.1:18842"
ACCOUNTS = frozenset(("operator", "document_member", "expense_member", "outsider"))
RESOURCES = {
    "documents": uuid.uuid5(uuid.NAMESPACE_URL, "signalbridge-reference/private-document"),
    "expenses": uuid.uuid5(uuid.NAMESPACE_URL, "signalbridge-reference/private-expense"),
}
CONTENT = {
    "documents": "SYNTHETIC-ONLY: Board briefing reference document 2026-10.",
    "expenses": "SYNTHETIC-ONLY: Expense record EXP-LAB-001, amount 42.00.",
}
MAX_REQUESTS = 80
MAX_RESPONSE_BYTES = 8192
MAX_REQUEST_BYTES = 1024
TOTAL_SECONDS = 180
REQUEST_SECONDS = 5


class ProfileError(ValueError):
    pass


def allowed_path(method, path):
    if method not in ("GET", "POST") or not isinstance(path, str):
        raise ProfileError("Request method or path escaped the reference profile.")
    basic = {"GET": {"/login/", "/identity/"}, "POST": {"/login/", "/logout/"}}
    paths = basic[method] | {
        f"/apps/{app}/resources/{identifier}/" + ("permission/" if method == "POST" else "")
        for app, identifier in RESOURCES.items()
    }
    if path not in paths:
        raise ProfileError("Request method or path escaped the reference profile.")
    return path


def content_observation(status, value, app):
    """Only an exact known private record establishes this narrow read result."""
    if app not in RESOURCES or type(status) is not int:
        raise ProfileError("Invalid observation scope or status.")
    exact = isinstance(value, dict) and value == {
        "app": app,
        "record_id": str(RESOURCES[app]),
        "synthetic_content": CONTENT[app],
    }
    if status == 200 and exact:
        outcome = "known_content_returned"
    elif status == 403 and value == {"error": "Access denied."}:
        outcome = "explicit_denial"
    else:
        outcome = "inconclusive"
    return {"http_status": status, "observation": outcome, "known_content": status == 200 and exact}


class RequestBudget:
    """One budget shared by every lab identity; failed requests consume it too."""

    def __init__(self):
        self.deadline, self.used = time.monotonic() + TOTAL_SECONDS, 0

    def consume(self):
        now = time.monotonic()
        remaining = self.deadline - now
        if self.used >= MAX_REQUESTS or remaining <= 0:
            raise ProfileError("Native reference request or duration ceiling reached.")
        self.used += 1
        return min(now + REQUEST_SECONDS, self.deadline)


class ClosedHTTPSClient:
    def __init__(self, ca_file, budget):
        ca_file = Path(ca_file)
        if not ca_file.is_file() or ca_file.is_symlink() or ca_file.stat().st_size > 16384:
            raise ProfileError("An explicit bounded lab CA file is required.")
        self.context = lab_context(ca_file)
        self.budget, self.cookies = budget, {}
        self.last_event_id = None
        self.last_response = None

    def request(self, method, path, body=b"", content_type="application/json", csrf=True):
        self.last_event_id = None
        self.last_response = None
        allowed_path(method, path)
        if not isinstance(body, bytes) or len(body) > MAX_REQUEST_BYTES:
            raise ProfileError("Reference request body exceeds the profile.")
        if method == "GET" and body:
            raise ProfileError("Reference reads cannot carry a body.")
        if content_type not in ("application/json", "application/x-www-form-urlencoded"):
            raise ProfileError("Reference content type escaped the profile.")
        deadline = self.budget.consume()
        request_started_at = datetime.now(timezone.utc).isoformat()
        headers = {"Content-Type": content_type, "Origin": ORIGIN, "Referer": ORIGIN + "/login/"}
        if self.cookies:
            headers["Cookie"] = "; ".join(
                name + "=" + value for name, value in self.cookies.items()
            )
        if csrf and "csrftoken" in self.cookies:
            headers["X-CSRFToken"] = self.cookies["csrftoken"]
        connection = BoundedHTTPSConnection(
            18842, seconds=REQUEST_SECONDS, deadline=deadline, context=self.context
        )
        try:
            connection.start()
            connection.connect()
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            connection.remaining()
            if len(raw) > MAX_RESPONSE_BYTES or 300 <= response.status < 400:
                raise ProfileError("Oversized or redirected reference response rejected.")
            identifiers = response.headers.get_all("X-SB-Lab-Event-ID", [])
            if identifiers:
                if len(identifiers) != 1 or not path.startswith("/apps/"):
                    raise ProfileError("Unexpected source observation binding.")
                try:
                    if str(uuid.UUID(identifiers[0])) != identifiers[0]:
                        raise ValueError()
                except (ValueError, TypeError, AttributeError):
                    raise ProfileError("Invalid source observation binding.") from None
                self.last_event_id = identifiers[0]
            for header in response.headers.get_all("Set-Cookie", []):
                parsed = SimpleCookie()
                parsed.load(header)
                for name in ("sessionid", "csrftoken"):
                    if name in parsed:
                        cookie = parsed[name]
                        if not cookie["secure"] or (name == "sessionid" and not cookie["httponly"]):
                            raise ProfileError(
                                "Native reference session cookie protection is missing."
                            )
                        if cookie.value:
                            if not re.fullmatch(r"[A-Za-z0-9]{32,64}", cookie.value):
                                raise ProfileError("Unexpected reference cookie format.")
                            self.cookies[name] = cookie.value
                        else:
                            self.cookies.pop(name, None)
            # Optional authenticated-header profile input. Password POSTs and
            # login pages are never captured, and cookie/authorization values are
            # absent. This is ephemeral response material, not an execution receipt.
            if method == "GET" and path != "/login/":
                if type(response.version) is not int or response.version not in (10, 11):
                    raise ProfileError(
                        "The captured source response has an unsupported HTTP version."
                    )
                retained = {
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
                self.last_response = {
                    "method": method,
                    "path": path,
                    "status": response.status,
                    "http_version": "HTTP/1.0" if response.version == 10 else "HTTP/1.1",
                    "headers": [
                        (name, value)
                        for name, value in response.headers.items()
                        if name.lower() in retained
                    ],
                    "body": raw,
                    "started_at": request_started_at,
                }
            if path == "/login/" and method == "GET":
                return response.status, {"csrf_cookie_received": "csrftoken" in self.cookies}
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeError):
                value = None
            return response.status, value
        finally:
            connection.finish()

    def sign_in(self, account, password):
        if (
            account not in ACCOUNTS
            or not isinstance(password, str)
            or not 32 <= len(password) <= 128
        ):
            raise ProfileError("Only a dedicated synthetic account credential is allowed.")
        status, value = self.request("GET", "/login/")
        if status != 200 or value != {"csrf_cookie_received": True}:
            raise ProfileError("Native reference login did not establish CSRF state.")
        status, value = self.request(
            "POST",
            "/login/",
            urlencode({"username": account, "password": password}).encode("ascii"),
            "application/x-www-form-urlencoded",
        )
        if status != 200 or value != {"signed_in": True} or "sessionid" not in self.cookies:
            raise ProfileError("Native reference authentication failed.")
        status, value = self.request("GET", "/identity/")
        if status != 200 or value != {"account": account, "authenticated": True}:
            raise ProfileError("Native authenticated identity did not match the intended account.")

    def read(self, app):
        if app not in RESOURCES:
            raise ProfileError("Reference read escaped the two application scopes.")
        status, value = self.request("GET", f"/apps/{app}/resources/{RESOURCES[app]}/")
        return content_observation(status, value, app)

    def permission(self, app, subject, kind, granted):
        if (
            app not in RESOURCES
            or subject not in ACCOUNTS
            or kind not in ("group", "direct")
            or type(granted) is not bool
        ):
            raise ProfileError("Permission change escaped the synthetic reference inventory.")
        return self.request(
            "POST",
            f"/apps/{app}/resources/{RESOURCES[app]}/permission/",
            json.dumps({"subject": subject, "kind": kind, "granted": granted}).encode("ascii"),
        )


def exercise(factory, passwords, set_fault):
    """Declare controls before execution; retain each predicate as it is observed.

    The caller must supply the native factory and fixed operator mechanism in
    the reviewed container profile. Calling this with test doubles is offline
    regression evidence only. Restoration runs even after a failed assertion.
    """
    if set(passwords) != ACCOUNTS:
        raise ProfileError("All four dedicated reference identities are required.")
    clients, trace = {}, []
    restored = False

    def record(name, facts, expected, event_id=None):
        trace.append({"step": name, **facts, "event_id": event_id, "passed": facts == expected})
        if facts != expected:
            raise ProfileError("Native reference control failed: " + name)

    def read(client, app, step, allowed):
        facts = client.read(app)
        if client.last_event_id is None:
            raise ProfileError("The source read has no exact observation binding.")
        record(
            step,
            facts,
            {
                "http_status": 200 if allowed else 403,
                "observation": "known_content_returned" if allowed else "explicit_denial",
                "known_content": allowed,
            },
            client.last_event_id,
        )

    try:
        for account in sorted(ACCOUNTS):
            client = factory()
            clients[account] = client
            client.sign_in(account, passwords[account])
            trace.append({"step": "authenticated_" + account, "passed": True})
        owner, outsider = clients["operator"], clients["outsider"]
        for app, account, other_account in (
            ("documents", "document_member", "expense_member"),
            ("expenses", "expense_member", "document_member"),
        ):
            member = clients[account]
            session = member.cookies["sessionid"]
            read(member, app, app + "_allowed", True)
            read(outsider, app, app + "_outsider_denied", False)
            read(clients[other_account], app, app + "_cross_app_denied", False)
            status, value = owner.permission(app, account, "group", False)
            if owner.last_event_id is None:
                raise ProfileError("Effective removal has no source assertion binding.")
            record(
                app + "_permission_removed",
                {"http_status": status, "effective_access": (value or {}).get("effective_access")},
                {"http_status": 200, "effective_access": False},
                owner.last_event_id,
            )
            status, value = member.request("GET", "/identity/")
            record(
                app + "_session_still_valid",
                {
                    "http_status": status,
                    "identity_matched": value == {"account": account, "authenticated": True},
                    "session_unchanged": member.cookies.get("sessionid") == session,
                },
                {"http_status": 200, "identity_matched": True, "session_unchanged": True},
            )
            read(member, app, app + "_removed_member_denied", False)
            read(owner, app, app + "_owner_control", True)
            if app == "documents":
                set_fault(True, 120)
                try:
                    read(member, app, "bounded_regression_known_content", True)
                finally:
                    set_fault(False, 120)
                read(member, app, "regression_reset_denied", False)
                read(owner, app, "documents_reset_owner_control", True)
            status, value = owner.permission(app, account, "group", True)
            if owner.last_event_id is None:
                raise ProfileError("Effective restoration has no source assertion binding.")
            record(
                app + "_permission_restored",
                {"http_status": status, "effective_access": (value or {}).get("effective_access")},
                {"http_status": 200, "effective_access": True},
                owner.last_event_id,
            )
            read(member, app, app + "_restored_known_content", True)
            # Removing one grant must not claim effective removal when a direct
            # grant or ownership still permits the real authorization path.
            owner.permission(app, account, "direct", True)
            status, value = owner.permission(app, account, "group", False)
            if owner.last_event_id is not None:
                raise ProfileError("Alternate access incorrectly emitted an effective change.")
            record(
                app + "_alternate_grant_preserved",
                {"http_status": status, "effective_access": (value or {}).get("effective_access")},
                {"http_status": 200, "effective_access": True},
            )
            read(member, app, app + "_alternate_grant_content", True)
            owner.permission(app, account, "group", True)
            owner.permission(app, account, "direct", False)
        restored = True
    except Exception as error:
        trace.append(
            {"step": "incomplete_execution", "passed": False, "error_class": type(error).__name__}
        )
    finally:
        try:
            set_fault(False, 120)
            owner = clients.get("operator")
            if owner is not None:
                for app, account in (
                    ("documents", "document_member"),
                    ("expenses", "expense_member"),
                ):
                    status, value = owner.permission(app, account, "group", True)
                    if (
                        status != 200
                        or not isinstance(value, dict)
                        or value.get("effective_access") is not True
                    ):
                        raise ProfileError("Native reference grant restoration failed.")
                    status, _value = owner.permission(app, account, "direct", False)
                    if status != 200:
                        raise ProfileError("Native reference direct-grant reset failed.")
                for app, account in (
                    ("documents", "document_member"),
                    ("expenses", "expense_member"),
                ):
                    read(clients[account], app, app + "_final_restore_known_content", True)
                restored = True
            else:
                restored = False
        except Exception as error:
            restored = False
            trace.append(
                {
                    "step": "restoration_incomplete",
                    "passed": False,
                    "error_class": type(error).__name__,
                }
            )
    return {
        "completed": bool(restored and trace and all(row["passed"] for row in trace)),
        "restoration_verified": restored,
        "steps": trace,
    }
