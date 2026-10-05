"""Finite native Keycloak form client, not a browser or a simulated provider.

Only the reviewed two loopback TLS origins can receive requests. Credentials,
cookies, codes and token bodies stay in memory and are never execution receipts.
The caller must supply an explicit disposable lab CA. No network on import.
"""

import base64
import hashlib
import hmac
import os
import re
import struct
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from http.cookiejar import CookieJar, DefaultCookiePolicy
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import Request

from integrations.enterprise.https_deadline import BoundedHTTPSConnection, lab_context

CONSOLE = "https://127.0.0.1:18842"
PROVIDER = "https://127.0.0.2:18844"
CALLBACK = CONSOLE + "/sso/callback/"
MAX_BYTES = 262144
# Exact provider admin routes for the synthetic realm: one user's logout, and the
# realm/key/component reads and single key-provider creation used for rotation.
ADMIN = re.compile(
    r"/admin/realms/signalbridge(?:/keys|/components|/users/[a-f0-9-]{36}(?:/logout)?)?"
)
# Response headers retained for browser-protection checks; never cookies or bodies.
SECURITY_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "cross-origin-opener-policy",
    "permissions-policy",
    "cache-control",
    "strict-transport-security",
)


class NativeIdentityError(ValueError):
    def __init__(self):
        super().__init__("The bounded native identity step did not meet its predicate.")


def require(condition):
    if not condition:
        raise NativeIdentityError()


def check_abort():
    """The independent host guard permanently vetoes a late native runner."""
    if os.environ.get("SB_IDENTITY_NATIVE") != "1":
        return
    try:
        Path("/evidence/identity-abort.json").lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise NativeIdentityError() from None
    raise NativeIdentityError()


def destination(url):
    require(isinstance(url, str) and len(url) <= 8192 and url.isascii())
    require(not any(ord(c) < 33 or c == "\\" for c in url))
    parsed = urlsplit(url)
    require(parsed.scheme == "https" and not parsed.username and not parsed.fragment)
    origin = parsed.scheme + "://" + parsed.netloc
    require(origin in {CONSOLE, PROVIDER})
    if origin == CONSOLE:
        require(
            parsed.path
            in {
                "/",
                "/login/",
                "/logout/",
                "/sso/start/",
                "/sso/callback/",
                "/sso/backchannel/",
                "/_lab/identity/",
            }
            or re.fullmatch(r"/investigations/[a-f0-9-]{36}/(?:brief|work)/", parsed.path)
        )
        require(not parsed.query)
    else:
        require(
            parsed.path.startswith("/realms/signalbridge/")
            or parsed.path == "/realms/master/protocol/openid-connect/token"
            or ADMIN.fullmatch(parsed.path)
        )
        require(".." not in parsed.path and "%" not in parsed.path)
    return origin, parsed


class ProviderConnection(BoundedHTTPSConnection):
    LOOPBACK_ADDRESS = "127.0.0.2"
    ALLOWED_PORTS = (18844,)


@dataclass(repr=False)
class Reply:
    status: int
    url: str
    body: bytes
    location: str = ""
    content_type: str = ""
    headers: dict = field(default_factory=dict)


@dataclass(repr=False)
class Form:
    action: str
    fields: dict = field(default_factory=dict)
    names: set = field(default_factory=set)


class Forms(HTMLParser):
    def __init__(self, raw, base):
        super().__init__(convert_charrefs=True)
        self.forms, self.current, self.base = [], None, base
        require(len(raw) <= MAX_BYTES)
        self.feed(raw.decode("utf-8"))
        require(self.current is None and len(self.forms) <= 8)

    def handle_starttag(self, tag, attributes):
        values = dict(attributes)
        require(len(values) == len(attributes))
        if tag == "form":
            require(self.current is None)
            if values.get("method", "get").lower() != "post":
                self.current = False
                return
            action = urljoin(self.base, values.get("action", ""))
            destination(action)
            self.current = Form(action)
        elif tag == "input" and isinstance(self.current, Form) and "name" in values:
            name = values["name"]
            require(name not in self.current.names and len(name) <= 100)
            self.current.names.add(name)
            # HTML type values are case-insensitive; Keycloak's form_post
            # response writes TYPE="HIDDEN".
            if (values.get("type") or "text").lower() == "hidden":
                value = values.get("value", "")
                require(len(value) <= 4096)
                self.current.fields[name] = value

    def handle_endtag(self, tag):
        if tag == "form":
            if isinstance(self.current, Form):
                self.forms.append(self.current)
            self.current = None

    def one(self, field):
        found = [form for form in self.forms if field in form.names]
        require(len(found) == 1)
        return found[0]


class Budget:
    def __init__(self, seconds=600, requests=160):
        require(type(seconds) is int and 1 <= seconds <= 1200)
        require(type(requests) is int and 1 <= requests <= 200)
        self.deadline, self.maximum, self.used = time.monotonic() + seconds, requests, 0

    def consume(self):
        check_abort()
        require(time.monotonic() < self.deadline and self.used < self.maximum)
        self.used += 1
        return min(self.deadline, time.monotonic() + 5)


class NativeClient:
    def __init__(self, ca_file, budget):
        self.context, self.budget = lab_context(ca_file), budget
        self.jar = CookieJar(
            policy=DefaultCookiePolicy(strict_ns_domain=DefaultCookiePolicy.DomainStrict)
        )

    def request(self, method, url, fields=None, *, json_body=None, bearer=None, initiator=None):
        origin, parsed = destination(url)
        require(method in {"GET", "POST", "PUT"})
        require(not (fields is not None and json_body is not None))
        body = urlencode(fields).encode("ascii") if fields is not None else json_body
        require(body is None or isinstance(body, bytes) and len(body) <= 16384)
        require(method != "GET" or body is None)
        request = Request(url, data=body, method=method)
        request.add_header("Accept-Encoding", "identity")
        request.add_header("Connection", "close")
        if body is not None:
            request.add_header(
                "Content-Type",
                "application/json"
                if json_body is not None
                else "application/x-www-form-urlencoded",
            )
            initiating_origin = origin if initiator is None else initiator
            require(initiating_origin in {CONSOLE, PROVIDER})
            request.add_header("Origin", initiating_origin)
            request.add_header("Referer", initiating_origin + "/")
        if bearer is not None:
            require(origin == PROVIDER and ADMIN.fullmatch(parsed.path))
            require(isinstance(bearer, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,16384}", bearer))
            request.add_header("Authorization", "Bearer " + bearer)
        self.jar.add_cookie_header(request)
        connection_class = ProviderConnection if origin == PROVIDER else BoundedHTTPSConnection
        connection = connection_class(
            parsed.port, context=self.context, seconds=5, deadline=self.budget.consume()
        )
        try:
            connection.start()
            check_abort()
            connection.request(
                method,
                parsed.path + ("?" + parsed.query if parsed.query else ""),
                body=body,
                headers=dict(request.header_items()),
            )
            response = connection.getresponse()
            require(response.getheader("Content-Encoding", "identity") == "identity")
            raw = response.read(MAX_BYTES + 1)
            connection.remaining()
            require(len(raw) <= MAX_BYTES)
            for header in response.headers.get_all("Set-Cookie", []):
                require(len(header) <= 8192)
            self.jar.extract_cookies(response, request)
            require(len(self.jar) <= 32 and all(cookie.secure for cookie in self.jar))
            security = {}
            for name in SECURITY_HEADERS if origin == CONSOLE else ():
                values = response.headers.get_all(name, [])
                require(len(values) <= 1 and all(len(value) <= 1024 for value in values))
                if values:
                    security[name] = values[0]
            return Reply(
                response.status,
                url,
                raw,
                response.getheader("Location", ""),
                response.headers.get_content_type(),
                security,
            )
        finally:
            connection.finish()

    def follow(self, reply):
        for _ in range(8):
            if reply.status not in {301, 302, 303}:
                return reply
            target = urljoin(reply.url, reply.location)
            destination(target)
            reply = self.request("GET", target)
        raise NativeIdentityError()

    def begin(self):
        reply = self.request("GET", CONSOLE + "/login/")
        require(reply.status == 200)
        reply = self.request(
            "POST", CONSOLE + "/sso/start/", {"csrfmiddlewaretoken": self.csrf_token()}
        )
        require(
            reply.status == 302
            and reply.location.startswith(
                PROVIDER + "/realms/signalbridge/protocol/openid-connect/auth?"
            )
        )
        return self.follow(reply)

    def csrf_token(self):
        tokens = [
            cookie.value
            for cookie in self.jar
            if cookie.name == "sb_enterprise_csrf"
            and cookie.domain == "127.0.0.1"
            and not cookie.domain_specified
            and cookie.path == "/"
            and cookie.secure
        ]
        require(len(tokens) == 1 and re.fullmatch(r"[A-Za-z0-9]{32}", tokens[0]))
        return tokens[0]

    def case_work(self, case_id, fields, *, csrf=True):
        require(isinstance(fields, dict) and "csrfmiddlewaretoken" not in fields)
        values = {**fields, "csrfmiddlewaretoken": self.csrf_token()} if csrf else fields
        return self.request("POST", CONSOLE + "/investigations/" + case_id + "/work/", values)

    def password(self, reply, account):
        require(reply.status == 200)
        form = Forms(reply.body, reply.url).one("username")
        require(
            form.action.startswith(PROVIDER + "/realms/signalbridge/login-actions/authenticate?")
        )
        fields = {**form.fields, "username": account["username"], "password": account["password"]}
        return self.follow(self.request("POST", form.action, fields))

    def otp(self, reply, value):
        require(reply.status == 200 and re.fullmatch(r"[0-9]{6}", value))
        form = Forms(reply.body, reply.url).one("otp")
        require(
            form.action.startswith(PROVIDER + "/realms/signalbridge/login-actions/authenticate?")
        )
        return self.follow(self.request("POST", form.action, {**form.fields, "otp": value}))

    def callback_fields(self, reply):
        require(reply.status == 200)
        form = Forms(reply.body, reply.url).one("code")
        require(
            form.action == CALLBACK
            and set(form.fields) <= {"code", "state", "session_state", "iss"}
        )
        require({"code", "state"}.issubset(form.fields))
        return form.fields

    def finish(self, reply):
        return self.request("POST", CALLBACK, self.callback_fields(reply), initiator=PROVIDER)


def totp(secret, at=None):
    """RFC6238 SHA256, matching the imported Keycloak credential profile."""
    require(isinstance(secret, str) and re.fullmatch(r"[A-Z2-7]{52}", secret))
    instant = time.time() if at is None else at
    require(type(instant) in {int, float} and instant >= 0)
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(instant) // 30), hashlib.sha256).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"
