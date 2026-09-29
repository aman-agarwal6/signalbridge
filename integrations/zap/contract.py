"""Fixed synthetic pilot inputs shared by the fixture and its no-follow driver."""

import hashlib

PROFILE = "signalbridge-disposable-web-v1"
ORIGIN = "http://signalbridge-zap-target:8000"
HOST = "signalbridge-zap-target:8000"
PATHS = ("/", "/login/", "/health/")
BODIES = {
    "/": b"<!doctype html><html><title>Synthetic ZAP pilot</title><p>Synthetic fixture only.</p></html>",
    "/login/": b"<!doctype html><html><title>Synthetic login</title><p>No login form or accounts.</p></html>",
    "/health/": b'{"kind":"synthetic-zap-fixture","status":"ok"}',
}
BODY_HASHES = {path: hashlib.sha256(body).hexdigest() for path, body in BODIES.items()}
CONTENT_TYPES = {
    "/": "text/html; charset=utf-8",
    "/login/": "text/html; charset=utf-8",
    "/health/": "application/json",
}
BODY_LIMIT = 256 * 1024
REPORT_LIMIT = 2 * 1024 * 1024
LOG_LIMIT = 1024 * 1024
REQUEST_TIMEOUT = 5
STARTUP_SECONDS = 120
PASSIVE_SECONDS = 60
TOTAL_SECONDS = 240
EXPECTED_RULE = "10021"
