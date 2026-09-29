"""Three-request synthetic HTTP fixture. Not SignalBridge application code."""

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

if __package__:
    from .contract import BODIES, CONTENT_TYPES, HOST, PATHS, PROFILE
else:
    sys.path.insert(0, "/pilot")  # Fixed read-only reviewed mount; works with Python -I.
    from contract import BODIES, CONTENT_TYPES, HOST, PATHS, PROFILE


class Fixture(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SignalBridgeSyntheticFixture"
    sys_version = ""

    def log_message(self, *_args):
        pass  # Never echo incoming paths, headers, peer identities or credentials.

    def do_GET(self):
        self.server.request_count += 1
        ordinal = self.server.request_count
        accepted = (
            ordinal <= len(PATHS)
            and self.path == PATHS[ordinal - 1]
            and self.headers.get_all("Host") == [HOST]
            and self.headers.get("X-ZAP-API-Key") is None
            and self.headers.get("Cookie") is None
            and self.headers.get("Authorization") is None
            and self.headers.get("Transfer-Encoding") is None
            and self.headers.get("Content-Length", "0") == "0"
        )
        body = BODIES[self.path] if accepted else b"Request outside synthetic pilot contract."
        self.send_response(200 if accepted else 400)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", CONTENT_TYPES[self.path] if accepted else "text/plain")
        self.send_header("X-SignalBridge-Fixture", PROFILE)
        self.send_header("X-SignalBridge-Request-Ordinal", str(ordinal))
        if accepted and self.path == "/health/":
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"
            )
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True
        print(json.dumps({"request_ordinal": ordinal, "accepted": accepted}), flush=True)


class BoundedServer(HTTPServer):
    request_count = 0

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address

    def handle_error(self, _request, _client_address):
        print('{"fixture_error":"request_failed"}', flush=True)


def main():
    if (
        len(sys.argv) != 1
        or sys.platform != "linux"
        or os.getuid() == 0
        or not Path("/.dockerenv").is_file()
        or Path(__file__).resolve() != Path("/pilot/fixture.py")
    ):
        print("The synthetic fixture requires its reviewed non-root pilot container.")
        return 2
    # All-interface binding is internal to the dedicated, unpublished lab network.
    with BoundedServer(("0.0.0.0", 8000), Fixture) as server:
        server.timeout = 1
        deadline = time.monotonic() + 360
        print('{"fixture":"ready","synthetic_only":true,"request_budget":3}', flush=True)
        while time.monotonic() < deadline:
            server.handle_request()
        print(json.dumps({"fixture": "finished", "requests": server.request_count}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
