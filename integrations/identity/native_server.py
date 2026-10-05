"""Finite, loopback-only TLS console for genuine native Keycloak execution."""

import os
import ssl
import sys
import time
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIServer, make_server

from integrations.enterprise.reference_native_server import PrivateHandler

from .native_http import NativeIdentityError, check_abort


class Server(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    block_on_close = False

    def get_request(self):
        # socketserver drops TLS handshake failures silently; keep the class only.
        try:
            return super().get_request()
        except OSError as error:
            sys.stderr.write(f"console accept failed {type(error).__name__}\n")
            raise

    def handle_error(self, request, client_address):
        # Fixed label only: no peer data, traceback or certificate details.
        sys.stderr.write("console request error\n")


ROUTES = (
    "/login/",
    "/sso/start/",
    "/sso/callback/",
    "/sso/backchannel/",
    "/_lab/identity/",
)


class IdentityHandler(PrivateHandler):
    def log_request(self, code="-", size="-"):
        # Route labels come from a fixed allowlist; never raw paths or headers.
        path = (self.path or "").split("?", 1)[0]
        route = path if path in ROUTES else "other"
        sys.stderr.write(f"console {self.command} {route} {code}\n")


def main():
    check_abort()
    os.environ["DJANGO_SETTINGS_MODULE"] = "integrations.identity.native_settings"
    import django
    from django.core.wsgi import get_wsgi_application

    django.setup()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        "/run/secrets/console-certificate.pem", "/run/secrets/console-private-key.pem"
    )
    context.num_tickets = 0
    check_abort()
    with make_server(
        "127.0.0.1",
        18842,
        get_wsgi_application(),
        server_class=Server,
        handler_class=IdentityHandler,
    ) as server:
        server.timeout = 1
        server.socket = context.wrap_socket(server.socket, server_side=True)
        deadline = time.monotonic() + 1500
        while time.monotonic() < deadline:
            try:
                check_abort()
            except NativeIdentityError:
                break
            server.handle_request()


if __name__ == "__main__":
    main()
