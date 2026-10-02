"""Finite TLS WSGI lab server, never a public or production deployment server.

Only a reviewed container may run this entry point. No URL, bind address or
port arguments are accepted; each component has a fixed loopback port. Python's
wsgiref is a reference server, so the enterprise deployment needs another server.
"""

import os
import ssl
import time
from wsgiref.simple_server import WSGIRequestHandler, make_server

from integrations.enterprise.reference_native_support import configure


class PrivateHandler(WSGIRequestHandler):
    def get_environ(self):
        environ = super().get_environ()
        environ["HTTPS"] = "on"
        return environ

    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, format, *args):
        # Never log request headers, cookies, passwords or untrusted paths.
        pass


def main():
    configure()
    import django
    from django.core.wsgi import get_wsgi_application

    django.setup()
    component = os.environ["SB_SOURCE_COMPONENT"]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        "/run/secrets/" + component + "_certificate", "/run/secrets/" + component + "_private_key"
    )
    context.num_tickets = 0
    port = 18842 if component == "source" else 18841
    with make_server(
        "127.0.0.1", port, get_wsgi_application(), handler_class=PrivateHandler
    ) as server:
        server.timeout = 1
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.socket.settimeout(5)
        deadline = time.monotonic() + 240
        # Independent host/container watchdogs remain mandatory. This deadline
        # only bounds this process and does not prove container shutdown.
        while time.monotonic() < deadline:
            server.handle_request()


if __name__ == "__main__":
    main()
