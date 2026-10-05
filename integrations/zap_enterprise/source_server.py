"""Finite header-only TLS source server for the reviewed native container profile."""

import ssl
import time
from wsgiref.simple_server import make_server

from integrations.enterprise.reference_native_server import PrivateHandler
from integrations.zap_enterprise.source_support import configure


def main():
    configure()
    import django
    from django.core.wsgi import get_wsgi_application

    django.setup()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/run/secrets/source_certificate", "/run/secrets/source_private_key")
    context.num_tickets = 0
    with make_server(
        "127.0.0.1", 18842, get_wsgi_application(), handler_class=PrivateHandler
    ) as server:
        server.timeout = 1
        server.socket = context.wrap_socket(server.socket, server_side=True)
        deadline = time.monotonic() + 360
        while time.monotonic() < deadline:
            server.handle_request()


if __name__ == "__main__":
    main()
