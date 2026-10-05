"""One request to either fixed lab loopback endpoint, with one total deadline.

The timer starts before TCP/TLS, keeps the active socket through HTTP detach,
and cannot turn an expired response into successful evidence. Imports do not
open sockets. This is a lab client, not a configurable outbound HTTP facility.
"""

import http.client
import math
import socket
import ssl
import threading
import time


def lab_context(ca_file):
    # Construct explicitly so SSLKEYLOGFILE cannot enable secret-bearing logs.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.load_verify_locations(cafile=str(ca_file))
    return context


class BoundedHTTPSConnection(http.client.HTTPSConnection):
    ALLOWED_PORTS = (18841, 18842)
    LOOPBACK_ADDRESS = "127.0.0.1"

    def __init__(self, port, *, context, seconds, deadline=None):
        if (
            type(port) is not int
            or self.LOOPBACK_ADDRESS not in ("127.0.0.1", "127.0.0.2")
            or port not in self.ALLOWED_PORTS
            or type(seconds) not in (int, float)
            or not math.isfinite(seconds)
            or not 0 < seconds <= 5
            or (
                deadline is not None
                and (type(deadline) not in (int, float) or not math.isfinite(deadline))
            )
            or not isinstance(context, ssl.SSLContext)
            or not context.check_hostname
            or context.verify_mode != ssl.CERT_REQUIRED
            or context.minimum_version < ssl.TLSVersion.TLSv1_2
            or context.keylog_filename is not None
        ):
            raise ValueError("Unreviewed lab connection or TLS protections.")
        super().__init__(self.LOOPBACK_ADDRESS, port, timeout=seconds, context=context)
        self.seconds = seconds
        self.deadline = time.monotonic() + seconds
        if deadline is not None:
            self.deadline = min(self.deadline, deadline)
        self._timer = None
        self._channel = None
        self._connected_once = False
        self._active = False
        self._expired = False
        self._started = False

    def start(self):
        if self._started:
            raise ValueError("A lab connection cannot reuse a request deadline.")
        self._started = True
        self._active = True
        self._timer = threading.Timer(self.remaining(), self._interrupt)
        self._timer.daemon = True
        self._timer.start()

    def remaining(self):
        if not self._active or self.deadline is None:
            raise ValueError("Lab connection deadline must be armed first.")
        value = self.deadline - time.monotonic()
        if self._expired or value <= 0:
            raise TimeoutError("Lab request total deadline exceeded.")
        return value

    def _interrupt(self):
        self._expired = True
        channel = self._channel
        if channel is not None:
            try:
                channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def connect(self):
        self.remaining()
        if self._connected_once or self._tunnel_host is not None:
            raise ValueError("Lab connection cannot reconnect or use a tunnel.")
        self._connected_once = True
        # Numeric IPv4 only: no DNS, proxy, host argument or address fallback.
        self.sock = self._channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.remaining())
        self.sock.connect((self.host, self.port))
        self.remaining()
        # Assign the TLS socket before handshake, so the timer can interrupt it.
        self.sock = self._channel = self._context.wrap_socket(
            self.sock, server_hostname=self.host, do_handshake_on_connect=False
        )
        self.sock.settimeout(self.remaining())
        self.sock.do_handshake()
        self.sock.settimeout(self.remaining())

    def close(self):
        # http.client closes/detaches connections with a Connection: close or
        # HTTP/1.0 response before its body is consumed. Keep the socket live for
        # the deadline guard until finish(), including a trickled response body.
        if self._active and self.sock is self._channel:
            self.sock = None
        super().close()

    def finish(self):
        self._active = False
        if self._timer is not None:
            self._timer.cancel()
        channel, self._channel = self._channel, None
        try:
            super().close()
        finally:
            if channel is not None:
                channel.close()
