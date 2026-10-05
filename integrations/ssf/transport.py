"""HTTPS client for the AccessOps lab transmitter: loopback address, fixed TLS name, pinned CA.

The receiver connects to 127.0.0.1:8443 and verifies the certificate for accessops.test
against the lab CA file only (no system trust store, no hosts-file change). Requests have a
deadline, responses a size bound, redirects are not followed and the bearer token never
appears in an error message.
"""

import http.client
import json
import socket
import ssl

MAX_RESPONSE = 1024 * 1024


class TransmitterError(RuntimeError):
    """A failed exchange; the message never contains credentials or response bodies."""


class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, server_name, port, address, context, timeout):
        super().__init__(server_name, port, context=context, timeout=timeout)
        self._address = address
        self._ssl_context = context
        self.peer_certificate = None

    def connect(self):
        raw = socket.create_connection(self._address, self.timeout)
        self.sock = self._ssl_context.wrap_socket(raw, server_hostname=self.host)
        self.peer_certificate = self.sock.getpeercert(binary_form=True)


class Transmitter:
    def __init__(
        self,
        cafile,
        *,
        server_name="accessops.test",
        port=8443,
        address=("127.0.0.1", 8443),
        timeout=10,
    ):
        context = ssl.create_default_context(cafile=str(cafile))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context = context
        self.server_name = server_name
        self.port = port
        self.address = address
        self.timeout = timeout
        self.peer_certificate = None

    def _exchange(self, method, path, body=None, token=None):
        headers = {"Accept": "application/json"}
        payload = None
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        connection = _PinnedConnection(
            self.server_name, self.port, self.address, self.context, self.timeout
        )
        try:
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            self.peer_certificate = connection.peer_certificate
            raw = response.read(MAX_RESPONSE + 1)
            status = response.status
        except (OSError, http.client.HTTPException) as error:
            raise TransmitterError(f"{method} {path} failed: {type(error).__name__}") from None
        finally:
            connection.close()
        if len(raw) > MAX_RESPONSE:
            raise TransmitterError(f"{method} {path} response exceeds {MAX_RESPONSE} bytes")
        if status != 200:
            raise TransmitterError(f"{method} {path} returned HTTP {status}")
        try:
            value = json.loads(raw)
        except ValueError:
            raise TransmitterError(f"{method} {path} did not return JSON") from None
        if not isinstance(value, dict):
            raise TransmitterError(f"{method} {path} did not return a JSON object")
        return value

    def configuration(self):
        return self._exchange("GET", "/.well-known/ssf-configuration")

    def jwks(self):
        return self._exchange("GET", "/api/v1/ssf/jwks")

    def poll(self, token, *, max_events, ack=(), set_errs=None):
        body = {
            "maxEvents": max_events,
            "returnImmediately": True,
            "ack": list(ack),
            "setErrs": set_errs or {},
        }
        reply = self._exchange("POST", "/api/v1/ssf/poll", body, token)
        sets = reply.get("sets", {})
        if not isinstance(sets, dict) or not isinstance(reply.get("moreAvailable", False), bool):
            raise TransmitterError("The poll reply is not an RFC 8936 response")
        return sets, reply.get("moreAvailable", False)
