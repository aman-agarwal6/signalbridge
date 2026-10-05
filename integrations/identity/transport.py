"""Single fixed loopback token POST with explicit CA, size and total-time bounds."""

import hashlib
import re
import ssl
from urllib.parse import parse_qs, urlsplit

from bridge.contract import parse_json
from integrations.enterprise.https_deadline import BoundedHTTPSConnection, lab_context

from .configuration import CALLBACK, CLIENT_ID, JWKS_ENDPOINT, TOKEN, _owned_file


class IdentityTransportError(RuntimeError):
    def __init__(self):
        super().__init__("The configured identity provider is unavailable.")


class IdentityHTTPSConnection(BoundedHTTPSConnection):
    ALLOWED_PORTS = (18844,)
    LOOPBACK_ADDRESS = "127.0.0.2"


def jwks_get(*, ca_file, ca_sha256):
    """One fixed public certs request; never accept a URL or token-derived path.

    Build explicit TLS trust from the exact bounded CA bytes that match the
    configuration identity, avoiding a second trust-file read during TLS setup.
    HTTP cache headers cannot extend the caller's fixed key-cache lifetime.
    """
    connection = None
    try:
        if not isinstance(ca_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", ca_sha256):
            raise ValueError()
        _, ca = _owned_file(str(ca_file), 16384)
        if hashlib.sha256(ca).hexdigest() != ca_sha256:
            raise ValueError()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        context.load_verify_locations(cadata=ca.decode("ascii"))
        connection = IdentityHTTPSConnection(18844, context=context, seconds=5)
        connection.start()
        connection.request(
            "GET",
            urlsplit(JWKS_ENDPOINT).path,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        connection.remaining()
        if (
            response.status != 200
            or response.headers.get_content_type() != "application/json"
            or response.getheader("Content-Encoding", "identity") != "identity"
        ):
            raise ValueError()
        raw = response.read(65537)
        connection.remaining()
        if len(raw) > 65536 or type(parse_json(raw)) is not dict:
            raise ValueError()
        return raw
    except Exception:
        raise IdentityTransportError() from None
    finally:
        if connection is not None:
            connection.finish()


def token_post(body, *, ca_file):
    """Called only by Authlib's adapter; no arbitrary URL, proxy or redirect."""
    connection = None
    try:
        if isinstance(body, str):
            body = body.encode("ascii")
        if not isinstance(body, bytes) or not 1 <= len(body) <= 8192:
            raise ValueError()
        data = parse_qs(body.decode("ascii"), strict_parsing=True, max_num_fields=6)
        expected = {"grant_type", "client_id", "redirect_uri", "code", "code_verifier"}
        if set(data) != expected or any(len(value) != 1 for value in data.values()):
            raise ValueError()
        if (
            data["grant_type"] != ["authorization_code"]
            or data["client_id"] != [CLIENT_ID]
            or data["redirect_uri"] != [CALLBACK]
            or not re.fullmatch(r"[A-Za-z0-9._~-]{1,2048}", data["code"][0])
            or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", data["code_verifier"][0])
        ):
            raise ValueError()
        connection = IdentityHTTPSConnection(18844, context=lab_context(ca_file), seconds=5)
        connection.start()
        connection.request(
            "POST",
            urlsplit(TOKEN).path,
            body=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        connection.remaining()
        if (
            response.status != 200
            or response.headers.get_content_type() != "application/json"
            or response.getheader("Content-Encoding", "identity") != "identity"
        ):
            raise ValueError()
        raw = response.read(65537)
        connection.remaining()
        if len(raw) > 65536 or type(parse_json(raw)) is not dict:
            raise ValueError()
        return raw
    except Exception:
        raise IdentityTransportError() from None
    finally:
        if connection is not None:
            connection.finish()
