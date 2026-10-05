"""Strict Keycloak lab token adapter using established JOSE/OIDC libraries.

No network, key discovery, login route or account creation. The Django client
must supply its bounded trusted-provider JWKS and the consumed login nonce.
State, PKCE, callback binding and transactional logout replay are separate gates.
Dependency installation and signed-token execution remain independently recorded.
"""

import base64
import json
import re
import secrets
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from bridge.contract import parse_json
from bridge.federation import VerifiedIdentity, validate_link

LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
MAX_TOKEN_BYTES = 16384


class TokenRejected(ValueError):
    def __init__(self, check=None):
        super().__init__("Identity token validation failed.")
        # Fixed source coordinate of the failed predicate; never token content.
        self.check = check


def _failed_check(error):
    frames = [
        frame
        for frame in traceback.extract_tb(error.__traceback__)
        if Path(frame.filename).name == "protocol.py" and frame.name != "require"
    ]
    return "protocol.py:" + str(frames[-1].lineno) if frames else None


@dataclass(frozen=True)
class VerifiedLogout:
    """Signature-verified adapter result; a replay gate is still required."""

    issuer: str
    subject: str
    provider_session: str
    token_id: str
    issued_at: datetime
    expires_at: datetime


def require(condition):
    if not condition:
        raise TokenRejected()


def identifier(value):
    require(isinstance(value, str) and 1 <= len(value) <= 255)
    require(all(32 < ord(c) < 127 for c in value))
    return value


def _segment(value):
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    require(base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return parse_json(raw)


def _compact(value):
    require(isinstance(value, str) and 1 <= len(value) <= MAX_TOKEN_BYTES)
    require(re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value))
    head, body, _signature = value.split(".")
    header, claims = _segment(head), _segment(body)
    require(type(header) is dict and set(header) == {"alg", "kid", "typ"})
    require(header["alg"] == "RS256" and header["typ"] in {"JWT", "logout+jwt"})
    identifier(header["kid"])
    require(type(claims) is dict)
    return header, claims


def _public_keys(value):
    require(type(value) is dict and set(value) == {"keys"})
    require(len(json.dumps(value, separators=(",", ":"))) <= 65536)
    require(type(value["keys"]) is list and 1 <= len(value["keys"]) <= 8)
    selected, seen = [], set()
    for row in value["keys"]:
        require(type(row) is dict)
        require(not set(row).intersection({"d", "p", "q", "dp", "dq", "qi", "oth", "k"}))
        # Keycloak can publish encryption keys alongside signature keys.
        if row.get("use") != "sig" or row.get("alg") != "RS256":
            continue
        require(row.get("kty") == "RSA" and row.get("e") == "AQAB")
        kid = identifier(row.get("kid"))
        require(kid not in seen)
        seen.add(kid)
        modulus = row.get("n")
        require(isinstance(modulus, str) and re.fullmatch(r"[A-Za-z0-9_-]{342,683}", modulus))
        decoded = base64.urlsafe_b64decode(modulus + "=" * (-len(modulus) % 4))
        require(2048 <= int.from_bytes(decoded, "big").bit_length() <= 4096)
        require(row.get("key_ops", ["verify"]) == ["verify"])
        selected.append({k: row[k] for k in ("kty", "kid", "use", "alg", "n", "e")})
    require(bool(selected))
    return {"keys": selected}


def _verified(value, jwks, issuer, audience, now):
    # Parsing before verification only rejects malformed/bounded input. No claim
    # can become a trusted identity until the library verifies the signature.
    header, untrusted = _compact(value)
    validate_link(issuer, identifier(audience))
    require(type(now) is int and now > 0)
    from joserfc import jwt
    from joserfc.jwk import KeySet

    key_set = KeySet.import_key_set(_public_keys(jwks))
    token = jwt.decode(value, key_set, algorithms=["RS256"])
    require(token.header == header and token.claims == untrusted)
    claims = token.claims
    require(claims.get("iss") == issuer)
    # This dedicated RP accepts a single exact audience. No cross-client token
    # or provider role claim can be used to authorize a local account.
    require(claims.get("aud") in (audience, [audience]))
    require("azp" not in claims or claims["azp"] == audience)
    for name in ("iat", "exp"):
        require(type(claims.get(name)) is int)
    if "nbf" in claims:
        require(type(claims["nbf"]) is int and claims["nbf"] <= now + 5)
    require(now - 300 <= claims["iat"] <= now + 5)
    require(now < claims["exp"] <= claims["iat"] + 900)
    require(claims["exp"] > claims["iat"])
    for name in ("sub", "sid"):
        identifier(claims.get(name))
    return header, claims


def verify_login_token(value, *, jwks, issuer, audience, nonce, access_token, now=None):
    """Return only the identity needed for explicit local account mapping.

    The lab requires Keycloak ACR 2 plus signed pwd/otp AMR and recent auth_time.
    This policy requires the matching Keycloak MFA flow and claim mappers; it
    cannot establish that MFA happened until native provider tests are retained.
    """
    try:
        current = int(datetime.now(timezone.utc).timestamp()) if now is None else now
        header, claims = _verified(value, jwks, issuer, audience, current)
        require(header["typ"] == "JWT" and "events" not in claims)
        require(isinstance(nonce, str) and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", nonce))
        require(isinstance(claims.get("nonce"), str))
        require(secrets.compare_digest(claims["nonce"], nonce))
        require(claims.get("nonce_supported") is not False)
        require(claims.get("acr") == "2")
        amr = claims.get("amr")
        require(type(amr) is list and 2 <= len(amr) <= 8 and all(type(v) is str for v in amr))
        require(len(set(amr)) == len(amr) and {"pwd", "otp"}.issubset(amr))
        require(type(claims.get("auth_time")) is int)
        require(current - 300 <= claims["auth_time"] <= min(current + 5, claims["iat"] + 5))
        require(isinstance(access_token, str) and 1 <= len(access_token) <= MAX_TOKEN_BYTES)
        from authlib.oidc.core import CodeIDToken

        oidc = CodeIDToken(
            claims,
            header,
            {"iss": {"essential": True, "value": issuer}},
            {"nonce": nonce, "client_id": audience, "access_token": access_token},
        )
        oidc.validate(now=current, leeway=5)
        return VerifiedIdentity(
            issuer=issuer,
            subject=claims["sub"],
            provider_session=claims["sid"],
            issued_at=datetime.fromtimestamp(claims["iat"], timezone.utc),
            authenticated_at=datetime.fromtimestamp(claims["auth_time"], timezone.utc),
            expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc),
        )
    except Exception as error:
        # Provider errors must never carry JWTs, private claims or key material.
        raise TokenRejected(_failed_check(error)) from None


def verify_logout_token(value, *, jwks, issuer, audience, now=None):
    """Session-specific Keycloak logout; replay consumption is a caller obligation."""
    try:
        current = int(datetime.now(timezone.utc).timestamp()) if now is None else now
        _header, claims = _verified(value, jwks, issuer, audience, current)
        require("nonce" not in claims)
        events = claims.get("events")
        require(type(events) is dict and events.get(LOGOUT_EVENT) == {})
        # Keycloak adds this boolean to events when the client revokes offline
        # tokens on logout. No other event or value is accepted.
        require(set(events) <= {LOGOUT_EVENT, "revoke_offline_access"})
        require(type(events.get("revoke_offline_access", False)) is bool)
        require(claims["exp"] <= claims["iat"] + 300)
        identifier(claims.get("jti"))
        return VerifiedLogout(
            issuer=issuer,
            subject=claims["sub"],
            provider_session=claims["sid"],
            token_id=claims["jti"],
            issued_at=datetime.fromtimestamp(claims["iat"], timezone.utc),
            expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc),
        )
    except Exception as error:
        raise TokenRejected(_failed_check(error)) from None
