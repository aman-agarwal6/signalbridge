"""Parse and verify AccessOps leaver Security Event Tokens (RFC 8417, SSF 1.0).

No Django and no network: these functions decide whether one compact token is accepted.
There is exactly one signature path, ES256 with a published P-256 key whose kid is its
RFC 7638 thumbprint, so a token cannot choose a weaker algorithm or bring its own key.
Claims form a closed schema: an unknown claim or event member is refused, which keeps the
contract's promise that tokens carry no names, emails or IP addresses.
"""

import base64
import hashlib
import json
import re
from datetime import datetime, timezone

ISSUER = "https://accessops.test:8443"
AUDIENCE = "urn:accessops:soc-receiver"
TYP = "secevent+jwt"
ACCOUNT_DISABLED = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
SESSION_ESTABLISHED = "https://schemas.openid.net/secevent/caep/event-type/session-established"
EVENT_TYPES = {
    ACCOUNT_DISABLED: "account_disabled",
    SESSION_REVOKED: "session_revoked",
    SESSION_ESTABLISHED: "session_established",
}
# Event members allowed per type, beyond event_timestamp.
EVENT_MEMBERS = {
    ACCOUNT_DISABLED: set(),
    SESSION_REVOKED: {"initiating_entity", "reason_admin"},
    SESSION_ESTABLISHED: set(),
}
INITIATING_ENTITIES = {"admin", "user", "policy", "system"}
MAX_TOKEN = 8192
MAX_KEYS = 10
FUTURE_SKEW = 300
JTI = re.compile(r"[0-9a-f]{32}")
TXN = re.compile(r"[0-9A-Za-z_.:-]{1,128}")
SUBJECT = re.compile(r"[0-9A-Za-z_.:@-]{1,255}")
B64URL = re.compile(r"[A-Za-z0-9_-]+")


class SetError(ValueError):
    """A refused token; code is the RFC 8935 error reported back in setErrs."""

    def __init__(self, code, description):
        super().__init__(description)
        self.code = code
        self.description = description


class UnknownKey(SetError):
    """The kid is not in the current key set; the caller may refetch keys once."""

    def __init__(self):
        super().__init__("invalid_key", "The signing key is not published by the transmitter.")


def b64url(part, what):
    if not isinstance(part, str) or not B64URL.fullmatch(part):
        raise SetError("invalid_request", what + " is not base64url.")
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def strict_json(raw, what):
    """JSON object with no duplicate members and no NaN/Infinity."""

    def members(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise SetError("invalid_request", what + " repeats a member.")
            value[key] = item
        return value

    def constant(name):
        raise SetError("invalid_request", what + " contains a non-finite number.")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=members, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SetError("invalid_request", what + " is not JSON.") from None
    if not isinstance(value, dict):
        raise SetError("invalid_request", what + " is not a JSON object.")
    return value


def split(token):
    """(header, claims, signing input, signature) of a bounded compact JWS."""
    if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN:
        raise SetError("invalid_request", "The token is empty or too large.")
    parts = token.split(".")
    if len(parts) != 3:
        raise SetError("invalid_request", "The token is not a compact JWS.")
    header = strict_json(b64url(parts[0], "The header"), "The header")
    claims = strict_json(b64url(parts[1], "The payload"), "The payload")
    signature = b64url(parts[2], "The signature")
    return header, claims, (parts[0] + "." + parts[1]).encode("ascii"), signature


def thumbprint(jwk):
    """RFC 7638 SHA-256 thumbprint of an EC public key."""
    canonical = json.dumps(
        {name: jwk[name] for name in ("crv", "kty", "x", "y")},
        separators=(",", ":"),
        sort_keys=True,
    )
    return (
        base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()
    )


def load_keys(jwks):
    """{kid: public key} for published P-256 signing keys whose kid is their thumbprint."""
    from cryptography.hazmat.primitives.asymmetric import ec

    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise ValueError("The key set is not a JWKS.")
    if len(jwks["keys"]) > MAX_KEYS:
        raise ValueError("The key set has too many keys.")
    keys = {}
    for jwk in jwks["keys"]:
        if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            continue
        if "d" in jwk:
            raise ValueError("The key set publishes private key material.")
        if jwk.get("use", "sig") != "sig" or jwk.get("alg", "ES256") != "ES256":
            continue
        try:
            x, y = b64url(jwk.get("x"), "x"), b64url(jwk.get("y"), "y")
        except SetError:
            continue
        if len(x) != 32 or len(y) != 32 or jwk.get("kid") != thumbprint(jwk):
            continue
        try:
            numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
            )
            keys[jwk["kid"]] = numbers.public_key()
        except ValueError:
            continue  # Not a point on P-256.
    return keys


def verify_signature(signing_input, signature, public_key):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    if len(signature) != 64:
        raise SetError("invalid_key", "An ES256 signature is 64 bytes.")
    der = encode_dss_signature(
        int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    )
    try:
        public_key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise SetError("invalid_key", "The signature does not verify.") from None


def check_header(header, keys):
    if header.get("typ") != TYP:
        raise SetError("invalid_request", "typ must be secevent+jwt.")
    if header.get("alg") != "ES256":
        raise SetError("invalid_key", "Only ES256 is accepted.")
    if set(header) - {"typ", "alg", "kid"}:
        raise SetError("invalid_request", "The header has a member other than typ, alg and kid.")
    kid = header.get("kid")
    if not isinstance(kid, str) or kid not in keys:
        raise UnknownKey()
    return kid


def timestamp(value, now, what):
    if type(value) is not int or not 0 < value <= now + FUTURE_SKEW:
        raise SetError("invalid_request", what + " is not a valid time.")
    return datetime.fromtimestamp(value, tz=timezone.utc)


def check_claims(claims, now):
    """Normalized facts of one accepted token; everything else is refused."""
    if set(claims) - {"iss", "aud", "iat", "jti", "txn", "sub_id", "events"}:
        raise SetError("invalid_request", "The token has an unknown claim.")
    if claims.get("iss") != ISSUER:
        raise SetError("invalid_issuer", "The issuer is not AccessOps.")
    if claims.get("aud") not in (AUDIENCE, [AUDIENCE]):
        raise SetError("invalid_audience", "The token is not addressed to this receiver.")
    issued = timestamp(claims.get("iat"), now, "iat")
    jti = claims.get("jti")
    if not isinstance(jti, str) or not JTI.fullmatch(jti):
        raise SetError("invalid_request", "jti must be 32 lowercase hex characters.")
    txn = claims.get("txn", "")
    if not isinstance(txn, str) or (txn and not TXN.fullmatch(txn)):
        raise SetError("invalid_request", "txn is not a bounded identifier.")
    subject = claims.get("sub_id")
    if (
        not isinstance(subject, dict)
        or set(subject) != {"format", "iss", "sub"}
        or subject["format"] != "iss_sub"
        or not isinstance(subject["iss"], str)
        or not subject["iss"].startswith("https://")
        or not 9 < len(subject["iss"]) <= 255
        or any(ord(c) < 33 for c in subject["iss"])
        or not isinstance(subject["sub"], str)
        or not SUBJECT.fullmatch(subject["sub"])
    ):
        raise SetError("invalid_request", "sub_id must be an iss_sub subject.")
    events = claims.get("events")
    if not isinstance(events, dict) or len(events) != 1:
        raise SetError("invalid_request", "A token must carry exactly one event.")
    ((uri, event),) = events.items()
    if uri not in EVENT_TYPES:
        raise SetError("invalid_request", "The event type is not a leaver signal.")
    if not isinstance(event, dict) or set(event) - EVENT_MEMBERS[uri] - {"event_timestamp"}:
        raise SetError("invalid_request", "The event has an unknown member.")
    occurred = timestamp(event.get("event_timestamp"), now, "event_timestamp")
    entity = event.get("initiating_entity", "")
    if entity and entity not in INITIATING_ENTITIES:
        raise SetError("invalid_request", "initiating_entity is not a CAEP value.")
    reason = event.get("reason_admin", {})
    if (
        not isinstance(reason, dict)
        or len(reason) > 4
        or any(
            not isinstance(k, str) or not isinstance(v, str) or len(k) > 8 or len(v) > 200
            for k, v in reason.items()
        )
    ):
        raise SetError("invalid_request", "reason_admin must be short language-tagged text.")
    return {
        "jti": jti,
        "txn": txn,
        "event_type": EVENT_TYPES[uri],
        "subject_issuer": subject["iss"],
        "subject_id": subject["sub"],
        "event_at": occurred,
        "issued_at": issued,
        "initiating_entity": entity,
        "reason": reason.get("en", ""),
    }


def accept(token, keys, now, verifier=verify_signature):
    """Facts of a token that passes the header, signature and claim checks, in that order."""
    header, claims, signing_input, signature = split(token)
    kid = check_header(header, keys)
    verifier(signing_input, signature, keys[kid])
    facts = check_claims(claims, now)
    facts["key_id"] = kid
    return facts


def facts_digest(facts):
    """Identity of what a token says, used to tell a redelivery from a conflicting reuse."""
    stable = [
        facts["event_type"],
        facts["subject_issuer"],
        facts["subject_id"],
        int(facts["event_at"].timestamp()),
        facts["txn"],
    ]
    return hashlib.sha256(json.dumps(stable, separators=(",", ":")).encode()).hexdigest()
