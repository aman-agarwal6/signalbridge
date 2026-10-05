"""Opt-in bounded public Keycloak keys; no discovery, installs or import-time IO.

The cache is process-local. Each verified configuration has at most one fetch in
flight and one attempt per cooldown, independent of the untrusted token's kid.
Tokens still require the existing full JOSE/OIDC validation after key selection.
"""

import hashlib
import re
import threading
import time
from dataclasses import dataclass

from django.views.decorators.debug import sensitive_variables

from bridge.contract import canonical, parse_json

from .configuration import CALLBACK, CLIENT_ID, ISSUER, JWKS_ENDPOINT
from .protocol import TokenRejected, _compact, _public_keys, identifier
from .transport import jwks_get

MAX_PROFILES = 8
MAX_LIFETIME = 300
REFRESH_COOLDOWN = 15
SINGLEFLIGHT_WAIT = 5


def _profile(configuration):
    identity = configuration.key_refresh_identity
    if (
        type(identity) is not tuple
        or len(identity) != 8
        or not all(type(value) is str for value in identity)
        or identity[:4] != (ISSUER, CLIENT_ID, CALLBACK, JWKS_ENDPOINT)
        or (configuration.issuer, configuration.client_id, configuration.callback)
        != (ISSUER, CLIENT_ID, CALLBACK)
        or identity[4] != str(configuration.ca_file.resolve())
        or not re.fullmatch(r"[0-9a-f]{64}", identity[5])
        or not re.fullmatch(r"[0-9a-f]{64}", identity[7])
        or hashlib.sha256(canonical(_public_keys(configuration.jwks))).hexdigest() != identity[7]
    ):
        raise TokenRejected()
    return identity


@sensitive_variables()
def _refreshed_keys(raw):
    try:
        return _select_public_keys(raw)
    except Exception:
        raise TokenRejected() from None


@sensitive_variables()
def _select_public_keys(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 65536:
        raise TokenRejected()
    value = parse_json(raw)
    # Preserve the existing public-key validator, including its private-material,
    # key count, modulus/exponent and verification-operation checks.
    public = _public_keys(value)
    seen = set()
    for row in value["keys"]:
        kid = identifier(row.get("kid"))
        if kid in seen or (row.get("use") == "sig" and row.get("alg") != "RS256"):
            raise TokenRejected()
        seen.add(kid)
    # Encryption keys may be published alongside signing keys. They are never
    # imported into the cache or used to validate a login/logout token.
    return canonical(public), frozenset(row["kid"] for row in public["keys"])


@dataclass
class _Entry:
    raw: bytes | None = None
    kids: frozenset[str] = frozenset()
    expires_at: float = 0
    next_attempt: float = 0
    fetching: bool = False


class PublicKeyCache:
    def __init__(self, *, clock=time.monotonic):
        self._clock = clock
        self._condition = threading.Condition()
        self._entries = {}

    @sensitive_variables()
    def resolve(self, configuration, value):
        # No untrusted claims authorize an identity here. Header parsing only
        # rejects malformed input before it can trigger a provider request.
        try:
            header, _ = _compact(value)
        except Exception:
            raise TokenRejected() from None
        kid = header["kid"]
        identity = _profile(configuration)
        wait_until = time.monotonic() + SINGLEFLIGHT_WAIT
        with self._condition:
            entry = self._entries.get(identity)
            if entry is None:
                if len(self._entries) >= MAX_PROFILES:
                    # Do not evict/reseed an entry and reset an attacker's budget.
                    raise TokenRejected()
                entry = self._entries[identity] = _Entry()
            while True:
                current = self._clock()
                if entry.raw is not None and current < entry.expires_at and kid in entry.kids:
                    return parse_json(entry.raw)
                if entry.fetching:
                    remaining = wait_until - time.monotonic()
                    if remaining <= 0:
                        raise TokenRejected()
                    self._condition.wait(timeout=remaining)
                    continue
                if current < entry.next_attempt:
                    raise TokenRejected()
                entry.fetching = True
                entry.next_attempt = current + REFRESH_COOLDOWN
                break

        try:
            raw, kids = _refreshed_keys(
                jwks_get(ca_file=configuration.ca_file, ca_sha256=identity[5])
            )
        except Exception:
            with self._condition:
                entry.fetching = False
                self._condition.notify_all()
            # Retain the original expiry on failure; expired keys never become
            # trusted again by loading the same file or retrying the request.
            raise
        with self._condition:
            entry.raw, entry.kids = raw, kids
            entry.expires_at = self._clock() + MAX_LIFETIME
            entry.fetching = False
            self._condition.notify_all()
            if kid not in kids:
                raise TokenRejected()
            return parse_json(raw)


_CACHE = PublicKeyCache()


@sensitive_variables()
def keys_for_token(configuration, value):
    return _CACHE.resolve(configuration, value)
