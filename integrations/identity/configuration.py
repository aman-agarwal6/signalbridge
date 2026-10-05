"""Fixed loopback enterprise identity profile; no discovery or network access."""

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings
from django.views.decorators.debug import sensitive_variables

from bridge.contract import canonical, parse_json
from bridge.federation import FederationDenied

from .constants import AUTHORIZATION, CALLBACK, CLIENT_ID, ISSUER, TOKEN  # noqa: F401
from .protocol import _public_keys

JWKS_ENDPOINT = ISSUER + "/protocol/openid-connect/certs"


@dataclass(frozen=True)
class IdentityConfiguration:
    ca_file: Path
    jwks: dict
    issuer: str = ISSUER
    client_id: str = CLIENT_ID
    callback: str = CALLBACK
    key_refresh_identity: tuple[str, ...] | None = None

    @sensitive_variables()
    def keys_for_token(self, value):
        if self.key_refresh_identity is None:
            return self.jwks
        from .key_refresh import keys_for_token

        return keys_for_token(self, value)


def _owned_file(value, maximum):
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise FederationDenied()
    path = Path(value)
    base = settings.BASE_DIR / "var" / "enterprise" / "identity"
    if not path.is_absolute() or not path.is_relative_to(base):
        raise FederationDenied()
    if not path.resolve().is_relative_to(base.resolve()):
        raise FederationDenied()
    for parent in (path, *path.parents):
        if parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction()):
            raise FederationDenied()
    if not path.is_file() or path.stat().st_size > maximum:
        raise FederationDenied()
    with path.open("rb") as handle:
        value = handle.read(maximum + 1)
    if not value or len(value) > maximum:
        raise FederationDenied()
    return path, value


def load_configuration():
    # SameSite=None is needed for a cross-site form_post callback. Browser writes
    # keep CSRF protection. Ordinary local settings remain Strict and fail here.
    if not (
        settings.FEDERATED_AUTH_ENABLED
        and settings.SESSION_ENGINE == "django.contrib.sessions.backends.db"
        and settings.SESSION_COOKIE_SECURE
        and settings.SESSION_COOKIE_HTTPONLY
        and settings.SESSION_COOKIE_SAMESITE == "None"
        and settings.CSRF_COOKIE_SECURE
        and settings.CSRF_COOKIE_SAMESITE == "Strict"
        and settings.SESSION_COOKIE_DOMAIN is None
        and settings.CSRF_COOKIE_DOMAIN is None
        and settings.SESSION_COOKIE_NAME == "sb_enterprise_session"
        and settings.CSRF_COOKIE_NAME == "sb_enterprise_csrf"
        and not settings.DEBUG
    ):
        raise FederationDenied()
    refresh = getattr(settings, "OIDC_JWKS_REFRESH_ENABLED", False)
    if type(refresh) is not bool:
        raise FederationDenied()
    ca_file, ca = _owned_file(getattr(settings, "OIDC_CA_FILE", ""), 16384)
    if not re.fullmatch(
        rb"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?", ca
    ):
        raise FederationDenied()
    jwks_file, raw = _owned_file(getattr(settings, "OIDC_JWKS_FILE", ""), 65536)
    jwks = _public_keys(parse_json(raw))
    identity = None
    if refresh:
        identity = (
            ISSUER,
            CLIENT_ID,
            CALLBACK,
            JWKS_ENDPOINT,
            str(ca_file.resolve()),
            hashlib.sha256(ca).hexdigest(),
            str(jwks_file.resolve()),
            hashlib.sha256(canonical(jwks)).hexdigest(),
        )
    # Loading remains offline; network access happens only during token checking.
    return IdentityConfiguration(ca_file=ca_file, jwks=jwks, key_refresh_identity=identity)
