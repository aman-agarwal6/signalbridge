"""Prepared loopback TLS identity profile; needs a separately reviewed launch.

No issuer or callback is taken from browser input. No host trust is changed.
Provider keys and CA are explicitly provisioned into the owned private lab folder.
"""

from .settings import *  # noqa: F403

FEDERATED_AUTH_ENABLED = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_NAME = "sb_enterprise_session"
SESSION_COOKIE_DOMAIN = None
SESSION_COOKIE_SAMESITE = "None"  # cross-site OIDC form_post, guarded by one-time state
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_NAME = "sb_enterprise_csrf"
CSRF_COOKIE_DOMAIN = None
OIDC_CA_FILE = os.environ.get("SB_OIDC_CA_FILE", "")  # noqa: F405
OIDC_JWKS_FILE = os.environ.get("SB_OIDC_JWKS_FILE", "")  # noqa: F405
