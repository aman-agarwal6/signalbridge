"""Disposable native identity console; never ordinary local application settings."""

import os
import sys
from pathlib import Path

from .native_profile import load_profile

if sys.platform != "linux" or os.environ.get("SB_IDENTITY_NATIVE") != "1":
    raise RuntimeError("Native identity settings require the reviewed isolated Linux profile.")

_profile = load_profile(Path("/run/secrets/identity-profile.json"))
os.environ.update(
    SB_MODE="enterprise",
    SB_SECRET_KEY=_profile["django_secret"],
    SB_ALLOWED_HOSTS="127.0.0.1",
    SB_DB_HOST="database",
    SB_DB_NAME="identity_console",
    SB_DB_USER="identity_console",
    SB_DB_PASSWORD=_profile["database_password"],
    SB_OIDC_CA_FILE="/workspace/var/enterprise/identity/lab-ca.pem",
    SB_OIDC_JWKS_FILE="/workspace/var/enterprise/identity/jwks.json",
)

from config.identity_settings import *  # noqa: E402,F403

ROOT_URLCONF = "integrations.identity.native_urls"
# The rotation control signs with a key absent from the startup JWKS file; the
# bounded single-flight refresh is the only path that can admit that login.
OIDC_JWKS_REFRESH_ENABLED = True
DATABASES["default"]["OPTIONS"] = {"sslmode": "disable", "gssencmode": "disable"}  # noqa: F405
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False
LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
    "handlers": {
        "null": {"class": "logging.NullHandler"},
        # Fixed rejection-class warnings only; the runner keeps stderr private.
        "stderr": {"class": "logging.StreamHandler", "level": "WARNING"},
    },
    "loggers": {"bridge.oidc_views": {"handlers": ["stderr"], "level": "WARNING"}},
    "root": {"handlers": ["null"]},
}
