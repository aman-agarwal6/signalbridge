"""Closed native source-proof profile; no workstation database or secret fallback.

This is a finite component proof with TLS HTTP inside one isolated runner and
two separate PostgreSQL roles/databases. It is not the full enterprise profile.
"""

import os
import sys
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

from config.verification_settings import *  # noqa: F403

component = os.environ.get("SB_SOURCE_COMPONENT")
if (
    sys.platform != "linux"
    or os.environ.get("SB_SOURCE_PROOF") != "1"
    or component not in ("source", "console")
    or any(name.startswith("PG") and value for name, value in os.environ.items())
):
    raise ImproperlyConfigured(
        "The closed Linux source proof requires an explicit component opt-in."
    )
credential = Path("/run/secrets/" + component + "_password")
if not credential.is_file() or credential.is_symlink() or credential.stat().st_size != 64:
    raise ImproperlyConfigured("A dedicated native source-proof database credential is required.")
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": "database",
        "PORT": "5432",
        "NAME": "sb_reference" if component == "source" else "sb_enterprise_access",
        "USER": "sb_reference" if component == "source" else "sb_access_console",
        "PASSWORD": credential.read_text(encoding="ascii"),
        "CONN_MAX_AGE": 0,
        "OPTIONS": {
            "sslmode": "disable",
            "gssencmode": "disable",
            "connect_timeout": 3,
            "options": "-c statement_timeout=5000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=10000",
        },
    }
}
if component == "console":
    # This closed two-container proof gets one dedicated writable evidence
    # mount. Never let a request/environment variable choose export paths.
    SOC_SEGMENTED_EXPORT = True
    SOC_DELIVERY_ROOT = Path("/evidence/soc-delivery")
    WAZUH_SNAPSHOT_ROOT = Path("/evidence/wazuh-enterprise/native")
ALLOWED_HOSTS = ["127.0.0.1"]
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_AGE = 900
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = None
LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
    "handlers": {"discard": {"class": "logging.NullHandler"}},
    "root": {"handlers": ["discard"], "level": "ERROR"},
}
if component == "source":
    INSTALLED_APPS = [*INSTALLED_APPS, "reference_lab"]  # noqa: F405
    ROOT_URLCONF = "reference_lab.urls"
