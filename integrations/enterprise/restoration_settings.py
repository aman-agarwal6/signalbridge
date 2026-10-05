"""Closed restored-console profile; no workstation database or secret fallback.

The database is a separate PostgreSQL instance restored from a logical backup of
a retained native console. Operator commands run here as the local database
operator against that restoration only, never against the original volume.
"""

import os
import sys
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

from config.verification_settings import *  # noqa: F403

if (
    sys.platform != "linux"
    or os.environ.get("SB_RESTORATION_PROOF") != "1"
    or any(name.startswith("PG") and value for name, value in os.environ.items())
):
    raise ImproperlyConfigured("The closed restoration proof requires an explicit Linux opt-in.")
credential = Path("/run/secrets/console_password")
if not credential.is_file() or credential.is_symlink() or credential.stat().st_size != 64:
    raise ImproperlyConfigured("A dedicated restoration database credential is required.")
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": "database",
        "PORT": "5432",
        "NAME": "sb_enterprise_access",
        "USER": "sb_restored_console",
        "PASSWORD": credential.read_text(encoding="ascii"),
        "CONN_MAX_AGE": 0,
        "OPTIONS": {
            "sslmode": "disable",
            "gssencmode": "disable",
            "connect_timeout": 3,
            "options": "-c statement_timeout=15000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=20000",
        },
    }
}
LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
    "handlers": {"discard": {"class": "logging.NullHandler"}},
    "root": {"handlers": ["discard"], "level": "ERROR"},
}
