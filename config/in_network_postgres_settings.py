"""Closed, disposable internal-network component gate; no host database fallback."""

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

from .verification_settings import *  # noqa: F403

TEST_RUNNER = "django.test.runner.DiscoverRunner"

if os.environ.get("SB_DISPOSABLE_PG") != "1" or any(
    name.startswith("PG") and value for name, value in os.environ.items()
):
    raise ImproperlyConfigured("An isolated PostgreSQL opt-in without inherited libpq is required.")
secret_path = Path("/run/secrets/verifier_password")
if not secret_path.is_file() or secret_path.stat().st_size != 64:
    raise ImproperlyConfigured("A dedicated disposable database credential is required.")
password = secret_path.read_text(encoding="ascii")
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": "database",
        "PORT": "5432",
        "NAME": "sb_enterprise_verification",
        "USER": "sb_verifier",
        "PASSWORD": password,
        "CONN_MAX_AGE": 0,
        "TEST": {"NAME": "test_sb_enterprise_verification"},
        "OPTIONS": {
            "sslmode": "disable",
            "gssencmode": "disable",
            "connect_timeout": 3,
            "options": "-c statement_timeout=5000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=10000",
        },
    }
}
# A fixed helper process can only select this profile's exact disposable test DB.
if os.environ.get("SB_NATIVE_CRASH_CHILD") == "1":
    DATABASES["default"]["NAME"] = "test_sb_enterprise_verification"
# Plaintext is restricted to the dedicated internal component-test network. This
# is not the enterprise TLS profile, and provides no source HTTP or SSO proof.
