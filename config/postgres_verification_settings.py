"""Opt-in disposable PostgreSQL gate; never selects a workstation/project DB."""

import os

from django.core.exceptions import ImproperlyConfigured

from .verification_settings import *  # noqa: F403

if os.environ.get("SB_DISPOSABLE_PG") != "1":
    raise ImproperlyConfigured("The disposable PostgreSQL gate requires an explicit opt-in.")
if any(name.startswith("PG") and value for name, value in os.environ.items()):
    raise ImproperlyConfigured("Inherited PostgreSQL settings are forbidden in this gate.")
password = os.environ.get("SB_ENTERPRISE_VERIFY_PASSWORD", "")
if len(password) < 32:
    raise ImproperlyConfigured("A dedicated ephemeral verification credential is required.")
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": "127.0.0.1",
        "PORT": "15432",
        "NAME": "sb_enterprise_verification",
        "USER": "sb_verifier",
        "PASSWORD": password,
        "CONN_MAX_AGE": 0,
        "TEST": {"NAME": "test_sb_enterprise_verification"},
        "OPTIONS": {
            "sslmode": "disable",
            "gssencmode": "disable",
            "hostaddr": "127.0.0.1",
            "connect_timeout": 3,
            "options": "-c statement_timeout=5000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=10000",
        },
    }
}
# This is only a loopback, disposable database verification profile. Enterprise
# application transport and Keycloak require the separately reviewed TLS profile.
