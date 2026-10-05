"""Opt-in memory-only header-profile checks; no native server or live database."""

from .reference_verification_settings import *  # noqa: F403

REFERENCE_HEADER_PROFILE = "signalbridge-reference-authenticated-headers-v1"
MIDDLEWARE = ["reference_lab.header_probe.HeaderProbe", *MIDDLEWARE]  # noqa: F405
SECURE_CONTENT_TYPE_NOSNIFF = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
