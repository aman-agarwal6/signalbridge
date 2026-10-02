"""Source-app unit/HTTP-client tests in memory, without a native lab claim."""

from .verification_settings import *  # noqa: F403

INSTALLED_APPS = [*INSTALLED_APPS, "reference_lab"]  # noqa: F405
ROOT_URLCONF = "reference_lab.urls"
