"""Fresh disposable SQLite only; never import the running application's settings."""

from pathlib import Path

from config.simulation_settings import *  # noqa: F403

BASE_DIR = Path("/state")
ALLOWED_HOSTS = ["127.0.0.1"]
ROOT_URLCONF = "integrations.monitoring.native_urls"
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "/state/monitoring.sqlite3",
        "OPTIONS": {"timeout": 2},
    }
}
MONITORED_WORKERS = ("monitoring-proof",)
