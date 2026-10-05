"""Disposable Shuffle-lab receiver profile; never a deployment configuration.

Inherits the real settings and changes only the reachable hostname, the private
SQLite location (a tmpfs inside the isolated lab) and federation (off).
"""

from config.settings import *  # noqa: F403

ALLOWED_HOSTS = ["signalbridge"]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "/receiver/signalbridge.sqlite3",
    }
}
FEDERATED_AUTH_ENABLED = False
