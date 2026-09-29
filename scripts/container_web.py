"""Compose-only lab server. The Compose host port is loopback-bound."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if os.environ.get("SB_CONTAINER") != "1" or os.environ.get("SB_DB_HOST") != "db":
    raise SystemExit("Use this entry point only inside the reviewed local Compose configuration.")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
import django

django.setup()
from django.contrib.staticfiles.handlers import StaticFilesHandler
from waitress import serve

from config.wsgi import application

serve(
    StaticFilesHandler(application),
    host="0.0.0.0",
    port=8000,
    threads=4,
    max_request_body_size=16384,
)
