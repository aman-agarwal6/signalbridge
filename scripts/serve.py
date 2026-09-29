"""Loopback-only Windows/Linux development server with one queue worker."""

import json
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.runtime_identity import runtime_file
from scripts.sb import local_environment


def checked_path(name, *, create_directory=False):
    try:
        return runtime_file(ROOT, name, create_directory=create_directory)
    except (OSError, ValueError):
        raise SystemExit("Local server runtime paths cannot be redirected or linked.") from None


def clear_stop_request():
    checked_path("stop.request").unlink(missing_ok=True)


def stop_requested():
    return checked_path("stop.request").exists()


def main():
    # Validate before importing Django: its normal settings create local runtime state.
    local_environment()
    checked_path("server.log", create_directory=True)
    checked_path("stop.request")
    keys = checked_path("lab-keys.json")
    os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
    if keys.exists():
        for app, key in json.loads(keys.read_text()).items():
            os.environ["SB_" + app.upper() + "_LAB_KEY"] = key
    import django

    django.setup()
    from django.conf import settings
    from django.contrib.staticfiles.handlers import StaticFilesHandler
    from django.db import close_old_connections
    from waitress import create_server

    from bridge.worker import drain
    from config.wsgi import application

    if not settings.LOCAL:
        raise SystemExit(
            "This launcher is local-only; use the reviewed container setup for PostgreSQL."
        )
    server = create_server(
        StaticFilesHandler(application),
        host="127.0.0.1",
        port=8741,
        threads=4,
        max_request_body_size=16384,
    )
    # A failed port bind must not clear a running server's pending stop marker.
    try:
        clear_stop_request()
    except (SystemExit, OSError):
        server.close()
        raise

    def worker():
        while True:
            try:
                drain()
            except Exception:
                print("Worker failed; retry recorded. Check queue health.", flush=True)
            finally:
                close_old_connections()
            time.sleep(2)

    def shutdown():
        warned = False
        while True:
            try:
                if stop_requested():
                    server.close()
                    os._exit(0)
                warned = False
            except SystemExit:
                # A newly redirected marker is not authorization to stop this server.
                if not warned:
                    print(
                        "Ignored redirected shutdown marker; inspect local runtime paths.",
                        flush=True,
                    )
                    warned = True
            time.sleep(0.5)

    threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=shutdown, daemon=True).start()
    print("SignalBridge local lab: http://127.0.0.1:8741/", flush=True)
    server.run()


if __name__ == "__main__":
    main()
