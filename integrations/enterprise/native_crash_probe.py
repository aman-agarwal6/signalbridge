"""Fixed subprocess probe: hold uncommitted lab work until its parent kills it."""

import json
import os
import sys
import time
from pathlib import Path

import django


def main(marker):
    if sys.platform != "linux" or os.environ.get("SB_NATIVE_CRASH_CHILD") != "1":
        raise RuntimeError("Only the isolated native crash test can run this helper.")
    marker = Path(marker)
    if marker.parent.parent != Path("/tmp") or not marker.parent.name.startswith("sb-crash-"):
        raise RuntimeError("Crash handshake must belong to the disposable container tmpfs.")
    os.environ["DJANGO_SETTINGS_MODULE"] = "config.in_network_postgres_settings"
    django.setup()
    from django.db import connection, transaction

    from bridge.worker import drain

    if connection.vendor != "postgresql" or connection.settings_dict["NAME"] != (
        "test_sb_enterprise_verification"
    ):
        raise RuntimeError("Crash probe refused a non-disposable database.")
    with transaction.atomic():
        if drain(worker_id="pg-killed-worker") != 3:
            raise RuntimeError("Crash fixture did not process exactly its three events.")
        marker.write_text(json.dumps({"state": "uncommitted", "pid": os.getpid()}), encoding="utf8")
        time.sleep(30)
        raise RuntimeError("Parent failed to interrupt the crash fixture.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise RuntimeError("One fixed handshake path is required.")
    main(sys.argv[1])
