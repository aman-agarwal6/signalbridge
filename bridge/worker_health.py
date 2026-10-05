"""Observe explicitly configured worker slots; a pulse is not completed detection."""

import re
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from .models import WorkerHeartbeat

WORKER_STATES = ("recent", "stale", "missing", "clock_error")
SLOTS = ("primary", "secondary")


def configured_workers():
    names = getattr(settings, "MONITORED_WORKERS", ("default",))
    if (
        not isinstance(names, (tuple, list))
        or not 1 <= len(names) <= 2
        or any(
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,39}", name) is None
            for name in names
        )
        or len(set(names)) != len(names)
    ):
        raise ValueError("Worker monitoring requires one or two distinct configured identities.")
    return tuple(names)


def worker_health(now=None):
    now = now or timezone.now()
    try:
        names = configured_workers()
    except ValueError:
        return {"configuration_valid": False, "all_recent": False, "workers": []}
    rows = dict(WorkerHeartbeat.objects.filter(name__in=names).values_list("name", "last_seen"))
    workers = []
    for slot, name in zip(SLOTS, names, strict=False):
        seen = rows.get(name)
        state = (
            "missing"
            if seen is None
            else "clock_error"
            if seen > now + timedelta(seconds=5) or seen.year < 1970
            else "recent"
            if seen >= now - timedelta(seconds=30)
            else "stale"
        )
        workers.append({"slot": slot, "state": state, "seen_at": seen})
    return {
        "configuration_valid": True,
        "all_recent": all(item["state"] == "recent" for item in workers),
        "workers": workers,
    }
