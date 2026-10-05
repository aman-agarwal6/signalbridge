"""Step-free lab clock for the reliability runtime only.

Docker Desktop's VM wall clock drifts (about 50 ppm) and is periodically stepped,
including backwards. Every runner process therefore reads one shared timeline:
the run's UTC origin plus elapsed CLOCK_MONOTONIC, which never steps and is the
same for every container on the VM kernel. Django's timezone.now() is replaced
in these processes only, so committed database timestamps share that timeline.
The wall clock is still sampled so tool timestamps can be mapped onto it.
"""

import bisect
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

CLOCK = Path("/clock/reliability-clock.json")
FIELDS = {"run_id", "origin_utc", "origin_monotonic_ns"}


class ClockError(ValueError):
    """Closed code only."""


def require(condition, code="lab_clock"):
    if not condition:
        raise ClockError(code)


class LabClock:
    def __init__(self, origin_utc, origin_monotonic_ns):
        require(isinstance(origin_utc, datetime) and origin_utc.utcoffset() is not None)
        require(type(origin_monotonic_ns) is int and origin_monotonic_ns > 0)
        self.origin_utc = origin_utc.astimezone(timezone.utc)
        self.origin_monotonic_ns = origin_monotonic_ns

    def elapsed_ns(self):
        return time.monotonic_ns() - self.origin_monotonic_ns

    def offset_ms(self):
        return self.elapsed_ns() // 1_000_000

    def now(self):
        return self.origin_utc + timedelta(microseconds=self.elapsed_ns() // 1000)

    def offset_of(self, moment):
        """Milliseconds from the origin for a timestamp taken on this lab clock."""
        return int((moment - self.origin_utc).total_seconds() * 1000)


def parse(raw):
    value = json.loads(raw)
    require(type(value) is dict and set(value) == FIELDS, "lab_clock_shape")
    return value, LabClock(
        datetime.fromisoformat(value["origin_utc"]), value["origin_monotonic_ns"]
    )


def load(path=CLOCK):
    return parse(Path(path).read_bytes())[1]


def install(path=CLOCK):
    """Point Django's timezone.now() at the lab clock in this process."""
    clock = load(path)
    from django.utils import timezone as django_timezone

    django_timezone.now = clock.now
    return clock


class WallMapping:
    """Map wall-clock timestamps (e.g. Wazuh records) onto the lab timeline.

    Samples are (lab_ms, wall_ms) pairs taken by the runner every second. Near a
    backward wall step a wall time is ambiguous; the nearest sample is used, so
    the error is at most about one step and only for records inside that step.
    """

    def __init__(self, samples):
        rows = sorted((wall, lab) for lab, wall in samples)
        require(rows, "lab_clock_samples")
        self.walls = [wall for wall, _ in rows]
        self.divergence = [wall - lab for wall, lab in rows]

    def lab_ms(self, wall_ms):
        index = bisect.bisect_left(self.walls, wall_ms)
        candidates = [i for i in (index - 1, index) if 0 <= i < len(self.walls)]
        nearest = min(candidates, key=lambda i: abs(self.walls[i] - wall_ms))
        return wall_ms - self.divergence[nearest]
