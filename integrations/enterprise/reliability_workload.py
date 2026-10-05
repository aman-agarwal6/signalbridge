"""Paced source workload on the runner's step-free lab timeline.

The runner writes the run's origin as a UTC time plus its CLOCK_MONOTONIC value
before any server starts. Every runner process, including this one and the TLS
source server that records each read, measures from that same monotonic origin
(lab_clock.py), so the VM's wall-clock drift and steps cannot shift the ledger.
The origin is set shortly in the future; the first slot waits for it.
"""

import os
import sys
import time
from datetime import datetime, timezone

from .lab_clock import load
from .reliability_source import RunClock, WorkloadError, run_native

EARLIEST_LAG_S, LATEST_LAG_S = -120, 120


class SharedClock(RunClock):
    def __init__(self, clock):
        lag = clock.elapsed_ns() / 1e9
        if not EARLIEST_LAG_S <= lag <= LATEST_LAG_S:
            raise WorkloadError("clock_origin_out_of_range")
        self.origin_ns = clock.origin_monotonic_ns
        self.origin_utc = clock.origin_utc
        self.maximum_drift_ms = 0

    def elapsed_ms(self):
        elapsed = (time.monotonic_ns() - self.origin_ns) // 1_000_000
        if elapsed < 0:
            raise WorkloadError("clock_alignment_changed")
        # Informational only: how far the VM wall clock wandered from the lab timeline.
        wall = (datetime.now(timezone.utc) - self.origin_utc).total_seconds() * 1000
        self.maximum_drift_ms = max(self.maximum_drift_ms, int(abs(wall - elapsed)))
        return elapsed

    def wait_until(self, due_ms, stopped):
        # Before the shared origin, elapsed time is negative by design; wait on
        # the monotonic clock alone, then let the parent pace the schedule.
        while time.monotonic_ns() < self.origin_ns:
            if stopped():
                raise WorkloadError("operator_stop")
            time.sleep(min(0.25, (self.origin_ns - time.monotonic_ns()) / 1e9))
        return super().wait_until(due_ms, stopped)


def main():
    if sys.platform != "linux" or os.environ.get("SB_RELIABILITY_RUNTIME") != "1":
        raise WorkloadError("unreviewed_reliability_runtime")
    result = run_native(clock=SharedClock(load()))
    return 0 if result.get("status") == "source_workload_completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
