"""Paced 24-hour reliability runner inside its reviewed Linux profile.

Starts the TLS source and console, the courier collector, two console workers
and the live SOC publisher, then drives the unchanged 47,760-read schedule
through genuine source HTTPS reads. It applies the fixed runner-owned
interruptions (workers, collector, source delivery) on the shared run clock.
Wazuh-side windows belong to the Wazuh driver; the host measures the ledger.

A rehearsal (``SB_RELIABILITY_REHEARSAL_MS`` > 0) scales the same windows into
the shortened period and stops the schedule early; it is never a 24-hour result.
"""

import json
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .lab_clock import LabClock
from .reference_runner import (
    component_environment,
    install_dependencies,
    operate,
    runtime_gate,
    stop_processes,
    wait_for_tls,
)
from .reliability import DAY_MS, FINAL_DRAIN_MS, INTERRUPTIONS

ROOT = Path("/workspace")
OUTPUT = Path("/evidence")
CLOCK = Path("/clock")
STOP = OUTPUT / "reliability-stop"
# The manager finalizes its capture once the runner has drained and exported.
MANAGER_STOP = CLOCK / "reliability-stop"
RUNNER_WINDOWS = {
    "workers": ("worker-1", "worker-2"),
    "collector": ("collector",),
    "source_delivery": ("console",),
}
SERVICES = ("worker-1", "worker-2", "collector", "publisher")
# The clock is written before the servers start; the lead covers their start
# and TLS readiness so slot 0 is not born late.
ORIGIN_LEAD = timedelta(seconds=45)
SAMPLES = OUTPUT / "reliability-clock-samples.jsonl"
MAX_SAMPLES = 120_000
REHEARSAL_DRAIN_MS = 60_000
BOUNDARY = {
    "actual_identity_verified": True,
    "cross_database_connect_denied": True,
}


class ReliabilityError(ValueError):
    """Closed code only."""


def require(condition, code="reliability_predicate"):
    if not condition:
        raise ReliabilityError(code)


def write(name, value):
    require(name in {"reliability-clock", "reliability-runner"}, "receipt_name")
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")
    require(len(raw) <= 262144, "receipt_size")
    folder = CLOCK if name == "reliability-clock" else OUTPUT
    temporary = folder / (name + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(raw)
    temporary.replace(folder / (name + ".json"))


def rehearsal_ms():
    raw = os.environ.get("SB_RELIABILITY_REHEARSAL_MS", "")
    require(raw.isdigit() and len(raw) <= 9, "rehearsal_length")
    value = int(raw)
    require(value == 0 or 300_000 <= value <= 5_400_000, "rehearsal_length")
    return value


def offset_ms(clock):
    return clock.offset_ms()


def sample_wall_clock(clock, sampling):
    """Once a second: lab offset and wall offset, to map tool wall timestamps."""
    with SAMPLES.open("xb") as stream:
        for _ in range(MAX_SAMPLES):
            if sampling.is_set():
                return
            wall = int((datetime.now(timezone.utc) - clock.origin_utc).total_seconds() * 1000)
            row = {"lab_ms": clock.offset_ms(), "wall_ms": wall}
            stream.write(json.dumps(row, separators=(",", ":")).encode() + b"\n")
            stream.flush()
            sampling.wait(1)


class Supervisor:
    """Exact Popen handles only; never find or signal processes by name."""

    def __init__(self, environment):
        self.environment, self.handles, self.lock = environment, {}, threading.Lock()
        self.events = []

    def start(self, role, origin=None):
        with self.lock:
            require(role not in self.handles or self.handles[role].poll() is not None, "running")
            if role in ("source", "console"):
                component = role
                module = "integrations.enterprise.reference_native_server"
                argv = [sys.executable, "-B", "-m", module]
            else:
                component = "source" if role == "collector" else "console"
                module = "integrations.enterprise.reliability_services"
                argv = [sys.executable, "-B", "-m", module, role]
            env = component_environment(self.environment, component)
            env["SB_RELIABILITY_RUNTIME"] = "1"
            self.handles[role] = subprocess.Popen(
                argv,
                cwd=ROOT,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if origin is not None:
                self.events.append({"role": role, "action": "start", "at_ms": offset_ms(origin)})

    def stop(self, role, origin=None):
        with self.lock:
            process = self.handles.get(role)
            require(process is not None and process.poll() is None, "not_running")
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            if origin is not None:
                self.events.append({"role": role, "action": "stop", "at_ms": offset_ms(origin)})

    def unexpected_exits(self, paused):
        with self.lock:
            return sorted(
                role
                for role, process in self.handles.items()
                if role not in paused and process.poll() is not None
            )

    def close(self, roles=None):
        with self.lock:
            chosen = [p for r, p in self.handles.items() if roles is None or r in roles]
            return stop_processes(chosen)


def windows(scale=1.0):
    """Runner-owned fixed windows, mapped to the exact processes they stop."""
    rows = []
    for name, start, end, _ in INTERRUPTIONS:
        if name in RUNNER_WINDOWS:
            rows.append((int(start * scale), "stop", RUNNER_WINDOWS[name], name))
            rows.append((int(end * scale), "start", RUNNER_WINDOWS[name], name))
    return sorted(rows)


def interruptions(supervisor, origin, stopped, record, paused, scale):
    try:
        for at, action, roles, name in windows(scale):
            while offset_ms(origin) < at:
                if stopped.is_set():
                    return
                time.sleep(min(1, max(0.05, (at - offset_ms(origin)) / 1000)))
            for role in roles:
                if action == "stop":
                    paused.add(role)
                    supervisor.stop(role, origin)
                else:
                    supervisor.start(role, origin)
                    paused.discard(role)
            record.append({"window": name, "action": action, "at_ms": offset_ms(origin)})
    except Exception as error:
        record.append({"window": "controller", "action": "failed", "error": type(error).__name__})


def run_service_command(environment, role, timeout):
    component = "console"
    env = component_environment(environment, component)
    env["SB_RELIABILITY_RUNTIME"] = "1"
    result = subprocess.run(
        [sys.executable, "-B", "-m", "integrations.enterprise.reliability_services", role],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
    )
    require(result.returncode == 0 and len(result.stdout) <= 4096, role.replace("-", "_"))
    return json.loads(result.stdout)


def terminated(*_):
    # A host stop still records the receipt and releases the manager.
    raise ReliabilityError("terminated")


def main():
    signal.signal(signal.SIGTERM, terminated)
    run = runtime_gate()
    shortened = rehearsal_ms()
    scale = shortened / DAY_MS if shortened else 1.0
    drain = REHEARSAL_DRAIN_MS if shortened else FINAL_DRAIN_MS
    receipt = {
        "schema_version": 1,
        "run_id": run,
        "completed": False,
        "phase": "dependencies",
        "rehearsal_ms": shortened,
    }
    environment = component_environment(os.environ, "source")
    supervisor, stopped, record, paused = None, threading.Event(), [], set()
    sampling = threading.Event()
    try:
        for name in ("reliability-source", "reliability-collector"):
            (OUTPUT / name).mkdir(mode=0o700)
        install_dependencies(environment)
        receipt["phase"] = "provision"
        receipt["database_boundaries"] = {}
        for component in ("source", "console"):
            value = operate(environment, component, "provision")
            require(value == {"provisioned": True, "component": component}, "provision")
            value = operate(environment, component, "verify-boundary")
            require(
                value.get("component") == component
                and all(value.get(k) is v for k, v in BOUNDARY.items()),
                "database_boundary",
            )
            receipt["database_boundaries"][component] = value
        receipt["streams"] = run_service_command(environment, "provision-streams", 60)
        lead_ns = int(ORIGIN_LEAD.total_seconds() * 1_000_000_000)
        origin = LabClock(datetime.now(timezone.utc) + ORIGIN_LEAD, time.monotonic_ns() + lead_ns)
        write(
            "reliability-clock",
            {
                "run_id": run,
                "origin_utc": origin.origin_utc.isoformat(),
                "origin_monotonic_ns": origin.origin_monotonic_ns,
            },
        )
        threading.Thread(target=sample_wall_clock, args=(origin, sampling), daemon=True).start()
        supervisor = Supervisor(environment)
        for role in ("source", "console"):
            supervisor.start(role)
        from .reference_http import RequestBudget

        receipt["tls"] = wait_for_tls(
            RequestBudget(), [supervisor.handles["source"], supervisor.handles["console"]]
        )
        for role in SERVICES:
            supervisor.start(role, origin)
        receipt["phase"] = "workload"
        controller = threading.Thread(
            target=interruptions,
            args=(supervisor, origin, stopped, record, paused, scale),
            daemon=True,
        )
        controller.start()
        workload = subprocess.Popen(
            [sys.executable, "-B", "-m", "integrations.enterprise.reliability_workload"],
            cwd=ROOT,
            env={
                **component_environment(environment, "source"),
                "SB_RELIABILITY_RUNTIME": "1",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        period = shortened or DAY_MS
        exits = set()
        while workload.poll() is None:
            if shortened and offset_ms(origin) >= shortened and not STOP.exists():
                STOP.write_bytes(b"rehearsal\n")
            # A crashed service is evidence, not a reason to hide the run: it is
            # recorded and the schedule continues so the ledger shows the impact.
            exits.update(supervisor.unexpected_exits(paused))
            require(offset_ms(origin) < period + drain + 900_000, "workload_deadline")
            time.sleep(1)
        receipt["workload_exit_code"] = workload.returncode
        receipt["unexpected_service_exits"] = sorted(exits)
        receipt["phase"] = "final_drain"
        while offset_ms(origin) < period + drain:
            time.sleep(1)
        stopped.set()
        controller.join(timeout=30)
        receipt["phase"] = "stored_export"
        receipt["services_stopped"] = supervisor.close(SERVICES)
        receipt["stored"] = run_service_command(environment, "export-stored", 600)
        MANAGER_STOP.write_bytes(b"drained\n")
        receipt["completed"] = workload.returncode == 0 and not shortened
        receipt["phase"] = "finished"
    except Exception as error:
        receipt["error_class"] = type(error).__name__
        receipt["error_code"] = str(error) if isinstance(error, ReliabilityError) else None
    finally:
        stopped.set()
        sampling.set()
        if not MANAGER_STOP.exists():
            try:
                MANAGER_STOP.write_bytes(b"runner_finished\n")
            except OSError:
                receipt["manager_stop_signal_failed"] = True
        if supervisor is not None:
            receipt["service_events"] = supervisor.events[-200:]
            receipt["processes_stopped"] = supervisor.close()
        receipt["runner_windows"] = record
        write("reliability-runner", receipt)
    return 0 if receipt["completed"] or (shortened and receipt["phase"] == "finished") else 1


if __name__ == "__main__":
    raise SystemExit(main())
