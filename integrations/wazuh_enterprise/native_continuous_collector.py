"""Continuous native Wazuh collection beside the paced 24-hour reliability run.

Runs the reviewed manager configuration on the console's live SOC observation
segments (read-only binds) and durably captures every archived record across
Wazuh's own log rotations. It applies the two Wazuh-side fixed windows on the
runner's shared clock: a log-collector stop/restart (collector_rotation) and a
manager analysis and collection outage (wazuh_connector). There is no expected
set: the host reconciles captured records with the source ledger afterwards.
The finite bootstrap module and its pinned bytes remain unchanged.
"""

import json
import os
import re
import signal
import sqlite3
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from bridge.contract import canonical, parse_json
from integrations.wazuh import run_pilot as base

from . import native_collector as core
from .capture_journal import MAX_BYTES as CAPTURE_BYTES
from .contract import EnterpriseWazuhError, require

KIND = "signalbridge-wazuh-native-continuous-v1"
SOURCE_FILES = (
    *(
        name
        for name in core.SOURCE_FILES
        if name != "integrations/wazuh_enterprise/export_snapshot.py"
    ),
    "integrations/wazuh_enterprise/native_continuous_collector.py",
)
CLOCK = Path("/signalbridge/clock/reliability-clock.json")
STOP = Path("/signalbridge/clock/reliability-stop")
HOURS = 26
HARD_SECONDS = HOURS * 3600 + 900
# The heartbeat lives on a Windows bind mount, where scanners can briefly lock a
# file being renamed; it is diagnostic, so write it sparingly and never fail on it.
HEARTBEAT_SECONDS = 15
# Wazuh rotates archives every ten minutes or 2 MB: a day leaves a few hundred
# rotated files per month folder, beyond the ten-minute bootstrap's 64.
LOG_DIRECTORY_ENTRIES = 4096
PROCESS_LOG_BYTES = 64 * 1024**2
MANAGER_LOG_BYTES = 256 * 1024**2
PRIVATE_OUTPUT_BYTES = 3 * 1024**3
LOGCOLLECTOR, ANALYSISD = "wazuh-logcollector", "wazuh-analysisd"
WINDOW_DAEMONS = {
    "collector_rotation": (LOGCOLLECTOR,),
    "wazuh_connector": (LOGCOLLECTOR, ANALYSISD),
}


def _entries(path, maximum):
    result = []
    with os.scandir(path) as iterator:
        for entry in iterator:
            require(len(result) < maximum, "native_collector_log_directory_limit")
            result.append(Path(entry.path))
    return result


def current_native_file(kind):
    """The pinned finder's checks with a day-long directory bound; identity only."""
    require(kind in {"archive", "alert"}, "native_collector_log_kind")
    folder = core.WAZUH / "logs" / ("archives" if kind == "archive" else "alerts")
    path = folder / ("archives.json" if kind == "archive" else "alerts.json")
    for parent in (folder, *folder.parents):
        core._directory(parent)
    if not path.exists():
        return None
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 2,
        "native_collector_log_file",
    )
    identity = info.st_dev, info.st_ino
    aliases = []
    prefix = "ossec-archive-" if kind == "archive" else "ossec-alerts-"
    for year in _entries(folder, 64):
        if not re.fullmatch(r"[0-9]{4}", year.name):
            continue
        core._directory(year)
        for month in _entries(year, 12):
            core._directory(month)
            for candidate in _entries(month, LOG_DIRECTORY_ENTRIES):
                if not (candidate.name.startswith(prefix) and candidate.name.endswith(".json")):
                    continue
                other = candidate.lstat()
                require(stat.S_ISREG(other.st_mode), "native_collector_daily_log")
                if (other.st_dev, other.st_ino) == identity:
                    aliases.append(candidate)
    require(len(aliases) == 1, "native_collector_log_alias")
    for candidate in (path, aliases[0]):
        final = candidate.lstat()
        require(
            stat.S_ISREG(final.st_mode)
            and final.st_nlink == 2
            and (final.st_dev, final.st_ino) == identity,
            "native_collector_log_race",
        )
    return identity


def validate_plan(raw, run_id):
    plan = parse_json(raw)
    require(
        type(plan) is dict
        and set(plan) == {"run_id", "mode", "windows"}
        and plan["run_id"] == run_id
        and plan["mode"] == "continuous"
        and type(plan["windows"]) is list
        and len(plan["windows"]) == 2 * len(WINDOW_DAEMONS),
        "native_collector_continuous_plan",
    )
    seen = set()
    for window in plan["windows"]:
        require(
            type(window) is dict
            and set(window) == {"component", "action", "at_ms"}
            and window["component"] in WINDOW_DAEMONS
            and window["action"] in ("stop", "start")
            and type(window["at_ms"]) is int
            and 0 < window["at_ms"] < HOURS * 3_600_000
            and (window["component"], window["action"]) not in seen,
            "native_collector_continuous_window",
        )
        seen.add((window["component"], window["action"]))
    for component in WINDOW_DAEMONS:
        stop, start = (
            next(
                w["at_ms"]
                for w in plan["windows"]
                if w["component"] == component and w["action"] == a
            )
            for a in ("stop", "start")
        )
        require(stop < start, "native_collector_continuous_window")
    return plan


class ContinuousCollector(core.NativeCollector):
    source_files = SOURCE_FILES

    def __init__(self):
        super().__init__()
        self.report["kind"] = KIND
        self.deadline = self.started + HOURS * 3600
        self.windows_applied, self.origin, self.plan = [], None, None
        self.last_heartbeat, self.heartbeat_failures = None, 0
        # The ledger binds archived records only; the pinned journal's fixed
        # per-kind ceiling then covers a full day of archives with headroom.
        self.last = {"archive": (None, b"")}

    def load_expected(self, raw_manifest):
        # The fresh, host-hashed manifest is the fixed window plan in this mode.
        run_id = core.validate_context(
            core._file(core.EVIDENCE / "run-context.json", 4096), now=datetime.now(timezone.utc)
        )["run_id"]
        self.plan = validate_plan(raw_manifest, run_id)
        return {}

    def verify_inputs(self):
        return None

    def check_budget(self):
        require(time.monotonic() < self.started + HARD_SECONDS, "native_collector_hard_limit")
        for path in self.files:
            require(path.stat().st_size <= PROCESS_LOG_BYTES, "native_collector_process_log_limit")
        for process, _, daemon in self.children:
            if daemon:
                require(process.poll() is None, "native_collector_daemon_exited")
        log = core.WAZUH / "logs/ossec.log"
        if log.exists():
            require(log.lstat().st_size <= MANAGER_LOG_BYTES, "native_collector_manager_log_limit")
        require(
            sum(p.stat().st_size for p in core.EVIDENCE.iterdir() if p.is_file())
            <= PRIVATE_OUTPUT_BYTES,
            "native_collector_private_output_limit",
        )

    def heartbeat(self, coverage):
        now = time.monotonic()
        if self.last_heartbeat is not None and now - self.last_heartbeat < HEARTBEAT_SECONDS:
            return
        self.last_heartbeat = now
        try:
            super().heartbeat(coverage)
        except OSError:
            self.heartbeat_failures += 1
            self.report["heartbeat_failures"] = self.heartbeat_failures
            stale = core.EVIDENCE / "heartbeat-next.json"
            try:
                stale.unlink()
            except OSError:
                pass

    def poll_records(self):
        require(self.journal is not None, "native_collector_capture_unprepared")
        for kind in self.last:
            try:
                identity = current_native_file(kind)
            except FileNotFoundError:
                identity = None
            captured = self.captures[kind]
            if identity is not None:
                folder = "archives" if kind == "archive" else "alerts"
                captured.attach(
                    core.WAZUH / "logs" / folder / (folder + ".json"),
                    f"{identity[0]:x}:{identity[1]:x}",
                )
            captured.drain()
        return {"windows_applied": len(self.windows_applied)}

    def offset_ms(self):
        if self.origin is None:
            if not CLOCK.exists():
                return None
            value = parse_json(core._file(CLOCK, 1024))
            require(
                type(value) is dict
                and set(value) == {"origin_utc", "origin_monotonic_ns", "run_id"}
                and type(value["origin_monotonic_ns"]) is int,
                "native_collector_continuous_clock",
            )
            # Same VM kernel: CLOCK_MONOTONIC is the runner's step-free timeline.
            self.origin = value["origin_monotonic_ns"]
        return (time.monotonic_ns() - self.origin) // 1_000_000

    def daemon(self, name):
        binary = str(core.WAZUH / "bin" / name)
        for index, (process, log, live) in enumerate(self.children):
            if live and process.args[0] == binary:
                return index, process, log
        raise EnterpriseWazuhError("native_collector_continuous_daemon_missing")

    def stop_daemon(self, name):
        index, process, log = self.daemon(name)
        self.signal_process(process, signal.SIGTERM)
        process.wait(timeout=30)
        self.children[index] = (process, log, False)

    def restart_daemon(self, name):
        log = self.new_log(name + "-restart-" + str(len(self.windows_applied)) + ".log")
        process = subprocess.Popen(
            [str(core.WAZUH / "bin" / name), "-f"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=base.SUBPROCESS_ENV,
            cwd=core.WAZUH,
            start_new_session=True,
        )
        self.children.append((process, log, True))
        if name in base.SOCKETS:
            self.wait_socket(base.SOCKETS[name])

    def apply_windows(self):
        now = self.offset_ms()
        if now is None:
            return
        done = {(w["component"], w["action"]) for w in self.windows_applied}
        for window in sorted(self.plan["windows"], key=lambda w: w["at_ms"]):
            key = (window["component"], window["action"])
            if key in done or now < window["at_ms"]:
                continue
            names = WINDOW_DAEMONS[window["component"]]
            if window["action"] == "stop":
                for name in names:
                    self.stop_daemon(name)
            else:
                # Analysis before collection, so restarted reads have a consumer.
                for name in reversed(names):
                    self.restart_daemon(name)
            self.windows_applied.append({**window, "applied_ms": self.offset_ms()})
            done.add(key)

    def run(self):
        self.prepare()
        log = self.new_log("analysisd-config.log")
        command = subprocess.Popen(
            [str(core.WAZUH / "bin/wazuh-analysisd"), "-t"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=base.SUBPROCESS_ENV,
            cwd=core.WAZUH,
            start_new_session=True,
        )
        self.children.append((command, log, False))
        require(command.wait(timeout=8) == 0, "native_collector_config_rejected")
        for daemon in core.DAEMONS[:2]:
            self.start_daemon(daemon)
            self.wait_socket(base.SOCKETS[daemon])
        self.start_daemon(core.DAEMONS[2])
        coverage = None
        while time.monotonic() < self.deadline and not STOP.exists():
            self.check_budget()
            self.apply_windows()
            coverage = self.poll_records()
            self.heartbeat(coverage)
            time.sleep(1)
        self.report["coverage"] = coverage
        self.report["windows_applied"] = self.windows_applied
        self.report["stop_reason"] = "runner_stop" if STOP.exists() else "deadline"


def main():
    require(len(sys.argv) == 1, "native_collector_arguments_not_supported")
    pilot = ContinuousCollector()

    def limit(_signal, _frame):
        raise base.PilotFailure("native_collector_hard_limit")

    signal.signal(signal.SIGALRM, limit)
    signal.alarm(HARD_SECONDS)
    try:
        pilot.run()
        pilot.report["status"], pilot.report["failure_code"] = "captured_pending_host_ledger", None
    except (base.PilotFailure, ValueError) as error:
        safe = isinstance(error, EnterpriseWazuhError) and re.fullmatch(
            r"(?:native_collector|collector_kernel)_[a-z_]{1,64}", str(error)
        )
        pilot.report["failure_code"] = (
            str(error)
            if isinstance(error, base.PilotFailure) or safe
            else "native_collector_control_rejected"
        )
    except (OSError, KeyError, TypeError, subprocess.SubprocessError, sqlite3.Error):
        pilot.report["failure_code"] = "native_collector_dependency_or_filesystem_failure"
    finally:
        try:
            pilot.cleanup()
        except (OSError, ValueError, base.PilotFailure):
            pilot.report["owned_processes_stopped"] = False
        signal.alarm(0)
    if not pilot.report["owned_processes_stopped"]:
        pilot.report["failure_code"] = "native_collector_process_shutdown_incomplete"
    if pilot.evidence_bound:
        try:
            # Daemons are stopped: drain and seal every pinned generation.
            for captured in pilot.captures.values():
                captured.drain(seal=True)
                captured.close()
            pilot.journal.verify()
            for kind in pilot.last:
                raw = pilot.journal.captured(kind, limit=CAPTURE_BYTES)
                require(not raw or raw.endswith(b"\n"), "native_collector_capture_incomplete")
                with (core.EVIDENCE / f"native-{kind}s.jsonl").open("xb") as output:
                    output.write(raw)
        except (OSError, ValueError, sqlite3.Error):
            pilot.report["failure_code"] = (
                pilot.report["failure_code"] or "native_collector_capture_incomplete"
            )
        finally:
            for captured in pilot.captures.values():
                captured.close()
            pilot.journal.close()
        if pilot.report["failure_code"]:
            pilot.report["status"] = "failed"
        pilot.report["finished_at"] = datetime.now(timezone.utc).isoformat()
        pilot.report["duration_seconds"] = round(time.monotonic() - pilot.started, 3)
        with (core.EVIDENCE / "native-report.json").open("xb") as output:
            output.write(canonical(pilot.report) + b"\n")
    passed = pilot.report["failure_code"] is None and pilot.report["owned_processes_stopped"]
    print(json.dumps({"status": pilot.report["status"], "passed_pending_host_ledger": passed}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
