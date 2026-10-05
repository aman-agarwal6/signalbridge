"""Bounded ownership of one reviewed Docker Desktop acquisition, Windows only.

Usage by an authorized operator: ``with DesktopStartup(...) as guard:`` then
``guard.start()`` and ``guard.check("acquisition")`` around approved acquisition.
The independent watchdog is armed before start. Scope exit stops the Desktop we
started; there is deliberately no handoff, download, image or container API.
Approval references record authorization; they do not grant it. Import is inert.
"""

import argparse
import ctypes
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from integrations.enterprise.reference_host_controls import INITIAL_DISK, read_json
from integrations.enterprise.verification import GIB, LabControlError, private_run_directory
from integrations.enterprise.windows_capacity import available_memory
from scripts.enterprise_reference_verify import POWERSHELL, clean_environment, private_acl

ROOT = Path(__file__).resolve().parents[2]
ACTIVE_SECONDS, CLEANUP_SECONDS, STABLE_SECONDS = 600, 120, 30
FILES = {"context", "ready", "intent", "abort", "finished", "phase", "watchdog", "launcher"}
REQUIRED_PATHS = {
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "PROGRAMDATA",
}


def require(condition):
    if not condition:
        raise LabControlError(
            "Docker Desktop acquisition guard refused an unsafe or unknown state."
        )


def environment():
    """Never invent missing Windows folders or inherit proxy/credential inputs."""
    value = clean_environment()
    normalized = {name.upper(): item for name, item in value.items()}
    require(REQUIRED_PATHS | {"SYSTEMDRIVE"} <= set(normalized))
    drive = normalized["SYSTEMDRIVE"]
    require(isinstance(drive, str) and re.fullmatch(r"[A-Za-z]:", drive))
    # C: alone is drive-relative on Windows. Validate the absolute C:\\ root,
    # without treating the drive prefix itself as an absolute directory.
    root = Path(drive + "\\")
    require(root.is_absolute() and root.is_dir())
    for name in REQUIRED_PATHS:
        item = normalized[name]
        require(isinstance(item, str) and 0 < len(item) <= 32768 and "\x00" not in item)
        require(Path(item).is_absolute() and Path(item).is_dir())
    require(bool(normalized.get("PATH")))
    return value


def control(directory, name, value):
    require(name in FILES)
    target = directory / ("desktop-" + name + ".json")
    require(not target.exists() and not target.is_symlink())
    raw = (json.dumps(value, sort_keys=True) + "\n").encode("ascii")
    require(len(raw) <= 262144)
    temporary = target.with_suffix(".tmp")
    with temporary.open("xb") as output:
        output.write(raw)
    temporary.replace(target)


def load(directory, name):
    require(name in FILES)
    return read_json(directory / ("desktop-" + name + ".json"), 262144)


def present(directory, name):
    path = directory / ("desktop-" + name + ".json")
    return path.exists() or path.is_symlink()


def sample(baseline, before_start=False):
    disk, memory = shutil.disk_usage(ROOT).free, available_memory()
    value = {
        "at": datetime.now(timezone.utc).isoformat(),
        "free_disk_bytes": disk,
        "available_memory_bytes": memory,
        "stage_free_space_decrease_bytes": max(0, baseline - disk),
        "milestone_free_space_decrease_bytes": max(0, INITIAL_DISK - disk),
    }
    value["within_limits"] = bool(
        disk >= 25 * GIB
        and memory >= (7 if before_start else 4) * GIB
        and baseline - disk < 4 * GIB
        and INITIAL_DISK - disk < 30 * GIB
        and (not before_start or disk >= 25 * GIB + 4 * GIB - max(0, baseline - disk))
    )
    return value


def command(docker, arguments, env, timeout=3):
    """Bounded read/control output only; never retain raw engine diagnostics."""
    result = subprocess.run(
        [str(docker), *arguments],
        env=env,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        shell=False,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    require(result.returncode == 0 and len(result.stdout) <= 16384 and len(result.stderr) <= 16384)
    return result.stdout.decode("utf8", errors="strict").strip()


def desktop_process_count(env):
    """Read only known Desktop lifecycle processes; query failure is unknown."""
    query = (
        "$ErrorActionPreference='Stop';"
        "$items=@(Get-CimInstance Win32_Process -ErrorAction Stop -Filter "
        "\"Name='Docker Desktop.exe' OR Name='com.docker.backend.exe' OR "
        "Name='com.docker.build.exe' OR Name='com.docker.proxy.exe' OR Name='DockerCli.exe'\");"
        "@{desktop_process_count=$items.Count}|ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", query],
        env=env,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=3,
        shell=False,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    require(result.returncode == 0 and len(result.stdout) <= 1024 and len(result.stderr) <= 1024)
    value = json.loads(result.stdout)
    require(type(value) is dict and set(value) == {"desktop_process_count"})
    count = value["desktop_process_count"]
    require(type(count) is int and 0 <= count <= 100)
    return count


def engine_pipe_absent():
    """One non-opening kernel query; access denied is never absence evidence."""
    require(sys.platform == "win32")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    wait = kernel.WaitNamedPipeW
    wait.argtypes, wait.restype = [ctypes.c_wchar_p, ctypes.c_uint32], ctypes.c_int
    ctypes.set_last_error(0)
    result = wait(r"\\.\pipe\dockerDesktopLinuxEngine", 1)
    if result:
        return False
    error = ctypes.get_last_error()
    if error == 2:  # ERROR_FILE_NOT_FOUND, rather than unavailable/busy/access denied.
        return True
    if error in {121, 231}:  # Existing pipe, timeout or busy.
        return False
    raise LabControlError("Docker Desktop engine-pipe state could not be established.")


def desktop_status(docker, env, timeout=3, capture=None):
    try:
        raw = command(docker, ["desktop", "status", "--format", "json"], env, timeout)
    except (LabControlError, subprocess.TimeoutExpired, OSError, UnicodeError):
        # Installed Desktop exits nonzero when completely stopped. A CLI failure
        # alone is not admission evidence; independently prove process/pipe absence.
        count, absent = desktop_process_count(env), engine_pipe_absent()
        require(count == 0 and absent is True)
        if capture is not None:
            capture.update(
                status="stopped",
                source="windows_process_and_pipe_absence",
                desktop_process_count=0,
                linux_engine_pipe_absent=True,
            )
        return "stopped"
    value = json.loads(raw)
    require(type(value) is dict)
    keys = set(value) - {"SessionID"}
    require(len(keys) == 1)
    key = next(iter(keys))
    require(
        key in {"Status", "status"} and value[key] in {"running", "stopped", "starting", "stopping"}
    )
    if "SessionID" in value:
        require(
            isinstance(value["SessionID"], str)
            and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value["SessionID"])
        )
    if capture is not None:
        capture.update(status=value[key], source="desktop_cli_status")
    return value[key]


def inventory(docker, env):
    """No containers belong to an acquisition; every running workload is foreign."""
    try:
        raw = command(
            docker,
            ["--host", "npipe:////./pipe/dockerDesktopLinuxEngine", "ps", "--quiet", "--no-trunc"],
            env,
            timeout=2,
        )
        rows = raw.splitlines() if raw else []
        require(len(rows) <= 100 and all(re.fullmatch(r"[a-f0-9]{64}", row) for row in rows))
        return "foreign" if rows else "empty"
    except Exception:
        return "unavailable"


def shutdown_owned(docker, env, deadline, observe=None):
    """Stop our owned startup even if the daemon never admitted an inventory.

    Never stop a reachable foreign workload. CLI timeout does not prove a daemon
    operation ended; recheck for late startup during a finite quiet interval.
    """
    result = {
        "shutdown_verified": False,
        "desktop_stop_requested": False,
        "foreign_workload_preserved": False,
        "inventory_unavailable_seen": False,
        "cli_timeout_seen": False,
        "daemon_request_settlement_verified": False,
        "stopped_observation_seconds": 0,
    }
    stop_at = time.monotonic() + max(0, min(CLEANUP_SECONDS, deadline - time.time()))
    stable = None
    while time.time() < deadline and time.monotonic() < stop_at:
        if observe is not None:
            try:
                observe("cleanup")
            except Exception as error:
                result["last_capacity_error_class"] = type(error).__name__
        state = inventory(docker, env)
        if state == "foreign":
            result["foreign_workload_preserved"] = True
            result["reason"] = "reachable_foreign_workload"
            return result
        result["inventory_unavailable_seen"] |= state == "unavailable"
        remaining = min(deadline - time.time(), stop_at - time.monotonic())
        if remaining <= 0:
            break
        # This call is intentionally independent of successful engine inventory.
        result["desktop_stop_requested"] = True
        try:
            command(docker, ["desktop", "stop", "--timeout", "15"], env, timeout=min(20, remaining))
        except subprocess.TimeoutExpired:
            result["cli_timeout_seen"] = True
            result["last_stop_error_class"] = "TimeoutExpired"
        except Exception as error:
            result["last_stop_error_class"] = type(error).__name__
        try:
            remaining = min(deadline - time.time(), stop_at - time.monotonic())
            require(remaining > 0)
            observation = {}
            status = desktop_status(docker, env, timeout=min(3, remaining), capture=observation)
            result["last_desktop_observation"] = observation
        except Exception as error:
            status = "unknown"
            result["last_status_error_class"] = type(error).__name__
        if status == "stopped":
            stable = time.monotonic() if stable is None else stable
            result["stopped_observation_seconds"] = round(time.monotonic() - stable, 3)
            if time.monotonic() - stable >= STABLE_SECONDS:
                result.update(
                    shutdown_verified=True, reason="observed_stopped_during_bounded_drain"
                )
                return result
        else:
            stable = None
        time.sleep(min(2, max(0, stop_at - time.monotonic())))
    result["reason"] = "shutdown_not_verified_before_deadline"
    return result


def watchdog(run, docker, deadline):
    directory = private_run_directory(ROOT, run)
    require(directory.is_dir())
    receipt = {
        "run_id": run,
        "kind": "docker-desktop-startup-watchdog",
        "shutdown_verified": False,
        "samples": [],
        "phase": "armed",
        "sampled_guards_are_hard_quotas": False,
    }
    env = None
    baseline = None

    def observe(phase):
        if baseline is not None and len(receipt["samples"]) < 800:
            value = sample(baseline)
            receipt["samples"].append({"phase": phase, **value})
            return value["within_limits"]
        return False

    try:
        require(
            type(deadline) in (int, float)
            and math.isfinite(deadline)
            and 0 < deadline - time.time() <= ACTIVE_SECONDS + CLEANUP_SECONDS
        )
        env = environment()
        private_acl(run, "Verify")
        context = load(directory, "context")
        require(
            context["run_id"] == run
            and context["deadline"] == deadline
            and context["initial_desktop_status"] == "stopped"
        )
        baseline = context["stage_initial_free_disk_bytes"]
        require(type(baseline) is int and baseline > 0)
        require(desktop_status(docker, env) == "stopped" and inventory(docker, env) != "foreign")
        require(observe("armed"))
        control(directory, "ready", {"run_id": run, "armed": True})
        stop_at = time.monotonic() + max(0, deadline - time.time() - CLEANUP_SECONDS)
        while time.time() < deadline - CLEANUP_SECONDS and time.monotonic() < stop_at:
            if present(directory, "finished"):
                require(load(directory, "finished") == {"run_id": run})
                receipt["reason"] = "launcher_finished"
                break
            if present(directory, "abort"):
                receipt["reason"] = "launcher_abort"
                break
            if present(directory, "intent"):
                require(load(directory, "intent") == {"run_id": run, "start_requested": True})
                receipt["phase"] = "startup"
            if present(directory, "phase"):
                require(load(directory, "phase") == {"run_id": run, "phase": "acquisition"})
                receipt["phase"] = "acquisition"
            require(observe(receipt["phase"]))
            if present(directory, "intent"):
                require(inventory(docker, env) != "foreign")
            time.sleep(1)
        else:
            receipt["reason"] = "active_deadline"
    except Exception as error:
        receipt.update(reason="guard_failure", error_class=type(error).__name__)
    finally:
        try:
            if not present(directory, "abort"):
                control(directory, "abort", {"run_id": run, "reason": "scope_closed"})
        except Exception as error:
            receipt["abort_marker_error_class"] = type(error).__name__
        # A malformed context or capacity failure must not bypass stop after our
        # recorded start intent. Environment failure before start remains inert.
        if env is not None and present(directory, "intent"):
            try:
                require(load(directory, "intent") == {"run_id": run, "start_requested": True})
                receipt["shutdown"] = shutdown_owned(docker, env, deadline, observe)
                receipt["shutdown_verified"] = receipt["shutdown"]["shutdown_verified"]
            except Exception as error:
                receipt["shutdown_error_class"] = type(error).__name__
        else:
            receipt["reason"] = "no_owned_start_intent"
        receipt["finished_at"] = datetime.now(timezone.utc).isoformat()
        control(directory, "watchdog", receipt)
    return receipt


class DesktopStartup:
    """One guarded acquisition; never adopt an already running Docker Desktop."""

    def __init__(self, docker, approval_reference, stage_initial_free_disk_bytes):
        self.docker = Path(docker)
        self.approval = approval_reference
        self.baseline = stage_initial_free_disk_bytes
        self.process = self.guard = None
        self.started = False
        self.samples = []

    def __enter__(self):
        require(sys.platform == "win32")
        self.env = environment()  # Missing ProgramData fails before any subprocess.
        require(
            self.docker.is_absolute()
            and self.docker.is_file()
            and not self.docker.is_symlink()
            and not getattr(self.docker.lstat(), "st_file_attributes", 0) & 0x400
        )
        require(re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", self.approval))
        require(type(self.baseline) is int and self.baseline > 0)
        first = sample(self.baseline, before_start=True)
        self.samples.append({"phase": "armed", **first})
        require(first["within_limits"] and self.baseline >= first["free_disk_bytes"])
        observation = {}
        require(desktop_status(self.docker, self.env, capture=observation) == "stopped")
        require(inventory(self.docker, self.env) != "foreign")
        self.run = uuid.uuid4().hex
        self.directory = private_run_directory(ROOT, self.run)
        self.directory.mkdir(parents=True, exist_ok=False)
        private_acl(self.run, "SecureEmpty")
        self.deadline = time.time() + ACTIVE_SECONDS + CLEANUP_SECONDS
        control(
            self.directory,
            "context",
            {
                "run_id": self.run,
                "approval_reference": self.approval,
                "deadline": self.deadline,
                "initial_desktop_status": "stopped",
                "initial_desktop_observation": observation,
                "stage_initial_free_disk_bytes": self.baseline,
                "capacity_before": first,
            },
        )
        self.guard = subprocess.Popen(
            [
                sys.executable,
                "-B",
                "-m",
                __name__,
                "watchdog",
                "--run",
                self.run,
                "--docker",
                str(self.docker),
                "--deadline",
                str(self.deadline),
            ],
            env=self.env,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        )
        try:
            until = time.monotonic() + 40
            while not present(self.directory, "ready"):
                require(self.guard.poll() is None and time.monotonic() < until)
                require(not present(self.directory, "abort"))
                time.sleep(0.25)
            require(load(self.directory, "ready") == {"run_id": self.run, "armed": True})
            self.check("armed")
            return self
        except Exception:
            self.__exit__(*sys.exc_info())
            raise

    def check(self, phase):
        require(phase in {"armed", "startup", "acquisition"})
        require(self.guard is not None and self.guard.poll() is None)
        require(
            not present(self.directory, "abort") and time.time() < self.deadline - CLEANUP_SECONDS
        )
        measured = sample(self.baseline)
        if len(self.samples) < 800:
            self.samples.append({"phase": phase, **measured})
        require(measured["within_limits"])

    def start(self):
        self.check("startup")
        require(not self.started and desktop_status(self.docker, self.env) == "stopped")
        measured = sample(self.baseline, before_start=True)
        self.samples.append({"phase": "startup", **measured})
        require(measured["within_limits"])
        control(self.directory, "intent", {"run_id": self.run, "start_requested": True})
        self.check("startup")
        self.started = True
        self.process = subprocess.Popen(
            [str(self.docker), "desktop", "start", "--timeout", "90"],
            env=self.env,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        until = time.monotonic() + 110
        while self.process.poll() is None:
            self.check("startup")
            require(time.monotonic() < until)
            time.sleep(0.5)
        require(self.process.returncode == 0)
        self.check("startup")
        require(desktop_status(self.docker, self.env) == "running")
        require(inventory(self.docker, self.env) == "empty")
        control(self.directory, "phase", {"run_id": self.run, "phase": "acquisition"})

    def __exit__(self, error_type, error, traceback):
        receipt = {
            "run_id": self.run,
            "start_requested": self.started,
            "error_class": error_type.__name__ if error_type else None,
            "shutdown_verified": False,
            "guard_pending": False,
            "samples": self.samples,
            "sampled_guards_are_hard_quotas": False,
        }
        try:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()  # Only our CLI child; not the Desktop daemon.
                self.process.wait(timeout=5)
                receipt["start_cli_terminated"] = True
                receipt["daemon_request_settlement_verified"] = False
        except Exception as stop_error:
            receipt["cli_error_class"] = type(stop_error).__name__
        finally:
            if not present(self.directory, "finished"):
                control(self.directory, "finished", {"run_id": self.run})
            if self.guard is not None:
                try:
                    self.guard.wait(timeout=CLEANUP_SECONDS + 10)
                    independent = load(self.directory, "watchdog")
                    receipt["shutdown_verified"] = independent.get("shutdown_verified") is True
                except Exception as guard_error:
                    receipt["guard_error_class"] = type(guard_error).__name__
                    receipt["guard_pending"] = self.guard.poll() is None
            control(self.directory, "launcher", receipt)
        if error_type is None:
            require(receipt["shutdown_verified"] or not self.started)
        return False


def main():
    require(sys.platform == "win32")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["watchdog"])
    parser.add_argument("--run", required=True)
    parser.add_argument("--docker", type=Path, required=True)
    parser.add_argument("--deadline", type=float, required=True)
    options = parser.parse_args()
    return 0 if watchdog(options.run, options.docker, options.deadline)["shutdown_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
