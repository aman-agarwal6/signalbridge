"""Two fresh native ZAP processes for reviewed offline synthetic capture analysis.

No container control, source connection, credential input or add-on installation.
The host must separately verify the source input, isolated runtime and shutdown.
"""

import hashlib
import http.client
import math
import os
import secrets
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# Direct execution is restricted before importing anything from the snapshot.
if __name__ == "__main__" and not __package__:
    if sys.platform != "linux" or Path(__file__).resolve() != Path(
        "/workspace/integrations/zap_enterprise/scanner_runner.py"
    ):
        raise SystemExit("A separately reviewed offline scanner container is required.")
    sys.path.insert(0, "/workspace")

from bridge.contract import parse_json, timestamp
from integrations.enterprise.reference_kernel import CGROUPS
from integrations.zap.run_passive import collect_log, private_write, safe_directory
from integrations.zap_enterprise.capture import PROFILE, require, validate_rows
from integrations.zap_enterprise.passive import analyze_phase
from integrations.zap_enterprise.scanner_contract import (
    INPUT_BYTES,
    TRANSCRIPT_BYTES,
    TranscriptClient,
    hex_value,
    receipt_bytes,
    validate_addons,
    validate_gate,
    validate_input,
    verify_kernel,
)

INPUT, OUTPUT, RUNTIME = (
    Path("/input"),
    Path("/evidence"),
    Path("/tmp/signalbridge-zap-authenticated"),
)
PHASES = ("fault", "corrected")
TOTAL_SECONDS, PHASE_SECONDS, STARTUP_SECONDS = 540, 240, 60
LIMITS = (
    "Host must verify the actual source run, cached image, selected source and both shutdown receipts.",
    "Only rule 10021 analyzes credential-free captured responses; there are no source connections or active requests.",
    "Local runtime files are consistency evidence within the trusted operator boundary, not independent attestation.",
)
OUTPUTS = {"scanner-kernel.json", "scanner-runner.json"} | {
    phase + suffix
    for phase in PHASES
    for suffix in ("-api.json", "-analysis.json", "-process.json", "-process.log")
}


def runtime_gate():
    require(
        sys.platform == "linux"
        and os.getuid() == os.getgid() == 1000
        and Path("/.dockerenv").is_file()
        and Path(__file__).resolve()
        == Path("/workspace/integrations/zap_enterprise/scanner_runner.py")
        and os.environ.get("SB_ZAP_SOURCE_PROOF") == "1"
        and len(sys.argv) == 1
        and (3, 11) <= sys.version_info[:2] < (3, 15)
    )
    run = hex_value(os.environ.get("SB_ZAP_RUN"), 32)
    safe_directory(INPUT)
    safe_directory(OUTPUT)
    require({p.name for p in INPUT.iterdir()} == {"source-capture.json"})
    require({p.name for p in OUTPUT.iterdir()} == {"allow-scanner.json"})
    return run


def read_closed(path, bound):
    require(path.is_file() and not path.is_symlink() and path.resolve() == path)
    require(0 < path.stat().st_size <= bound)
    raw = path.read_bytes()
    require(len(raw) <= bound)
    return raw, parse_json(raw)


def save(name, value):
    require(name in OUTPUTS)
    raw = receipt_bytes(value)
    bound = TRANSCRIPT_BYTES + 65536 if name.endswith("-api.json") else 262144
    require(len(raw) <= bound)
    private_write(OUTPUT / name, raw)
    return hashlib.sha256(raw).hexdigest()


def child_environment(directory):
    # Do not inherit Java options, proxies, source credentials or key logging.
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(directory),
        "LANG": "C.UTF-8",
        "TZ": "UTC",
    }


def command(directory):
    require(directory in {RUNTIME / phase for phase in PHASES})
    return [
        "/zap/zap.sh",
        "-Xmx1536m",
        "-daemon",
        "-silent",
        "-host",
        "127.0.0.1",
        "-port",
        "8080",
        "-dir",
        str(directory / "zap-home"),
        "-configfile",
        str(directory / "private.properties"),
        "-loglevel",
        "WARN",
    ]


def group_present(identifier):
    try:
        os.killpg(identifier, 0)
        return True
    except ProcessLookupError:
        return False


def stop_child(child):
    if child is None:
        return {"stopped": True, "forced": False, "exit_code": None}
    require(type(child.pid) is int and child.pid > 1)
    forced = False
    try:
        if child.poll() is None:
            require(os.getpgid(child.pid) == child.pid, "The owned ZAP process group changed.")
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            forced = True
        if group_present(child.pid):
            forced = True
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
        deadline = time.monotonic() + 2
        while group_present(child.pid) and time.monotonic() < deadline:
            time.sleep(0.1)
        return {
            "stopped": not group_present(child.pid),
            "forced": forced,
            "exit_code": child.returncode,
        }
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"stopped": False, "forced": forced, "exit_code": child.poll()}


def ready(client, child, overflow):
    deadline, attempts = min(client.deadline, time.monotonic() + STARTUP_SECONDS), 0
    while time.monotonic() < deadline and attempts < 60:
        require(child.poll() is None and not overflow.is_set())
        attempts += 1
        try:
            require(client.api("core", "view", "version") == {"version": "2.17.0"})
            return attempts
        except (ConnectionError, TimeoutError, http.client.HTTPException):
            time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise ValueError("The native ZAP readiness deadline expired.")


def run_phase(phase, rows, captured_at, overall_deadline):
    now = time.monotonic()
    require(
        phase in PHASES
        and type(overall_deadline) in (int, float)
        and math.isfinite(overall_deadline)
        and 45 <= overall_deadline - now <= TOTAL_SECONDS
    )
    validate_rows(rows, phase)
    require(timestamp(captured_at) <= datetime.now(timezone.utc))
    started, key = time.monotonic(), secrets.token_hex(32)
    directory = RUNTIME / phase
    directory.mkdir(mode=0o700)
    safe_directory(directory)
    private_write(
        directory / "private.properties",
        (
            f"api.key={key}\napi.disablekey=false\napi.addrs.addr.name=127.0.0.1\n"
            "api.addrs.addr.regex=false\nstart.checkForUpdates=false\nstart.checkAddonUpdates=false\n"
            "start.downloadNewRelease=false\nstart.installAddonUpdates=false\nstart.installScannerRules=false\n"
        ).encode("ascii"),
    )
    client = TranscriptClient(key, min(started + PHASE_SECONDS - 30, overall_deadline - 45))
    process, collector, analysis = None, None, None
    overflow, result = threading.Event(), {"phase": phase, "completed": False}
    try:
        process = subprocess.Popen(
            command(directory),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=child_environment(directory),
            shell=False,
            start_new_session=True,
        )
        collector = threading.Thread(
            target=collect_log,
            args=(process.stdout, OUTPUT / (phase + "-process.log"), overflow, key),
            daemon=True,
        )
        collector.start()
        result["readiness_attempts"] = ready(client, process, overflow)
        result["installed_addons"] = validate_addons(
            client.api("autoupdate", "view", "installedAddons")
        )
        analysis = analyze_phase(client, rows, phase, captured_at)
        require(process.poll() is None and not overflow.is_set())
        result["api_evidence_validated"] = True
    except Exception as error:
        result["error_class"] = type(error).__name__
    finally:
        shutdown = stop_child(process)
        result["process_shutdown"] = shutdown
        if collector is not None:
            collector.join(timeout=3)
        result.update(
            log_overflow=overflow.is_set(),
            log_collector_stopped=collector is None or not collector.is_alive(),
            api_calls=client.calls,
            duration_seconds=round(time.monotonic() - started, 3),
        )
        result["completed"] = bool(
            result.get("api_evidence_validated") is True
            and shutdown["stopped"] is True
            and shutdown["forced"] is False
            and shutdown["exit_code"] in (0, -signal.SIGTERM, 143)
            and not result["log_overflow"]
            and result["log_collector_stopped"]
            and result["duration_seconds"] <= PHASE_SECONDS
        )
        result["transcript_sha256"] = save(phase + "-api.json", client.transcript)
        if analysis is not None:
            result["analysis_sha256"] = save(phase + "-analysis.json", analysis)
        save(phase + "-process.json", result)
    return result


def main():
    run, started = runtime_gate(), time.monotonic()
    os.umask(0o077)
    result = {
        "schema_version": 1,
        "profile": PROFILE,
        "run_id": run,
        "completed": False,
        "source_capture_attested": False,
        "runtime_attested": False,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "phases": [],
        "limits": list(LIMITS),
    }
    try:
        kernel = verify_kernel(
            Path("/proc/self/status").read_text(encoding="ascii"),
            {name: (Path("/sys/fs/cgroup") / name).read_text(encoding="ascii") for name in CGROUPS},
            Path("/proc/self/mountinfo").read_text(encoding="ascii"),
            sorted(p.name for p in Path("/sys/class/net").iterdir()),
        )
        result["kernel_sha256"] = save("scanner-kernel.json", kernel)
        raw, value = read_closed(INPUT / "source-capture.json", INPUT_BYTES)
        validate_input(value)
        _, gate = read_closed(OUTPUT / "allow-scanner.json", 4096)
        validate_gate(gate, run, value, raw)
        result.update(
            input_sha256=hashlib.sha256(raw).hexdigest(),
            source_run_id=value["source_run_id"],
            source_receipt_sha256=value["source_receipt_sha256"],
        )
        RUNTIME.mkdir(mode=0o700)
        safe_directory(RUNTIME)
        for phase in PHASES:
            outcome = run_phase(
                phase,
                value["phases"][phase],
                value["execution"]["captured_at"],
                started + TOTAL_SECONDS,
            )
            result["phases"].append(outcome)
            require(outcome["completed"] is True)
        require(result["phases"][0]["installed_addons"] == result["phases"][1]["installed_addons"])
        result["completed"] = True
    except Exception as error:
        result["error_class"] = type(error).__name__
    finally:
        result.update(
            duration_seconds=round(time.monotonic() - started, 3),
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        result["completed"] = bool(
            result["completed"] and result["duration_seconds"] <= TOTAL_SECONDS
        )
        save("scanner-runner.json", result)
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
