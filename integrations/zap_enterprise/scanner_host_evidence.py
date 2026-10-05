"""Bounded read-only recomputation of scanner receipts, never native attestation.

No sockets, subprocesses, imports to the console or write operations. The host
controller must separately establish the source run, effective container and
both shutdowns. An administrator can fabricate an internally consistent archive.
"""

import hashlib
import math
import time

from bridge.contract import parse_json, timestamp
from integrations.enterprise.reference_host_controls import same
from integrations.enterprise.reference_host_evidence import safe_path, validate_snapshot
from integrations.enterprise.verification import private_run_directory, validate_identity

from .capture import PROFILE, require
from .passive import API_BYTES, MAX_CALLS, Client, analyze_phase, validate_request
from .scanner_contract import (
    INPUT_BYTES,
    MEMORY,
    TRANSCRIPT_BYTES,
    receipt_bytes,
    validate_addons,
    validate_gate,
    validate_input,
)
from .scanner_runner import LIMITS, OUTPUTS, PHASE_SECONDS, PHASES, TOTAL_SECONDS

FILES = OUTPUTS | {"allow-scanner.json"}
PHASE_FIELDS = {
    "phase",
    "completed",
    "readiness_attempts",
    "installed_addons",
    "api_evidence_validated",
    "process_shutdown",
    "log_overflow",
    "log_collector_stopped",
    "api_calls",
    "duration_seconds",
    "transcript_sha256",
    "analysis_sha256",
}
RUNNER_FIELDS = {
    "schema_version",
    "profile",
    "run_id",
    "completed",
    "source_capture_attested",
    "runtime_attested",
    "started_at",
    "phases",
    "limits",
    "kernel_sha256",
    "input_sha256",
    "source_run_id",
    "source_receipt_sha256",
    "duration_seconds",
    "finished_at",
}
READINESS_ERRORS = frozenset(
    (
        "ConnectionError",
        "ConnectionRefusedError",
        "ConnectionResetError",
        "ConnectionAbortedError",
        "BrokenPipeError",
        "TimeoutError",
        "HTTPException",
        "RemoteDisconnected",
        "IncompleteRead",
        "BadStatusLine",
        "LineTooLong",
        "CannotSendRequest",
        "CannotSendHeader",
        "ResponseNotReady",
        "NotConnected",
        "UnknownProtocol",
        "UnknownTransferEncoding",
        "UnimplementedFileMode",
        "ImproperConnectionState",
    )
)


def duration(value, bound):
    require(type(value) in (int, float) and math.isfinite(value) and 0 < value <= bound)
    return value


class ReplayClient(Client):
    """Reuse the closed API/parser against recorded bytes without network access."""

    def __init__(self, entries):
        require(isinstance(entries, list) and 1 <= len(entries) <= MAX_CALLS)
        require(all(isinstance(entry, dict) for entry in entries))
        require(len(receipt_bytes(entries)) <= TRANSCRIPT_BYTES + 65536)
        require(sum(len(receipt_bytes(entry)) for entry in entries) <= TRANSCRIPT_BYTES)
        self.entries, self.calls, self.elapsed_seconds = entries, 0, 0.0
        # The live deadline is a local validation bound, not reconstructed latency.
        self.deadline = time.monotonic() + 10

    def request(self, method, path, body=None):
        validate_request(method, path, body)
        require(self.calls < len(self.entries) and time.monotonic() < self.deadline)
        entry = self.entries[self.calls]
        self.calls += 1
        require(
            isinstance(entry, dict) and entry.get("method") == method and entry.get("path") == path
        )
        require(len(receipt_bytes(entry)) <= API_BYTES + 8192)
        if "error_class" in entry:
            require(
                set(entry) == {"method", "path", "error_class", "calls_attempted"}
                and type(entry["calls_attempted"]) is int
                and entry["calls_attempted"] == self.calls
                and method == "GET"
                and path == "/JSON/core/view/version/"
                and isinstance(entry["error_class"], str)
                and entry["error_class"] in READINESS_ERRORS
            )
            # Only readiness can consume this sentinel. No arbitrary exception
            # name is imported, evaluated or reconstructed from untrusted input.
            raise ConnectionError("Recorded readiness attempt did not return a response.")
        fields = {"method", "path", "response", "elapsed_seconds"}
        if body is not None:
            fields.add("body_sha256")
            require(entry.get("body_sha256") == hashlib.sha256(body).hexdigest())
        require(set(entry) == fields)
        value, elapsed = entry["response"], entry["elapsed_seconds"]
        require(isinstance(value, dict) and "code" not in value)
        require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 6)
        self.elapsed_seconds += elapsed
        return value


def revalidate_phase(entries, process, analysis, rows, phase, captured_at, hashes):
    """Strict successful-phase gate; partial archives remain retained elsewhere."""
    require(isinstance(process, dict) and set(process) == PHASE_FIELDS)
    client = ReplayClient(entries)
    require(
        process["phase"] == phase
        and process["completed"] is True
        and process["api_evidence_validated"] is True
        and process["log_overflow"] is False
        and process["log_collector_stopped"] is True
    )
    shutdown = process["process_shutdown"]
    require(
        isinstance(shutdown, dict)
        and set(shutdown) == {"stopped", "forced", "exit_code"}
        and shutdown["stopped"] is True
        and shutdown["forced"] is False
        and type(shutdown["exit_code"]) is int
        and shutdown["exit_code"] in (0, -15, 143)
    )
    duration(process["duration_seconds"], PHASE_SECONDS)
    require(type(process["readiness_attempts"]) is int and 1 <= process["readiness_attempts"] <= 60)
    require(type(process["api_calls"]) is int and process["api_calls"] == len(entries))
    require(process["transcript_sha256"] == hashes[phase + "-api.json"])
    require(process["analysis_sha256"] == hashes[phase + "-analysis.json"])
    for attempt in range(process["readiness_attempts"]):
        last = attempt + 1 == process["readiness_attempts"]
        try:
            response = client.api("core", "view", "version")
        except ConnectionError:
            require(not last)
        else:
            require(last and response == {"version": "2.17.0"})
    addons = validate_addons(client.api("autoupdate", "view", "installedAddons"))
    require(same(addons, process["installed_addons"]))
    recomputed = analyze_phase(client, rows, phase, captured_at, pause=lambda _: None)
    require(client.calls == len(entries), "Extra scanner exchanges are outside the fixed profile.")
    require(same(analysis, recomputed), "Recomputed scanner result differs from the saved finding.")
    require(client.elapsed_seconds <= process["duration_seconds"] + 0.01)
    return {"analysis": recomputed, "installed_addons": addons}


def read_receipt(path, root, bound, *, text=False):
    checked = safe_path(path, root)
    require(checked.is_file() and 0 <= checked.stat().st_size <= bound)
    size = checked.stat().st_size
    raw = checked.read_bytes()
    require(len(raw) == size, "Scanner receipt changed while being read.")
    value = None if text else parse_json(raw)
    return value, hashlib.sha256(raw).hexdigest(), raw


def validate_receipts(workspace, run, manifest, *, now):
    """Read only this private run. Returned flags deliberately stay unattested."""
    validate_identity(run)
    directory = private_run_directory(workspace, run)
    require(
        isinstance(manifest, dict)
        and isinstance(manifest.get("files"), dict)
        and {
            "integrations/zap_enterprise/" + name + ".py"
            for name in ("scanner_runner", "scanner_contract", "passive", "capture")
        }
        <= manifest["files"].keys()
    )
    snapshot = validate_snapshot(directory / "source", manifest)
    source = safe_path(directory / "input", directory)
    require(source.is_dir() and {p.name for p in source.iterdir()} == {"source-capture.json"})
    input_value, input_hash, input_raw = read_receipt(
        source / "source-capture.json", directory, INPUT_BYTES
    )
    validate_input(input_value, now=now)
    require(input_value["source_sha256"] == manifest["sha256"], "Scanner/source snapshots differ.")
    evidence = safe_path(directory / "evidence", directory)
    require(evidence.is_dir() and {p.name for p in evidence.iterdir()} == FILES)
    values, hashes = {}, {}
    for name in sorted(FILES):
        bound = (
            TRANSCRIPT_BYTES + 65536
            if name.endswith("-api.json")
            else 2 * 1024**2
            if name.endswith(".log")
            else 262144
        )
        values[name], hashes[name], _ = read_receipt(
            evidence / name, directory, bound, text=name.endswith(".log")
        )
    validate_gate(values["allow-scanner.json"], run, input_value, input_raw)
    runner = values["scanner-runner.json"]
    require(isinstance(runner, dict) and set(runner) == RUNNER_FIELDS)
    require(
        type(runner["schema_version"]) is int
        and runner["schema_version"] == 1
        and runner["profile"] == PROFILE
        and runner["run_id"] == run
        and runner["completed"] is True
        and runner["source_capture_attested"] is False
        and runner["runtime_attested"] is False
        and runner["input_sha256"] == input_hash
        and runner["source_run_id"] == input_value["source_run_id"]
        and runner["source_receipt_sha256"] == input_value["source_receipt_sha256"]
        and runner["kernel_sha256"] == hashes["scanner-kernel.json"]
        and same(runner["limits"], list(LIMITS))
    )
    elapsed = duration(runner["duration_seconds"], TOTAL_SECONDS)
    started, finished = timestamp(runner["started_at"]), timestamp(runner["finished_at"])
    require(timestamp(input_value["execution"]["captured_at"]) <= started <= finished <= now)
    require(abs((finished - started).total_seconds() - elapsed) <= 5)
    kernel = {
        "uid": 1000,
        "gid": 1000,
        "all_capabilities_zero": True,
        "no_new_privileges": True,
        "seccomp_filter": True,
        "cgroup_version": 2,
        "memory_bytes": MEMORY,
        "swap_bytes": 0,
        "pids": 256,
        "cpu_quota": "1.5",
        "interfaces": ["lo"],
        "read_only_source_and_input": True,
        "scratch_noexec_tmpfs": True,
        "reviewed_evidence_mount_writable": True,
    }
    require(
        any(
            same(values["scanner-kernel.json"], {**kernel, "supplementary_groups": group})
            for group in ([], [1000])
        )
    )
    require(isinstance(runner["phases"], list) and len(runner["phases"]) == 2)
    phases, addons = {}, []
    for ordinal, phase in enumerate(PHASES):
        process = values[phase + "-process.json"]
        require(
            same(process, runner["phases"][ordinal]), "Runner phase disagrees with its raw receipt."
        )
        result = revalidate_phase(
            values[phase + "-api.json"],
            process,
            values[phase + "-analysis.json"],
            input_value["phases"][phase],
            phase,
            input_value["execution"]["captured_at"],
            hashes,
        )
        phases[phase] = result["analysis"]
        addons.append(result["installed_addons"])
    require(same(*addons), "Scanner add-ons changed across the equivalent retest.")
    require(sum(p["duration_seconds"] for p in runner["phases"]) <= elapsed + 0.01)
    # Explicitly do not elevate file assertions into source/container proof.
    return {
        "scanner_receipts_revalidated": True,
        "profile": PROFILE,
        "run_id": run,
        "source_snapshot": snapshot,
        "input_sha256": input_hash,
        "source_run_id": input_value["source_run_id"],
        "source_receipt_sha256": input_value["source_receipt_sha256"],
        "raw_receipt_sha256": hashes,
        "phases": phases,
        "installed_addons": addons[0],
        "source_capture_attested": False,
        "runtime_attested": False,
        "host_shutdowns_verified": False,
        "native_zap_executed": False,
    }
