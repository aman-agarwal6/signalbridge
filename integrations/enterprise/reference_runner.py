"""Finite native source proof, callable only inside its reviewed Linux profile.

No Docker/host control, downloads, external destinations or paid services.
The host controller must separately verify effective isolation and shutdown.
"""

import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import time
from pathlib import Path

from bridge.contract import parse_json
from integrations.enterprise.https_deadline import BoundedHTTPSConnection, lab_context
from integrations.enterprise.native_runner import verify_kernel_mounts
from integrations.enterprise.network_verification import wheel_expansion
from integrations.enterprise.reference_http import ClosedHTTPSClient, RequestBudget, exercise
from integrations.enterprise.reference_kernel import CGROUPS, verify_identity
from integrations.enterprise.reference_native_support import profile
from integrations.enterprise.reference_reconciliation import reconcile

ROOT = Path("/workspace")
OUTPUT = Path("/evidence")
DEPENDENCIES = Path("/opt/verification-deps")
RUNTIME = DEPENDENCIES / "runtime"
OPERATIONS = {
    "provision": 90,
    "verify-boundary": 15,
    "fault-on": 15,
    "fault-off": 15,
    "collect": 90,
    "inspect": 90,
    "wazuh-export": 150,
}
WAZUH_EXPORT_FIELDS = frozenset(
    (
        "run_id",
        "snapshot_run_id",
        "logical_observations",
        "forwarded_core_signals",
        "scope_counts",
        "manifest_sha256",
        "snapshot_verified",
    )
)


def validate_wazuh_export(value, run, logical_observations, expected_scopes):
    """Reject lossy or weakly typed source receipts before they become runner evidence."""
    if (
        not isinstance(value, dict)
        or set(value) != WAZUH_EXPORT_FIELDS
        or value["run_id"] != run
        or not isinstance(value["snapshot_run_id"], str)
        or not re.fullmatch(
            r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value["snapshot_run_id"]
        )
        or type(value["logical_observations"]) is not int
        or value["logical_observations"] != logical_observations
        or type(value["forwarded_core_signals"]) is not int
        or value["forwarded_core_signals"] != 1
        or not isinstance(value["scope_counts"], dict)
        or set(value["scope_counts"]) != set(expected_scopes)
        or any(
            type(value["scope_counts"][key]) is not int
            or value["scope_counts"][key] != expected_scopes[key]
            for key in expected_scopes
        )
        or not isinstance(value["manifest_sha256"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", value["manifest_sha256"])
        or value["snapshot_verified"] is not True
    ):
        raise ValueError("Native Wazuh input export is incomplete or unbound.")
    return value


def runtime_gate():
    run = os.environ.get("SB_SOURCE_RUN", "")
    if (
        sys.platform != "linux"
        or sys.version_info[:2] != (3, 14)
        or os.getuid() != 10001
        or os.getgid() != 10001
        or os.environ.get("SB_SOURCE_PROOF") != "1"
        or not re.fullmatch(r"[a-f0-9]{32}", run)
        or any(name.startswith("PG") and value for name, value in os.environ.items())
    ):
        raise ValueError("Native reference runner refused an unreviewed runtime.")
    gate = OUTPUT / "allow-source.json"
    deadline = time.monotonic() + 30
    while not gate.exists() and time.monotonic() < deadline:
        time.sleep(0.2)
    if (
        not gate.is_file()
        or gate.is_symlink()
        or gate.stat().st_size > 1024
        or parse_json(gate.read_bytes()) != {"run_id": run, "runtime_verified": True}
    ):
        raise ValueError("The host did not verify the source profile before execution.")
    return run


def write_receipt(name, value):
    if name not in {
        "kernel-mounts",
        "kernel-identity",
        "reference-execution",
        "source-outbox",
        "console-events",
        "reference-reconciliation",
        "wazuh-export",
        "reference-runner",
    }:
        raise ValueError("Receipt escaped the closed reference inventory.")
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")
    if len(raw) > 262144:
        raise ValueError("Native reference receipt byte limit reached.")
    with (OUTPUT / (name + ".json")).open("xb") as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def install_dependencies(environment):
    footprint = wheel_expansion(Path("/wheels"))
    temporary = DEPENDENCIES / "install-tmp"
    temporary.mkdir(mode=0o700, exist_ok=False)
    environment["TMPDIR"] = str(temporary)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "--isolated",
            "install",
            "--no-index",
            "--no-deps",
            "--no-cache-dir",
            "--no-compile",
            "--only-binary=:all:",
            "--require-hashes",
            "--find-links=/wheels",
            "--target=" + str(RUNTIME),
            "-r",
            str(ROOT / "integrations/enterprise/runner-requirements.lock"),
        ],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=120,
    )
    # Only known cached public package names are expected, never source credentials.
    (OUTPUT / "install.log").write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise ValueError("Offline reference dependency installation failed.")
    environment["PYTHONPATH"] = str(RUNTIME) + ":/workspace"
    return footprint


def component_environment(environment, component):
    if component not in ("source", "console"):
        raise ValueError("Unknown reference component.")
    result = {
        name: value
        for name, value in environment.items()
        if not name.startswith(("PG", "SB_REF_", "SB_SERVICE_", "SB_ENTERPRISE_"))
        and name
        not in ("SSLKEYLOGFILE", "PYTHONSTARTUP", "PYTHONINSPECT", "DJANGO_SETTINGS_MODULE")
    }
    result.update(SB_SOURCE_PROOF="1", SB_SOURCE_COMPONENT=component, PYTHONDONTWRITEBYTECODE="1")
    return result


def operate(environment, component, action):
    if action not in OPERATIONS:
        raise ValueError("Unknown reference operation.")
    result = subprocess.run(
        [sys.executable, "-B", "-m", "integrations.enterprise.reference_native_support", action],
        cwd=ROOT,
        env=component_environment(environment, component),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=OPERATIONS[action],
    )
    if result.returncode or len(result.stdout) > 262144 or len(result.stderr) > 65536:
        # Raw Django/database failures can echo configuration. Do not propagate them.
        raise ValueError("Native reference component operation failed.")
    return parse_json(result.stdout)


def stop_processes(processes):
    """Only exact Popen handles created here; never find processes by a name."""
    stopped = True
    for process in reversed(processes):
        if process.poll() is None:
            try:
                process.terminate()
            except OSError:
                stopped = False
    for process in reversed(processes):
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                stopped = False
        stopped = stopped and process.poll() is not None
    return stopped


class ReadinessFailure(ValueError):
    """Fixed categories only: never retain exception text, responses or cookies."""

    def __init__(self, facts):
        super().__init__("Bounded TLS readiness failed.")
        self.facts = facts


def wait_for_tls(budget, processes):
    """Fixed readiness paths only; TLS and response predicates both must pass."""
    source = ClosedHTTPSClient("/run/secrets/lab_ca", budget)
    context = lab_context("/run/secrets/lab_ca")
    deadline = time.monotonic() + 20
    facts = {"attempts": 0, "reason": "deadline", "phase": "console", "http_status": None}
    for attempt in range(10):
        if time.monotonic() >= deadline:
            break
        if any(p.poll() is not None for p in processes):
            facts["reason"] = "child_exited"
            break
        facts.update(attempts=attempt + 1, phase="console", http_status=None)
        client = BoundedHTTPSConnection(18841, seconds=2, deadline=deadline, context=context)
        try:
            client.start()
            client.connect()
            client.request("GET", "/health/")
            response = client.getresponse()
            facts["http_status"] = response.status
            raw = response.read(8193)
            client.remaining()
            if len(raw) > 8192:
                raise ValueError("Oversized console readiness response.")
            value = parse_json(raw)
            if (
                response.status != 200
                or not isinstance(value, dict)
                or set(value) != {"service", "status", "workspace_id"}
                or value["service"] != "signalbridge"
                or value["status"] != "running"
            ):
                raise ValueError("Console readiness predicate failed.")
            original_deadline = budget.deadline
            budget.deadline = min(original_deadline, deadline)
            facts.update(phase="source", http_status=None)
            try:
                status, source_facts = source.request("GET", "/login/")
            finally:
                budget.deadline = original_deadline
            facts["http_status"] = status
            if status != 200 or source_facts != {"csrf_cookie_received": True}:
                raise ValueError("Source readiness predicate failed.")
            if time.monotonic() >= deadline:
                raise ValueError("Readiness phase deadline exceeded.")
            return {"console_readiness_attempts": attempt + 1, "tls_readiness": True}
        except (OSError, ValueError) as error:
            facts["reason"] = (
                "tls_verification"
                if isinstance(error, ssl.SSLCertVerificationError)
                else "connection_refused"
                if isinstance(error, ConnectionRefusedError)
                else "request_timeout"
                if isinstance(error, TimeoutError)
                else "transport"
                if isinstance(error, OSError)
                else "response_predicate"
            )
        finally:
            client.finish()
        # Ten immediate connection refusals previously exhausted retries in two
        # seconds, despite declaring a twenty-second startup budget. Keep both
        # bounds and space attempts across that budget without extending it.
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(2, remaining))
    facts["child_exit_codes"] = [p.poll() for p in processes]
    raise ReadinessFailure(facts)


def main():
    started, run = time.monotonic(), runtime_gate()
    processes, result = (
        [],
        {"schema_version": 1, "run_id": run, "completed": False, "receipt_sha256": {}},
    )
    environment = component_environment(os.environ, "source")
    provisioned = False
    try:
        mounts = verify_kernel_mounts(Path("/proc/self/mountinfo").read_text(encoding="ascii"))
        result["receipt_sha256"]["kernel-mounts"] = write_receipt("kernel-mounts", mounts)
        identity = verify_identity(
            Path("/proc/self/status").read_text(encoding="ascii"),
            {name: (Path("/sys/fs/cgroup") / name).read_text(encoding="ascii") for name in CGROUPS},
            Path("/proc/self/mountinfo").read_text(encoding="ascii"),
        )
        result["receipt_sha256"]["kernel-identity"] = write_receipt("kernel-identity", identity)
        result["wheel_footprint"] = install_dependencies(environment)
        credentials = profile()
        for component in ("source", "console"):
            value = operate(environment, component, "provision")
            if value != {"provisioned": True, "component": component}:
                raise ValueError("Native reference provisioning was not confirmed.")
            provisioned = provisioned or component == "source"
        result["database_boundaries"] = {}
        for component in ("source", "console"):
            value = operate(environment, component, "verify-boundary")
            expected = {
                "component": component,
                "actual_identity_verified": True,
                "cross_database_connect_denied": True,
            }
            variants = [
                {**expected, "denial_kind": "sqlstate", "denial_sqlstate": "42501"},
                {
                    **expected,
                    "denial_kind": "server_connect_privilege_message",
                    "denial_sqlstate": None,
                },
            ]
            if json.dumps(value, sort_keys=True) not in [
                json.dumps(item, sort_keys=True) for item in variants
            ]:
                raise ValueError("Native database boundary was not confirmed.")
            result["database_boundaries"][component] = value
        for component in ("source", "console"):
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-B", "-m", "integrations.enterprise.reference_native_server"],
                    cwd=ROOT,
                    env=component_environment(environment, component),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            )
        budget = RequestBudget()
        result.update(wait_for_tls(budget, processes))

        def fault(enabled, seconds):
            if type(enabled) is not bool or seconds != 120:
                raise ValueError("Fault escaped the fixed source profile.")
            value = operate(environment, "source", "fault-on" if enabled else "fault-off")
            if value != {"fault_enabled": enabled, "maximum_seconds": 120}:
                raise ValueError("Native fault/reset operation was not confirmed.")

        execution = exercise(
            lambda: ClosedHTTPSClient("/run/secrets/lab_ca", budget), credentials["accounts"], fault
        )
        result["source_http_requests"] = budget.used
        result["receipt_sha256"]["reference-execution"] = write_receipt(
            "reference-execution", execution
        )
        collection = operate(environment, "source", "collect")
        if (
            not isinstance(collection, dict)
            or set(collection)
            != {
                "committed_claim_results",
                "collector_transport_invocations",
                "phase_deadline_reached",
            }
            or any(
                type(collection[name]) is not int or not 0 <= collection[name] <= 80
                for name in ("committed_claim_results", "collector_transport_invocations")
            )
            or collection["phase_deadline_reached"] is not False
        ):
            raise ValueError("Native collector phase is incomplete.")
        result["collection"] = collection
        source, console = (
            operate(environment, "source", "inspect"),
            operate(environment, "console", "inspect"),
        )
        for name, value in (("source-outbox", source), ("console-events", console)):
            result["receipt_sha256"][name] = write_receipt(name, value)
        proof = reconcile(execution, source, console)
        if (
            collection["committed_claim_results"] != proof["committed_outbox_claims"]
            or collection["collector_transport_invocations"] != proof["logical_source_events"]
        ):
            raise ValueError("Unexpected native source attempts require review.")
        result["receipt_sha256"]["reference-reconciliation"] = write_receipt(
            "reference-reconciliation", proof
        )
        export = operate(environment, "console", "wazuh-export")
        observation_counts = {
            app: sum(row["app"] == app for row in console["events"])
            for app in ("documents", "expenses")
        }
        expected_scopes = {
            "documents/observation": observation_counts["documents"],
            "documents/detection": 1,
            "expenses/observation": observation_counts["expenses"],
            "expenses/detection": 0,
        }
        if proof["logical_source_events"] != len(console["events"]):
            raise ValueError("Native source and console event inventories differ.")
        export = validate_wazuh_export(export, run, len(console["events"]), expected_scopes)
        result["wazuh_export"] = export
        result["receipt_sha256"]["wazuh-export"] = write_receipt("wazuh-export", export)
        result["completed"] = True
    except Exception as error:
        result["error_class"] = type(error).__name__
        if isinstance(error, ReadinessFailure):
            result["readiness_failure"] = error.facts
    finally:
        # HTTP restoration already runs inside exercise. Independently reset the
        # fixed defect even if failure preceded HTTP or occurred during collection.
        if provisioned:
            try:
                value = operate(environment, "source", "fault-off")
                result["final_fault_reset"] = value == {
                    "fault_enabled": False,
                    "maximum_seconds": 120,
                }
            except Exception:
                result["final_fault_reset"] = False
        else:
            result["final_fault_reset"] = False
        result["processes_stopped"] = stop_processes(processes)
        result["completed"] = bool(
            result["completed"] and result["final_fault_reset"] and result["processes_stopped"]
        )
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        result["limits"] = [
            "Native completion additionally requires host snapshot/runtime verification and both shutdown receipts.",
            "TLS source/console processes share one container uid; database roles are not separate OS security boundaries.",
            "Transport invocations count initiated collector calls, not proof of transmitted packets or native tool observations.",
        ]
        write_receipt("reference-runner", result)
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
