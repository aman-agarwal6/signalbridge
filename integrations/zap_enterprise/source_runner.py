"""Finite authenticated source capture inside a separately reviewed Linux profile.

No host/Docker control, network target arguments, downloads or native ZAP claim.
The native host must verify this exact variant before releasing allow-source.
"""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from bridge.contract import parse_json
from integrations.enterprise import reference_runner as base
from integrations.enterprise.native_runner import verify_kernel_mounts
from integrations.enterprise.reference_http import ClosedHTTPSClient, RequestBudget
from integrations.enterprise.reference_kernel import CGROUPS, verify_identity
from integrations.enterprise.reference_native_support import profile

from .capture import PROFILE, exercise, require, validate_pair
from .source_reconciliation import reconcile

ROOT, OUTPUT = Path("/workspace"), Path("/evidence")
FILES = {
    "kernel-mounts",
    "kernel-identity",
    "header-execution",
    "source-captures",
    "source-outbox",
    "console-events",
    "header-reconciliation",
    "header-runner",
}
OPERATIONS = {"header-on": 15, "header-off": 15, "inspect-header": 90}


def environment(source, component):
    result = base.component_environment(source, component)
    for name in list(result):
        if name.startswith("SB_HEADER_"):
            result.pop(name)
    result["SB_HEADER_PROOF"] = "1"
    return result


def operate(context, action):
    require(action in OPERATIONS)
    child = subprocess.run(
        [sys.executable, "-B", "-m", "integrations.zap_enterprise.source_support", action],
        cwd=ROOT,
        env=environment(context, "source"),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=OPERATIONS[action],
    )
    require(
        child.returncode == 0 and len(child.stdout) <= 262144 and len(child.stderr) <= 65536,
        "The fixed native header operation failed.",
    )
    return parse_json(child.stdout)


def write_receipt(name, value):
    require(name in FILES)
    raw = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("ascii")
    require(len(raw) <= 262144)
    with (OUTPUT / (name + ".json")).open("xb") as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def database_boundary(value, component):
    expected = {
        "component": component,
        "actual_identity_verified": True,
        "cross_database_connect_denied": True,
    }
    variants = (
        {**expected, "denial_kind": "sqlstate", "denial_sqlstate": "42501"},
        {**expected, "denial_kind": "server_connect_privilege_message", "denial_sqlstate": None},
    )
    require(
        isinstance(value, dict)
        and json.dumps(value, sort_keys=True)
        in [json.dumps(item, sort_keys=True) for item in variants]
    )
    return value


def main():
    require(
        os.environ.get("SB_HEADER_PROOF") == "1"
        and Path(__file__).resolve() == ROOT / "integrations/zap_enterprise/source_runner.py"
    )
    started, run = time.monotonic(), base.runtime_gate()
    context, processes, provisioned = environment(os.environ, "source"), [], False
    result = {
        "schema_version": 1,
        "profile": PROFILE,
        "run_id": run,
        "completed": False,
        "native_zap_executed": False,
        "receipt_sha256": {},
    }
    try:
        mounts = verify_kernel_mounts(Path("/proc/self/mountinfo").read_text(encoding="ascii"))
        identity = verify_identity(
            Path("/proc/self/status").read_text(encoding="ascii"),
            {name: (Path("/sys/fs/cgroup") / name).read_text(encoding="ascii") for name in CGROUPS},
            Path("/proc/self/mountinfo").read_text(encoding="ascii"),
        )
        for name, value in (("kernel-mounts", mounts), ("kernel-identity", identity)):
            result["receipt_sha256"][name] = write_receipt(name, value)
        result["wheel_footprint"] = base.install_dependencies(context)
        credentials = profile()
        for component in ("source", "console"):
            require(
                base.operate(context, component, "provision")
                == {"provisioned": True, "component": component}
            )
            provisioned = provisioned or component == "source"
        result["database_boundaries"] = {
            component: database_boundary(
                base.operate(context, component, "verify-boundary"), component
            )
            for component in ("source", "console")
        }
        for component, module in (
            ("source", "integrations.zap_enterprise.source_server"),
            ("console", "integrations.enterprise.reference_native_server"),
        ):
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-B", "-m", module],
                    cwd=ROOT,
                    env=environment(context, component),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            )
        budget = RequestBudget()
        result.update(base.wait_for_tls(budget, processes))
        readiness = budget.used

        def fault(enabled, seconds):
            require(type(enabled) is bool and seconds == 300)
            value = operate(context, "header-on" if enabled else "header-off")
            require(value == {"enabled": enabled, "maximum_seconds": 300})
            return value

        summary, phases = exercise(
            lambda: ClosedHTTPSClient("/run/secrets/lab_ca", budget), credentials["accounts"], fault
        )
        result["source_http_requests"] = budget.used
        result["source_readiness_requests"] = readiness
        result["receipt_sha256"]["header-execution"] = write_receipt("header-execution", summary)
        result["receipt_sha256"]["source-captures"] = write_receipt("source-captures", phases)
        require(summary["completed"] is True and budget.used - readiness == 18)
        validate_pair(phases)
        collection = base.operate(context, "source", "collect")
        require(
            collection
            == {
                "committed_claim_results": 8,
                "collector_transport_invocations": 8,
                "phase_deadline_reached": False,
            }
        )
        result["collection"] = collection
        source, console = (
            operate(context, "inspect-header"),
            base.operate(context, "console", "inspect"),
        )
        for name, value in (("source-outbox", source), ("console-events", console)):
            result["receipt_sha256"][name] = write_receipt(name, value)
        proof = reconcile(summary, phases, source, console)
        require(proof["source_outbox_claims"] == proof["worker_committed_attempts"] == 8)
        result["receipt_sha256"]["header-reconciliation"] = write_receipt(
            "header-reconciliation", proof
        )
        result["completed"] = True
    except Exception as error:
        result["error_class"] = type(error).__name__
    finally:
        try:
            result["final_fault_reset"] = provisioned and operate(context, "header-off") == {
                "enabled": False,
                "maximum_seconds": 300,
            }
        except Exception:
            result["final_fault_reset"] = False
        result["processes_stopped"] = base.stop_processes(processes)
        result["completed"] = bool(
            result["completed"] and result["final_fault_reset"] and result["processes_stopped"]
        )
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        result["limits"] = [
            "Host must verify the exact header runtime/source snapshot and both shutdown receipts.",
            "This is source capture/delivery proof; native ZAP has not executed.",
            "No performance estimate is derived from HAR placeholder timings.",
        ]
        write_receipt("header-runner", result)
    return 0 if result["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
