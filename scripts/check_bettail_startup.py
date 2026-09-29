"""Read-only pre-start gate for the fixed, stopped eight-container BetTail lab.

Checks configured boundaries before any service is started. A pass is permission
to continue verification, not proof of password authentication or runtime isolation.
"""

import argparse
import json
import shutil
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import verify_bettail_routes as gate
from scripts.lab_credentials import LabCredentialError, read_database_password

FREE_FLOOR = 25 * 1024**3
LIMITS = [
    "Read-only configuration preflight; no container is started or changed.",
    "No password authentication, service health, route or runtime isolation is tested.",
    "A generated credential file does not prove that database roles and clients use it.",
    "Run the live isolation gate before application tests; do not bypass a failed preflight.",
    "Local operating-system and Docker administrators remain trusted.",
]


def run_check():
    report = {
        "schema_version": 1,
        "kind": "signalbridge-bettail-startup-preflight",
        "started_at": datetime.now(UTC).isoformat(),
        "status": "blocked",
        "errors": [],
        "coverage_limits": LIMITS,
    }
    try:
        script_hash = gate.base.sha256(Path(__file__).read_bytes())
        report["preflight_source_sha256"] = script_hash
        before = gate.gather_topology()
        report["topology_sha256"] = gate.base.sha256(gate.base.canonical(before))
        report["errors"] = gate.verify_topology(before, stopped=True)
        for row in before["containers"]:
            name = row["Name"].lstrip("/")
            if name in gate.base.NAMES:
                report["errors"].extend(gate.base.verify_startup_controls(name, row["HostConfig"]))
        report["configured_controls"] = [
            {
                "name": row["Name"].lstrip("/"),
                "id": row["Id"],
                "state": row["State"],
                "memory_bytes": row["HostConfig"]["Memory"],
                "swap_total_bytes": row["HostConfig"]["MemorySwap"],
                "nano_cpus": row["HostConfig"]["NanoCpus"],
                "pids_limit": row["HostConfig"]["PidsLimit"],
                "restart": row["HostConfig"]["RestartPolicy"],
                "requested_ports": row["HostConfig"]["PortBindings"],
            }
            for row in before["containers"]
        ]
        report["running_container_count"] = len(
            gate.base.docker(["ps", "--format", "{{.ID}}", "--no-trunc"]).splitlines()
        )
        if report["running_container_count"]:
            report["errors"].append("other_or_lab_container_running")
        report["host_free_bytes"] = shutil.disk_usage(ROOT).free
        if report["host_free_bytes"] < FREE_FLOOR:
            report["errors"].append("host_free_floor")
        try:
            read_database_password(ROOT)
            report["generated_credential_present"] = True
        except LabCredentialError:
            report["generated_credential_present"] = False
            report["errors"].append("coordinated_credentials_required")
        after = gate.gather_topology()
        report["errors"].extend(gate.verify_topology(after, stopped=True))
        if gate.base.canonical(before) != gate.base.canonical(after):
            report["errors"].append("preflight_environment_changed")
        if not report["errors"]:
            # Avoid hashing the large copied dependency tree when cheaper
            # configuration/credential checks already prohibit startup.
            sources = gate.source_hashes()
            report["source_hashes"] = sources
            final = gate.gather_topology()
            report["errors"].extend(gate.verify_topology(final, stopped=True))
            if (
                gate.base.canonical(before) != gate.base.canonical(final)
                or sources != gate.source_hashes()
            ):
                report["errors"].append("preflight_environment_changed")
            report["source_check"] = "completed"
            if not report["errors"]:
                report["status"] = "ready_for_live_verification"
        else:
            report["source_check"] = "not_run_startup_blocked"
        if script_hash != gate.base.sha256(Path(__file__).read_bytes()):
            report["errors"].append("preflight_source_changed")
    except (gate.VerificationError, OSError, ValueError, KeyError, TypeError, AttributeError):
        report["errors"].append("preflight_input_or_runtime_failure")
    report["errors"] = sorted(set(report["errors"]))
    if report["errors"]:
        report["status"] = "blocked"
    report["finished_at"] = datetime.now(UTC).isoformat()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)  # No arbitrary target or configuration paths.
    report = run_check()
    directory = ROOT / "artifacts/local/startup-preflight"
    current = ROOT
    for part in directory.relative_to(ROOT).parts:
        gate._safe(current, directory=True)
        current = current / part
        if not current.exists():
            current.mkdir()
        gate._safe(current, directory=True)
    name = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8]
    path = directory / (name + ".json")
    body = json.dumps(report, indent=2).encode() + b"\n"
    with path.open("xb") as handle:
        handle.write(body)
    with path.with_suffix(".sha256").open("x", encoding="ascii") as handle:
        handle.write(gate.base.sha256(body) + "\n")
    print(f"BetTail startup: {report['status']}. Private record: {path.relative_to(ROOT)}")
    if report["errors"]:
        print("Do not start the lab. Checks requiring attention: " + ", ".join(report["errors"]))
    return 0 if report["status"] == "ready_for_live_verification" else 1


if __name__ == "__main__":
    raise SystemExit(main())
