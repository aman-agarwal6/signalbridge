"""Explicit shared-engine admission; ordinary launches remain exclusive.

No import performs IO. Approval labels never grant authority. The reviewed plan
and private baseline are bound independently in the main process and watchdog.
Only a separately approved launch may call capture; historical readers use the
retained plan, never live Docker. Snapshot checks are not service-health proof.
"""

import hashlib
import os
import time
from pathlib import Path

from bridge.contract import canonical
from integrations.enterprise import verification as base
from integrations.enterprise.reference_host_controls import read_json
from integrations.zap_enterprise.scanner_host_controls import validate_shutdown

from . import collector_host_controls as host
from . import preservation_profile as preserved
from .contract import require

POLICY = preserved.PROFILE
PLAN = "integrations/wazuh_enterprise/ready-publication-stage-plan.json"
CAPACITY_PLAN = "integrations/wazuh_enterprise/ready-publication-capacity-stage-plan.json"
# Same controls as CAPACITY_PLAN, re-reviewed against the ACL-diagnostic source.
# Earlier plans stay byte-for-byte as historical records.
ACL_REVIEW_PLAN = "integrations/wazuh_enterprise/ready-publication-acl-review-stage-plan.json"
PLAN_NAMES = (PLAN, CAPACITY_PLAN, ACL_REVIEW_PLAN)
REVIEWED_FILES = (
    "scripts/enterprise_wazuh_live_verify.py",
    "scripts/enterprise_wazuh_verify.py",
    "scripts/enterprise_reference_verify.py",
    "scripts/enterprise_zap_verify.py",
    "integrations/enterprise/verification.py",
    "integrations/enterprise/network_verification.py",
    "integrations/enterprise/reference_host_controls.py",
    "integrations/enterprise/reference-private-acl.ps1",
    "integrations/enterprise/private_acl_diagnostics.py",
    "integrations/enterprise/windows_capacity.py",
    "integrations/enterprise/preserved_workloads.py",
    "integrations/wazuh_enterprise/execution_policy.py",
    "integrations/wazuh_enterprise/preservation_profile.py",
    "integrations/wazuh_enterprise/collector_host_controls.py",
    "integrations/wazuh_enterprise/collector_profile.py",
    "integrations/wazuh_enterprise/collector_kernel.py",
    "integrations/wazuh_enterprise/collector_source_binding.py",
    "integrations/wazuh_enterprise/native_collector.py",
    "integrations/wazuh_enterprise/native_live_collector.py",
    "integrations/wazuh_enterprise/native_reconciliation.py",
    "integrations/wazuh_enterprise/ready_contract.py",
    "integrations/wazuh_enterprise/ready_publisher.py",
    "integrations/wazuh_enterprise/capture_journal.py",
    "integrations/wazuh_enterprise/contract.py",
    "integrations/wazuh_enterprise/export_snapshot.py",
    "integrations/wazuh_enterprise/collector-stage-plan.json",
    "integrations/wazuh_enterprise/manager-lab.conf",
    "integrations/wazuh_enterprise/local_internal_options.conf",
    "integrations/wazuh_enterprise/signalbridge_rules.xml",
    "integrations/wazuh/run_pilot.py",
    "integrations/wazuh/run_context.py",
    "integrations/wazuh/verify_static.py",
    "integrations/zap_enterprise/scanner_host_controls.py",
    "bridge/contract.py",
    "bridge/runtime_identity.py",
)
SOURCE_BINDING = {
    "native_source_run_id": "b8667b816ce8419da7f3d5d9ac9d6ad6",
    "snapshot_run_id": "88ce9f77-2d7f-4b1d-9d36-26f698c2c01a",
    "native_source_receipt_sha256": "c254c2099077fdcb129902748a1f302476751605ea4c1b485fbfad1d7c608cc0",
    "expected_packets_sha256": "06e57444b697d067cd9da21b1f2cd8580dce40917e0ef541d4dc506ee037f5d5",
    "logical_observations": 23,
    "forwarded_core_signals": 1,
}
CONTROLS = {
    "profile": POLICY,
    "image": host.IMAGE,
    "maximum_preserved_workloads": 8,
    "container_memory_bytes": host.MEMORY,
    "container_cpus": 1,
    "network": "none",
    "published_ports": 0,
    "pull_policy": "never",
    "active_watchdog_seconds": 840,
    "late_operation_drain_seconds": 60,
    "watchdog_completion_wait_seconds": 240,
    "cumulative_disk_growth_guard_bytes": host.GROWTH,
    "minimum_free_disk_bytes": base.MIN_FREE_DISK,
    "minimum_host_available_memory_bytes": base.MIN_FREE_MEMORY,
    "desktop_start_or_stop": False,
    "downloads": False,
    "delete_resources": False,
    "source_binding": SOURCE_BINDING,
}


def controls_for(plan_name):
    require(type(plan_name) is str and plan_name in PLAN_NAMES, "collector_review_plan_unknown")
    return {
        **CONTROLS,
        "cumulative_disk_growth_guard_bytes": (
            host.REVIEWED_CAPACITY_GROWTH
            if plan_name in (CAPACITY_PLAN, ACL_REVIEW_PLAN)
            else host.GROWTH
        ),
    }


def read_plan(workspace, expected_digest=None, *, plan_name=PLAN):
    """Verify the closed implementation inventory before any native request."""
    controls_for(plan_name)
    path = Path(workspace) / plan_name
    plan = read_json(path, 32768)
    validate_plan(plan, plan_name=plan_name)
    identity = hashlib.sha256(canonical(plan)).hexdigest()
    require(expected_digest is None or expected_digest == identity, "collector_review_plan_changed")
    for relative, expected in plan["reviewed_files"].items():
        source = Path(workspace) / relative
        require(
            source.is_file()
            and not source.is_symlink()
            and not getattr(source.lstat(), "st_file_attributes", 0) & 0x400
            and 0 < source.stat().st_size <= 1024 * 1024
            and hashlib.sha256(source.read_bytes()).hexdigest() == expected,
            "collector_reviewed_implementation_changed",
        )
    return plan, identity


def validate_plan(plan, *, plan_name=PLAN):
    controls = controls_for(plan_name)
    require(
        type(plan) is dict
        and set(plan) == {"schema_version", "controls", "reviewed_files", "review_notes"}
        and type(plan["schema_version"]) is int
        and plan["schema_version"] == 1
        and canonical(plan["controls"]) == canonical(controls)
        and type(plan["reviewed_files"]) is dict
        and set(plan["reviewed_files"]) == set(REVIEWED_FILES)
        and all(
            type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
            for value in plan["reviewed_files"].values()
        )
        and type(plan["review_notes"]) is list
        and 1 <= len(plan["review_notes"]) <= 16
        and all(type(note) is str and 0 < len(note) <= 1024 for note in plan["review_notes"]),
        "collector_review_plan_invalid",
    )


class PreservationPolicy:
    def __init__(
        self, docker, run, workspace, baseline, baseline_digest, plan_digest, *, plan_name=PLAN
    ):
        self.run, self.workspace = run, Path(workspace)
        self.directory = base.private_run_directory(workspace, run)
        self.baseline, self.digest, self.plan_digest = baseline, baseline_digest, plan_digest
        # Capacity is derived from the exact retained, reviewed plan. Neither
        # a free integer nor a baseline reset can widen the launch budget.
        plan = read_json(self.directory / "reviewed-stage-plan.json", 32768)
        validate_plan(plan, plan_name=plan_name)
        require(
            hashlib.sha256(canonical(plan)).hexdigest() == plan_digest,
            "collector_review_plan_changed",
        )
        self.plan_name = plan_name
        self.growth_ceiling = plan["controls"]["cumulative_disk_growth_guard_bytes"]
        preserved.validate_baseline(
            baseline, run, self.directory, plan_digest, expected_digest=baseline_digest
        )
        self.request = preserved.bind_request(docker, run, workspace)
        self.docker = docker
        self.failed = False

    def checkpoint(self, owned):
        deadline = time.monotonic() + 20

        def bounded_request(arguments, *, timeout):
            require(time.monotonic() + timeout <= deadline, "collector_preservation_deadline")
            return self.request(arguments, timeout=timeout)

        try:
            return preserved.checkpoint(
                bounded_request,
                self.baseline,
                self.run,
                self.directory,
                self.plan_digest,
                owned,
                expected_digest=self.digest,
            )
        except Exception:
            self.failed = True
            raise

    def admit_stop(self, identifier):
        # This path deliberately ignores preserved-workload health: failure
        # there must not prevent cleanup of this exact owned run.
        targets = host.owned(self.docker, self.run, self.workspace, publication=True)
        return preserved.mutation_admitted(
            identifier,
            self.run,
            preserved.engine(self.request),
            self.baseline,
            self.run,
            self.directory,
            self.plan_digest,
            targets,
            expected_digest=self.digest,
        )

    def public_binding(self):
        return {
            "execution_policy": POLICY,
            "reviewed_plan_sha256": self.plan_digest,
            "stage_plan": self.plan_name,
            "preservation_digest": self.digest,
            "preserved_count": len(self.baseline["envelopes"]),
        }


def capture(docker, run, workspace, plan_digest, *, plan_name=PLAN):
    plan, _ = read_plan(workspace, plan_digest, plan_name=plan_name)
    directory = base.private_run_directory(workspace, run)
    baseline, public = preserved.capture(
        preserved.bind_request(docker, run, workspace), run, directory, plan_digest
    )
    for name, value in (("preservation.json", baseline), ("reviewed-stage-plan.json", plan)):
        raw = canonical(value) + b"\n"
        with (directory / name).open("xb") as output:
            require(output.write(raw) == len(raw), "collector_preservation_short_write")
            output.flush()
            os.fsync(output.fileno())
    return PreservationPolicy(
        docker,
        run,
        workspace,
        baseline,
        public["preservation_digest"],
        plan_digest,
        plan_name=plan_name,
    )


def load(docker, run, workspace, baseline_digest, plan_digest, *, plan_name=PLAN):
    read_plan(workspace, plan_digest, plan_name=plan_name)
    baseline = read_json(base.private_run_directory(workspace, run) / "preservation.json", 262144)
    return PreservationPolicy(
        docker, run, workspace, baseline, baseline_digest, plan_digest, plan_name=plan_name
    )


def verify_recorded(directory, receipt, watchdog):
    """Read retained evidence only; never inspect an engine from an import."""
    if receipt.get("execution_policy", "exclusive") == "exclusive":
        require("preservation_digest" not in receipt, "collector_unbound_preservation")
        require(
            receipt.get("stage_plan", PLAN) == PLAN
            and type(receipt.get("stage_growth_ceiling_bytes", host.GROWTH)) is int
            and receipt.get("stage_growth_ceiling_bytes", host.GROWTH) == host.GROWTH,
            "collector_unbound_capacity_revision",
        )
        return
    require(receipt.get("execution_policy") == POLICY, "collector_execution_policy_unknown")
    baseline = read_json(Path(directory) / "preservation.json", 262144)
    plan = read_json(Path(directory) / "reviewed-stage-plan.json", 32768)
    validate_plan(plan, plan_name=receipt.get("stage_plan", PLAN))
    plan_digest = hashlib.sha256(canonical(plan)).hexdigest()
    preserved.validate_baseline(
        baseline,
        receipt["run_id"],
        directory,
        plan_digest,
        expected_digest=receipt.get("preservation_digest"),
    )
    final = receipt.get("preservation_final")
    checkpoint_fields = {
        "preserved_count",
        "preserved_digest",
        "owned_count",
        "owned_running_count",
        "running_count",
        "running_digest",
        "preservation_digest",
        "engine_digest",
    }
    require(
        receipt.get("reviewed_plan_sha256") == plan_digest
        and type(receipt.get("stage_growth_ceiling_bytes")) is int
        and receipt["stage_growth_ceiling_bytes"]
        == plan["controls"]["cumulative_disk_growth_guard_bytes"]
        and type(receipt.get("preserved_count")) is int
        and receipt.get("preserved_count") == len(baseline["envelopes"])
        and receipt.get("preservation_verified") is True
        and watchdog.get("preservation_verified") is True
        and watchdog.get("late_operation_drain_verified") is True
        and watchdog.get("late_operation_drain_seconds") == 60
        and type(final) is dict
        and set(final) == checkpoint_fields
        and all(
            type(final[key]) is int and 0 <= final[key] <= 8
            for key in ("preserved_count", "owned_count", "owned_running_count", "running_count")
        )
        and final["owned_count"] == 1
        and final.get("preservation_digest") == receipt["preservation_digest"]
        and final.get("engine_digest") == preserved.digest(baseline["engine"])
        and final.get("preserved_digest") == baseline["running_baseline"]["sha256"]
        and final.get("running_count") == len(baseline["envelopes"])
        and final.get("running_digest")
        == preserved.digest(list(baseline["running_baseline"]["preserved_ids"]))
        and final.get("owned_running_count") == 0
        and final.get("preserved_count") == len(baseline["envelopes"])
        and canonical(final) == canonical(watchdog.get("preservation_final")),
        "collector_preservation_incomplete",
    )


def publication_shutdown(main, independent, run, *, started, finished, shared=False):
    """Validate this profile's closed extensions without loosening ZAP's schema."""
    fields = {"run_id", "shutdown_verified", "reason", "stopped_component_count", "stopped_at"}
    extra = {
        "late_operation_drain_seconds",
        "late_operation_drain_verified",
        "late_operation_drain_elapsed_ms",
    }
    if shared:
        extra |= {"preservation_final", "preservation_verified"}
    require(
        type(shared) is bool
        and type(independent) is dict
        and set(independent) == fields | extra
        and type(independent["late_operation_drain_seconds"]) is int
        and independent["late_operation_drain_seconds"] == 60
        and type(independent["late_operation_drain_elapsed_ms"]) is int
        and 60000 <= independent["late_operation_drain_elapsed_ms"] <= 240000
        and independent["late_operation_drain_verified"] is True,
        "collector_publication_shutdown_incomplete",
    )
    if shared:
        require(
            independent["preservation_verified"] is True
            and type(independent["preservation_final"]) is dict,
            "collector_preservation_shutdown_incomplete",
        )
    return validate_shutdown(
        main, {key: independent[key] for key in fields}, run, started=started, finished=finished
    )
