"""Pure bounded native-readiness checks shared by host and isolated runner.

Supplied state is not attestation: runtime ownership and retained source binding
must be verified by the host controller before publication or acceptance.
"""

import hashlib
import xml.etree.ElementTree as ET

from bridge.contract import digest, parse_json, timestamp

from .collector_profile import INTERNAL_OPTIONS, configuration
from .contract import require

MAX_BYTES = 128 * 1024
RECOVERY_PROFILE = "wazuh-recovery-rotation-v1"
ROTATED_SUFFIX = ".rotated-1"


def recovery_split(plan, frozen):
    """Deterministic interruption/rotation split shared by host and native driver.

    Each file publishes its first half of complete records while the collector
    runs. The remainder is a backlog written while the collector is stopped. The
    file with the most records (ties by path) is rotated logrotate-style before
    its backlog: renamed aside and recreated empty at the same monitored path.
    """
    rows = plan["files"]
    require(
        type(frozen) is dict and set(frozen) == {row["relative"] for row in rows},
        "recovery_frozen_inventory",
    )
    phases = {}
    for row in rows:
        raw = frozen[row["relative"]]
        lines = raw.splitlines(keepends=True)
        require(
            len(lines) == row["records"] and all(line.endswith(b"\n") for line in lines),
            "recovery_frozen_records",
        )
        half = len(lines) // 2
        phases[row["relative"]] = (b"".join(lines[:half]), b"".join(lines[half:]))
    target = max(rows, key=lambda row: (row["records"], row["relative"]))
    require(target["records"] >= 2, "recovery_rotation_target")
    return target["relative"], phases


def recovery_binding(plan, frozen):
    target, phases = recovery_split(plan, frozen)
    return {
        "profile": RECOVERY_PROFILE,
        "rotation_relative": target,
        "rotated_suffix": ROTATED_SUFFIX,
        "initial_sha256": {
            name: hashlib.sha256(first).hexdigest() for name, (first, _) in sorted(phases.items())
        },
        "backlog_sha256": {
            name: hashlib.sha256(rest).hexdigest() for name, (_, rest) in sorted(phases.items())
        },
        "initial_records": sum(len(first.splitlines()) for first, _ in phases.values()),
        "backlog_records": sum(len(rest.splitlines()) for _, rest in phases.values()),
    }


STOPPED_FIELDS = {
    "kind",
    "run_id",
    "plan_sha256",
    "initial_sha256",
    "stopped_at",
    "archived_before_stop",
    "alerted_before_stop",
    "collector_exit_code",
    "native_execution_verified",
}


def recovery_initial(plan, readiness):
    """Host record after the first half was appended while the collector ran."""
    recovery = plan["recovery"]
    return {
        "kind": "signalbridge-wazuh-recovery-initial-v1",
        "run_id": plan["run_id"],
        "plan_sha256": digest(plan),
        "readiness_sha256": digest(readiness),
        "published_records": recovery["initial_records"],
        "initial_sha256": recovery["initial_sha256"],
        "native_execution_verified": False,
        "tool_receipt_verified": False,
    }


def validate_stopped(plan, initial, stopped):
    """Native driver's record that the collector stopped after archiving phase one."""
    require(type(stopped) is dict and set(stopped) == STOPPED_FIELDS, "recovery_stopped_fields")
    require(
        stopped["kind"] == "signalbridge-wazuh-collector-stopped-v1"
        and stopped["run_id"] == plan["run_id"]
        and stopped["plan_sha256"] == digest(plan)
        and stopped["initial_sha256"] == digest(initial)
        and stopped["native_execution_verified"] is False,
        "recovery_stopped_binding",
    )
    require(
        type(stopped["archived_before_stop"]) is int
        and stopped["archived_before_stop"] == plan["recovery"]["initial_records"]
        and type(stopped["alerted_before_stop"]) is int
        and 0 <= stopped["alerted_before_stop"] <= stopped["archived_before_stop"]
        and type(stopped["collector_exit_code"]) is int
        and -64 <= stopped["collector_exit_code"] <= 255,
        "recovery_stopped_counts",
    )
    timestamp(stopped["stopped_at"])
    return stopped


def recovery_completion(plan, initial, stopped):
    """Host record after rotation and the backlog written while the collector was down."""
    recovery = plan["recovery"]
    return {
        "kind": "signalbridge-wazuh-recovery-publication-v1",
        "run_id": plan["run_id"],
        "plan_sha256": digest(plan),
        "initial_sha256": digest(initial),
        "stopped_sha256": digest(stopped),
        "rotation_relative": recovery["rotation_relative"],
        "rotated_name": recovery["rotation_relative"] + recovery["rotated_suffix"],
        "backlog_records": recovery["backlog_records"],
        "published_records": recovery["initial_records"] + recovery["backlog_records"],
        "native_execution_verified": False,
        "tool_receipt_verified": False,
    }


def delivery_configuration(plan):
    """Monitor only the finite prepared files, with existing disabled modules."""
    locations = {row["location"] for row in plan["files"]}
    tree = ET.fromstring(configuration())
    for node in list(tree.findall("localfile")):
        if node.findtext("location") not in locations:
            tree.remove(node)
    require({node.findtext("location") for node in tree.findall("localfile")} == locations)
    ET.indent(tree, space="  ")
    return ET.tostring(tree, encoding="utf8", xml_declaration=False) + b"\n"


def empty_readiness(plan, raw_state, *, observed_at):
    """Require exact native collector file counters, not merely live processes.

    A supervisor must obtain raw_state from wazuh-logcollector.state in its
    verified container and bind this result to that run's execution receipt.
    The shape follows run_pilot.collector_observations, used by the retained
    native pilot. Its raw state was not retained; fixtures here are modeled.
    """
    require(type(raw_state) is bytes and 0 < len(raw_state) <= MAX_BYTES, "publisher_state_size")
    # Wazuh v4.14.0 src/logcollector/state.c:w_logcollector_state_dump appends
    # this newline before overwriting the state file; incomplete reads wait.
    require(raw_state.endswith(b"\n"), "publisher_state_incomplete")
    state = parse_json(raw_state)
    require(type(state) is dict and set(state) == {"global", "interval"}, "publisher_state_fields")
    require(type(state["global"]) is dict and type(state["interval"]) is dict)
    files = state["global"].get("files")
    require(type(files) is list and len(files) == len(plan["files"]), "publisher_state_inventory")
    expected, actual = {row["location"] for row in plan["files"]}, set()
    for row in files:
        require(
            type(row) is dict and row.get("location") in expected and row["location"] not in actual
        )
        require(
            all(type(row.get(key)) is int and row[key] == 0 for key in ("events", "bytes")),
            "publisher_collector_not_empty",
        )
        require(
            row.get("targets") == [{"name": "agent", "drops": 0}]
            and type(row["targets"][0]["drops"]) is int,
            "publisher_target_or_drops",
        )
        actual.add(row["location"])
    require(actual == expected, "publisher_state_inventory")
    require(timestamp(plan["prepared_at"]) <= observed_at, "publisher_readiness_before_prepare")
    return {
        "kind": "signalbridge-wazuh-empty-input-ready-v1",
        "run_id": plan["run_id"],
        "plan_sha256": digest(plan),
        "observed_at": observed_at.isoformat(),
        "native_state_sha256": hashlib.sha256(raw_state).hexdigest(),
        "empty_native_files": sorted(actual),
        "native_execution_verified": False,
    }


def verify_delivery_configuration(plan, raw, internal):
    require(raw == delivery_configuration(plan), "publisher_configuration_changed")
    require(internal == INTERNAL_OPTIONS, "publisher_internal_options_changed")
    return {
        "configuration_sha256": hashlib.sha256(raw).hexdigest(),
        "internal_options_sha256": hashlib.sha256(internal).hexdigest(),
        "monitored_paths": len(plan["files"]),
        "native_execution_verified": False,
    }
