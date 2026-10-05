"""Closed native collector preparation. Never launches or attests a manager.

The first profile covers documents/expenses only. A reviewed host controller,
genuine source exports and independent shutdown proof are prerequisites.
"""

import hashlib
import xml.etree.ElementTree as ET

from .contract import require, segmented_location

APPS = ("documents", "expenses")
CHANNELS = ("observation", "detection")
DAEMONS = ("wazuh-db", "wazuh-analysisd", "wazuh-logcollector")
IMAGE = (
    "wazuh/wazuh-manager@sha256:f74021c1275393aa094b6f6bb57f9bac240cba7ddb35f2a841e430341f5fc6a0"
)
MAX_CONFIG_BYTES = 32768
INTERNAL_OPTIONS = (
    b"logcollector.remote_commands=0\n"
    b"logcollector.loop_timeout=1\n"
    b"logcollector.vcheck_files=1\n"
    b"logcollector.max_files=32\n"
    b"logcollector.max_lines=100\n"
    b"logcollector.input_threads=2\n"
    b"logcollector.state_interval=1\n"
)


def configuration():
    root = ET.Element("ossec_config")

    def group(tag, pairs, **attributes):
        node = ET.SubElement(root, tag, attributes)
        for tag, value in pairs:
            ET.SubElement(node, tag).text = value
        return node

    group(
        "global",
        (
            ("jsonout_output", "yes"),
            ("alerts_log", "no"),
            ("logall", "no"),
            ("logall_json", "yes"),
            ("email_notification", "no"),
            ("update_check", "no"),
            ("rotate_interval", "10m"),
            ("max_output_size", "2M"),
        ),
    )
    group("alerts", (("log_alert_level", "3"),))
    group("logging", (("log_format", "plain"),))
    for name in ("active-response", "auth", "cluster", "rootcheck", "syscheck"):
        group(name, (("disabled", "yes"),))
    group("sca", (("enabled", "no"),))
    for name in ("syscollector", "osquery", "docker-listener"):
        group("wodle", (("disabled", "yes"),), name=name)
    group("vulnerability-detection", (("enabled", "no"),))
    group("indexer", (("enabled", "no"),))
    group(
        "ruleset",
        (
            ("decoder_dir", "ruleset/decoders"),
            ("rule_dir", "ruleset/rules"),
            ("rule_include", "etc/rules/signalbridge_enterprise_rules.xml"),
        ),
    )
    # Fixed entries avoid accidentally collecting extra wildcard matches.
    # Missing segments are discovered using the reviewed one-second interval.
    for app in APPS:
        for channel in CHANNELS:
            for number in range(8):
                local = group(
                    "localfile",
                    (
                        ("location", segmented_location(app, channel, number)),
                        ("log_format", "json"),
                    ),
                )
                ET.SubElement(local, "only-future-events", {"max-size": "16MB"}).text = "no"
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf8", xml_declaration=False) + b"\n"


def _tree(node):
    # Ignore formatting only; attributes, order, duplicates and mixed content
    # are part of the closed configuration contract.
    return (
        node.tag,
        tuple(sorted(node.attrib.items())),
        (node.text or "").strip(),
        (node.tail or "").strip(),
        tuple(_tree(child) for child in node),
    )


def verify_configuration(raw, internal):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_CONFIG_BYTES, "collector_config_size")
    require(b"<!" not in raw and b"<?" not in raw, "collector_config_declaration")
    try:
        node = ET.fromstring(raw)
    except (ET.ParseError, ValueError) as error:
        raise ValueError("collector_config_xml") from error
    require(_tree(node) == _tree(ET.fromstring(configuration())), "collector_config_changed")
    require(internal == INTERNAL_OPTIONS, "collector_internal_options_changed")
    return {
        "configuration_sha256": hashlib.sha256(raw).hexdigest(),
        "internal_options_sha256": hashlib.sha256(internal).hexdigest(),
        "monitored_paths": 32,
        "apps": list(APPS),
        "native_execution_verified": False,
    }


def recipe():
    """Exact proposal; a recipe is never launch authorization or a runtime gate."""
    return {
        "schema_version": 1,
        "status": "native_bootstrap_controller_prepared_pending_review_and_genuine_inputs",
        "scope": "two_reference_applications_metadata_only",
        "apps": list(APPS),
        "channels": list(CHANNELS),
        "image": IMAGE,
        "pull_policy": "never",
        "native_processes": list(DAEMONS),
        "stock_init": False,
        "native_driver": "integrations/wazuh_enterprise/native_collector.py",
        "host_controller": "scripts/enterprise_wazuh_verify.py",
        "native_driver_entrypoint": "/var/ossec/framework/python/bin/python3",
        "native_driver_arguments": ["-B", "-m", "integrations.wazuh_enterprise.native_collector"],
        "native_working_directory": "/workspace",
        "container": {
            "user": "0:0",
            "network": "none",
            "published_ports": 0,
            "restart": "no",
            "root_filesystem": "disposable_writable",
            "cap_drop": ["ALL"],
            "cap_add": ["SETUID", "SETGID", "SYS_CHROOT"],
            "privileged": False,
            "no_new_privileges": True,
            "docker_socket": False,
            "host_namespaces": False,
            "memory_bytes": 1536 * 1024**2,
            "memory_swap_bytes": 1536 * 1024**2,
            "cpus": 1,
            "pids": 256,
            "init": True,
            "shm_bytes": 16777216,
            "ipc": "private",
            "cgroup": "private",
            "container_log_max_bytes": 2097152,
            "container_log_files": 2,
            "input_mounts_readonly": [
                f"/signalbridge/input/{app}/{channel}" for app in APPS for channel in CHANNELS
            ],
            "source_mount_readonly": "/workspace",
            "private_evidence_mount": "/evidence",
            "other_project_mounts": False,
        },
        "limits": {
            "collector_seconds": 600,
            "independent_host_shutdown_seconds": 900,
            "minimum_free_disk_bytes": 25 * 1024**3,
            "minimum_host_available_memory_bytes": 4 * 1024**3,
            "minimum_host_available_memory_before_launch_bytes": (4 * 1024**3) + (1536 * 1024**2),
            "whole_stage_disk_guard_bytes": 12 * 1024**3,
            "additional_milestone_disk_ceiling_bytes": 30 * 1024**3,
            "combined_milestone_guest_container_memory_bytes": 10 * 1024**3,
            "native_record_bytes": 16384,
            "private_output_bytes": 128 * 1024**2,
        },
        "input": {
            "segments_per_app_channel": 8,
            "segment_bytes": 2 * 1024**2,
            "batch_bytes": 128 * 1024,
            "closed_enterprise_packets_only": True,
            "actor_resource_content_credentials": False,
            "published_export_inventory_required": True,
            "bootstrap_logical_records": 128,
            "bootstrap_input_bytes": 128 * 1024,
        },
        "configuration_sha256": hashlib.sha256(configuration()).hexdigest(),
        "internal_options_sha256": hashlib.sha256(INTERNAL_OPTIONS).hexdigest(),
        "launch_authorized": False,
        "native_execution_verified": False,
        "required_before_launch": [
            "Current cached immutable image inspection; stop if absent, no automatic pull.",
            "A fresh native reference-access run that produces the fixed 23-observation/one-forwarded-R3 Wazuh snapshot; host validation must recompute its exact source, case, packet and manifest bindings. Historical or modeled packets are not source proof.",
            "Current-source verification, private run ACLs, reviewed host/process controller and effective container/kernel isolation.",
            "Independent host watchdog, resource rechecks, exact user approval and both verified shutdown paths.",
        ],
        "acceptance_boundary": (
            "A ten-minute snapshot bootstrap cannot certify live outbox propagation, collector/input rotation recovery, "
            "the 24-hour workload or container/host restart recovery. A durable journal drains pinned output generations "
            "at rotation; missing prior inodes or incomplete final lines fail explicitly. Native rotation is unverified. "
            "Collector interruption may repeat native records; distinguish physical copies, capture retries and logical events. "
            "No indexer/dashboard, host monitoring, containment, paid service or external access."
        ),
    }


def _typed_equal(value, expected):
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(value) == set(expected) and all(
            _typed_equal(value[k], v) for k, v in expected.items()
        )
    if isinstance(expected, list):
        return len(value) == len(expected) and all(
            _typed_equal(a, b) for a, b in zip(value, expected, strict=True)
        )
    return value == expected


def verify_recipe(value):
    require(_typed_equal(value, recipe()), "collector_recipe_changed")
    return {"launch_authorized": False, "native_execution_verified": False}
