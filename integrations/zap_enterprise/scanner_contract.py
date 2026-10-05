"""Closed offline scanner input, kernel and API evidence; never runtime attestation."""

import hashlib
import json
import re
import time
from datetime import datetime, timezone

from bridge.contract import timestamp
from integrations.enterprise.reference_kernel import CGROUPS, STATUS

from .capture import PROFILE, identifier, require, validate_pair
from .passive import API_BYTES, Client, validate_request
from .source_reconciliation import SUMMARY_FIELDS

IMAGE = "zaproxy/zap-stable@sha256:71db37cd5b75663b35758d10aaec05bf6fbac23f5020e3046c70e628a5f84efa"
INPUT_BYTES = 128 * 1024
TRANSCRIPT_BYTES = 4 * 1024 * 1024
MEMORY = 2560 * 1024**2
INPUT_FIELDS = {
    "schema_version",
    "profile",
    "source_run_id",
    "source_receipt_sha256",
    "source_sha256",
    "capture_sha256",
    "execution_sha256",
    "execution",
    "phases",
}
ADDON_FIELDS = {
    "id",
    "name",
    "author",
    "changes",
    "description",
    "hash",
    "infoUrl",
    "repoUrl",
    "sizeInBytes",
    "status",
    "url",
    "version",
    "installationStatus",
    "file",
    "mandatory",
}


def receipt_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("ascii")


def digest(value):
    return hashlib.sha256(receipt_bytes(value)).hexdigest()


def hex_value(value, length=64):
    require(isinstance(value, str) and re.fullmatch("[0-9a-f]{" + str(length) + "}", value))
    return value


def validate_input(value, *, now=None):
    require(isinstance(value, dict) and set(value) == INPUT_FIELDS)
    require(len(receipt_bytes(value)) <= INPUT_BYTES)
    require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    require(value["profile"] == PROFILE)
    hex_value(value["source_run_id"], 32)
    for name in ("source_receipt_sha256", "source_sha256", "capture_sha256", "execution_sha256"):
        hex_value(value[name])
    summary, phases = value["execution"], value["phases"]
    require(isinstance(summary, dict) and set(summary) == SUMMARY_FIELDS)
    require(
        summary["profile"] == PROFILE
        and summary["completed"] is True
        and summary["native_zap_executed"] is False
        and summary["failure"] == ""
        and summary["fault_disabled"] is True
    )
    require(summary["restoration_checks"] == {"document_member": True, "operator": True})
    require(all(type(v) is bool for v in summary["restoration_checks"].values()))
    for name in ("phase_requests", "phase_attempted_requests"):
        require(summary[name] == {"fault": 5, "corrected": 5})
        require(all(type(v) is int for v in summary[name].values()))
    validate_pair(phases)
    require(timestamp(summary["captured_at"]) <= (now or datetime.now(timezone.utc)))
    require(
        summary["response_digests"]
        == {
            phase: [hashlib.sha256(row["body"].encode()).hexdigest() for row in rows]
            for phase, rows in phases.items()
        }
    )
    restoration = summary["restoration_event_ids"]
    require(isinstance(restoration, dict) and set(restoration) == {"document_member", "operator"})
    events = [row["event_id"] for rows in phases.values() for row in rows if row["event_id"]]
    events += [identifier(v) for v in restoration.values()]
    require(len(events) == len(set(events)) == 8)
    require(digest(phases) == value["capture_sha256"])
    require(digest(summary) == value["execution_sha256"])
    # A matching input is a binding, not proof of source or scanner execution.
    return {"input_validated": True, "source_capture_attested": False, "runtime_attested": False}


def validate_gate(value, run, input_value, input_raw):
    hex_value(run, 32)
    expected = {
        "run_id": run,
        "runtime_verified": True,
        "source_run_id": input_value["source_run_id"],
        "source_receipt_sha256": input_value["source_receipt_sha256"],
        "input_sha256": hashlib.sha256(input_raw).hexdigest(),
    }
    require(json.dumps(value, sort_keys=True) == json.dumps(expected, sort_keys=True))


def validate_addons(value):
    require(len(receipt_bytes(value)) <= API_BYTES)
    require(isinstance(value, dict) and set(value) == {"installedAddons"})
    addons = value["installedAddons"]
    require(isinstance(addons, list) and 3 <= len(addons) <= 150)
    result = {}
    for item in addons:
        require(isinstance(item, dict) and set(item) == ADDON_FIELDS)
        require(all(isinstance(v, str) and len(v) <= 65536 for v in item.values()))
        name = item["id"]
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) and name not in result)
        require(item["installationStatus"] == "INSTALLED")
        require(re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", item["version"]))
        require(item["mandatory"] in ("true", "false"))
        result[name] = {"version": item["version"], "installation_status": "INSTALLED"}
    require({"exim", "network", "pscanrules"} <= result.keys())
    return result


def verify_kernel(status, cgroups, mountinfo, interfaces):
    require(isinstance(status, str) and len(status) <= 16384)
    require(isinstance(mountinfo, str) and len(mountinfo) <= 131072)
    require(isinstance(cgroups, dict) and set(cgroups) == CGROUPS)
    fields = {}
    for line in status.splitlines():
        key, separator, value = line.partition(":")
        if separator and key in STATUS:
            require(key not in fields)
            fields[key] = value.strip()
    require(set(fields) == STATUS)
    require(all(fields[k].split() == ["1000"] * 4 for k in ("Uid", "Gid")))
    require(fields["Groups"].split() in ([], ["1000"]))
    require(all(fields[k] == "0000000000000000" for k in STATUS if k.startswith("Cap")))
    require(fields["NoNewPrivs"] == "1" and fields["Seccomp"] == "2")
    require(all(type(v) is str and 1 <= len(v) <= 64 for v in cgroups.values()))
    require(cgroups["memory.max"].strip() == str(MEMORY))
    require(cgroups["memory.swap.max"].strip() == "0" and cgroups["pids.max"].strip() == "256")
    cpu = cgroups["cpu.max"].split()
    require(len(cpu) == 2 and all(v.isascii() and v.isdecimal() for v in cpu))
    require(1000 <= int(cpu[1]) <= 1000000 and int(cpu[0]) * 2 == int(cpu[1]) * 3)
    require(isinstance(interfaces, list) and interfaces == ["lo"])
    expected = {"/": True, "/workspace": True, "/input": True, "/evidence": False, "/tmp": False}
    observed = {}
    for line in mountinfo.splitlines():
        columns = line.split()
        if len(columns) < 10 or columns[4] not in expected:
            continue
        target, options = columns[4], set(columns[5].split(","))
        require(target not in observed)
        require(("ro" in options) == expected[target] and ("rw" in options) != expected[target])
        if target == "/tmp":
            require({"noexec", "nosuid", "nodev"} <= options)
            require("-" in columns and columns[columns.index("-") + 1] == "tmpfs")
        observed[target] = True
    require(set(observed) == set(expected))
    return {
        "uid": 1000,
        "gid": 1000,
        "supplementary_groups": [int(v) for v in fields["Groups"].split()],
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


class TranscriptClient(Client):
    """Retain only closed API exchanges, capped independently of call/body bounds."""

    def __init__(self, key, deadline):
        super().__init__(key, deadline)
        self.transcript, self.transcript_bytes = [], 0

    def request(self, method, path, body=None):
        validate_request(method, path, body)
        started = time.monotonic()
        entry = {"method": method, "path": path}
        # The parent allowlist is checked before any socket or transcript write.
        try:
            value = super().request(method, path, body)
        except Exception as error:
            entry.update(error_class=type(error).__name__, calls_attempted=self.calls)
            self.record(entry)
            raise
        entry.update(response=value, elapsed_seconds=round(time.monotonic() - started, 6))
        if body is not None:
            entry["body_sha256"] = hashlib.sha256(body).hexdigest()
        self.record(entry)
        return value

    def record(self, entry):
        raw = receipt_bytes(entry)
        require(self.key.encode() not in raw and len(raw) <= API_BYTES + 8192)
        require(self.transcript_bytes + len(raw) <= TRANSCRIPT_BYTES)
        self.transcript_bytes += len(raw)
        self.transcript.append(entry)
