"""Finite host publication after native empty-file readiness, not a lab launcher.

Wazuh's first start tails an existing file even with only-future-events=no.
This alternative prepares empty files, then publishes a frozen snapshot after
the supervisor supplies the real collector's per-file zero counters. Input
mounts remain read-only inside the container; only the reviewed host writes.

No subprocess, Docker, network, automatic retries or deletion. The future
supervisor must verify native origin, mount isolation, capacity and shutdown.
These helpers and a supplied state file alone do not attest native execution.
"""

import hashlib
import os
import stat
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from bridge.contract import canonical, digest, parse_json, timestamp
from integrations.enterprise.verification import private_run_directory

from .collector_source_binding import read_bytes
from .contract import require
from .export_snapshot import MAX_RECORD_BYTES, _plain, manifest
from .native_reconciliation import expected_exports
from .ready_contract import delivery_configuration as delivery_configuration
from .ready_contract import (
    empty_readiness,
    recovery_binding,
    recovery_completion,
    recovery_initial,
    recovery_split,
    validate_stopped,
)

MAX_BYTES = 128 * 1024
READY_SECONDS = 10
PUBLICATION_SECONDS = 60


def _save(path, raw):
    with path.open("xb") as handle:
        require(handle.write(raw) == len(raw), "publisher_short_control_write")
        handle.flush()
        os.fsync(handle.fileno())


def _fingerprint(info):
    return [info.st_dev, info.st_ino]


def _directory(path):
    for candidate in (path, *path.parents):
        _plain(candidate, directory=True)
    require(path.resolve(strict=True) == path, "publisher_redirected_directory")


def _snapshot(directory, raw_manifest):
    frozen = directory / "frozen-input"
    expected = expected_exports(frozen, raw_manifest)
    files = []
    for stream in manifest(raw_manifest)["streams"]:
        stem = "observations" if stream["channel"] == "observation" else "detections"
        for segment in stream["segments"]:
            relative = f"{stream['app']}/{stream['channel']}/{stem}-{segment['number']:03}.jsonl"
            raw = read_bytes(frozen / relative, frozen, MAX_BYTES)
            require(hashlib.sha256(raw).hexdigest() == segment["sha256"], "publisher_frozen_digest")
            files.append(
                {
                    "relative": relative,
                    "location": "/signalbridge/input/" + relative,
                    "bytes": len(raw),
                    "sha256": segment["sha256"],
                    "records": len(raw.splitlines()),
                }
            )
    require(
        1 <= len(files) <= 32 and sum(row["bytes"] for row in files) <= MAX_BYTES,
        "publisher_capacity",
    )
    return files, digest(
        sorted([[*key, packet, location] for key, (packet, location) in expected.items()])
    )


def prepare(workspace, run_id, raw_manifest, *, now=None, recovery=False):
    """A reviewed controller has already copied the snapshot into frozen-input."""
    require(type(recovery) is bool, "publisher_recovery_flag")
    directory = private_run_directory(workspace, run_id)
    _directory(directory)
    files, packets = _snapshot(directory, raw_manifest)
    publisher = directory / "publisher"
    inputs = directory / "input"
    require(not publisher.exists() and not inputs.exists(), "publisher_fresh_run_required")
    publisher.mkdir()
    inputs.mkdir()
    for row in files:
        path = inputs / row["relative"]
        path.parent.mkdir(parents=True, exist_ok=True)
        _directory(path.parent)
        _save(path, b"")
        info = _plain(path, directory=False)
        require(info.st_nlink == 1 and info.st_size == 0)
        row["file_identity"] = _fingerprint(info)
    plan = {
        "schema_version": 1,
        "kind": "signalbridge-wazuh-ready-publication-v1",
        "run_id": run_id,
        "prepared_at": (now or datetime.now(timezone.utc)).isoformat(),
        "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
        "expected_packets_sha256": packets,
        "files": files,
        "maximum_bytes": MAX_BYTES,
        "input_mount_readonly_inside_container": True,
        "native_execution_verified": False,
    }
    if recovery:
        plan["recovery"] = recovery_binding(plan, _frozen(directory, plan))
    _save(publisher / "manifest.json", raw_manifest)
    _save(publisher / "plan.json", canonical(plan) + b"\n")
    _save(publisher / "writer.lock", b"\0")
    return plan


@contextmanager
def _writer_lock(path):
    """OS releases this advisory lock after an interrupted publisher process."""
    before = _plain(path, directory=False)
    require(before.st_nlink == 1 and before.st_size == 1, "publisher_lock_file")
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "r+b", buffering=0) as handle:
        require(
            _fingerprint(os.fstat(handle.fileno())) == _fingerprint(before),
            "publisher_lock_changed",
        )
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _input(directory, row, expected):
    path = directory / "input" / row["relative"]
    _directory(path.parent)
    raw = read_bytes(path, directory / "input", MAX_BYTES)
    info = _plain(path, directory=False)
    require(_fingerprint(info) == row["file_identity"], "publisher_input_replaced")
    require(
        len(raw) <= len(expected) and expected.startswith(raw), "publisher_input_prefix_conflict"
    )
    # A collector may already have consumed an incomplete line. Never append
    # its remainder and pretend that this produced one clean native record.
    require(not raw or raw.endswith(b"\n"), "publisher_interrupted_record")
    return path, info, raw


def _append(path, before, expected, offset, *, deadline):
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "r+b", buffering=0) as handle:
        opened = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 1
            and _fingerprint(opened) == _fingerprint(before)
            and opened.st_size == offset,
            "publisher_input_changed",
        )
        handle.seek(offset)
        for line in expected[offset:].splitlines(keepends=True):
            require(datetime.now(timezone.utc) <= deadline, "publisher_deadline")
            require(
                line.endswith(b"\n") and 0 < len(line) <= MAX_RECORD_BYTES + 1,
                "publisher_record_size_or_boundary",
            )
            # One bounded JSONL record per OS write; short writes remain an
            # incomplete failed run, never automatically retried in place.
            written = handle.write(line)
            os.fsync(handle.fileno())
            require(type(written) is int and written == len(line), "publisher_short_write")
            offset += written
        require(os.fstat(handle.fileno()).st_size == len(expected), "publisher_input_changed")


def completion(plan, files, readiness):
    return {
        "kind": "signalbridge-wazuh-frozen-publication-v1",
        "run_id": plan["run_id"],
        "plan_sha256": digest(plan),
        "readiness_sha256": digest(readiness),
        "files": files,
        "published_bytes": sum(row["bytes"] for row in files),
        "published_records": sum(row["records"] for row in files),
        "native_execution_verified": False,
        "tool_receipt_verified": False,
    }


PLAN_FIELDS = {
    "schema_version",
    "kind",
    "run_id",
    "prepared_at",
    "manifest_sha256",
    "expected_packets_sha256",
    "files",
    "maximum_bytes",
    "input_mount_readonly_inside_container",
    "native_execution_verified",
}


def _frozen(directory, plan):
    return {
        row["relative"]: read_bytes(
            directory / "frozen-input" / row["relative"], directory / "frozen-input", MAX_BYTES
        )
        for row in plan["files"]
    }


def _checked_plan(directory, run_id, *, recovery):
    """Revalidate the retained plan, manifest and frozen bytes before any append."""
    publisher = directory / "publisher"
    plan = parse_json(read_bytes(publisher / "plan.json", publisher, 32768))
    require(
        type(plan) is dict and set(plan) == PLAN_FIELDS | ({"recovery"} if recovery else set()),
        "publisher_plan_fields",
    )
    require(
        type(plan["schema_version"]) is int
        and plan["schema_version"] == 1
        and plan["kind"] == "signalbridge-wazuh-ready-publication-v1"
        and type(plan["maximum_bytes"]) is int
        and plan["maximum_bytes"] == MAX_BYTES
        and plan["input_mount_readonly_inside_container"] is True
        and plan["native_execution_verified"] is False,
        "publisher_plan_profile",
    )
    raw_manifest = read_bytes(publisher / "manifest.json", publisher, 32768)
    files, packets = _snapshot(directory, raw_manifest)
    require(
        plan.get("run_id") == run_id
        and plan.get("expected_packets_sha256") == packets
        and plan.get("manifest_sha256") == hashlib.sha256(raw_manifest).hexdigest(),
        "publisher_plan_binding",
    )
    require(
        [{k: v for k, v in row.items() if k != "file_identity"} for row in plan["files"]] == files,
        "publisher_plan_files",
    )
    require(
        all(
            type(row["file_identity"]) is list
            and len(row["file_identity"]) == 2
            and all(type(value) is int and value >= 0 for value in row["file_identity"])
            for row in plan["files"]
        ),
        "publisher_file_identity",
    )
    source = _frozen(directory, plan)
    for row in plan["files"]:
        require(
            hashlib.sha256(source[row["relative"]]).hexdigest() == row["sha256"],
            "publisher_frozen_changed",
        )
    if recovery:
        base_plan = {key: value for key, value in plan.items() if key != "recovery"}
        require(
            canonical(plan["recovery"]) == canonical(recovery_binding(base_plan, source)),
            "publisher_recovery_binding",
        )
    return plan, files, source


def _begin(directory, plan, source, readiness, raw_state, now):
    """Bind the native empty-file readiness once; later calls must repeat it exactly."""
    publisher = directory / "publisher"
    observed = timestamp(readiness["observed_at"])
    require(
        readiness == empty_readiness(plan, raw_state, observed_at=observed),
        "publisher_readiness_changed",
    )
    current = now or datetime.now(timezone.utc)
    require(observed <= current, "publisher_readiness_future")
    deadline = observed + timedelta(seconds=PUBLICATION_SECONDS)
    require(current <= deadline, "publisher_deadline")
    start_path = publisher / "publication-start.json"
    if not start_path.exists():
        require((current - observed).total_seconds() <= READY_SECONDS, "publisher_readiness_stale")
        for row in plan["files"]:
            require(
                not _input(directory, row, source[row["relative"]])[2], "publisher_input_not_empty"
            )
        state_path = publisher / "readiness-state.json"
        if state_path.exists():
            require(
                read_bytes(state_path, publisher, MAX_BYTES) == raw_state,
                "publisher_state_changed",
            )
        else:
            _save(state_path, raw_state)
        _save(start_path, canonical(readiness) + b"\n")
    else:
        require(
            parse_json(read_bytes(start_path, publisher, 32768)) == readiness,
            "publisher_start_changed",
        )
        require(
            read_bytes(publisher / "readiness-state.json", publisher, MAX_BYTES) == raw_state,
            "publisher_state_changed",
        )
    return deadline


def _record(path, value):
    """Write a completion record once; a repeated call must reproduce it exactly."""
    if path.exists():
        require(
            parse_json(read_bytes(path, path.parent, 32768)) == value, "publisher_record_changed"
        )
    else:
        _save(path, canonical(value) + b"\n")


def _recorded_readiness(directory, plan):
    publisher = directory / "publisher"
    evidence = directory / "evidence"
    raw = read_bytes(evidence / "collector-ready-state.json", directory, MAX_BYTES)
    ready = parse_json(read_bytes(evidence / "collector-ready.json", directory, 32768))
    require(
        canonical(ready)
        == canonical(empty_readiness(plan, raw, observed_at=timestamp(ready["observed_at"]))),
        "publisher_recorded_readiness",
    )
    require(
        read_bytes(publisher / "readiness-state.json", directory, MAX_BYTES) == raw
        and parse_json(read_bytes(publisher / "publication-start.json", directory, 32768)) == ready
        and parse_json(read_bytes(publisher / "plan.json", directory, 32768)) == plan,
        "publisher_recorded_start",
    )
    manifest_raw = read_bytes(publisher / "manifest.json", directory, 32768)
    files, packets = _snapshot(directory, manifest_raw)
    require(
        plan["manifest_sha256"] == hashlib.sha256(manifest_raw).hexdigest()
        and plan["expected_packets_sha256"] == packets,
        "publisher_recorded_binding",
    )
    require(
        [{k: v for k, v in row.items() if k != "file_identity"} for row in plan["files"]] == files,
        "publisher_recorded_files",
    )
    return ready, files


def _matching_records(directory, value, *names):
    for name in names:
        require(
            canonical(parse_json(read_bytes(directory / name, directory, 32768)))
            == canonical(value),
            "publisher_recorded_completion",
        )


def validate_recorded_publication(directory, plan):
    """Recheck retained handshake and exact inputs without appending or launching."""
    if "recovery" in plan:
        return validate_recorded_recovery(directory, plan)
    ready, files = _recorded_readiness(directory, plan)
    for row in plan["files"]:
        expected = read_bytes(directory / "frozen-input" / row["relative"], directory, MAX_BYTES)
        require(_input(directory, row, expected)[2] == expected, "publisher_recorded_input")
    expected_result = completion(plan, files, ready)
    _matching_records(
        directory,
        expected_result,
        "publisher/publication-finished.json",
        "evidence/publication-complete.json",
    )
    return {"readiness_sha256": digest(ready), "publication_sha256": digest(expected_result)}


def validate_recorded_recovery(directory, plan):
    """Recheck the interruption handshake and the rotated plus current input bytes."""
    ready, _ = _recorded_readiness(directory, plan)
    source = _frozen(directory, plan)
    base_plan = {key: value for key, value in plan.items() if key != "recovery"}
    require(
        canonical(plan["recovery"]) == canonical(recovery_binding(base_plan, source)),
        "publisher_recorded_recovery_binding",
    )
    target, phases = recovery_split(plan, source)
    initial = recovery_initial(plan, ready)
    _matching_records(
        directory,
        initial,
        "publisher/publication-initial.json",
        "evidence/publication-initial.json",
    )
    stopped = validate_stopped(
        plan,
        initial,
        parse_json(read_bytes(directory / "evidence/collector-stopped.json", directory, 32768)),
    )
    result = recovery_completion(plan, initial, stopped)
    _matching_records(
        directory,
        result,
        "publisher/publication-finished.json",
        "evidence/publication-complete.json",
    )
    inputs = directory / "input"
    for row in plan["files"]:
        first, rest = phases[row["relative"]]
        current = read_bytes(inputs / row["relative"], inputs, MAX_BYTES)
        if row["relative"] == target:
            rotated = inputs / (target + plan["recovery"]["rotated_suffix"])
            require(read_bytes(rotated, inputs, MAX_BYTES) == first, "publisher_recorded_rotated")
            require(current == rest, "publisher_recorded_rotated_backlog")
        else:
            require(current == first + rest, "publisher_recorded_input")
    return {
        "readiness_sha256": digest(ready),
        "publication_sha256": digest(result),
        "recovery_sha256": digest(stopped),
    }


def publish(workspace, run_id, readiness, raw_state, *, now=None):
    """Finite exact append; resume only a complete-record prefix in this run.

    The caller must continuously enforce the reviewed runtime/capacity watchdog.
    A completed file write is not Wazuh acknowledgement or native proof.
    """
    directory = private_run_directory(workspace, run_id)
    publisher = directory / "publisher"
    _directory(publisher)
    with _writer_lock(publisher / "writer.lock"):
        plan, files, source = _checked_plan(directory, run_id, recovery=False)
        deadline = _begin(directory, plan, source, readiness, raw_state, now)
        recovered, appended = 0, 0
        for row in plan["files"]:
            expected = source[row["relative"]]
            path, before, prefix = _input(directory, row, expected)
            _append(path, before, expected, len(prefix), deadline=deadline)
            require(_input(directory, row, expected)[2] == expected, "publisher_final_bytes")
            recovered += len(prefix)
            appended += len(expected) - len(prefix)
        result = completion(plan, files, readiness)
        _record(publisher / "publication-finished.json", result)
        return {**result, "existing_prefix_bytes": recovered, "appended_bytes_this_call": appended}


def publish_initial(workspace, run_id, readiness, raw_state, *, now=None):
    """Recovery profile, phase one: append each file's first half while the collector runs."""
    directory = private_run_directory(workspace, run_id)
    publisher = directory / "publisher"
    _directory(publisher)
    with _writer_lock(publisher / "writer.lock"):
        plan, _, source = _checked_plan(directory, run_id, recovery=True)
        deadline = _begin(directory, plan, source, readiness, raw_state, now)
        _, phases = recovery_split(plan, source)
        for row in plan["files"]:
            first = phases[row["relative"]][0]
            path, before, prefix = _input(directory, row, first)
            _append(path, before, first, len(prefix), deadline=deadline)
            require(_input(directory, row, first)[2] == first, "publisher_initial_bytes")
        result = recovery_initial(plan, readiness)
        _record(publisher / "publication-initial.json", result)
        return result


def publish_backlog(workspace, run_id, stopped, *, now=None):
    """Recovery profile, phase two, only after the native driver stopped the collector.

    The rotation target is renamed aside and recreated empty at the same monitored
    path (logrotate "create" mode); every file then receives its backlog.
    """
    directory = private_run_directory(workspace, run_id)
    publisher = directory / "publisher"
    inputs = directory / "input"
    _directory(publisher)
    with _writer_lock(publisher / "writer.lock"):
        plan, _, source = _checked_plan(directory, run_id, recovery=True)
        initial = parse_json(read_bytes(publisher / "publication-initial.json", publisher, 32768))
        ready = parse_json(read_bytes(publisher / "publication-start.json", publisher, 32768))
        require(initial == recovery_initial(plan, ready), "publisher_initial_changed")
        validate_stopped(plan, initial, stopped)
        current = now or datetime.now(timezone.utc)
        stopped_at = timestamp(stopped["stopped_at"])
        require(stopped_at <= current, "publisher_stop_future")
        deadline = stopped_at + timedelta(seconds=PUBLICATION_SECONDS)
        require(current <= deadline, "publisher_deadline")
        target, phases = recovery_split(plan, source)
        rotated = inputs / (target + plan["recovery"]["rotated_suffix"])
        for row in plan["files"]:
            first, rest = phases[row["relative"]]
            if row["relative"] != target:
                expected = first + rest
                path, before, prefix = _input(directory, row, expected)
                require(len(prefix) >= len(first), "publisher_initial_missing")
                _append(path, before, expected, len(prefix), deadline=deadline)
                require(_input(directory, row, expected)[2] == expected, "publisher_final_bytes")
                continue
            path = inputs / target
            if not rotated.exists():
                # Exactly the phase-one bytes must be rotated aside.
                require(_input(directory, row, first)[2] == first, "publisher_rotation_source")
                os.rename(path, rotated)
                _save(path, b"")
            require(read_bytes(rotated, inputs, MAX_BYTES) == first, "publisher_rotated_changed")
            _directory(path.parent)
            info = _plain(path, directory=False)
            require(info.st_nlink == 1, "publisher_rotated_identity")
            present = read_bytes(path, inputs, MAX_BYTES)
            require(
                rest.startswith(present) and (not present or present.endswith(b"\n")),
                "publisher_backlog_prefix_conflict",
            )
            _append(path, info, rest, len(present), deadline=deadline)
            require(read_bytes(path, inputs, MAX_BYTES) == rest, "publisher_backlog_bytes")
        result = recovery_completion(plan, initial, stopped)
        _record(publisher / "publication-finished.json", result)
        return result
