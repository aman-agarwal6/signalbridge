"""Inspect only committed, scoped export bytes for a future native collector.

This is an idle-export preparation check, not an ongoing publisher protocol or
source/runtime attestation. No database, process, network, or manager access.
"""

import hashlib
import os
import re
import stat
from pathlib import Path

from bridge.contract import canonical, parse_json

from .collector_profile import APPS, CHANNELS
from .contract import identifier, require, validate_observation, validate_signal

MAX_SEGMENT_BYTES = 2 * 1024**2
MAX_STREAM_BYTES = 16 * 1024**2
MAX_RECORD_BYTES = 4096
MAX_LOGICAL_RECORDS = 65536
MAX_MANIFEST_BYTES = 32768
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
STREAM_FIELDS = {"app", "channel", "stream_id", "offset", "prefix_sha256", "segments"}
SEGMENT_FIELDS = {"number", "start_offset", "bytes", "sha256", "sealed"}


def _hash(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value), "export_digest")


def manifest(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_MANIFEST_BYTES, "export_manifest_size")
    value = parse_json(raw)
    require(
        type(value) is dict and set(value) == {"manifest_version", "streams"},
        "export_manifest_fields",
    )
    require(
        type(value["manifest_version"]) is int and value["manifest_version"] == 1,
        "export_manifest_version",
    )
    streams = value["streams"]
    require(type(streams) is list and len(streams) == 4, "export_stream_inventory")
    scopes, ids = set(), set()
    for stream in streams:
        require(type(stream) is dict and set(stream) == STREAM_FIELDS, "export_stream_fields")
        app, channel = stream["app"], stream["channel"]
        require(
            isinstance(app, str)
            and app in APPS
            and isinstance(channel, str)
            and channel in CHANNELS,
            "export_scope",
        )
        require((app, channel) not in scopes, "export_duplicate_scope")
        scopes.add((app, channel))
        require(
            type(stream["offset"]) is int and 0 <= stream["offset"] <= MAX_STREAM_BYTES,
            "export_offset",
        )
        _hash(stream["prefix_sha256"])
        segments = stream["segments"]
        require(type(segments) is list and len(segments) <= 8, "export_segment_inventory")
        if stream["stream_id"] is None:
            require(
                not segments and stream["offset"] == 0 and stream["prefix_sha256"] == EMPTY_SHA256,
                "export_unallocated_stream",
            )
            continue
        identifier(stream["stream_id"])
        require(stream["stream_id"] not in ids and segments, "export_stream_identity")
        ids.add(stream["stream_id"])
        offset = 0
        for index, segment in enumerate(segments):
            require(
                type(segment) is dict and set(segment) == SEGMENT_FIELDS, "export_segment_fields"
            )
            require(
                type(segment["number"]) is int
                and segment["number"] == index
                and type(segment["start_offset"]) is int
                and segment["start_offset"] == offset,
                "export_segment_offsets",
            )
            require(
                type(segment["bytes"]) is int and 0 <= segment["bytes"] <= MAX_SEGMENT_BYTES,
                "export_segment_size",
            )
            require(
                type(segment["sealed"]) is bool
                and segment["sealed"] == (index < len(segments) - 1),
                "export_segment_sealing",
            )
            _hash(segment["sha256"])
            offset += segment["bytes"]
        require(offset == stream["offset"], "export_stream_offset")
    require(
        scopes == {(app, channel) for app in APPS for channel in CHANNELS}, "export_scope_inventory"
    )
    return value


def _plain(path, *, directory):
    info = path.lstat()
    require(not (getattr(info, "st_file_attributes", 0) & 0x400), "export_redirected_path")
    require(
        stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "export_path_type"
    )
    if not directory:
        require(info.st_nlink == 1, "export_hardlink")
    return info


def _names(path, maximum):
    result = set()
    with os.scandir(path) as entries:
        for entry in entries:
            require(len(result) < maximum, "export_directory_capacity")
            result.add(entry.name)
    return result


def inspect_exports(input_root, raw_manifest):
    """Bounded files must exactly match the operator's committed SQL snapshot.

    Concurrent or pending writes are rejected rather than called loss. The
    reviewed controller must obtain an idle snapshot and recheck before start.
    """
    value = manifest(raw_manifest)
    root = Path(input_root)
    require(root.is_absolute(), "export_absolute_root")
    for path in (root, *root.parents):
        _plain(path, directory=True)
    require(root.resolve(strict=True) == root, "export_redirected_root")
    require(_names(root, len(APPS) + 1) == set(APPS), "export_root_scope")
    for app in APPS:
        parent = root / app
        _plain(parent, directory=True)
        require(_names(parent, len(CHANNELS) + 1) == set(CHANNELS), "export_channel_inventory")
    counts, total, summaries = {}, 0, []
    for stream in value["streams"]:
        app, channel = stream["app"], stream["channel"]
        parent = root / app / channel
        _plain(parent, directory=True)
        stem = "observations" if channel == "observation" else "detections"
        paths = {f"{stem}-{s['number']:03}.jsonl" for s in stream["segments"]}
        require(_names(parent, 9) == paths, "export_unaccounted_file")
        seen, whole = set(), hashlib.sha256()
        for segment in stream["segments"]:
            path = parent / f"{stem}-{segment['number']:03}.jsonl"
            before = _plain(path, directory=False)
            require(before.st_size == segment["bytes"], "export_pending_or_changed_bytes")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            local, read = hashlib.sha256(), 0
            with os.fdopen(os.open(path, flags), "rb") as handle:
                opened = os.fstat(handle.fileno())
                require(
                    (opened.st_dev, opened.st_ino, opened.st_size, opened.st_nlink)
                    == (before.st_dev, before.st_ino, before.st_size, 1),
                    "export_changed_during_open",
                )
                while line := handle.readline(MAX_RECORD_BYTES + 2):
                    read += len(line)
                    require(
                        read <= segment["bytes"]
                        and len(line) <= MAX_RECORD_BYTES + 1
                        and line.endswith(b"\n"),
                        "export_line_limit",
                    )
                    packet = parse_json(line)
                    row = (validate_observation if channel == "observation" else validate_signal)(
                        packet
                    )
                    require(
                        row["app"] == app and canonical(packet) + b"\n" == line,
                        "export_packet_scope_or_encoding",
                    )
                    key = row["event_id" if channel == "observation" else "signal_id"]
                    require(key not in seen, "export_duplicate_logical_record")
                    seen.add(key)
                    total += 1
                    require(total <= MAX_LOGICAL_RECORDS, "export_record_capacity")
                    local.update(line)
                    whole.update(line)
                after = os.fstat(handle.fileno())
                require(
                    (after.st_size, after.st_mtime_ns) == (opened.st_size, opened.st_mtime_ns),
                    "export_changed_during_read",
                )
            final = _plain(path, directory=False)
            require(
                (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
                == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns),
                "export_replaced_during_read",
            )
            require(
                read == segment["bytes"] and local.hexdigest() == segment["sha256"],
                "export_segment_digest",
            )
        require(whole.hexdigest() == stream["prefix_sha256"], "export_whole_stream_digest")
        counts[f"{app}/{channel}"] = len(seen)
        summaries.append(
            {
                "app": app,
                "channel": channel,
                "stream_id": stream["stream_id"],
                "bytes": stream["offset"],
                "sha256": stream["prefix_sha256"],
                "segments": len(stream["segments"]),
            }
        )
    return {
        "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
        "committed_file_snapshot_verified": True,
        "logical_records": total,
        "scope_counts": counts,
        "streams": summaries,
        "genuine_source_execution_verified": False,
        "native_collector_execution_verified": False,
        "continuous_collection_verified": False,
    }
