"""Opt-in finite enterprise export segments with exact interrupted-write recovery.

No log deletion, native collector launch, network or connection attestation.
Existing streams stay in their original file format; enabling requires a fresh
empty stream. Logical offsets and SHA-256 still cover all retained ordered bytes.
"""

import hashlib
import os
import stat

from django.conf import settings
from django.utils import timezone

from integrations.wazuh_enterprise.contract import (
    APPS,
    EnterpriseWazuhError,
    segmented_location,
    validate_observation,
    validate_signal,
)

from .contract import parse_json
from .models import Audit, SocBatch, SocSegment
from .runtime_identity import _plain_path
from .soc_delivery import (
    MAX_BATCH_BYTES,
    MAX_STREAM_BYTES,
    DeliveryError,
    delivery_location,
    ensure_delivery_root,
    require,
    sha256,
)

SEGMENT_BYTES = 2 * 1024**2
MAX_SEGMENTS = 8
READ_BYTES = 128 * 1024
CHANNEL_FILES = {"observation": "observations", "detection": "detections"}


def segment_path(segment):
    """Run-owned directory; same deterministic mapping may be mounted read-only."""
    path = segment_location(segment)
    root, boundary = ensure_delivery_root()
    require(root in path.parents, "unsafe_segment_directory")
    parent = root
    for name in path.parent.relative_to(root).parts:
        current = parent / name
        _plain_path(current, directory=True)
        current.mkdir(exist_ok=True)
        _plain_path(current, directory=True)
        require(current.resolve(strict=True).is_relative_to(boundary), "unsafe_segment_directory")
        parent = current
    _plain_path(path, directory=False)
    if path.exists():
        require(path.is_file() and path.stat().st_nlink == 1, "unsafe_segment_file")
    return path


def segment_location(segment):
    """Return the deterministic path without creating or inspecting files."""
    stream = segment.stream
    require(
        stream.segmented_export
        and stream.integration.slug in APPS
        and stream.channel in CHANNEL_FILES,
        "invalid_segment_scope",
    )
    require(
        type(segment.number) is int and 0 <= segment.number < MAX_SEGMENTS, "invalid_segment_number"
    )
    root, _boundary = delivery_location()
    return (
        root
        / "enterprise"
        / stream.integration.slug
        / stream.channel
        / str(stream.pk)
        / f"{CHANNEL_FILES[stream.channel]}-{segment.number:03}.jsonl"
    )


def _metadata(stream):
    segments = list(
        SocSegment.objects.filter(stream=stream)
        .select_related("stream__integration")
        .order_by("number")[: MAX_SEGMENTS + 1]
    )
    require(1 <= len(segments) <= MAX_SEGMENTS, "invalid_segment_inventory")
    offset = 0
    for number, segment in enumerate(segments):
        require(
            segment.number == number
            and segment.start_offset == offset
            and 0 <= segment.byte_count <= SEGMENT_BYTES,
            "segment_offset_mismatch",
        )
        require(
            (segment.sealed_at is None) == (number == len(segments) - 1), "segment_sealing_mismatch"
        )
        require(len(segment.prefix_sha256) == 64, "segment_digest_mismatch")
        offset += segment.byte_count
    require(offset == stream.offset <= MAX_STREAM_BYTES, "segment_stream_offset_mismatch")
    return segments


def _prefix(segment, whole):
    """Hash at most one fixed segment, streaming sealed files in small chunks."""
    path = segment_path(segment)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        info = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_size == segment.byte_count,
            "sealed_segment_changed",
        )
        digest, count, last = hashlib.sha256(), 0, b""
        while chunk := handle.read(READ_BYTES):
            require(count + len(chunk) <= segment.byte_count, "sealed_segment_changed")
            digest.update(chunk)
            whole.update(chunk)
            count += len(chunk)
            last = chunk[-1:]
        require(
            count == segment.byte_count
            and digest.hexdigest() == segment.prefix_sha256
            and (count == 0 or last == b"\n"),
            "sealed_segment_changed",
        )


def reserve_segment(stream, body):
    """Within the caller's locked staging transaction, assign immutable file scope."""
    require(0 < len(body) <= MAX_BATCH_BYTES, "invalid_segment_batch_size")
    if not stream.segmented_export:
        if not getattr(settings, "SOC_SEGMENTED_EXPORT", False):
            return None
        require(
            stream.offset == 0 and not SocBatch.objects.filter(stream=stream).exists(),
            "segmentation_requires_fresh_stream",
        )
        stream.segmented_export = True
        stream.save(update_fields=["segmented_export"])
        SocSegment.objects.create(stream=stream, number=0, start_offset=0)
    require(len(body) <= SEGMENT_BYTES, "segment_batch_too_large")
    # This mode is only for closed enterprise records, never legacy v1 exports.
    for line in body.splitlines(keepends=True):
        require(line.endswith(b"\n"), "segment_batch_incomplete")
        try:
            packet = parse_json(line)
            row = (validate_observation if stream.channel == "observation" else validate_signal)(
                packet
            )
            require(row["app"] == stream.integration.slug, "segment_packet_scope_mismatch")
        except EnterpriseWazuhError as error:
            raise DeliveryError("invalid_enterprise_segment_record") from error
    segments = _metadata(stream)
    current = segments[-1]
    if current.byte_count + len(body) <= SEGMENT_BYTES:
        return current
    require(current.number + 1 < MAX_SEGMENTS, "segment_capacity_reached")
    whole = hashlib.sha256()
    for segment in segments:
        _prefix(segment, whole)
    require(whole.hexdigest() == stream.prefix_sha256, "segment_stream_digest_mismatch")
    current.sealed_at = timezone.now()
    current.save(update_fields=["sealed_at"])
    Audit.objects.create(
        integration=stream.integration,
        action="soc.segment_sealed",
        object_id=str(current.pk),
        detail={
            "channel": stream.channel,
            "number": current.number,
            "bytes": current.byte_count,
            "sha256": current.prefix_sha256,
            "native_observed": False,
        },
    )
    return SocSegment.objects.create(
        stream=stream, number=current.number + 1, start_offset=stream.offset
    )


def append_segment(stream, batch, body):
    """Retain exact staged bytes through partial/full file writes before SQL commit."""
    require(stream.segmented_export and batch.segment_id is not None, "missing_batch_segment")
    require(0 < len(body) <= MAX_BATCH_BYTES and body.endswith(b"\n"), "invalid_segment_batch_size")
    segments = _metadata(stream)
    current = segments[-1]
    require(
        current.pk == batch.segment_id
        and batch.start_offset == stream.offset
        and current.byte_count + len(body) <= SEGMENT_BYTES,
        "batch_segment_scope_mismatch",
    )
    whole = hashlib.sha256()
    for sealed in segments[:-1]:
        _prefix(sealed, whole)
    path = segment_path(current)
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not path.exists():
        require(current.byte_count == 0, "segment_missing")
        flags |= os.O_CREAT | os.O_EXCL
    with os.fdopen(os.open(path, flags, 0o600), "r+b") as handle:
        info = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and current.byte_count <= info.st_size <= SEGMENT_BYTES,
            "unsafe_active_segment",
        )
        data = handle.read(SEGMENT_BYTES + 1)
        require(len(data) == info.st_size, "active_segment_changed")
        prefix, tail = data[: current.byte_count], data[current.byte_count :]
        require(sha256(prefix) == current.prefix_sha256, "segment_prefix_changed")
        whole.update(prefix)
        require(whole.hexdigest() == stream.prefix_sha256, "segment_stream_digest_mismatch")
        require(len(tail) <= len(body) and body.startswith(tail), "segment_tail_conflict")
        handle.seek(0, os.SEEK_END)
        require(handle.tell() == len(data), "active_segment_changed")
        remaining = body[len(tail) :]
        if remaining:
            require(handle.write(remaining) == len(remaining), "segment_short_write")
        handle.flush()
        os.fsync(handle.fileno())
    current.byte_count += len(body)
    current.prefix_sha256 = sha256(prefix + body)
    current.save(update_fields=["byte_count", "prefix_sha256"])
    whole.update(body)
    return stream.offset + len(body), whole.hexdigest(), len(tail)


def export_inventory(stream):
    """Read bounded metadata for operator inspection; not native collector health."""
    if not stream.segmented_export:
        return {"segmented_export": False, "segments": [], "native_observed": False}
    segments = _metadata(stream)
    return {
        "segmented_export": True,
        "segments": [
            {
                "number": s.number,
                "start_offset": s.start_offset,
                "bytes": s.byte_count,
                "sha256": s.prefix_sha256,
                "sealed": s.sealed_at is not None,
                "collector_location": segmented_location(
                    stream.integration.slug, stream.channel, s.number
                ),
            }
            for s in segments
        ],
        "segment_capacity_bytes": SEGMENT_BYTES,
        "maximum_segments": MAX_SEGMENTS,
        "remaining_segments": MAX_SEGMENTS - len(segments),
        "active_remaining_bytes": SEGMENT_BYTES - segments[-1].byte_count,
        "files_inspected": False,
        "native_observed": False,
    }
