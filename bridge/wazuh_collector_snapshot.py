"""Trusted local operator snapshot of idle reference-app enterprise exports.

No collector launch, source classification change or imported tool observation.
Cooperating publishers/disable operations use the same application-row locks.
Native PostgreSQL concurrency and private host ACL enforcement remain required.
"""

import hashlib
import os
import stat
from pathlib import Path

from django.conf import settings
from django.db import transaction

from integrations.wazuh_enterprise.collector_profile import APPS, CHANNELS
from integrations.wazuh_enterprise.contract import identifier
from integrations.wazuh_enterprise.export_snapshot import EMPTY_SHA256, inspect_exports, manifest

from .contract import canonical
from .models import Audit, Integration, SocBatch, SocStream
from .runtime_identity import _plain_path
from .soc_delivery import ensure_delivery_root, require
from .soc_rotation import _metadata

CHUNK_BYTES = 128 * 1024


def _plan():
    streams, sources = [], []
    integrations = list(Integration.objects.filter(slug__in=APPS).order_by("pk"))
    require(len(integrations) == len(APPS), "collector_app_inventory")
    for integration in integrations:
        app = integration.slug
        require(
            Integration.objects.filter(pk=integration.pk, enabled=True).update(enabled=True) == 1,
            "collector_app_disabled",
        )
        for channel in CHANNELS:
            stream = SocStream.objects.filter(integration=integration, channel=channel).first()
            row = {
                "app": app,
                "channel": channel,
                "stream_id": None,
                "offset": 0,
                "prefix_sha256": EMPTY_SHA256,
                "segments": [],
            }
            if stream:
                require(
                    not SocBatch.objects.filter(stream=stream, state="staged").exists(),
                    "collector_snapshot_pending_batch",
                )
                if not stream.segmented_export:
                    require(
                        stream.offset == 0 and not SocBatch.objects.filter(stream=stream).exists(),
                        "collector_snapshot_legacy_stream",
                    )
                else:
                    row.update(
                        stream_id=str(stream.pk),
                        offset=stream.offset,
                        prefix_sha256=stream.prefix_sha256,
                    )
                    for segment in _metadata(stream):
                        row["segments"].append(
                            {
                                "number": segment.number,
                                "start_offset": segment.start_offset,
                                "bytes": segment.byte_count,
                                "sha256": segment.prefix_sha256,
                                "sealed": segment.sealed_at is not None,
                            }
                        )
                        from .soc_rotation import segment_location

                        path = segment_location(segment)
                        sources.append(
                            (
                                path,
                                app,
                                channel,
                                segment.number,
                                segment.byte_count,
                                segment.prefix_sha256,
                            )
                        )
            streams.append(row)
    return {"manifest_version": 1, "streams": streams}, sources


def _directory(parent, name, boundary):
    path = parent / name
    _plain_path(path, directory=True)
    path.mkdir(exist_ok=True)
    _plain_path(path, directory=True)
    require(
        path.resolve(strict=True).is_relative_to(boundary),
        "collector_snapshot_path",
    )
    return path


def _snapshot_location():
    workspace = Path(settings.BASE_DIR).resolve(strict=True)
    default = workspace / "var" / "wazuh-enterprise" / "native"
    configured = Path(getattr(settings, "WAZUH_SNAPSHOT_ROOT", default))
    if configured == default:
        boundary = workspace
    else:
        boundary = Path("/evidence")
        require(
            configured == Path("/evidence/wazuh-enterprise/native")
            and os.name != "nt"
            and os.environ.get("SB_SOURCE_PROOF") == "1"
            and os.environ.get("SB_SOURCE_COMPONENT") == "console",
            "collector_snapshot_path",
        )
        _plain_path(boundary, directory=True)
        require(boundary.resolve(strict=True) == boundary, "collector_snapshot_path")
    return configured, boundary


def _root(run):
    configured, boundary = _snapshot_location()
    relative = configured.relative_to(boundary)
    parent = boundary
    for name in relative.parts:
        parent = _directory(parent, name, boundary)
    root = parent / run
    _plain_path(root, directory=True)
    require(not root.exists(), "collector_snapshot_run_exists")
    root.mkdir()
    _plain_path(root, directory=True)
    return root


def _copy(source, destination, size, expected):
    root, _boundary = ensure_delivery_root()
    for path in (source, *source.parents):
        _plain_path(path, directory=path != source)
        require(path.exists(), "collector_snapshot_source_missing")
        if path == root:
            break
    require(
        source.resolve().is_relative_to(root.resolve(strict=True)),
        "collector_snapshot_source_path",
    )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(source, flags), "rb") as incoming:
        info = os.fstat(incoming.fileno())
        require(
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == size,
            "collector_snapshot_source_changed",
        )
        digest, count = hashlib.sha256(), 0
        with destination.open("xb") as outgoing:
            while chunk := incoming.read(CHUNK_BYTES):
                require(count + len(chunk) <= size, "collector_snapshot_source_changed")
                require(outgoing.write(chunk) == len(chunk), "collector_snapshot_short_write")
                digest.update(chunk)
                count += len(chunk)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        after = os.fstat(incoming.fileno())
        _plain_path(source, directory=False)
        final = source.stat()
        require(
            (after.st_size, after.st_mtime_ns) == (info.st_size, info.st_mtime_ns)
            and (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
            == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns),
            "collector_snapshot_source_changed",
        )
        require(
            count == size and digest.hexdigest() == expected, "collector_snapshot_source_digest"
        )


@transaction.atomic(durable=True)
def capture_idle_exports(run, *, dry_run=False):
    require(settings.LOCAL, "collector_snapshot_local_only")
    identifier(run)
    value, sources = _plan()
    raw = canonical(value) + b"\n"
    manifest(raw)
    if dry_run:
        return {
            "run_id": run,
            "planned_files": len(sources),
            "planned_bytes": sum(source[4] for source in sources),
            "database_inventory_only": True,
            "files_inspected": False,
            "native_execution_verified": False,
        }
    root = _root(run)
    _, boundary = _snapshot_location()
    inputs = _directory(root, "input", boundary)
    for app in APPS:
        app_root = _directory(inputs, app, boundary)
        for channel in CHANNELS:
            _directory(app_root, channel, boundary)
    for source, app, channel, number, size, expected in sources:
        stem = "observations" if channel == "observation" else "detections"
        _copy(source, inputs / app / channel / f"{stem}-{number:03}.jsonl", size, expected)
    report = inspect_exports(inputs, raw)
    report.update(run_id=run, private_host_acl_verified=False, snapshot_live_after_capture=False)
    # A failure retains partial files without a completed summary; no overwrites.
    for name, data in (("manifest.json", raw), ("snapshot.json", canonical(report) + b"\n")):
        with (root / name).open("xb") as output:
            require(output.write(data) == len(data), "collector_snapshot_short_write")
            output.flush()
            os.fsync(output.fileno())
    for app in APPS:
        Audit.objects.create(
            integration=Integration.objects.get(slug=app),
            action="wazuh.collector_snapshot",
            object_id=run,
            detail={
                "origin": "local_database_operator",
                "manifest_sha256": report["manifest_sha256"],
                "observation_records": report["scope_counts"][f"{app}/observation"],
                "forwarded_signals": report["scope_counts"][f"{app}/detection"],
                "native_execution_verified": False,
            },
        )
    return report
