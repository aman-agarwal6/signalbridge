"""Read only this checkout's BetTail delivery ledger and exact sanitized file."""

import hashlib
import json
import time
import uuid
from collections import Counter
from contextlib import closing
from pathlib import Path

from integrations.wazuh.verify_static import parse_json, validate_export
from integrations.wazuh_backfill.contract import expected_rule, require, validate_input
from scripts.local_backup import DB_LIMIT, bounded_read, connect, local_mode, safe

ROOT = Path(__file__).resolve().parents[2]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def inspect(root=ROOT):
    local_mode()
    root = Path(root).absolute()
    deadline = time.monotonic() + 10
    db = root / "var/signalbridge.sqlite3"
    safe(root, db)
    require(db.stat().st_size <= DB_LIMIT, "database_size")
    with closing(connect(db)) as connection, connection:
        connection.execute("PRAGMA query_only=ON")
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        connection.execute("BEGIN")
        row = connection.execute(
            "SELECT s.id,s.offset,s.prefix_sha256,s.revision,s.integration_id FROM bridge_socstream s JOIN bridge_integration i ON i.id=s.integration_id WHERE i.slug=? AND i.enabled=1",
            ("bettail",),
        ).fetchall()
        require(len(row) == 1, "one_enabled_stream")
        identity, offset, digest, revision, app_id = row[0]
        stream = str(uuid.UUID(identity))
        require(0 < offset <= 128 * 1024, "stream_size")
        path = root / "var/soc-delivery" / (stream + ".jsonl")
        safe(root, path)
        require(path.stat().st_nlink == 1 and path.stat().st_size == offset, "stream_file")
        raw = bounded_read(root, path, 128 * 1024)
        require(len(raw) == offset and sha(raw) == digest, "file_digest")
        batches = connection.execute(
            "SELECT id,body,body_sha256,start_offset,record_count,state FROM bridge_socbatch WHERE stream_id=? ORDER BY start_offset LIMIT 101",
            (identity,),
        ).fetchall()
        require(0 < len(batches) <= 100, "batch_bound")
        assembled = b""
        packets = {}
        batch_meta = []
        for batch_id, body, body_hash, start, count, state in batches:
            require(type(body) is str and len(body) <= 128 * 1024, "batch_size")
            body = body.encode("ascii")
            require(
                state == "file_appended" and start == len(assembled) and (sha(body) == body_hash),
                "batch_integrity",
            )
            lines = body.splitlines(keepends=True)
            require(len(lines) == count and 0 < count <= 100, "batch_count")
            linked = connection.execute(
                "SELECT e.event_id,e.integration_id FROM bridge_socdelivery d JOIN bridge_event e ON e.id=d.event_id WHERE d.batch_id=? LIMIT 101",
                (batch_id,),
            ).fetchall()
            require(len(linked) == count and all((i == app_id for _, i in linked)), "linked_scope")
            ids = set()
            for line in lines:
                require(line.endswith(b"\n"), "partial_record")
                packet = parse_json(line.decode("ascii"))
                event = validate_export(packet)
                require(
                    event["app"] == "bettail"
                    and event["environment"] == "lab"
                    and (
                        event["source"]
                        in {"migration_lab", "synthetic_demo", "legacy_unclassified"}
                    ),
                    "approved_lab_scope",
                )
                require(event["event_id"] not in packets, "duplicate_identity")
                packets[event["event_id"]] = packet
                ids.add(event["event_id"])
            require(ids == {str(uuid.UUID(e)) for e, _ in linked}, "linked_identities")
            assembled += body
            batch_meta.append(
                {
                    "id": str(uuid.UUID(batch_id)),
                    "offset": start,
                    "bytes": len(body),
                    "records": count,
                    "sha256": body_hash,
                }
            )
        require(assembled == raw and 0 < len(packets) <= 100, "whole_stream_match")
    alerts = {
        identity: rule
        for identity, packet in packets.items()
        if (rule := expected_rule(packet["signalbridge"])) is not None
    }
    report = {
        "schema_version": 1,
        "kind": "signalbridge-wazuh-backfill-input",
        "app": "bettail",
        "stream_id": stream,
        "revision": revision,
        "offset": offset,
        "sha256": digest,
        "batches": batch_meta,
        "packets": packets,
        "expected_alerts": alerts,
    }
    validate_input(report, raw)
    return (path, report)


if __name__ == "__main__":
    path, report = inspect()
    print(
        json.dumps(
            {
                "records": len(report["packets"]),
                "bytes": report["offset"],
                "sha256": report["sha256"],
                "alerts": len(report["expected_alerts"]),
                "rules": dict(Counter((rule[0] for rule in report["expected_alerts"].values()))),
            }
        )
    )
