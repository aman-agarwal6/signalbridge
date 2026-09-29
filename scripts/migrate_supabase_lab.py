"""Apply an exact private BetTail snapshot only to the verified disposable local lab."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.lab_credentials import read_database_password  # noqa: E402
from scripts.snapshot_app import verify_snapshot  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "var/labs/bettail"


def digest(value):
    return hashlib.sha256(value).hexdigest()


def manifest(snapshot):
    metadata = verify_snapshot(snapshot)
    if metadata["app"] != "bettail":
        raise ValueError("Only the BetTail lab is supported.")
    files = []
    for name, checksum in sorted(metadata["files"].items()):
        if name.startswith("supabase/migrations/"):
            filename = Path(name).name
            if not re.fullmatch(r"\d+_[A-Za-z0-9_]+\.sql", filename):
                raise ValueError("Unexpected migration filename.")
            files.append({"file": filename, "sha256": checksum})
    if not files:
        raise ValueError("The verified snapshot contains no migrations.")
    return metadata, files


def isolation_gate():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/verify_supabase_isolation.py")],
        cwd=ROOT,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode:
        raise ValueError("Live isolation verification failed. No migration is authorized.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    args = parser.parse_args(argv)
    # libpq's PGHOSTADDR/PGSERVICE can redirect even an explicit host. This is a
    # dedicated process; remove all inherited libpq settings before any connection.
    for name in tuple(os.environ):
        if name.upper().startswith("PG"):
            os.environ.pop(name)
    snapshot = args.snapshot.resolve()
    metadata, files = manifest(snapshot)
    isolation_gate()
    password = read_database_password(ROOT)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    report_path = LAB / "migration-runs" / f"{run_id}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": 1,
        "app": "bettail",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "snapshot_digest": metadata["snapshot_digest"],
        "source_revision": metadata["source_revision"],
        "source_dirty": metadata["source_dirty"],
        "files": files,
        "applied": [],
        "status": "running",
        "limits": "Exact source SQL; per-file commits, not an all-or-nothing schema transaction. No cloud target.",
    }

    def save():
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    save()
    try:
        # Both address and name are fixed; no libpq service/env overrides remain.
        with psycopg.connect(
            host="127.0.0.1",
            hostaddr="127.0.0.1",
            sslmode="disable",
            port=55322,
            dbname="postgres",
            user="postgres",
            password=password,
            connect_timeout=4,
            options="-c statement_timeout=45000",
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("select current_setting('cron.launch_active_jobs', true)")
                if cursor.fetchone() != ("off",):
                    raise ValueError("Scheduled jobs must remain disabled.")
                cursor.execute(
                    "select to_regclass('public.profiles'), to_regclass('signalbridge_lab.migrations')"
                )
                if cursor.fetchone() != (None, None):
                    raise ValueError(
                        "The lab is not empty. Preserve it and inspect; automatic replay is refused."
                    )
                cursor.execute("create schema signalbridge_lab")
                cursor.execute(
                    "revoke all on schema signalbridge_lab from public, anon, authenticated"
                )
                cursor.execute(
                    "create table signalbridge_lab.migrations (file text primary key, sha256 text not null, source_revision text not null)"
                )
                connection.commit()
                for item in files:
                    raw = (snapshot / "supabase/migrations" / item["file"]).read_bytes()
                    if digest(raw) != item["sha256"]:
                        raise ValueError("Migration bytes changed after snapshot verification.")
                    cursor.execute(raw.decode("utf-8-sig"), prepare=False)
                    cursor.execute(
                        "insert into signalbridge_lab.migrations values (%s, %s, %s)",
                        (item["file"], item["sha256"], metadata["source_revision"]),
                    )
                    connection.commit()
                    report["applied"].append(item)
                    save()
                cursor.execute(
                    "select file, sha256, source_revision from signalbridge_lab.migrations order by file"
                )
                actual = cursor.fetchall()
                if actual != [(f["file"], f["sha256"], metadata["source_revision"]) for f in files]:
                    raise ValueError("Applied migration ledger did not reconcile.")
                cursor.execute("select current_setting('cron.launch_active_jobs', true)")
                if cursor.fetchone() != ("off",):
                    raise ValueError("Scheduled job safety setting changed.")
                cursor.execute(
                    "select (select enabled from public.result_feed_settings), (select enabled from public.statistics_result_settings), (select enabled from public.push_settings)"
                )
                if cursor.fetchone() != (False, False, False):
                    raise ValueError("An external provider is enabled in the disposable lab.")
                cursor.execute("notify pgrst, 'reload schema'")
                connection.commit()
        if manifest(snapshot) != (metadata, files):
            raise ValueError("Source snapshot changed during migration.")
        isolation_gate()
        report["status"] = "passed"
        state = {
            "schema_version": 1,
            "app": "bettail",
            "isolation_verified": True,
            "snapshot_digest": metadata["snapshot_digest"],
            "migrations": {
                "status": "passed",
                "count": len(files),
                "files": files,
                "source_revision": metadata["source_revision"],
                "digest": digest(json.dumps(files, separators=(",", ":")).encode("utf-8")),
            },
        }
        with (LAB / "lab-state.json").open("x", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2)
    except Exception as error:
        report["status"] = "failed"
        report["error_type"] = type(error).__name__
        report["sqlstate"] = getattr(error, "sqlstate", None)
        # Driver errors can contain connection parameters or source SQL. Keep only
        # the fixed failure class/SQLSTATE already recorded in the bounded receipt.
        (report_path.with_suffix(".error.txt")).write_text(
            "Migration failed. Inspect error_type, sqlstate and completed files in the receipt; "
            "raw driver text is intentionally not retained.\n",
            encoding="utf-8",
        )
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        save()
    print(
        f"Local migration run {report['status']}: {len(report['applied'])}/{len(files)} files. Record: {report_path.relative_to(ROOT)}"
    )
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
