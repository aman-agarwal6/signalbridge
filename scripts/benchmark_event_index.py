"""Fixed SQLite microbenchmark; memory only, no app settings, files or network."""

import json
import sqlite3
import statistics
import sys
from time import perf_counter

QUERY = "SELECT COUNT(*) FROM bridge_event WHERE integration_id = ? AND received_at >= ?"


def measure(database, cutoff, repeats):
    steps = 0

    def progress():
        nonlocal steps
        steps += 1
        return 0

    plan = [row[3] for row in database.execute("EXPLAIN QUERY PLAN " + QUERY, (1, cutoff))]
    database.set_progress_handler(progress, 1)
    try:
        count = database.execute(QUERY, (1, cutoff)).fetchone()[0]
    finally:
        database.set_progress_handler(None, 0)
    timings = []
    for _ in range(repeats):
        start = perf_counter()
        measured_count = database.execute(QUERY, (1, cutoff)).fetchone()[0]
        if measured_count != count:
            raise RuntimeError("The measured query changed its result.")
        timings.append((perf_counter() - start) * 1000)
    return {
        "matched_records": count,
        "sqlite_vm_instructions": steps,
        "query_plan": plan,
        "median_ms": round(statistics.median(timings), 6),
    }


def benchmark(history=10000, repeats=25):
    if type(history) is not int or not 1000 <= history <= 20000:
        raise ValueError("Use between 1000 and 20000 synthetic history rows.")
    if type(repeats) is not int or not 1 <= repeats <= 50:
        raise ValueError("Use between one and 50 repetitions.")
    database = sqlite3.connect(":memory:")
    try:
        database.execute(
            "CREATE TABLE bridge_event (id INTEGER PRIMARY KEY, integration_id INTEGER NOT NULL, "
            "received_at INTEGER NOT NULL)"
        )
        database.execute("CREATE INDEX existing_app_fk ON bridge_event (integration_id)")
        database.executemany(
            "INSERT INTO bridge_event (integration_id, received_at) VALUES (?, ?)",
            ((app, at) for app in (1, 2) for at in range(history)),
        )
        # Include the cutoff itself and recent records from an unrelated app.
        cutoff = history - 60
        before = measure(database, cutoff, repeats)
        database.execute(
            "CREATE INDEX sb_event_app_received ON bridge_event (integration_id, received_at)"
        )
        after = measure(database, cutoff, repeats)
        if before["matched_records"] != 60 or after["matched_records"] != 60:
            raise RuntimeError("The scoped range query changed its result.")
        return {
            "schema_version": 1,
            "kind": "signalbridge-event-index-microbenchmark",
            "sqlite_version": sqlite3.sqlite_version,
            "rows_per_app": history,
            "applications": 2,
            "timing_repetitions": repeats,
            "before": before,
            "after": after,
            "instruction_reduction_percent": round(
                100 * (1 - after["sqlite_vm_instructions"] / before["sqlite_vm_instructions"]), 2
            ),
            "limits": [
                "Fixed in-memory relational microbenchmark of the collector's scoped COUNT query.",
                "Minimal table models its predicate/index columns, not the entire application schema.",
                "No live data, HTTP, collector throughput, PostgreSQL or enterprise capacity is measured.",
                "Instruction counts use SQLite's progress handler; timings run separately without it.",
                "The additional index consumes storage and adds work to event insertions and deletion.",
            ],
        }
    finally:
        database.close()


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("This fixed benchmark accepts no command-line arguments.")
    print(json.dumps(benchmark(), indent=2))
