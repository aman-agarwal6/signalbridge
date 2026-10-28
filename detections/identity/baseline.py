"""Measure false alarms: run the Windows identity rules on a week of normal enterprise logs.

The logs are days 1-7 of the Windows host events in Los Alamos National Laboratory's Unified Host
and Network Data Set (2017): de-identified authentication events from most of LANL's Windows
computers, released under CC0 (https://csr.lanl.gov/data/2017/). LANL's own download needs a
registration form, so the files come from Imperial College London's mirror and are pinned by size
and SHA-256 in sources.json ("baseline"). They are about 3 GB, so CI doesn't fetch them; the tests
check that baseline-report.json was built from the current rules and the pinned files.

LANL doesn't label the data. Every alert here counts as a false alarm, so the figures are an
upper bound.

Each Windows rule, mine and SigmaHQ's, runs as in score.py: compiled by pySigma's SQLite backend
and run on a table of rows (logs.lanl_row) with case-insensitive columns. Only the events those
rules name are loaded. The week is scored an hour at a time, with the rules' longest correlation
window before each hour loaded too, so every window ending in the hour sees all of its events.

A correlation query returns one row per qualifying window, so one burst gives many rows. Here an
alert is a run of overlapping qualifying windows for one group, which is what a SIEM that
suppresses repeats per group raises. For single-event rules, every matching event is an alert.

Run from the repository root:
    python -m detections.identity.baseline fetch [--data DIR]   # once; about 3 GB
    python -m detections.identity.baseline score [--data DIR]   # rewrite baseline-report.json
"""

import argparse
import bz2
import hashlib
import json
import re
import sqlite3
import sys
import tempfile
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta
from importlib.metadata import version
from pathlib import Path

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaDetection

from .fetch import DATA, check_url, load_sources, safe_relative
from .logs import LANL_FIELDS, LANL_START, WINDOWS_SECURITY, lanl_row
from .score import PACKAGES, RULES, Rule, compiled, own_rules, quoted, sha256, sigmahq_rules

HERE = Path(__file__).parent
REPORT = HERE / "baseline-report.json"
DEFAULT_DATA = DATA / "lanl"
ALLOWED_HOSTS = {"lanl.ma.ic.ac.uk"}
DAY = 86400
CHUNK = 3600
EVENT_ID = re.compile(rb'"EventID":\s*(\d+)')
TOP_GROUPS = 10
# LANL merged all of its domain controllers into one host with this name.
DOMAIN_CONTROLLERS = "ActiveDirectory"


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def is_pinned(path, item):
    return (
        path.is_file()
        and path.stat().st_size == item["bytes"]
        and file_sha256(path) == item["sha256"]
    )


def download(url, path, item):
    """Stream one file to disk; keep it only if its size and SHA-256 match the pin."""
    check_url(url, ALLOWED_HOSTS)
    request = urllib.request.Request(url, headers={"User-Agent": "signalbridge-identity-baseline"})
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".partial")
    digest, size = hashlib.sha256(), 0
    try:
        with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as out:
            check_url(response.geturl(), ALLOWED_HOSTS)
            for block in iter(lambda: response.read(1 << 20), b""):
                size += len(block)
                if size > item["bytes"]:
                    raise ValueError("larger than sources.json pins")
                digest.update(block)
                out.write(block)
        if size != item["bytes"] or digest.hexdigest() != item["sha256"]:
            raise ValueError("size or SHA-256 does not match sources.json")
        partial.replace(path)
    finally:
        partial.unlink(missing_ok=True)


def fetch(data):
    """Return the number of files that could not be fetched and verified."""
    baseline = load_sources()["baseline"]
    failures = 0
    for item in baseline["files"]:
        path = data / safe_relative(item["path"])
        if is_pinned(path, item):
            continue
        url = baseline["url"].format(path=safe_relative(item["path"]))
        try:
            download(url, path, item)
        except (OSError, ValueError) as error:
            print(f"failed: {url}: {error}")
            failures += 1
            continue
        print(f"fetched {item['path']}")
    return failures


def event_ids(rule):
    """The EventID values a rule names, including those of the rules a correlation counts."""
    if isinstance(rule, SigmaCorrelationRule):
        return set().union(*(event_ids(reference.rule) for reference in rule.rules))
    found = set()

    def walk(detection):
        for item in detection.detection_items:
            if isinstance(item, SigmaDetection):
                walk(item)
            elif item.field == "EventID":
                found.update(str(value) for value in item.value)

    for detection in rule.detection.detections.values():
        walk(detection)
    return found


def windows_rules():
    sides = {"mine": own_rules(), "sigmahq": sigmahq_rules(load_sources())}
    return {
        side: {key: rule for key, rule in rules.items() if rule.source == WINDOWS_SECURITY}
        for side, rules in sides.items()
    }


def table_sql(name, columns, temp=False):
    return (
        f"CREATE {'TEMP ' if temp else ''}TABLE {name} ("
        + ", ".join(quoted(column) + " TEXT COLLATE NOCASE" for column in columns)
        + ")"
    )


def baseline_columns(rules):
    """The columns lanl_row fills, plus every other field a rule reads (always empty here)."""
    columns = ["timestamp", "EventID", *dict.fromkeys(LANL_FIELDS.values()), "IpAddress"]
    columns.append("Workstation")
    for rule in rules:
        for name in rule.fields:
            if name.lower() not in {column.lower() for column in columns}:
                columns.append(name)
    return columns


def extract(path, db_path, keep, columns):
    """Load one day's file into its own database; return a count of every event by EventID."""
    keep = {name.encode() for name in keep}
    seen = Counter()
    insert = f"INSERT INTO events VALUES ({', '.join('?' for _ in columns)})"

    def rows():
        with bz2.open(path, "rb") as stream:
            for line in stream:
                match = EVENT_ID.search(line)
                event_id = match.group(1) if match else b"none"
                seen[event_id.decode()] += 1
                if event_id in keep:
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError(f"{path}: a record is not a JSON object")
                    row = lanl_row(record)
                    yield tuple(row.get(column) for column in columns)

    db = sqlite3.connect(db_path)
    try:
        db.execute(table_sql("events", columns))
        db.executemany(insert, rows())
        db.commit()
    finally:
        db.close()
    return dict(seen)


def load_week(files, columns, keep, work):
    """One table holding the kept events of every day, and each day's event counts."""
    with ProcessPoolExecutor() as pool:
        jobs = {
            day: pool.submit(extract, str(path), str(work / f"{day}.db"), sorted(keep), columns)
            for day, path in files
        }
        counts = {day: job.result() for day, job in jobs.items()}
    (work / "week.db").unlink(missing_ok=True)
    db = sqlite3.connect(work / "week.db")
    db.execute(table_sql("week", columns))
    for day in sorted(counts):
        db.execute("ATTACH DATABASE ? AS day", (str(work / f"{day}.db"),))
        db.execute("INSERT INTO week SELECT * FROM day.events")
        db.commit()
        db.execute("DETACH DATABASE day")
        (work / f"{day}.db").unlink()
    db.execute("CREATE INDEX week_time ON week (timestamp)")
    db.commit()
    return db, counts


def stamp(seconds):
    return (LANL_START + timedelta(seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S.000")


def seconds_of(text):
    return int((datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S") - LANL_START).total_seconds())


def day_of(seconds):
    return f"day-{int(seconds) // DAY + 1:02d}"


def is_correlation(rule):
    return isinstance(rule.rule, SigmaCorrelationRule)


def lead_time(rules):
    spans = [rule.rule.timespan.seconds for rule in rules if is_correlation(rule)]
    return max(spans, default=0)


def lowered(rule):
    """The correlation with its threshold set to 1, so every window reports its count."""
    original = rule.rule.condition
    rule.rule.condition = replace(original, count=1)
    try:
        return Rule(rule.key, rule.rule)
    finally:
        rule.rule.condition = original


def base_coverage(db, rule):
    """Events the correlation's base rules match, and how many carry every group-by field."""
    has_groups = " AND ".join(f"{quoted(name)} IS NOT NULL" for name in rule.rule.group_by)
    db.execute("CREATE TEMP VIEW logs AS SELECT * FROM week")
    try:
        total = grouped = 0
        for reference in rule.rule.rules:
            # A rule a correlation references converts to nothing on its own; a copy does.
            base = type(reference.rule).from_dict(reference.rule.to_dict())
            matched, with_groups = db.execute(
                f"SELECT COUNT(*), COALESCE(SUM({has_groups}), 0) FROM ({compiled(base)})"
            ).fetchone()
            total += matched
            grouped += with_groups
    finally:
        db.execute("DROP VIEW temp.logs")
    return {"events": total, "with_group_fields": grouped}


def run_week(db, rules, columns):
    """Every result row of every rule, scored an hour at a time; each row gets its time."""
    lead = lead_time(rules.values())
    first, last = db.execute("SELECT MIN(timestamp), MAX(timestamp) FROM week").fetchone()
    db.execute(table_sql("logs", columns, temp=True))
    found = {key: [] for key in rules}
    for hour in range(seconds_of(first) // CHUNK * CHUNK, seconds_of(last) + 1, CHUNK):
        db.execute("DELETE FROM temp.logs")
        db.execute(
            "INSERT INTO temp.logs SELECT * FROM week WHERE timestamp >= ? AND timestamp < ?",
            (stamp(hour - lead), stamp(hour + CHUNK)),
        )
        for key, rule in rules.items():
            cursor = db.execute(rule.query)
            names = [column[0] for column in cursor.description]
            for values in cursor:
                row = dict(zip(names, values, strict=True))
                if is_correlation(rule):
                    row["time"] = int(row["occurrence_time"])
                else:
                    row["time"] = seconds_of(row["timestamp"])
                if hour <= row["time"] < hour + CHUNK:
                    found[key].append(row)
    db.execute("DROP TABLE temp.logs")
    return found


def episodes(windows):
    """Merge each group's overlapping qualifying windows into alerts."""
    by_group = defaultdict(list)
    for window in windows:
        by_group[window["group_keys"]].append(
            (window["window_start"], window["window_end"], window["metric_value"])
        )
    alerts = []
    for group, spans in sorted(by_group.items()):
        current = None
        for start, end, metric in sorted(spans):
            if current is not None and start <= current["last"]:
                current["last"] = max(current["last"], end)
                current["peak"] = max(current["peak"], metric)
                current["windows"] += 1
            else:
                current = {"group": group, "time": end, "last": end, "peak": metric, "windows": 1}
                alerts.append(current)
    return alerts


def single_alerts(rows):
    """Each matching event is an alert; its group is the account it names, with its domain
    (for a local account, LANL's domain is the computer)."""
    return [
        {
            "group": json.dumps(
                {
                    "TargetDomainName": (row.get("TargetDomainName") or "").lower(),
                    "TargetUserName": (row.get("TargetUserName") or "").lower(),
                }
            ),
            "time": row["time"],
            "event": f"{row.get('EventID')} {(row.get('Status') or '').lower()}".strip(),
            "host": (row.get("Computer") or "").lower(),
        }
        for row in rows
    ]


def account_kind(group):
    account = json.loads(group).get("TargetUserName")
    if account is None:
        return None
    return "computer" if account.endswith("$") else "user"


def peaks_by_day(rows, days):
    """The highest count any window reached each day, and the group that reached it."""
    best = {day: {"value": 0, "group": None} for day in days}
    for row in sorted(rows, key=lambda row: (row["group_keys"], row["time"])):
        entry = best[day_of(row["time"])]
        if row["metric_value"] > entry["value"]:
            entry.update(value=row["metric_value"], group=json.loads(row["group_keys"]))
    return best


def rule_result(rule, rows, days, present_events, present_fields):
    correlation = is_correlation(rule)
    alerts = episodes(rows) if correlation else single_alerts(rows)
    per_day = {day: {"alerts": 0, "groups": set(), "rows": 0} for day in days}
    for row in rows:
        per_day[day_of(row["time"])]["rows"] += 1
    for alert in alerts:
        entry = per_day[day_of(alert["time"])]
        entry["alerts"] += 1
        entry["groups"].add(alert["group"])
    totals = Counter(alert["group"] for alert in alerts)
    peaks = defaultdict(int)
    for alert in alerts:
        peaks[alert["group"]] = max(peaks[alert["group"]], alert.get("peak", 0))
    names = event_ids(rule.rule)
    result = {
        "title": rule.rule.title,
        "level": str(rule.rule.level) if rule.rule.level else None,
        "kind": "correlation" if correlation else "single event",
        "event_ids": sorted(names),
        "event_ids_absent": sorted(names - present_events),
        "fields_never_present": [
            name for name in rule.fields if name.lower() not in present_fields
        ],
        "alerts": len(alerts),
        "alerts_per_day": round(len(alerts) / len(days), 1),
        "groups": len(totals),
        "per_day": {
            day: {"alerts": e["alerts"], "groups": len(e["groups"]), "rows": e["rows"]}
            for day, e in per_day.items()
        },
        "top_groups": [
            {"group": json.loads(group), "alerts": count}
            | ({"peak": peaks[group]} if correlation else {})
            for group, count in sorted(totals.items(), key=lambda item: (-item[1], item[0]))[
                :TOP_GROUPS
            ]
        ],
    }
    kinds = Counter(account_kind(alert["group"]) for alert in alerts)
    if None not in kinds and kinds:
        result["alerts_by_account_kind"] = dict(sorted(kinds.items()))
    if not correlation:
        result["alerts_by_event"] = dict(sorted(Counter(a["event"] for a in alerts).items()))
        result["alerts_logged_by"] = {
            "domain controllers": sum(a["host"] == DOMAIN_CONTROLLERS.lower() for a in alerts),
            "other computers": sum(a["host"] != DOMAIN_CONTROLLERS.lower() for a in alerts),
        }
    return result


def week_counts(db):
    """Loaded events by EventID and Status, and logon failures (4625) by LANL's reason text."""
    by_status = {
        f"{event_id} {status.lower() if status else '-'}": count
        for event_id, status, count in db.execute(
            "SELECT EventID, Status, COUNT(*) FROM week GROUP BY EventID, Status "
            "ORDER BY CAST(EventID AS INTEGER), Status"
        )
    }
    reasons = {
        reason or "-": count
        for reason, count in db.execute(
            "SELECT FailureReason, COUNT(*) FROM week WHERE EventID = '4625' "
            "GROUP BY FailureReason ORDER BY COUNT(*) DESC, FailureReason"
        )
    }
    return {"by_event_and_status": by_status, "logon_failure_reasons": reasons}


def present(db, columns):
    found = set()
    for column in columns:
        name = quoted(column)
        if db.execute(
            f"SELECT 1 FROM week WHERE {name} IS NOT NULL AND {name} != '' LIMIT 1"
        ).fetchone():
            found.add(column.lower())
    return found


def build_report(data, work):
    sources = load_sources()
    baseline = sources["baseline"]
    files = [
        (f"day-{item['day']:02d}", data / safe_relative(item["path"])) for item in baseline["files"]
    ]
    unpinned = [
        item["path"] for item in baseline["files"] if not is_pinned(data / item["path"], item)
    ]
    if unpinned:
        raise SystemExit(
            f"{len(unpinned)} baseline file(s) missing or changed; "
            "run python -m detections.identity.baseline fetch"
        )
    sides = windows_rules()
    every = [rule for rules in sides.values() for rule in rules.values()]
    keep = set().union(*(event_ids(rule.rule) for rule in every))
    if any(not event_ids(rule.rule) for rule in every):
        raise SystemExit("a Windows rule names no EventID, so the baseline can't be filtered")
    columns = baseline_columns(every)
    db, counts = load_week(files, columns, keep, work)
    try:
        loaded = week_counts(db)
        present_fields = present(db, columns)
        present_events = {
            str(event_id) for (event_id,) in db.execute("SELECT DISTINCT EventID FROM week")
        }
        days = [day for day, _ in files]
        rules = {}
        for side, side_rules in sides.items():
            found = run_week(db, side_rules, columns)
            rules[side] = {
                key: rule_result(rule, found[key], days, present_events, present_fields)
                for key, rule in side_rules.items()
            }
            correlations = {
                key: lowered(rule) for key, rule in side_rules.items() if is_correlation(rule)
            }
            windows = run_week(db, correlations, columns)
            for key in correlations:
                rules[side][key]["threshold"] = side_rules[key].rule.condition.count
                rules[side][key]["peak_per_day"] = peaks_by_day(windows[key], days)
                rules[side][key]["base_events"] = base_coverage(db, side_rules[key])
    finally:
        db.close()
    return {
        "kind": "signalbridge-identity-baseline",
        "baseline": baseline,
        "sigmahq": sources["sigmahq"],
        "packages": {name: version(name) for name in PACKAGES},
        "rules_sha256": {
            path.relative_to(RULES).as_posix(): sha256(path)
            for path in sorted(RULES.rglob("*.yml"))
        },
        "method": (
            "Each pinned day of LANL host logs is read line by line; events whose EventID one of "
            "the Windows rules names become rows with Windows EventData field names (logs.py, "
            "lanl_row). Every rule is compiled by pySigma-backend-sqlite and run on the week an "
            "hour at a time, with the longest correlation window before each hour also loaded. "
            "A correlation alert is a run of overlapping qualifying windows for one group; a "
            "single-event alert is one matching event. LANL doesn't label the data, so every "
            "alert counts as a false alarm."
        ),
        "event_ids_loaded": sorted(keep, key=int),
        "days": {
            day: {
                "events": sum(counts[day].values()),
                "loaded": {
                    event_id: counts[day][event_id]
                    for event_id in sorted(keep, key=int)
                    if counts[day].get(event_id)
                },
            }
            for day in sorted(counts)
        },
        "week_loaded": loaded,
        "rules": rules,
        "not_measured": {
            "entra": (
                "E1-E8 have no benign baseline: no public data set of an organization's Entra "
                "sign-in and audit logs in normal operation was found, and the Entra ID Free "
                "test tenant has no regular traffic."
            ),
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("fetch", "score"))
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA, help="folder for the LANL files")
    parser.add_argument(
        "--work", type=Path, help="keep the working databases here (default: a temporary folder)"
    )
    args = parser.parse_args()
    if args.command == "fetch":
        failures = fetch(args.data)
        if failures:
            print(f"{failures} file(s) failed")
            return 1
        print("all baseline files present and verified")
        return 0
    if args.work:
        args.work.mkdir(parents=True, exist_ok=True)
        report = build_report(args.data, args.work)
    else:
        with tempfile.TemporaryDirectory() as work:
            report = build_report(args.data, Path(work))
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    REPORT.write_text(text, encoding="utf-8", newline="\n")
    summary = {
        side: {key: rule["alerts_per_day"] for key, rule in rules.items()}
        for side, rules in report["rules"].items()
    }
    print(json.dumps({"alerts_per_day": summary}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
