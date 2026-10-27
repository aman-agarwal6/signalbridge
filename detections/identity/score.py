"""Score the identity rules, and SigmaHQ's rules for the same attacks, on public attack logs.

The logs are Splunk's attack_data captures, pinned in sources.json and fetched by fetch.py. For
each file, sources.json says which rules should fire. Expectations for W1-W4 and E1-E8 were set
before the first scoring run; W5's were added after it (see changes_after_first_run). Every rule
is compiled with pySigma's SQLite backend and run on an in-memory table holding that file's
events for the rule's log source. A rule fires if its query returns any row.

Matching follows Sigma's rules: string comparisons ignore letter case (the table's columns use
COLLATE NOCASE; the SQLite backend alone would compare exact strings case-sensitively).

Run from the repository root:
    python -m detections.identity.fetch          # once; downloads and verifies the inputs
    python -m detections.identity.score          # rewrite score-report.json
    python -m detections.identity.score --check  # fail if the report is out of date
"""

import argparse
import hashlib
import json
import sqlite3
import sys
from importlib.metadata import version
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaDetection

from ..sigma.compile import with_dependencies
from .fetch import is_verified, load_sources, local_file
from .logs import ENTRA_COLUMNS, LOG_SOURCES, read_rows

HERE = Path(__file__).parent
RULES = HERE / "rules"
REPORT = HERE / "score-report.json"
PACKAGES = ("pySigma", "pySigma-backend-sqlite")
DETECTIONS = {
    "W1": "identity_kerberoasting_burst",
    "W2": "identity_windows_password_spray",
    "W3": "identity_windows_disabled_account_logon",
    "W4": "identity_kerberos_preauth_disabled",
    "W5": "identity_windows_ntlm_password_spray",
    "E1": "identity_entra_password_spray",
    "E2": "identity_entra_mfa_fatigue",
    "E3": "identity_entra_device_code_signin",
    "E4": "identity_entra_auth_method_registered",
    "E5": "identity_entra_temporary_access_pass",
    "E6": "identity_entra_app_consent",
    "E7": "identity_entra_app_credential_added",
    "E8": "identity_entra_disabled_account_signin",
}


def sha256(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def log_source(rule):
    if isinstance(rule, SigmaCorrelationRule):
        return log_source(rule.rules[0].rule)
    return f"{rule.logsource.product}/{rule.logsource.service}"


def detection_fields(detection):
    for item in detection.detection_items:
        if isinstance(item, SigmaDetection):
            yield from detection_fields(item)
        elif item.field:
            yield item.field


def rule_fields(rule):
    """Every field a rule reads, including the fields its correlation groups and counts by."""
    if isinstance(rule, SigmaCorrelationRule):
        yield from rule.group_by or ()
        if rule.condition.fieldref:
            yield rule.condition.fieldref
        for reference in rule.rules:
            yield from rule_fields(reference.rule)
    else:
        for detection in rule.detection.detections.values():
            yield from detection_fields(detection)


def compiled(rule):
    """The rule (with any rules it references) as one SQLite query."""
    return sqliteBackend().convert(SigmaCollection(with_dependencies(rule)))[-1]


class Rule:
    def __init__(self, key, rule):
        self.key = key
        self.rule = rule
        self.source = log_source(rule)
        self.fields = sorted(set(rule_fields(rule)))
        self.query = compiled(rule)


def load_rules(paths):
    rules = SigmaCollection.load_ruleset(paths)
    rules.resolve_rule_references()
    return {rule.name: rule for rule in rules.rules}


def own_rules():
    by_name = load_rules([RULES])
    return {key: Rule(key, by_name[name]) for key, name in DETECTIONS.items()}


def sigmahq_rules(sources):
    found = {}
    for item in sources["sigmahq_rules"]:
        (rule,) = SigmaCollection.from_yaml(
            local_file("sigmahq", item["path"]).read_text(encoding="utf-8")
        ).rules
        found[item["name"]] = Rule(item["name"], rule)
    return found


def quoted(name):
    return '"' + name.replace('"', '""') + '"'


def hits(rows, rules):
    """Run each rule on the rows of its log source; return the number of rows each returns."""
    columns = {"timestamp": "timestamp"}
    for row in rows:
        for name in row:
            columns.setdefault(name.lower(), name)
    for rule in rules:
        for name in rule.fields:
            columns.setdefault(name.lower(), name)
    names = list(columns.values())
    db = sqlite3.connect(":memory:")
    try:
        db.execute(
            "CREATE TABLE logs ("
            + ", ".join(quoted(name) + " TEXT COLLATE NOCASE" for name in names)
            + ")"
        )
        lookup = [{key.lower(): value for key, value in row.items()} for row in rows]
        db.executemany(
            "INSERT INTO logs VALUES (" + ", ".join("?" for _ in names) + ")",
            [tuple(row.get(name.lower()) for name in names) for row in lookup],
        )
        return {rule.key: len(db.execute(rule.query).fetchall()) for rule in rules}
    finally:
        db.close()


def run(rows_by_source, rules):
    """Hits for every rule whose log source has rows; rules without rows return nothing."""
    result = {}
    for source in LOG_SOURCES:
        applicable = [rule for rule in rules.values() if rule.source == source]
        if rows_by_source.get(source) and applicable:
            result.update(hits(rows_by_source[source], applicable))
    return {key: count for key, count in sorted(result.items()) if count}


def present_fields(rows):
    return {name.lower() for row in rows for name, value in row.items() if value not in (None, "")}


def rule_summary(rules, datasets, side):
    summary = {}
    for key, rule in rules.items():
        caught, missed, unexpected = [], [], []
        for dataset in datasets:
            expected, fired = key in dataset["expect"][side], key in dataset[side]
            if expected and fired:
                caught.append(dataset["id"])
            elif expected:
                missed.append(dataset["id"])
            elif fired:
                unexpected.append(dataset["id"])
        summary[key] = {
            "name": rule.rule.name or key,
            "title": rule.rule.title,
            "level": str(rule.rule.level) if rule.rule.level else None,
            "log_source": rule.source,
            "caught": caught,
            "missed": missed,
            "unexpected": unexpected,
            "fields": rule.fields,
        }
    return summary


def totals(summary):
    return {
        "expected": sum(len(r["caught"]) + len(r["missed"]) for r in summary.values()),
        "caught": sum(len(r["caught"]) for r in summary.values()),
        "missed": sum(len(r["missed"]) for r in summary.values()),
        "unexpected": sum(len(r["unexpected"]) for r in summary.values()),
        "rules_without_public_data": sorted(
            key for key, r in summary.items() if not r["caught"] and not r["missed"]
        ),
    }


def build_report():
    sources = load_sources()
    missing = [
        item["path"]
        for kind, items in (
            ("attack_data", sources["datasets"]),
            ("sigmahq", sources["sigmahq_rules"]),
        )
        for item in items
        if not is_verified(local_file(kind, item["path"]), item["sha256"], item["bytes"])
    ]
    if missing:
        raise SystemExit(
            f"{len(missing)} pinned file(s) missing or changed; run python -m detections.identity.fetch"
        )
    mine, theirs = own_rules(), sigmahq_rules(sources)
    datasets, seen = [], {source: set() for source in LOG_SOURCES}
    for item in sources["datasets"]:
        rows, ignored = read_rows(local_file("attack_data", item["path"]), item["format"])
        for source, source_rows in rows.items():
            seen[source] |= present_fields(source_rows)
        datasets.append(
            {
                "id": item["id"],
                "technique": item["technique"],
                "path": item["path"],
                "events": {source: len(r) for source, r in rows.items() if r},
                "set_aside": ignored,
                "expect": item["expect"],
                "mine": run(rows, mine),
                "sigmahq": run(rows, theirs),
            }
        )
    rules = {
        "mine": rule_summary(mine, datasets, "mine"),
        "sigmahq": rule_summary(theirs, datasets, "sigmahq"),
    }
    for side in rules.values():
        for rule in side.values():
            rule["fields_never_present"] = [
                name for name in rule["fields"] if name.lower() not in seen[rule["log_source"]]
            ]
    return {
        "kind": "signalbridge-identity-score",
        "sources": {kind: sources[kind] for kind in ("attack_data", "sigmahq")},
        "packages": {name: version(name) for name in PACKAGES},
        "rules_sha256": {
            path.relative_to(RULES).as_posix(): sha256(path)
            for path in sorted(RULES.rglob("*.yml"))
        },
        "method": (
            "Each pinned log file is parsed into rows per Sigma log source (logs.py). Every rule "
            "is compiled by pySigma-backend-sqlite and run on an in-memory table of that file's "
            "rows for the rule's log source, with case-insensitive columns. A rule fires on a file "
            "if its query returns any row; 'hits' counts the rows. Which rules should fire on "
            "each file comes from sources.json. Expectations for W1-W4 and E1-E8 were set "
            "before the first scoring run; W5's were added after it (see "
            "changes_after_first_run in sources.json)."
        ),
        "entra_columns": {column: list(paths) for column, paths in ENTRA_COLUMNS.items()},
        "summary": {side: totals(summary) for side, summary in rules.items()},
        "rules": rules,
        "datasets": datasets,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the report is out of date")
    args = parser.parse_args()
    text = json.dumps(build_report(), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        current = REPORT.read_text(encoding="utf-8") if REPORT.exists() else None
        if current != text:
            print("score-report.json is out of date")
            return 1
        print("score-report.json is current")
        return 0
    REPORT.write_text(text, encoding="utf-8", newline="\n")
    print(json.dumps(json.loads(text)["summary"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
