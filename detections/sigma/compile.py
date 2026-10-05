"""Compile the SignalBridge Sigma rules to Splunk SPL, Microsoft Sentinel KQL and SQLite.

Run from the repository root:
    python -m detections.sigma.compile          # rewrite compiled/
    python -m detections.sigma.compile --check  # fail if compiled/ is out of date
"""

import argparse
import json
import sys
from importlib.metadata import version
from pathlib import Path

from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation

HERE = Path(__file__).parent
RULES = HERE / "rules"
COMPILED = HERE / "compiled"
DETECTIONS = ("R1", "R2", "R3", "R4", "R5")
SPLUNK_SOURCETYPE = "signalbridge:access"
SENTINEL_TABLE = "SignalBridgeAccess_CL"
PACKAGES = ("pySigma", "pySigma-backend-splunk", "pySigma-backend-kusto", "pySigma-backend-sqlite")


def load():
    rules = SigmaCollection.load_ruleset([RULES])
    rules.resolve_rule_references()
    by_name = {rule.name: rule for rule in rules.rules}
    return {rule_id: by_name[f"signalbridge_{rule_id.lower()}"] for rule_id in DETECTIONS}


def with_dependencies(rule, found=None):
    """A correlation converts together with the rules it references, in dependency order."""
    found = [] if found is None else found
    if isinstance(rule, SigmaCorrelationRule):
        for reference in rule.rules:
            with_dependencies(reference.rule, found)
    if rule not in found:
        found.append(rule)
    return found


def splunk_pipeline():
    return ProcessingPipeline(
        name="SignalBridge sourcetype",
        priority=10,
        items=[
            ProcessingItem(
                AddConditionTransformation({"sourcetype": SPLUNK_SOURCETYPE}),
                rule_conditions=[LogsourceCondition(product="signalbridge")],
            )
        ],
    )


def convert(backend, rule):
    """Return the query for this rule, or the backend's reason for not supporting it."""
    try:
        queries = backend.convert(SigmaCollection(with_dependencies(rule)))
    except NotImplementedError as error:
        return None, str(error)
    # Dependencies are emitted first; the rule's own query is last.
    return queries[-1].strip() + "\n", None


def compile_all():
    # Processing pipelines change rule objects in place, so each backend gets a fresh load.
    splunk, kusto, sqlite = load(), load(), load()
    files, support = {}, {}
    for rule_id in DETECTIONS:
        rule = splunk[rule_id]
        spl, spl_gap = convert(SplunkBackend(splunk_pipeline()), rule)
        kql, kql_gap = convert(KustoBackend(), kusto[rule_id])
        sql, sql_gap = convert(sqliteBackend(), sqlite[rule_id])
        if spl:
            files[f"splunk/{rule_id}.spl"] = spl
        if kql:
            files[f"kusto/{rule_id}.kql"] = f"{SENTINEL_TABLE}\n| where {kql}"
        support[rule_id] = {
            "sigma_rule": rule.name,
            "splunk_spl": "converted" if spl else f"unsupported: {spl_gap}",
            "sentinel_kql": "converted" if kql else f"unsupported: {kql_gap}",
            "sqlite": "converted" if sql else f"unsupported: {sql_gap}",
        }
    manifest = {
        "packages": {name: version(name) for name in PACKAGES},
        "splunk_sourcetype": SPLUNK_SOURCETYPE,
        "sentinel_table": SENTINEL_TABLE,
        "rules": support,
    }
    files["support.json"] = json.dumps(manifest, indent=2) + "\n"
    return files


def sqlite_queries():
    """SQLite queries for the replay; generated on demand, not committed."""
    return {rule_id: convert(sqliteBackend(), rule)[0] for rule_id, rule in load().items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if compiled/ is out of date")
    args = parser.parse_args()
    expected = compile_all()
    present = {
        path.relative_to(COMPILED).as_posix(): path.read_text(encoding="utf-8")
        for path in COMPILED.rglob("*")
        if path.is_file()
    }
    if args.check:
        if present != expected:
            stale = sorted(
                set(present) ^ set(expected)
                | {name for name in expected if present.get(name) != expected[name]}
            )
            print("compiled/ is out of date:", ", ".join(stale))
            return 1
        print(f"compiled/ is current ({len(expected)} files)")
        return 0
    for name in set(present) - set(expected):
        (COMPILED / name).unlink()
    for name, text in expected.items():
        target = COMPILED / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(expected)} files to {COMPILED}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
