"""Headline identity-detection figures for the offline evidence viewer.

Every figure is recomputed from detections/identity/score-report.json when the page is
built, and the report is checked to reconcile with its own summary. The report is the
output of detections.identity.score, which CI re-runs on the pinned public captures.
"""

import hashlib

REPORT = "detections/identity/score-report.json"
MAX_BYTES = 2 * 1024 * 1024
SIDES = ("mine", "sigmahq")


def flagged(dataset, side):
    return bool(set(dataset[side]) & set(dataset["expect"][side]))


def side_figures(report, side, require):
    rules, summary = report["rules"][side], report["summary"][side]
    caught = sum(len(rule["caught"]) for rule in rules.values())
    missed = sum(len(rule["missed"]) for rule in rules.values())
    unexpected = sum(len(rule["unexpected"]) for rule in rules.values())
    without = sorted(
        key for key, rule in rules.items() if not rule["caught"] and not rule["missed"]
    )
    require(
        summary["caught"] == caught
        and summary["missed"] == missed
        and summary["expected"] == caught + missed
        and summary["unexpected"] == unexpected
        and summary["rules_without_public_data"] == without,
        "Identity score summary does not reconcile with its rules.",
    )
    targeted = [item for item in report["datasets"] if item["expect"][side]]
    return {
        "rules": len(rules),
        "rules_with_data": len(rules) - len(without),
        "without_data": without,
        "files_targeted": len(targeted),
        "files_flagged": sum(flagged(item, side) for item in targeted),
        "pairs_expected": caught + missed,
        "pairs_caught": caught,
        "unexpected": unexpected,
        "message_field_rules": sum(
            "properties.message" in rule["fields_never_present"] for rule in rules.values()
        ),
    }


def load_identity(root, unlinked, json_document, require):
    """Omit the card when the report is absent; fail closed on an inconsistent one."""
    path = root / REPORT
    unlinked(root, path)
    if not path.exists():
        return None
    require(path.is_file() and path.stat().st_size <= MAX_BYTES, "Identity score report too large.")
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "Identity score report too large.")
    report = json_document(raw)
    require(report["kind"] == "signalbridge-identity-score", "Unexpected identity score report.")
    datasets = report["datasets"]
    targeted = [item for item in datasets if any(item["expect"][side] for side in SIDES)]
    return {
        "report": REPORT,
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "captures": len(datasets),
        "attack_data_commit": report["sources"]["attack_data"]["commit"][:7],
        "sigmahq_commit": report["sources"]["sigmahq"]["commit"][:7],
        "mine": side_figures(report, "mine", require),
        "sigmahq": side_figures(report, "sigmahq", require),
        "together_targeted": len(targeted),
        "together_flagged": sum(any(flagged(item, side) for side in SIDES) for item in targeted),
    }
