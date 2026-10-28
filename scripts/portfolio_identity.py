"""Headline identity-detection figures for the offline evidence viewer.

Every figure is recomputed from detections/identity/score-report.json when the page is
built, and the report is checked to reconcile with its own summary. The report is the
output of detections.identity.score, which CI re-runs on the pinned public captures.

False-alarm figures come from detections/identity/baseline-report.json, the output of
detections.identity.baseline on a week of unlabeled LANL host logs. Each rule's alerts must
add up across its days before they are shown.
"""

import hashlib

REPORT = "detections/identity/score-report.json"
BASELINE = "detections/identity/baseline-report.json"
MAX_BYTES = 2 * 1024 * 1024
SIDES = ("mine", "sigmahq")
# Group-by field -> what the viewer calls one group, most specific first.
GROUP_KINDS = (
    ("Workstation", "workstation"),
    ("IpAddress", "source"),
    ("TargetUserName", "account"),
)


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


def read_report(root, name, unlinked, json_document, require):
    """(report, SHA-256 of its bytes), or (None, None) when the file is absent."""
    path = root / name
    unlinked(root, path)
    if not path.exists():
        return None, None
    require(path.is_file() and path.stat().st_size <= MAX_BYTES, "Identity report too large.")
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "Identity report too large.")
    return json_document(raw), hashlib.sha256(raw).hexdigest()


def group_kind(rule):
    fields = {field for item in rule["top_groups"] for field in item["group"]}
    return next((kind for field, kind in GROUP_KINDS if field in fields), "account")


def per_day_text(value):
    return f"{value:,.1f}".removesuffix(".0")


def baseline_figures(report, digest, require):
    """Alerts per day for my rules on the benign week; unlabeled, so every alert counts."""
    require(
        report["kind"] == "signalbridge-identity-baseline", "Unexpected identity baseline report."
    )
    days = report["days"]
    rules = []
    for key, rule in sorted(report["rules"]["mine"].items()):
        per_day = rule["per_day"]
        require(
            days
            and set(per_day) == set(days)
            and rule["alerts"] == sum(day["alerts"] for day in per_day.values())
            and rule["alerts_per_day"] == round(rule["alerts"] / len(days), 1)
            and set(rule["event_ids_absent"]) <= set(rule["event_ids"]),
            "Identity baseline does not reconcile with its days.",
        )
        rules.append(
            {
                "rule": key,
                "measured": set(rule["event_ids"]) != set(rule["event_ids_absent"]),
                "absent": rule["event_ids_absent"],
                "alerts": rule["alerts"],
                "per_day": per_day_text(rule["alerts_per_day"]),
                "groups": rule["groups"],
                "group_kind": group_kind(rule),
            }
        )
    return {
        "report": BASELINE,
        "report_sha256": digest,
        "days": len(days),
        "events_million": round(sum(day["events"] for day in days.values()) / 1_000_000),
        "rules": rules,
    }


def load_identity(root, unlinked, json_document, require):
    """Omit the card when the score report is absent; fail closed on an inconsistent report."""
    report, digest = read_report(root, REPORT, unlinked, json_document, require)
    if report is None:
        return None
    require(report["kind"] == "signalbridge-identity-score", "Unexpected identity score report.")
    baseline, baseline_digest = read_report(root, BASELINE, unlinked, json_document, require)
    datasets = report["datasets"]
    targeted = [item for item in datasets if any(item["expect"][side] for side in SIDES)]
    return {
        "report": REPORT,
        "report_sha256": digest,
        "captures": len(datasets),
        "attack_data_commit": report["sources"]["attack_data"]["commit"][:7],
        "sigmahq_commit": report["sources"]["sigmahq"]["commit"][:7],
        "mine": side_figures(report, "mine", require),
        "sigmahq": side_figures(report, "sigmahq", require),
        "together_targeted": len(targeted),
        "together_flagged": sum(any(flagged(item, side) for side in SIDES) for item in targeted),
        "baseline": None
        if baseline is None
        else baseline_figures(baseline, baseline_digest, require),
    }
