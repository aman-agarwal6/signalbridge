"""Read-only explanations tied to reviewed executions and inspectable source.

The four-receipt integration loader remains usable without these optional files.
This module never executes project code, Wazuh rules, requests or database queries.
"""

import ast
import hashlib
import re
import stat
import xml.etree.ElementTree as ET

from scripts.portfolio_integrations import canonical_sha

ROUTE_RECEIPT = "20260924-bettail-next-routes.json"
ROUTE_REVIEW = "40a56e409965c8855ba3dd0352250c2a4a04ff807cf38674ed1fbadb159287ae"
RULE_PATH = "integrations/wazuh/signalbridge_rules.xml"
RULE_EXECUTED_SHA = "9d31bff5f315b92108c8e6e1b56880e5511d30055d56496a33dfc1f3217f241b"
MAX_SOURCE_BYTES = 512 * 1024

CONTROLS = (
    {
        "title": "Interrupted delivery",
        "problem": "A write stops after only part of an event batch reaches the file.",
        "control": "Verify the retained prefix and append only the missing suffix; acknowledge only after the write is flushed.",
        "adverse_test": "Seed a half-written batch, retry twice, and verify one exact complete copy plus an unchanged second retry.",
        "source": "bridge/soc_delivery.py",
        "symbol": "_append",
        "test_source": "tests/test_soc_delivery.py",
        "test": "test_partial_write_recovers_exactly_once",
        "limit": "Local file recovery; this does not prove Wazuh receipt or exactly-once delivery across replay runs.",
    },
    {
        "title": "Lost acknowledgement",
        "problem": "File bytes are complete, but the database still says the batch is pending.",
        "control": "Recognize the exact existing bytes, flush them again and advance the database checkpoint without appending a duplicate.",
        "adverse_test": "Place the complete batch before its checkpoint and verify the retry performs a flush without changing file bytes.",
        "source": "bridge/soc_delivery.py",
        "symbol": "publish",
        "test_source": "tests/test_soc_delivery.py",
        "test": "test_full_file_before_database_commit_recovers_without_reappend",
        "limit": "An injected acknowledgement gap, not a physical power-loss or PostgreSQL crash experiment.",
    },
    {
        "title": "Damaged evidence",
        "problem": "An imported receipt is changed to claim extra records, a different application or a continuous connection.",
        "control": "Revalidate the latest receipt before presentation and show that it needs review instead of retaining a verified state.",
        "adverse_test": "Alter receipt fields, including with a recalculated digest, and require the console to suppress its verified result.",
        "source": "bridge/wazuh_backfill_presentation.py",
        "symbol": "backfill_card",
        "test_source": "tests/test_wazuh_backfill_evidence.py",
        "test": "test_damaged_latest_receipt_never_falls_back_to_green",
        "limit": "Consistency checking under a trusted local administrator; hashes are not independent attestation.",
    },
    {
        "title": "Failed scan presented as clean",
        "problem": "A target outage is relabelled as a successful scan or given successful finding counts.",
        "control": "Require the outage mode to remain failed with incomplete coverage and reject contradictory reports.",
        "adverse_test": "Change failure status, finding counts or scanner exit code separately; each contradictory bundle must be rejected.",
        "source": "bridge/zap_repeat_evidence.py",
        "symbol": "validate_result",
        "test_source": "tests/test_zap_repeat_evidence.py",
        "test": "test_failed_scan_cannot_claim_pass_counts_or_successful_report",
        "limit": "Offline validation tests supplement the separate historical ZAP outage and retry shown above.",
    },
)


def read_source(root, relative, require):
    """Read fixed public sources with the same no-link boundary as receipts."""
    path = root
    for part in relative.split("/"):
        require(part not in ("", ".", ".."), "Invalid presentation source path.")
        path /= part
        require(path.exists(), "Presentation source is missing.")
        info = path.lstat()
        require(
            not stat.S_ISLNK(info.st_mode)
            and not getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024),
            "Presentation sources must not be links.",
        )
    require(path.is_file(), "Presentation source must be a regular file.")
    require(path.stat().st_size <= MAX_SOURCE_BYTES, "Presentation source exceeds its limit.")
    with path.open("rb") as handle:
        raw = handle.read(MAX_SOURCE_BYTES + 1)
    require(len(raw) <= MAX_SOURCE_BYTES, "Presentation source exceeds its limit.")
    return raw, {"path": relative, "sha256": hashlib.sha256(raw).hexdigest()}


def rule_predicates(rule, row):
    """Explain only the pinned XML's simple regex subset, never general PCRE."""
    predicates = []
    for field in rule.findall("field"):
        key = field.attrib["name"].removeprefix("signalbridge.")
        actual = str(row[key])
        pattern = field.text
        predicates.append(
            {
                "field": key,
                "actual": actual,
                "expected": pattern,
                "matches": re.fullmatch(pattern, actual) is not None,
            }
        )
    return predicates


def explain_records(raw, rows, require):
    """Bind the explanation to executed rule bytes before parsing/evaluating."""
    require(
        hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest() == RULE_EXECUTED_SHA,
        "Rule explanation requires the reviewed historical XML; current rules have changed.",
    )
    xml = ET.fromstring(raw)
    rules = {rule.attrib["id"]: rule for rule in xml.findall("rule")}
    base = rules["100200"]
    explained = []
    for row in rows:
        base_checks = rule_predicates(base, row)
        base_matches = all(check["matches"] for check in base_checks)
        matches = []
        for rule_id, rule in rules.items():
            if rule_id != "100200" and base_matches:
                checks = rule_predicates(rule, row)
                if all(check["matches"] for check in checks):
                    matches.append(rule_id)
        require(len(matches) <= 1, "Rule explanation is ambiguous.")
        expected_id = matches[0] if matches else None
        expected_level = int(rules[expected_id].attrib["level"]) if expected_id else None
        require(
            (row["rule_id"], row["level"]) == (expected_id, expected_level),
            "Historical rule predicates disagree with the recorded observation.",
        )
        checks = base_checks + (rule_predicates(rules[expected_id], row) if expected_id else [])
        if not base_matches:
            rejected_fields = ", ".join(
                check["field"] for check in base_checks if not check["matches"]
            )
            reason = f"The parent gate rejects these fields: {rejected_fields}. Child rules are not eligible. Unknown classification is not a benign result."
        elif expected_id:
            reason = "The parent rule and every displayed child condition match. The recorded Wazuh rule and level agree with these predicates."
        else:
            reason = "The record passes the parent gate, but no custom child rule matches its operation, outcome and reason. No alert is not a safety verdict."
        explained.append(
            {
                **row,
                "anchor": "record-" + row["event_id"],
                "base_matches": base_matches,
                "checks": checks,
                "reasoning": reason,
            }
        )
    selectors = (
        ("Observed boundary signal", lambda row: row["rule_id"] == "100201"),
        ("Synthetic comparison", lambda row: row["rule_id"] == "100202"),
        ("Denied request", lambda row: row["rule_id"] == "100203"),
        ("Hidden record", lambda row: row["rule_id"] == "100204"),
        ("Unclassified source", lambda row: row["source"] == "legacy_unclassified"),
        ("Known source, no custom alert", lambda row: row["base_matches"] and not row["rule_id"]),
    )
    examples = []
    for title, select in selectors:
        example = next((row for row in explained if select(row)), None)
        require(example is not None, "A reviewed rule example is missing.")
        examples.append({**example, "example_title": title})
    return {
        "path": RULE_PATH,
        "executed_sha256": RULE_EXECUTED_SHA,
        "examples": examples,
        "reconciled_records": len(explained),
        "scope": "Explanation of the reviewed historical predicates, not a new Wazuh execution. The current XML matches the executed snapshot after newline normalization.",
    }


def load_authorization(root, read_public, require):
    path = root / "docs/evidence" / ROUTE_RECEIPT
    if not path.exists() and not path.is_symlink():
        return None, []
    value, raw_sha = read_public(root, ROUTE_RECEIPT)
    require(canonical_sha(value) == ROUTE_REVIEW, "Authorization story receipt is not reviewed.")
    checks = {row["id"]: row for row in value["route_checks"]}
    require(len(checks) == len(value["route_checks"]), "Duplicate authorization story check.")
    stages = (
        (
            "Before removal",
            "The member can retrieve the known state and image.",
            ("member_next_exact_state_visible", "member_next_exact_image_visible"),
        ),
        (
            "Remove membership",
            "An owner removes membership; the existing session is retained.",
            ("route_member_removed",),
        ),
        (
            "Check the same session",
            "Authentication still succeeds. Identity alone does not grant permission.",
            ("removed_member_same_session_still_auth_valid",),
        ),
        (
            "Recheck access and owner control",
            "The former member's state request is denied. The image is not visible; the owner can still retrieve both.",
            (
                "removed_member_same_cookie_next_state_denied",
                "removed_member_same_cookie_next_image_hidden",
                "owner_next_state_survives_removal",
                "owner_next_image_survives_removal",
            ),
        ),
        (
            "Restore membership",
            "The lab restores membership before its final positive checks.",
            ("route_membership_restored",),
        ),
        (
            "Verify restored access",
            "The member sees the state and the same known image again.",
            ("restored_member_next_state_visible", "restored_member_next_image_visible"),
        ),
    )
    labels = {
        "member_next_exact_state_visible": "Member · state",
        "member_next_exact_image_visible": "Member · image",
        "route_member_removed": "Membership change",
        "removed_member_same_session_still_auth_valid": "Retained session",
        "removed_member_same_cookie_next_state_denied": "Former member · state",
        "removed_member_same_cookie_next_image_hidden": "Former member · image",
        "owner_next_state_survives_removal": "Owner control · state",
        "owner_next_image_survives_removal": "Owner control · image",
        "route_membership_restored": "Membership recovery",
        "restored_member_next_state_visible": "Restored member · state",
        "restored_member_next_image_visible": "Restored member · image",
    }
    timeline = [
        {
            "title": title,
            "explanation": explanation,
            "checks": [{**checks[key], "label": labels[key]} for key in keys],
        }
        for title, explanation, keys in stages
    ]
    return {
        "run_id": value["run_id"],
        "finished_at": value["finished_at"],
        "receipt": ROUTE_RECEIPT,
        "stages": timeline,
        "counts": value["results"]["route"],
        "source": value["source"]["provenance"],
        "source_dirty": value["source"]["source_dirty"],
        "receipt_sha256": raw_sha,
        "limits": "Historical local checks of /api/state and /api/chat-image on a copied development app with synthetic identities. Separate from the Wazuh ledger replay; these are not the same events. A 404 alone does not prove authorization denial.",
    }, [{"receipt": ROUTE_RECEIPT, "receipt_sha256": raw_sha}]


def symbol_reference(raw, path, name, require):
    """Find a real source/test symbol without importing or executing the module."""
    tree = ast.parse(raw.decode("utf-8-sig"), filename=path)
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    require(len(matches) == 1, "An engineering source/test reference is missing or ambiguous.")
    return {"path": path, "symbol": name, "line": matches[0].lineno}


def load_story(root, integrations, read_public, require):
    story = {"rules": None, "authorization": None, "engineering": [], "receipts": [], "sources": []}
    if integrations is None:
        return story
    source_cache = {}

    def source(path):
        if path not in source_cache:
            raw, identity = read_source(root, path, require)
            source_cache[path] = raw
            story["sources"].append(identity)
        return source_cache[path]

    if (root / RULE_PATH).exists() or (root / RULE_PATH).is_symlink():
        story["rules"] = explain_records(
            source(RULE_PATH), integrations["wazuh"]["records"], require
        )
    story["authorization"], story["receipts"] = load_authorization(root, read_public, require)
    paths = {item[key] for item in CONTROLS for key in ("source", "test_source")}
    available = [(root / path).exists() or (root / path).is_symlink() for path in paths]
    if any(available):
        require(all(available), "Engineering presentation needs every source/test reference.")
        for item in CONTROLS:
            story["engineering"].append(
                {
                    **item,
                    "implementation": symbol_reference(
                        source(item["source"]), item["source"], item["symbol"], require
                    ),
                    "regression": symbol_reference(
                        source(item["test_source"]), item["test_source"], item["test"], require
                    ),
                }
            )
    return story
