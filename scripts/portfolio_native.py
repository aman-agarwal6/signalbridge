"""Fixed reviewed October native-run receipts for the offline employer presentation.

Every figure shown is read from a pinned receipt and checked before rendering; the
prose around it is reviewed text. Content pins use canonical JSON so Git line-ending
conversions do not invalidate the review. They establish reviewed bytes, not
independent attestation or current health.
"""

from datetime import date

from scripts.portfolio_integrations import canonical_sha

COLLECTION = "20261003-wazuh-native-collection-0d137b4720ad476faa68d36754b7357f.json"
RECOVERY = "20261003-wazuh-native-recovery-4a5748dcc7a74525a7469dc8d802438a.json"
ZAP = "20261003-authenticated-zap-offline-d975b97fad814c9b8e4304e114c776e5.json"
RESTORATION = "20261003-console-restoration-de4f6409fdf444a9bc22cf60463cdb05.json"
MONITORING = "20261003-monitoring-native-0cd4256f4a1c4f2692f67eae4704bd53.json"
IDENTITY = "20261004-identity-native-73632025aeee400bb7ee49b69fba7c99.json"
REHEARSAL = "20261004-reliability-rehearsal-8a1889fec8ef49f5acde3c01bfa88e63-remeasured.json"
CONTINUOUS = "20261004-reliability-continuous-894fb388a2004b43b6b1643e93342df4-summary.json"
SHUFFLE = "20261005-shuffle-native-workflow-315cfb85-9c28-4e4e-9cac-8ce455e92448.json"
LEAVER_DRY_RUN = "20261005-accessops-leaver-dry-run-f567427abbbc4929ad50e25be2c84724.json"
LEAVER_ROUND_1 = "20261005-accessops-leaver-poll-eefe76ecded04ffe9892bd174c973232.json"
LEAVER_ROUND_2 = "20261005-accessops-leaver-poll-931402fb1ee44209b58c60063f63150f.json"

RECEIPTS = {
    COLLECTION: "ed0d3e1b84bef62676f19066ff58fa3a26f03ef756a33635733d1dff10735441",
    RECOVERY: "8dfb4b446691e38481a734e1edc768e0e68138c8035dac0bdae2265ec50c4642",
    ZAP: "6dbe99149ec2e9f54ca74445a73ae509723255bda127c1dea35c53e1092007b7",
    RESTORATION: "c0baa9569de5e11875969206f931028aa18b7ffd8ccac299d95de746bbbdcf1d",
    MONITORING: "173154f1ada326d6735a0688df8895525f14c3cd9613749523935f920e77c22a",
    IDENTITY: "79b6829c9f34c8098b7aa7cdd7171bf34db45bfdd9c3f5dd37f30930e2039a12",
    REHEARSAL: "c65d6f75aa3acc331c4c2075f1c6b35d9f7141a7b2a09b96820db1d9682d4c7d",
    CONTINUOUS: "4505c1bd318a0c0f45157da99c5d55c2fb098a0f27475e957cf3a998bb37c0c8",
    SHUFFLE: "feffebd04e6be35b7154a7cb3134d85a3953777f427b4961edafe1561028efd2",
    LEAVER_DRY_RUN: "63f36b913e5e0e6897f6fefed3c9c1e6acdfc230cbe1028ee0199c2bd9d509b4",
    LEAVER_ROUND_1: "faf8fafc94f5d11bfc20e42c8f4343df8e2e19ed07061d5ece0db0a877113f65",
    LEAVER_ROUND_2: "239459cfa560aaac5443af14dae22a9b0f4107090dfe2ed8d754db902f6f4a06",
}

# Expected receiver answer per Shuffle scenario: (HTTP status, error code, duplicate flag).
SHUFFLE_SCENARIOS = {
    "first": (201, None, False),
    "retry_new_nonce": (200, None, True),
    "replayed_request": (409, "request_replayed", None),
    "changed_content": (409, "idempotency_conflict", None),
    "wrong_scope": (404, "case_unavailable", None),
    "stale_evidence": (409, "case_evidence_changed", None),
    "receiver_timeout": (None, None, None),
    "lost_reply": (None, None, None),
    "retry_after_lost_reply": (200, None, True),
}
IDENTITY_CONTROLS = {
    "callback_replay_rejected",
    "csrf_missing_write_denied",
    "analyst_cross_app_write_denied",
    "provider_signing_key_rotation_admitted",
    "native_backchannel_logout_revoked_session",
    "real_session_expiry_denied",
}
BROWSER_CONTROLS = {
    "browser_keyboard_mfa_login",
    "browser_cookie_attributes_enforced",
    "browser_csp_blocks_inline_script",
    "browser_framing_blocked",
    "browser_logout_ends_session",
}
MONITORING_CONTROLS = {
    "queue_delay_alert_fired",
    "worker_missing_alert_fired",
    "worker_and_queue_alerts_cleared",
    "exporter_missing_bearer_denied",
    "grafana_anonymous_query_denied",
    "prometheus_missing_client_certificate_denied",
    "all_dashboard_queries_match",
}


def day(name):
    value = date(int(name[:4]), int(name[4:6]), int(name[6:8]))
    return f"{value:%B} {value.day}"


def link(name, label):
    return {"path": "docs/evidence/" + name, "label": label}


def card(key, short, tool, title, receipts, figure, figure_label, facts, limit, status="passed"):
    return {
        "key": key,
        "short": short,
        "tool": tool,
        "title": title,
        "date": day(receipts[0]["path"].rsplit("/", 1)[1]),
        "status": status,
        "figure": figure,
        "figure_label": figure_label,
        "facts": facts,
        "limit": limit,
        "receipts": receipts,
    }


def shutdowns(value, require):
    require(
        value["main_shutdown_verified"] is True and value["independent_shutdown_verified"] is True,
        "Native run shutdown was not verified.",
    )


def wazuh(value, require):
    receipt = value["receipt"]
    shutdowns(receipt, require)
    coverage = receipt["native_proof"]["coverage"]
    require(
        receipt["status"] == "passed"
        and receipt["acceptance_passed"] is True
        and coverage["archived_logical_inputs"] == coverage["expected_logical_inputs"] > 0
        and coverage["alerted_logical_inputs"] == coverage["expected_alert_inputs"] > 0
        and coverage["missing_archive_inputs"] == coverage["missing_alert_inputs"] == 0
        and coverage["extra_archive_copies"] == coverage["extra_alert_copies"] == 0,
        "Wazuh receipt does not reconcile.",
    )
    return receipt, coverage


def identity_card(value, require):
    native = value["native_receipt"]
    protocol = native["execution"]["controls"]
    browser = native["browser_result"]["controls"]
    names = {item["control"] for item in protocol}
    require(
        value["entire_identity_gate_passed"] is True
        and native["passed"] is True
        and native["browser_result"]["passed"] is True
        and all(item["passed"] is True for item in protocol + browser)
        and IDENTITY_CONTROLS <= names
        and {item["control"] for item in browser} == BROWSER_CONTROLS
        and value["main_shutdown"]["shutdown_verified"] is True
        and value["independent_shutdown"]["shutdown_verified"] is True,
        "Identity receipt does not support the presented controls.",
    )
    return card(
        "identity",
        "Login and MFA",
        "Keycloak · Chromium",
        "Password and TOTP sign-in, attacked and walked through",
        [link(IDENTITY, "Identity run")],
        f"{len(protocol)} / {len(protocol)}",
        "protocol controls passed",
        [
            "Covered callback replay, a missing CSRF token, cross-app writes, signing-key "
            "rotation, back-channel logout and real session expiry",
            f"{len(browser)} / {len(browser)} real-browser controls: keyboard sign-in, cookie "
            "attributes, CSP, framing and sign-out",
        ],
        "A real Keycloak server and browser in an isolated lab, with synthetic accounts.",
    )


def collection_card(value, require):
    receipt, coverage = wazuh(value, require)
    source = receipt["source_binding"]
    require(
        source["source_inputs_match_revalidated_reference_run"] is True
        and source["logical_observations"] + source["forwarded_core_signals"]
        == coverage["expected_logical_inputs"],
        "Wazuh input is not bound to the reference run.",
    )
    return card(
        "wazuh-collection",
        "Wazuh collection",
        "Wazuh",
        "Every record archived, every alert raised once",
        [link(COLLECTION, "Collection run")],
        f"{coverage['archived_logical_inputs']} / {coverage['expected_logical_inputs']}",
        "records archived",
        [
            f"{coverage['alerted_logical_inputs']} / {coverage['expected_alert_inputs']} "
            "expected alerts, each raised once",
            "0 missing records and 0 extra copies",
            f"Input: the October 2 access run's {source['logical_observations']} observations "
            f"and {source['forwarded_core_signals']} forwarded detection",
        ],
        "One forwarded SignalBridge detection; not independent Wazuh rediscovery.",
    )


def recovery_card(value, require):
    receipt, coverage = wazuh(value, require)
    publication = receipt["publication"]
    require(
        receipt["profile"] == "recovery_rotation"
        and publication["backlog_records"] > 0
        and publication["published_records"] == coverage["expected_logical_inputs"]
        and publication["rotated_name"].startswith(publication["rotation_relative"] + ".rotated-"),
        "Wazuh recovery receipt does not show the recovery profile.",
    )
    return card(
        "wazuh-recovery",
        "Wazuh recovery",
        "Wazuh",
        "Collector stopped mid-run, log rotated, nothing lost",
        [link(RECOVERY, "Recovery run")],
        f"{coverage['archived_logical_inputs']} / {coverage['expected_logical_inputs']}",
        "records archived after recovery",
        [
            f"{publication['backlog_records']} records waited while the collector was stopped",
            "The source log rotated during the run",
            f"0 extra copies; {coverage['alerted_logical_inputs']} / "
            f"{coverage['expected_alert_inputs']} alerts",
        ],
        "A planned stop and rotation in the lab, not an unplanned outage.",
    )


def zap_card(value, require):
    shutdowns(value, require)
    phases = value["scanner_proof"]["phases"]
    fault, corrected = phases["fault"]["findings"], phases["corrected"]["findings"]
    require(
        value["acceptance_passed"] is True
        and value["native_zap_executed"] is True
        and len(fault) == 1
        and corrected == [],
        "ZAP receipt does not show one finding fixed.",
    )
    return card(
        "zap",
        "ZAP",
        "OWASP ZAP",
        "A finding on the faulty build, gone after the fix",
        [link(ZAP, "Scan run")],
        f"{len(fault)} → {len(corrected)}",
        "findings before and after the fix",
        [
            f"{fault[0]['risk']}-risk finding from ZAP rule {fault[0]['plugin_id']} on the faulty build",
            "The corrected build, scanned the same way, had none",
        ],
        "Authenticated passive scan of the lab reference app; not a full assessment.",
    )


def restoration_card(value, require):
    shutdowns(value, require)
    runner = value["runner"]
    workflow = runner["workflow"]
    restored = runner["restored"]
    imported = workflow["wazuh_import"]
    require(
        value["acceptance_passed"] is True
        and value["status"] == "passed"
        and value["restored_into_separate_database"] is True
        and runner["passed"] is True
        and restored
        == {**value["backup"]["source_rows"], "archive_sha256": restored["archive_sha256"]}
        and workflow["self_review_denied"] is True
        and workflow["independent_review"] == "approved"
        and workflow["task_status"] == "verified"
        and imported["unmatched_events"] == 0
        and imported["repeat_created"] is False,
        "Restoration receipt does not support the operator workflow.",
    )
    return card(
        "restoration",
        "Investigation to fix",
        "SignalBridge console · PostgreSQL",
        "From finding to verified fix, on a restored console",
        [link(RESTORATION, "Restoration run")],
        f"{restored['events']} / {value['backup']['source_rows']['events']}",
        "events restored into a separate database",
        [
            "Assigned, remediation task, retest imported, independent reviewer approved",
            "Self-review refused; a repeated retest import created no duplicate",
            f"The Wazuh run matched {imported['matched_events']} events to the case",
        ],
        "Synthetic lab data; one case through the full workflow.",
    )


def monitoring_card(value, require):
    receipt = value["receipt"]
    controls = receipt["proof"]["controls"]
    require(
        receipt["status"] == "passed"
        and receipt["shutdown_verified"] is True
        and all(item is True for item in controls.values())
        and MONITORING_CONTROLS <= set(controls),
        "Monitoring receipt does not support the presented controls.",
    )
    return card(
        "monitoring",
        "Monitoring",
        "Prometheus · Grafana",
        "Alerts that fire on a backlog and then clear",
        [link(MONITORING, "Monitoring run")],
        f"{len(controls)} / {len(controls)}",
        "monitoring controls passed",
        [
            "Queue-delay and missing-worker alerts fired, then cleared after recovery",
            "Requests without credentials were denied by the exporter, Prometheus and Grafana",
            "Every dashboard query matched the database",
        ],
        "Lab thresholds and synthetic load, not production capacity.",
    )


def endurance_card(rehearsal, continuous, require):
    measurement = rehearsal["measurement"]
    recovery = measurement["recovery"]
    capture = continuous["wazuh_capture"]
    require(
        len(recovery) == 5
        and all(item["late_or_missing"] == 0 for item in recovery)
        and all(count == 0 for count in measurement["anomalies"].values())
        and measurement["missing_processing"] == measurement["missing_acceptance"] == 0
        and continuous["reads_delivered"] == continuous["source_reads"] > 0
        and continuous["service_errors"] == 0
        and capture["stopped_after_hours"] < continuous["elapsed_hours"] < 24,
        "Endurance receipts do not support the presented result.",
    )
    minutes = round(measurement["declared_elapsed_ms"] / 60000)
    return card(
        "endurance",
        f"Endurance, {continuous['elapsed_hours']:.1f} of 24 hours",
        "Reliability lab · Wazuh",
        f"{continuous['elapsed_hours']:.1f} hours of continuous reads, with planned interruptions",
        [link(REHEARSAL, "Rehearsal"), link(CONTINUOUS, "Continuous run")],
        f"{continuous['reads_delivered']:,} / {continuous['source_reads']:,}",
        "reads delivered",
        [
            f"{minutes}-minute rehearsal: all {len(recovery)} interruptions recovered with "
            "0 events late or missing",
            f"Wazuh captured the first {capture['stopped_after_hours']:.1f} hours, then hit a "
            "log-folder limit, since fixed",
        ],
        "Not a 24-hour result; the run was stopped after the Wazuh capture ended.",
        status="partial",
    )


def shuffle_card(value, require):
    scenarios = value["dispatcher"]["scenarios"]
    receiver = value["guest"]["receiver"]
    require(set(scenarios) == set(SHUFFLE_SCENARIOS), "Shuffle scenarios differ from the review.")
    for name, (status, error, duplicate) in SHUFFLE_SCENARIOS.items():
        result = scenarios[name]
        require(
            result["execution_status"] == "FINISHED"
            and result["http_status"] == status
            and result["error"] == error
            and result["duplicate"] == duplicate,
            "A Shuffle scenario did not end as reviewed.",
        )
    first = scenarios["first"]["task_id"]
    require(
        value["shutdown_verified"] is True
        and value["end_record_received"] is True
        and value["guest"]["status"] == "completed"
        and scenarios["retry_new_nonce"]["task_id"] == first
        and scenarios["retry_after_lost_reply"]["task_id"] not in (None, first)
        and receiver["review_tasks"] == 2,
        "Shuffle receipt does not reconcile.",
    )
    return card(
        "shuffle",
        "Shuffle",
        "Shuffle SOAR",
        "A real workflow through nine failure cases",
        [link(SHUFFLE, "Workflow run")],
        f"{len(scenarios)} / {len(SHUFFLE_SCENARIOS)}",
        "scenarios answered as designed",
        [
            f"{receiver['review_tasks']} review tasks created; each retry returned its original task",
            "Replayed, changed, wrong-app and stale requests were refused",
            "A lost reply was recovered by retrying",
        ],
        "Nine synthetic scenarios in a dedicated offline VM.",
    )


def leaver_card(dry_run, rounds, require):
    require(
        dry_run["dry_run"] is True
        and dry_run["offered"] > 0
        and dry_run["stored"] == dry_run["acknowledged"] == dry_run["reported_as_errors"] == 0,
        "Leaver dry run stored or acknowledged tokens.",
    )
    for poll in rounds:
        require(
            poll["dry_run"] is False
            and poll["failure"] is None
            and poll["offered"] == poll["stored"] == poll["acknowledged"] > 0
            and poll["duplicates"] == poll["reported_as_errors"] == 0
            and poll["queue_drained"] is True,
            "Leaver poll does not reconcile.",
        )
    stored = sum(poll["stored"] for poll in rounds)
    first, second = (poll["case_actions"].get("case.created", 0) for poll in rounds)
    return card(
        "leaver",
        "Leaver signals",
        "AccessOps · Shared Signals",
        "Leaver events from another system, verified before use",
        [
            link(LEAVER_DRY_RUN, "Dry run"),
            link(LEAVER_ROUND_1, "Round 1"),
            link(LEAVER_ROUND_2, "Round 2"),
        ],
        f"{stored} / {sum(poll['offered'] for poll in rounds)}",
        "signed tokens verified, stored once and acknowledged",
        [
            f"Dry run first: {dry_run['offered']} tokens checked, nothing stored or acknowledged",
            f"Round 2 opened {second} access-after-departure case from real lab activity",
            f"Round 1's {first} cases came from the sender's test backdating departures",
        ],
        "Two lab systems on one PC, with synthetic accounts.",
    )


def load_native(root, read_public, require):
    """Omit an absent snapshot; fail closed on partial, changed or contradictory evidence."""
    available = [(root / "docs/evidence" / name).exists() for name in RECEIPTS]
    if not any(available):
        return None
    require(all(available), "October presentation needs every reviewed receipt.")
    values, identities = {}, []
    for name, expected in RECEIPTS.items():
        value, raw_sha = read_public(root, name)
        require(
            canonical_sha(value) == expected, "Native receipt differs from the reviewed snapshot."
        )
        values[name] = value
        identities.append(
            {"receipt": name, "receipt_sha256": raw_sha, "reviewed_content_sha256": expected}
        )
    cards = [
        shuffle_card(values[SHUFFLE], require),
        leaver_card(
            values[LEAVER_DRY_RUN], (values[LEAVER_ROUND_1], values[LEAVER_ROUND_2]), require
        ),
        identity_card(values[IDENTITY], require),
        endurance_card(values[REHEARSAL], values[CONTINUOUS], require),
        collection_card(values[COLLECTION], require),
        recovery_card(values[RECOVERY], require),
        zap_card(values[ZAP], require),
        restoration_card(values[RESTORATION], require),
        monitoring_card(values[MONITORING], require),
    ]
    return {
        "scope": "Real tools in an isolated lab with synthetic accounts and data.",
        "first_day": day(min(RECEIPTS)),
        "last_day": day(max(RECEIPTS)),
        "passed": sum(item["status"] == "passed" for item in cards),
        "partial": [item for item in cards if item["status"] == "partial"],
        "runs": cards,
        "receipts": identities,
    }
