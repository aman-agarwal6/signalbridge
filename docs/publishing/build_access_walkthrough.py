"""Publish an allowlisted extract of one recorded native run; never start a lab."""

import hashlib
import json
import os
import re
import secrets
import sys
from pathlib import Path

from django.template import Context, Engine

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.portfolio import load_stylesheet  # noqa: E402

RUN = "b8667b816ce8419da7f3d5d9ac9d6ad6"
RECEIPT = f"20261002-reference-access-{RUN}.json"


def read(path):
    for parent in (path, *path.parents):
        if parent == ROOT:
            break
        if parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction()):
            raise ValueError("Evidence paths must not be links.")
    raw = path.read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("Evidence exceeds this publication profile.")
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def failed_collector(milestone):
    """Expose the recorded incomplete attempt without promoting it to proof."""
    selected = milestone.get("wazuh_native_attempts", {})
    run_id = selected.get("latest_run_id", "")
    if not run_id:
        return None
    if not re.fullmatch(r"[a-f0-9]{32}", run_id):
        raise ValueError("Unsupported collector execution identifier.")
    filename = f"20261003-wazuh-reference-bootstrap-{run_id}.json"
    attempt, checksum = read(ROOT / "docs/evidence" / filename)
    diagnosis, diagnosis_hash = read(
        ROOT / "docs/evidence/20261003-wazuh-final-attempt-diagnosis.json"
    )
    if not (
        attempt["run_id"] == diagnosis["run_id"] == run_id
        and attempt["source_binding"]["native_source_run_id"] == RUN
        and attempt["status"] == "incomplete"
        and attempt["bootstrap_acceptance_passed"] is False
        and diagnosis["native_collection_accepted"] is False
        and diagnosis["native_processes_observed"] is True
        and diagnosis["last_heartbeat"]["coverage"]["archived_logical_inputs"] == 0
        and diagnosis["last_heartbeat"]["coverage"]["expected_logical_inputs"] == 24
        and diagnosis["old_launcher"] == "retired_no_cli_retry"
    ):
        raise ValueError("Incomplete collector report does not match its retained diagnosis.")
    return {
        "run_id": run_id,
        "finished_at": attempt["finished_at"],
        "receipt": filename,
        "receipt_sha256": checksum,
        "diagnosis_receipt": "20261003-wazuh-final-attempt-diagnosis.json",
        "diagnosis_sha256": diagnosis_hash,
        "archived_inputs": 0,
        "expected_inputs": 24,
        "acceptance_passed": False,
        "main_stop_reported": attempt["main_shutdown"]["shutdown_verified"] is True,
        "independent_stop_reported": attempt["independent_shutdown"]["shutdown_verified"] is True,
        "independent_shutdown_reason": attempt["independent_shutdown"]["reason"],
        "launcher_retired": True,
        "claim_boundary": "Retained failed execution and diagnosis; no collection success, continuous operation or independent attestation.",
    }


def build():
    receipt, receipt_hash = read(ROOT / "docs/evidence" / RECEIPT)
    if not all(
        receipt[k] is True
        for k in (
            "acceptance_passed",
            "source_unchanged",
            "runtime_isolation_verified",
            "main_shutdown_verified",
            "independent_shutdown_verified",
        )
    ):
        raise ValueError("This walkthrough requires the completed recorded native run.")
    evidence = ROOT / "var/enterprise/runs" / RUN / "evidence"
    loaded = {}
    for name in ("reference-execution", "console-events", "reference-reconciliation"):
        document, checksum = read(evidence / (name + ".json"))
        if receipt["native_proof"]["raw_receipt_sha256"][name] != checksum:
            raise ValueError("Retained input changed; do not publish.")
        loaded[name] = document
    # Closed selection: do not copy arbitrary private fields or raw process logs.
    events = []
    for row in loaded["console-events"]["events"]:
        payload = row["payload"]
        selected = {
            key: row[key]
            for key in ("event_id", "app", "digest", "source", "processed_at", "state")
        }
        selected.update(
            {
                key: payload[key]
                for key in ("operation", "actor", "resource", "outcome", "reason", "occurred_at")
            }
        )
        selected["membership"] = payload.get("membership")
        events.append(selected)
    steps = [
        {
            k: row[k]
            for k in (
                "step",
                "event_id",
                "http_status",
                "known_content",
                "observation",
                "effective_access",
                "session_unchanged",
                "identity_matched",
                "passed",
            )
            if k in row
        }
        for row in loaded["reference-execution"]["steps"]
    ]
    report = {
        "kind": "signalbridge-recorded-access-walkthrough",
        "schema_version": 1,
        "run_id": RUN,
        "finished_at": receipt["finished_at"],
        "source_sha256": receipt["source_sha256"],
        "receipt": RECEIPT,
        "receipt_sha256": receipt_hash,
        "events": events,
        "controls": steps,
        "cases": loaded["console-events"]["cases"],
        "limits": [
            "Recorded synthetic reference lab; not production or live monitoring.",
            "One deliberately introduced regression is not a detection-accuracy benchmark.",
            "The case remained open; reset checks are not independent analyst approval of remediation.",
            "Wazuh inputs were staged in this run; the enterprise manager did not execute.",
            "The recorded source hash identifies the executed revision, not subsequent UI changes.",
            "Local administrators can replace receipts; hashes are not independent attestation.",
        ],
    }
    milestone, _ = read(ROOT / "docs/enterprise-milestone.json")
    selected = milestone.get("native_wazuh_bootstrap", {}).get("run_id")
    if selected:
        # Reuse the console's raw-evidence validator. A passing-looking JSON
        # receipt alone must not become a public execution claim.
        sys.path.insert(0, str(ROOT))
        os.environ.update(
            DJANGO_SETTINGS_MODULE="config.verification_settings",
            SB_SECRET_KEY=secrets.token_urlsafe(48),
        )
        import django

        django.setup()
        from bridge.wazuh_native_review import load_native_review

        scopes = load_native_review(ROOT, selected)
        if any(scope["source_run_id"] != RUN for scope in scopes.values()):
            raise ValueError("The collector receipt belongs to another source run.")
        report["wazuh"] = {
            "run_id": selected,
            "executed_at": scopes["documents"]["executed_at"],
            "scopes": list(scopes.values()),
            "receipt": milestone["native_wazuh_bootstrap"]["receipt"].removeprefix(
                "docs/evidence/"
            ),
            "counts": {
                key: sum(scope["counts"][key] for scope in scopes.values())
                for key in scopes["documents"]["counts"]
            },
        }
        report["limits"][3] = (
            "A separate native Wazuh run consumed this source snapshot. It establishes recorded "
            "collection and exact reconciliation, not continuous operation or independent R3 rediscovery."
        )
    else:
        report["wazuh_attempt"] = failed_collector(milestone)
        if report["wazuh_attempt"]:
            report["limits"][3] = (
                "Wazuh inputs were staged in the source run. A later native collector attempt "
                "collected zero of 24 inputs and its launcher was retired. No successful "
                "enterprise collection is claimed."
            )
    by_step = {s["step"]: s for s in steps}
    by_id = {e["event_id"]: e for e in events}
    sequence = [
        (
            "documents_allowed",
            "01",
            "Establish legitimate access",
            "A member reads the known private document. This positive control establishes that the app and record work.",
            "good",
        ),
        (
            "documents_permission_removed",
            "02",
            "Remove effective permission",
            "The application commits the permission change and its telemetry together. The account’s existing session is still valid.",
            "neutral",
        ),
        (
            "documents_removed_member_denied",
            "03",
            "Observe the intended boundary",
            "The same session receives HTTP 403. The owner still receives the known document: the service is available.",
            "good",
        ),
        (
            "bounded_regression_known_content",
            "04",
            "Detect the deliberately introduced flaw",
            "The bounded lab defect allows the removed member to retrieve the known private document. R3 joins this read to the removal event and opens one investigation.",
            "bad",
        ),
        (
            "regression_reset_denied",
            "05",
            "Reset and verify the controls",
            "After the defect is reset, the member receives HTTP 403 and the owner still reads the document. Re-granting permission then restores legitimate access.",
            "good",
        ),
    ]
    cards = []
    for name, number, title, meaning, tone in sequence:
        step = by_step[name]
        event = by_id[step["event_id"]]
        cards.append(
            {
                "number": number,
                "title": title,
                "meaning": meaning,
                "tone": tone,
                "step": step,
                "event": event,
                "json": json.dumps(event, indent=2),
            }
        )
    context = {
        "portfolio_css": load_stylesheet(ROOT, "access-walkthrough.css"),
        "report": report,
        "cards": cards,
        "receipt": receipt,
        "case": report["cases"][0],
        "receipt_name": RECEIPT,
        "events": sorted(events, key=lambda e: e["occurred_at"]),
    }
    template = Engine().from_string(
        (ROOT / "docs/publishing/access_walkthrough.html").read_text(encoding="utf8")
    )
    output = ROOT / "portfolio"
    (output / "access-assurance.json").write_bytes((json.dumps(report, indent=2) + "\n").encode())
    (output / "access-assurance.html").write_bytes(
        template.render(Context(context, use_l10n=False, use_tz=False)).encode()
    )
    print(
        json.dumps(
            {
                "events": len(events),
                "cases": len(report["cases"]),
                "page": "portfolio/access-assurance.html",
            }
        )
    )


if __name__ == "__main__":
    build()
