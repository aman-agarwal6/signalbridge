"""Read-only assignments from four reviewed public historical tool receipts.

The questions and coaching are authored teaching material. The observations are
retained lab results, never a new execution or a source of operational coverage.
"""

import hashlib
import json
import stat
from pathlib import Path

from scripts.portfolio_integrations import RECEIPTS, load_integrations

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 256 * 1024
ASSIGNMENTS = {
    "recorded-wazuh-review": {
        "workspace": "bettail",
        "title": "Review the actual Wazuh collection receipt",
        "focus": "Collection completeness versus a confirmed security incident",
        "brief": "Review the retained BetTail lab replay. Explain what the Wazuh manager demonstrably received and whether its alerts alone establish an unauthorized read. Use the recorded evidence, not an assumed live connection.",
        "requirement": "Every record in this bounded exported batch must be accounted for; an alert must not be presented as an independently confirmed access failure.",
    },
    "recorded-zap-review": {
        "workspace": "signalbridge",
        "title": "Review the actual ZAP failure and retry",
        "focus": "Separate scan failure, successful retry and remediation evidence",
        "brief": "Review the retained local ZAP outage exercise and separate retry. Explain their coverage and whether either result establishes that an application vulnerability was fixed.",
        "requirement": "An incomplete scan must remain incomplete. A later run needs its own identity, scope and positive controls before supporting a bounded conclusion.",
    },
}


class RecordedEvidenceError(ValueError):
    pass


def require(condition, _message):
    if not condition:
        raise RecordedEvidenceError("Reviewed historical evidence is unavailable or inconsistent.")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate key")
        result[key] = value
    return result


def read_public(root, name):
    require(name in RECEIPTS, "unknown receipt")
    target = root / "docs" / "evidence" / name
    current = root
    for part in target.relative_to(root).parts:
        current /= part
        info = current.lstat()
        require(
            not stat.S_ISLNK(info.st_mode)
            and not getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024),
            "linked receipt",
        )
    require(target.is_file() and target.stat().st_size <= MAX_BYTES, "receipt size")
    with target.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "receipt size")
    value = json.loads(raw, object_pairs_hook=unique_object)
    return value, hashlib.sha256(raw).hexdigest()


def packet(identity, action, at, text, **reference):
    return {
        "id": identity,
        "action": action,
        "source": "Reviewed historical local tool receipt",
        "at": at,
        "text": text,
        "reference": reference,
    }


def scenario(key, workspace):
    require(key in ASSIGNMENTS and ASSIGNMENTS[key]["workspace"] == workspace, "scope")
    try:
        data = load_integrations(ROOT, read_public, require)
        require(data is not None, "missing receipts")
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        raise RecordedEvidenceError(
            "Reviewed historical evidence is unavailable or inconsistent. The attempt was not created."
        ) from error
    common = {
        "version": "historical-tool-review-v1",
        "key": key,
        "fictional": False,
        "evidence_kind": "historical_local_lab",
        "scope": data["scope"],
        "receipts": data["receipts"],
        **ASSIGNMENTS[key],
    }
    if key == "recorded-wazuh-review":
        run = data["wazuh"]
        counts = run["counts"]
        signal = next(row for row in run["records"] if row["rule_id"] == "100201")
        sources = "; ".join(f"{name}={count}" for name, count in run["source_counts"].items())
        packets = [
            packet(
                "E1",
                "Inspect batch reconciliation",
                run["finished_at"],
                f"Wazuh {run['version']}: exported={counts['inputs']}, received={counts['received']}, custom alerts={counts['alerts']}, missing={counts['missing']}, duplicates={counts['duplicates']}. This reconciles one retained batch, not continuous service health.",
                run_id=run["run_id"],
                input_sha256=run["input_sha256"],
            ),
            packet(
                "E2",
                "Trace one recorded boundary signal",
                signal["occurred_at"],
                f"The received event records operation={signal['operation']}, outcome={signal['outcome']}, reason={signal['reason']}, source={signal['source']}. Wazuh matched custom rule {signal['rule_id']} at level {signal['level']}. Actor identity, returned private content and membership timing are not included in this sanitized record.",
                run_id=run["run_id"],
                event_id=signal["event_id"],
                rule_id=signal["rule_id"],
            ),
            packet(
                "E3",
                "Inspect source classes and non-alert limits",
                run["finished_at"],
                f"Recorded source composition: {sources}. {counts['received'] - counts['alerts']} received records had no custom alert. The input is local lab metadata; legacy unknown remains unclassified. No alert is not a benign verdict, and manager receipt does not independently prove source truth or an unauthorized read.",
                run_id=run["run_id"],
            ),
        ]
        explanation = "The receipt supports complete collection of this fixed batch and the recorded rule results. Establishing an unauthorized read still needs the original scoped access evidence, effective membership timing, returned-content checks and legitimate-user controls. The 31 alerts are not 31 confirmed vulnerabilities, and the 33 non-alerts are not automatically benign."
    else:
        runs = data["zap"]["runs"]
        failed = next(run for run in runs if run["failed"])
        retry = next(run for run in runs if not run["failed"])
        counts = retry["counts"]
        packets = [
            packet(
                "E1",
                "Inspect the unsuccessful scan",
                failed["finished_at"],
                f"Scan failed; coverage={failed['coverage']}; accepted requests={failed['accepted']}; scanner exit={failed['scanner_exit_code']}. The deliberately unavailable local target exercise was verified, but the scan itself remains incomplete.",
                run_id=failed["run_id"],
                imported_receipt_sha256=failed["imported_receipt_sha256"],
            ),
            packet(
                "E2",
                "Inspect the separate successful retry",
                retry["finished_at"],
                f"The separate retry accepted {retry['accepted']} fixed GET requests, reported {counts['reported_findings']} normalized findings, and checked {counts['header_positive_paths']} positive header paths plus {counts['header_negative_paths']} negative-control path. Scope is the isolated synthetic fixture, not BetTail, Netted or production. A successful scan execution is not an all-clear verdict.",
                run_id=retry["run_id"],
                imported_receipt_sha256=retry["imported_receipt_sha256"],
            ),
            packet(
                "E3",
                "Inspect console import and decision boundaries",
                retry["finished_at"],
                f"The console import retained {data['zap']['import_receipts']} execution receipts and {data['zap']['audit_records']} audit entries. Repeat imports created duplicates={data['zap']['import_duplicates']}. Imports did not close findings or overwrite the failed run. These receipts contain no source correction and comparable before/after remediation test.",
                failed_run_id=failed["run_id"],
                retry_run_id=retry["run_id"],
            ),
        ]
        explanation = "The failed scan remains incomplete; the separate retry establishes only its three-request fixture scope. Preserve both identities. Five reported header findings are not five confirmed application vulnerabilities, and no recorded fix/retest supports remediation. Choose the next check according to the claim being investigated, without widening scan scope without authorization."
    return {
        **common,
        "packets": packets,
        "answer": {"required": ["E1", "E2", "E3"], "explanation": explanation},
    }
