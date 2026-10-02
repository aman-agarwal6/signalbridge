"""Render the retained evaluation and five explicitly AI-authored teaching reviews."""

import hashlib
import json
import sys
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.evaluate_detection import metrics

RECEIPT = ROOT / "docs/evidence/20260929-membership-evaluation.json"
REVIEWS = {
    "E01": (
        "Investigate a possible permission failure",
        "A separate removal assertion at t=0 identifies the affected account and exact resource. At t=7 the same account has an allowed read labeled member. R3 links both observations; it does not need the read to call itself suspicious.",
        "High review priority is justified by the potential private-data exposure. The fixture's oracle says content was returned; the telemetry itself only says allowed. Check actual returned content, alternate permissions, clock accuracy, missing grants and a legitimate owner control before calling this a confirmed disclosure.",
        "If the source check is defective, enforce current resource membership at the read boundary. Retest the unchanged removed-member session, legitimate owner, denied/error distinction and restoration. That source-app repair was not performed by this evaluation.",
    ),
    "E11": (
        "Explain legitimate access after a re-grant",
        "Removal occurs at t=0, an authorized grant at t=2, and an allowed read at t=7. The latest available membership state permits access. No R3 case is opened.",
        "Classify this controlled case as expected activity after verifying that the grant was authorized. A prior removal alone is insufficient evidence of a current violation. No alert does not mean that every permission check is healthy.",
        "No permission fix is warranted from this sequence. Preserve the timeline and test another removal after the grant; E03 exercises that sequence and should trigger review.",
    ),
    "E18": (
        "Correct an alert when delayed evidence arrives",
        "The collector first sees removal t=0 and read t=7. It opens R3. A grant effective at t=3 arrives last. The existing case is retained, changed to medium priority and reopened for reassessment, with a new evidence version.",
        "Distinguish event time from arrival order. The final label is benign because access was restored before the read. The initial alert still consumed analyst attention and is reported separately from final-state false-positive counts.",
        "Investigate missing or delayed membership telemetry. Keep the original audit entry and the correction; do not erase history. Test delayed removal, delayed grant, duplicates and conflicting timestamps before relying on the workflow.",
    ),
    "E19": (
        "Keep a service outage inconclusive",
        "After a removal, the read produces dependency_unavailable with outcome error. No successful read or explicit denial is established; R3 does not alert.",
        "Record the authorization outcome as inconclusive. Investigate service health and repeat the check. Treating an error as proof of safe denial would turn missing evidence into false assurance.",
        "Restore only the authorized lab dependency, then repeat member, removed-member and owner controls with known private content. This evaluation injects metadata; it does not recover or test a real service.",
    ),
    "E16": (
        "Investigate a false alert instead of hiding it",
        "A legitimate user follows three stale bookmarks within 40 seconds. The three distinct not-visible resources meet R1, producing a medium case even though the declared scenario is benign.",
        "This is one of the two measured false alerts. Confirm resource existence, expected access and why the links are stale before a false-positive decision. Do not broadly suppress managed devices or all not-visible results.",
        "A proposed tuning change needs positive and negative controls, another-person review and a new evaluation round. Keep this receipt unchanged. E17 adds another false alert caused by a missing grant; detection alone cannot reconstruct that absent fact.",
    ),
}


def render(report):
    if report["metrics"] != metrics(report["scenarios"]):
        raise ValueError("Evaluation counts do not reconcile.")
    m = report["metrics"]

    def percent(metric):
        value = metric["value"]
        return "not defined" if value is None else f"{value:.0%}"

    rows, studies = [], []
    for row in report["scenarios"]:
        result = (
            "Inconclusive"
            if row["label"] == "inconclusive"
            else (
                "Detected"
                if row["alerted"] and row["label"] == "suspicious"
                else "False alert"
                if row["alerted"]
                else "Missed"
                if row["label"] == "suspicious"
                else "No alert"
            )
        )
        rows.append(
            f'<tr><th scope="row">{escape(row["id"])}</th><td>{escape(row["title"])}</td>'
            f"<td>{escape(row['label'])}</td><td>{result}</td>"
            f"<td>{escape(', '.join(row['rules']) or 'None')}</td></tr>"
        )
        if row["id"] in REVIEWS:
            title, evidence, judgment, followup = REVIEWS[row["id"]]
            timeline = "".join(
                f"<li><strong>t={d['offset_seconds']}s</strong> · "
                f"{escape(d['operation'])} · {escape(d['outcome'])} "
                f"<small>Accepted HTTP {d['http_status']} · event {escape(d['event_id'])}</small></li>"
                for d in row["deliveries"]
            )
            cases = (
                "; ".join(
                    f"{c['rule']}: {c['priority']}, version {c['version']}, "
                    f"{c['evidence_events']} linked events"
                    for c in row["cases"]
                )
                or "No case created"
            )
            studies.append(
                f'<article id="{escape(row["id"])}"><p class="eyebrow">{escape(row["id"])} · {result}</p>'
                f"<h3>{escape(title)}</h3><p>{escape(evidence)}</p><p><b>Analyst decision.</b> {escape(judgment)}</p>"
                f"<p><b>Remediation & verification.</b> {escape(followup)}</p><details><summary>Inspect actual delivery order and case result</summary>"
                f'<ol class="timeline">{timeline}</ol><p>{escape(cases)}.</p></details></article>'
            )
    cards = "".join(
        f"<div><strong>{value}</strong><span>{label}</span></div>"
        for value, label in (
            (f"{m['tp']}/{m['suspicious_scenarios']}", "Suspicious scenarios detected"),
            (f"{m['fp']}/{m['benign_scenarios']}", "Benign scenarios alerted"),
            (str(m["fn"]), "Suspicious scenarios missed"),
            (str(m["inconclusive_scenarios"]), "Inconclusive, excluded from scoring"),
        )
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'">
<title>SignalBridge · Detection evidence and analyst reviews</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#edf1f6;color:#15283e;font:18px/1.65 system-ui,-apple-system,Segoe UI,sans-serif}}header{{background:#0c2036;color:#f3f8ff;padding:48px max(24px,calc((100vw - 1080px)/2))}}header p{{max-width:850px;color:#c7d9ec}}h1{{font-size:clamp(30px,5vw,48px);line-height:1.15;margin:12px 0}}h2{{font-size:28px;line-height:1.3}}h3{{font-size:23px;line-height:1.35}}a{{color:#065ca5;text-underline-offset:3px}}header a{{color:#83d7ff}}main{{max-width:1128px;padding:28px 24px 64px;margin:auto}}section{{margin:32px 0}}article,.panel{{background:white;border:1px solid #ccd7e3;border-radius:12px;padding:26px;margin:18px 0}}.eyebrow{{text-transform:uppercase;letter-spacing:.1em;font-size:13px;font-weight:750}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}}.metrics div{{background:white;border:1px solid #ccd7e3;padding:20px;border-radius:10px}}.metrics strong{{display:block;font-size:34px;color:#064e69}}.metrics span{{font-size:15px;line-height:1.4;display:block}}.note{{border-left:4px solid #c48b21;padding-left:18px}}details{{border-top:1px solid #dde5ed;padding-top:16px}}summary{{cursor:pointer;font-weight:650;color:#065ca5}}summary:focus-visible,a:focus-visible{{outline:3px solid #cf8b00;outline-offset:5px}}small{{display:block;color:#4d647b;font-size:13px;overflow-wrap:anywhere}}code{{font-size:.85em;overflow-wrap:anywhere}}.table-wrap{{overflow:auto;border:1px solid #ccd7e3;border-radius:10px}}table{{border-collapse:collapse;background:white;width:100%;min-width:630px;font-size:15px}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #e0e7ef}}thead{{background:#dce7f2}}.timeline li{{margin:12px 0}}footer{{font-size:14px;color:#4d647b}}@media(max-width:700px){{.metrics{{grid-template-columns:repeat(2,1fr)}}article,.panel{{padding:20px}}main{{padding:18px 16px}}body{{font-size:17px}}}}@media print{{body{{background:white;font-size:11pt}}header{{background:white;color:black;padding:0}}header p,header a{{color:black}}main{{padding:0}}article{{break-inside:avoid}}.metrics strong{{font-size:22px}}details{{display:block}}}}
</style></head><body><header><p class="eyebrow">SignalBridge · Recorded offline evaluation</p><h1>What did the detector find—and what did it miss?</h1><p>A real execution of signed ingestion, the queue, detection rules and case updates, using synthetic observations in a disposable database. The findings below include false alerts and missed detections.</p><a href="index.html">Recorded Wazuh & ZAP evidence</a> · <a href="../docs/evidence/20260929-membership-evaluation.json">Download this execution receipt</a></header><main>
<section aria-label="Evaluation results"><div class="metrics">{cards}</div><p><b>Precision: {m["precision"]["numerator"]}/{m["precision"]["denominator"]} ({percent(m["precision"])}). Recall: {m["recall"]["numerator"]}/{m["recall"]["denominator"]} ({percent(m["recall"])}).</b> False-positive rate: {m["false_positive_rate"]["numerator"]}/{m["false_positive_rate"]["denominator"]} ({percent(m["false_positive_rate"])}). The unit is a scenario, not an event.</p><p class="note">These are results on 22 selected AI/builder-authored scenarios. They are not production accuracy estimates, independent validation or a comparison with enterprise products. Historical alerts corrected by late evidence remain visible and are reported separately.</p></section>
<section class="panel"><h2>The engineering change</h2><p>R3 joins a separate resource membership removal to a later allowed read. A new closed event schema identifies the affected account; a server-controlled credential permission limits who can send that assertion. Matching stays within one app, environment, evidence source and resource, over 24 hours. Re-grants and ambiguous timing matter.</p><p>Existing integrations still send their earlier event format. The new behavior is verified through in-process signed requests; a native source adapter for these richer membership events has not been enabled.</p></section>
<section><h2>Five completed reference reviews</h2><p>These are <b>AI-authored teaching reviews of the executed synthetic scenarios</b>. They are examples for learning, not investigations Aman personally performed. Each expands into the actual delivered event order and resulting case state.</p>{"".join(studies)}</section>
<section><h2>All outcomes, including the gaps</h2><div class="table-wrap" tabindex="0" aria-label="All evaluation outcomes"><table><thead><tr><th>Case</th><th>Scenario</th><th>Declared label</th><th>Measured result</th><th>Rule</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div><p>Slow probing (E07) and distributed probing (E08) remain missed. Inconclusive cases are not counted as true negatives. E18 retains its initial alert and correction rather than erasing either.</p></section>
<section class="panel"><h2>Your next 30 minutes</h2><ol><li><b>Trace E01.</b> Explain why the operator who removed membership is different from the account that later reads. Name the two evidence records supporting R3.</li><li><b>Compare E01 with E17.</b> Their visible permission sequence is equivalent, but the declared labels differ because E17 loses a re-grant. Write what additional evidence you would request and why an alert alone cannot settle the case.</li><li><b>Write your own decision.</b> For E18, separate observation, interpretation, uncertainty and next action. Mention the initial false alert as well as the corrected state. Save the note privately and state what AI assistance you used.</li><li><b>Present the tradeoff.</b> Explain why widening the time window might find E07 but create noise. Ask a reviewer to challenge your proposed test and record their actual feedback.</li></ol><p><b>Employer-ready claim:</b> “I can explain the telemetry trust boundary, trace a rule to its evidence, interpret evaluation denominators and investigate false alerts.” Use that claim after you can demonstrate those tasks yourself.</p></section>
<section><h2>How to verify this result</h2><p>After the README setup, run <code>python scripts/evaluate_detection.py</code>. It checks the frozen implementation and sealed dataset, blocks network and child-process operations, uses memory-only SQLite, sends signed in-process requests, then joins labels after predictions. It writes a fresh local receipt; it never overwrites this recorded run.</p><p><a href="../fixtures/detection_evaluation/freeze.json">Implementation freeze</a> · <a href="../fixtures/detection_evaluation/declaration.json">Dataset declaration</a> · <a href="../fixtures/detection_evaluation/inputs.json">Inputs</a> · <a href="../fixtures/detection_evaluation/labels.json">Labels and rationales</a> · <a href="../docs/DESIGN.md">Design and operational limits</a></p></section>
<footer>Executed {escape(report["executed_at"])}. Receipt SHA-256: <code>{hashlib.sha256(RECEIPT.read_bytes()).hexdigest()}</code>. Rule snapshots and dataset hashes identify content; they do not independently certify the source observations. No native Wazuh/ZAP replay or multi-day soak was run for this evaluation.</footer></main></body></html>"""


def main():
    report = json.loads(RECEIPT.read_text(encoding="utf8"))
    (ROOT / "portfolio/evaluation.html").write_text(render(report), encoding="utf8")
    print("Built portfolio/evaluation.html from the retained receipt.")


if __name__ == "__main__":
    main()
