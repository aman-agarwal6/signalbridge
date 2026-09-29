"""Fictional tabletop evidence. Never imported as operational or verified lab data."""

import json
from copy import deepcopy
from hashlib import sha256

VERSION = "analyst-tabletop-v1"
ASSESSMENTS = {
    "boundary_failure": "Supported access-boundary failure",
    "inconclusive": "Inconclusive - more evidence needed",
    "benign": "Supported benign explanation",
    "visibility_gap": "Monitoring visibility gap",
}
PRIORITIES = {"high": "High", "medium": "Medium", "low": "Low"}
CONFIDENCE = {"high": "High", "medium": "Medium", "low": "Low"}
NEXT_ACTIONS = {
    "corroborate_source": "Request original access context and controls before declaring an incident",
    "escalate_retest": "Escalate the access issue and request a scoped fix/retest",
    "restore_service": "Restore service health and repeat permission checks",
    "document_benign": "Document the benign explanation and retain relevant monitoring",
    "restore_visibility": "Escalate collection failure and reconcile the missing interval",
    "validate_scan": "Validate scan scope and rerun the affected checks",
}


def packet(identity, action, source, at, text):
    return dict(id=identity, action=action, source=source, at=at, text=text)


CATALOG = {
    "access-review": {
        "title": "Private record after a membership change",
        "focus": "Access verification and engineering handoff",
        "brief": "You are on triage for a fictional collaboration service. An R2-style alert reports an allowed private-record read after a membership removal. The application owner asks whether to treat it as a permission failure. Evaluate one tenant, one actor and one known record; no wider compromise has been reported.",
        "requirement": "Once group removal commits, a former member cannot read the group's private record. The owner must retain access.",
        "packets": [
            packet(
                "E1",
                "Inspect the alert and request",
                "Simulated application event",
                "09:04:00Z",
                "tenant=t-training; actor=member-17; resource=record-42; request=req-204; operation=private_record.read; outcome=allowed; reason=membership_revoked. This is a source-provided label, not independent proof of removal.",
            ),
            packet(
                "E2",
                "Request membership and identity evidence",
                "Simulated identity and change records",
                "09:01:00Z",
                "The owner removed member-17 from group-blue; the transaction committed at 09:01:00Z. A 09:03 identity check maps the unchanged ordinary session to member-17 with no service/admin role. record-42 belongs to group-blue in tenant t-training; no alternate membership exists.",
            ),
            packet(
                "E3",
                "Inspect response content and positive control",
                "Simulated scoped HTTP comparison",
                "09:04:02Z",
                "req-204 returned HTTP 200 with the known record-42 marker after removal committed. An owner request returned the same marker. No write request was made. The record and service were available; this is more than proof of a valid session.",
            ),
            packet(
                "E4",
                "Check change scope and recovery evidence",
                "Simulated operator handoff",
                "09:08:00Z",
                "The operator confirms this is a deliberately weakened policy in a disposable training tenant. Other tenants, images, write access and production were not tested. The exercise has no completed restoration run yet; the operator must restore policy and verify the former member is blocked while the owner still reads and restored membership regains intended access.",
            ),
        ],
        "answer": dict(
            assessment="boundary_failure",
            priority="high",
            confidence="high",
            next_action="escalate_retest",
            required=["E2", "E3", "E4"],
            explanation="The fictional packet supports one unauthorized read after committed removal, with an ordinary identity and working owner control. The deliberate lab fault explains the result; it is not a production breach. Request correction and negative, positive and restoration checks. Do not claim writes, other tenants or completed recovery.",
        ),
    },
    "availability-review": {
        "title": "Permission test interrupted by a service error",
        "focus": "Uncertainty and positive controls",
        "brief": "An overnight access check is marked unsuccessful. A colleague proposes closing it because a removed member did not receive the private record. Decide whether the control was actually verified.",
        "requirement": "A removed member must be blocked because of their permissions, while an authorized owner can read the known record.",
        "packets": [
            packet(
                "E1",
                "Inspect the negative check",
                "Simulated HTTP check",
                "10:05:00Z",
                "The removed member's unchanged session still authenticates. Their request for known record-42 returns HTTP 503 Service Unavailable with no record content. No authorization denial was recorded.",
            ),
            packet(
                "E2",
                "Inspect the owner control",
                "Simulated HTTP comparison",
                "10:05:02Z",
                "The authorized owner also receives HTTP 503 for record-42. The expected successful control failed. The test cannot distinguish a working authorization boundary from a broken dependency.",
            ),
            packet(
                "E3",
                "Inspect health and change context",
                "Simulated service health and membership records",
                "10:06:00Z",
                "Removal committed at 10:00Z. The storage dependency is unhealthy and the request failed before a permission verdict. Recovery has not yet been tested. No successful unauthorized response appears in this packet.",
            ),
        ],
        "answer": dict(
            assessment="inconclusive",
            priority="medium",
            confidence="high",
            next_action="restore_service",
            required=["E1", "E2", "E3"],
            explanation="Both forbidden and authorized requests failed because the dependency was unavailable. This is inconclusive for authorization, not a proven denial or a confirmed read. Confidence can be high in that limited conclusion. Restore health and repeat both controls with the same scoped identities and known record.",
        ),
    },
    "repeated-denials": {
        "title": "Three unsuccessful reads during a project move",
        "focus": "Benign context without weakening a detector",
        "brief": "An R1-style alert opened during a workspace reorganization. The actor has three unsuccessful reads. Determine whether the available context supports an attack finding, a benign explanation, or an unresolved gap.",
        "requirement": "Private records stay restricted to current members. A detector groups suspicious patterns for human review; a match alone is not an incident.",
        "packets": [
            packet(
                "E1",
                "Inspect the ordered events",
                "Simulated event timeline",
                "11:02:00Z",
                "Same actor member-23, tenant t-training and source: distinct records r-11 at 11:00Z, r-12 at 11:01Z and r-13 at 11:02Z all returned denied/membership_required. This meets the three-distinct-resources-in-five-minutes R1 pattern.",
            ),
            packet(
                "E2",
                "Request approved change context",
                "Simulated change ticket and helpdesk record",
                "10:55:00Z",
                "A recorded, approved group move removed old memberships before the reads. The actor's helpdesk report identifies three old bookmarked links matching r-11/r-12/r-13. The timeline and actor match the change. This is corroborating benign context, not a reason to trust every managed device.",
            ),
            packet(
                "E3",
                "Check comparison and remaining scope",
                "Simulated access controls and follow-up",
                "11:07:00Z",
                "An owner read each known record successfully. No allowed old-group read appears in this bounded packet, and the actor successfully used the new group's correct link. The packet does not prove all future or off-source behavior is benign.",
            ),
        ],
        "answer": dict(
            assessment="benign",
            priority="low",
            confidence="medium",
            next_action="document_benign",
            required=["E1", "E2", "E3"],
            explanation="The detector correctly found repeated denials; matching change and helpdesk evidence support a benign explanation for this case. Record that bounded conclusion and retain the rule. Closing one case does not justify globally suppressing alerts or claiming the actor can never be malicious.",
        ),
    },
    "quiet-queue": {
        "title": "An unexpectedly quiet monitoring queue",
        "focus": "Collection health and blind spots",
        "brief": "The morning dashboard shows zero new alerts. A manager asks whether that means the application was quiet overnight. Your job is to assess whether the queue can support that conclusion.",
        "requirement": "Expected observations must reach collection and processing before alert silence can support a monitoring conclusion.",
        "packets": [
            packet(
                "E1",
                "Check source arrival and processing times",
                "Simulated collection dashboard",
                "12:00:00Z",
                "Last accepted event: 06:00Z. Last processed event: 06:00Z. Pending queue: zero. No new case since 06:00Z. The worker's current heartbeat is healthy, but there is no later source arrival.",
            ),
            packet(
                "E2",
                "Check expected source activity",
                "Simulated source health summary",
                "11:59:00Z",
                "The source's synthetic health counter records 240 expected observations between 06:00Z and 12:00Z. Delivery attempts fail with an authentication configuration error. Their durable outbox retains 240 records. No event body or credential is included.",
            ),
            packet(
                "E3",
                "Check recovery ownership and limits",
                "Simulated operator handoff",
                "12:03:00Z",
                "The operator must repair the scoped delivery configuration, retry retained records and reconcile sent/accepted/processed counts and duplicates for the missing interval. No recovery has run. The monitoring gap does not by itself prove an attack or prove no attack occurred.",
            ),
        ],
        "answer": dict(
            assessment="visibility_gap",
            priority="high",
            confidence="high",
            next_action="restore_visibility",
            required=["E1", "E2", "E3"],
            explanation="A healthy worker and empty queue do not establish healthy collection. Expected source records are stranded upstream, creating a six-hour blind interval. Escalate delivery recovery and reconcile the backlog; do not report zero incidents from zero received telemetry.",
        ),
    },
    "scanner-followup": {
        "title": "A finding disappeared from the latest scan",
        "focus": "Coverage, provenance and remediation claims",
        "brief": "An earlier scanner observation reported a missing security header on a private route. A later report contains zero findings. A teammate asks you to mark the issue fixed.",
        "requirement": "A remediation claim needs evidence that the affected control was corrected and retested in a comparable scope.",
        "packets": [
            packet(
                "E1",
                "Inspect the original observation",
                "Simulated ZAP-style passive observation",
                "13:00:00Z",
                "Report scan-a, source revision training-rev-a, observed a header warning on /private/example in a disposable fixture. It is a passive response observation, not proof of exploitation or broad scan coverage.",
            ),
            packet(
                "E2",
                "Compare current coverage and source",
                "Simulated scan manifest",
                "14:00:00Z",
                "Report scan-b used training-rev-a and visited only /health. It contains zero findings, but never visited /private/example. No source correction was recorded. The two reports do not cover the same path.",
            ),
            packet(
                "E3",
                "Check review and retest requirements",
                "Simulated review history",
                "14:05:00Z",
                "The original finding is marked Reviewed. That means someone assessed the observation; it is not a fixed state. Ask for the change identity and a scoped response check on the affected path, with authorized access working. No exploitation or wider scan is needed for this exercise.",
            ),
        ],
        "answer": dict(
            assessment="inconclusive",
            priority="medium",
            confidence="high",
            next_action="validate_scan",
            required=["E1", "E2", "E3"],
            explanation="The latest report omitted the affected path. Neither zero results nor a Reviewed disposition establishes remediation. Request change evidence and a comparable scoped retest, and preserve both original and follow-up reports.",
        ),
    },
}


def scenario(key):
    value = deepcopy(CATALOG[key])
    return {"version": VERSION, "key": key, "fictional": True, **value}


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def feedback(snapshot, decision):
    answer = snapshot["answer"]
    if snapshot.get("fictional") is False:
        return {
            "checks": [
                {
                    "label": "Key evidence cited",
                    "matches": set(answer["required"]).issubset(decision["citations"]),
                    "expected": ", ".join(answer["required"]),
                }
            ],
            "explanation": answer["explanation"],
            "human_review": "The written reasoning is not automatically graded. Choices about priority, confidence and next action require a human review of your scoped argument. These reviewed historical receipts do not establish your independent competency or current tool health.",
        }
    checks = [
        {
            "label": "Assessment",
            "matches": decision["assessment"] == answer["assessment"],
            "expected": ASSESSMENTS[answer["assessment"]],
        },
        {
            "label": "Priority in this exercise",
            "matches": decision["priority"] == answer["priority"],
            "expected": PRIORITIES[answer["priority"]],
        },
        {
            "label": "Confidence in the scoped conclusion",
            "matches": decision["confidence"] == answer["confidence"],
            "expected": CONFIDENCE[answer["confidence"]],
        },
        {
            "label": "Next action",
            "matches": decision["next_action"] == answer["next_action"],
            "expected": NEXT_ACTIONS[answer["next_action"]],
        },
        {
            "label": "Key evidence cited",
            "matches": set(answer["required"]).issubset(decision["citations"]),
            "expected": ", ".join(answer["required"]),
        },
    ]
    return {
        "checks": checks,
        "explanation": answer["explanation"],
        "human_review": "The written reasoning is not automatically graded. A person must review accuracy, scope, uncertainty, business impact and the requested next step. These published exercises are coached practice, not an independent competency assessment.",
    }
