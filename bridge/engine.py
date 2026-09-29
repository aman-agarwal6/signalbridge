"""Pure decisions. Benchmark labels must never be passed into this module."""

from collections import Counter, defaultdict
from datetime import timedelta

from .contract import digest, timestamp

POLICIES = ("baseline", "unsafe", "revised")
R1_WINDOW_SECONDS = 300


def context_valid(event):
    c = event.get("context")
    if not c:
        return False
    at = timestamp(event["occurred_at"])
    return (
        c["managed_device"]
        and c["reauthenticated"]
        and timestamp(c["valid_from"]) <= at < timestamp(c["valid_to"])
        and timestamp(c["known_at"]) <= at
    )


def triage(events, policy):
    if policy not in POLICIES:
        raise ValueError("Unknown policy.")
    grouped = defaultdict(list)
    for event in events:
        if event["operation"] != "private_record.read":
            continue
        grouped[(event["app"], event["actor"], event["episode"])].append(event)
    cases = []
    for (app, actor, episode), group in sorted(grouped.items()):
        failures = [e for e in group if e["outcome"] in ("denied", "not_visible")]
        revoked = [
            e
            for e in group
            if e["outcome"] == "allowed"
            and e["reason"] in ("membership_removed", "policy_regression")
        ]
        if not failures and not revoked:
            continue
        candidates = failures + revoked
        if policy == "unsafe" and all(
            e.get("context") and e["context"]["managed_device"] for e in candidates
        ):
            continue
        if (
            policy == "revised"
            and not revoked
            and all(
                e["outcome"] == "not_visible"
                and e["reason"] == "resource_unavailable"
                and context_valid(e)
                for e in failures
            )
        ):
            continue
        cases.append(
            {
                "app": app,
                "actor": actor,
                "episode": episode,
                "event_ids": sorted(e["event_id"] for e in candidates),
                "severity": "critical" if revoked else "medium",
                "explanation": "Access succeeded after recorded revocation."
                if revoked
                else "Unavailable or denied access needs analyst review; missing rows do not establish a confirmed denial.",
            }
        )
    return cases


def _rolling_failures(events, endpoint_from, endpoint_to):
    groups = defaultdict(list)
    for event in events:
        if event["outcome"] in ("denied", "not_visible"):
            scope = (event["app"], event["environment"], event["actor"])
            groups[scope].append((timestamp(event["occurred_at"]), event))
    results = []
    window_size = timedelta(seconds=R1_WINDOW_SECONDS)
    for scope, group in sorted(groups.items()):
        group.sort(key=lambda item: (item[0], item[1]["event_id"]))
        resources = Counter()
        support = defaultdict(list)
        left = 0
        for right, (at, event) in enumerate(group):
            resources[event["resource"]] += 1
            while at - group[left][0] > window_size:
                expired = group[left][1]["resource"]
                resources[expired] -= 1
                if not resources[expired]:
                    del resources[expired]
                left += 1
            if len(resources) < 3:
                continue
            if endpoint_from is not None and at < endpoint_from:
                continue
            if endpoint_to is not None and at > endpoint_to:
                continue
            bucket = at.replace(second=0, microsecond=0) - timedelta(minutes=at.minute % 5)
            intervals = support[bucket]
            # Store the union of supporting intervals once, not a copy per endpoint.
            if intervals and left <= intervals[-1][1] + 1:
                intervals[-1] = (intervals[-1][0], right)
            else:
                intervals.append((left, right))
        for bucket, intervals in sorted(support.items()):
            ids = {
                group[index][1]["event_id"]
                for start, end in intervals
                for index in range(start, end + 1)
            }
            results.append(
                {
                    "rule": "R1",
                    "correlation": digest(["R1/rolling-v2", *scope, bucket.isoformat()]),
                    "severity": "medium",
                    "title": "Repeated private-resource access failures",
                    "explanation": "At least three distinct resources were denied or not visible within a rolling five-minute window. This case groups qualifying window endpoints within one fixed UTC five-minute bucket, so its combined evidence can span more than five minutes. This is a review signal, not proof of an attack or of database denial.",
                    "event_ids": sorted(ids),
                }
            )
    return results


def detections(events, *, endpoint_from=None, endpoint_to=None):
    """R1 uses inclusive rolling windows; optional endpoint bounds preserve lookback context.

    Callers must keep trusted source classes separate: source is not a wire-payload field.
    The worker supplies only the endpoint range affected by one newly processed event.
    R2 remains a per-event revoked-success signal, independent of these R1 bounds.
    """
    if endpoint_from is not None and endpoint_to is not None and endpoint_from > endpoint_to:
        raise ValueError("Detection endpoint range is reversed.")
    results = []
    events = [event for event in events if event["operation"] == "private_record.read"]
    for event in events:
        if event["outcome"] == "allowed" and event["reason"] in (
            "membership_removed",
            "policy_regression",
        ):
            results.append(
                {
                    "rule": "R2",
                    "correlation": event["event_id"],
                    "severity": "critical",
                    "title": "Access after a recorded revocation",
                    "explanation": "The source observed an allowed read after revocation. Verify the source context and permission boundary.",
                    "event_ids": [event["event_id"]],
                }
            )
    return results + _rolling_failures(events, endpoint_from, endpoint_to)
