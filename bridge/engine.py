"""Pure decisions. Benchmark labels must never be passed into this module."""

from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from datetime import timedelta

from .contract import digest, timestamp

POLICIES = ("baseline", "unsafe", "revised")
R1_WINDOW_SECONDS = 300
MEMBERSHIP_WINDOW_SECONDS = 86400
R4_WINDOW_SECONDS = 1800
R4_MIN_SPAN_SECONDS = 600
R5_WINDOW_SECONDS = 600


def membership_evaluations(events, *, endpoint_from=None, endpoint_to=None):
    """Evaluate validated resource-scoped assertions accepted by a privileged ingest key.

    Callers isolate app/environment/key-bound source. Actor is the operator on a
    change, while membership.subject is the affected account. Labels never enter
    this function. A signature establishes provenance, not source truth.
    """
    changes = defaultdict(list)
    reads = []
    for event in events:
        scope = (event["app"], event["environment"], event["resource"])
        if event.get("schema_version") == 2 and event["operation"] == "membership.change":
            changes[(*scope, event["membership"]["subject"])].append(event)
        elif event["operation"] == "private_record.read" and event["outcome"] == "allowed":
            reads.append(((*scope, event["actor"]), event))
    indexed = {}
    for scope, group in changes.items():
        group.sort(key=lambda e: (timestamp(e["occurred_at"]), e["event_id"]))
        indexed[scope] = ([timestamp(e["occurred_at"]) for e in group], group)
    results = []
    for scope, read in sorted(reads, key=lambda item: item[1]["event_id"]):
        at = timestamp(read["occurred_at"])
        if (endpoint_from is not None and at < endpoint_from) or (
            endpoint_to is not None and at > endpoint_to
        ):
            continue
        times, group = indexed.get(scope, ([], []))
        end = bisect_right(times, at)
        if not end or at - times[end - 1] > timedelta(seconds=MEMBERSHIP_WINDOW_SECONDS):
            continue
        latest = times[end - 1]
        evidence = group[bisect_left(times, latest) : end]
        states = {e["membership"]["state"] for e in evidence}
        matched = latest < at and states == {"removed"}
        results.append(
            {
                "rule": "R3",
                "correlation": digest(["R3/resource-membership-v1", read["event_id"]]),
                "matches": matched,
                "severity": "high" if matched else "medium",
                "title": "Allowed read after correlated membership removal"
                if matched
                else "Membership correlation needs reassessment",
                "explanation": (
                    "A credential-authorized membership assertion removed this account from this exact resource before an allowed read, within 24 hours. The read need not be labeled suspicious. Verify returned content, alternate permissions, clock accuracy and missing re-grants before escalating."
                    if matched
                    else "The latest available membership assertion grants access or has ambiguous ordering/state. Earlier R3 evidence no longer establishes the removal-before-read condition. Review the added evidence; no automatic closure or external response occurred."
                ),
                "event_ids": sorted({read["event_id"], *(e["event_id"] for e in evidence)}),
            }
        )
    return results


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


def _bounded_denials(events, rule, endpoint_from, endpoint_to):
    """Union qualifying intervals without copying a window for every endpoint."""
    slow = rule == "R4"
    groups, seen = defaultdict(list), set()
    for event in events:
        if event["outcome"] != "denied" or event["event_id"] in seen:
            continue
        seen.add(event["event_id"])
        scope = (event["app"], event["environment"], event["actor" if slow else "resource"])
        groups[scope].append((timestamp(event["occurred_at"]), event))
    window_seconds = R4_WINDOW_SECONDS if slow else R5_WINDOW_SECONDS
    results = []
    for scope, group in sorted(groups.items()):
        group.sort(key=lambda item: (item[0], item[1]["event_id"]))
        distinct, support, left = Counter(), defaultdict(list), 0
        field = "resource" if slow else "actor"
        for right, (at, event) in enumerate(group):
            distinct[event[field]] += 1
            while (at - group[left][0]).total_seconds() > window_seconds:
                expired = group[left][1][field]
                distinct[expired] -= 1
                if not distinct[expired]:
                    del distinct[expired]
                left += 1
            qualifies = (
                len(distinct) >= 5 and (at - group[left][0]).total_seconds() >= R4_MIN_SPAN_SECONDS
                if slow
                else len(distinct) >= 3 and right - left + 1 >= 6
            )
            if (
                not qualifies
                or (endpoint_from is not None and at < endpoint_from)
                or (endpoint_to is not None and at > endpoint_to)
            ):
                continue
            bucket = int(at.timestamp()) // window_seconds * window_seconds
            intervals = support[bucket]
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
                    "rule": rule,
                    "correlation": digest([rule + "/bounded-denials-v1", *scope, bucket]),
                    "severity": "medium",
                    "title": "Extended private-resource probing"
                    if slow
                    else "Private-resource denials across accounts",
                    "explanation": (
                        "One account was denied at least five distinct private resources within 30 minutes, with qualifying evidence spanning at least ten minutes. Fast requests followed by a delayed request can also qualify; this does not establish deliberate slow probing. Review stale links, intended permissions and approved testing."
                        if slow
                        else "At least six denied reads involving three accounts targeted the same private resource within ten minutes. This does not establish coordinated attackers or successful access. Review shared links, expected access changes and authorized tests."
                    )
                    + " Cases group qualifying endpoints into fixed UTC buckets; combined case evidence can exceed the rolling window. Missing or not-visible observations do not contribute to this rule.",
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
    results = [
        {key: value for key, value in row.items() if key != "matches"}
        for row in membership_evaluations(
            events, endpoint_from=endpoint_from, endpoint_to=endpoint_to
        )
        if row["matches"]
    ]
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
    return (
        results
        + _rolling_failures(events, endpoint_from, endpoint_to)
        + _bounded_denials(events, "R4", endpoint_from, endpoint_to)
        + _bounded_denials(events, "R5", endpoint_from, endpoint_to)
    )
