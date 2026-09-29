"""Explain imported authorization evidence without running tests or merging scopes.

The catalog is a review aid, not an inventory of every permission or attack.
Each row requires its own checks from ONE recorded run. Missing, duplicate,
mis-staged or unsupported evidence never becomes a passing coverage claim.
"""

from collections import Counter

from .assurance import EvidenceError, validate_checks

SQL_SUITE = "Repository PostgreSQL authorization checks"
HTTP_SUITE = "Local Supabase Auth, REST and Storage"


def objective(key, actor, resource, state, expected, why, *checks, stage="assertion"):
    return {
        "id": key,
        "actor": actor,
        "resource": resource,
        "action": "Read",
        "condition": state,
        "expected": expected,
        "why": why,
        "stage": stage,
        "required_checks": list(checks),
    }


HTTP = (
    objective(
        "owner-read",
        "Owner",
        "Private record and attached image",
        "Before removal",
        "Allow exact fixture",
        "A denial test needs a positive control proving the fixture exists and is reachable.",
        "owner_exact_row_visible",
        "owner_snapshot_visible",
        "owner_attached_image_visible",
    ),
    objective(
        "member-read",
        "Member",
        "Private record and attached image",
        "Active membership",
        "Allow exact fixture",
        "The control must preserve legitimate access, not block everybody.",
        "member_exact_row_visible",
        "member_snapshot_visible",
        "member_attached_image_visible",
    ),
    objective(
        "outsider-read",
        "Outsider",
        "Private record and attached image",
        "No membership",
        "Hide record / deny request",
        "An authenticated outsider is different from an anonymous visitor. Compare the known fixture with the owner control.",
        "outsider_exact_row_hidden",
        "outsider_snapshot_denied",
        "outsider_attached_image_hidden",
    ),
    objective(
        "anonymous-read",
        "Anonymous visitor",
        "Private record / snapshot",
        "No session",
        "Deny",
        "This tests the unauthenticated data path; it does not establish anonymous image coverage.",
        "anonymous_table_read_denied",
        "anonymous_snapshot_denied",
    ),
    objective(
        "draft-read",
        "Owner and member",
        "Unattached private image",
        "Before attachment",
        "Owner allowed; member hidden",
        "Having group membership must not automatically reveal an owner's unattached draft.",
        "owner_draft_image_visible",
        "member_unattached_draft_hidden",
    ),
    objective(
        "retained-session",
        "Removed member",
        "Identity endpoint",
        "Same token after removal",
        "Still authenticated",
        "Authentication proves identity. This control separates membership revocation from simply logging the user out.",
        "removed_member_same_jwt_still_valid",
    ),
    objective(
        "removed-read",
        "Removed member",
        "Private record and attached image",
        "Same token after removal",
        "Hide record / deny new request",
        "A valid session must not preserve a permission that has been removed. Previously downloaded bytes are outside this check.",
        "removed_member_same_jwt_still_valid",
        "removed_member_exact_row_hidden",
        "removed_member_snapshot_denied",
        "removed_member_new_image_request_hidden",
    ),
    objective(
        "owner-survives",
        "Owner",
        "Private record",
        "After another member is removed",
        "Allow",
        "A system-wide outage could make a negative test look successful; the owner's continued access is a separate control.",
        "owner_read_survives_removal",
    ),
    objective(
        "restored-read",
        "Restored member",
        "Private record and attached image",
        "Membership restored",
        "Allow again",
        "A successful cleanup request is insufficient. Positive reads must establish that access really recovered.",
        "membership_restored",
        "restored_member_exact_row_visible",
        "restored_member_snapshot_visible",
        "restored_member_image_visible",
        stage="restoration",
    ),
)

SQL = {
    "bettail": (
        objective(
            "member-read",
            "Member",
            "Private pick / snapshot",
            "Active membership",
            "Allow known record",
            "SQL roles use supplied claims; this does not test a real login.",
            "member-can-read-exact-private-pick",
            "member-real-snapshot-rpc",
        ),
        objective(
            "outsider-read",
            "Outsider",
            "Private pick / snapshot",
            "Substituted known identifier",
            "Hide / deny",
            "A known private record distinguishes isolation from querying an identifier that never existed.",
            "outsider-id-substitution-is-not-visible",
            "outsider-real-snapshot-rpc-denied",
        ),
        objective(
            "unknown-read",
            "Outsider",
            "Unknown identifiers",
            "No matching record",
            "Not visible",
            "An empty result alone does not establish that authorization denied an existing record.",
            "unknown-identifiers-stay-not-visible",
        ),
        objective(
            "removed-read",
            "Removed member",
            "Private pick / snapshot",
            "Membership removed",
            "Hide / deny",
            "The database should evaluate current membership on the new request.",
            "removed-member-new-read-is-not-visible",
            "removed-member-snapshot-rpc-denied",
        ),
        objective(
            "owner-survives",
            "Owner",
            "Private pick",
            "Another member removed",
            "Allow",
            "Retain a legitimate-access control alongside the denial.",
            "owner-remains-authorized-after-removal",
        ),
        objective(
            "anonymous-read",
            "Anonymous visitor",
            "Private table",
            "No identity claim",
            "Deny",
            "Anonymous and authenticated outsider access are different boundaries.",
            "anonymous-direct-read-rejected",
        ),
        objective(
            "fault-retest",
            "Member and outsider",
            "Private pick",
            "Disposable SQL policy fault / rollback",
            "Catch fault; restore allow and deny",
            "The unchanged assertion must detect the deliberately weakened policy and pass after rollback. This is not an HTTP fault test.",
            "mutation-is-caught-by-unchanged-boundary",
            "restored-policy-preserves-allow-and-filter",
        ),
    ),
    "netted": (
        objective(
            "owner-read",
            "Owner",
            "Private record",
            "Own snapshot",
            "Allow known record",
            "A legitimate-access control proves that the private record is present.",
            "owner-can-read-created-record-via-rpc",
        ),
        objective(
            "other-user-read",
            "Other user",
            "Owner's private record",
            "Other user's snapshot",
            "Exclude private record",
            "Authentication does not grant access to another user's records.",
            "other-user-snapshot-excludes-private-record",
        ),
        objective(
            "direct-table",
            "Owner",
            "Private table",
            "Bypassing approved database function",
            "Deny",
            "Test alternate access paths as well as the intended function.",
            "direct-table-access-denied",
        ),
        objective(
            "mfa-claim",
            "Owner",
            "Private snapshot",
            "Insufficient supplied assurance claim",
            "Deny",
            "This tests the database's MFA claim requirement, not a genuine second-factor challenge.",
            "mfa-required-by-real-database-function",
        ),
        objective(
            "forged-session",
            "Owner",
            "Private snapshot",
            "Other user's supplied session identifier",
            "Deny",
            "The function must bind the supplied session to the supplied user; no JWT signature is exercised here.",
            "forged-session-rejected",
        ),
        objective(
            "revoked-session",
            "Owner and other user",
            "Private snapshot",
            "Owner's session revoked",
            "Owner denied; other session survives",
            "Revocation should be scoped and preserve another user's legitimate session.",
            "revoked-session-rejected",
            "other-user-session-survives-revocation",
        ),
        objective(
            "fault-retest",
            "Owner and other user",
            "Private records",
            "Disposable SQL function fault / rollback",
            "Catch fault; restore user isolation",
            "The same assertion must catch the fault and pass after rollback. Genuine service behavior remains untested by this run.",
            "mutation-is-caught-by-unchanged-boundary",
            "restored-rpc-preserves-owner-isolation",
        ),
    ),
}

LABELS = {
    "passed": "Supported in this run",
    "failed": "Check failed - investigate",
    "not_recorded": "Not recorded in this run",
    "inconsistent": "Evidence needs review",
}


def coverage_for_run(run, app_slug):
    """Return JSON-safe presentation data, with no additional database/file reads."""
    result = run.result
    if not isinstance(result, dict) or result.get("app") != app_slug:
        return None
    kind = result.get("evidence_kind")
    if kind == "supabase_http" and app_slug == "bettail" and run.suite == HTTP_SUITE:
        catalog, layer = HTTP, "Genuine local Auth, REST and Storage"
    elif kind is None and run.suite == SQL_SUITE and app_slug in SQL:
        catalog, layer = SQL[app_slug], "Disposable SQL with supplied identity claims"
    else:
        return None
    collections = {
        "assertion": result.get("checks"),
        "setup": result.get("setup_checks", []),
        "restoration": result.get("restoration_checks", []),
    }
    invalid = (
        run.status not in {"passed", "failed", "blocked"} or result.get("status") != run.status
    )
    rows = []
    for stage, items in collections.items():
        if not isinstance(items, list) or len(items) > 100:
            invalid = True
            continue
        for item in items:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("id"), str)
                or len(item["id"]) > 160
                or item.get("status") not in {"passed", "failed"}
                or item.get("stage", stage) != stage
            ):
                invalid = True
                continue
            rows.append((stage, item))
    identities = [item["id"] for _, item in rows]
    invalid |= len(identities) != len(set(identities))
    if kind == "supabase_http":
        try:
            # The importer retains setup and recovery separately. Reconstruct the
            # harness order to apply its exact outcome/HTTP/content semantics.
            from .assurance import SPECS

            order = {spec[0]: index for index, spec in enumerate(SPECS)}
            validate_checks(
                {
                    "checks": sorted(
                        (item for _, item in rows), key=lambda item: order.get(item["id"], 1000)
                    ),
                    "status": run.status,
                    "restoration": result.get("restoration"),
                }
            )
        except (EvidenceError, KeyError, TypeError):
            invalid = True
    by_key = {(stage, item["id"]): item["status"] for stage, item in rows}
    mapped = []
    for spec in catalog:
        states = [
            by_key.get((spec["stage"], key), "not_recorded") for key in spec["required_checks"]
        ]
        if kind is None:
            states.append(
                by_key.get(("assertion", "ordinary-role-is-not-superuser"), "not_recorded")
            )
        status = (
            "inconsistent"
            if invalid
            else "failed"
            if "failed" in states
            else "not_recorded"
            if "not_recorded" in states
            else "passed"
        )
        mapped.append({**spec, "status": status, "status_label": LABELS[status]})
    counts = Counter(row["status"] for row in mapped)
    return {
        "catalog_version": 1,
        "app": app_slug,
        "run_id": str(run.pk),
        "report_sha256": run.digest,
        "layer": layer,
        "rows": mapped,
        "counts": {key: counts[key] for key in LABELS},
        "limit": "Selected review objectives from one imported historical run. Not a new execution, complete application coverage, independent validation or proof of current security.",
    }
