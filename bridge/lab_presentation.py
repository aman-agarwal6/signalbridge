"""Plain-language objectives for the fixed synthetic capability suite."""

SCENARIOS = {
    "authorized_read": (
        "Authorized access",
        "A normal member reads a private resource. An allowed read alone should not create a case.",
    ),
    "distinct_private_failures": (
        "Repeated failures across private resources",
        "Three failed reads target different resources under one actor and source. The repetition should be detected.",
    ),
    "same_resource_retries": (
        "Retries against one resource",
        "Three retries target the same resource. The distinct-resource threshold should prevent an alert.",
    ),
    "below_threshold": (
        "Activity below the threshold",
        "Two distinct failed reads should remain below the configured threshold.",
    ),
    "bucket_boundary_gap": (
        "Attempts crossing a time boundary",
        "Three distinct failed reads occur across adjacent five-minute buckets. The security expectation is a detection even at the boundary.",
    ),
    "revoked_read_allowed": (
        "Allowed read after reported removal",
        "A synthetic source reports a successful read after membership removal. This should prompt investigation.",
    ),
    "controlled_policy_fault": (
        "Reported policy regression",
        "Synthetic metadata describes allowed access during a policy regression. No actual policy or service is changed by this scenario.",
    ),
    "successful_membership_change": (
        "Legitimate membership administration",
        "A successful membership-change operation is not a private-resource read and should not trigger the access detector.",
    ),
    "session_errors_not_private_reads": (
        "Session checks remain distinct",
        "Failed session-verification operations should not be misclassified as repeated private-resource reads.",
    ),
    "dependency_errors": (
        "Dependency errors remain distinct",
        "Dependency errors should not be presented as confirmed permission failures.",
    ),
    "mixed_sources": (
        "Evidence-source separation",
        "Observed-lab and synthetic-fixture records must not combine to meet one detection threshold.",
    ),
    "cross_application": (
        "Application separation",
        "Records from different applications must not combine into a shared case.",
    ),
    "mixed_environments": (
        "Environment separation",
        "Records from test and lab environments must remain separate during correlation.",
    ),
    "out_of_order": (
        "Out-of-order delivery",
        "A qualifying set arrives out of chronological order. The worker should still find the pattern.",
    ),
    "duplicate_delivery": (
        "Duplicate delivery",
        "Repeated delivery of the same event must not inflate the unique-resource count or produce a new case.",
    ),
}


def describe_scenario(row):
    title, objective = SCENARIOS.get(
        row["id"], (row["id"], "Inspect this recorded scenario's expected and observed outcomes.")
    )
    return dict(row, title=title, objective=objective)
