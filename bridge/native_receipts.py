"""Shared consistency checks for locally admitted historical tool evidence.

These checks bind stored rows to their admission audit. They do not validate a
native execution; each importer must first use its tool-specific archive loader.
"""

from integrations.enterprise.reference_host_controls import same

from .models import Audit


def matches_result(run, integration_id, suite, revision, result, *, checksum):
    """Keep each receipt format's established canonical hash encoding."""
    return (
        run.integration_id == integration_id
        and run.suite == suite
        and run.status == "passed"
        and run.revision == revision
        and run.digest == checksum
        and same(run.result, result)
    )


def admission_audits(run, action, profile):
    """Bind an import marker to this exact row, scope and immutable result."""
    return Audit.objects.filter(
        integration_id=run.integration_id,
        action=action,
        object_id=str(run.pk),
        detail__digest=run.digest,
        detail__run_id=run.result["run_id"],
        detail__profile=profile,
    )
