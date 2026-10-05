"""Seed the disposable Shuffle-lab receiver with synthetic cases and scoped keys.

Two applications each get one synthetic investigation with linked events. The
documents application gets one evidence-read key and one review-task key; the
expenses case exists only to prove that a documents key cannot reach it.
Secrets come from the environment and are never printed. Output: case facts.
"""

import json
import os
import sys
import uuid
from datetime import timedelta


def observation(app, index, base):
    return {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"shuffle-lab/{app}/{index}")),
        "app": app,
        "environment": "lab",
        "occurred_at": (base + timedelta(seconds=index)).isoformat(),
        "actor": "a" * 64,
        "resource": f"{index:064x}",
        "episode": str(uuid.uuid5(uuid.NAMESPACE_URL, f"shuffle-lab/{app}/episode")),
        "operation": "private_record.read",
        "outcome": "denied",
        "reason": "membership_required",
        "context": None,
    }


def main():
    import django

    django.setup()
    from django.core.management import call_command
    from django.utils import timezone

    from bridge.case_workflow import evidence_binding
    from bridge.contract import digest, timestamp
    from bridge.models import Event, Integration, Investigation, ServiceCredential

    for name in ("SB_SERVICE_SHUFFLE_READ", "SB_SERVICE_SHUFFLE_TASK"):
        if len(os.environ.get(name, "")) < 32:
            raise SystemExit("missing_lab_service_secret")
    call_command("migrate", verbosity=0, interactive=False)
    if Integration.objects.exists():
        raise SystemExit("receiver_not_fresh")
    base = timezone.now() - timedelta(minutes=5)
    cases = {}
    for slug in ("documents", "expenses"):
        app = Integration.objects.create(slug=slug, name="Synthetic " + slug)
        case = Investigation.objects.create(
            integration=app,
            rule="R1",
            correlation=("d" if slug == "documents" else "e") * 64,
            title="Synthetic Shuffle-lab investigation",
            severity="medium",
            explanation="Synthetic only",
        )
        events = []
        for index in range(2):
            value = observation(slug, index, base)
            events.append(
                Event.objects.create(
                    integration=app,
                    event_id=value["event_id"],
                    occurred_at=timestamp(value["occurred_at"]),
                    actor=value["actor"],
                    membership_subject="",
                    resource=value["resource"],
                    episode=value["episode"],
                    operation=value["operation"],
                    outcome=value["outcome"],
                    reason=value["reason"],
                    environment=value["environment"],
                    source="synthetic_demo",
                    payload=value,
                    digest=digest(value),
                    available_at=timezone.now(),
                )
            )
        case.events.add(*events)
        case.refresh_from_db()
        cases[slug] = {
            "case_id": str(case.pk),
            "case_version": case.version,
            "evidence_sha256": evidence_binding(case),
        }
        if slug == "documents":
            ServiceCredential.objects.create(
                integration=app,
                key_id="shuffle-read",
                secret_env="SB_SERVICE_SHUFFLE_READ",
                capability="read_case_evidence",
            )
            ServiceCredential.objects.create(
                integration=app,
                key_id="shuffle-task",
                secret_env="SB_SERVICE_SHUFFLE_TASK",
                capability="create_review_task",
            )
    sys.stdout.write(json.dumps({"cases": cases}, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
