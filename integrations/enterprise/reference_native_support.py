"""Fixed source-proof provisioning and operator controls, with no secret output."""

import json
import os
import sys
from pathlib import Path

FIELDS = frozenset(
    (
        "accounts",
        "source_secret",
        "console_secret",
        "pseudo_documents",
        "pseudo_expenses",
        "delivery_documents",
        "delivery_expenses",
    )
)
ACCOUNTS = frozenset(("operator", "document_member", "expense_member", "outsider"))


def profile(path=Path("/run/secrets/source_profile")):
    if not path.is_file() or path.is_symlink() or not 100 <= path.stat().st_size <= 4096:
        raise ValueError("The bounded dedicated source profile is unavailable.")
    value = json.loads(path.read_bytes())
    if (
        not isinstance(value, dict)
        or set(value) != FIELDS
        or not isinstance(value["accounts"], dict)
        or set(value["accounts"]) != ACCOUNTS
    ):
        raise ValueError("Source-profile credential inventory changed.")
    secrets = [*value["accounts"].values(), *(v for k, v in value.items() if k != "accounts")]
    if any(
        not isinstance(v, str) or not 32 <= len(v) <= 128 or not v.isascii() for v in secrets
    ) or len(set(secrets)) != len(secrets):
        raise ValueError("Separate long native source-profile credentials are required.")
    return value


def configure():
    component = os.environ.get("SB_SOURCE_COMPONENT")
    if (
        sys.platform != "linux"
        or os.environ.get("SB_SOURCE_PROOF") != "1"
        or component not in ("source", "console")
        or any(name.startswith("PG") and value for name, value in os.environ.items())
    ):
        raise ValueError("Reference controls refuse an unreviewed runtime profile.")
    value = profile()
    for name in list(os.environ):
        if name.startswith(("SB_REF_", "SB_SERVICE_", "SB_ENTERPRISE_")):
            os.environ.pop(name)
    os.environ.update(
        DJANGO_SETTINGS_MODULE="integrations.enterprise.reference_native_settings",
        SB_SECRET_KEY=value[component + "_secret"],
        SB_REF_DELIVERY_CA="/run/secrets/lab_ca",
        SB_REF_DELIVERY_DOCUMENTS=value["delivery_documents"],
        SB_REF_DELIVERY_EXPENSES=value["delivery_expenses"],
    )
    if component == "source":
        os.environ.update(
            SB_REF_PSEUDO_DOCUMENTS=value["pseudo_documents"],
            SB_REF_PSEUDO_EXPENSES=value["pseudo_expenses"],
        )
    return value


def operate(action):
    if action not in ("provision", "fault-on", "fault-off", "collect", "inspect"):
        raise ValueError("Operator action escaped the finite source profile.")
    value = configure()
    import django
    from django.core.management import call_command
    from django.db import connection

    django.setup()
    source = os.environ["SB_SOURCE_COMPONENT"] == "source"
    expected = "sb_reference" if source else "sb_enterprise_access"
    if connection.vendor != "postgresql" or connection.settings_dict["NAME"] != expected:
        raise ValueError("Operator action refused an unrelated database.")
    if action == "provision":
        call_command("migrate", verbosity=0, interactive=False)
        if source:
            from reference_lab.seed import seed_accounts

            seed_accounts(value["accounts"])
        else:
            from bridge.models import IngestKey, Integration

            if Integration.objects.exists():
                raise ValueError("Console provisioning requires an empty dedicated database.")
            for app in ("documents", "expenses"):
                integration = Integration.objects.create(slug=app, name="Synthetic " + app)
                IngestKey.objects.create(
                    integration=integration,
                    key_id="reference-" + app + "-v1",
                    environment="lab",
                    source="instrumented_lab",
                    secret_env="SB_REF_DELIVERY_" + app.upper(),
                    can_assert_membership=True,
                )
        return {"provisioned": True, "component": "source" if source else "console"}
    if source:
        if action in ("fault-on", "fault-off"):
            from reference_lab.seed import set_regression

            set_regression(action == "fault-on", 120)
            return {"fault_enabled": action == "fault-on", "maximum_seconds": 120}
        if action == "collect":
            from reference_lab.collector import deliver_one

            count = 0
            while count < 80 and deliver_one() is not None:
                count += 1
            return {"physical_delivery_attempts": count}
        if action == "inspect":
            from reference_lab.models import BoundedFault, Grant, Outbox

            if Outbox.objects.count() > 80:
                raise ValueError("Reference outbox exceeded the declared event bound.")
            return {
                "events": [
                    {
                        "event_id": str(row.pk),
                        "app": row.app,
                        "state": row.state,
                        "attempts": row.attempts,
                        "digest": row.digest,
                        "operation": row.payload["operation"],
                        "outcome": row.payload["outcome"],
                    }
                    for row in Outbox.objects.order_by("created_at", "pk")
                ],
                "fault_enabled": BoundedFault.objects.filter(enabled=True).exists(),
                "direct_grants": Grant.objects.filter(kind="direct").count(),
            }
    elif action == "inspect":
        from bridge.models import Event, Investigation
        from bridge.worker import drain

        drain(limit=80, worker_id="native-reference-proof")
        if Event.objects.count() > 80 or Investigation.objects.count() > 20:
            raise ValueError("Reference console exceeded its declared evidence bound.")
        return {
            "events": [
                {
                    "event_id": str(row.event_id),
                    "app": row.integration.slug,
                    "state": row.state,
                    "digest": row.digest,
                    "source": row.source,
                }
                for row in Event.objects.select_related("integration").order_by(
                    "received_at", "event_id"
                )
            ],
            "cases": [
                {
                    "rule": row.rule,
                    "app": row.integration.slug,
                    "evidence_event_ids": [
                        str(v) for v in row.events.values_list("event_id", flat=True)
                    ],
                }
                for row in Investigation.objects.select_related("integration").order_by(
                    "rule", "correlation"
                )
            ],
        }
    raise ValueError("Operator action does not apply to this fixed component.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Exactly one fixed source-proof operation is required.")
    try:
        print(json.dumps(operate(sys.argv[1]), sort_keys=True))
    except Exception as error:
        print(json.dumps({"completed": False, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
