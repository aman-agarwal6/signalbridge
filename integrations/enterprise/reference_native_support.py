"""Fixed source-proof provisioning and operator controls, with no secret output."""

import json
import os
import re
import sys
import time
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
    if action not in (
        "provision",
        "verify-boundary",
        "fault-on",
        "fault-off",
        "collect",
        "inspect",
        "wazuh-export",
    ):
        raise ValueError("Operator action escaped the finite source profile.")
    value = configure()
    import django
    from django.core.management import call_command
    from django.db import connection

    django.setup()
    source = os.environ["SB_SOURCE_COMPONENT"] == "source"
    verify_database_identity(connection, "source" if source else "console")
    if action == "verify-boundary":
        return verify_database_boundary(connection, "source" if source else "console")
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
            from reference_lab.collector import NativeTransport, deliver_one

            count, invocations = 0, 0
            transport = NativeTransport()
            deadline = time.monotonic() + 60

            def observed_transport(app, body, headers):
                nonlocal invocations
                if time.monotonic() >= deadline:
                    raise TimeoutError("Source collection phase expired.")
                invocations += 1
                return transport(app, body, headers)

            while count < 80 and time.monotonic() < deadline:
                result = deliver_one(observed_transport)
                if result is None:
                    break
                count += 1
            return {
                "committed_claim_results": count,
                "collector_transport_invocations": invocations,
                "phase_deadline_reached": time.monotonic() >= deadline,
            }
        if action == "inspect":
            return source_evidence()
    elif action == "inspect":
        from bridge.worker import drain

        drain(limit=80, worker_id="native-reference-proof")
        return console_evidence()
    elif action == "wazuh-export":
        return publish_wazuh_evidence()
    raise ValueError("Operator action does not apply to this fixed component.")


def publish_wazuh_evidence():
    """Export the current bounded synthetic source proof to the closed collector profile."""
    import uuid
    from collections import Counter

    from bridge.models import Event, ForwardedDetection, Integration, Investigation, SocDelivery
    from bridge.soc_delivery import publish, stage
    from bridge.wazuh_collector_snapshot import capture_idle_exports
    from bridge.wazuh_enterprise import publish_signals, stage_signals
    from bridge.worker import drain

    apps = list(Integration.objects.filter(slug__in=("documents", "expenses")).order_by("slug"))
    if [app.slug for app in apps] != ["documents", "expenses"] or any(
        not app.enabled for app in apps
    ):
        raise ValueError("Reference Wazuh application inventory changed.")
    drain(limit=80, worker_id="native-reference-wazuh")
    events = list(Event.objects.select_related("integration").order_by("received_at", "event_id"))
    if len(events) != 23 or any(
        row.integration.slug not in {"documents", "expenses"}
        or row.state != "processed"
        or row.source != "instrumented_lab"
        or row.environment != "lab"
        for row in events
    ):
        raise ValueError("Reference Wazuh source event inventory is incomplete.")
    cases = list(Investigation.objects.select_related("integration").order_by("pk"))
    if (
        len(cases) != 1
        or cases[0].integration.slug != "documents"
        or cases[0].rule != "R3"
        or cases[0].status != "open"
    ):
        raise ValueError("Reference Wazuh source case is incomplete.")

    observation_counts = Counter(row.integration.slug for row in events)
    for app in apps:
        batch = stage(app)
        expected_count = observation_counts[app.slug]
        if batch is not None:
            if batch.record_count > expected_count or batch.record_count > 100:
                raise ValueError("Reference Wazuh observation batch exceeded its scope.")
            if publish(app) is None:
                raise ValueError("Reference Wazuh observation batch did not append.")
        if (
            stage(app) is not None
            or SocDelivery.objects.filter(
                event__integration=app, batch__state="file_appended"
            ).count()
            != expected_count
        ):
            raise ValueError("Reference Wazuh observation export did not drain exactly.")
        signal = stage_signals(app)
        expected_signals = 1 if app.slug == "documents" else 0
        if signal is not None:
            if signal.record_count > expected_signals or publish_signals(app) is None:
                raise ValueError("Reference Wazuh core detection export is incomplete.")
        if (
            ForwardedDetection.objects.filter(
                investigation__integration=app, batch__state="file_appended"
            ).count()
            != expected_signals
        ):
            raise ValueError("Unexpected reference Wazuh core detection scope.")

    snapshot_run = str(uuid.uuid4())
    report = capture_idle_exports(snapshot_run)
    scope_counts = report.get("scope_counts")
    expected_counts = {
        "documents/observation": observation_counts["documents"],
        "documents/detection": 1,
        "expenses/observation": observation_counts["expenses"],
        "expenses/detection": 0,
    }
    if (
        not isinstance(scope_counts, dict)
        or set(scope_counts) != set(expected_counts)
        or any(
            type(scope_counts[key]) is not int or scope_counts[key] != expected_counts[key]
            for key in expected_counts
        )
        or type(report.get("logical_records")) is not int
        or report["logical_records"] != 24
        or report.get("committed_file_snapshot_verified") is not True
    ):
        raise ValueError("Reference Wazuh export snapshot did not match the source evidence.")
    return {
        "run_id": os.environ.get("SB_SOURCE_RUN", ""),
        "snapshot_run_id": snapshot_run,
        "logical_observations": len(events),
        "forwarded_core_signals": 1,
        "scope_counts": scope_counts,
        "manifest_sha256": report["manifest_sha256"],
        "snapshot_verified": True,
    }


def verify_database_identity(connection, component):
    inventory = {
        "source": ("sb_reference", "sb_reference"),
        "console": ("sb_enterprise_access", "sb_access_console"),
    }
    if component not in inventory or connection.vendor != "postgresql":
        raise ValueError("Operator action refused an unrelated database.")
    expected = inventory[component]
    if (connection.settings_dict["NAME"], connection.settings_dict["USER"]) != expected:
        raise ValueError("Configured reference database identity changed.")
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database(), current_user")
        if cursor.fetchone() != expected:
            raise ValueError("Actual reference database identity changed.")


def verify_database_boundary(connection, component):
    import psycopg

    verify_database_identity(connection, component)
    other = "sb_enterprise_access" if component == "source" else "sb_reference"
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
            "FROM pg_roles WHERE rolname = current_user"
        )
        if cursor.fetchone() != (False, False, False, False, False):
            raise ValueError("Reference database role has unexpected privileges.")
        cursor.execute("SELECT has_database_privilege(current_user, %s, 'CONNECT')", [other])
        if cursor.fetchone() != (False,):
            raise ValueError("Reference role may connect to the other component database.")
    parameters = connection.get_connection_params()
    parameters.update(dbname=other, connect_timeout=3)
    try:
        with psycopg.connect(**parameters):
            pass
    except psycopg.Error as error:
        denial = connect_denial(error, other)
        if denial is not None:
            return {
                "component": component,
                "actual_identity_verified": True,
                "cross_database_connect_denied": True,
                **denial,
            }
        raise ValueError("Cross-database connection failure is inconclusive.") from None
    raise ValueError("Cross-database connection unexpectedly succeeded.")


def connect_denial(error, database):
    """libpq startup errors may lack SQLSTATE; accept only its exact server denial.

    The successful identity/role/CONNECT queries must precede this fixed-target
    attempt. A generic failure, password rejection or timeout is inconclusive.
    Diagnostic text is examined in memory and is never returned or logged.
    """
    import psycopg

    if database not in ("sb_reference", "sb_enterprise_access"):
        raise ValueError("Unexpected database denial target.")
    if error.sqlstate == "42501":
        return {"denial_kind": "sqlstate", "denial_sqlstate": "42501"}
    if not isinstance(error, psycopg.OperationalError) or error.sqlstate is not None:
        return None
    text = str(error)
    if len(text) > 8192 or re.search(
        r"timeout|connection refused|could not translate|password authentication failed",
        text,
        re.IGNORECASE,
    ):
        return None
    if re.search(
        r'FATAL:\s+permission denied for database "'
        + re.escape(database)
        + r'"\r?\nDETAIL:\s+User does not have CONNECT privilege\.\s*$',
        text,
    ):
        return {"denial_kind": "server_connect_privilege_message", "denial_sqlstate": None}
    return None


def source_evidence():
    """Called after native database verification; also exercised in memory tests."""
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
                "payload": row.payload,
            }
            for row in Outbox.objects.order_by("created_at", "pk")
        ],
        "fault_enabled": BoundedFault.objects.filter(enabled=True).exists(),
        "direct_grants": Grant.objects.filter(kind="direct").count(),
    }


def console_evidence():
    from bridge.models import Event, Investigation

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
                "payload": row.payload,
                "processing_attempts": row.processing_attempts,
                "processed_by": row.processed_by,
                "processed_at": row.processed_at.isoformat() if row.processed_at else None,
            }
            for row in Event.objects.select_related("integration").order_by(
                "received_at", "event_id"
            )
        ],
        "cases": [
            {
                "case_id": str(row.pk),
                "rule": row.rule,
                "app": row.integration.slug,
                "severity": row.severity,
                "status": row.status,
                "version": row.version,
                "evidence_event_ids": [
                    str(v) for v in row.events.values_list("event_id", flat=True)
                ],
            }
            for row in Investigation.objects.select_related("integration").order_by(
                "rule", "correlation"
            )
        ],
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Exactly one fixed source-proof operation is required.")
    try:
        print(json.dumps(operate(sys.argv[1]), sort_keys=True))
    except Exception as error:
        print(json.dumps({"completed": False, "error_class": type(error).__name__}))
        raise SystemExit(1) from None
