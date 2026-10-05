"""Restored-console proof; install reviewed wheels only into bounded tmpfs.

The host restores a logical backup of a retained native console into a separate
PostgreSQL instance before releasing this runner. Here the restored rows are
compared with the retained archive, the schema is migrated to the current
revision, and the real operator import and case workflows run against it.
Synthetic operator accounts are created in the restoration only.
"""

import hashlib
import io
import json
import os
import re
import secrets
import subprocess
import sys
import time
import traceback
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path("/workspace")
OUTPUT = Path("/evidence")
DEPENDENCIES = Path("/opt/verification-deps")
RUNTIME = DEPENDENCIES / "runtime"
PLAN = Path("/run/secrets/restoration_plan")
TOOL_SCOPE = Path("/run/secrets/tool_scope")
PROFILES = ("access", "header")
RUN = re.compile(r"[a-f0-9]{32}")


class RestorationError(ValueError):
    """Closed code only; never row contents, credentials or command output."""


def require(condition, code="restoration_predicate"):
    if not condition:
        raise RestorationError(code)


def load_plan(raw):
    plan = json.loads(raw)
    require(
        type(plan) is dict
        and set(plan)
        == {
            "run_id",
            "profile",
            "source_run",
            "tool_run",
            "console_events_sha256",
            "tool_scope_sha256",
        },
        "plan_shape",
    )
    require(plan["profile"] in PROFILES, "plan_profile")
    require(
        all(isinstance(plan[k], str) and RUN.fullmatch(plan[k]) for k in ("run_id", "source_run")),
        "plan_identity",
    )
    require(isinstance(plan["tool_run"], str) and RUN.fullmatch(plan["tool_run"]), "plan_tool")
    require(re.fullmatch(r"[0-9a-f]{64}", plan["console_events_sha256"]) is not None, "plan_hash")
    scope = plan["tool_scope_sha256"]
    # Only the Wazuh review needs a host-revalidated scope (see access_workflow).
    require(
        (scope is None) == (plan["profile"] == "header")
        and (scope is None or re.fullmatch(r"[0-9a-f]{64}", scope) is not None),
        "plan_tool_scope",
    )
    return plan


def failure_location(error):
    """Up to three project frames as fixed source coordinates, never values."""
    frames = []
    for frame in traceback.extract_tb(error.__traceback__):
        path = Path(frame.filename)
        if path.parent.name in {"enterprise", "bridge"} and frame.name != "require":
            frames.append({"file": path.name, "line": frame.lineno, "function": frame.name})
    return frames[-3:]


def install(environment):
    temporary = DEPENDENCIES / "install-tmp"
    temporary.mkdir(mode=0o700, exist_ok=False)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "--isolated",
            "install",
            "--no-index",
            "--no-deps",
            "--no-cache-dir",
            "--no-compile",
            "--only-binary=:all:",
            "--require-hashes",
            "--find-links=/wheels",
            "--target=" + str(RUNTIME),
            "-r",
            str(ROOT / "integrations/enterprise/runner-requirements.lock"),
        ],
        env={**environment, "TMPDIR": str(temporary)},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=120,
    )
    (OUTPUT / "install.log").write_bytes(result.stdout + result.stderr)
    require(result.returncode == 0, "dependency_install")


def command(name, *arguments):
    """Run a real management command; retain only its fixed status lines."""
    from django.core.management import call_command

    output, errors = io.StringIO(), io.StringIO()
    with redirect_stdout(output), redirect_stderr(errors):
        call_command(name, *arguments, stdout=output, stderr=errors)
    lines = [line for line in output.getvalue().splitlines() if line]
    require(len(lines) <= 8 and all(len(line) <= 300 for line in lines), "command_output")
    return lines


def restored_archive(plan):
    """Every retained console row exists exactly once, unchanged, and nothing else."""
    from bridge.contract import canonical, timestamp
    from bridge.models import Event, Investigation

    directory = ROOT / "var/enterprise/runs" / plan["source_run"]
    raw = (directory / "evidence/console-events.json").read_bytes()
    require(hashlib.sha256(raw).hexdigest() == plan["console_events_sha256"], "archive_hash")
    retained = json.loads(raw)
    require(set(retained) == {"events", "cases"}, "archive_shape")
    require(Event.objects.count() == len(retained["events"]), "event_count")
    for row in retained["events"]:
        event = Event.objects.select_related("integration").get(
            integration__slug=row["app"], event_id=row["event_id"]
        )
        require(
            event.digest == row["digest"]
            and event.source == row["source"]
            and event.state == row["state"]
            and event.processed_by == row["processed_by"]
            and event.processing_attempts == row["processing_attempts"]
            and event.processed_at == timestamp(row["processed_at"])
            and canonical(event.payload) == canonical(row["payload"]),
            "event_restored_exactly",
        )
    require(Investigation.objects.count() == len(retained["cases"]), "case_count")
    for row in retained["cases"]:
        case = Investigation.objects.select_related("integration").get(pk=row["case_id"])
        require(
            case.integration.slug == row["app"]
            and (case.rule, case.severity, case.status, case.version)
            == (row["rule"], row["severity"], row["status"], row["version"])
            and {str(value) for value in case.events.values_list("event_id", flat=True)}
            == set(row["evidence_event_ids"]),
            "case_restored_exactly",
        )
    require(not Event.objects.filter(state="pending").exists(), "pending_after_restore")
    return {
        "events": len(retained["events"]),
        "cases": len(retained["cases"]),
        "archive_sha256": plan["console_events_sha256"],
    }


def account(name, memberships):
    from django.contrib.auth import get_user_model

    from bridge.models import Integration, Membership

    user = get_user_model().objects.create_user(username="restoration-" + name, password=None)
    for slug, role in memberships.items():
        Membership.objects.create(
            user=user, integration=Integration.objects.get(slug=slug), role=role
        )
    return user


def access_workflow(plan):
    """Investigation to verified fix on the restored native case, with real imports."""
    from django.db import transaction
    from django.test import Client

    from bridge.case_workflow import operate
    from bridge.models import CaseTask, CaseVerification, CheckRun, Investigation, Membership
    from bridge.reference_retest import load_native_retest
    from bridge.services import WorkflowError
    from bridge.wazuh_native_review import case_receipt_card, import_native_review

    retest = load_native_retest(ROOT, plan["source_run"])
    case = Investigation.objects.get(pk=retest["case_id"])
    analyst = account("analyst", {"documents": "analyst"})
    reviewer = account("reviewer", {"documents": "reviewer"})
    membership = Membership.objects.get(user=analyst, integration=case.integration)

    def step(user, operation, values=None):
        # The console's write paths authorize inside the caller's transaction.
        with transaction.atomic():
            current = Investigation.objects.get(pk=case.pk)
            return operate(user, case.pk, current.version, operation, values or {})

    step(analyst, "acknowledge")
    step(analyst, "assign", {"assignee": str(membership.pk)})
    step(
        analyst,
        "task",
        {"kind": "remediation", "title": "Restore the membership check on document reads"},
    )
    task = CaseTask.objects.get(investigation=case, kind="remediation")
    for state in ("in_progress", "awaiting_retest"):
        step(analyst, "task_state", {"task_id": str(task.pk), "status": state})
    imported = command(
        "import_reference_retest", "--run-id", plan["source_run"], "--local-database-operator"
    )
    repeated = command(
        "import_reference_retest", "--run-id", plan["source_run"], "--local-database-operator"
    )
    runs = CheckRun.objects.filter(integration=case.integration, result__run_id=plan["source_run"])
    require(runs.count() == 1, "retest_import_once")
    step(analyst, "submit_retest", {"task_id": str(task.pk), "check_run_id": str(runs.get().pk)})
    verification = CaseVerification.objects.get(task=task)
    denied = False
    try:
        step(
            analyst,
            "review_retest",
            {
                "verification_id": str(verification.pk),
                "decision": "approved",
                "rationale": "Submitter must not approve their own retest.",
            },
        )
    except (WorkflowError, PermissionError, ValueError):
        denied = True
    require(denied and CaseVerification.objects.get(pk=verification.pk).status == "pending")
    step(
        reviewer,
        "review_retest",
        {
            "verification_id": str(verification.pk),
            "decision": "approved",
            "rationale": "Native retest denies the removed member and keeps owner access.",
        },
    )
    verification.refresh_from_db()
    task.refresh_from_db()
    require(verification.status == "approved" and task.status == "verified", "review_outcome")
    # The Wazuh loader checks each published input's Windows file identity, which
    # no Linux mount preserves, so the host ran it and pinned the scope's hash.
    raw = TOOL_SCOPE.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == plan["tool_scope_sha256"], "tool_scope_hash")
    scope = json.loads(raw)
    require(scope.get("app") == "documents" and scope.get("run_id") == plan["tool_run"])
    _, created, links = import_native_review(analyst, scope)
    _, wazuh_repeat, _ = import_native_review(analyst, scope)
    require(created and not wazuh_repeat and not links["conflicting_events"], "wazuh_import_once")
    card = case_receipt_card(Investigation.objects.get(pk=case.pk))
    require(card is not None and card["verified"], "wazuh_case_link")
    client = Client()
    client.force_login(reviewer)
    page = client.get("/investigations/" + str(case.pk) + "/")
    require(page.status_code == 200, "case_page")
    return {
        "case_id": str(case.pk),
        "case_operations": [
            "acknowledge",
            "assign",
            "task",
            "task_state",
            "task_state",
            "submit_retest",
            "review_retest",
        ],
        "retest_import_lines": imported,
        "retest_repeat_lines": repeated,
        "retest_check_runs": 1,
        "self_review_denied": True,
        "independent_review": "approved",
        "task_status": "verified",
        "wazuh_import": {
            "matched_events": links["matched_events"],
            "unmatched_events": links["unmatched_events"],
            "linked_cases": len(links["cases"]),
            "repeat_created": False,
        },
        "wazuh_case_linked": True,
        "case_page_status": 200,
    }


def header_workflow(plan):
    """Real scoped ZAP import against the events of its own restored source console."""
    from bridge.models import Audit, CheckRun

    analyst = account("analyst", {"documents": "analyst", "expenses": "analyst"})
    imported = command(
        "import_zap_enterprise", "--run-id", plan["tool_run"], "--user-id", str(analyst.pk)
    )
    repeated = command(
        "import_zap_enterprise", "--run-id", plan["tool_run"], "--user-id", str(analyst.pk)
    )
    runs = {
        run.integration.slug: run
        for run in CheckRun.objects.select_related("integration").filter(
            result__evidence_kind="native_authenticated_header_review",
            result__run_id=plan["tool_run"],
        )
    }
    require(set(runs) == {"documents", "expenses"}, "zap_scopes")
    require(
        runs["documents"].result["finding"]["plugin_id"] == "10021"
        and runs["expenses"].result["finding"] is None
        and [len(runs[app].result["event_bindings"]) for app in ("documents", "expenses")]
        == [6, 2],
        "zap_scoped_results",
    )
    require(Audit.objects.filter(action="zap_native.imported").count() == 2, "zap_audit")
    return {
        "zap_import_lines": imported,
        "zap_repeat_lines": repeated,
        "scoped_check_runs": 2,
        "documents_finding_plugin": "10021",
        "expenses_finding": None,
        "event_bindings": {"documents": 6, "expenses": 2},
    }


def main():
    receipt = {"schema_version": 1, "passed": False, "phase": "await_gate"}
    plan = None
    try:
        require(sys.platform == "linux" and sys.version_info[:2] == (3, 14), "runtime")
        require(os.getuid() == 10001 and os.getgid() == 10001, "runtime_user")
        plan = load_plan(PLAN.read_bytes())
        require(plan["run_id"] == os.environ.get("SB_RESTORE_RUN"), "plan_run")
        receipt.update(run_id=plan["run_id"], profile=plan["profile"])
        gate, deadline = OUTPUT / "allow-restoration.json", time.monotonic() + 240
        while not gate.exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        require(
            gate.is_file()
            and json.loads(gate.read_bytes())
            == {"run_id": plan["run_id"], "runtime_verified": True, "restored": True},
            "host_gate",
        )
        receipt["phase"] = "dependencies"
        environment = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        install(environment)
        sys.path.insert(0, str(RUNTIME))
        os.environ.update(
            DJANGO_SETTINGS_MODULE="integrations.enterprise.restoration_settings",
            SB_SECRET_KEY=secrets.token_urlsafe(64),
        )
        import django

        django.setup()
        from django.db import connection
        from django.db.migrations.executor import MigrationExecutor

        receipt["phase"] = "restored_identity"
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database(), current_user")
            require(cursor.fetchone() == ("sb_enterprise_access", "sb_restored_console"))
            cursor.execute(
                "SELECT rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname=current_user"
            )
            require(cursor.fetchone() == (False, False, False), "least_privilege")
        receipt["phase"] = "restored_rows_before_migration"
        receipt["restored"] = restored_archive(plan)
        executor = MigrationExecutor(connection)
        pending = executor.migration_plan(executor.loader.graph.leaf_nodes())
        receipt["pending_migrations"] = [f"{m.app_label}.{m.name}" for m, _ in pending]
        receipt["phase"] = "migrate"
        command("migrate", "--noinput", "--verbosity", "0")
        executor = MigrationExecutor(connection)
        require(not executor.migration_plan(executor.loader.graph.leaf_nodes()), "migrated")
        receipt["phase"] = "restored_rows_after_migration"
        require(restored_archive(plan) == receipt["restored"], "rows_after_migration")
        receipt["phase"] = plan["profile"] + "_workflow"
        receipt["workflow"] = (access_workflow if plan["profile"] == "access" else header_workflow)(
            plan
        )
        receipt.update(passed=True, phase="complete")
    except Exception as error:
        receipt["error_class"] = type(error).__name__
        receipt["error_code"] = str(error) if isinstance(error, RestorationError) else None
        receipt["failure_location"] = failure_location(error)
    finally:
        raw = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("ascii")
        if len(raw) <= 65536:
            (OUTPUT / "restoration-runner.json").write_bytes(raw)
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
