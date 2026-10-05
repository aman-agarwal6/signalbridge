import hashlib
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Case, Count, F, IntegerField, Prefetch, Q, Value, When, Window
from django.db.models.functions import RowNumber, TruncDate
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .access_coverage import coverage_for_run
from .case_verification import console_context as verification_context
from .contract import digest
from .detection_catalog import RULES, engine_fingerprint, engine_source_state, explain_case
from .evaluation import evaluate
from .lab_presentation import describe_scenario
from .models import (
    Audit,
    CheckRun,
    Event,
    Investigation,
    LoginAttempt,
    Membership,
    Note,
    Replay,
    WazuhRecord,
)
from .operations import event_summary, workspace_health
from .presentation import case_preview_events, decorate_cases, event_filters, page_context
from .runtime_identity import workspace_id
from .services import WorkflowError, create_replay, decide_replay, write_membership
from .soc_delivery import status as delivery_status
from .soc_presentation import pilot_cards
from .wazuh_backfill_presentation import backfill_card
from .wazuh_import import status as enterprise_wazuh_status
from .wazuh_native_review import case_receipt_card
from .wazuh_native_review import receipt_card as native_wazuh_card
from .wazuh_native_review import with_admission as native_wazuh_admission
from .worker_health import worker_health
from .zap_repeat_presentation import repeat_cards


def sign_in(request):
    if request.user.is_authenticated:
        return redirect("/")
    error = ""
    if request.method == "POST":
        username = request.POST.get("username", "")[:150]
        fingerprint = hashlib.sha256(
            (request.META.get("REMOTE_ADDR", "") + "|" + username.casefold()).encode()
        ).hexdigest()
        now = timezone.now()
        with transaction.atomic():
            attempt, _ = LoginAttempt.objects.select_for_update().get_or_create(
                fingerprint=fingerprint, defaults={"window_start": now}
            )
            if attempt.window_start < now - timedelta(minutes=15):
                attempt.window_start = now
                attempt.failures = 0
            if attempt.failures >= 8:
                error = "Too many attempts. Try again in 15 minutes."
            else:
                user = authenticate(
                    request,
                    username=username,
                    password=request.POST.get("password", "")[:1024],
                )
                if user:
                    attempt.failures = 0
                    login(request, user)
                    attempt.save()
                    return redirect("/")
                attempt.failures += 1
                error = "Sign-in failed. Check your credentials."
            attempt.save()
    return render(request, "login.html", {"error": error})


def scope(request, *, app_id=None):
    memberships = list(
        Membership.objects.filter(user=request.user)
        .select_related("integration")
        .order_by("integration__name", "integration__id")
    )
    slug = request.GET.get("app")
    if app_id is not None:
        selected = next((item for item in memberships if item.integration_id == app_id), None)
    elif slug:
        selected = next((item for item in memberships if item.integration.slug == slug), None)
    else:
        selected = memberships[0] if memberships else None
    if selected is None:
        raise Http404("No app membership.")
    available = [membership.integration for membership in memberships]
    current, role = selected.integration, selected.role
    return {
        "apps": available,
        "lab_app": next((app for app in available if app.slug == "signalbridge"), None),
        "app": current,
        "role": role,
        "can_write": role in ("analyst", "reviewer"),
        "snapshot_at": timezone.now(),
        "nav_open_count": Investigation.objects.filter(integration=current, status="open").count(),
    }


@login_required
def overview(request):
    ctx = scope(request)
    if ctx["app"].slug == "signalbridge":
        return redirect("/findings/?app=signalbridge")
    app = ctx["app"]
    events = Event.objects.filter(integration=app)
    cases = Investigation.objects.filter(integration=app)
    now = timezone.now()
    today = now.date()
    daily = {
        row["day"]: row["total"]
        for row in events.filter(
            occurred_at__date__gte=today - timedelta(days=6), occurred_at__lte=now
        )
        .annotate(day=TruncDate("occurred_at"))
        .values("day")
        .annotate(total=Count("id"))
    }
    peak = max(daily.values(), default=0) or 1
    activity = []
    for index in range(7):
        day = today - timedelta(days=6 - index)
        count = daily.get(day, 0)
        height = round(count / peak * 116, 2)
        activity.append(
            {"date": day, "count": count, "x": 34 + index * 68, "height": height, "y": 140 - height}
        )
    totals = event_summary(events)
    case_totals = cases.aggregate(
        open=Count("pk", filter=Q(status="open")),
        critical=Count("pk", filter=Q(status="open", severity="critical")),
        resolved=Count("pk", filter=Q(status="resolved")),
    )
    workers = worker_health(now)
    latest_run = (
        CheckRun.objects.filter(integration=app)
        .exclude(
            result__evidence_kind__isnull=False,
            result__evidence_kind__in=(
                "wazuh_backfill",
                "zap_repeat",
                "native_wazuh_reference_bootstrap",
            ),
        )
        .order_by("-created_at")
        .first()
    )
    priority_cases = (
        cases.filter(status="open")
        .annotate(
            priority=Case(
                When(severity="critical", then=Value(0)),
                When(severity="high", then=Value(1)),
                default=Value(2),
                output_field=IntegerField(),
            ),
            evidence_count=Count("events", filter=Q(events__integration=app)),
        )
        .prefetch_related(
            Prefetch("events", queryset=case_preview_events(app), to_attr="preview_events")
        )
        .order_by("priority", "-created_at", "id")[:5]
    )
    ctx.update(
        page="overview",
        event_count=totals["accepted"],
        case_count=case_totals["open"],
        processed_count=totals["processed"],
        pending_count=totals["pending"],
        dead_count=totals["dead"],
        cases=decorate_cases(priority_cases, app),
        critical_count=case_totals["critical"],
        resolved_count=case_totals["resolved"],
        latest_run=latest_run,
        passed_checks=sum(c.get("status") == "passed" for c in latest_run.result.get("checks", []))
        if latest_run
        else 0,
        worker_health=workers,
        worker_recent=workers["all_recent"],
        activity=activity,
        activity_total=sum(daily.values()),
        source_counts=[
            {"value": value, "label": label, "count": totals["sources"].get(value, 0)}
            for value, label in Event._meta.get_field("source").choices
        ],
        outcomes=[
            {"value": value, "count": totals["outcomes"].get(value, 0)}
            for value in ("allowed", "denied", "not_visible", "error")
        ],
        recent_events=events.only(
            "id", "event_id", "occurred_at", "operation", "outcome", "source"
        ).order_by("-occurred_at")[:7],
    )
    return render(request, "overview.html", ctx)


@login_required
def integrations(request):
    ctx = scope(request)
    app = ctx["app"]
    enterprise_wazuh = (
        enterprise_wazuh_status(app)
        if app.slug in {"bettail", "netted", "documents", "expenses"}
        else None
    )
    queue = (
        enterprise_wazuh
        if enterprise_wazuh is not None
        else Event.objects.filter(integration=app).aggregate(
            pending=Count("pk", filter=Q(state="pending")),
            dead=Count("pk", filter=Q(state="dead")),
        )
    )
    latest_receipts = {
        run.result["evidence_kind"]: run
        for run in native_wazuh_admission(
            CheckRun.objects.filter(
                integration=app,
                result__evidence_kind__in=(
                    "supabase_http",
                    "wazuh_backfill",
                    "native_wazuh_reference_bootstrap",
                ),
            )
        )
        .annotate(
            evidence_rank=Window(
                expression=RowNumber(),
                partition_by=[F("result__evidence_kind")],
                order_by=[F("created_at").desc(), F("id").desc()],
            )
        )
        .filter(evidence_rank=1)
    }
    ctx.update(pilot_cards(app))
    ctx["wazuh_backfill"] = backfill_card(app, latest_receipts.get("wazuh_backfill"))
    ctx["native_wazuh"] = (
        native_wazuh_card(
            app,
            latest_receipts.get("native_wazuh_reference_bootstrap"),
            lookup=False,
            summary_only=True,
        )
        if app.slug in {"documents", "expenses"}
        else None
    )
    if enterprise_wazuh is not None and ctx["native_wazuh"] and ctx["native_wazuh"]["verified"]:
        enterprise_wazuh["connection_state"] = (
            "Historical native run verified; current connection unverified"
        )
    ctx["zap_repeats"] = repeat_cards(app)
    ctx.update(
        page="integrations",
        pending_count=queue["pending"],
        dead_count=queue["dead"],
        health={"latest_http": latest_receipts.get("supabase_http")},
        delivery=delivery_status(app)
        if app.slug in {"bettail", "netted", "documents", "expenses"}
        else None,
        enterprise_wazuh=enterprise_wazuh,
    )
    return render(request, "integrations.html", ctx)


@login_required
def detection_coverage(request):
    ctx = scope(request)
    counts = {
        row["rule"]: row["total"]
        for row in Investigation.objects.filter(integration=ctx["app"])
        .values("rule")
        .annotate(total=Count("pk"))
    }
    ctx.update(
        page="detections",
        rules=[dict(rule, case_count=counts.get(key, 0)) for key, rule in RULES.items()],
        current_engine=engine_fingerprint(),
        current_engine_state=engine_source_state(),
        health=workspace_health(ctx["app"]),
    )
    return render(request, "detections.html", ctx)


@login_required
def capability_lab(request):
    ctx = scope(request)
    if ctx["app"].slug != "signalbridge":
        raise Http404("The capability lab belongs to the SignalBridge workspace.")
    runs = CheckRun.objects.filter(
        integration=ctx["app"], result__evidence_kind="offline_simulation"
    ).order_by("-created_at", "-id")
    selected = request.GET.get("run")
    try:
        run = get_object_or_404(runs, pk=selected) if selected else runs.first()
    except (ValidationError, ValueError):
        raise Http404("Unknown capability run.") from None
    simulation = run.result["simulation"] if run else None
    quality = simulation["detection_quality"] if simulation else {}
    positive_count = quality.get("true_positive_scenarios", 0) + quality.get(
        "false_negative_scenarios", 0
    )
    ctx.update(
        page="lab",
        run=run,
        runs=runs.only("id", "created_at", "status", "revision")[:20],
        simulation=simulation,
        quality=quality,
        positive_count=positive_count,
        recall_percent=round(100 * quality["recall"]) if positive_count else None,
        scenarios=[describe_scenario(row) for row in simulation["scenarios"]] if simulation else [],
    )
    return render(request, "capability_lab.html", ctx)


@login_required
def simulation_export(request, run_id):
    run = get_object_or_404(
        CheckRun,
        pk=run_id,
        integration__slug="signalbridge",
        integration__membership__user=request.user,
        result__evidence_kind="offline_simulation",
    )
    report = {
        "schema_version": 1,
        "kind": "signalbridge-capability-evidence-export",
        "run": str(run.id),
        "status": run.status,
        "revision": run.revision,
        "report_sha256": run.digest,
        "imported_at": run.created_at.isoformat(),
        "result": run.result,
    }
    report["export_sha256"] = digest(report)
    response = JsonResponse(report, json_dumps_params={"indent": 2})
    response["Content-Disposition"] = f'attachment; filename="signalbridge-lab-{run.id}.json"'
    return response


@login_required
def investigations(request):
    ctx = scope(request)
    cases = Investigation.objects.filter(integration=ctx["app"]).select_related(
        "assignee__user", "acknowledged_by"
    )
    counts = dict(cases.values_list("status").annotate(total=Count("id")))
    status = request.GET.get("status", "")
    status = status if status in ("open", "resolved", "false_positive") else ""
    severity = request.GET.get("severity", "")
    severity = severity if severity in ("critical", "high", "medium") else ""
    rule = request.GET.get("rule", "")
    rule = rule if rule in RULES else ""
    query = request.GET.get("q", "").strip()[:120]
    queue = request.GET.get("queue", "")
    queue = queue if queue in ("mine", "unassigned", "unacknowledged", "overdue") else ""
    now = timezone.now()
    if queue == "mine":
        cases = cases.filter(assignee__user=request.user, assignee__integration=ctx["app"])
    elif queue == "unassigned":
        cases = cases.filter(status="open", assignee__isnull=True)
    elif queue == "unacknowledged":
        cases = cases.filter(status="open", acknowledged_at__isnull=True)
    elif queue == "overdue":
        cases = cases.filter(status="open", due_at__lt=now)
    if status:
        cases = cases.filter(status=status)
    if severity:
        cases = cases.filter(severity=severity)
    if rule:
        cases = cases.filter(rule=rule)
    if query:
        cases = cases.filter(
            Q(title__icontains=query) | Q(explanation__icontains=query) | Q(id__icontains=query)
        )
    sort = request.GET.get("sort", "priority")
    sort = sort if sort in ("priority", "newest", "oldest") else "priority"
    cases = cases.annotate(
        evidence_count=Count("events", filter=Q(events__integration=ctx["app"])),
        priority=Case(
            When(severity="critical", then=Value(0)),
            When(severity="high", then=Value(1)),
            default=Value(2),
            output_field=IntegerField(),
        ),
    ).prefetch_related(
        Prefetch("events", queryset=case_preview_events(ctx["app"]), to_attr="preview_events")
    )
    ordering = {
        "priority": ("priority", "-created_at", "id"),
        "newest": ("-created_at", "id"),
        "oldest": ("created_at", "id"),
    }
    pagination = Paginator(cases.order_by(*ordering[sort]), 20).get_page(request.GET.get("p"))
    ctx.update(page_context(pagination))
    ctx.update(
        page="investigations",
        cases=decorate_cases(pagination.object_list, ctx["app"]),
        selected_status=status,
        selected_severity=severity,
        selected_rule=rule,
        selected_queue=queue,
        queue_now=now,
        selected_sort=sort,
        query=query,
        status_counts=counts,
        total_cases=sum(counts.values()),
    )
    return render(request, "investigations.html", ctx)


@login_required
def events(request):
    ctx = scope(request)
    records = Event.objects.filter(integration=ctx["app"])
    filtered, filters = event_filters(records, request.GET)
    filtered = filtered.prefetch_related(
        Prefetch(
            "investigation_set",
            queryset=Investigation.objects.filter(integration=ctx["app"]).order_by("created_at"),
        )
    )
    pagination = Paginator(filtered.order_by("-occurred_at", "id"), 25).get_page(
        request.GET.get("p")
    )
    ctx.update(page_context(pagination))
    ctx.update(
        page="events",
        events=pagination.object_list,
        filters=filters,
        total_events=records.count(),
        source_choices=Event._meta.get_field("source").choices,
    )
    return render(request, "events.html", ctx)


@login_required
def investigation(request, case_id):
    case = get_object_or_404(
        Investigation.objects.select_related("integration", "assignee__user", "acknowledged_by"),
        id=case_id,
        integration__membership__user=request.user,
    )
    ctx = scope(request, app_id=case.integration_id)
    if request.method == "POST":
        if not ctx["can_write"]:
            return HttpResponse("Analyst role required.", status=403)
        action = request.POST.get("action")
        try:
            version = int(request.POST.get("version", "0"))
            with transaction.atomic():
                write_membership(request.user, case.integration)
                locked = (
                    Investigation.objects.select_for_update()
                    .filter(pk=case.pk, integration_id=case.integration_id)
                    .first()
                )
                if locked is None:
                    raise PermissionError()
                if locked.version != version:
                    raise WorkflowError("Case changed. Reload before saving.")
                if action == "note":
                    note = request.POST.get("note", "").strip()
                    kind = request.POST.get("kind", "general")
                    if not 1 <= len(note) <= 2000:
                        raise WorkflowError("Write a note between 1 and 2,000 characters.")
                    if kind not in dict(Note._meta.get_field("kind").choices):
                        raise WorkflowError("Choose a valid note category.")
                    Note.objects.create(
                        investigation=locked, author=request.user, text=note, kind=kind
                    )
                    detail = {"note_added": True}
                elif action == "disposition":
                    status = request.POST.get("status", "")
                    if status not in ("open", "resolved", "false_positive"):
                        raise WorkflowError("Invalid disposition.")
                    rationale = request.POST.get("rationale", "").strip()
                    if not 10 <= len(rationale) <= 2000:
                        raise WorkflowError("Explain the disposition in 10 to 2,000 characters.")
                    previous = locked.status
                    locked.status = status
                    detail = {"status": status, "previous_status": previous, "rationale": rationale}
                    bindings = list(
                        locked.events.filter(integration=case.integration)
                        .order_by("event_id")
                        .values_list("event_id", "digest")
                    )
                    detail["evidence_sha256"] = digest(
                        [[str(identifier), checksum] for identifier, checksum in bindings]
                    )
                    detail["event_count"] = len(bindings)
                    detail["current_engine_sha256"] = engine_fingerprint()
                    detail["engine_source_state"] = engine_source_state()
                    Note.objects.create(investigation=locked, author=request.user, text=rationale)
                else:
                    raise WorkflowError("Invalid action.")
                count = Investigation.objects.filter(pk=locked.pk, version=version).update(
                    status=locked.status, version=F("version") + 1
                )
                if count != 1:
                    raise WorkflowError("Case changed. Reload before saving.")
                Audit.objects.create(
                    integration=case.integration,
                    actor=request.user,
                    action="case." + action,
                    object_id=str(case.pk),
                    detail=detail,
                )
        except PermissionError:
            return HttpResponse("Your current role does not allow this action.", status=403)
        except (WorkflowError, ValueError) as e:
            messages.error(request, str(e))
        return redirect("case", case_id=case.pk)
    linked = list(
        case.events.filter(integration=case.integration).order_by("occurred_at", "id")[:501]
    )
    truncated = len(linked) > 500
    analysis = explain_case(case, linked[:500], evidence_complete=not truncated)
    if truncated:
        analysis.update(
            comparison="First 500 records shown; full case was not evaluated", current_match=False
        )
    ctx.update(
        page="investigations",
        case=case,
        events=linked[:500],
        analysis=analysis,
        evidence_truncated=truncated,
        notes=case.note_set.select_related("author").order_by("created_at"),
        audits=Audit.objects.filter(integration=case.integration, object_id=str(case.pk))
        .select_related("actor")
        .order_by("-created_at")[:20],
        eligible_assignees=Membership.objects.select_related("user")
        .filter(
            integration=case.integration,
            user__is_active=True,
            role__in=("analyst", "reviewer"),
        )
        .order_by("user__username", "pk")[:100],
        **verification_context(case),
        case_wazuh_records=WazuhRecord.objects.filter(integration=case.integration)
        .filter(Q(event__investigation=case) | Q(signal__investigation=case))
        .select_related("signal", "event")
        .distinct()
        .order_by("-occurred_at", "pk")[:20],
        case_native_wazuh=case_receipt_card(case),
        leaver_signals=case.leaver_signals.order_by("event_at", "jti")[:50],
    )
    return render(request, "case.html", ctx)


@login_required
def case_export(request, case_id):
    case = get_object_or_404(Investigation, id=case_id, integration__membership__user=request.user)
    events = list(
        case.events.filter(integration=case.integration).order_by("occurred_at", "id")[:1001]
    )
    if len(events) > 1000:
        return JsonResponse(
            {"error": "This case exceeds the 1,000-record export limit; use scoped event review."},
            status=413,
        )
    report = {
        "schema_version": 1,
        "kind": "signalbridge-case-evidence",
        "application": case.integration.slug,
        "generated_at": timezone.now().isoformat(),
        "case_id": str(case.pk),
        "version": case.version,
        "rule": case.rule,
        "status": case.status,
        "priority": case.severity,
        "correlation": case.correlation,
        "analysis": explain_case(case, events),
        "events": [
            {
                "event_id": str(e.event_id),
                "source": e.source,
                "received_at": e.received_at.isoformat(),
                "payload": e.payload,
                "payload_sha256": e.digest,
            }
            for e in events
        ],
        "limits": [
            "Metadata-only source observations; no independent attestation or production-incident claim.",
            "Analyst free-text notes are excluded from this portable export; inspect them in the authenticated console.",
        ],
    }
    checksum = digest(report)
    Audit.objects.create(
        integration=case.integration,
        actor=request.user,
        action="case.exported",
        object_id=str(case.pk),
        detail={"report_sha256": checksum, "case_version": case.version},
    )
    response = JsonResponse(
        {"report": report, "report_sha256": checksum}, json_dumps_params={"indent": 2}
    )
    response["Content-Disposition"] = f'attachment; filename="signalbridge-case-{case.pk}.json"'
    return response


@login_required
def checks(request):
    ctx = scope(request)
    if ctx["app"].slug == "signalbridge":
        return redirect("/lab/?app=signalbridge")
    runs = (
        CheckRun.objects.filter(integration=ctx["app"])
        .exclude(
            result__evidence_kind__isnull=False,
            result__evidence_kind__in=(
                "wazuh_backfill",
                "zap_repeat",
                "native_wazuh_reference_bootstrap",
            ),
        )
        .order_by("-created_at", "id")
    )
    pagination = Paginator(runs, 10).get_page(request.GET.get("p"))
    latest = runs.first()
    displayed_runs = list(pagination.object_list)
    for run in displayed_runs:
        run.access_coverage = coverage_for_run(run, ctx["app"].slug)
    ctx.update(page_context(pagination))
    ctx.update(
        page="checks",
        runs=displayed_runs,
        latest_run=latest,
        passed_checks=sum(c.get("status") == "passed" for c in latest.result.get("checks", []))
        if latest
        else 0,
    )
    return render(request, "checks.html", ctx)


@login_required
def replay_lab(request):
    ctx = scope(request)
    if request.method == "POST":
        try:
            if request.POST.get("action") == "create":
                create_replay(request.user, ctx["app"], request.POST.get("policy", ""))
                messages.success(
                    request,
                    "Comparison saved. A separate reviewer can record a decision.",
                )
            else:
                replay = get_object_or_404(
                    Replay, id=request.POST.get("replay"), integration=ctx["app"]
                )
                decide_replay(
                    request.user,
                    replay.pk,
                    request.POST.get("decision", ""),
                    int(request.POST.get("version", "0")),
                )
                messages.success(
                    request,
                    "Review decision recorded. Source-app permissions are unchanged.",
                )
        except PermissionError:
            return HttpResponse("Your role does not allow this action.", status=403)
        except ValidationError:
            messages.error(request, "Invalid proposal identifier.")
        except (ValueError, WorkflowError) as e:
            messages.error(request, str(e))
        return redirect("/replay/?app=" + ctx["app"].slug)
    replay_query = Replay.objects.filter(integration=ctx["app"])
    pagination = Paginator(
        replay_query.select_related("author", "reviewer").order_by("-created_at", "id"), 10
    ).get_page(request.GET.get("p"))
    replays = list(pagination.object_list)
    current = {}
    comparison_unavailable = False
    for policy in {r.policy for r in replays}:
        try:
            current[policy] = evaluate(policy, ctx["app"].slug)
        except ValueError:
            current[policy] = None
            comparison_unavailable = True
    for replay in replays:
        replay.comparison_unavailable = current[replay.policy] is None
        if replay.comparison_unavailable:
            replay.stale = True
        else:
            data_hash, engine_hash, result = current[replay.policy]
            replay.stale = (
                data_hash != replay.dataset_hash
                or engine_hash != replay.engine_hash
                or result != replay.result
            )
        replay.can_approve = (
            replay.result.get("safe", False)
            and not replay.stale
            and replay.author_id != request.user.pk
        )
    ctx.update(page_context(pagination))
    ctx.update(
        page="replay",
        replays=replays,
        comparison_unavailable=comparison_unavailable,
        pending_reviews=replay_query.filter(status="pending").count(),
    )
    return render(request, "replay.html", ctx)


REQUIREMENTS = [
    (
        "SB-01",
        "Private data stays within its intended sharing boundary.",
        "Actual app SQL tests: member/owner, outsider, removal/revocation.",
    ),
    (
        "SB-02",
        "Only authorized senders contribute trusted evidence.",
        "HMAC verification, app binding, schema and freshness tests.",
    ),
    (
        "SB-03",
        "Repeated delivery does not inflate the evidence.",
        "Unique app/event constraint; changed duplicate returns conflict.",
    ),
    (
        "SB-04",
        "A quiet dashboard never implies complete coverage.",
        "Pending/dead queue counts, last delivery, explicit coverage gaps.",
    ),
    (
        "SB-05",
        "Unsafe automation cannot receive approval.",
        "Independent suspicious labels, retention gate, separate reviewer, evidence hashes.",
    ),
    (
        "SB-06",
        "Operators see and change only their assigned apps.",
        "Membership checks on lists, object pages, notes and exports.",
    ),
    (
        "SB-07",
        "Tests must catch a relevant bad change.",
        "Unchanged authorization assertions fail inside a rolled-back test transaction.",
    ),
]


@login_required
def requirements(request):
    ctx = scope(request)
    ctx.update(
        page="requirements",
        requirements=REQUIREMENTS,
        audits=Audit.objects.filter(integration=ctx["app"])
        .select_related("actor")
        .order_by("-created_at")[:30],
    )
    return render(request, "requirements.html", ctx)


def evidence(app):
    events = Event.objects.filter(integration=app)
    totals = event_summary(events)
    check_runs = list(CheckRun.objects.filter(integration=app).order_by("-created_at")[:5])
    return {
        "application": app.slug,
        "generated_at": timezone.now().isoformat(),
        "environment": "local lab",
        "coverage": app.coverage,
        "telemetry_sources": totals["sources"],
        "counts": {
            "accepted_events": totals["accepted"],
            "processed_events": totals["processed"],
            "pending_events": totals["pending"],
            "dead_events": totals["dead"],
            "investigations": Investigation.objects.filter(integration=app).count(),
        },
        "checks": [run.result for run in check_runs],
        "authorization_matrices": [
            matrix for run in check_runs if (matrix := coverage_for_run(run, app.slug))
        ],
        "replays": [
            {
                "id": str(r.pk),
                "status": r.status,
                "dataset_hash": r.dataset_hash,
                "engine_hash": r.engine_hash,
                "result": r.result,
            }
            for r in Replay.objects.filter(integration=app).order_by("-created_at")[:10]
        ],
        "limits": [
            "Synthetic/local lab evidence only.",
            "PGlite claims are supplied by the harness, not validated JWTs.",
            "Imported Supabase evidence is historical local service testing only; hosted instrumentation, signed URLs, continuous Wazuh/Shuffle/ZAP connections and remote CI enforcement remain unverified. Separately recorded synthetic SOC pilots do not assess source applications.",
        ],
    }


@login_required
def export_evidence(request):
    ctx = scope(request)
    Audit.objects.create(
        integration=ctx["app"],
        actor=request.user,
        action="evidence.exported",
        object_id=ctx["app"].slug,
    )
    response = JsonResponse(evidence(ctx["app"]), json_dumps_params={"indent": 2})
    response["Content-Disposition"] = (
        'attachment; filename="signalbridge-' + ctx["app"].slug + '-evidence.json"'
    )
    return response


def health(request):
    return JsonResponse(
        {
            "service": "signalbridge",
            "status": "running",
            "workspace_id": workspace_id(settings.BASE_DIR),
        }
    )
