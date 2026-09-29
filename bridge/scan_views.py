"""Authenticated, application-scoped scanner evidence and review workspaces."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count, Max, Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_http_methods

from .findings import evidence_binding, triage
from .models import Audit, Finding, FindingObservation, ScanRun
from .presentation import page_context
from .scanner_guidance import guidance, observation_guidance, run_guidance
from .services import WorkflowError
from .views import scope


def attach_evidence(records, integration):
    """A fixed number of scoped queries for one paginated view; no source-file reads."""
    records = list(records)
    ids = [item.pk for item in records]
    latest_ids = (
        FindingObservation.objects.filter(finding_id__in=ids, scan_run__integration=integration)
        .values("finding_id")
        .annotate(latest=Max("pk"))
        .values("latest")
    )
    observations = {
        item.finding_id: item
        for item in FindingObservation.objects.filter(pk__in=latest_ids).select_related("scan_run")
    }
    review_ids = (
        Audit.objects.filter(
            integration=integration, action="finding.triaged", object_id__in=[str(pk) for pk in ids]
        )
        .values("object_id")
        .annotate(latest=Max("pk"))
        .values("latest")
    )
    reviews = {item.object_id: item for item in Audit.objects.filter(pk__in=review_ids)}
    for item in records:
        observation = observations.get(item.pk)
        review = reviews.get(str(item.pk))
        binding = review.detail.get("evidence", {}) if review else {}
        current = bool(observation and binding == evidence_binding(observation))
        if review is None:
            label, detail = "Not reviewed", "No disposition has been recorded for this finding."
        elif not binding:
            label = "Earlier review not bound"
            detail = "This earlier review did not record an observation binding. Review the latest evidence before relying on it."
        elif not current:
            label = "New evidence needs review"
            detail = "The recorded decision applies to an earlier observation. Its rationale is preserved; review the newer evidence separately."
        else:
            label = "Latest observation reviewed"
            detail = "The decision matches the latest recorded observation. It does not verify current source files or establish a fix."
        item.guidance = guidance(item)
        item.latest_observation = observation
        item.evidence = observation_guidance(observation)
        item.review = {"label": label, "detail": detail, "current": current, "record": review}
    return records


@login_required
@require_GET
def findings(request):
    ctx = scope(request)
    records = Finding.objects.filter(integration=ctx["app"])
    counts = dict(records.values_list("status").annotate(total=Count("id")))
    tools = list(records.order_by("tool").values_list("tool", flat=True).distinct())
    selected = {
        "status": request.GET.get("status", ""),
        "tool": request.GET.get("tool", ""),
        "q": request.GET.get("q", "").strip()[:120],
    }
    if selected["status"] not in ("open", "reviewed", "accepted_risk", "false_positive"):
        selected["status"] = ""
    if selected["tool"] not in tools:
        selected["tool"] = ""
    for name in ("status", "tool"):
        if selected[name]:
            records = records.filter(**{name: selected[name]})
    if selected["q"]:
        records = records.filter(
            Q(rule_id__icontains=selected["q"])
            | Q(path__icontains=selected["q"])
            | Q(package__icontains=selected["q"])
            | Q(title__icontains=selected["q"])
        )
    pagination = Paginator(records.order_by("-last_seen", "id"), 20).get_page(request.GET.get("p"))
    pagination.object_list = attach_evidence(pagination.object_list, ctx["app"])
    runs = ScanRun.objects.filter(integration=ctx["app"])
    ctx.update(page_context(pagination))
    ctx.update(
        page="findings",
        findings=pagination.object_list,
        filters=selected,
        tools=tools,
        open_count=counts.get("open", 0),
        reviewed_count=sum(v for k, v in counts.items() if k != "open"),
        total_count=sum(counts.values()),
        run_count=runs.count(),
        latest_run=runs.order_by("-created_at").first(),
    )
    return render(request, "findings.html", ctx)


@login_required
@require_http_methods(["GET", "POST"])
def finding(request, finding_id):
    ctx = scope(request)
    record = get_object_or_404(Finding, pk=finding_id, integration=ctx["app"])
    record.guidance = guidance(record)
    if request.method == "POST":
        try:
            triage(
                request.user,
                record.pk,
                request.POST.get("status", ""),
                int(request.POST.get("version", "0")),
                request.POST.get("rationale", ""),
            )
        except PermissionError:
            return HttpResponse("Your role does not allow this action.", status=403)
        except (ValueError, WorkflowError) as error:
            messages.error(request, str(error))
        else:
            messages.success(request, "Review recorded. Scanner evidence is preserved.")
        return redirect(f"/findings/{record.pk}/?app={ctx['app'].slug}")
    attach_evidence([record], ctx["app"])
    observations = (
        FindingObservation.objects.filter(finding=record, scan_run__integration=ctx["app"])
        .select_related("scan_run")
        .order_by("-pk")
    )
    latest_run = (
        ScanRun.objects.filter(integration=ctx["app"], tool=record.tool)
        .order_by("-created_at", "-pk")
        .first()
    )
    shown_observations = list(observations[:20])
    for observation in shown_observations:
        observation.evidence = observation_guidance(observation)
    ctx.update(
        page="findings",
        finding=record,
        observations=shown_observations,
        newer_report=bool(
            latest_run
            and record.latest_observation
            and latest_run.pk != record.latest_observation.scan_run_id
        ),
        history=Audit.objects.filter(
            integration=ctx["app"], object_id=str(record.pk), action="finding.triaged"
        )
        .select_related("actor")
        .order_by("-created_at")[:30],
    )
    return render(request, "finding.html", ctx)


@login_required
@require_GET
def scan_runs(request):
    ctx = scope(request)
    runs = (
        ScanRun.objects.filter(integration=ctx["app"])
        .select_related("imported_by")
        .order_by("-created_at", "id")
    )
    pagination = Paginator(runs, 10).get_page(request.GET.get("p"))
    for run in pagination.object_list:
        run.guidance = run_guidance(run)
    ctx.update(page_context(pagination))
    ctx.update(page="findings", runs=pagination.object_list)
    return render(request, "scan_runs.html", ctx)


@login_required
@require_GET
def scan_export(request, run_id):
    ctx = scope(request)
    run = get_object_or_404(ScanRun, pk=run_id, integration=ctx["app"])
    observations = FindingObservation.objects.filter(scan_run=run, finding__integration=ctx["app"])
    data = {
        "application": ctx["app"].slug,
        "run": str(run.pk),
        "tool": run.tool,
        "tool_version": run.tool_version,
        "report_digest": run.digest,
        "source_revision": run.source_revision,
        "manifest": run.manifest,
        "provenance": run.provenance,
        "execution": run.execution,
        "coverage_status": run.coverage_status,
        "input_count": run.input_count,
        "skipped_count": run.skipped_count,
        "suppressed_count": run.suppressed_count,
        "finding_count": run.finding_count,
        "scope_explanation": run_guidance(run),
        "imported_at": run.created_at.isoformat(),
        "findings": [o.snapshot for o in observations],
        "limits": [
            "Scanner reports are observations, not proof of exploitability.",
            "Imported reports are untrusted claims. Only the fixed local runner records execution.",
            "A missing finding in a later report does not prove a correction.",
            "Reported levels are not vulnerability severity or analyst confidence.",
            "Source hashes describe recorded inputs; current checkout contents were not compared by this export.",
        ],
    }
    Audit.objects.create(
        integration=ctx["app"], actor=request.user, action="scan.exported", object_id=str(run.pk)
    )
    response = JsonResponse(data, json_dumps_params={"indent": 2})
    response["Content-Disposition"] = (
        f'attachment; filename="signalbridge-{ctx["app"].slug}-{run.pk}.json"'
    )
    return response
