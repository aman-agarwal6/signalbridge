"""Training-only screens; evidence and answer keys stay server-side until needed."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.views.decorators.http import require_GET, require_http_methods

from . import practice, recorded_practice
from .models import PracticeSession
from .practice_catalog import ASSESSMENTS, CATALOG, CONFIDENCE, NEXT_ACTIONS, PRIORITIES, digest
from .views import scope


def valid_post(request, allowed, multiple=()):
    return all(
        key in {*allowed, "csrfmiddlewaretoken"} and (key in multiple or len(values) == 1)
        for key, values in request.POST.lists()
    )


@login_required
@require_http_methods(["GET", "POST"])
def index(request):
    ctx = scope(request)
    if request.method == "POST":
        if not valid_post(request, {"scenario"}):
            return HttpResponse("Invalid practice request.", status=400)
        try:
            record = practice.start(request.user, ctx["app"], request.POST.get("scenario", ""))
        except PermissionError as error:
            return HttpResponse(str(error), status=403)
        except practice.PracticeError as error:
            messages.error(request, str(error))
        else:
            return redirect(f"/practice/{record.pk}/?app={ctx['app'].slug}")
    records = PracticeSession.objects.filter(author=request.user, integration=ctx["app"]).order_by(
        "-created_at", "-pk"
    )
    page = Paginator(records, 20).get_page(request.GET.get("p"))
    # Do not send unrevealed evidence or answer keys to the template/context.
    attempts = [
        {"id": r.pk, "title": r.snapshot["title"], "created_at": r.created_at, "status": r.status}
        for r in page
    ]
    ctx.update(
        page="practice",
        exercises=[
            {
                "key": k,
                "title": v["title"],
                "focus": v["focus"],
                "brief": v["brief"],
                "fictional": True,
            }
            for k, v in CATALOG.items()
        ],
        recorded_exercises=[
            {"key": k, **v}
            for k, v in recorded_practice.ASSIGNMENTS.items()
            if v["workspace"] == ctx["app"].slug
        ],
        attempts=attempts,
        pagination=page,
        total=records.count(),
    )
    return render(request, "practice.html", ctx)


def displayed(record):
    valid = record.snapshot_hash == digest(record.snapshot)
    return {
        "id": record.pk,
        "status": record.status,
        "version": record.version,
        "title": record.snapshot["title"],
        "brief": record.snapshot["brief"],
        "requirement": record.snapshot["requirement"],
        "snapshot_hash": record.snapshot_hash,
        "catalog_version": record.snapshot["version"],
        "fictional": record.snapshot.get("fictional", True),
        "scope": record.snapshot.get("scope", "Authored fictional tabletop; no actual execution."),
        "receipts": record.snapshot.get("receipts", []),
        "authorship": practice.AUTHORSHIP.get(record.decision.get("authorship"), "Not recorded"),
        "assistance": record.decision.get("assistance") or "Not recorded",
        "authorship_verified": False,
        "human_review_status": "Not recorded",
        "rubric": practice.HUMAN_RUBRIC,
        "valid": valid,
        "created_at": record.created_at,
        "submitted_at": record.submitted_at,
        "packets": [
            {**p, "opened": True}
            if p["id"] in record.revealed
            else {"id": p["id"], "action": p["action"], "opened": False}
            for p in record.snapshot["packets"]
        ],
        "decision": record.decision,
        "labels": {
            key: choices.get(record.decision.get(key), "Not recorded")
            for key, choices in (
                ("assessment", ASSESSMENTS),
                ("priority", PRIORITIES),
                ("confidence", CONFIDENCE),
                ("next_action", NEXT_ACTIONS),
            )
        },
        "review": record.review if record.status == "submitted" and valid else None,
    }


@login_required
@require_http_methods(["GET", "POST"])
def detail(request, session_id):
    ctx = scope(request)
    record = get_object_or_404(
        PracticeSession, pk=session_id, author=request.user, integration=ctx["app"]
    )
    form = None
    if request.method == "POST":
        action = request.POST.get("action")
        allowed = (
            {"action", "version", "evidence"}
            if action == "reveal"
            else {"action", "version", *practice.DecisionForm.base_fields}
        )
        if not valid_post(request, allowed, multiple={"citations"}):
            return HttpResponse("Invalid practice request.", status=400)
        try:
            version = int(request.POST.get("version", "0"))
        except ValueError:
            return HttpResponse("Invalid record version.", status=400)
        try:
            record, form = practice.update(
                request.user,
                ctx["app"],
                record.pk,
                version,
                action,
                evidence=request.POST.get("evidence"),
                form_data=request.POST,
            )
        except PermissionError as error:
            return HttpResponse(str(error), status=403)
        except practice.PracticeError as error:
            messages.error(request, str(error))
        else:
            if form is None:
                messages.success(
                    request,
                    {
                        "save": "Draft saved. Your earlier versions are retained.",
                        "submit": "Attempt submitted. Review the coaching feedback below.",
                        "reveal": "Assignment evidence opened and recorded in your activity history.",
                    }[action],
                )
                return redirect(f"/practice/{record.pk}/?app={ctx['app'].slug}")
        record.refresh_from_db()
    if form is None:
        form = practice.DecisionForm(
            initial=record.decision, packets=record.snapshot["packets"], revealed=record.revealed
        )
    ctx.update(
        page="practice",
        attempt=displayed(record),
        form=form,
        entries=record.entries.order_by("version"),
    )
    return render(
        request, "practice_case.html", ctx, status=400 if form.is_bound and form.errors else 200
    )


@login_required
@require_GET
def export(request, session_id):
    ctx = scope(request)
    record = get_object_or_404(
        PracticeSession, pk=session_id, author=request.user, integration=ctx["app"]
    )
    if record.status != "submitted" or record.snapshot_hash != digest(record.snapshot):
        return HttpResponse("Only an intact submitted attempt can be exported.", status=409)
    attempt = displayed(record)
    entries = list(
        record.entries.order_by("version").values("version", "action", "content", "created_at")
    )
    if request.GET.get("format") == "json":
        response = JsonResponse(
            {
                "kind": "signalbridge-coached-tabletop"
                if attempt["fictional"]
                else "signalbridge-historical-evidence-review",
                "version": 2,
                "fictional": attempt["fictional"],
                "independent_assessment": False,
                "attempt": attempt,
                "history": entries,
            }
        )
        extension = "json"
    else:
        response = HttpResponse(
            render_to_string("practice_export.html", {"attempt": attempt, "entries": entries}),
            content_type="text/html; charset=utf-8",
        )
        extension = "html"
    response["Content-Disposition"] = (
        f'attachment; filename="SignalBridge_Practice_{record.pk}.{extension}"'
    )
    return response
