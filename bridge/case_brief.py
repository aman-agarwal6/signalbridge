"""Authenticated, printable analyst handoff; never a public portfolio export."""

from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.http import require_GET

from .case_verification import console_context
from .detection_catalog import explain_case
from .models import Investigation, Note
from .services import write_membership


@require_GET
@login_required
def brief(request, case_id):
    # Match the mutation lock order: current membership, then case. Render inside
    # the transaction so deferred template queries cannot escape admission.
    with transaction.atomic():
        candidate = get_object_or_404(
            Investigation, pk=case_id, integration__membership__user=request.user
        )
        try:
            write_membership(request.user, candidate.integration, ("viewer", "analyst", "reviewer"))
        except PermissionError:
            raise Http404 from None
        case = get_object_or_404(Investigation.objects.select_for_update(), pk=candidate.pk)
        events = list(
            case.events.filter(integration=case.integration).order_by("occurred_at", "pk")[:1001]
        )
        if len(events) > 1000:
            return HttpResponse(
                "This brief exceeds the 1,000-event limit. Use scoped event review.", status=413
            )
        notes = list(case.note_set.select_related("author").order_by("-created_at", "-pk")[:101])
        groups = []
        for kind, label in Note._meta.get_field("kind").choices:
            selected = [note for note in reversed(notes[:100]) if note.kind == kind]
            groups.append({"label": label, "notes": selected})
        context = {
            "case": case,
            "app": case.integration,
            "events": events,
            "analysis": explain_case(case, events),
            "note_groups": groups,
            "notes_limited": len(notes) > 100,
            "tasks_limited": case.tasks.count() > 50,
            "prepared_at": timezone.now(),
            **console_context(case),
        }
        response = render(request, "case_brief.html", context)
        response["Cache-Control"] = "no-store, private"
        response["X-Robots-Tag"] = "noindex, nofollow, noarchive"
        return response
