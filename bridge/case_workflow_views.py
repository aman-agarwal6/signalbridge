"""Browser writes retain session authentication and Django CSRF protection."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import HttpResponse, RawPostDataException
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from .case_workflow import operate
from .models import CaseTask, CaseVerification, CheckRun, Investigation
from .services import WorkflowError


@require_POST
@login_required
def update(request, case_id):
    get_object_or_404(Investigation, pk=case_id, integration__membership__user=request.user)
    # WSGI bounds its stream by CONTENT_LENGTH. CSRF may already have consumed
    # a multipart form; do not read that stream again or silently drop the cap.
    declared = request.META.get("CONTENT_LENGTH", "")
    if not isinstance(declared, str) or not declared.isascii() or not declared.isdigit():
        return HttpResponse("Case form requires a valid length.", status=400)
    if int(declared) > 8192:
        return HttpResponse("Case form exceeds the size limit.", status=413)
    if request.FILES:
        return HttpResponse("Case forms do not accept files.", status=415)
    try:
        size = len(request.body)
    except RawPostDataException:
        if request.content_type != "multipart/form-data":
            return HttpResponse("Case form could not be read.", status=400)
        size = len(request.POST.urlencode().encode("utf8"))
    if size > 8192:
        return HttpResponse("Case form exceeds the size limit.", status=413)
    try:
        operate(
            request.user,
            case_id,
            int(request.POST.get("version", "0")),
            request.POST.get("operation"),
            request.POST,
        )
    except PermissionError:
        return HttpResponse("Your current role does not allow this action.", status=403)
    except (
        WorkflowError,
        ValueError,
        TypeError,
        ValidationError,
        CaseTask.DoesNotExist,
        CaseVerification.DoesNotExist,
        CheckRun.DoesNotExist,
        Investigation.DoesNotExist,
    ):
        messages.error(
            request, "Case update was not accepted. Check the fields and reload the latest version."
        )
    return redirect("case", case_id=case_id)
