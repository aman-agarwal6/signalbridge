"""Browser writes retain session authentication and Django CSRF protection."""

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST

from .case_workflow import operate
from .models import Investigation
from .services import WorkflowError


@require_POST
@login_required
def update(request, case_id):
    get_object_or_404(Investigation, pk=case_id, integration__membership__user=request.user)
    if len(request.body) > 8192:
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
    except (WorkflowError, ValueError, TypeError, ValidationError):
        messages.error(
            request, "Case update was not accepted. Check the fields and reload the latest version."
        )
    return redirect("case", case_id=case_id)
