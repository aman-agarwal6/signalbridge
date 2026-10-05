from datetime import timedelta

from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from bridge.contract import ContractError, parse_json

from .authorization import observe_permission_change, observe_resource
from .models import LoginAttempt, Resource


@require_http_methods(["GET", "POST"])
def sign_in(request):
    if request.method == "GET":
        return render(request, "reference-login.html")
    with transaction.atomic():
        # Fixed synthetic accounts and a global limit bound this lab's login
        # surface. No passwords or supplied names are recorded in the throttle.
        owner = get_user_model().objects.select_for_update().filter(username="operator").first()
        if owner is None:
            return JsonResponse({"error": "Lab is not provisioned."}, status=503)
        cutoff = timezone.now() - timedelta(minutes=5)
        LoginAttempt.objects.filter(occurred_at__lt=cutoff).delete()
        if LoginAttempt.objects.count() >= 20:
            return JsonResponse({"error": "Login temporarily limited."}, status=429)
        LoginAttempt.objects.create()
        user = authenticate(
            request,
            username=request.POST.get("username", "")[:150],
            password=request.POST.get("password", ""),
        )
        if user is None:
            return JsonResponse({"error": "Invalid login."}, status=401)
        login(request, user)
        request.session.set_expiry(900)
    return JsonResponse({"signed_in": True})


@require_GET
@login_required
def identity(request):
    return JsonResponse({"account": request.user.username, "authenticated": True})


@require_POST
def sign_out(request):
    logout(request)
    return JsonResponse({"signed_out": True})


@require_GET
@login_required
def read(request, app, resource_id):
    try:
        content, event_id = observe_resource(app, resource_id, request.user.pk)
    except Resource.DoesNotExist:
        return JsonResponse({"error": "Resource unavailable."}, status=404)
    response = (
        JsonResponse({"error": "Access denied."}, status=403)
        if content is None
        else JsonResponse({"app": app, "record_id": str(resource_id), "synthetic_content": content})
    )
    response["X-SB-Lab-Event-ID"] = event_id
    return response


@require_POST
@login_required
def permission(request, app, resource_id):
    if request.content_type != "application/json" or len(request.body) > 1024:
        return JsonResponse({"error": "Bounded JSON required."}, status=400)
    try:
        value = parse_json(request.body)
        if (
            not isinstance(value, dict)
            or set(value) != {"subject", "kind", "granted"}
            or not isinstance(value["subject"], str)
            or len(value["subject"]) > 150
        ):
            raise ValueError()
        subject = get_user_model().objects.get(username=value["subject"])
        result, event_id = observe_permission_change(
            app, resource_id, request.user.pk, subject.pk, value["kind"], value["granted"]
        )
    except (ContractError, ValueError, Resource.DoesNotExist, get_user_model().DoesNotExist):
        return JsonResponse({"error": "Invalid permission request."}, status=400)
    response = JsonResponse(result)
    if event_id is not None:
        response["X-SB-Lab-Event-ID"] = event_id
    return response
