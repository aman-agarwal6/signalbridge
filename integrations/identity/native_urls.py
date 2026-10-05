"""Read-only native identity proof route, absent from the normal application."""

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.urls import path
from django.views.decorators.http import require_GET

from bridge.models import FederatedIdentity, Membership
from config.urls import urlpatterns as application_urls


@login_required
@require_GET
def current_identity(request):
    identity = FederatedIdentity.objects.get(user=request.user)
    response = JsonResponse(
        {
            "username": request.user.username,
            "issuer": identity.issuer,
            "subject": identity.subject,
            "staff": request.user.is_staff,
            "superuser": request.user.is_superuser,
            "memberships": list(
                Membership.objects.filter(user=request.user)
                .order_by("integration__slug")
                .values("integration__slug", "role")
            ),
        }
    )
    response["Cache-Control"] = "no-store, private"
    return response


urlpatterns = [path("_lab/identity/", current_identity), *application_urls]
