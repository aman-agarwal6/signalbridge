"""Local POST/CSRF logout only; no unverified OIDC callback is exposed."""

from django.contrib.auth.views import LogoutView
from django.db import DatabaseError
from django.http import HttpResponse

from .federation import (
    GENERIC_DENIAL,
    SESSION_KEY,
    FederationDenied,
    revoke_browser_session,
    unavailable_response,
)


class PolicyLogoutView(LogoutView):
    def post(self, request, *args, **kwargs):
        marker = request.session.get(SESSION_KEY)
        if marker is not None:
            try:
                revoke_browser_session(request.user, marker)
            except FederationDenied:
                return HttpResponse(GENERIC_DENIAL, status=403, content_type="text/plain")
            except DatabaseError:
                return unavailable_response()
        return super().post(request, *args, **kwargs)
