"""Enforce registry admission on every request carrying a federated session."""

from django.contrib.auth import logout
from django.db import DatabaseError
from django.http import HttpResponse
from django.shortcuts import redirect

from .federation import (
    GENERIC_DENIAL,
    SESSION_KEY,
    FederationDenied,
    check_browser_admission,
    unavailable_response,
)


class FederatedSessionPolicy:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if SESSION_KEY in request.session:
            try:
                if not request.is_secure():
                    raise FederationDenied()
                request.user._sb_federated_admission = check_browser_admission(
                    request.user, request.session[SESSION_KEY]
                )
            except DatabaseError:
                return unavailable_response()
            except FederationDenied:
                logout(request)
                if request.method not in ("GET", "HEAD"):
                    return HttpResponse(GENERIC_DENIAL, status=403, content_type="text/plain")
                return redirect("login")
        return self.get_response(request)
