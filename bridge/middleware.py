from django.conf import settings

POLICY = (
    "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
)


def form_action():
    """Browsers apply form-action to redirects after a submit, so the organization
    sign-in POST may only continue to the one fixed identity provider origin."""
    if getattr(settings, "FEDERATED_AUTH_ENABLED", False):
        from integrations.identity.constants import PROVIDER_ORIGIN

        return "form-action 'self' " + PROVIDER_ORIGIN
    return "form-action 'self'"


class SecurityHeaders:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Content-Security-Policy"] = POLICY + form_action()
        response["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response["Cache-Control"] = "no-store, private"
        return response
