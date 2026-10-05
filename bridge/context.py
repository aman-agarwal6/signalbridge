from django.conf import settings


def workspace(request):
    return {
        "local_mode": settings.LOCAL,
        "federated_login_enabled": settings.FEDERATED_AUTH_ENABLED,
    }
