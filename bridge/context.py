from django.conf import settings


def workspace(request):
    return {"local_mode": settings.LOCAL}
