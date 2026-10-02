from django.urls import path

from . import views

urlpatterns = [
    path("login/", views.sign_in),
    path("logout/", views.sign_out),
    path("identity/", views.identity),
    path("apps/<slug:app>/resources/<uuid:resource_id>/", views.read),
    path("apps/<slug:app>/resources/<uuid:resource_id>/permission/", views.permission),
]
