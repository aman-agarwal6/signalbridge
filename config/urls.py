from django.contrib.auth.views import LogoutView
from django.urls import path

from bridge import practice_views, scan_views, views
from bridge.ingestion import ingest

urlpatterns = [
    path("", views.overview, name="overview"),
    path("login/", views.sign_in, name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("integrations/", views.integrations, name="integrations"),
    path("detections/", views.detection_coverage, name="detections"),
    path("lab/", views.capability_lab, name="capability_lab"),
    path("lab/<uuid:run_id>/export/", views.simulation_export, name="simulation_export"),
    path("events/", views.events, name="events"),
    path("findings/", scan_views.findings, name="findings"),
    path("findings/<uuid:finding_id>/", scan_views.finding, name="finding"),
    path("scans/", scan_views.scan_runs, name="scans"),
    path("scans/<uuid:run_id>/export/", scan_views.scan_export, name="scan_export"),
    path("investigations/", views.investigations, name="investigations"),
    path("investigations/<uuid:case_id>/", views.investigation, name="case"),
    path("investigations/<uuid:case_id>/export/", views.case_export, name="case_export"),
    path("checks/", views.checks, name="checks"),
    path("replay/", views.replay_lab, name="replay"),
    path("practice/", practice_views.index, name="practice"),
    path("practice/<uuid:session_id>/", practice_views.detail, name="practice_case"),
    path("practice/<uuid:session_id>/export/", practice_views.export, name="practice_export"),
    path("requirements/", views.requirements, name="requirements"),
    path("export/", views.export_evidence, name="export"),
    path("api/v1/events/<slug:app>/", ingest, name="ingest"),
    path("health/", views.health, name="health"),
]
