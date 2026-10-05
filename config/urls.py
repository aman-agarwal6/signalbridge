from django.urls import path

from bridge import (
    case_brief,
    case_workflow_views,
    monitoring,
    oidc_views,
    practice_views,
    scan_views,
    service_api,
    views,
)
from bridge.federation_views import PolicyLogoutView
from bridge.ingestion import ingest

urlpatterns = [
    path("", views.overview, name="overview"),
    path("login/", views.sign_in, name="login"),
    path("logout/", PolicyLogoutView.as_view(), name="logout"),
    path("sso/start/", oidc_views.start, name="sso_start"),
    path("sso/callback/", oidc_views.callback, name="sso_callback"),
    path("sso/backchannel/", oidc_views.backchannel, name="sso_backchannel"),
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
    path("investigations/<uuid:case_id>/brief/", case_brief.brief, name="case_brief"),
    path("investigations/<uuid:case_id>/work/", case_workflow_views.update, name="case_work"),
    path("checks/", views.checks, name="checks"),
    path("replay/", views.replay_lab, name="replay"),
    path("practice/", practice_views.index, name="practice"),
    path("practice/<uuid:session_id>/", practice_views.detail, name="practice_case"),
    path("practice/<uuid:session_id>/export/", practice_views.export, name="practice_export"),
    path("requirements/", views.requirements, name="requirements"),
    path("export/", views.export_evidence, name="export"),
    path("api/v1/events/<slug:app>/", ingest, name="ingest"),
    path(
        "api/v1/cases/<uuid:case_id>/evidence/",
        service_api.read_evidence,
        name="service_case_evidence",
    ),
    path(
        "api/v1/cases/<uuid:case_id>/review-task/",
        service_api.create_review_task,
        name="service_review_task",
    ),
    path("health/", views.health, name="health"),
    path("metrics/", monitoring.metrics, name="metrics"),
]
