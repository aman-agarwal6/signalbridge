"""Only the two required proof endpoints; no analyst console or identity surface."""

from django.urls import path

from bridge.ingestion import ingest
from bridge.monitoring import metrics

urlpatterns = [
    path("metrics/", metrics),
    path("api/v1/events/<slug:app>/", ingest),
]
