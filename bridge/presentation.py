"""Read-only, application-scoped console presentation helpers."""

from datetime import date, timedelta

from django.db.models import Q
from django.utils import timezone

from .models import Event, Investigation


def decorate_cases(cases, integration):
    """Use bounded prefetched previews and grouped metadata for complete source labels."""
    cases = list(cases)
    sources = {case.pk: set() for case in cases}
    labels = dict(Event._meta.get_field("source").choices)
    if cases:
        links = (
            Investigation.events.through.objects.filter(
                investigation_id__in=sources,
                investigation__integration=integration,
                event__integration=integration,
            )
            .values_list("investigation_id", "event__source")
            .distinct()
        )
        for case_id, source in links:
            sources[case_id].add(labels.get(source, source))
    for case in cases:
        case.source_labels = sorted(sources[case.pk])
    return cases


def case_preview_events(integration):
    """Django applies the slice per parent using ROW_NUMBER, not across the whole page."""
    return (
        Event.objects.filter(integration=integration)
        .only("id", "occurred_at", "operation", "outcome", "reason", "source")
        .order_by("occurred_at", "id")[:3]
    )


def page_context(page):
    return {"pagination": page, "result_count": page.paginator.count}


def event_filters(records, params):
    choices = {
        "environment": {"lab", "test"},
        "source": {choice[0] for choice in Event._meta.get_field("source").choices},
        "outcome": {"allowed", "denied", "not_visible", "error"},
        "state": {"pending", "processed", "dead"},
        "range": {"24h", "7d", "30d"},
    }
    selected = {
        name: params.get(name, "") if params.get(name) in values else ""
        for name, values in choices.items()
    }
    for field in ("source", "outcome", "state", "environment"):
        if selected[field]:
            records = records.filter(**{field: selected[field]})
    if selected["range"]:
        duration = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}[
            selected["range"]
        ]
        now = timezone.now()
        records = records.filter(occurred_at__gte=now - duration, occurred_at__lte=now)
    selected["day"] = ""
    if params.get("day"):
        try:
            selected["day"] = date.fromisoformat(params["day"]).isoformat()
        except ValueError:
            pass
        else:
            records = records.filter(occurred_at__date=selected["day"])
    selected["q"] = params.get("q", "").strip()[:120]
    if selected["q"]:
        query = selected["q"]
        records = records.filter(
            Q(operation__icontains=query)
            | Q(reason__icontains=query)
            | Q(actor__icontains=query)
            | Q(resource__icontains=query)
            | Q(event_id__icontains=query)
            | Q(episode__icontains=query)
        )
    return records, selected
