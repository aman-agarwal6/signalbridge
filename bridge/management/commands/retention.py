from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from bridge.models import Audit, Event, Integration


class Command(BaseCommand):
    help = (
        "Preview retention; --apply deletes only processed, unlinked metadata older than 90 days."
    )

    def add_arguments(self, parser):
        parser.add_argument("app", choices=["bettail", "netted"])
        parser.add_argument("--apply", action="store_true")

    def handle(self, *args, **options):
        with transaction.atomic():
            app = Integration.objects.select_for_update().get(slug=options["app"])
            candidates = Event.objects.filter(
                integration=app,
                state="processed",
                received_at__lt=timezone.now() - timedelta(days=90),
                investigation__isnull=True,
                socdelivery__isnull=True,
            )
            count = candidates.count()
            if options["apply"]:
                candidates.delete()
                Audit.objects.create(
                    integration=app,
                    action="retention.applied",
                    object_id=app.slug,
                    detail={"unlinked_events_deleted": count, "minimum_age_days": 90},
                )
            self.stdout.write(
                f"{'Removed' if options['apply'] else 'Would remove'} {count} unlinked, processed records. Case evidence, SOC delivery evidence, pending and dead records are preserved."
            )
