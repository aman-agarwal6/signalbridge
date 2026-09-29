from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from bridge.models import Audit, Event, Integration


class Command(BaseCommand):
    help = "Explicitly requeue failed local collector records for one application."

    def add_arguments(self, parser):
        parser.add_argument("app", choices=["bettail", "netted"])

    def handle(self, *args, **options):
        with transaction.atomic():
            app = Integration.objects.get(slug=options["app"])
            count = Event.objects.filter(integration=app, state="dead").update(
                state="pending", attempts=0, available_at=timezone.now(), error_code=""
            )
            Audit.objects.create(
                integration=app,
                action="queue.retried",
                object_id=app.slug,
                detail={"count": count},
            )
        self.stdout.write(f"Requeued {count} records for {app.slug}.")
