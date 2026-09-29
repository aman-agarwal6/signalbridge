import json

from django.conf import settings
from django.core.management.base import BaseCommand

from bridge.models import Integration
from bridge.views import evidence


class Command(BaseCommand):
    help = "Write calculated local evidence; no personal source records."

    def handle(self, *args, **options):
        output = settings.BASE_DIR / "artifacts/local"
        output.mkdir(parents=True, exist_ok=True)
        for app in Integration.objects.all():
            path = output / (app.slug + "-evidence.json")
            path.write_text(json.dumps(evidence(app), indent=2) + "\n")
            self.stdout.write(str(path.relative_to(settings.BASE_DIR)))
