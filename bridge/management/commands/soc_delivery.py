"""Explicit local outbox operation, never a daemon or service installer."""

import json

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import OperationalError

from bridge.models import Integration
from bridge.soc_delivery import DeliveryError, publish, stage, status


class Command(BaseCommand):
    help = "Stage or append up to 100 sanitized records locally; no Wazuh receipt or network."

    def add_arguments(self, parser):
        parser.add_argument("app", choices=["bettail", "netted", "documents", "expenses"])
        parser.add_argument("action", choices=["status", "stage", "publish", "once"])

    def handle(self, *args, **options):
        if not settings.LOCAL:
            raise CommandError("SOC delivery is local-only.")
        try:
            app = Integration.objects.get(slug=options["app"])
            if options["action"] in {"stage", "once"}:
                stage(app)
            if options["action"] in {"publish", "once"}:
                publish(app)
            self.stdout.write(json.dumps(status(app), sort_keys=True))
            self.stdout.write("File acknowledgement only. Wazuh receipt has not been established.")
        except (DeliveryError, OSError, OperationalError, Integration.DoesNotExist) as error:
            code = str(error) if isinstance(error, DeliveryError) else type(error).__name__
            raise CommandError(
                f"SOC delivery stopped ({code}); preserve the ledger and file."
            ) from None
