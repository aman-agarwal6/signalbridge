"""Explicit local operations; never install, launch or connect to Wazuh."""

import json

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import OperationalError

from bridge.models import Integration
from bridge.soc_delivery import DeliveryError
from bridge.wazuh_enterprise import publish_signals, stage_signals
from bridge.wazuh_import import import_segment, status
from integrations.wazuh_enterprise.contract import APPS, EnterpriseWazuhError


class Command(BaseCommand):
    help = "Stage/publish bounded core signals or reconcile retained native-format Wazuh files."

    def add_arguments(self, parser):
        parser.add_argument("app", choices=sorted(APPS))
        parser.add_argument("action", choices=["status", "signals-once", "import"])
        parser.add_argument("--run-id")
        parser.add_argument("--kind", choices=["archive", "alert"])
        parser.add_argument("--segment", type=int, default=0)
        parser.add_argument("--local-database-operator", action="store_true")

    def handle(self, *args, **options):
        if not settings.LOCAL or (
            options["action"] != "status" and not options["local_database_operator"]
        ):
            raise CommandError("This mutation requires the trusted local database operator.")
        try:
            app = Integration.objects.get(slug=options["app"])
            result = None
            if options["action"] == "signals-once":
                stage_signals(app)
                publish_signals(app)
            elif options["action"] == "import":
                result = import_segment(app, options["run_id"], options["kind"], options["segment"])
            self.stdout.write(json.dumps(result or status(app), sort_keys=True, default=str))
            self.stdout.write(
                "Native-format reconciliation only; current Wazuh runtime/connection is unverified."
            )
        except (
            Integration.DoesNotExist,
            DeliveryError,
            EnterpriseWazuhError,
            OperationalError,
            ValueError,
            TypeError,
            OSError,
            ValidationError,
        ):
            raise CommandError(
                "Enterprise Wazuh operation rejected; preserve files and checkpoints for review."
            ) from None
