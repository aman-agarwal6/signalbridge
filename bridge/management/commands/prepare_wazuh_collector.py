"""Explicit trusted local snapshot; never starts a collector or grants access."""

import json

from django.core.management.base import BaseCommand, CommandError
from django.db import OperationalError

from bridge.models import Integration
from bridge.soc_delivery import DeliveryError
from bridge.wazuh_collector_snapshot import capture_idle_exports
from integrations.wazuh_enterprise.contract import EnterpriseWazuhError


class Command(BaseCommand):
    help = (
        "Copy idle published documents/expenses enterprise metadata for reviewed native collection."
    )

    def add_arguments(self, parser):
        parser.add_argument("--run-id", required=True)
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--local-database-operator", action="store_true")

    def handle(self, *args, **options):
        if not options["local_database_operator"]:
            raise CommandError(
                "Requires the trusted local database operator; this is not a browser/API permission."
            )
        try:
            value = capture_idle_exports(options["run_id"], dry_run=options["dry_run"])
        except (
            DeliveryError,
            EnterpriseWazuhError,
            ValueError,
            OSError,
            OperationalError,
            Integration.DoesNotExist,
        ) as error:
            code = (
                str(error)
                if isinstance(error, (DeliveryError, EnterpriseWazuhError))
                else type(error).__name__
            )
            raise CommandError(
                f"Collector snapshot stopped ({code}); retain partial files and use a fresh run ID after correction."
            ) from None
        self.stdout.write(json.dumps(value, sort_keys=True))
        self.stdout.write(
            "Preparation only. Source execution, private host ACLs and native collector delivery remain unverified."
        )
