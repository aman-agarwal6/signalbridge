"""One finite source outbox batch; native launch and TLS trust require review."""

from django.core.management.base import BaseCommand, CommandError

from reference_lab.collector import deliver_one


class Command(BaseCommand):
    help = "Deliver at most 250 source outbox records to the fixed TLS lab console."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=100)

    def handle(self, *args, **options):
        limit = options["limit"]
        if not 1 <= limit <= 250:
            raise CommandError("Batch limit must be between 1 and 250.")
        counts = {}
        for _ in range(limit):
            result = deliver_one()
            if result is None:
                break
            counts[result] = counts.get(result, 0) + 1
        self.stdout.write(str(counts))
