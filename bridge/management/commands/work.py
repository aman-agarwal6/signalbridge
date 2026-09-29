import time

from django.core.management.base import BaseCommand

from bridge.worker import drain


class Command(BaseCommand):
    help = "Process the durable queue; one worker in SQLite mode."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")

    def handle(self, *args, **options):
        while True:
            try:
                count = drain()
                if count:
                    self.stdout.write(f"Processed {count} queued records.")
            except Exception:
                self.stderr.write(
                    "Processing failed; bounded retry recorded. Inspect dead-letter counts."
                )
                if options["once"]:
                    raise
            if options["once"]:
                break
            time.sleep(2)
