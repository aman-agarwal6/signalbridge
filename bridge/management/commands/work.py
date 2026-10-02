import time

from django.core.management.base import BaseCommand, CommandError

from bridge.worker import drain, validate_worker_id


class Command(BaseCommand):
    help = "Process the durable queue; one worker in SQLite mode."

    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true")
        parser.add_argument("--worker-id", default="default")
        parser.add_argument("--batch-size", type=int, default=500)

    def handle(self, *args, **options):
        try:
            validate_worker_id(options["worker_id"])
            if not 1 <= options["batch_size"] <= 10000:
                raise ValueError("Batch size must be between 1 and 10000.")
        except ValueError as error:
            raise CommandError(str(error)) from None
        while True:
            try:
                count = drain(limit=options["batch_size"], worker_id=options["worker_id"])
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
