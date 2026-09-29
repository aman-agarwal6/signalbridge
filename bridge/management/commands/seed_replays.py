from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from bridge.evaluation import evaluate
from bridge.models import Integration, Replay
from bridge.services import create_replay, decide_replay


class Command(BaseCommand):
    help = "Create reproducible synthetic comparisons and two-person advisory decisions."

    def handle(self, *args, **options):
        analyst = get_user_model().objects.get(username="analyst")
        reviewer = get_user_model().objects.get(username="reviewer")
        for app in Integration.objects.filter(slug__in=("bettail", "netted")):
            for policy in ("unsafe", "revised"):
                dataset_hash, engine_hash, _ = evaluate(policy, app.slug)
                if Replay.objects.filter(
                    integration=app,
                    policy=policy,
                    dataset_hash=dataset_hash,
                    engine_hash=engine_hash,
                ).exists():
                    continue
                replay = create_replay(analyst, app, policy)
                decide_replay(
                    reviewer,
                    replay.pk,
                    "rejected" if policy == "unsafe" else "approved",
                    1,
                )
        self.stdout.write(
            "Synthetic comparisons recorded with distinct analyst and reviewer accounts."
        )
