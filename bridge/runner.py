import json
import time

from django.conf import settings
from django.test.runner import DiscoverRunner
from django.utils import timezone


class EvidenceRunner(DiscoverRunner):
    def run_suite(self, suite, **kwargs):
        start = time.perf_counter()
        result = super().run_suite(suite, **kwargs)
        output = settings.BASE_DIR / "artifacts/local"
        output.mkdir(parents=True, exist_ok=True)
        report = {
            "executed_at": timezone.now().isoformat(),
            "runner": "Django DiscoverRunner",
            "database": settings.DATABASES["default"]["ENGINE"],
            "tests": result.testsRun,
            "failed": len(result.failures),
            "errors": len(result.errors),
            "skipped": len(result.skipped),
            "duration_seconds": round(time.perf_counter() - start, 3),
            "passed": result.wasSuccessful() and result.testsRun > 0 and not result.skipped,
        }
        (output / "core-tests.json").write_text(json.dumps(report, indent=2) + "\n")
        if result.testsRun == 0:
            raise RuntimeError("No tests executed.")
        return result
