"""App-scoped stored evidence only. Never inspect Docker while serving a page."""

from bridge.assurance import timestamp
from bridge.zap_repeat_evidence import KIND, canonical, digest, validate_result
from scripts.verify_soc_pilot import VerificationError

from .models import CheckRun


def repeat_cards(app):
    if app.slug != "signalbridge":
        return []
    # Show the latest six imports, including invalid receipts. Do not silently
    # select only passing evidence or fall back to an earlier successful record.
    runs = CheckRun.objects.filter(integration=app, result__evidence_kind=KIND).order_by(
        "-created_at",
        "-id",
    )[:6]
    cards = []
    for run in runs:
        card = {"verified": False, "record_id": run.pk}
        try:
            result = run.result
            validate_result(result)
            if (
                run.status != result["status"]
                or run.digest != digest(canonical(result))
                or run.revision != result["provenance"]["execution_sha256"]
            ):
                raise ValueError("Receipt identity differs")
            card.update(
                result,
                verified=True,
                receipt_digest=run.digest,
                tested_at=timestamp(result["finished_at"]),
            )
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError, VerificationError):
            pass
        cards.append(card)
    return cards
