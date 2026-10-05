"""AccessOps leaver signals: store verified tokens once, then open access-after-departure cases.

Two detections, both critical because the person has left:
- L1: AccessOps reported a successful sign-in or token use after the departure took effect
  (a CAEP session-established event). Every such event is access after departure.
- L2: this console's own records show the same workforce identity (issuer and subject)
  signing in after AccessOps reported the account disabled.
Signals and cases live in a separate "accessops" workspace, visible only to its members.
Nothing here contains or disables an account; that decision stays with people.
"""

import hashlib

from django.db import transaction
from django.utils import timezone

from integrations.ssf.tokens import facts_digest

from .models import (
    Audit,
    FederatedSession,
    Integration,
    Investigation,
    LeaverSignal,
)

WORKSPACE = "accessops"
RULE_REPORTED = "L1"
RULE_CONSOLE = "L2"


def workspace():
    app, _ = Integration.objects.get_or_create(
        slug=WORKSPACE,
        defaults={
            "name": "AccessOps leavers",
            "enabled": False,
            "coverage": (
                "Signed leaver events from AccessOps (account disabled, sessions revoked, "
                "sign-in after departure); workforce identities only"
            ),
            "asset_criticality": "high",
        },
    )
    return app


def store(facts, token):
    """("stored" | "duplicate" | "conflict", signal) for one verified token."""
    digest = facts_digest(facts)
    with transaction.atomic():
        existing = LeaverSignal.objects.select_for_update().filter(jti=facts["jti"]).first()
        if existing is not None:
            return ("duplicate" if existing.facts_sha256 == digest else "conflict"), existing
        signal = LeaverSignal.objects.create(
            jti=facts["jti"],
            txn=facts["txn"],
            event_type=facts["event_type"],
            subject_issuer=facts["subject_issuer"],
            subject_id=facts["subject_id"],
            event_at=facts["event_at"],
            issued_at=facts["issued_at"],
            initiating_entity=facts["initiating_entity"],
            reason=facts["reason"],
            key_id=facts["key_id"],
            token=token,
            token_sha256=hashlib.sha256(token.encode()).hexdigest(),
            facts_sha256=digest,
            received_at=timezone.now(),
        )
    return "stored", signal


def _subject_signals(issuer, subject):
    return LeaverSignal.objects.filter(subject_issuer=issuer, subject_id=subject).order_by(
        "event_at", "jti"
    )


def _times(values):
    """One time, or how many between the first and the last."""
    values = sorted(values)
    first, last = (value.strftime("%Y-%m-%d %H:%M:%S") for value in (values[0], values[-1]))
    if len(values) == 1:
        return f"at {first}"
    return f"{len(values)} times between {first} and {last}"


def _containment(signals):
    disabled = [s.event_at for s in signals if s.event_type == "account_disabled"]
    revoked = [s.event_at for s in signals if s.event_type == "session_revoked"]
    parts = [
        f"account disabled {_times(disabled)} UTC"
        if disabled
        else "no account-disabled signal yet",
        f"sessions revoked {_times(revoked)} UTC" if revoked else "no session-revoked signal yet",
    ]
    return "AccessOps containment evidence: " + "; ".join(parts) + "."


def _upsert(app, rule, issuer, subject, title, explanation, evidence, detail, escalates):
    """Create or update one case; only new access after departure reopens a closed case."""
    correlation = hashlib.sha256(f"leaver|{rule}|{issuer}|{subject}".encode()).hexdigest()
    with transaction.atomic():
        case, created = Investigation.objects.select_for_update().get_or_create(
            integration=app,
            rule=rule,
            correlation=correlation,
            defaults={"severity": "critical", "title": title, "explanation": explanation},
        )
        linked = set(case.leaver_signals.values_list("jti", flat=True))
        additions = [s for s in evidence if s.jti not in linked]
        if not created and not additions and case.explanation == explanation:
            return None
        previous = case.status
        case.leaver_signals.add(*additions)
        reopened = False
        if not created:
            reopened = previous != "open" and escalates(case, additions)
            case.explanation = explanation
            if reopened:
                case.status = "open"
            case.version += 1
            case.save(update_fields=["explanation", "status", "version"])
        action = (
            "case.created" if created else "case.reopened" if reopened else "case.evidence_added"
        )
        Audit.objects.create(
            integration=app,
            action=action,
            object_id=str(case.pk),
            detail={
                "rule": rule,
                "previous_status": previous,
                "signals_added": len(additions),
                "version": case.version,
                **detail,
            },
        )
    return action


def _new_signin(case, additions):
    return any(s.event_type == "session_established" for s in additions)


def _more_console_signins(count):
    def escalates(case, additions):
        last = (
            Audit.objects.filter(object_id=str(case.pk), detail__has_key="console_signins")
            .order_by("-created_at", "-pk")
            .values_list("detail", flat=True)
            .first()
        ) or {}
        return count > last.get("console_signins", 0)

    return escalates


def detect_reported(app, issuer, subject):
    """L1 for a subject with at least one AccessOps-reported sign-in after departure."""
    signals = list(_subject_signals(issuer, subject))
    signins = [s for s in signals if s.event_type == "session_established"]
    if not signins:
        return None
    explanation = (
        f"AccessOps reported that departed workforce account {subject} (issuer {issuer}) "
        f"signed in or used a token {_times([s.event_at for s in signins])} UTC, after its "
        f"departure took effect. {_containment(signals)} SignalBridge verified each signal's "
        "ES256 signature, issuer and audience. The signals do not show what the session "
        "accessed; check the identity provider and the applications it can reach."
    )
    return _upsert(
        app,
        RULE_REPORTED,
        issuer,
        subject,
        "Access after departure reported by AccessOps",
        explanation,
        signals,
        {"reported_signins": len(signins)},
        _new_signin,
    )


def detect_console(app, issuer, subject):
    """L2 when this console saw a sign-in by the identity after its account-disabled time."""
    signals = list(_subject_signals(issuer, subject))
    disabled = [s.event_at for s in signals if s.event_type == "account_disabled"]
    if not disabled:
        return None
    sessions = list(
        FederatedSession.objects.filter(
            identity__issuer=issuer,
            identity__subject=subject,
            authenticated_at__gt=min(disabled),
        )
        .order_by("authenticated_at")
        .values_list("authenticated_at", flat=True)[:100]
    )
    if not sessions:
        return None
    explanation = (
        f"This console's own sign-in records show workforce account {subject} (issuer "
        f"{issuer}) authenticating {_times(sessions)} UTC, after AccessOps reported the "
        f"account disabled {_times(disabled)} UTC. {_containment(signals)} Review the "
        "console session and what that account did here; this detection does not revoke it."
    )
    return _upsert(
        app,
        RULE_CONSOLE,
        issuer,
        subject,
        "Departed account signed in to SignalBridge",
        explanation,
        [s for s in signals if s.event_type != "session_established"],
        {"console_signins": len(sessions)},
        _more_console_signins(len(sessions)),
    )


def detect(subjects):
    """Run both detections for each (issuer, subject); returns {action: count}."""
    app = workspace()
    actions = {}
    for issuer, subject in sorted(subjects):
        for result in (detect_reported(app, issuer, subject), detect_console(app, issuer, subject)):
            if result:
                actions[result] = actions.get(result, 0) + 1
    return actions


def departed_subjects():
    return set(
        LeaverSignal.objects.filter(event_type="account_disabled").values_list(
            "subject_issuer", "subject_id"
        )
    )
