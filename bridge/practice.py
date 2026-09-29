"""Bounded, owner-scoped coaching. No network, subprocess, scan or event writes."""

from django import forms
from django.db import transaction
from django.utils import timezone

from . import recorded_practice
from .models import PracticeEntry, PracticeSession
from .practice_catalog import (
    ASSESSMENTS,
    CATALOG,
    CONFIDENCE,
    NEXT_ACTIONS,
    PRIORITIES,
    digest,
    feedback,
    scenario,
)
from .services import write_membership

MAX_SESSIONS = 50
MAX_ENTRIES = 100
AUTHORSHIP = {
    "participant": "Participant-authored (self-reported)",
    "coached": "Participant-authored with coaching (self-reported)",
    "builder_qa": "Builder / AI quality-assurance exercise",
}
HUMAN_RUBRIC = [
    (
        "Evidence accuracy",
        "Identify the exact run/record and distinguish what was observed from what you inferred.",
    ),
    (
        "Scope and controls",
        "Name the environment, relevant positive control and the limits of the tested paths.",
    ),
    (
        "Alternative explanation",
        "Describe a plausible alternative and the missing evidence that would distinguish it.",
    ),
    (
        "Business impact",
        "Explain the affected permission or monitoring outcome without claiming untested exposure.",
    ),
    (
        "Safe handoff",
        "Assign a next check to a role and state a measurable completion condition within authorized scope.",
    ),
    (
        "Explain it aloud",
        "Answer an unfamiliar follow-up in your own words and disclose AI or human assistance.",
    ),
]


class PracticeError(ValueError):
    pass


class DecisionForm(forms.Form):
    assessment = forms.ChoiceField(
        label="Assessment", choices=[("", "Choose an assessment"), *ASSESSMENTS.items()]
    )
    priority = forms.ChoiceField(
        label="Priority within the assignment's scope",
        choices=[("", "Choose priority"), *PRIORITIES.items()],
    )
    confidence = forms.ChoiceField(
        label="Confidence in your scoped conclusion",
        choices=[("", "Choose confidence"), *CONFIDENCE.items()],
    )
    next_action = forms.ChoiceField(
        label="Recommended next action", choices=[("", "Choose next action"), *NEXT_ACTIONS.items()]
    )
    observation = forms.CharField(
        label="Observation - what does the evidence show?",
        min_length=30,
        max_length=2000,
        widget=forms.Textarea(attrs={"rows": 3}),
    )
    interpretation = forms.CharField(
        label="Interpretation - requirement, impact and conclusion",
        min_length=30,
        max_length=2000,
        widget=forms.Textarea(attrs={"rows": 3}),
    )
    uncertainty = forms.CharField(
        label="Uncertainty - what is not established?",
        min_length=30,
        max_length=2000,
        widget=forms.Textarea(attrs={"rows": 3}),
    )
    next_check = forms.CharField(
        label="Handoff - who should do what, and what result is needed?",
        min_length=30,
        max_length=2000,
        widget=forms.Textarea(attrs={"rows": 3}),
    )
    citations = forms.MultipleChoiceField(
        label="Evidence supporting your note", choices=[], widget=forms.CheckboxSelectMultiple
    )
    authorship = forms.ChoiceField(
        label="Who wrote this analysis?",
        choices=[("", "Choose an authorship declaration"), *AUTHORSHIP.items()],
    )
    assistance = forms.CharField(
        label="Assistance and prior attempts",
        min_length=3,
        max_length=600,
        help_text="State any AI/human help and whether you have seen this exercise before. Write 'None' only if that is accurate. This is a self-report, not verified authorship.",
        widget=forms.Textarea(attrs={"rows": 2}),
    )

    def __init__(self, *args, packets=(), revealed=(), draft=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["citations"].choices = [
            (p["id"], p["id"] + " - " + p["action"]) for p in packets if p["id"] in revealed
        ]
        if draft:
            for field in self.fields.values():
                field.required = False
                if isinstance(field, forms.CharField):
                    field.min_length = 0
                    field.validators = [
                        v
                        for v in field.validators
                        if getattr(v, "limit_value", None) not in (3, 30)
                    ]
        self.draft = draft

    def clean_citations(self):
        values = self.cleaned_data["citations"]
        if len(values) != len(set(values)):
            raise forms.ValidationError("Cite each evidence item once.")
        if not self.draft and len(values) < 2:
            raise forms.ValidationError("Cite at least two reviewed evidence items.")
        return values


def authorize(user, integration):
    write_membership(user, integration)


@transaction.atomic
def start(user, integration, key):
    # The membership row serializes bounded creation on PostgreSQL too.
    authorize(user, integration)
    if key not in CATALOG and key not in recorded_practice.ASSIGNMENTS:
        raise PracticeError("Choose a listed exercise.")
    if PracticeSession.objects.filter(author=user, integration=integration).count() >= MAX_SESSIONS:
        raise PracticeError(
            "This workspace has reached 50 retained attempts. Ask the operator to review retention; previous work is preserved."
        )
    try:
        snapshot = (
            recorded_practice.scenario(key, integration.slug)
            if key in recorded_practice.ASSIGNMENTS
            else scenario(key)
        )
    except recorded_practice.RecordedEvidenceError as error:
        raise PracticeError(str(error)) from error
    session = PracticeSession.objects.create(
        integration=integration,
        author=user,
        scenario=key,
        snapshot=snapshot,
        snapshot_hash=digest(snapshot),
    )
    PracticeEntry.objects.create(
        session=session,
        version=1,
        action="started",
        content={"scenario_sha256": session.snapshot_hash},
    )
    return session


@transaction.atomic
def update(user, integration, session_id, version, action, *, evidence=None, form_data=None):
    authorize(user, integration)
    session = PracticeSession.objects.select_for_update().get(
        id=session_id, author=user, integration=integration
    )
    if session.status != "draft":
        raise PracticeError(
            "This submitted attempt is preserved. Start a new attempt for further practice."
        )
    if session.version != version:
        raise PracticeError(
            "This attempt changed in another tab. Reload before saving; the newer work is preserved."
        )
    if session.snapshot_hash != digest(session.snapshot):
        raise PracticeError(
            "The exercise snapshot failed its integrity check. Ask the operator to review it."
        )
    if session.version >= MAX_ENTRIES or (
        session.version == MAX_ENTRIES - 1 and action != "submit"
    ):
        raise PracticeError(
            "This attempt reached its draft-history limit. Submit the current note to preserve a final decision."
        )
    packets = session.snapshot["packets"]
    if action == "reveal":
        if evidence not in {p["id"] for p in packets} or evidence in session.revealed:
            raise PracticeError("Choose an unopened evidence item.")
        session.revealed = [*session.revealed, evidence]
        content = {"evidence": evidence}
    elif action in ("save", "submit"):
        form = DecisionForm(
            form_data, packets=packets, revealed=session.revealed, draft=action == "save"
        )
        if not form.is_valid():
            return session, form
        session.decision = form.cleaned_data
        content = dict(session.decision)
        if action == "submit":
            session.status = "submitted"
            session.submitted_at = timezone.now()
            session.review = feedback(session.snapshot, session.decision)
    else:
        raise PracticeError("Unsupported practice action.")
    session.version += 1
    session.save()
    PracticeEntry.objects.create(
        session=session, version=session.version, action=action, content=content
    )
    return session, None
