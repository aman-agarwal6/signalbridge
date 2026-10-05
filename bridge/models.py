import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.db.models import Q


class Integration(models.Model):
    slug = models.SlugField(unique=True)
    name = models.CharField(max_length=80)
    enabled = models.BooleanField(default=True)
    coverage = models.CharField(max_length=240, default="Not connected")
    last_seen = models.DateTimeField(null=True, blank=True)
    rejected = models.PositiveIntegerField(default=0)
    business_owner = models.CharField(max_length=100, blank=True, default="")
    asset_criticality = models.CharField(
        max_length=16,
        default="unassessed",
        choices=[
            ("unassessed", "Not assessed"),
            ("low", "Low"),
            ("moderate", "Moderate"),
            ("high", "High"),
            ("critical", "Critical"),
        ],
    )

    def __str__(self):
        return self.name


class Membership(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    role = models.CharField(
        max_length=10,
        choices=[
            ("viewer", "Viewer"),
            ("analyst", "Analyst"),
            ("reviewer", "Reviewer"),
        ],
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "integration"], name="unique_membership"),
            models.CheckConstraint(
                condition=Q(role__in=["viewer", "analyst", "reviewer"]),
                name="valid_role",
            ),
        ]


class IngestKey(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.CASCADE)
    key_id = models.CharField(max_length=64, unique=True)
    secret_env = models.CharField(max_length=100)
    active = models.BooleanField(default=True)
    can_assert_membership = models.BooleanField(default=False)
    source = models.CharField(
        max_length=24,
        default="migration_lab",
        choices=[
            ("migration_lab", "Migration lab"),
            ("synthetic_demo", "Synthetic demo"),
            ("instrumented_lab", "Instrumented source lab"),
        ],
    )
    environment = models.CharField(
        max_length=12, default="lab", choices=[("lab", "Lab"), ("test", "Test")]
    )


class Event(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    integration = models.ForeignKey(Integration, on_delete=models.PROTECT)
    event_id = models.UUIDField()
    occurred_at = models.DateTimeField()
    received_at = models.DateTimeField(auto_now_add=True)
    actor = models.CharField(max_length=64)
    membership_subject = models.CharField(max_length=64, blank=True, default="")
    resource = models.CharField(max_length=64)
    episode = models.UUIDField()
    operation = models.CharField(max_length=32)
    outcome = models.CharField(max_length=20)
    reason = models.CharField(max_length=32)
    environment = models.CharField(max_length=12)
    source = models.CharField(
        max_length=24,
        default="legacy_unclassified",
        choices=[
            ("migration_lab", "Observed SQL lab"),
            ("synthetic_demo", "Synthetic fixture"),
            ("instrumented_lab", "Instrumented source lab"),
            ("legacy_unclassified", "Earlier development record"),
        ],
    )
    payload = models.JSONField()
    digest = models.CharField(max_length=64)
    state = models.CharField(max_length=12, default="pending")
    attempts = models.PositiveIntegerField(default=0)
    processing_attempts = models.PositiveIntegerField(default=0)
    processing_started_at = models.DateTimeField(null=True, blank=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    processed_by = models.CharField(max_length=40, blank=True, default="")
    available_at = models.DateTimeField()
    error_code = models.CharField(max_length=40, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["integration", "event_id"], name="unique_app_event")
        ]
        indexes = [
            models.Index(fields=["state", "available_at"]),
            models.Index(fields=["integration", "actor", "occurred_at"]),
            models.Index(
                fields=["integration", "resource", "occurred_at"], name="sb_event_resource_time"
            ),
            models.Index(fields=["integration", "received_at"], name="sb_event_app_received"),
            models.Index(
                fields=["integration", "state", "available_at", "received_at"],
                name="sb_event_app_queue",
            ),
            models.Index(
                fields=["integration", "resource", "membership_subject", "occurred_at"],
                name="sb_event_subject_time",
            ),
            models.Index(
                fields=["integration", "environment", "source", "actor", "occurred_at"],
                name="sb_event_actor_scope_time",
            ),
            models.Index(
                fields=["integration", "environment", "source", "resource", "occurred_at"],
                name="sb_event_resource_scope_time",
            ),
            models.Index(
                fields=["integration", "state", "processed_at"], name="sb_event_app_completion"
            ),
        ]


class SocStream(models.Model):
    """Separate bounded observation/detection files; never upstream acknowledgement."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    integration = models.ForeignKey(Integration, on_delete=models.PROTECT)
    channel = models.CharField(
        max_length=12,
        default="observation",
        choices=[("observation", "Source observations"), ("detection", "Forwarded detections")],
    )
    offset = models.PositiveIntegerField(default=0)
    prefix_sha256 = models.CharField(
        max_length=64, default="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    revision = models.PositiveIntegerField(default=0)
    selection_after = models.UUIDField(null=True)
    segmented_export = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["integration", "channel"], name="unique_soc_channel"),
            models.CheckConstraint(
                condition=Q(channel__in=["observation", "detection"]), name="valid_soc_channel"
            ),
        ]


class SocSegment(models.Model):
    """Retained enterprise output segment; sealing never deletes local evidence."""

    stream = models.ForeignKey(SocStream, on_delete=models.PROTECT, related_name="segments")
    number = models.PositiveSmallIntegerField()
    start_offset = models.PositiveIntegerField()
    byte_count = models.PositiveIntegerField(default=0)
    prefix_sha256 = models.CharField(
        max_length=64, default="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    sealed_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["stream", "number"], name="unique_soc_segment"),
            models.UniqueConstraint(
                fields=["stream"], condition=Q(sealed_at__isnull=True), name="one_open_soc_segment"
            ),
            models.CheckConstraint(
                condition=Q(number__lte=7, byte_count__lte=2097152), name="bounded_soc_segment"
            ),
        ]


class SocBatch(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    stream = models.ForeignKey(SocStream, on_delete=models.PROTECT)
    segment = models.ForeignKey(SocSegment, on_delete=models.PROTECT, null=True)
    body = models.TextField()
    body_sha256 = models.CharField(max_length=64)
    start_offset = models.PositiveIntegerField()
    record_count = models.PositiveIntegerField()
    state = models.CharField(max_length=16, default="staged")
    created_at = models.DateTimeField(auto_now_add=True)
    appended_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["stream"], condition=Q(state="staged"), name="one_staged_soc_batch"
            ),
            models.CheckConstraint(
                condition=Q(state__in=["staged", "file_appended"]), name="valid_soc_batch_state"
            ),
        ]


class SocDelivery(models.Model):
    event = models.OneToOneField(Event, on_delete=models.PROTECT)
    batch = models.ForeignKey(SocBatch, on_delete=models.PROTECT)


class ForwardedDetection(models.Model):
    """Immutable core-generated signal snapshot, distinct from native rediscovery."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    investigation = models.ForeignKey("Investigation", on_delete=models.PROTECT)
    batch = models.ForeignKey(SocBatch, on_delete=models.PROTECT)
    case_version = models.PositiveIntegerField()
    rule_version = models.CharField(max_length=40)
    evidence_sha256 = models.CharField(max_length=64)
    generation_source_sha256 = models.CharField(max_length=64)
    packet = models.JSONField()
    packet_sha256 = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=[
                    "investigation",
                    "evidence_sha256",
                    "generation_source_sha256",
                    "rule_version",
                ],
                name="unique_forwarded_detection_snapshot",
            )
        ]


class WazuhRecord(models.Model):
    """Sanitized operator-imported native-format record; runtime proof is separate."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    integration = models.ForeignKey(Integration, on_delete=models.PROTECT)
    collector_run = models.UUIDField()
    native_id = models.CharField(max_length=80)
    kind = models.CharField(max_length=8, choices=[("archive", "Archive"), ("alert", "Alert")])
    event = models.ForeignKey(Event, on_delete=models.PROTECT, null=True)
    signal = models.ForeignKey(ForwardedDetection, on_delete=models.PROTECT, null=True)
    rule_id = models.CharField(max_length=6, blank=True)
    rule_level = models.PositiveSmallIntegerField(null=True)
    occurred_at = models.DateTimeField()
    packet_sha256 = models.CharField(max_length=64)
    record_sha256 = models.CharField(max_length=64)
    imported_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["integration", "collector_run", "kind", "native_id"],
                name="unique_wazuh_native_record",
            ),
            models.CheckConstraint(
                condition=Q(event__isnull=False, signal__isnull=True)
                | Q(event__isnull=True, signal__isnull=False),
                name="one_wazuh_record_target",
            ),
            models.CheckConstraint(
                condition=Q(kind__in=["archive", "alert"]), name="valid_wazuh_record_kind"
            ),
        ]


class WazuhCursor(models.Model):
    """Persistent prefix checkpoint for bounded append-only native-format files."""

    integration = models.ForeignKey(Integration, on_delete=models.PROTECT)
    collector_run = models.UUIDField()
    kind = models.CharField(max_length=8, choices=[("archive", "Archive"), ("alert", "Alert")])
    segment = models.PositiveSmallIntegerField(default=0)
    offset = models.PositiveIntegerField(default=0)
    prefix_sha256 = models.CharField(
        max_length=64, default="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    physical_records = models.PositiveIntegerField(default=0)
    last_native_at = models.DateTimeField(null=True)
    last_import_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["integration", "collector_run", "kind"], name="unique_wazuh_cursor"
            ),
            models.CheckConstraint(
                condition=Q(kind__in=["archive", "alert"], segment__lte=7, offset__lte=4194304),
                name="bounded_wazuh_cursor",
            ),
        ]


class Investigation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    integration = models.ForeignKey(Integration, on_delete=models.PROTECT)
    rule = models.CharField(max_length=40)
    correlation = models.CharField(max_length=64)
    title = models.CharField(max_length=120)
    severity = models.CharField(max_length=12)
    explanation = models.TextField()
    status = models.CharField(max_length=20, default="open")
    version = models.PositiveIntegerField(default=1)
    events = models.ManyToManyField(Event)
    created_at = models.DateTimeField(auto_now_add=True)
    assignee = models.ForeignKey(Membership, on_delete=models.SET_NULL, null=True, blank=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="acknowledged_cases",
    )
    due_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["integration", "rule", "correlation"], name="unique_case"
            )
        ]


class Note(models.Model):
    investigation = models.ForeignKey(Investigation, on_delete=models.PROTECT)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    text = models.CharField(max_length=2000)
    created_at = models.DateTimeField(auto_now_add=True)
    kind = models.CharField(
        max_length=20,
        default="general",
        choices=[
            ("general", "General / earlier note"),
            ("observed_fact", "Observed fact"),
            ("interpretation", "Analyst interpretation"),
            ("uncertainty", "Uncertainty"),
            ("remediation", "Remediation plan"),
            ("verification", "Verification note"),
        ],
    )


class CaseTask(models.Model):
    """A review/remediation task; completion alone is not a verified security fix."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    investigation = models.ForeignKey(Investigation, on_delete=models.PROTECT, related_name="tasks")
    kind = models.CharField(
        max_length=12, choices=[("review", "Review"), ("remediation", "Remediation")]
    )
    title = models.CharField(max_length=160)
    status = models.CharField(
        max_length=16,
        default="open",
        choices=[
            ("open", "Open"),
            ("in_progress", "In progress"),
            ("awaiting_retest", "Awaiting retest"),
            ("verified", "Verified in recorded lab"),
        ],
    )
    assignee = models.ForeignKey(Membership, on_delete=models.SET_NULL, null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True)
    case_version = models.PositiveIntegerField()
    evidence_sha256 = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(kind__in=["review", "remediation"]), name="valid_case_task_kind"
            ),
            models.CheckConstraint(
                condition=Q(status__in=["open", "in_progress", "awaiting_retest", "verified"]),
                name="valid_case_task_state",
            ),
        ]


class ServiceCredential(models.Model):
    """One app and one machine capability. The secret exists only at runtime."""

    integration = models.ForeignKey(Integration, on_delete=models.PROTECT)
    key_id = models.CharField(max_length=64, unique=True)
    secret_env = models.CharField(max_length=100, unique=True)
    active = models.BooleanField(default=True)
    capability = models.CharField(
        max_length=24,
        choices=[
            ("read_case_evidence", "Read case evidence"),
            ("create_review_task", "Create review task"),
        ],
    )

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(capability__in=["read_case_evidence", "create_review_task"]),
                name="valid_service_capability",
            )
        ]


class ServiceNonce(models.Model):
    credential = models.ForeignKey(ServiceCredential, on_delete=models.CASCADE)
    nonce = models.UUIDField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["credential", "nonce"], name="unique_service_nonce")
        ]
        indexes = [models.Index(fields=["credential", "created_at"], name="sb_service_nonce_time")]


class ServiceRequest(models.Model):
    credential = models.ForeignKey(ServiceCredential, on_delete=models.PROTECT)
    idempotency_key = models.UUIDField()
    request_sha256 = models.CharField(max_length=64)
    task = models.OneToOneField(CaseTask, on_delete=models.PROTECT)
    response = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["credential", "idempotency_key"],
                name="unique_service_request",
            )
        ]


class Audit(models.Model):
    integration = models.ForeignKey(Integration, on_delete=models.PROTECT)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True)
    action = models.CharField(max_length=40)
    object_id = models.CharField(max_length=64)
    detail = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)


class Replay(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    integration = models.ForeignKey(Integration, on_delete=models.PROTECT)
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="proposals"
    )
    policy = models.CharField(max_length=20)
    dataset_hash = models.CharField(max_length=64)
    engine_hash = models.CharField(max_length=64)
    result = models.JSONField()
    status = models.CharField(max_length=12, default="pending")
    version = models.PositiveIntegerField(default=1)
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        related_name="reviews",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True)


class CheckRun(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    integration = models.ForeignKey(Integration, on_delete=models.PROTECT)
    suite = models.CharField(max_length=80)
    revision = models.CharField(max_length=64)
    digest = models.CharField(max_length=64, unique=True)
    result = models.JSONField()
    status = models.CharField(max_length=12)
    created_at = models.DateTimeField(auto_now_add=True)


class CaseVerification(models.Model):
    """A scoped, historical retest decision; never current deployment health."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    task = models.ForeignKey(CaseTask, on_delete=models.PROTECT, related_name="verifications")
    check_run = models.ForeignKey(CheckRun, on_delete=models.PROTECT)
    case_version = models.PositiveIntegerField()
    evidence_sha256 = models.CharField(max_length=64)
    check_digest = models.CharField(max_length=64)
    status = models.CharField(
        max_length=12,
        default="pending",
        choices=[
            ("pending", "Awaiting review"),
            ("approved", "Approved"),
            ("rejected", "Rejected"),
        ],
    )
    submitted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="submitted_verifications"
    )
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        related_name="reviewed_verifications",
    )
    rationale = models.CharField(max_length=1000, blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["task", "check_run", "case_version"], name="unique_case_retest_submission"
            ),
            models.CheckConstraint(
                condition=Q(
                    status="pending", reviewer__isnull=True, decided_at__isnull=True, rationale=""
                )
                | (
                    Q(
                        status__in=["approved", "rejected"],
                        reviewer__isnull=False,
                        decided_at__isnull=False,
                    )
                    & ~Q(rationale="")
                ),
                name="valid_case_verification_decision",
            ),
            models.CheckConstraint(
                condition=Q(reviewer__isnull=True) | ~Q(reviewer=models.F("submitted_by")),
                name="independent_case_verification_reviewer",
            ),
        ]


class LoginAttempt(models.Model):
    fingerprint = models.CharField(max_length=64, unique=True)
    window_start = models.DateTimeField()
    failures = models.PositiveIntegerField(default=0)


class FederatedIdentity(models.Model):
    """Explicit private identity link; provider claims never provision local roles."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    issuer = models.CharField(max_length=255)
    subject = models.CharField(max_length=255)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    enabled = models.BooleanField(default=True)
    version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["issuer", "subject"], name="sb_identity_issuer_subject"
            ),
            models.CheckConstraint(
                condition=Q(version__gte=1), name="sb_identity_version_positive"
            ),
        ]


class FederatedSession(models.Model):
    """Revocable local admission, retaining no provider token or browser cookie."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    identity = models.ForeignKey(FederatedIdentity, on_delete=models.PROTECT)
    identity_version = models.PositiveIntegerField()
    binding_digest = models.CharField(max_length=64, unique=True)
    provider_session_digest = models.CharField(max_length=64, blank=True, default="")
    created_at = models.DateTimeField()
    authenticated_at = models.DateTimeField()
    expires_at = models.DateTimeField(db_index=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(expires_at__gt=models.F("created_at")), name="sb_sso_positive_lifetime"
            ),
            models.CheckConstraint(
                condition=Q(expires_at__lte=models.F("created_at") + timedelta(minutes=15)),
                name="sb_sso_max_lifetime",
            ),
            models.CheckConstraint(
                condition=Q(identity_version__gte=1), name="sb_sso_link_version"
            ),
        ]


class FederatedExchange(models.Model):
    """One-time OIDC callback admission; no code, verifier, nonce or cookie."""

    state_digest = models.CharField(max_length=64, primary_key=True)
    browser_digest = models.CharField(max_length=64)
    issuer_digest = models.CharField(max_length=64)
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField(db_index=True)
    consumed_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(expires_at__gt=models.F("created_at"))
                & Q(expires_at__lte=models.F("created_at") + timedelta(minutes=5)),
                name="sb_exchange_lifetime",
            ),
        ]


class FederatedLogoutNotice(models.Model):
    """Replay and re-admission barrier; provider identifiers are keyed digests."""

    token_digest = models.CharField(max_length=64, primary_key=True)
    scope_digest = models.CharField(max_length=64)
    received_at = models.DateTimeField()
    block_until = models.DateTimeField(db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=["scope_digest", "block_until"], name="sb_logout_scope_expiry")
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(block_until__gt=models.F("received_at")),
                name="sb_logout_block_lifetime",
            ),
        ]


class FederatedFlowWindow(models.Model):
    """Fixed global admission slots; no unbounded labels or per-person records."""

    operation = models.CharField(max_length=12, primary_key=True)
    window_start = models.DateTimeField()
    requests = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(operation__in=["login", "logout", "protocol"]),
                name="sb_federated_window_scope",
            )
        ]


class IdentityAudit(models.Model):
    """Closed identity audit without email, subject, token, cookie or claim payloads."""

    identity = models.ForeignKey(FederatedIdentity, on_delete=models.PROTECT)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True)
    session_id = models.UUIDField(null=True)
    action = models.CharField(
        max_length=24,
        choices=[
            ("link.provisioned", "Link provisioned"),
            ("link.disabled", "Link disabled"),
            ("link.enabled", "Link enabled"),
            ("session.issued", "Session issued"),
            ("session.revoked", "Session revoked"),
            ("account.recovered", "Local account recovery"),
        ],
    )
    origin = models.CharField(
        max_length=24,
        choices=[
            ("local_operator", "Trusted local database operator"),
            ("validated_oidc", "Validated OIDC admission"),
            ("local_session", "Local browser session"),
            ("provider_logout", "Validated provider logout"),
        ],
    )
    identity_version = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(
                    action__in=[
                        "link.provisioned",
                        "link.disabled",
                        "link.enabled",
                        "session.issued",
                        "session.revoked",
                        "account.recovered",
                    ]
                ),
                name="sb_identity_audit_action",
            ),
            models.CheckConstraint(
                condition=Q(
                    origin__in=[
                        "local_operator",
                        "validated_oidc",
                        "local_session",
                        "provider_logout",
                    ]
                ),
                name="sb_identity_audit_origin",
            ),
        ]


class WorkerHeartbeat(models.Model):
    name = models.CharField(max_length=40, unique=True)
    last_seen = models.DateTimeField()


class MetricsScrapeState(models.Model):
    """One admission row for the separately authenticated read-only exporter."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    last_started_at = models.DateTimeField()

    class Meta:
        constraints = [models.CheckConstraint(condition=Q(id=1), name="sb_metrics_singleton")]


class ScanRun(models.Model):
    """An imported report, with provenance separate from the report's own claims."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    integration = models.ForeignKey(Integration, on_delete=models.PROTECT)
    format = models.CharField(max_length=16)
    tool = models.CharField(max_length=100)
    tool_version = models.CharField(max_length=80, blank=True)
    digest = models.CharField(max_length=64)
    identity_digest = models.CharField(max_length=64, unique=True)
    provenance = models.CharField(
        max_length=24,
        choices=[("claimed_report", "Imported report"), ("local_execution", "Local execution")],
    )
    source_revision = models.CharField(max_length=64, blank=True)
    manifest = models.JSONField(default=dict)
    execution = models.JSONField(default=dict)
    coverage_status = models.CharField(max_length=16)
    input_count = models.PositiveIntegerField(default=0)
    skipped_count = models.PositiveIntegerField(default=0)
    suppressed_count = models.PositiveIntegerField(default=0)
    finding_count = models.PositiveIntegerField(default=0)
    imported_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [models.Index(fields=["integration", "tool", "created_at"])]


class Finding(models.Model):
    """An app/tool-scoped review item; a later scan never silently closes it."""

    STATUS_CHOICES = [
        ("open", "Open"),
        ("reviewed", "Reviewed"),
        ("accepted_risk", "Accepted risk"),
        ("false_positive", "False positive"),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    integration = models.ForeignKey(Integration, on_delete=models.PROTECT)
    tool = models.CharField(max_length=100)
    fingerprint = models.CharField(max_length=64)
    severity = models.CharField(max_length=16)
    rule_id = models.CharField(max_length=160)
    title = models.CharField(max_length=240)
    path = models.CharField(max_length=500, blank=True)
    line = models.PositiveIntegerField(null=True, blank=True)
    package = models.CharField(max_length=160, blank=True)
    package_version = models.CharField(max_length=100, blank=True)
    fix_versions = models.JSONField(default=list)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="open")
    version = models.PositiveIntegerField(default=1)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["integration", "tool", "fingerprint"], name="unique_app_tool_finding"
            ),
            models.CheckConstraint(
                condition=Q(status__in=["open", "reviewed", "accepted_risk", "false_positive"]),
                name="valid_finding_status",
            ),
        ]
        indexes = [models.Index(fields=["integration", "status", "last_seen"])]


class FindingObservation(models.Model):
    """The normalized report facts at import time; no source snippets are kept."""

    scan_run = models.ForeignKey(ScanRun, on_delete=models.PROTECT, related_name="observations")
    finding = models.ForeignKey(Finding, on_delete=models.PROTECT, related_name="observations")
    severity = models.CharField(max_length=16)
    rule_id = models.CharField(max_length=160)
    title = models.CharField(max_length=240)
    path = models.CharField(max_length=500, blank=True)
    line = models.PositiveIntegerField(null=True, blank=True)
    package = models.CharField(max_length=160, blank=True)
    package_version = models.CharField(max_length=100, blank=True)
    fix_versions = models.JSONField(default=list)
    suppressed = models.BooleanField(default=False)
    suppression_statuses = models.JSONField(default=list)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["scan_run", "finding"], name="unique_scan_finding")
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("Finding observations cannot be edited.")
        return super().save(*args, **kwargs)

    @property
    def snapshot(self):
        return {
            field: getattr(self, field)
            for field in (
                "severity",
                "rule_id",
                "title",
                "path",
                "line",
                "package",
                "package_version",
                "fix_versions",
                "suppressed",
                "suppression_statuses",
            )
        }


class PracticeSession(models.Model):
    """Owner-private tabletop records; never contribute to security coverage."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    integration = models.ForeignKey(Integration, on_delete=models.PROTECT)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    scenario = models.CharField(max_length=40)
    snapshot = models.JSONField()
    snapshot_hash = models.CharField(max_length=64)
    status = models.CharField(max_length=12, default="draft")
    version = models.PositiveIntegerField(default=1)
    revealed = models.JSONField(default=list)
    decision = models.JSONField(default=dict)
    review = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    submitted_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(status__in=["draft", "submitted"]), name="valid_practice_status"
            )
        ]
        indexes = [
            models.Index(fields=["author", "integration", "-created_at"], name="sb_practice_owner")
        ]


class PracticeEntry(models.Model):
    session = models.ForeignKey(PracticeSession, on_delete=models.PROTECT, related_name="entries")
    version = models.PositiveIntegerField()
    action = models.CharField(max_length=12)
    content = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["session", "version"], name="unique_practice_version")
        ]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("Practice history cannot be edited.")
        return super().save(*args, **kwargs)


class LeaverSignal(models.Model):
    """A verified AccessOps leaver event (SSF Security Event Token), stored before its ack."""

    EVENT_TYPES = [
        ("account_disabled", "Account disabled"),
        ("session_revoked", "Sessions revoked"),
        ("session_established", "Sign-in after departure"),
    ]
    jti = models.CharField(max_length=32, primary_key=True)
    txn = models.CharField(max_length=128, blank=True, default="")
    event_type = models.CharField(max_length=24, choices=EVENT_TYPES)
    subject_issuer = models.CharField(max_length=255)
    subject_id = models.CharField(max_length=255)
    event_at = models.DateTimeField()
    issued_at = models.DateTimeField()
    initiating_entity = models.CharField(max_length=16, blank=True, default="")
    reason = models.CharField(max_length=200, blank=True, default="")
    key_id = models.CharField(max_length=64)
    token = models.TextField()
    token_sha256 = models.CharField(max_length=64)
    facts_sha256 = models.CharField(max_length=64)
    received_at = models.DateTimeField()
    cases = models.ManyToManyField(Investigation, related_name="leaver_signals", blank=True)

    class Meta:
        indexes = [
            models.Index(
                fields=["subject_issuer", "subject_id", "event_type"], name="sb_leaver_subject"
            )
        ]
