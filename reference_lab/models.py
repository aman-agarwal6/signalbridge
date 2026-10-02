import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.db.models import F, Q

APP_CHOICES = [("documents", "Private documents"), ("expenses", "Expense records")]


class Resource(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    app = models.CharField(max_length=12, choices=APP_CHOICES)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    label = models.CharField(max_length=80)
    synthetic_content = models.CharField(max_length=512)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(app__in=["documents", "expenses"]), name="ref_valid_app"
            )
        ]


class Grant(models.Model):
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    kind = models.CharField(max_length=8, choices=[("group", "Group"), ("direct", "Direct")])

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["resource", "user", "kind"], name="ref_unique_grant"),
            models.CheckConstraint(
                condition=Q(kind__in=["group", "direct"]), name="ref_valid_grant"
            ),
        ]


class Outbox(models.Model):
    """Source-owned durable event; created in the source authorization transaction."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    app = models.CharField(max_length=12, choices=APP_CHOICES)
    payload = models.JSONField()
    digest = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    state = models.CharField(max_length=12, default="pending")
    attempts = models.PositiveIntegerField(default=0)
    available_at = models.DateTimeField()
    acknowledged_at = models.DateTimeField(null=True)
    error_code = models.CharField(max_length=32, blank=True)
    lease_token = models.UUIDField(null=True)
    leased_until = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(app__in=["documents", "expenses"]), name="ref_outbox_app"
            ),
            models.CheckConstraint(
                condition=Q(state__in=["pending", "acknowledged", "dead"]), name="ref_outbox_state"
            ),
            models.CheckConstraint(
                condition=Q(lease_token__isnull=True, leased_until__isnull=True)
                | Q(lease_token__isnull=False, leased_until__isnull=False),
                name="ref_outbox_lease_pair",
            ),
        ]
        indexes = [
            models.Index(fields=["state", "available_at", "created_at"], name="ref_outbox_queue")
        ]


class BoundedFault(models.Model):
    """One operator-created synthetic account/resource bypass with a finite expiry."""

    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    enabled = models.BooleanField(default=False)
    started_at = models.DateTimeField()
    expires_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["resource", "user"], name="ref_unique_fault"),
            models.CheckConstraint(
                condition=Q(expires_at__gt=F("started_at"))
                & Q(expires_at__lte=F("started_at") + timedelta(minutes=10)),
                name="ref_bounded_fault",
            ),
        ]


class LoginAttempt(models.Model):
    """Global bounded lab login window, with no password or supplied username."""

    occurred_at = models.DateTimeField(auto_now_add=True)
