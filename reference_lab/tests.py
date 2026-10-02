"""Actual Django auth/authorization paths with a memory-only source DB.

These are portable regressions. Native HTTP/PostgreSQL proof remains separate.
"""

import json
import os
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.db import IntegrityError, transaction
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from bridge.contract import canonical, signature, validate_event
from bridge.models import IngestKey, Integration, Investigation
from bridge.worker import drain

from .authorization import change_permission, read_resource
from .models import BoundedFault, Grant, Outbox, Resource
from .seed import ACCOUNTS, CONTENT, DOCUMENT_ID, EXPENSE_ID, seed_accounts, set_regression
from .telemetry import pseudonym

PASSWORDS = {name: "nonfunctional-reference-test-only-" + name + "x" * 32 for name in ACCOUNTS}
KEY = "nonfunctional-reference-test-only-" + "x" * 48


class ReferenceApplicationTests(TestCase):
    def setUp(self):
        self.environment = patch.dict(
            os.environ,
            {
                "SB_REF_PSEUDO_DOCUMENTS": KEY,
                "SB_REF_PSEUDO_EXPENSES": KEY + "different",
                "SB_REF_DELIVERY_DOCUMENTS": KEY,
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.users = seed_accounts(PASSWORDS)
        self.member = self.users["document_member"]
        self.owner = self.users["operator"]

    def change(self, granted=False, user=None, kind="group"):
        return change_permission(
            "documents", DOCUMENT_ID, self.owner.pk, (user or self.member).pk, kind, granted
        )

    def test_native_auth_path_retains_session_across_permission_change(self):
        member = Client(enforce_csrf_checks=True)
        login = member.get("/login/")
        self.assertEqual(login.status_code, 200)
        token = member.cookies["csrftoken"].value
        self.assertEqual(
            member.post(
                "/login/",
                {"username": "document_member", "password": PASSWORDS["document_member"]},
                HTTP_X_CSRFTOKEN=token,
            ).status_code,
            200,
        )
        session = member.cookies["sessionid"].value
        path = f"/apps/documents/resources/{DOCUMENT_ID}/"
        allowed = member.get(path)
        self.assertEqual(allowed.json()["synthetic_content"], CONTENT["documents"])
        self.change()
        self.assertEqual(member.get("/identity/").json()["account"], "document_member")
        self.assertEqual(member.cookies["sessionid"].value, session)
        self.assertEqual(member.get(path).status_code, 403)
        self.assertEqual(
            read_resource("documents", DOCUMENT_ID, self.owner.pk), CONTENT["documents"]
        )
        self.change(granted=True)
        self.assertEqual(member.get(path).json()["synthetic_content"], CONTENT["documents"])
        self.assertEqual(
            [
                event.payload["outcome"]
                for event in Outbox.objects.filter(
                    payload__operation="private_record.read"
                ).order_by("created_at")
            ],
            ["allowed", "denied", "allowed", "allowed"],
        )

    def test_membership_change_and_outbox_are_atomic_when_telemetry_fails(self):
        with (
            patch(
                "reference_lab.authorization.emit",
                side_effect=RuntimeError("Synthetic outbox failure"),
            ),
            self.assertRaises(RuntimeError),
        ):
            self.change()
        self.assertTrue(Grant.objects.filter(resource_id=DOCUMENT_ID, user=self.member).exists())
        self.assertFalse(Outbox.objects.exists())

    def test_read_cannot_return_content_when_its_observation_cannot_commit(self):
        with (
            patch(
                "reference_lab.authorization.emit",
                side_effect=RuntimeError("Synthetic observation failure"),
            ),
            self.assertRaises(RuntimeError),
        ):
            read_resource("documents", DOCUMENT_ID, self.member.pk)
        self.assertFalse(Outbox.objects.exists())

    def test_direct_grant_and_owner_controls_do_not_assert_false_removals(self):
        self.change(granted=True, kind="direct")
        self.assertFalse(self.change()["effective_access_changed"])
        self.assertEqual(
            read_resource("documents", DOCUMENT_ID, self.member.pk), CONTENT["documents"]
        )
        self.assertFalse(Outbox.objects.filter(payload__operation="membership.change").exists())
        self.assertTrue(self.change(kind="direct")["effective_access_changed"])
        self.assertEqual(
            Outbox.objects.get(payload__operation="membership.change").payload["membership"][
                "state"
            ],
            "removed",
        )
        self.assertFalse(self.change(user=self.owner)["effective_access_changed"])
        self.assertEqual(
            read_resource("documents", DOCUMENT_ID, self.owner.pk), CONTENT["documents"]
        )

    def test_cross_app_and_outsider_access_cannot_retrieve_known_records(self):
        self.assertIsNone(read_resource("expenses", EXPENSE_ID, self.member.pk))
        self.assertIsNone(read_resource("documents", DOCUMENT_ID, self.users["outsider"].pk))
        with self.assertRaises(Resource.DoesNotExist):
            read_resource("expenses", DOCUMENT_ID, self.member.pk)
        self.assertEqual(
            read_resource("expenses", EXPENSE_ID, self.users["expense_member"].pk),
            CONTENT["expenses"],
        )

    def test_non_owner_and_disabled_owner_cannot_change_permissions(self):
        for operator in (self.member, self.users["outsider"]):
            with self.subTest(operator=operator.username), self.assertRaises(PermissionDenied):
                change_permission(
                    "documents", DOCUMENT_ID, operator.pk, self.member.pk, "group", False
                )
        get_user_model().objects.filter(pk=self.owner.pk).update(is_active=False)
        with self.assertRaises(PermissionDenied):
            self.change()
        self.assertFalse(Outbox.objects.exists())

    def test_membership_observation_is_closed_metadata_with_stable_app_scope(self):
        self.change()
        payload = Outbox.objects.get().payload
        validate_event(payload, "documents")
        self.assertEqual(
            payload["membership"]["subject"], pseudonym("documents", "account", self.member.pk)
        )
        self.assertNotEqual(
            pseudonym("documents", "account", self.member.pk),
            pseudonym("expenses", "account", self.member.pk),
        )
        serialized = json.dumps(payload)
        for forbidden in (
            CONTENT["documents"],
            self.member.username,
            PASSWORDS["document_member"],
            KEY,
        ):
            self.assertNotIn(forbidden, serialized)

    def test_fixed_regression_expires_and_resets_with_restoration_controls(self):
        self.change()
        set_regression(True, duration_seconds=60)
        self.assertEqual(
            read_resource("documents", DOCUMENT_ID, self.member.pk), CONTENT["documents"]
        )
        set_regression(False)
        self.assertIsNone(read_resource("documents", DOCUMENT_ID, self.member.pk))
        self.assertEqual(
            read_resource("documents", DOCUMENT_ID, self.owner.pk), CONTENT["documents"]
        )
        self.change(granted=True)
        self.assertEqual(
            read_resource("documents", DOCUMENT_ID, self.member.pk), CONTENT["documents"]
        )
        self.change()
        set_regression(True, duration_seconds=60)
        now = timezone.now()
        BoundedFault.objects.update(
            started_at=now - timedelta(seconds=120), expires_at=now - timedelta(seconds=60)
        )
        self.assertIsNone(read_resource("documents", DOCUMENT_ID, self.member.pk))
        for duration in (0, 601, True):
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                set_regression(True, duration)

    def test_fault_cannot_restore_access_for_a_disabled_account(self):
        self.change()
        set_regression(True)
        get_user_model().objects.filter(pk=self.member.pk).update(is_active=False)
        with self.assertRaises(PermissionDenied):
            read_resource("documents", DOCUMENT_ID, self.member.pk)

    def test_database_rejects_unbounded_fault_and_duplicate_grants(self):
        now = timezone.now()
        with self.assertRaises(IntegrityError), transaction.atomic():
            BoundedFault.objects.create(
                resource_id=DOCUMENT_ID,
                user=self.member,
                enabled=True,
                started_at=now,
                expires_at=now + timedelta(hours=1),
            )
        with self.assertRaises(IntegrityError), transaction.atomic():
            Grant.objects.create(resource_id=DOCUMENT_ID, user=self.member, kind="group")

    def test_browser_permission_mutation_requires_csrf(self):
        owner = Client(enforce_csrf_checks=True)
        owner.force_login(self.owner)
        response = owner.post(
            f"/apps/documents/resources/{DOCUMENT_ID}/permission/",
            json.dumps({"subject": "document_member", "kind": "group", "granted": False}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Grant.objects.filter(resource_id=DOCUMENT_ID, user=self.member).exists())

    def test_login_rejects_bad_credentials_and_disabled_account(self):
        self.assertEqual(
            self.client.post(
                "/login/", {"username": "document_member", "password": "bad"}
            ).status_code,
            401,
        )
        get_user_model().objects.filter(pk=self.member.pk).update(is_active=False)
        self.assertEqual(
            self.client.post(
                "/login/", {"username": "document_member", "password": PASSWORDS["document_member"]}
            ).status_code,
            401,
        )
        for _ in range(18):
            self.client.post("/login/", {"username": "document_member", "password": "bad"})
        self.assertEqual(
            self.client.post(
                "/login/", {"username": "document_member", "password": PASSWORDS["document_member"]}
            ).status_code,
            429,
        )

    def test_observed_bounded_regression_enters_existing_detector_without_suspicious_label(self):
        app = Integration.objects.create(slug="documents", name="Private document lab")
        IngestKey.objects.create(
            integration=app,
            key_id="reference-documents",
            secret_env="SB_REF_DELIVERY_DOCUMENTS",
            can_assert_membership=True,
            source="instrumented_lab",
        )
        self.change()
        set_regression(True)
        read_resource("documents", DOCUMENT_ID, self.member.pk)
        set_regression(False)
        self.assertEqual(Outbox.objects.order_by("created_at").last().payload["reason"], "member")
        with override_settings(ROOT_URLCONF="config.urls"):
            for event in Outbox.objects.order_by("created_at"):
                raw, at = canonical(event.payload), timezone.now().isoformat()
                response = self.client.post(
                    "/api/v1/events/documents/",
                    raw,
                    content_type="application/json",
                    HTTP_X_SB_KEY="reference-documents",
                    HTTP_X_SB_TIME=at,
                    HTTP_X_SB_SIGNATURE=signature(KEY, "documents", "reference-documents", at, raw),
                )
                self.assertEqual(response.status_code, 202)
            drain()
        case = Investigation.objects.get()
        self.assertEqual((case.rule, case.severity, case.events.count()), ("R3", "high", 2))
        self.assertEqual(set(case.events.values_list("source", flat=True)), {"instrumented_lab"})

    def test_seed_and_fault_refuse_main_console_profile(self):
        with override_settings(ROOT_URLCONF="config.urls"), self.assertRaises(ImproperlyConfigured):
            set_regression(True)
        with self.assertRaises(ValueError):
            seed_accounts(PASSWORDS)
