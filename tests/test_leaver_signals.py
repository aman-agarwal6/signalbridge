"""AccessOps leaver signals: receive, store-then-acknowledge, refuse, and open cases.

Signature verification itself is checked with real ES256 keys in
integrations.ssf.signature_tests; these tests replace only the verifier.
"""

import base64
import json
import tempfile
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings

from bridge.leaver import RULE_CONSOLE, RULE_REPORTED, departed_subjects, detect, workspace
from bridge.leaver_receiver import Receiver
from bridge.models import (
    FederatedIdentity,
    FederatedSession,
    Investigation,
    LeaverSignal,
    Membership,
)
from integrations.ssf import tokens

WORKFORCE = "https://id.accessops.test:8443/realms/accessops-workforce"
NOW = 1_791_172_800
KID = "test-kid"


def b64(value):
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_token(event, *, jti, sub="worker-1", at=NOW - 60, header=None, **changes):
    claims = {
        "iss": tokens.ISSUER,
        "aud": tokens.AUDIENCE,
        "iat": NOW - 30,
        "jti": jti,
        "txn": "t" + jti[:16],
        "sub_id": {"format": "iss_sub", "iss": WORKFORCE, "sub": sub},
        "events": {event: {"event_timestamp": at}},
    }
    claims.update(changes)
    head = header or {"typ": "secevent+jwt", "alg": "ES256", "kid": KID}
    return b64(head) + "." + b64(claims) + "." + b64(b"\0" * 64)


def jti(n):
    return f"{n:032x}"


class FakeTransmitter:
    """In-memory RFC 8936 transmitter that checks acknowledgements follow storage."""

    def __init__(self, sets, *, metadata=None):
        self.pending = dict(sets)
        self.calls = []
        self.jwks_calls = 0
        self.fail_on_ack = False
        self.metadata = metadata or {
            "issuer": tokens.ISSUER,
            "jwks_uri": tokens.ISSUER + "/api/v1/ssf/jwks",
            "delivery_methods_supported": ["urn:ietf:rfc:8936"],
        }

    def configuration(self):
        return self.metadata

    def jwks(self):
        self.jwks_calls += 1
        return {"keys": []}

    def poll(self, token, *, max_events, ack=(), set_errs=None):
        set_errs = set_errs or {}
        self.calls.append({"max": max_events, "ack": list(ack), "errs": dict(set_errs)})
        if ack and self.fail_on_ack:
            from integrations.ssf.transport import TransmitterError

            raise TransmitterError("simulated failure before the acknowledgement arrived")
        for acked in ack:
            assert LeaverSignal.objects.filter(jti=acked).exists(), "acked before storage"
            self.pending.pop(acked, None)
        for refused in set_errs:
            self.pending.pop(refused, None)
        offered = dict(list(self.pending.items())[:max_events])
        return offered, len(self.pending) > len(offered)


def receiver(transmitter, **options):
    options.setdefault("verifier", lambda signing_input, signature, key: None)
    options.setdefault("keys_from", lambda jwks: {KID: object()})
    options.setdefault("clock", lambda: NOW)
    return Receiver(transmitter, "receiver-token-value", **options)


class ReceiveTests(TestCase):
    def test_signals_are_stored_before_they_are_acknowledged(self):
        sets = {
            jti(1): make_token(tokens.ACCOUNT_DISABLED, jti=jti(1)),
            jti(2): make_token(tokens.SESSION_REVOKED, jti=jti(2)),
            jti(3): make_token(tokens.SESSION_ESTABLISHED, jti=jti(3), at=NOW - 20),
        }
        transmitter = FakeTransmitter(sets)
        run = receiver(transmitter).run()
        self.assertEqual(LeaverSignal.objects.count(), 3)
        self.assertEqual(run.acknowledged, 3)
        self.assertTrue(run.drained)
        self.assertEqual(transmitter.calls[0]["ack"], [])
        self.assertEqual(sorted(transmitter.calls[1]["ack"]), [jti(1), jti(2), jti(3)])
        self.assertEqual(transmitter.pending, {})

    def test_a_redelivered_token_is_stored_once_and_acknowledged(self):
        from integrations.ssf.transport import TransmitterError

        token = make_token(tokens.ACCOUNT_DISABLED, jti=jti(7))
        first = FakeTransmitter({jti(7): token})
        first.fail_on_ack = True
        with self.assertRaises(TransmitterError):
            receiver(first).run()
        self.assertEqual(LeaverSignal.objects.count(), 1)  # stored, never acknowledged
        again = FakeTransmitter({jti(7): token})
        run = receiver(again).run()
        self.assertEqual(LeaverSignal.objects.count(), 1)
        self.assertEqual(run.counts["duplicate"], 1)
        self.assertEqual(again.pending, {})

    def test_refused_tokens_are_reported_with_rfc8935_codes_and_not_stored(self):
        cases = {
            jti(11): (
                make_token(tokens.ACCOUNT_DISABLED, jti=jti(11), iss="https://evil.test"),
                "invalid_issuer",
            ),
            jti(12): (
                make_token(tokens.ACCOUNT_DISABLED, jti=jti(12), aud="urn:other"),
                "invalid_audience",
            ),
            jti(13): (
                make_token(
                    tokens.ACCOUNT_DISABLED,
                    jti=jti(13),
                    header={"typ": "JWT", "alg": "ES256", "kid": KID},
                ),
                "invalid_request",
            ),
            jti(14): (
                make_token(
                    tokens.ACCOUNT_DISABLED,
                    jti=jti(14),
                    header={"typ": "secevent+jwt", "alg": "HS256", "kid": KID},
                ),
                "invalid_key",
            ),
            jti(15): (
                make_token(
                    tokens.ACCOUNT_DISABLED,
                    jti=jti(15),
                    header={
                        "typ": "secevent+jwt",
                        "alg": "ES256",
                        "kid": KID,
                        "jku": "https://evil.test/k",
                    },
                ),
                "invalid_request",
            ),
            jti(16): (
                make_token(tokens.ACCOUNT_DISABLED, jti=jti(16), email="a@b.test"),
                "invalid_request",
            ),
            jti(17): (
                make_token(
                    tokens.SESSION_ESTABLISHED,
                    jti=jti(17),
                    events={
                        tokens.SESSION_ESTABLISHED: {"event_timestamp": NOW, "ips": ["192.0.2.1"]}
                    },
                ),
                "invalid_request",
            ),
            jti(18): (make_token(tokens.ACCOUNT_DISABLED, jti=jti(99)), "invalid_request"),
            jti(19): (
                make_token(
                    "https://schemas.openid.net/secevent/risc/event-type/account-purged",
                    jti=jti(19),
                ),
                "invalid_request",
            ),
            jti(20): (
                make_token(tokens.ACCOUNT_DISABLED, jti=jti(20), at=NOW + 3600),
                "invalid_request",
            ),
        }
        transmitter = FakeTransmitter({key: value[0] for key, value in cases.items()})
        run = receiver(transmitter).run()
        reported = transmitter.calls[1]["errs"]
        self.assertEqual(
            {key: value["err"] for key, value in reported.items()},
            {key: value[1] for key, value in cases.items()},
        )
        self.assertEqual(LeaverSignal.objects.count(), 0)
        self.assertEqual(run.reported, len(cases))
        self.assertTrue(all(len(value["description"]) <= 200 for value in reported.values()))

    def test_an_unknown_key_is_refetched_at_most_once_per_minute(self):
        clock = [100.0]
        sets = {
            jti(n): make_token(
                tokens.ACCOUNT_DISABLED,
                jti=jti(n),
                header={"typ": "secevent+jwt", "alg": "ES256", "kid": "rotated"},
            )
            for n in (21, 22, 23)
        }
        transmitter = FakeTransmitter(sets)
        run = receiver(transmitter, monotonic=lambda: clock[0]).run()
        self.assertEqual(transmitter.jwks_calls, 2)  # initial fetch plus one refetch
        self.assertEqual(run.errors["invalid_key"], 3)
        self.assertFalse(run.refresh_keys(unknown_kid=True))
        clock[0] += 61
        self.assertTrue(run.refresh_keys(unknown_kid=True))
        self.assertEqual(transmitter.jwks_calls, 3)

    def test_a_rotated_key_found_on_refetch_is_accepted(self):
        published = [{KID: object()}, {KID: object(), "rotated": object()}]
        token = make_token(
            tokens.ACCOUNT_DISABLED,
            jti=jti(25),
            header={"typ": "secevent+jwt", "alg": "ES256", "kid": "rotated"},
        )
        run = receiver(
            FakeTransmitter({jti(25): token}), keys_from=lambda jwks: published.pop(0)
        ).run()
        self.assertEqual(run.counts["stored"], 1)

    def test_a_reused_jti_with_different_facts_is_refused_and_the_original_kept(self):
        receiver(FakeTransmitter({jti(31): make_token(tokens.ACCOUNT_DISABLED, jti=jti(31))})).run()
        transmitter = FakeTransmitter(
            {jti(31): make_token(tokens.ACCOUNT_DISABLED, jti=jti(31), sub="someone-else")}
        )
        run = receiver(transmitter).run()
        self.assertEqual(run.errors["jti_conflict"], 1)
        self.assertEqual(LeaverSignal.objects.get(jti=jti(31)).subject_id, "worker-1")

    def test_a_dry_run_neither_stores_acknowledges_nor_reports(self):
        transmitter = FakeTransmitter(
            {
                jti(41): make_token(tokens.ACCOUNT_DISABLED, jti=jti(41)),
                jti(42): make_token(tokens.ACCOUNT_DISABLED, jti=jti(42), aud="urn:other"),
            }
        )
        run = receiver(transmitter, dry_run=True).run()
        self.assertEqual(LeaverSignal.objects.count(), 0)
        self.assertEqual(len(transmitter.calls), 1)
        self.assertEqual((transmitter.calls[0]["ack"], transmitter.calls[0]["errs"]), ([], {}))
        self.assertEqual(len(transmitter.pending), 2)
        self.assertEqual(run.counts["verified_account_disabled"], 1)

    def test_transmitter_metadata_must_name_accessops_and_offer_polling(self):
        from integrations.ssf.transport import TransmitterError

        for metadata in (
            {
                "issuer": "https://evil.test",
                "jwks_uri": "https://evil.test/jwks",
                "delivery_methods_supported": ["urn:ietf:rfc:8936"],
            },
            {
                "issuer": tokens.ISSUER,
                "jwks_uri": "https://evil.test/jwks",
                "delivery_methods_supported": ["urn:ietf:rfc:8936"],
            },
            {
                "issuer": tokens.ISSUER,
                "jwks_uri": tokens.ISSUER + "/api/v1/ssf/jwks",
                "delivery_methods_supported": ["urn:ietf:rfc:8935"],
            },
        ):
            with self.subTest(metadata=metadata), self.assertRaises(TransmitterError):
                receiver(FakeTransmitter({}, metadata=metadata)).run()


class DetectionTests(TestCase):
    def receive(self, *specs):
        sets = {jti(n): make_token(event, jti=jti(n), **extra) for n, event, extra in specs}
        run = receiver(FakeTransmitter(sets)).run()
        return detect(run.subjects | departed_subjects())

    def test_a_reported_signin_opens_one_critical_case_per_subject(self):
        actions = self.receive(
            (51, tokens.ACCOUNT_DISABLED, {}),
            (52, tokens.SESSION_ESTABLISHED, {"at": NOW - 10}),
            (53, tokens.SESSION_ESTABLISHED, {"at": NOW - 5}),
        )
        case = Investigation.objects.get(rule=RULE_REPORTED)
        self.assertEqual(actions, {"case.created": 1})
        self.assertEqual(
            (case.severity, case.integration.slug, case.status), ("critical", "accessops", "open")
        )
        self.assertEqual(case.leaver_signals.count(), 3)
        self.assertIn("worker-1", case.explanation)
        self.assertIn("account disabled at", case.explanation)

    def test_containment_alone_opens_no_case(self):
        self.assertEqual(
            self.receive((61, tokens.ACCOUNT_DISABLED, {}), (62, tokens.SESSION_REVOKED, {})), {}
        )
        self.assertFalse(Investigation.objects.exists())

    def test_only_new_access_reopens_a_resolved_case(self):
        self.receive((71, tokens.SESSION_ESTABLISHED, {"at": NOW - 50}))
        case = Investigation.objects.get(rule=RULE_REPORTED)
        Investigation.objects.filter(pk=case.pk).update(status="resolved")
        self.receive((72, tokens.ACCOUNT_DISABLED, {"at": NOW - 40}))
        case.refresh_from_db()
        self.assertEqual(case.status, "resolved")
        self.assertEqual(case.leaver_signals.count(), 2)
        self.receive((73, tokens.SESSION_ESTABLISHED, {"at": NOW - 30}))
        case.refresh_from_db()
        self.assertEqual(case.status, "open")

    def console_session(self, subject, at):
        user = get_user_model().objects.get_or_create(username="sso-" + subject)[0]
        identity = FederatedIdentity.objects.get_or_create(
            issuer=WORKFORCE, subject=subject, defaults={"user": user}
        )[0]
        FederatedSession.objects.create(
            identity=identity,
            identity_version=1,
            binding_digest=f"{subject}{at.timestamp()}".encode().hex()[:64],
            created_at=at,
            authenticated_at=at,
            expires_at=at + timedelta(minutes=10),
        )

    def test_a_console_signin_after_the_account_was_disabled_opens_l2(self):
        disabled = datetime.fromtimestamp(NOW - 100, tz=timezone.utc)
        self.console_session("worker-1", disabled - timedelta(minutes=5))
        self.receive((81, tokens.ACCOUNT_DISABLED, {"at": NOW - 100}))
        self.assertFalse(Investigation.objects.filter(rule=RULE_CONSOLE).exists())
        self.console_session("worker-1", disabled + timedelta(seconds=30))
        self.assertEqual(detect(departed_subjects()), {"case.created": 1})
        case = Investigation.objects.get(rule=RULE_CONSOLE)
        self.assertEqual(case.severity, "critical")
        self.assertIn("This console's own sign-in records", case.explanation)
        Investigation.objects.filter(pk=case.pk).update(status="resolved")
        detect(departed_subjects())
        case.refresh_from_db()
        self.assertEqual(case.status, "resolved")  # nothing new; stays as the analyst left it


class CasePageTests(TestCase):
    def setUp(self):
        sets = {jti(91): make_token(tokens.SESSION_ESTABLISHED, jti=jti(91))}
        detect(receiver(FakeTransmitter(sets)).run().subjects)
        self.case = Investigation.objects.get(rule=RULE_REPORTED)
        self.analyst = get_user_model().objects.create_user(
            "leaver-analyst", password="unused-pass-1"
        )
        self.outsider = get_user_model().objects.create_user("outsider", password="unused-pass-2")
        Membership.objects.create(user=self.analyst, integration=workspace(), role="analyst")

    def test_members_see_the_signed_signals_and_others_get_404(self):
        self.client.force_login(self.analyst)
        page = self.client.get(f"/investigations/{self.case.pk}/")
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Leaver signals from AccessOps")
        self.assertContains(page, "Why critical priority?")
        self.assertNotContains(page, "has no current catalog entry")
        self.assertNotContains(page, "Linked observations shown")  # event fields hidden
        self.assertContains(page, "1 signed leaver signal")
        self.assertNotContains(page, LeaverSignal.objects.get().token)
        self.client.force_login(self.outsider)
        self.assertEqual(self.client.get(f"/investigations/{self.case.pk}/").status_code, 404)


class SetupCommandTests(TestCase):
    def test_setup_stores_the_token_privately_without_printing_it(self):
        secret = "s3cret-receiver-token-" + "x" * 30
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "ssf-receiver.env").write_text(
                f"OTHER=1\nSSF_RECEIVER_TOKEN={secret}\n", encoding="utf-8"
            )
            (root / "root.crt").write_text(
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", encoding="utf-8"
            )
            output = StringIO()
            with (
                override_settings(VAR_DIR=root / "var"),
                patch("bridge.management.commands.accessops_signals.ssl.create_default_context"),
            ):
                call_command(
                    "accessops_signals",
                    "setup",
                    "--receiver-env",
                    str(root / "ssf-receiver.env"),
                    "--ca",
                    str(root / "root.crt"),
                    stdout=output,
                )
            self.assertNotIn(secret, output.getvalue())
            self.assertEqual(
                (root / "var/ssf/receiver-token").read_text(encoding="utf-8").strip(), secret
            )
            self.assertEqual(LeaverSignal.objects.count(), 0)

    def test_setup_refuses_a_private_key_as_the_ca_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "env").write_text("SSF_RECEIVER_TOKEN=" + "y" * 40 + "\n", encoding="utf-8")
            (root / "ca").write_text(
                "-----BEGIN CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\n", encoding="utf-8"
            )
            with (
                override_settings(VAR_DIR=root / "var"),
                self.assertRaisesMessage(Exception, "public PEM certificate"),
            ):
                call_command(
                    "accessops_signals",
                    "setup",
                    "--receiver-env",
                    str(root / "env"),
                    "--ca",
                    str(root / "ca"),
                    stdout=StringIO(),
                )
            self.assertFalse((root / "var/ssf/receiver-token").exists())
