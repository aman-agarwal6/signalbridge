"""Actual HTTPS password/TOTP/callback/lifecycle checks against native Keycloak.

This is an operator-controlled disposable lab driver. It does not use Django's
test client, patch token responses, synthesize identity tokens or skip TLS.
It proves protocol execution and checks the console's cookie attributes and
security headers over HTTP; no browser engine enforces them, so it is not
browser accessibility or browser enforcement proof.
"""

import json
import re
import time
import uuid
from datetime import datetime, timezone

from .configuration import ISSUER
from .constants import PROVIDER_ORIGIN
from .key_refresh import REFRESH_COOLDOWN
from .native_http import (
    CALLBACK,
    CONSOLE,
    PROVIDER,
    Budget,
    Forms,
    NativeClient,
    check_abort,
    require,
    totp,
)


def case_fixture(integration, run_id):
    """Only identity authorization fixtures; never native source/detection evidence."""
    from django.utils import timezone as django_timezone

    from bridge.contract import digest
    from bridge.models import Event, Investigation

    check_abort()
    namespace = uuid.UUID(hex=run_id)
    identifier = uuid.uuid5(namespace, "identity-case-" + integration.slug)
    now = django_timezone.now()
    payload = {
        "schema_version": 1,
        "event_id": str(uuid.uuid5(namespace, "identity-fixture-" + integration.slug)),
        "episode": str(uuid.uuid5(namespace, "identity-fixture-episode")),
        "app": integration.slug,
        "environment": "test",
        "occurred_at": now.isoformat(),
        "actor": "a" * 64,
        "resource": "b" * 64,
        "operation": "private_record.read",
        "outcome": "denied",
        "reason": "membership_required",
        "context": None,
    }
    event = Event.objects.create(
        integration=integration,
        **{
            key: payload[key]
            for key in (
                "event_id",
                "episode",
                "actor",
                "resource",
                "environment",
                "operation",
                "outcome",
                "reason",
            )
        },
        occurred_at=now,
        available_at=now,
        source="synthetic_demo",
        payload=payload,
        digest=digest(payload),
    )
    case = Investigation.objects.create(
        id=identifier,
        integration=integration,
        rule="R3",
        correlation=integration.slug * 4,
        title="Synthetic identity boundary fixture",
        explanation="Operator-created identity role fixture; no source execution or detector finding.",
        severity="high",
    )
    case.events.add(event)
    return str(case.pk)


def case_snapshot(case_id):
    """Bounded local verification of writes, never exported as private content."""
    from bridge.models import Audit, CaseTask, CaseVerification, Investigation, Note

    case = Investigation.objects.get(pk=case_id)
    return (
        case.version,
        case.status,
        case.assignee_id,
        case.acknowledged_at,
        case.due_at,
        tuple(
            Note.objects.filter(investigation=case)
            .order_by("pk")
            .values_list("pk", "author_id", "kind", "text")
        ),
        tuple(
            CaseTask.objects.filter(investigation=case).order_by("pk").values_list("pk", "status")
        ),
        tuple(
            CaseVerification.objects.filter(task__investigation=case)
            .order_by("pk")
            .values_list("pk", "status")
        ),
        tuple(
            Audit.objects.filter(object_id=str(case.pk)).order_by("pk").values_list("pk", "action")
        ),
    )


def case_controls(clients, cases, record):
    """Use the real CSRF-protected application endpoint and inspect committed rows."""
    from bridge.case_workflow import evidence_binding
    from bridge.models import Audit, Investigation, Note

    role_error = b"Your current role does not allow this action."
    document = cases["documents"]
    note = {
        "operation": "structured_note",
        "kind": "observed_fact",
        "note": "Synthetic identity role control.",
    }

    def blocked(name, client, case_id, fields, status, *, csrf=True, role=False):
        before = case_snapshot(case_id)
        reply = client.case_work(case_id, {"version": before[0], **fields}, csrf=csrf)
        require(reply.status == status and (not role or reply.body == role_error))
        require(case_snapshot(case_id) == before)
        record(name, status=status, committed_state_unchanged=True)

    blocked("viewer_note_write_denied", clients["viewer"], document, note, 403, role=True)
    blocked("csrf_missing_write_denied", clients["analyst"], document, note, 403, csrf=False)
    before = case_snapshot(document)
    reply = clients["analyst"].case_work(document, {"version": before[0], **note})
    require(reply.status == 302 and reply.location == "/investigations/" + document + "/")
    case = Investigation.objects.get(pk=document)
    saved = Note.objects.get(investigation=case)
    require(
        case.version == before[0] + 1 and saved.kind == note["kind"] and saved.text == note["note"]
    )
    require(saved.author.membership_set.get(integration=case.integration).role == "analyst")
    require(
        Audit.objects.filter(
            object_id=document, action="case.structured_note", actor=saved.author
        ).count()
        == 1
    )
    record("analyst_note_write_persisted", status=302, committed_notes=1, case_version=case.version)

    # A valid evidence binding ensures this reaches the reviewer-role gate, not
    # an earlier empty-case failure. No fabricated retest or approval is seeded.
    require(bool(evidence_binding(case)))
    blocked(
        "analyst_reviewer_action_denied",
        clients["analyst"],
        document,
        {
            "operation": "review_retest",
            "verification_id": str(uuid.uuid4()),
            "decision": "approved",
            "rationale": "Synthetic role-denial control; no verified fix exists.",
        },
        403,
        role=True,
    )
    for name in ("analyst", "viewer", "reviewer"):
        blocked(name + "_cross_app_write_denied", clients[name], cases["expenses"], note, 404)


def provision(profile):
    from django.contrib.auth import get_user_model
    from django.core.management import call_command
    from django.db import connection

    from bridge.federation import provision_identity
    from bridge.models import Integration, Membership

    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database(), current_user")
        require(cursor.fetchone() == ("identity_console", "identity_console"))
        cursor.execute(
            "SELECT rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname=current_user"
        )
        require(cursor.fetchone() == (False, False, False))
    check_abort()
    call_command("migrate", verbosity=0, interactive=False)
    require(not Integration.objects.exists() and not get_user_model().objects.exists())
    apps, cases = {}, {}
    for name in ("documents", "expenses"):
        apps[name] = Integration.objects.create(slug=name, name="Synthetic " + name)
        cases[name] = case_fixture(apps[name], profile["run_id"])
    for name, account in profile["accounts"].items():
        check_abort()
        if name == "unmapped":
            continue
        user = get_user_model().objects.create_user(username=account["username"], password=None)
        provision_identity(issuer=ISSUER, subject=account["subject"], user_id=user.pk)
        role = name if name in {"viewer", "reviewer"} else "analyst"
        Membership.objects.create(user=user, integration=apps["documents"], role=role)
        if name == "local_disabled":
            user.is_active = False
            user.save(update_fields=["is_active"])
    return cases


def exercise(profile, cases, ca_file, progress=None):
    from django.contrib.auth import get_user_model
    from django.utils import timezone as django_timezone

    from bridge.models import FederatedSession, Membership

    budget = Budget(seconds=1200, requests=200)
    rows = []
    clients = {}

    def record(name, **facts):
        check_abort()
        rows.append(
            {
                "control": name,
                "passed": True,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                **facts,
            }
        )
        if progress is not None:
            progress(rows)

    def denied(client):
        reply = client.request("GET", CONSOLE + "/_lab/identity/")
        require(reply.status == 302 and reply.location.startswith("/login/?next="))

    def invalidated(client):
        # The federated session policy logs out a revoked or expired session and
        # redirects to login; only then is the browser an anonymous visitor.
        reply = client.request("GET", CONSOLE + "/_lab/identity/")
        require(reply.status == 302 and reply.location == "/login/")
        denied(client)

    used_steps = {}

    def login(name, accepted=True, control=None, facts=None):
        account = profile["accounts"][name]
        client = NativeClient(ca_file, budget)
        password_reply = client.password(client.begin(), account)
        # A real OTP form must exist after the real password exchange.
        Forms(password_reply.body, password_reply.url).one("otp")
        denied(client)
        instant = time.time()
        used_steps[name] = int(instant) // 30
        reply = client.otp(password_reply, totp(account["totp_base32"], instant))
        if name == "analyst":
            fields = client.callback_fields(reply)
            invalid = client.request(
                "POST",
                CALLBACK,
                {**fields, "state": "invalid-state-" + "x" * 40},
                initiator=PROVIDER,
            )
            require(invalid.status == 403)
            denied(client)
            record("callback_wrong_state_rejected", status=403, native_provider_callback=True)
        callback = client.finish(reply)
        if accepted:
            require(callback.status == 302 and callback.location == "/")
            identity = client.request("GET", CONSOLE + "/_lab/identity/")
            require(identity.status == 200 and identity.content_type == "application/json")
            value = json.loads(identity.body)
            role = name if name in {"viewer", "reviewer"} else "analyst"
            require(
                value
                == {
                    "username": account["username"],
                    "issuer": ISSUER,
                    "subject": account["subject"],
                    "staff": False,
                    "superuser": False,
                    "memberships": [{"integration__slug": "documents", "role": role}],
                }
            )
            record(
                control or name + "_native_mfa_login",
                factors=["password", "totp"],
                local_role=role,
                auto_privilege_grant=False,
                **(facts or {}),
            )
            if name == "analyst":
                admitted = FederatedSession.objects.filter(revoked_at=None).count()
                replay = client.finish(reply)
                require(replay.status == 403)
                require(FederatedSession.objects.filter(revoked_at=None).count() == admitted)
                current = client.request("GET", CONSOLE + "/_lab/identity/")
                require(current.status == 200 and json.loads(current.body) == value)
                record(
                    "callback_replay_rejected",
                    status=403,
                    native_callback_reused=True,
                    admission_unchanged=True,
                )
        else:
            require(callback.status == 403)
            denied(client)
            record(name + "_local_admission_denied", callback_status=403)
        clients[name] = client
        return client

    # Provider-denial controls use separate disposable cookie jars.
    client = NativeClient(ca_file, budget)
    # Keycloak's quick-login protection locks an account whose two failures
    # arrive within one second. The analyst gets the wrong-TOTP failure below,
    # so the wrong-password control uses a different valid account.
    wrong = dict(profile["accounts"]["viewer"], password="deliberately-invalid-synthetic-password")
    reply = client.password(client.begin(), wrong)
    Forms(reply.body, reply.url).one("username")
    denied(client)
    record("wrong_password_rejected")
    client = NativeClient(ca_file, budget)
    reply = client.password(client.begin(), profile["accounts"]["provider_disabled"])
    Forms(reply.body, reply.url).one("username")
    denied(client)
    record("provider_disabled_login_rejected")
    client = NativeClient(ca_file, budget)
    account = profile["accounts"]["analyst"]
    reply = client.password(client.begin(), account)
    Forms(reply.body, reply.url).one("otp")
    denied(client)
    record("password_alone_not_admitted")
    valid_codes = {totp(account["totp_base32"], time.time() + delta) for delta in (-30, 0, 30)}
    invalid = next(f"{n:06d}" for n in range(4) if f"{n:06d}" not in valid_codes)
    reply = client.otp(reply, invalid)
    Forms(reply.body, reply.url).one("otp")
    denied(client)
    record("wrong_totp_rejected")

    expiry = login("expiry")
    analyst = login("analyst")
    login("viewer")
    login("reviewer")
    login("local_disabled", accepted=False)
    login("unmapped", accepted=False)
    for name in ("analyst", "viewer", "reviewer"):
        client = clients[name]
        for app, expected in (("documents", 200), ("expenses", 404)):
            reply = client.request("GET", CONSOLE + "/investigations/" + cases[app] + "/brief/")
            require(reply.status == expected)
        record(name + "_application_boundary", own_app_status=200, other_app_status=404)

    case_controls(clients, cases, record)
    sessions = tuple(FederatedSession.objects.order_by("pk").values_list("pk", "revoked_at"))
    malformed = NativeClient(ca_file, budget).request(
        "POST",
        CONSOLE + "/sso/backchannel/",
        {"logout_token": "malformed.synthetic.token"},
        initiator=PROVIDER,
    )
    require(malformed.status == 403)
    require(
        tuple(FederatedSession.objects.order_by("pk").values_list("pk", "revoked_at")) == sessions
    )
    record(
        "malformed_logout_token_rejected",
        status=403,
        sessions_unchanged=True,
        token_kind="malformed_fixture",
    )

    # Withdrawal changes the real lab database, then the unchanged cookie is used.
    user = get_user_model().objects.get(username=profile["accounts"]["analyst"]["username"])
    before = case_snapshot(cases["documents"])
    cookie_before = tuple((cookie.name, cookie.value) for cookie in analyst.jar)
    check_abort()
    removed, _ = Membership.objects.filter(user=user).delete()
    require(removed == 1)
    reply = analyst.request("GET", CONSOLE + "/investigations/" + cases["documents"] + "/brief/")
    require(reply.status == 404)
    reply = analyst.case_work(
        cases["documents"],
        {
            "version": before[0],
            "operation": "structured_note",
            "kind": "observed_fact",
            "note": "This withdrawn account must not write.",
        },
    )
    require(reply.status == 404 and case_snapshot(cases["documents"]) == before)
    identity = analyst.request("GET", CONSOLE + "/_lab/identity/")
    require(identity.status == 200 and json.loads(identity.body)["memberships"] == [])
    require(tuple((cookie.name, cookie.value) for cookie in analyst.jar) == cookie_before)
    record(
        "permission_withdrawal_immediate",
        unchanged_browser_session=True,
        formerly_allowed_status=404,
        write_status=404,
        account_still_authenticated=True,
        committed_state_unchanged=True,
    )

    # Use the native IdP admin API only for this synthetic reviewer's logout and
    # the signing-key rotation below; each token stays in memory briefly.
    admin = NativeClient(ca_file, budget)

    def admin_token():
        reply = admin.request(
            "POST",
            PROVIDER + "/realms/master/protocol/openid-connect/token",
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": profile["operator_username"],
                "password": profile["operator_password"],
            },
        )
        require(reply.status == 200 and reply.content_type == "application/json")
        token = json.loads(reply.body).get("access_token")
        require(isinstance(token, str))
        return token

    def active_signing_key(token):
        reply = admin.request("GET", PROVIDER + "/admin/realms/signalbridge/keys", bearer=token)
        require(reply.status == 200 and reply.content_type == "application/json")
        active = json.loads(reply.body).get("active")
        require(isinstance(active, dict) and isinstance(active.get("RS256"), str))
        require(1 <= len(active["RS256"]) <= 255)
        return active["RS256"]

    access_token = admin_token()
    subject = profile["accounts"]["reviewer"]["subject"]
    reply = admin.request(
        "POST",
        PROVIDER + "/admin/realms/signalbridge/users/" + subject + "/logout",
        bearer=access_token,
    )
    require(reply.status == 204)
    del access_token
    deadline = time.monotonic() + 10
    reviewer = get_user_model().objects.get(username=profile["accounts"]["reviewer"]["username"])
    while (
        time.monotonic() < deadline
        and FederatedSession.objects.filter(identity__user=reviewer, revoked_at=None).exists()
    ):
        check_abort()
        time.sleep(0.2)
    require(not FederatedSession.objects.filter(identity__user=reviewer, revoked_at=None).exists())
    invalidated(clients["reviewer"])
    record("native_backchannel_logout_revoked_session", provider_status=204)

    # Rotate the provider's RS256 signing key through Keycloak's own admin API,
    # then require a fresh MFA login. The console was given only the startup
    # JWKS file, so admitting a token signed by the new key requires its bounded
    # refresh. Keycloak signs with the highest-priority active key.
    from django.conf import settings

    with open(settings.OIDC_JWKS_FILE, "rb") as handle:
        startup = {row["kid"] for row in json.loads(handle.read(65537))["keys"]}
    access_token = admin_token()
    realm = admin.request("GET", PROVIDER + "/admin/realms/signalbridge", bearer=access_token)
    require(realm.status == 200 and realm.content_type == "application/json")
    realm_id = json.loads(realm.body).get("id")
    require(isinstance(realm_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", realm_id))
    before = active_signing_key(access_token)
    require(before in startup)
    component = {
        "name": "sb-lab-rotated-rs256",
        "providerId": "rsa-generated",
        "providerType": "org.keycloak.keys.KeyProvider",
        "parentId": realm_id,
        "config": {
            "priority": ["1000"],
            "enabled": ["true"],
            "active": ["true"],
            "keySize": ["2048"],
            "algorithm": ["RS256"],
        },
    }
    created = admin.request(
        "POST",
        PROVIDER + "/admin/realms/signalbridge/components",
        json_body=json.dumps(component).encode("ascii"),
        bearer=access_token,
    )
    require(created.status == 201)
    rotated_at = time.monotonic()
    after = active_signing_key(access_token)
    del access_token
    require(after != before and after not in startup)
    # Keycloak refuses a reused TOTP code and the console's refresh has a fixed
    # cooldown; wait past both rather than weakening either control.
    while (
        time.monotonic() < rotated_at + REFRESH_COOLDOWN + 1
        or int(time.time()) // 30 <= used_steps["viewer"]
    ):
        check_abort()
        require(time.monotonic() + 2 < budget.deadline)
        time.sleep(0.5)
    rotated = login(
        "viewer",
        control="provider_signing_key_rotation_admitted",
        facts={
            "provider_component_status": 201,
            "new_signing_key_active": True,
            "new_key_absent_from_startup_jwks": True,
            "bounded_jwks_refresh_required": True,
        },
    )

    # Cookie attributes and security headers as served over HTTPS. A browser
    # engine would enforce them; this client only observes what is sent.
    def cookie(client, name):
        rows = [row for row in client.jar if row.name == name]
        require(len(rows) == 1)
        row = rows[0]
        require(row.domain == "127.0.0.1" and not row.domain_specified and row.path == "/")
        return {
            "secure": row.secure,
            "http_only": row.has_nonstandard_attr("HttpOnly"),
            "same_site": row.get_nonstandard_attr("SameSite"),
        }

    session_cookie = cookie(rotated, "sb_enterprise_session")
    csrf_cookie = cookie(rotated, "sb_enterprise_csrf")
    # SameSite=None is required for the cross-site form_post callback, which the
    # one-time state checks above guard; writes keep the Strict CSRF cookie.
    require(session_cookie == {"secure": True, "http_only": True, "same_site": "None"})
    require(csrf_cookie["secure"] is True and csrf_cookie["same_site"] == "Strict")
    pages = {
        "login": NativeClient(ca_file, budget).request("GET", CONSOLE + "/login/"),
        "case_brief": rotated.request(
            "GET", CONSOLE + "/investigations/" + cases["documents"] + "/brief/"
        ),
    }
    policy = {
        "default-src 'self'",
        "script-src 'none'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        # Exactly the console plus the fixed provider the sign-in POST redirects to.
        "form-action 'self' " + PROVIDER_ORIGIN,
    }
    for reply in pages.values():
        headers = reply.headers
        require(reply.status == 200 and "content-security-policy" in headers)
        require(policy <= {part.strip() for part in headers["content-security-policy"].split(";")})
        require(
            headers.get("x-frame-options") == "DENY"
            and headers.get("x-content-type-options") == "nosniff"
            and headers.get("referrer-policy") == "same-origin"
            and headers.get("cross-origin-opener-policy") == "same-origin"
            and headers.get("cache-control") == "no-store, private"
        )
    record(
        "http_cookie_and_header_policy",
        session_cookie=session_cookie,
        csrf_cookie=csrf_cookie,
        pages=sorted(pages),
        content_security_policy_directives=sorted(policy),
        hsts_sent=any("strict-transport-security" in r.headers for r in pages.values()),
        browser_engine=False,
    )

    # A real elapsed-time check. Do not edit issued-at/expiry rows to accelerate it.
    expiry_user = get_user_model().objects.get(username=profile["accounts"]["expiry"]["username"])
    session = FederatedSession.objects.get(identity__user=expiry_user, revoked_at=None)
    require(0 < (session.expires_at - session.created_at).total_seconds() <= 900)
    while django_timezone.now() <= session.expires_at:
        check_abort()
        require(time.monotonic() + 2 < budget.deadline)
        time.sleep(min(1, max(0.05, (session.expires_at - django_timezone.now()).total_seconds())))
    # The Django session expires with the federated session, so the browser is
    # already anonymous here (unlike back-channel revocation above).
    denied(expiry)
    record(
        "real_session_expiry_denied",
        lifetime_seconds=(session.expires_at - session.created_at).total_seconds(),
        clock_or_database_time_changed=False,
    )
    return {
        "passed": True,
        "controls": rows,
        "requests": budget.used,
        "native_keycloak": True,
        "browser_automation": False,
        "mocked_token_responses": False,
        "host_trust_changed": False,
        "case_evidence_source": "synthetic_demo",
        "remediation_verification_exercised": False,
    }
