"""Small offline contract checks; never reported as native provider execution."""

import base64
import json
import os
from http.cookiejar import Cookie, CookieJar
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

from .native_http import (
    CALLBACK,
    CONSOLE,
    PROVIDER,
    Budget,
    Forms,
    NativeClient,
    NativeIdentityError,
    Reply,
    check_abort,
    destination,
    totp,
)
from .native_profile import ACCOUNTS, material


class NativeIdentityPreparationTests(TestCase):
    def test_native_abort_vetoes_requests_before_connection_and_retains_budget(self):
        client = NativeClient.__new__(NativeClient)
        client.jar, client.context, client.budget = CookieJar(), object(), Budget()
        with (
            patch.dict(os.environ, {"SB_IDENTITY_NATIVE": "1"}),
            patch("integrations.identity.native_http.Path.lstat", return_value=object()),
            patch("integrations.identity.native_http.BoundedHTTPSConnection") as connect,
        ):
            with self.assertRaises(NativeIdentityError):
                client.request("GET", CONSOLE + "/login/")
        connect.assert_not_called()
        self.assertEqual(client.budget.used, 0)

    def test_abort_absence_permits_check_but_unreadable_marker_fails_closed(self):
        with patch.dict(os.environ, {"SB_IDENTITY_NATIVE": "1"}):
            with patch(
                "integrations.identity.native_http.Path.lstat", side_effect=FileNotFoundError
            ):
                check_abort()
            with patch("integrations.identity.native_http.Path.lstat", side_effect=PermissionError):
                with self.assertRaises(NativeIdentityError):
                    check_abort()

    def test_write_and_logout_destinations_stay_closed(self):
        identifier = "b" * 8 + "-" + "c" * 4 + "-" + "d" * 4 + "-" + "e" * 4 + "-" + "f" * 12
        for path in ("/sso/backchannel/", "/investigations/" + identifier + "/work/"):
            self.assertEqual(destination(CONSOLE + path)[0], CONSOLE)
        for path in (
            "/admin/",
            "/investigations/" + identifier + "/delete/",
            "/sso/backchannel/?x=1",
        ):
            with self.subTest(path=path), self.assertRaises(NativeIdentityError):
                destination(CONSOLE + path)

    def test_provider_admin_routes_are_exact_for_logout_and_key_rotation(self):
        user = "b" * 8 + "-" + "c" * 4 + "-" + "d" * 4 + "-" + "e" * 4 + "-" + "f" * 12
        for path in (
            "/admin/realms/signalbridge",
            "/admin/realms/signalbridge/keys",
            "/admin/realms/signalbridge/components",
            "/admin/realms/signalbridge/users/" + user + "/logout",
        ):
            self.assertEqual(destination(PROVIDER + path)[0], PROVIDER)
        for path in (
            "/admin/realms/master/keys",
            "/admin/realms/signalbridge/components/" + user,
            "/admin/realms/signalbridge/clients",
            "/admin/realms/signalbridge/keys/extra",
            "/admin/realms/signalbridge/users",
        ):
            with self.subTest(path=path), self.assertRaises(NativeIdentityError):
                destination(PROVIDER + path)

    def test_bearer_is_only_sent_to_exact_provider_admin_routes(self):
        client = NativeClient.__new__(NativeClient)
        client.jar, client.context, client.budget = CookieJar(), object(), Budget()
        with patch("integrations.identity.native_http.BoundedHTTPSConnection") as connect:
            for url in (
                CONSOLE + "/_lab/identity/",
                PROVIDER + "/realms/signalbridge/protocol/openid-connect/certs",
            ):
                with self.subTest(url=url), self.assertRaises(NativeIdentityError):
                    client.request("GET", url, bearer="synthetic")
        connect.assert_not_called()
        self.assertEqual(client.budget.used, 0)

    def test_only_single_allowlisted_console_security_headers_are_retained(self):
        client = NativeClient.__new__(NativeClient)
        client.jar, client.context, client.budget = CookieJar(), object(), Budget()
        response = Mock(status=200)
        response.read.return_value = b"page"
        response.getheader.side_effect = lambda name, default="": default
        headers = {
            "x-frame-options": ["DENY"],
            "set-cookie": [],
            "x-private": ["not retained"],
        }
        response.headers.get_all.side_effect = lambda name, default=None: headers.get(
            name.lower(), default
        )
        response.headers.get_content_type.return_value = "text/html"
        response.info.return_value = response.headers
        with patch("integrations.identity.native_http.BoundedHTTPSConnection") as connect:
            connect.return_value.getresponse.return_value = response
            reply = client.request("GET", CONSOLE + "/login/")
            self.assertEqual(reply.headers, {"x-frame-options": "DENY"})
            headers["x-frame-options"] = ["DENY", "SAMEORIGIN"]
            with self.assertRaises(NativeIdentityError):
                client.request("GET", CONSOLE + "/login/")

    def test_case_write_uses_only_secure_host_csrf_cookie(self):
        client = NativeClient.__new__(NativeClient)
        client.jar = CookieJar()
        cookie = Cookie(
            0,
            "sb_enterprise_csrf",
            "c" * 32,
            None,
            False,
            "127.0.0.1",
            False,
            False,
            "/",
            True,
            True,
            None,
            True,
            None,
            None,
            {},
        )
        client.jar.set_cookie(cookie)
        client.request = Mock(return_value=Reply(403, CONSOLE, b"bounded"))
        client.case_work("a" * 36, {"operation": "structured_note"})
        self.assertEqual(client.request.call_args.args[2]["csrfmiddlewaretoken"], "c" * 32)
        cookie.domain_specified = True
        with self.assertRaises(NativeIdentityError):
            client.case_work("a" * 36, {})
        self.assertEqual(client.request.call_count, 1)

    def test_native_callback_replay_reuses_fields_only_in_memory(self):
        client = NativeClient.__new__(NativeClient)
        client.request = Mock(return_value=Reply(403, CALLBACK, b"rejected"))
        raw = b'<form method="post" action="https://127.0.0.1:18842/sso/callback/"><input type="hidden" name="code" value="synthetic-code"><input type="hidden" name="state" value="synthetic-state"></form>'
        reply = Reply(200, PROVIDER + "/realms/signalbridge/login-actions/authenticate", raw)
        client.finish(reply)
        client.finish(reply)
        self.assertEqual(client.request.call_args_list[0], client.request.call_args_list[1])
        self.assertEqual(client.request.call_args.kwargs, {"initiator": PROVIDER})
        self.assertNotIn("synthetic-code", repr(reply))

    def test_callback_extra_fields_fail_before_http(self):
        client = NativeClient.__new__(NativeClient)
        client.request = Mock()
        raw = b'<form method="post" action="https://127.0.0.1:18842/sso/callback/"><input type="hidden" name="code" value="synthetic"><input type="hidden" name="state" value="synthetic"><input type="hidden" name="redirect" value="evil"></form>'
        with self.assertRaises(NativeIdentityError):
            client.finish(Reply(200, PROVIDER, raw))
        client.request.assert_not_called()

    def test_imported_users_satisfy_default_keycloak_profile_requirements(self):
        # Keycloak26.8 default profile requires email, firstName and lastName;
        # VerifyUserProfile.evaluateTriggers runs independently of requiredActions.
        realm = json.loads(Path(__file__).with_name("realm.json").read_bytes())
        prepared, _ = material(realm, "e" * 32)
        emails = set()
        for user in prepared["users"]:
            with self.subTest(username=user["username"]):
                for name in ("firstName", "lastName"):
                    self.assertRegex(user[name], r"^[A-Za-z ]{1,255}$")
                self.assertRegex(user["email"], r"^sb-lab-[a-z-]+@identity\.signalbridge\.invalid$")
                self.assertNotIn(user["email"], emails)
                emails.add(user["email"])
                self.assertFalse(user["emailVerified"])
        self.assertEqual(prepared.get("requiredActions"), realm.get("requiredActions"))
        self.assertEqual(prepared["smtpServer"], {})

    def test_totp_matches_published_rfc6238_sha256_vector(self):
        secret = base64.b32encode(b"12345678901234567890123456789012").decode().rstrip("=")
        # RFC6238 Appendix B, SHA256 at Unix59: 46119246; our six-digit policy.
        self.assertEqual(totp(secret, 59), "119246")

    def test_client_rejects_nonprofile_destinations_before_network(self):
        for value in (
            "http://127.0.0.1:18842/login/",
            "https://example.com/",
            "https://127.0.0.1:18842@evil.invalid/",
            CONSOLE + "/login/?next=https://evil.invalid",
            "https://127.0.0.2:18844/realms/other/login",
            CONSOLE + "/%2e%2e/admin/",
        ):
            with self.subTest(value=value), self.assertRaises(NativeIdentityError):
                destination(value)

    def test_form_post_preserves_decoded_code_without_execution(self):
        raw = b'<form method="post" action="https://127.0.0.1:18842/sso/callback/"><input type="hidden" name="code" value="a.b-c"><input type="hidden" name="state" value="safe&amp;bounded"></form><script>throw 1;</script>'
        form = Forms(
            raw, "https://127.0.0.2:18844/realms/signalbridge/login-actions/authenticate"
        ).one("code")
        self.assertEqual(form.action, CALLBACK)
        self.assertEqual(form.fields, {"code": "a.b-c", "state": "safe&bounded"})

    def test_keycloak_uppercase_hidden_inputs_are_read(self):
        # Keycloak's form_post page writes uppercase tags and TYPE="HIDDEN".
        raw = b'<FORM METHOD="POST" ACTION="https://127.0.0.1:18842/sso/callback/"><INPUT TYPE="HIDDEN" NAME="state" VALUE="s1"/><INPUT TYPE="HIDDEN" NAME="code" VALUE="c1"/><INPUT TYPE="HIDDEN" NAME="iss" VALUE="i1"/></FORM>'
        form = Forms(raw, CALLBACK).one("code")
        self.assertEqual(form.fields, {"state": "s1", "code": "c1", "iss": "i1"})

    def test_duplicate_inputs_and_external_form_actions_are_rejected(self):
        for raw in (
            b'<form method="post"><input name="code"><input name="code"></form>',
            b'<form method="post" action="https://evil.invalid/"></form>',
        ):
            with self.assertRaises(NativeIdentityError):
                Forms(raw, CALLBACK)

    def test_fresh_profile_uses_explicit_subjects_and_correct_totp_encoding(self):
        realm = json.loads(Path(__file__).with_name("realm.json").read_bytes())
        prepared, profile = material(realm, "d" * 32)
        self.assertEqual(realm["users"], [])
        self.assertEqual(set(profile["accounts"]), set(ACCOUNTS))
        self.assertEqual(len(prepared["users"]), 7)
        self.assertEqual(len({v["password"] for v in profile["accounts"].values()}), 7)
        for user in prepared["users"]:
            credential = json.loads(user["credentials"][1]["credentialData"])
            self.assertEqual(credential["secretEncoding"], "BASE32")
            self.assertEqual(credential["algorithm"], "HmacSHA256")
            self.assertEqual(user["realmRoles"], [])
        mapper = next(
            v
            for v in prepared["clients"][0]["protocolMappers"]
            if v["protocolMapper"] == "oidc-usersessionmodel-note-mapper"
        )
        self.assertEqual(mapper["config"]["user.session.note"], "AUTH_TIME")
