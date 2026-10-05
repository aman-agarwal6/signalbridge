"""Real headless Chromium walkthrough of the native identity lab.

The host starts this pinned container only after the protocol controls finish,
inside the Keycloak network namespace, with read-only source, hash-pinned wheels
and certificates. TLS stays verified: the browser trusts exactly the two lab
server keys by SPKI pin. It proves browser-enforced login, cookie, CSP, framing
and keyboard behavior; it is not a full accessibility (WCAG) audit.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/workspace")
OUTPUT = Path("/evidence")
SECRETS = Path("/run/secrets")
DEPENDENCIES = Path("/opt/browser-deps")
RUNTIME = DEPENDENCIES / "runtime"
CONSOLE = "https://127.0.0.1:18842"
PROVIDER = "https://127.0.0.2:18844"
ACCOUNT = "reviewer"
CONTROLS = (
    "browser_keyboard_mfa_login",
    "browser_cookie_attributes_enforced",
    "browser_csp_blocks_inline_script",
    "browser_framing_blocked",
    "browser_logout_ends_session",
)


STEP = {"name": "start"}


def step(name):
    STEP["name"] = name


def describe(error):
    """First line only, URLs without query strings; typed values never appear."""
    text = str(error).splitlines()[0] if str(error) else ""
    text = re.sub(r"(https?://[^\s?#]+)[?#]\S*", r"\1", text)
    return re.sub(r"[^\x20-\x7e]", "?", text)[:200]


class BrowserCheckError(ValueError):
    """Closed code only; never page content, cookies or credentials."""


def require(condition, code="browser_predicate"):
    if not condition:
        raise BrowserCheckError(code)


def install():
    temporary = DEPENDENCIES / "install-tmp"
    temporary.mkdir(mode=0o700, exist_ok=False)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "--isolated",
            "install",
            "--no-index",
            "--no-deps",
            "--no-cache-dir",
            "--no-compile",
            "--only-binary=:all:",
            "--require-hashes",
            "--find-links=/browser-wheels",
            "--target=" + str(RUNTIME),
            "-r",
            str(ROOT / "integrations/identity/browser-requirements.lock"),
        ],
        env={"PATH": "/usr/bin:/bin", "TMPDIR": str(temporary)},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=180,
    )
    require(result.returncode == 0, "browser_dependency_install")


def spki_pin(name):
    """SHA-256 of the certificate's SubjectPublicKeyInfo, as Chromium expects."""
    public = subprocess.run(
        ["openssl", "x509", "-in", str(SECRETS / name), "-pubkey", "-noout"],
        capture_output=True,
        check=True,
        timeout=10,
    ).stdout
    der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=public,
        capture_output=True,
        check=True,
        timeout=10,
    ).stdout
    # P-256 SubjectPublicKeyInfo is 91 bytes; RSA-4096 is about 550.
    require(64 <= len(der) <= 2048, "browser_spki")
    return base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")


def walkthrough(account, pins, totp):
    from playwright.sync_api import sync_playwright

    rows = []

    def record(name, **facts):
        rows.append({"control": name, "passed": True, **facts})

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            args=["--disable-dev-shm-usage", "--ignore-certificate-errors-spki-list=" + pins]
        )
        try:
            context = browser.new_context()
            page = context.new_page()
            page.set_default_timeout(15000)
            reply = page.goto(CONSOLE + "/login/")
            require(reply is not None and reply.status == 200, "browser_login_page")
            # Autofocus timing varies, so walk the real tab order from the top of
            # the page until the organization button holds keyboard focus.
            step("keyboard_focus")
            page.evaluate("() => document.activeElement && document.activeElement.blur()")
            target = ["BUTTON", "Sign in with organization account"]
            presses = 0
            while presses < 10:
                page.keyboard.press("Tab")
                presses += 1
                focused = page.evaluate(
                    "() => [document.activeElement.tagName,"
                    " document.activeElement.textContent.trim()]"
                )
                if focused == target:
                    break
            require(focused == target, "browser_focus")
            page.keyboard.press("Enter")
            step("provider_login_page")
            page.wait_for_url(PROVIDER + "/realms/signalbridge/**")
            step("provider_labels")
            for field in ("username", "password"):
                require(
                    page.locator("label[for='" + field + "']").count() == 1, "browser_form_label"
                )
            step("provider_password")
            page.focus("#username")
            page.keyboard.type(account["username"])
            page.keyboard.press("Tab")
            page.keyboard.type(account["password"])
            page.keyboard.press("Enter")
            step("provider_otp")
            page.wait_for_selector("#otp")
            require(page.locator("label[for='otp']").count() == 1, "browser_otp_label")
            page.focus("#otp")
            page.keyboard.type(totp(account["totp_base32"]))
            page.keyboard.press("Enter")
            step("callback")
            page.wait_for_url(CONSOLE + "/")
            identity = page.goto(CONSOLE + "/_lab/identity/")
            require(identity is not None and identity.status == 200, "browser_identity")
            # Chromium decorates rendered JSON; read the exact response body.
            value = identity.json()
            require(value["username"] == account["username"], "browser_identity_user")
            require(
                value["memberships"] == [{"integration__slug": "documents", "role": "reviewer"}],
                "browser_identity_role",
            )
            record(
                "browser_keyboard_mfa_login",
                factors=["password", "totp"],
                keyboard_activation=True,
                tab_presses_to_sign_in=presses,
                typed_credentials=True,
                labelled_inputs=["username", "password", "otp"],
                tls_verified_by_spki_pin=True,
            )

            step("cookies")
            cookies = {c["name"]: c for c in context.cookies(CONSOLE)}
            session, csrf = cookies.get("sb_enterprise_session"), cookies.get("sb_enterprise_csrf")
            require(session is not None and csrf is not None, "browser_cookies_missing")
            observed = {
                name: {
                    "secure": c["secure"],
                    "http_only": c["httpOnly"],
                    "same_site": c["sameSite"],
                }
                for name, c in (("session", session), ("csrf", csrf))
            }
            require(
                observed["session"] == {"secure": True, "http_only": True, "same_site": "None"}
                and observed["csrf"]["secure"] is True
                and observed["csrf"]["same_site"] == "Strict",
                "browser_cookie_flags",
            )
            page.goto(CONSOLE + "/")
            visible = page.evaluate("document.cookie")
            require("sb_enterprise_session" not in visible, "browser_session_script_visible")
            record(
                "browser_cookie_attributes_enforced",
                cookies=observed,
                session_hidden_from_script=True,
            )

            page.evaluate(
                "() => { window.__violations = []; document.addEventListener("
                "'securitypolicyviolation', e => window.__violations.push(e.violatedDirective)); }"
            )
            ran = page.evaluate(
                "() => { const s = document.createElement('script');"
                " s.textContent = 'window.__inlineRan = true'; document.body.appendChild(s);"
                " return window.__inlineRan === true; }"
            )
            page.wait_for_timeout(500)
            violations = page.evaluate("window.__violations")
            require(ran is False and "script-src-elem" in violations, "browser_csp")
            record("browser_csp_blocks_inline_script", violated_directive="script-src-elem")

            step("framing")
            framer = context.new_page()
            framer.set_content('<iframe src="' + CONSOLE + '/login/"></iframe>')
            framer.wait_for_timeout(2000)
            urls = [frame.url for frame in framer.frames]
            require(len(urls) == 2 and urls[1].startswith("chrome-error://"), "browser_framing")
            framer.close()
            record("browser_framing_blocked", blocked_frame_url="chrome-error")

            page.goto(CONSOLE + "/")
            step("logout")
            button = page.get_by_role("button", name="Sign out").first
            button.focus()
            # Wait for the sign-out POST to land; a new navigation would abort it.
            with page.expect_navigation(url=CONSOLE + "/login/"):
                page.keyboard.press("Enter")
            after = page.goto(CONSOLE + "/_lab/identity/")
            require(
                after is not None and after.url.startswith(CONSOLE + "/login/"), "browser_logout"
            )
            record("browser_logout_ends_session", keyboard_activation=True)
            version = browser.version
        finally:
            browser.close()
    return rows, version


def main():
    result = {"schema_version": 1, "passed": False, "browser_engine": "chromium"}
    try:
        require(sys.platform == "linux" and os.getuid() == 1000, "browser_runtime")
        run = os.environ.get("SB_IDENTITY_RUN", "")
        ready = json.loads((OUTPUT / "identity-browser-ready.json").read_bytes())
        require(ready == {"run_id": run, "ready": True, "account": ACCOUNT}, "browser_gate")
        result["run_id"] = run
        install()
        sys.path.insert(0, str(RUNTIME))
        sys.path.insert(1, str(ROOT))
        from integrations.identity.native_http import totp
        from integrations.identity.native_profile import load_profile

        profile = load_profile(SECRETS / "identity-profile.json")
        require(profile["run_id"] == run, "browser_profile")
        pins = ",".join(
            spki_pin(name) for name in ("console-certificate.pem", "provider-certificate.pem")
        )
        started = time.monotonic()
        rows, version = walkthrough(profile["accounts"][ACCOUNT], pins, totp)
        require([row["control"] for row in rows] == list(CONTROLS), "browser_controls")
        result.update(
            passed=True,
            controls=rows,
            browser_version=version,
            duration_seconds=round(time.monotonic() - started, 3),
            accessibility_scope="keyboard reachability and labelled inputs only; not a WCAG audit",
        )
    except Exception as error:
        result["error_class"] = type(error).__name__
        result["error_code"] = str(error) if isinstance(error, BrowserCheckError) else None
        result["failed_step"] = STEP["name"]
        result["error_summary"] = describe(error)
    finally:
        raw = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("ascii")
        temporary = OUTPUT / "identity-browser.tmp"
        with temporary.open("xb") as output:
            output.write(raw)
        temporary.replace(OUTPUT / "identity-browser.json")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
