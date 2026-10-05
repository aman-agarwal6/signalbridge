"""Check publishable files against known local credentials without printing values."""

import base64
import json
import re
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
MAX_PRIVATE_BYTES = 1024 * 1024
MAX_PUBLIC_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 250 * 1024 * 1024
MAX_FILES = 20000
MAX_SECRETS = 10000
RESTORATION_SECRETS = {
    "bootstrap-password",
    "console-password",
    "restoration-plan.json",
    "tool-scope.json",
}
MAX_HTTP_RUNS = 100
MAX_ROUTE_PRIVATE_FILES = 100
RUN_ID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
ACTOR_ROLES = frozenset({"owner", "member", "outsider"})
CREDENTIAL_NAME = re.compile(r"(?:^|_)(?:KEY|SECRET|PASSWORD|TOKEN|JWT)(?:_|$)")
PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k"})


class PublicationError(ValueError):
    """Fixed messages only; never include credentials, source text or parser errors."""


def _safe_path(path, root):
    try:
        relative = path.relative_to(root)
        current = root
        for part in relative.parts:
            current = current / part
            info = current.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise PublicationError(
                    "A publication or credential path is linked; inspect it locally."
                )
        if not path.resolve().is_relative_to(root.resolve()):
            raise PublicationError("A publication or credential path escaped this workspace.")
    except (OSError, ValueError) as error:
        if isinstance(error, PublicationError):
            raise
        raise PublicationError(
            "A required publication or credential path cannot be checked."
        ) from None


def _read(path, root, maximum):
    _safe_path(path, root)
    try:
        if not path.is_file() or path.stat().st_size > maximum:
            raise PublicationError("A publication or credential file exceeds the supported bounds.")
        with path.open("rb") as handle:
            raw = handle.read(maximum + 1)
    except OSError:
        raise PublicationError("A publication or credential file could not be read.") from None
    if len(raw) > maximum:
        raise PublicationError("A publication or credential file exceeds the supported bounds.")
    return raw


def _text(path, root, legacy_windows=False, *, maximum=None):
    raw = _read(path, root, MAX_PRIVATE_BYTES if maximum is None else maximum)
    try:
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            return raw.decode("utf-16")
        return raw.decode("utf-8-sig")
    except UnicodeError:
        if legacy_windows:
            try:
                return raw.decode("cp1252")
            except UnicodeError:
                pass
        raise PublicationError("A local credential file has an unsupported encoding.") from None


def _json_text(text):
    def closed_pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise PublicationError("A local credential file has duplicate JSON fields.")
            value[key] = item
        return value

    try:
        return json.loads(text, object_pairs_hook=closed_pairs)
    except (json.JSONDecodeError, RecursionError):
        raise PublicationError("A local credential file has invalid JSON.") from None


def _json(path, root, *, maximum=None):
    return _json_text(_text(path, root, maximum=maximum))


def _bounded_entries(directory, maximum):
    try:
        files = []
        for path in directory.iterdir():
            if len(files) == maximum:
                raise PublicationError("Private directory entries exceed the supported bounds.")
            files.append(path)
        return files
    except OSError:
        raise PublicationError("A private directory could not be enumerated.") from None


def _add(secrets, value):
    if not isinstance(value, str) or not 8 <= len(value) <= 16384:
        raise PublicationError("A local credential value has an unsupported shape or length.")
    secrets.add(value)
    if len(secrets) > MAX_SECRETS:
        raise PublicationError("Local credential count exceeds the supported bounds.")


def env_secrets(text):
    """Parse literal credential assignments; never expand variables or execute shell text."""
    result = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
        if not match:
            raise PublicationError("A local lab environment file has an unsupported assignment.")
        name, value = match.groups()
        if not CREDENTIAL_NAME.search(name.upper()):
            continue
        if value[:1] in ("'", '"'):
            quote = value[0]
            end = value.find(quote, 1)
            if end < 0 or (
                value[end + 1 :].strip() and not value[end + 1 :].strip().startswith("#")
            ):
                raise PublicationError("A local credential uses an unsupported quoted assignment.")
            value = value[1:end]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        if not value:
            continue
        if "${" in value or "$(" in value or "`" in value or "\\" in value:
            raise PublicationError("Local credential assignments must contain literal values.")
        _add(result, value)
    return result


def jwk_secrets(data):
    if isinstance(data, dict) and "keys" in data:
        keys = data["keys"]
    elif isinstance(data, dict):
        keys = [data]
    else:
        keys = data
    if not isinstance(keys, list) or not 1 <= len(keys) <= 100:
        raise PublicationError("The local signing-key set has an unsupported shape.")
    result = set()
    for key in keys:
        if not isinstance(key, dict) or key.get("kty") not in ("EC", "OKP", "RSA", "oct"):
            raise PublicationError("The local signing key has an unsupported type.")
        for field in PRIVATE_JWK_FIELDS:
            if field in key:
                _add(result, key[field])
        if "oth" in key:
            other = key["oth"]
            if not isinstance(other, list) or len(other) > 100:
                raise PublicationError("The local RSA signing key has invalid private factors.")
            for factor in other:
                if not isinstance(factor, dict) or set(factor) != {"r", "d", "t"}:
                    raise PublicationError("The local RSA signing key has invalid private factors.")
                for value in factor.values():
                    _add(result, value)
    return result


def route_cookie_secrets(header, token):
    """Collect the pinned SDK's cookie chunks and embedded refresh credential.

    The fixed password-session harness uses one base64url auth-token cookie,
    optionally split into numbered chunks. Unknown formats block publication.
    This parsing is credential discovery, not authentication or JWT verification.
    """
    if (
        not isinstance(header, str)
        or not 8 <= len(header) <= 32768
        or re.search(r"[\r\n\x00]", header)
    ):
        raise PublicationError("A private route session has an unsupported cookie header.")
    parts = header.split("; ")
    if not 1 <= len(parts) <= 24:
        raise PublicationError("A private route session has too many cookie chunks.")
    result, chunks, bases = set(), {}, set()
    if len(header) <= 16384:
        _add(result, header)
    for part in parts:
        match = re.fullmatch(
            r"(sb-[A-Za-z0-9_-]+-auth-token)(?:\.(0|[1-9][0-9]*))?=([^;\r\n\x00]{1,8192})",
            part,
        )
        if not match:
            raise PublicationError("A private route session has an unsupported cookie chunk.")
        base, index, value = match.groups()
        index = int(index) if index is not None else None
        if index in chunks:
            raise PublicationError("A private route session has duplicate cookie chunks.")
        bases.add(base)
        chunks[index] = value
        # Short trailing fragments are not usable credentials by themselves;
        # collect their complete joined value and decoded credentials below.
        if len(value) >= 8:
            _add(result, value)
    if (
        len(bases) != 1
        or (None in chunks and len(chunks) != 1)
        or (None not in chunks and set(chunks) != set(range(len(chunks))))
    ):
        raise PublicationError("A private route session has incomplete or mixed cookie chunks.")
    encoded = (
        chunks[None] if None in chunks else "".join(chunks[index] for index in range(len(chunks)))
    )
    if not re.fullmatch(r"base64-[A-Za-z0-9_-]+", encoded):
        raise PublicationError("A private route session uses an unsupported cookie encoding.")
    if len(encoded) <= 16384:
        _add(result, encoded)
    try:
        payload = encoded.removeprefix("base64-")
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True)
        decoded = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        raise PublicationError(
            "A private route session has an unreadable cookie payload."
        ) from None
    if (
        not isinstance(decoded, dict)
        or decoded.get("access_token") != token
        or "refresh_token" not in decoded
    ):
        raise PublicationError(
            "A private route session cookie does not match its retained session."
        )
    _add(result, decoded["access_token"])
    _add(result, decoded["refresh_token"])
    for name in ("provider_token", "provider_refresh_token"):
        if decoded.get(name) is not None:
            _add(result, decoded[name])
    return result


def route_run_secrets(data, run_id):
    """Read only supported recovery states; partial actor/session maps are valid."""
    if (
        not isinstance(data, dict)
        or type(data.get("schema_version")) is not int
        or data["schema_version"] != 1
        or data.get("run_id") != run_id
    ):
        raise PublicationError("A private route run has an unsupported identity or schema.")
    if set(data) == {"schema_version", "run_id", "state"} and data["state"] == "starting":
        return set()
    if set(data) != {
        "schema_version",
        "run_id",
        "service",
        "sessions",
        "route_restore_required",
        "restore_required",
    }:
        raise PublicationError("A private route run has unsupported fields.")
    service = data["service"]
    if (
        not isinstance(service, dict)
        or not set(service).issubset(
            {
                "schema_version",
                "run_id",
                "actors",
                "group_id",
                "post_id",
                "image_path",
                "comment_id",
                "restore_required",
            }
        )
        or type(service.get("schema_version")) is not int
        or service["schema_version"] != 1
        or service.get("run_id") != run_id
        or not isinstance(service.get("actors"), dict)
        or not set(service["actors"]).issubset(ACTOR_ROLES)
        or type(service.get("restore_required")) is not bool
        or type(data["route_restore_required"]) is not bool
        or type(data["restore_required"]) is not bool
        or data["restore_required"]
        != (data["route_restore_required"] or service["restore_required"])
        or not isinstance(data["sessions"], dict)
        or not set(data["sessions"]).issubset(ACTOR_ROLES)
    ):
        raise PublicationError("A private route run has unsupported recovery state.")
    result = set()
    for actor in service["actors"].values():
        if (
            not isinstance(actor, dict)
            or not set(actor).issubset({"password", "token", "email", "id"})
            or "password" not in actor
        ):
            raise PublicationError("A private route actor has invalid credentials.")
        _add(result, actor["password"])
        if "token" in actor:
            _add(result, actor["token"])
    for session in data["sessions"].values():
        if not isinstance(session, dict) or set(session) != {"cookie", "token"}:
            raise PublicationError("A private route session has invalid credentials.")
        _add(result, session["token"])
        for value in route_cookie_secrets(session["cookie"], session["token"]):
            _add(result, value)
    return result


def collect_route_secrets(directory, root, secrets):
    if not (directory.exists() or directory.is_symlink()):
        return
    _safe_path(directory, root)
    if not directory.is_dir():
        raise PublicationError("Private route evidence is not a directory.")
    # An interrupted atomic write can contain the only retained copy of a newly
    # issued session. Read pending files too; malformed partial JSON blocks release.
    files = []
    try:
        for path in directory.iterdir():
            if path.name.endswith((".private.json", ".pending")):
                files.append(path)
                if len(files) > MAX_ROUTE_PRIVATE_FILES:
                    raise PublicationError(
                        "Private route evidence count exceeds the supported bounds."
                    )
    except OSError:
        raise PublicationError("Private route evidence could not be enumerated.") from None
    for path in files:
        match = re.fullmatch(rf"({RUN_ID})(?:\.private\.json|\.{RUN_ID}\.pending)", path.name)
        if not match:
            raise PublicationError("A private route run has an invalid filename.")
        for value in route_run_secrets(_json(path, root), match[1]):
            _add(secrets, value)


def collect_secrets(root=ROOT):
    root = Path(root).resolve()
    secrets = set()
    for name in ("lab-keys.json", "synthetic-keys.json"):
        path = root / "var" / name
        if path.exists() or path.is_symlink():
            data = _json(path, root)
            if not isinstance(data, dict) or len(data) > 1000:
                raise PublicationError("A collector key file has an unsupported shape.")
            for value in data.values():
                _add(secrets, value)
    access = root / "var/local-access.txt"
    if access.exists() or access.is_symlink():
        for line in _text(access, root, legacy_windows=True).splitlines():
            if line.startswith(("analyst: ", "reviewer: ", "viewer: ")):
                _add(secrets, line.split(": ", 1)[1])
    django_key = root / "var/django-secret"
    if django_key.exists() or django_key.is_symlink():
        _add(secrets, _text(django_key, root))
    # The AccessOps leaver-signal receiver's bearer token (accessops_signals setup).
    receiver = root / "var/ssf/receiver-token"
    if receiver.exists() or receiver.is_symlink():
        _add(secrets, _text(receiver, root).strip())
    enterprise_runs = root / "var/enterprise/runs"
    if enterprise_runs.exists() or enterprise_runs.is_symlink():
        _safe_path(enterprise_runs, root)
        # Every retained run contributes known secrets; the bound only stops an
        # unbounded walk. Native diagnostics legitimately retain many runs.
        runs = _bounded_entries(enterprise_runs, 1000)
        for run in runs:
            _safe_path(run, root)
            if not run.is_dir() or not re.fullmatch(r"[a-f0-9]{32}", run.name):
                raise PublicationError("An enterprise run has an invalid private path.")
            directory = run / "secrets"
            if directory.exists() or directory.is_symlink():
                _safe_path(directory, root)
                files = _bounded_entries(directory, 11)
                collect_enterprise_credentials(files, root, secrets)
    labs = root / "var/labs"
    if labs.exists() or labs.is_symlink():
        _safe_path(labs, root)
        children = list(labs.iterdir())
        if len(children) > 100:
            raise PublicationError("Local lab count exceeds the supported bounds.")
        for lab in children:
            _safe_path(lab, root)
            if not lab.is_dir():
                continue
            envs = list(lab.glob(".env*"))
            if len(envs) > 100:
                raise PublicationError("Local lab environment count exceeds the supported bounds.")
            for env in envs:
                for secret in env_secrets(_text(env, root)):
                    _add(secrets, secret)
            signing = lab / "supabase/signing_keys.json"
            if signing.exists() or signing.is_symlink():
                for secret in jwk_secrets(_json(signing, root)):
                    _add(secrets, secret)
            http_runs = lab / "http-runs"
            if http_runs.exists() or http_runs.is_symlink():
                _safe_path(http_runs, root)
                private_runs = list(http_runs.glob("*.private.json"))
                if len(private_runs) > MAX_HTTP_RUNS:
                    raise PublicationError("Private HTTP run count exceeds the supported bounds.")
                for path in private_runs:
                    run_id = path.name.removesuffix(".private.json")
                    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", run_id):
                        raise PublicationError("A private HTTP run has an invalid filename.")
                    data = _json(path, root)
                    if (
                        not isinstance(data, dict)
                        or type(data.get("schema_version")) is not int
                        or data["schema_version"] != 1
                        or data.get("run_id") != run_id
                        or not isinstance(data.get("actors"), dict)
                        or not set(data["actors"]).issubset({"owner", "member", "outsider"})
                    ):
                        raise PublicationError("A private HTTP run has an unsupported shape.")
                    for actor in data["actors"].values():
                        if not isinstance(actor, dict) or "password" not in actor:
                            raise PublicationError("A private HTTP actor has invalid credentials.")
                        _add(secrets, actor["password"])
                        if "token" in actor:
                            _add(secrets, actor["token"])
            collect_route_secrets(lab / "routes/evidence", root, secrets)
    return secrets


def collect_enterprise_credentials(files, root, secrets):
    """Collect source-run secrets even when preparation stopped before TLS files.

    This is a publication leakage check, not proof that a native profile is complete.
    The source profile is written first; missing keys cannot silently hide passwords.
    Runtime launch separately requires the entire reviewed nine-file inventory.
    """
    from integrations.enterprise.reference_controls import SECRETS
    from integrations.enterprise.reference_native_support import ACCOUNTS, FIELDS

    names = {file.name for file in files}
    if "identity-profile.json" in names:
        collect_identity_credentials(files, root, secrets)
        return
    if names == RESTORATION_SECRETS:
        # Console restoration: two generated passwords; plan and scope are not secret.
        for file in files:
            if file.name in ("bootstrap-password", "console-password"):
                value = _text(file, root)
                if not re.fullmatch(r"[A-Za-z0-9_-]{64}", value):
                    raise PublicationError("Restoration credential format is invalid.")
                _add(secrets, value)
        return
    reference = "source-profile" in names
    if names != {"bootstrap-password", "verifier-password"} and not (
        reference and names.issubset(set(SECRETS.values()))
    ):
        raise PublicationError("Enterprise private credentials have an unreviewed shape.")
    for file in files:
        value = _text(file, root)
        if file.name == "source-profile":
            data = _json(file, root)
            if (
                not isinstance(data, dict)
                or set(data) != FIELDS
                or not isinstance(data["accounts"], dict)
                or set(data["accounts"]) != ACCOUNTS
            ):
                raise PublicationError("Source private profile has an unsupported shape.")
            values = [*data["accounts"].values(), *(v for k, v in data.items() if k != "accounts")]
            if any(
                not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_-]{64}", v) for v in values
            ) or len(set(values)) != len(values):
                raise PublicationError("Source private profile credentials are invalid.")
            for secret in values:
                _add(secrets, secret)
        elif file.name.endswith("private-key.pem"):
            match = re.fullmatch(
                r"-----BEGIN PRIVATE KEY-----\n([A-Za-z0-9+/=\n]+)-----END PRIVATE KEY-----\n",
                value,
            )
            if not match or len(value) > 4096:
                raise PublicationError("Source private key format is invalid.")
            _add(secrets, value)
            _add(secrets, re.sub(r"\s", "", match[1]))
        elif file.name.endswith(".pem"):
            if (
                not re.fullmatch(
                    r"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n",
                    value,
                )
                or len(value) > 4096
            ):
                raise PublicationError("Source public certificate format is invalid.")
        else:
            if not re.fullmatch(r"[A-Za-z0-9_-]{64}", value):
                raise PublicationError("Enterprise private credential format is invalid.")
            _add(secrets, value)


def _identity_require(condition):
    if not condition:
        raise PublicationError(
            "Native identity credentials have an unreviewed or inconsistent shape."
        )


def _identity_profile(path, root):
    from integrations.identity.constants import ISSUER
    from integrations.identity.native_profile import ACCOUNTS

    value = _json(path, root, maximum=16384)
    secret_fields = {
        "django_secret": 86,
        "database_password": 64,
        "keycloak_database_password": 64,
        "bootstrap_database_password": 64,
        "operator_password": 64,
    }
    _identity_require(
        type(value) is dict
        and set(value) == {*secret_fields, "run_id", "issuer", "accounts", "operator_username"}
        and value["run_id"] == path.parent.parent.name
        and re.fullmatch(r"[a-f0-9]{32}", value["run_id"])
        and value["issuer"] == ISSUER
        and value["operator_username"] == "sb-lab-operator"
        and type(value["accounts"]) is dict
        and set(value["accounts"]) == set(ACCOUNTS)
    )
    sensitive = set()
    for field, length in secret_fields.items():
        token = value[field]
        _identity_require(type(token) is str and re.fullmatch(r"[A-Za-z0-9_-]{%d}" % length, token))
        _add(sensitive, token)
    for name, account in value["accounts"].items():
        _identity_require(
            type(account) is dict
            and set(account) == {"username", "subject", "password", "totp_base32"}
            and account["username"] == "sb-lab-" + name.replace("_", "-")
            and account["subject"] == str(uuid.uuid5(uuid.UUID(hex=value["run_id"]), name))
        )
        for field, pattern in (
            ("password", r"[A-Za-z0-9_-]{48}"),
            ("totp_base32", r"[A-Z2-7]{52}"),
        ):
            token = account[field]
            _identity_require(type(token) is str and re.fullmatch(pattern, token))
            _add(sensitive, token)
    return value, sensitive


def _identity_realm(path, root, profile, run):
    """Reject additional or changed realm credentials, including nested OTP JSON."""
    from integrations.identity.native_profile import ACCOUNTS

    template = _json(run / "source/integrations/identity/realm.json", root, maximum=65536)
    value = _json(path, root, maximum=65536)
    _identity_require(
        type(template) is dict
        and template.get("realm") == "signalbridge"
        and template.get("users") == []
        and type(value) is dict
        and set(value) == set(template)
        and type(value.get("users")) is list
        and len(value["users"]) == len(ACCOUNTS)
        and {key: item for key, item in value.items() if key != "users"}
        == {key: item for key, item in template.items() if key != "users"}
    )
    for name, user in zip(ACCOUNTS, value["users"], strict=True):
        account = profile["accounts"][name]
        expected = {
            "id": account["subject"],
            "username": account["username"],
            "firstName": "Synthetic",
            "lastName": name.replace("_", " ").title(),
            "email": account["username"] + "@identity.signalbridge.invalid",
            "enabled": name != "provider_disabled",
            "emailVerified": False,
            "requiredActions": [],
            "groups": [],
            "realmRoles": [],
        }
        _identity_require(
            type(user) is dict
            and set(user) == {*expected, "credentials"}
            and {key: item for key, item in user.items() if key != "credentials"} == expected
            and type(user["credentials"]) is list
            and len(user["credentials"]) == 2
        )
        password, otp = user["credentials"]
        _identity_require(
            password == {"type": "password", "value": account["password"], "temporary": False}
            and type(otp) is dict
            and set(otp) == {"type", "userLabel", "secretData", "credentialData"}
            and otp["type"] == "otp"
            and otp["userLabel"] == "Disposable synthetic MFA factor"
            and type(otp["secretData"]) is str
            and type(otp["credentialData"]) is str
        )
        _identity_require(
            _json_text(otp["secretData"]) == {"value": account["totp_base32"]}
            and _json_text(otp["credentialData"])
            == {
                "subType": "totp",
                "digits": 6,
                "counter": 0,
                "period": 30,
                "algorithm": "HmacSHA256",
                "secretEncoding": "BASE32",
            }
        )


def _identity_config(path, root, profile, run):
    plan = _json(run / "source/integrations/identity/native-stage-plan.json", root, maximum=32768)
    _identity_require(type(plan) is dict and type(plan.get("required_keycloak_config")) is dict)
    expected = {
        **plan["required_keycloak_config"],
        "db-password": profile["keycloak_database_password"],
        "bootstrap-admin-username": profile["operator_username"],
        "bootstrap-admin-password": profile["operator_password"],
    }
    text = _text(path, root, maximum=16384)
    _identity_require(text.endswith("\n") and not any(char in text for char in "\r\x00"))
    actual = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        _identity_require(separator == "=" and key not in actual and key in expected)
        actual[key] = value
    _identity_require(actual == expected)


def collect_identity_credentials(files, root, secrets):
    """Discover the fixed profile first, even after interrupted preparation.

    Copies must agree with the retained profile; a mismatch blocks publication.
    Source snapshots precede secret generation and remain private under var/.
    Tokens/cookies remain in memory, and database volumes are not read here.
    This is a byte-copy guard, not TLS validation or native identity acceptance.
    """
    passwords = {
        "bootstrap-password": "bootstrap_database_password",
        "console-password": "database_password",
        "keycloak-password": "keycloak_database_password",
    }
    pem_names = {
        "lab-ca.pem",
        "console-certificate.pem",
        "console-private-key.pem",
        "provider-certificate.pem",
        "provider-private-key.pem",
    }
    by_name = {file.name: file for file in files}
    allowed = {
        *passwords,
        *pem_names,
        "identity-profile.json",
        "signalbridge-realm.json",
        "keycloak.conf",
    }
    _identity_require(
        len(by_name) == len(files)
        and "identity-profile.json" in by_name
        and set(by_name) <= allowed
    )
    profile_path = by_name["identity-profile.json"]
    run = profile_path.parent.parent
    try:
        for path in files:
            _safe_path(path, root)
            _identity_require(
                path.parent == profile_path.parent and path.is_file() and path.stat().st_nlink == 1
            )
    except OSError:
        raise PublicationError("Native identity credentials could not be inspected.") from None
    profile, sensitive = _identity_profile(profile_path, root)
    for secret in sensitive:
        _add(secrets, secret)
    for name, path in by_name.items():
        if name in passwords:
            _identity_require(_text(path, root, maximum=64) == profile[passwords[name]])
        elif name == "signalbridge-realm.json":
            _identity_realm(path, root, profile, run)
        elif name == "keycloak.conf":
            _identity_config(path, root, profile, run)
        elif name in pem_names:
            value = _text(path, root, maximum=4096)
            private = name.endswith("private-key.pem")
            label = "PRIVATE KEY" if private else "CERTIFICATE"
            match = re.fullmatch(
                rf"-----BEGIN {label}-----\n([A-Za-z0-9+/=\n]+)-----END {label}-----\n", value
            )
            _identity_require(match is not None)
            if private:
                _add(secrets, value)
                _add(secrets, re.sub(r"\s", "", match[1]))


def publication_files(root=ROOT):
    git = shutil.which("git")
    if not git:
        raise PublicationError("Git is required to enumerate publishable files.")
    try:
        raw = subprocess.check_output(
            [git, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        names = raw.decode("utf-8").split("\0")
    except (OSError, UnicodeError, subprocess.SubprocessError):
        raise PublicationError("Publishable Git paths could not be enumerated.") from None
    return sorted(set(name for name in names if name))


def _private_name(name):
    parts = tuple(part.casefold() for part in PurePosixPath(name).parts)
    return (
        parts[0] in ("var", ".venv", "node_modules", "private-source", ".git")
        or parts[:2] == ("artifacts", "local")
        or any(part.startswith(".env") and part != ".env.example" for part in parts)
        or parts[-1] in (".npmrc", "signing_keys.json")
    )


def scan_publishable(root, files, secrets):
    root = Path(root).resolve()
    files = sorted(set(files))
    if len(files) > MAX_FILES:
        raise PublicationError("Publishable file count exceeds the supported bounds.")
    needles = {
        secret.encode(encoding)
        for secret in secrets
        for encoding in ("utf-8", "utf-16-le", "utf-16-be")
    }
    blocked, total = [], 0
    for name in files:
        relative = PurePosixPath(name)
        if (
            not name
            or not relative.parts
            or relative.is_absolute()
            or ".." in relative.parts
            or "\\" in name
            or ":" in name
        ):
            raise PublicationError("Git returned an unsupported publication path.")
        if _private_name(name):
            blocked.append(name)
            continue
        path = root / name
        # A tracked deletion is not published as file content.
        if not path.exists() and not path.is_symlink():
            continue
        raw = _read(path, root, MAX_PUBLIC_BYTES)
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise PublicationError("Publishable content exceeds the total scan bounds.")
        if any(needle in raw for needle in needles):
            blocked.append(name)
    return blocked


def main(root=ROOT):
    try:
        files = publication_files(root)
        secrets = collect_secrets(root)
        forbidden = scan_publishable(root, files, secrets)
    except PublicationError as error:
        print(f"BLOCKED: {error}")
        return 1
    if forbidden:
        names = []
        for name in forbidden:
            for secret in secrets:
                name = name.replace(secret, "[redacted]")
            names.append(name)
        print("BLOCKED: private content in publishable files:", json.dumps(names))
        return 1
    print(
        f"Checked {len(files)} publishable files: known generated credentials and private runtime paths are excluded."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
