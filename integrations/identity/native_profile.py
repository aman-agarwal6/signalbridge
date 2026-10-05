"""Synthetic identity provisioning for the isolated native provider lab.

Returned private values must only be written by the guarded host controller to
its verified private run directory. Importing this module creates no credentials.
"""

import base64
import copy
import json
import re
import secrets
import uuid

from .constants import CALLBACK, CLIENT_ID, ISSUER

ACCOUNTS = (
    "analyst",
    "viewer",
    "reviewer",
    "provider_disabled",
    "local_disabled",
    "unmapped",
    "expiry",
)


def material(realm, run):
    if not re.fullmatch(r"[a-f0-9]{32}", run):
        raise ValueError("A fresh isolated identity run is required.")
    if realm.get("realm") != "signalbridge" or realm.get("users") != []:
        raise ValueError("Only the empty synthetic SignalBridge realm may be prepared.")
    clients = realm.get("clients", [])
    if (
        len(clients) != 1
        or clients[0].get("clientId") != CLIENT_ID
        or clients[0].get("redirectUris") != [CALLBACK]
    ):
        raise ValueError("Identity profile has an unreviewed client destination.")
    prepared = copy.deepcopy(realm)
    accounts = {}
    for name in ACCOUNTS:
        account = {
            "username": "sb-lab-" + name.replace("_", "-"),
            "subject": str(uuid.uuid5(uuid.UUID(hex=run), name)),
            "password": secrets.token_urlsafe(36),
            "totp_base32": base64.b32encode(secrets.token_bytes(32)).decode().rstrip("="),
        }
        accounts[name] = account
        prepared["users"].append(
            {
                "id": account["subject"],
                "username": account["username"],
                # Keycloak's default VerifyUserProfile action checks these at
                # login even when requiredActions is initially empty. Supply
                # synthetic valid fields; preserve the provider's validation.
                "firstName": "Synthetic",
                "lastName": name.replace("_", " ").title(),
                "email": account["username"] + "@identity.signalbridge.invalid",
                "enabled": name != "provider_disabled",
                "emailVerified": False,
                "requiredActions": [],
                "groups": [],
                "realmRoles": [],
                "credentials": [
                    {"type": "password", "value": account["password"], "temporary": False},
                    {
                        "type": "otp",
                        "userLabel": "Disposable synthetic MFA factor",
                        "secretData": json.dumps({"value": account["totp_base32"]}),
                        "credentialData": json.dumps(
                            {
                                "subType": "totp",
                                "digits": 6,
                                "counter": 0,
                                "period": 30,
                                "algorithm": "HmacSHA256",
                                "secretEncoding": "BASE32",
                            }
                        ),
                    },
                ],
            }
        )
    profile = {
        "run_id": run,
        "issuer": ISSUER,
        "accounts": accounts,
        "django_secret": secrets.token_urlsafe(64),
        "database_password": secrets.token_urlsafe(48),
        "keycloak_database_password": secrets.token_urlsafe(48),
        "bootstrap_database_password": secrets.token_urlsafe(48),
        "operator_username": "sb-lab-operator",
        "operator_password": secrets.token_urlsafe(48),
    }
    return prepared, profile


def load_profile(path):
    from pathlib import Path

    path = Path(path)
    if not path.is_file() or path.is_symlink() or not 1024 <= path.stat().st_size <= 16384:
        raise ValueError("Private identity profile unavailable.")
    value = json.loads(path.read_bytes())
    if value.get("issuer") != ISSUER or set(value.get("accounts", {})) != set(ACCOUNTS):
        raise ValueError("Private identity profile scope changed.")
    if not re.fullmatch(r"[a-f0-9]{32}", value.get("run_id", "")):
        raise ValueError("Private identity run identity changed.")
    for name, account in value["accounts"].items():
        if account.get("username") != "sb-lab-" + name.replace("_", "-") or account.get(
            "subject"
        ) != str(uuid.uuid5(uuid.UUID(hex=value["run_id"]), name)):
            raise ValueError("Synthetic identity binding changed.")
        if not re.fullmatch(r"[A-Za-z0-9_-]{48}", account.get("password", "")) or not re.fullmatch(
            r"[A-Z2-7]{52}", account.get("totp_base32", "")
        ):
            raise ValueError("Synthetic credentials have an unexpected format.")
    for name in (
        "django_secret",
        "database_password",
        "keycloak_database_password",
        "bootstrap_database_password",
        "operator_password",
    ):
        if not re.fullmatch(r"[A-Za-z0-9_-]{64,100}", value.get(name, "")):
            raise ValueError("Native identity secret profile changed.")
    return value
