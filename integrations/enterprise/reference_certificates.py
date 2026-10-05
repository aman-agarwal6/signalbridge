"""Offline, short-lived loopback certificates for the reviewed source proof.

Uses the existing bundled PyCA library only when explicitly called. No imports
generate keys, change trust stores, install packages, contact a CA or launch TLS.
The ephemeral signing key is never serialized or returned.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .verification import LabControlError, private_run_directory, validate_identity

FILENAMES = {
    "lab-ca.pem",
    "source-certificate.pem",
    "source-private-key.pem",
    "console-certificate.pem",
    "console-private-key.pem",
}


# Reviewed lifetimes: the finite stages use two hours; only the paced 24-hour
# reliability run needs its TLS identities to outlive the measured day.
LIFETIME_HOURS = (2, 26)


def lifetime(hours):
    if type(hours) is not int or hours not in LIFETIME_HOURS:
        raise LabControlError("Unreviewed temporary certificate lifetime.")
    return timedelta(hours=hours)


def material(run, now=None, hours=2):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    validate_identity(run)
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise LabControlError("Certificate time must be explicit UTC.")
    start, end = now - timedelta(minutes=5), now + lifetime(hours)
    authority_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SB reference CA " + run)])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(authority_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(authority_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key.public_key()),
            critical=False,
        )
        .sign(authority_key, hashes.SHA256())
    )
    result = {"lab-ca.pem": ca.public_bytes(serialization.Encoding.PEM)}
    for component in ("source", "console"):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SB " + component + " " + run)])
            )
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(authority_key.public_key()),
                critical=False,
            )
            .sign(authority_key, hashes.SHA256())
        )
        result[component + "-certificate.pem"] = cert.public_bytes(serialization.Encoding.PEM)
        result[component + "-private-key.pem"] = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    # The caller receives only the two server keys. The signing key stays here.
    verify_material(result, run, now, hours)
    return result


def verify_material(value, run, now=None, hours=2):
    """Closed profile check with genuine signature/key verification, no network."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

    validate_identity(run)
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    if (
        not isinstance(value, dict)
        or set(value) != FILENAMES
        or any(type(raw) is not bytes or not 100 <= len(raw) <= 4096 for raw in value.values())
    ):
        raise LabControlError("Certificate material escaped the closed inventory.")
    try:
        ca = x509.load_pem_x509_certificate(value["lab-ca.pem"])
        expected_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "SB reference CA " + run)]
        )
        constraints = ca.extensions.get_extension_for_class(x509.BasicConstraints)
        usage = ca.extensions.get_extension_for_class(x509.KeyUsage)
        if (
            ca.subject != expected_name
            or ca.issuer != ca.subject
            or constraints.value != x509.BasicConstraints(ca=True, path_length=0)
            or not constraints.critical
            or not usage.critical
            or usage.value
            != x509.KeyUsage(False, False, False, False, False, True, True, False, False)
            or {e.oid for e in ca.extensions}
            != {
                ExtensionOID.BASIC_CONSTRAINTS,
                ExtensionOID.KEY_USAGE,
                ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            }
            or ca.not_valid_before_utc != now - timedelta(minutes=5)
            or ca.not_valid_after_utc != now + lifetime(hours)
        ):
            raise LabControlError("Certificate authority profile changed.")
        keys = []
        for cert in [ca] + [
            x509.load_pem_x509_certificate(value[c + "-certificate.pem"])
            for c in ("source", "console")
        ]:
            public = cert.public_key()
            if (
                not isinstance(public, ec.EllipticCurvePublicKey)
                or not isinstance(public.curve, ec.SECP256R1)
                or cert.signature_hash_algorithm.name != "sha256"
            ):
                raise LabControlError("Certificate algorithm changed.")
            ca.public_key().verify(
                cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm)
            )
            keys.append(
                public.public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
            if cert.extensions.get_extension_for_class(
                x509.SubjectKeyIdentifier
            ).value != x509.SubjectKeyIdentifier.from_public_key(
                public
            ) or cert.extensions.get_extension_for_class(
                x509.AuthorityKeyIdentifier
            ).value != x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()):
                raise LabControlError("Certificate key identifiers changed.")
        for component in ("source", "console"):
            cert = x509.load_pem_x509_certificate(value[component + "-certificate.pem"])
            key = serialization.load_pem_private_key(value[component + "-private-key.pem"], None)
            leaf_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
            if (
                not isinstance(key, ec.EllipticCurvePrivateKey)
                or key.public_key().public_numbers() != cert.public_key().public_numbers()
                or cert.issuer != ca.subject
                or cert.subject
                != x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, "SB " + component + " " + run)]
                )
                or cert.not_valid_before_utc != ca.not_valid_before_utc
                or cert.not_valid_after_utc != ca.not_valid_after_utc
                or cert.extensions.get_extension_for_class(x509.BasicConstraints).value
                != x509.BasicConstraints(ca=False, path_length=None)
                or not leaf_usage.critical
                or leaf_usage.value
                != x509.KeyUsage(True, False, False, False, False, False, False, False, False)
                or not cert.extensions.get_extension_for_class(x509.BasicConstraints).critical
                or {e.oid for e in cert.extensions}
                != {
                    ExtensionOID.BASIC_CONSTRAINTS,
                    ExtensionOID.KEY_USAGE,
                    ExtensionOID.EXTENDED_KEY_USAGE,
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                    ExtensionOID.SUBJECT_KEY_IDENTIFIER,
                    ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                }
                or cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                != x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
                or cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                != x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
            ):
                raise LabControlError("Server certificate profile or key binding changed.")
        if len(set(keys)) != 3:
            raise LabControlError("Separate certificate keys are required.")
    except LabControlError:
        raise
    except Exception:
        raise LabControlError("Certificate validation failed.") from None
    return {
        "run_id": run,
        "authority_sha256": hashlib.sha256(value["lab-ca.pem"]).hexdigest(),
        "server_certificate_sha256": {
            c: hashlib.sha256(value[c + "-certificate.pem"]).hexdigest()
            for c in ("source", "console")
        },
        "created_at": now.isoformat(),
        "expires_at": ca.not_valid_after_utc.isoformat(),
        "loopback_only": True,
        "host_trust_changed": False,
        "signing_key_persisted": False,
    }


def prepare(workspace, run, hours=2):
    """Caller creates and secures this exact private run before invoking us."""
    root = private_run_directory(workspace, run)
    directory = root / "secrets"
    if (
        not directory.is_dir()
        or directory.is_symlink()
        or getattr(directory.lstat(), "st_file_attributes", 0) & 0x400
        or not directory.resolve().is_relative_to(root.resolve())
        or any((directory / name).exists() or (directory / name).is_symlink() for name in FILENAMES)
    ):
        raise LabControlError("Certificate destination is missing, redirected or already used.")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    value = material(run, now, hours)
    for name, raw in value.items():
        # No overwrite, no filename input, no CA private key serialization.
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    return verify_material(value, run, now, hours)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--run", required=True)
    parser.add_argument("--hours", type=int, choices=LIFETIME_HOURS, default=2)
    options = parser.parse_args()
    import cryptography

    if not options.workspace.is_absolute() or cryptography.__version__ != "50.0.1":
        raise LabControlError("The reviewed existing certificate runtime is required.")
    receipt = prepare(options.workspace, options.run, options.hours)
    receipt.update(
        cryptography_version=cryptography.__version__, python_version=sys.version.split()[0]
    )
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
