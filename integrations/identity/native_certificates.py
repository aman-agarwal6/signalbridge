"""Offline two-hour certificates for one reviewed native identity lab.

The CA signing key exists only in memory. Server keys stay in the already private
run directory. This module never changes an OS/browser/container trust store.
"""

import argparse
import hashlib
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from integrations.enterprise.verification import private_run_directory, validate_identity

ADDRESSES = {"console": "127.0.0.1", "provider": "127.0.0.2"}


def material(run, now=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    validate_identity(run)
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise ValueError("Certificate time must be UTC.")
    begin, end = now - timedelta(minutes=5), now + timedelta(hours=2)
    authority = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SB identity CA " + run)])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(authority.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(begin)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(authority.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.public_key()),
            critical=False,
        )
        .sign(authority, hashes.SHA256())
    )
    result = {"lab-ca.pem": ca.public_bytes(serialization.Encoding.PEM)}
    for component, address in ADDRESSES.items():
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "SB identity " + component + " " + run
                        )
                    ]
                )
            )
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(begin)
            .not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(address))]),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.public_key()),
                critical=False,
            )
            .sign(authority, hashes.SHA256())
        )
        ca.public_key().verify(
            leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm)
        )
        result[component + "-certificate.pem"] = leaf.public_bytes(serialization.Encoding.PEM)
        result[component + "-private-key.pem"] = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    public = {
        "run_id": run,
        "created_at": now.isoformat(),
        "expires_at": end.isoformat(),
        "public_file_sha256": {
            name: hashlib.sha256(raw).hexdigest()
            for name, raw in result.items()
            if "private-key" not in name
        },
        "server_addresses": ADDRESSES,
        "host_trust_changed": False,
        "ca_private_key_persisted": False,
    }
    return result, public


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--run", required=True)
    options = parser.parse_args()
    directory = private_run_directory(options.workspace, options.run) / "secrets"
    if (
        not directory.is_dir()
        or directory.is_symlink()
        or getattr(directory.lstat(), "st_file_attributes", 0) & 0x400
    ):
        raise ValueError("Prepared private credential directory required.")
    values, receipt = material(options.run)
    for name, raw in values.items():
        with (directory / name).open("xb") as stream:
            stream.write(raw)
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
