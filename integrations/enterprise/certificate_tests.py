"""Real in-memory certificate/TLS controls using the existing bundled PyCA runtime.

Run explicitly with that runtime. No sockets, daemon, trust-store writes or
dependency installs. These checks are separate from the Django test totals.
"""

import hashlib
import os
import shutil
import ssl
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from .https_deadline import lab_context
from .reference_certificates import FILENAMES, material, prepare, verify_material
from .verification import LabControlError, private_run_directory

ROOT = Path(__file__).resolve().parents[2]


def handshake(context, certificate, key, hostname="127.0.0.1"):
    """Drive real OpenSSL TLS over four finite memory BIOs; never open a socket."""
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(certificate, key)
    client_in, client_out, server_in, server_out = [ssl.MemoryBIO() for _ in range(4)]
    client = context.wrap_bio(client_in, client_out, server_hostname=hostname)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    done, transferred = set(), 0
    for _ in range(32):
        for name, endpoint in (("client", client), ("server", server)):
            if name in done:
                continue
            try:
                endpoint.do_handshake()
                done.add(name)
            except ssl.SSLWantReadError:
                pass
        for output, incoming in ((client_out, server_in), (server_out, client_in)):
            raw = output.read()
            transferred += len(raw)
            if transferred > 65536:
                raise AssertionError("Memory TLS byte ceiling reached.")
            incoming.write(raw)
        if len(done) == 2:
            return client.version()
    raise AssertionError("Memory TLS handshake did not complete within the step bound.")


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.parent = ROOT / "var/tests"
        self.workspace = self.parent / ("reference-certificate-" + uuid.uuid4().hex)
        self.workspace.mkdir(parents=True)
        self.run = uuid.uuid4().hex
        self.directory = private_run_directory(self.workspace, self.run)
        (self.directory / "secrets").mkdir(parents=True)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        path = self.workspace.resolve()
        if not path.is_relative_to(self.parent.resolve()) or self.workspace.is_symlink():
            raise RuntimeError("Unsafe certificate test cleanup.")
        shutil.rmtree(path)

    def test_run_unique_separate_keys_and_ca_key_never_returned(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        first, second = material(self.run, now), material(self.run, now)
        self.assertEqual(set(first), FILENAMES)
        self.assertNotEqual(first["lab-ca.pem"], second["lab-ca.pem"])
        self.assertNotEqual(first["source-private-key.pem"], first["console-private-key.pem"])
        receipt = verify_material(first, self.run, now)
        self.assertFalse(receipt["signing_key_persisted"])
        self.assertFalse(receipt["host_trust_changed"])
        self.assertNotIn(b"PRIVATE KEY", first["lab-ca.pem"])
        self.assertEqual(datetime.fromisoformat(receipt["expires_at"]), now + timedelta(hours=2))

    def test_reliability_lifetime_is_explicit_reviewed_and_exactly_verified(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        long = material(self.run, now, 26)
        receipt = verify_material(long, self.run, now, 26)
        self.assertEqual(datetime.fromisoformat(receipt["expires_at"]), now + timedelta(hours=26))
        with self.assertRaises(LabControlError):
            verify_material(long, self.run, now)
        for hours in (3, 0, "26", 72):
            with self.subTest(hours=hours), self.assertRaises(LabControlError):
                material(self.run, now, hours)

    def test_explicit_utc_and_closed_run_identity_required(self):
        for run, now in (("../escape", None), (self.run, datetime(2026, 10, 2))):
            with self.subTest(run=run), self.assertRaises(LabControlError):
                material(run, now)

    def test_tampered_wrong_scope_mismatched_and_extra_material_rejected(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        good = material(self.run, now)
        for replacement in (
            {**good, "source-private-key.pem": good["console-private-key.pem"]},
            {**good, "lab-ca.pem": material(self.run, now)["lab-ca.pem"]},
            {**good, "signing-key.pem": b"not-a-key"},
            {**good, "source-certificate.pem": b"changed"},
        ):
            with self.subTest(keys=sorted(replacement)), self.assertRaises(LabControlError):
                verify_material(replacement, self.run, now)
        with self.assertRaises(LabControlError):
            verify_material(good, "a" * 32, now)
        with self.assertRaises(LabControlError):
            verify_material(good, self.run, now + timedelta(seconds=1))

    def test_no_overwrite_and_redirected_destination_rejected(self):
        prepare(self.workspace, self.run)
        existing = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (self.directory / "secrets").iterdir()
        }
        with self.assertRaises(LabControlError):
            prepare(self.workspace, self.run)
        self.assertEqual(
            existing,
            {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (self.directory / "secrets").iterdir()
            },
        )
        with patch(
            "integrations.enterprise.reference_certificates.private_run_directory",
            return_value=self.workspace,
        ):
            with self.assertRaises(LabControlError):
                prepare(self.workspace, self.run)

    def test_real_tls_strict_chain_host_and_expiry_without_network_or_keylog(self):
        prepare(self.workspace, self.run)
        directory = self.directory / "secrets"
        keylog = self.workspace / "unexpected-keylog"
        with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog)}):
            context = lab_context(directory / "lab-ca.pem")
            for component in ("source", "console"):
                self.assertIn(
                    handshake(
                        context,
                        directory / (component + "-certificate.pem"),
                        directory / (component + "-private-key.pem"),
                    ),
                    ("TLSv1.2", "TLSv1.3"),
                )
            with self.assertRaises(ssl.SSLCertVerificationError):
                handshake(
                    context,
                    directory / "source-certificate.pem",
                    directory / "source-private-key.pem",
                    "127.0.0.2",
                )
            untrusted = self.workspace / "wrong-ca.pem"
            untrusted.write_bytes(material(self.run)["lab-ca.pem"])
            with self.assertRaises(ssl.SSLCertVerificationError):
                handshake(
                    lab_context(untrusted),
                    directory / "source-certificate.pem",
                    directory / "source-private-key.pem",
                )
            expired = material(self.run, datetime.now(timezone.utc) - timedelta(hours=3))
            for name, raw in expired.items():
                (self.workspace / name).write_bytes(raw)
            with self.assertRaises(ssl.SSLCertVerificationError):
                handshake(
                    lab_context(self.workspace / "lab-ca.pem"),
                    self.workspace / "source-certificate.pem",
                    self.workspace / "source-private-key.pem",
                )
        self.assertFalse(keylog.exists())
