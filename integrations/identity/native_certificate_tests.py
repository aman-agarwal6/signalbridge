"""Explicit optional-runtime check: certificates remain in synthetic memory only."""

import ipaddress
import json
import unittest
from datetime import datetime, timezone

from integrations.identity import native_certificates as certificates

RUN = "a" * 32


class NativeCertificateTests(unittest.TestCase):
    def test_certificate_authority_and_distinct_ip_identities_in_memory(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

        files, public = certificates.material(RUN, datetime(2026, 10, 3, tzinfo=timezone.utc))
        self.assertEqual(len(files), 5)
        self.assertFalse(public["ca_private_key_persisted"])
        self.assertFalse(public["host_trust_changed"])
        self.assertFalse(any("PRIVATE KEY" in value for value in (json.dumps(public),)))
        ca = x509.load_pem_x509_certificate(files["lab-ca.pem"])
        self.assertEqual(
            ca.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.path_length, 0
        )
        for component, address in certificates.ADDRESSES.items():
            leaf = x509.load_pem_x509_certificate(files[component + "-certificate.pem"])
            ca.public_key().verify(
                leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm)
            )
            self.assertEqual(
                leaf.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ).value.get_values_for_type(x509.IPAddress),
                [ipaddress.ip_address(address)],
            )
            self.assertIn(
                ExtendedKeyUsageOID.SERVER_AUTH,
                leaf.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value,
            )
            self.assertEqual(
                (leaf.not_valid_after_utc - leaf.not_valid_before_utc).total_seconds(), 7500
            )
        self.assertNotEqual(files["console-private-key.pem"], files["provider-private-key.pem"])


if __name__ == "__main__":
    unittest.main()
