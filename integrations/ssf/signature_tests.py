"""Real ES256 checks for leaver Security Event Tokens (needs only the cryptography package).

Run: python -m unittest integrations.ssf.signature_tests -v
"""

import base64
import json
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from integrations.ssf import tokens

NOW = 1_791_172_800


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk_for(private):
    numbers = private.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64(numbers.x.to_bytes(32, "big")),
        "y": b64(numbers.y.to_bytes(32, "big")),
    }
    jwk.update(kid=tokens.thumbprint(jwk), use="sig", alg="ES256")
    return jwk


def sign(private, claims, *, header=None, kid=None):
    # Header member order as PyJWT writes it, which AccessOps uses.
    head = header or {"alg": "ES256", "kid": kid, "typ": "secevent+jwt"}
    signing_input = b64(json.dumps(head).encode()) + "." + b64(json.dumps(claims).encode())
    r, s = decode_dss_signature(private.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return signing_input + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def claims(**changes):
    value = {
        "iss": tokens.ISSUER,
        "jti": "a" * 32,
        "iat": NOW - 5,
        "aud": tokens.AUDIENCE,
        "txn": "b" * 32,
        "sub_id": {
            "format": "iss_sub",
            "iss": "https://id.accessops.test:8443/realms/accessops-workforce",
            "sub": "0f6b2c5e-1d3a-4b7c-9e8f-123456789abc",
        },
        "events": {
            tokens.SESSION_REVOKED: {
                "event_timestamp": NOW - 10,
                "initiating_entity": "policy",
                "reason_admin": {"en": "Departure containment"},
            }
        },
    }
    value.update(changes)
    return value


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.jwk = jwk_for(self.private)
        self.keys = tokens.load_keys({"keys": [self.jwk]})

    def test_a_token_signed_like_accessops_is_accepted(self):
        token = sign(self.private, claims(), kid=self.jwk["kid"])
        facts = tokens.accept(token, self.keys, NOW)
        self.assertEqual(facts["event_type"], "session_revoked")
        self.assertEqual(facts["initiating_entity"], "policy")
        self.assertEqual(facts["reason"], "Departure containment")
        self.assertEqual(facts["key_id"], self.jwk["kid"])

    def test_a_changed_payload_or_another_key_fails_the_signature(self):
        token = sign(self.private, claims(), kid=self.jwk["kid"])
        head, _, signature = token.split(".")
        forged = head + "." + b64(json.dumps(claims(jti="c" * 32)).encode()) + "." + signature
        other = sign(ec.generate_private_key(ec.SECP256R1()), claims(), kid=self.jwk["kid"])
        for candidate in (forged, other):
            with self.subTest(), self.assertRaises(tokens.SetError) as caught:
                tokens.accept(candidate, self.keys, NOW)
            self.assertEqual(caught.exception.code, "invalid_key")

    def test_no_other_algorithm_or_signature_shape_is_accepted(self):
        kid = self.jwk["kid"]
        for header in (
            {"alg": "none", "kid": kid, "typ": "secevent+jwt"},
            {"alg": "HS256", "kid": kid, "typ": "secevent+jwt"},
            {"alg": "ES384", "kid": kid, "typ": "secevent+jwt"},
        ):
            with self.subTest(header=header), self.assertRaises(tokens.SetError):
                tokens.accept(sign(self.private, claims(), header=header), self.keys, NOW)
        token = sign(self.private, claims(), kid=kid)
        head, body, signature = token.split(".")
        short = head + "." + body + "." + b64(base64.urlsafe_b64decode(signature + "==")[:63])
        with self.assertRaises(tokens.SetError):
            tokens.accept(short, self.keys, NOW)

    def test_the_key_set_must_be_public_p256_keys_named_by_thumbprint(self):
        renamed = dict(self.jwk, kid="chosen-by-attacker")
        off_curve = dict(self.jwk, y=b64((1).to_bytes(32, "big")))
        off_curve["kid"] = tokens.thumbprint(off_curve)
        self.assertEqual(tokens.load_keys({"keys": [renamed, off_curve]}), {})
        with self.assertRaises(ValueError):
            tokens.load_keys({"keys": [dict(self.jwk, d=b64(b"\1" * 32))]})
        with self.assertRaises(ValueError):
            tokens.load_keys({"keys": [self.jwk] * (tokens.MAX_KEYS + 1)})

    def test_the_thumbprint_uses_the_rfc7638_member_order(self):
        canonical = json.dumps(
            {"crv": "P-256", "kty": "EC", "x": self.jwk["x"], "y": self.jwk["y"]},
            separators=(",", ":"),
        )
        expected = b64(__import__("hashlib").sha256(canonical.encode()).digest())
        self.assertEqual(tokens.thumbprint(self.jwk), expected)
        self.assertEqual(len(expected), 43)

    def test_duplicate_members_are_refused_before_the_signature_is_checked(self):
        head = b64(b'{"alg":"ES256","alg":"none","kid":"x","typ":"secevent+jwt"}')
        with self.assertRaises(tokens.SetError) as caught:
            tokens.accept(head + ".e30." + b64(b"\0" * 64), self.keys, NOW)
        self.assertEqual(caught.exception.code, "invalid_request")


if __name__ == "__main__":
    unittest.main()
