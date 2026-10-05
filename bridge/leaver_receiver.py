"""RFC 8936 polling receiver for AccessOps leaver signals.

A token is acknowledged only after it is committed, so a crash between the two leads to a
redelivery, which is stored once and then acknowledged (deduplication by jti). Refused tokens
are reported in setErrs; AccessOps then stops offering them, so refusals are deliberate and
counted. A dry run verifies and counts without storing, acknowledging or reporting anything,
which leaves the transmitter's queue exactly as it was.
"""

import re
import time
from collections import Counter

from integrations.ssf.tokens import (
    ISSUER,
    SetError,
    UnknownKey,
    accept,
    load_keys,
    verify_signature,
)
from integrations.ssf.transport import TransmitterError

from .leaver import store

POLL_METHOD = "urn:ietf:rfc:8936"
BATCH = 50
MAX_POLLS = 40
KEY_REFRESH_SECONDS = 60
JTI = re.compile(r"[0-9a-f]{32}")


class Receiver:
    def __init__(
        self,
        transmitter,
        token,
        *,
        dry_run=False,
        max_polls=MAX_POLLS,
        verifier=verify_signature,
        keys_from=load_keys,
        clock=time.time,
        monotonic=time.monotonic,
    ):
        self.transmitter = transmitter
        self.token = token
        self.dry_run = dry_run
        self.max_polls = max_polls
        self.verifier = verifier
        self.keys_from = keys_from
        self.clock = clock
        self.monotonic = monotonic
        self.keys = {}
        self.unknown_refetch_at = None
        self.key_fetches = 0
        self.counts = Counter()
        self.errors = Counter()
        self.subjects = set()
        self.polls = 0
        self.acknowledged = 0
        self.reported = 0
        self.drained = False

    def check_configuration(self):
        meta = self.transmitter.configuration()
        if meta.get("issuer") != ISSUER or meta.get("jwks_uri") != ISSUER + "/api/v1/ssf/jwks":
            raise TransmitterError("The transmitter metadata does not name the AccessOps issuer.")
        methods = meta.get("delivery_methods_supported")
        if not isinstance(methods, list) or POLL_METHOD not in methods:
            raise TransmitterError("The transmitter does not offer RFC 8936 polling.")
        return meta

    def refresh_keys(self, *, unknown_kid):
        """Fetch the key set; an unknown kid may trigger a refetch at most once per minute."""
        if unknown_kid:
            if (
                self.unknown_refetch_at is not None
                and self.monotonic() - self.unknown_refetch_at < KEY_REFRESH_SECONDS
            ):
                return False
            self.unknown_refetch_at = self.monotonic()
        try:
            self.keys = self.keys_from(self.transmitter.jwks())
        except ValueError as error:
            raise TransmitterError("The published key set is not usable: " + str(error)) from None
        self.key_fetches += 1
        return True

    def handle(self, jti, token):
        """(jti to acknowledge | None, setErr entry | None) for one offered token."""
        now = int(self.clock())
        try:
            try:
                facts = accept(token, self.keys, now, self.verifier)
            except UnknownKey:
                if not self.refresh_keys(unknown_kid=True):
                    raise
                facts = accept(token, self.keys, now, self.verifier)
            if facts["jti"] != jti:
                raise SetError("invalid_request", "The token's jti differs from its delivery key.")
        except SetError as error:
            self.errors[error.code] += 1
            return None, {"err": error.code, "description": error.description[:200]}
        if self.dry_run:
            self.counts["verified_" + facts["event_type"]] += 1
            return None, None
        result, signal = store(facts, token)
        if result == "conflict":
            self.errors["jti_conflict"] += 1
            return None, {
                "err": "invalid_request",
                "description": "This jti was already received with different content.",
            }
        self.counts[result] += 1
        if result == "stored":
            self.counts[facts["event_type"]] += 1
        self.subjects.add((signal.subject_issuer, signal.subject_id))
        return jti, None

    def run(self):
        self.check_configuration()
        self.refresh_keys(unknown_kid=False)
        ack, errs = [], {}
        while self.polls < self.max_polls:
            sets, more = self.transmitter.poll(
                self.token,
                max_events=BATCH,
                ack=[] if self.dry_run else ack,
                set_errs={} if self.dry_run else errs,
            )
            self.polls += 1
            self.acknowledged += len(ack)
            self.reported += len(errs)
            ack, errs = [], {}
            for jti, token in sets.items():
                self.counts["offered"] += 1
                if not isinstance(jti, str) or not JTI.fullmatch(jti):
                    self.errors["unusable_delivery_key"] += 1
                    continue
                done, error = self.handle(jti, token)
                if done:
                    ack.append(done)
                elif error:
                    errs[jti] = error
            if self.dry_run:
                # Nothing is acknowledged, so a second poll would offer the same tokens.
                self.drained = not more
                break
            if not sets and not more:
                self.drained = True
                break
        if not self.dry_run and (ack or errs):
            self.transmitter.poll(self.token, max_events=0, ack=ack, set_errs=errs)
            self.polls += 1
            self.acknowledged += len(ack)
            self.reported += len(errs)
        return self
