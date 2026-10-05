"""Inert, bounded running-inventory preservation for separately approved profiles.

The injected request must already be bound to the reviewed engine, implement the
supplied timeout, and return bounded text. This module issues only one fixed
read-only inventory request per capture/compare and never performs mutations.
Private baseline IDs must stay in the caller's protected run; retain the expected
digest separately. Hashes detect changes against that retained digest, not an
administrator who can replace both records.

Presence proves neither untouched configuration nor uninterrupted service or
application health. Snapshots do not prevent competing resources, another engine
or races. Before each native stop/removal, recheck this admission predicate AND
the controller's authoritative label/name/image/runtime ownership controls.
Explicit preserve-baseline selection records a profile; it grants no approval.
"""

import hashlib
import hmac
import json
import re

from .verification import LabControlError, validate_identity

MAX_IDS, MAX_RAW_BYTES, MAX_PRIVATE_BYTES = 100, 6600, 8192
RUNNING_ARGUMENTS = ("ps", "--quiet", "--no-trunc")
REQUEST_SECONDS = 3
PROFILES = {"exclusive", "preserve-baseline"}
KIND = "signalbridge-preserved-running-workloads"
FIELDS = {"schema_version", "kind", "profile", "run_id", "preserved_ids", "sha256"}


def require(condition, message="Workload preservation rejected an invalid or unknown state."):
    if not condition:
        raise LabControlError(message)


def identifiers(value):
    """No truncated IDs, duplicates, unbounded iterators or implicit coercion."""
    require(type(value) in (list, tuple, set, frozenset) and len(value) <= MAX_IDS)
    require(all(type(item) is str and re.fullmatch(r"[a-f0-9]{64}", item) for item in value))
    require(len(set(value)) == len(value))
    return tuple(sorted(value))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def inventory_digest(value):
    return hashlib.sha256(canonical(identifiers(value))).hexdigest()


def running(request):
    require(callable(request))
    try:
        raw = request(RUNNING_ARGUMENTS, timeout=REQUEST_SECONDS)
    except Exception:
        raise LabControlError("Running workload inventory could not be established.") from None
    require(type(raw) is str and len(raw) <= MAX_RAW_BYTES)
    if not raw:
        return ()
    require(re.fullmatch(r"[a-f0-9]{64}(?:\r?\n[a-f0-9]{64})*(?:\r?\n)?", raw))
    return identifiers(raw.splitlines())


def validate_baseline(baseline, run_id, expected_digest):
    """Validate the private record against independently retained run/digest."""
    validate_identity(run_id)
    require(type(expected_digest) is str and re.fullmatch(r"[a-f0-9]{64}", expected_digest))
    require(type(baseline) is dict and set(baseline) == FIELDS)
    require(type(baseline["schema_version"]) is int and baseline["schema_version"] == 1)
    require(baseline["kind"] == KIND and baseline["run_id"] == run_id)
    require(type(baseline["profile"]) is str and baseline["profile"] in PROFILES)
    require(type(baseline["preserved_ids"]) is list)
    preserved = identifiers(baseline["preserved_ids"])
    require(list(preserved) == baseline["preserved_ids"])
    require(baseline["profile"] != "exclusive" or not preserved)
    require(type(baseline["sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}", baseline["sha256"]))
    payload = {name: value for name, value in baseline.items() if name != "sha256"}
    actual = hashlib.sha256(canonical(payload)).hexdigest()
    require(hmac.compare_digest(actual, expected_digest))
    require(hmac.compare_digest(baseline["sha256"], expected_digest))
    return preserved


def private_bytes(baseline, run_id, *, expected_digest):
    """Serialize validated private data; this function performs no filesystem IO."""
    validate_baseline(baseline, run_id, expected_digest)
    raw = canonical(baseline) + b"\n"
    require(len(raw) <= MAX_PRIVATE_BYTES)
    return raw


def load_private(raw, run_id, *, expected_digest):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_PRIVATE_BYTES)

    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result)
            result[name] = value
        return result

    try:
        baseline = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, ValueError, RecursionError):
        raise LabControlError("Private workload baseline is malformed.") from None
    validate_baseline(baseline, run_id, expected_digest)
    return baseline


def admitted_sets(baseline, run_id, owned_ids, expected_digest):
    preserved = set(validate_baseline(baseline, run_id, expected_digest))
    owned = set(identifiers(owned_ids))
    require(not preserved & owned, "Owned IDs overlap preserved running workloads.")
    require(len(preserved | owned) <= MAX_IDS)
    return preserved, owned


def capture(request, run_id, owned_ids=(), *, profile="exclusive"):
    """Return (private_baseline, public_counts_and_digest), before owned startup."""
    validate_identity(run_id)
    require(type(profile) is str and profile in PROFILES)
    owned = set(identifiers(owned_ids))
    preserved = running(request)
    require(not set(preserved) & owned, "Owned IDs overlap preserved running workloads.")
    require(len(set(preserved) | owned) <= MAX_IDS)
    require(
        profile != "exclusive" or not preserved, "Exclusive profile requires no foreign workloads."
    )
    baseline = {
        "schema_version": 1,
        "kind": KIND,
        "profile": profile,
        "run_id": run_id,
        "preserved_ids": list(preserved),
    }
    digest = hashlib.sha256(canonical(baseline)).hexdigest()
    baseline["sha256"] = digest
    return baseline, {"preserved_count": len(preserved), "preserved_digest": digest}


def compare(request, baseline, run_id, owned_ids=(), *, expected_digest):
    """Preserved IDs must remain running; only exact known owned arrivals pass.

    Owned containers may be created but not yet running, or already stopped.
    Presence is an inventory assertion, not configuration/service assurance.
    Return counts/digests only; IDs remain private.
    """
    preserved, owned = admitted_sets(baseline, run_id, owned_ids, expected_digest)
    observed = set(running(request))
    require(preserved <= observed, "A preserved running workload is missing.")
    require(observed <= preserved | owned, "An unexpected running workload arrived.")
    return {
        "preserved_count": len(preserved),
        "preserved_digest": expected_digest,
        "owned_count": len(owned),
        "owned_running_count": len(observed & owned),
        "running_count": len(observed),
        "running_digest": inventory_digest(observed),
    }


def mutation_admitted(candidate, observed_run_id, baseline, run_id, owned_ids, *, expected_digest):
    """Pure stop/removal predicate; observed_run_id must come from fresh inspection.

    This cannot authenticate caller-supplied metadata or replace the controller's
    scope/name/image/runtime verification, nor authorize a profile or mutation.
    """
    try:
        preserved, owned = admitted_sets(baseline, run_id, owned_ids, expected_digest)
        identifiers((candidate,))
        validate_identity(observed_run_id)
        return observed_run_id == run_id and candidate in owned and candidate not in preserved
    except LabControlError:
        return False
