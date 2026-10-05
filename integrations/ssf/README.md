# AccessOps leaver signals

SignalBridge receives [AccessOps](https://github.com/aman-agarwal6/AccessOps) leaver events and opens a case when a person who has left still gets in. AccessOps is the transmitter: it signs Shared Signals (SSF 1.0) Security Event Tokens and queues them. SignalBridge polls for them (RFC 8936); AccessOps never connects out. The contract is AccessOps' `contracts/leaver-signals.md`.

| Event | AccessOps sends it when | SignalBridge does |
| --- | --- | --- |
| RISC `account-disabled` | Containment is verified | Stores it as containment evidence; it marks the subject as departed |
| CAEP `session-revoked` | No session remains | Stores it as containment evidence |
| CAEP `session-established` | A sign-in or token use after the departure took effect | Opens or reopens a critical **L1** case for that subject |

A second detection, **L2**, uses SignalBridge's own records: a sign-in to this console by the same workforce issuer and subject after its `account-disabled` time opens a critical case. Both case types live in a separate `accessops` workspace that only its members can see. Nothing here disables an account or ends a session; people decide that.

## How a token is accepted

1. **Transport.** Connect to `127.0.0.1:8443` with TLS server name `accessops.test`, trusting only the lab CA file. There is no system trust store, no hosts-file change and no redirect following, and responses are capped at 1 MiB.
2. **Transmitter metadata.** It must name the AccessOps issuer, the fixed key URL and RFC 8936 polling. The key URL is never taken from a token.
3. **Header.** It must be exactly `typ: secevent+jwt`, `alg: ES256` and a `kid`. Any other member (for example `jku`, `jwk`, `x5u`, `crit`) is refused, so a token cannot bring its own key.
4. **Signature.** ES256 is checked with the `cryptography` library against a published P-256 key whose `kid` is its RFC 7638 thumbprint. A key set holding private material is refused. An unknown `kid` triggers at most one key refetch per minute.
5. **Claims.** The schema is closed: `iss` and `aud` must match exactly, and `jti` must be 32 lowercase hex. `sub_id` must be an `iss_sub` subject, and there must be exactly one known event, with bounded timestamps. An unknown claim or event member is refused. That keeps the contract's promise of no names, emails or IP addresses.
6. **Store, then acknowledge.** A token is acknowledged only after its database commit. A redelivery is stored once (deduplicated by `jti`). The same `jti` with different facts is refused and the original kept.
7. **Refusals** go back in `setErrs` with RFC 8935 codes (`invalid_key`, `invalid_issuer`, `invalid_audience`, `invalid_request`). AccessOps then stops offering that token, so a refusal is final; that's why a dry run comes first.

## Run it

The poll needs the `cryptography` package, which the identity runtime provides. Run from the repository root:

```powershell
python -B manage.py accessops_signals setup --receiver-env ..\accessops\.local\ssf-receiver.env --ca ..\accessops\.local\tls\root.crt --grant analyst:analyst
var\enterprise\identity\<id>\venv\Scripts\python.exe -B manage.py accessops_signals poll --dry-run --receipt
var\enterprise\identity\<id>\venv\Scripts\python.exe -B manage.py accessops_signals poll --receipt
python -B manage.py accessops_signals status
```

`setup` copies the receiver token and CA certificate into the git-ignored `var/ssf`. It never prints the token, and the publication scan treats it as a secret. A dry run verifies and counts every offered token without storing, acknowledging or reporting anything, so the transmitter's queue stays as it was. Receipts contain counts, the TLS and key fingerprints and timings, but no token or subject IDs.

Tests: `tests/test_leaver_signals.py` covers the receive loop, refusals, deduplication, detection and the case page. `integrations/ssf/signature_tests.py` uses real ES256 keys and runs in the release gate's certificate step.

## Limits

- One transmitter, one stream, configured by the lab; there is no SSF stream-management API.
- A signal proves what AccessOps observed and signed, not what the session accessed.
- L2 covers sign-ins to SignalBridge itself. Source-app telemetry uses app-scoped pseudonyms, not workforce issuer and subject, so it cannot be matched to a leaver.
- The workforce issuer is checked for shape, not pinned. AccessOps sets it per lab, and a wrong pin would make every refusal final.
