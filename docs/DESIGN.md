# Design notes

SignalBridge is a local Django application that takes access-control telemetry from web apps, runs detection rules over it, and gives an analyst a place to investigate and record decisions. This page covers how the pieces fit together and where the limits are.

## Data flow

```
source app ──► local outbox ──► collector ──► queue ──► worker ──► cases ──► analyst decision
               (Node courier)   (HMAC check)   (SQLite)  (rules R1, R2)
```

| Component | Code | Responsibility |
| --- | --- | --- |
| Courier | `integrations/sender.mjs` | Sends outbox files to the collector over loopback only; deletes a file only after a matching receipt |
| Collector | `bridge/ingestion.py` | Verifies signatures, validates the event schema, rejects duplicates and floods |
| Queue and worker | `bridge/worker.py` | Processes accepted events, retries failures, moves repeated failures to a dead-letter state |
| Detection engine | `bridge/engine.py` | Evaluates rules R1 and R2 and links evidence to cases |
| Rule replay | `bridge/evaluation.py` | Replays proposed rule changes against labeled history before a reviewer approves them |
| Console | `bridge/views.py`, `templates/` | Case review, scanner findings, authorization evidence, analyst practice |

The console runs behind Waitress on `127.0.0.1:8741` with SQLite. It is meant for a single trusted machine, not public hosting.

## Event contract

Events are JSON, at most 16 KiB, with a fixed set of fields: app, environment, source, event ID, timestamps, pseudonymous actor and resource IDs, and an operation/outcome/reason drawn from closed lists. Unknown or missing fields, duplicate keys, non-finite numbers and wrong types are rejected. There are no fields for names, emails, IP addresses, tokens or record contents, so that data can't end up in telemetry by accident.

Each request is signed with HMAC-SHA-256 over a version prefix, the app, the key ID, the request time and the exact body. The signature is compared in constant time, requests older than five minutes are rejected, and keys can be rotated with an overlap window. A valid signature proves which key sent the event, not that the source observed it correctly.

## Delivery

- An event ID seen again with identical content gets a duplicate acknowledgement. The same ID with different content gets `409`.
- Each app can submit 600 new events per minute; beyond that the collector returns `429`.
- The queue commits before the collector returns `202`.
- The worker retries with backoff and marks an event dead after five failures, so a failure is visible instead of silently dropped.

## Detection rules

**R1: repeated unsuccessful private reads.** One actor is denied, or finds nothing, on three or more *distinct* private records in the same app within a rolling five-minute window. Reading the same record repeatedly does not count.

**R2: allowed read after a boundary change.** An allowed private read that the source tags with `membership_removed` or `policy_regression` opens a critical-priority case.

Known gaps, confirmed by a pre-declared challenge where none of these alerted:

- slow probing spread over more than five minutes,
- probing distributed across several accounts,
- revocations where the telemetry doesn't say which member was affected.

## Console access control

- Every list, object, export and write is scoped to apps the user is a member of. Superusers get no implicit bypass.
- Roles: viewers read, analysts investigate and propose, reviewers approve another person's proposal. Nobody can approve their own rule change.
- Django sessions last one hour with HttpOnly, SameSite=Strict cookies. CSRF protection covers all changes. The CSP blocks scripts, external connections and framing.
- Login is throttled after eight failures per address and username over 15 minutes.
- Access is re-checked inside the database transaction before a write, which closed a race where a user could still write for a moment after losing access.

## Integrations

**Wazuh 4.14.8.** Events are exported through a recoverable ledger into a Wazuh manager in a Docker lab, using custom rules on the built-in JSON decoder (`integrations/wazuh/signalbridge_rules.xml`). The recorded backfill delivered 64 of 64 records: 31 expected alerts, 33 expected non-alerts, none missing or duplicated. A separate run restarted the collector twice without losing or duplicating input.

**OWASP ZAP 2.17.0.** Passive scan reports are imported as findings. When the scan target was deliberately taken offline, the run was recorded as failed and incomplete rather than as a clean result. Re-importing the same report doesn't create duplicates.

**BetTail route harness.** `integrations/bettail-routes.mjs` checks member, outsider and removed-member access against a local copy of the BetTail app, then restores membership and re-checks.

Labs use synthetic identities, dedicated containers and networks, resource limits and no production credentials.

## Testing

The suite has 1,083 tests: 1,030 Python tests plus 53 Node tests for the courier, HTTP client and route harness. The Node tests use mocked responses. Offline detection checks run fixed scenarios in an in-memory database with network and process calls blocked.

Recorded runs are in `docs/evidence/` as JSON receipts, and the [evidence viewer](../portfolio/index.html) presents them record by record.

## Limits

- Integration results are recorded lab runs, not continuous monitoring.
- Test scenarios were written by the builder with knowledge of the rules; they aren't a blind evaluation.
- SQLite is the supported database. PostgreSQL configuration exists but concurrency hasn't been demonstrated.
- A Shuffle SOAR integration was started and paused after a storage startup failure.
