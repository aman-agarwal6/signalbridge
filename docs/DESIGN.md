# Design notes

SignalBridge is a local Django application that takes access-control telemetry from web apps, runs detection rules over it, and gives an analyst a place to investigate and record decisions. This page covers how the pieces fit together and where the limits are.

## Data flow

```
source app ──► local outbox ──► collector ──► queue ──► worker ──► cases ──► analyst decision
               (durable outbox) (HMAC check)  (SQLite / PostgreSQL) (rules R1–R5)
```

| Component | Code | Responsibility |
| --- | --- | --- |
| Courier | `integrations/sender.mjs` | Sends outbox files to the collector over loopback only; deletes a file only after a matching receipt |
| Collector | `bridge/ingestion.py` | Verifies signatures, validates the event schema, rejects duplicates and floods |
| Queue and worker | `bridge/worker.py` | Processes accepted events, retries failures, moves repeated failures to a dead-letter state |
| Detection engine | `bridge/engine.py` | Evaluates R1–R5 and links evidence to cases |
| Rule replay | `bridge/evaluation.py` | Replays proposed rule changes against labeled history before a reviewer approves them |
| Console | `bridge/views.py`, `templates/` | Case review, scanner findings, authorization evidence, analyst practice |

The lightweight console runs behind Waitress on `127.0.0.1:8741` with SQLite. The enterprise profile adds PostgreSQL app-first queue locking and native concurrency proof. It remains an isolated reference lab, not a public hosting recipe.

## Event contract

Events are JSON, at most 16 KiB, with a fixed set of fields including app, environment, event ID, event time, pseudonymous actor and resource IDs, and an operation/outcome/reason drawn from closed lists. The collector assigns the source class from the signing key; it is not a caller-controlled wire field. Unknown or missing fields, duplicate keys, non-finite numbers and wrong types are rejected. There are no fields for raw names, emails, IP addresses, tokens or record contents. This reduces accidental disclosure; pseudonyms remain linkable, and a malicious sender could still encode information.

Each request is signed with HMAC-SHA-256 over a version prefix, the app, the key ID, the request time and the exact body. The signature is compared in constant time, request timestamps outside a five-minute window are rejected, and keys can be rotated with an overlap window. A valid signature attributes the signed bytes to a holder of the shared key; it does not prove that the source observed the event correctly.

Version 2 adds exactly one `membership` object containing an app-scoped pseudonymous `subject` and `state` (`removed` or `granted`). It is permitted only on successful `membership.change` observations with the corresponding reason. `actor` remains the operator; `subject` is the affected account. `resource` means one exact private resource, not an implicit group or wildcard. The signing envelope and URL stay at v1; the signed body declares its schema version.

Only an ingest key with server-controlled `can_assert_membership=True` can submit v2 assertions. The default is false, including every existing key after migration 0008. The collector rechecks this capability under its transaction lock. Extra fields and caller-provided authority claims are rejected. The Node courier validates v2 before enqueueing; authority remains a server decision. Privileged local administrators can still alter database records, so this is not independent attestation.

## Delivery

- An event ID seen again with identical content gets a duplicate acknowledgement. The same ID with different content gets `409`.
- Each app can submit 600 new events per minute; beyond that the collector returns `429`.
- The queue commits before the collector returns `202`.
- The worker retries with backoff and marks an event dead after five failures, so a failure is visible instead of silently dropped.

## Detection rules

**R1: repeated unsuccessful private reads.** One actor is denied, or finds nothing, on three or more *distinct* private records in the same app within a rolling five-minute window. Reading the same record repeatedly does not count.

**R2: allowed read after a boundary change.** An allowed private read that the source tags with `membership_removed` or `policy_regression` opens a critical-priority case.

**R3: resource-scoped membership correlation.** Match an accepted v2 assertion's affected subject to an allowed-read actor, within the same app, environment, collector-assigned source and exact resource. The latest available assertion must unambiguously say removed, strictly before the read and no more than 24 hours earlier. The read can say `member`; it does not need a suspicious label. Priority is high pending source verification, not a confirmed disclosure.

R3 uses event time, accepts out-of-order delivery, suppresses legitimate re-grants and treats equal-time/conflicting state as inconclusive. A delayed grant that contradicts an existing R3 case adds evidence, retains the original audit, reopens the case and changes its explanation/priority for reassessment. It never automatically closes a case or performs external response. Candidate loading is capped at 10,000 events; over-capacity processing retries visibly and can enter the existing dead-letter state. A resource/time index and a lightweight membership-history probe avoid fetching a second payload for ordinary reads without v2 history.

This covers resource-level correlation in the core pipeline. Group membership needs an explicit, reviewed group-to-resource mapping before integration. The existing BetTail, Wazuh and ZAP receipts do not validate a v2 adapter; none was enabled or replayed in this change. Missing events, alternate owner/admin permissions and clock skew can still cause false alerts.

**R4: extended denied-resource activity.** One actor receives denied reads for at least five distinct resources within an inclusive 30-minute window, with at least ten minutes between the earliest and latest evidence. Errors and not-visible results are excluded. Cases use fixed 30-minute endpoint buckets; combined case evidence can exceed one trigger window. A fast burst followed by a later denial can qualify. Legitimate stale links and approved testing remain indistinguishable from suspicious intent.

**R5: multi-account same-resource denials.** At least six distinct denied reads involve at least three actors and one exact resource within an inclusive ten-minute window. Fixed endpoint buckets bound case identities. This does not establish coordination or compromise; activity spread across resources falls outside this pattern. App, environment and source boundaries remain separate.

Both rules have versions, paired controls and bounded indexed candidate loading. The historical challenge remains attached to its original source, where none of these alerted:

- slow probing spread over more than five minutes (new R4 now covers a declared subset),
- probing distributed across several accounts (new R5 covers one shared resource only),
- revocations where the telemetry doesn't say which member was affected. R3 addresses new richer inputs, while this original v1 challenge remains a documented gap.

## Console access control

- Every list, object, export and write is scoped to apps the user is a member of. Superusers get no implicit bypass.
- Roles: viewers read, analysts investigate and propose, reviewers approve another person's proposal. Nobody can approve their own rule change.
- Django sessions last one hour with HttpOnly, SameSite=Strict cookies. Secure cookies, HTTPS redirects and HSTS are enabled outside local mode; the local console uses loopback HTTP. CSRF protection covers browser-session writes. Signed ingestion is exempt from CSRF and instead requires its HMAC gate. The CSP blocks scripts, external connections and framing.
- Login is throttled after eight failures per address and username over 15 minutes.
- Access is re-checked inside the database transaction before a write, which closed a race where a user could still write for a moment after losing access.

## Integrations

**Wazuh 4.14.8.** Events are exported through a recoverable ledger into a Wazuh manager in a Docker lab, using custom rules on the built-in JSON decoder (`integrations/wazuh/signalbridge_rules.xml`). The recorded backfill delivered 64 of 64 records: 31 expected alerts, 33 expected non-alerts, none missing or duplicated. A separate run restarted the collector twice without losing or duplicating input.

**OWASP ZAP 2.17.0.** Passive scan reports are imported as findings. When the scan target was deliberately taken offline, the run was recorded as failed and incomplete rather than as a clean result. Re-importing the same report doesn't create duplicates.

**BetTail route harness.** `integrations/bettail-routes.mjs` checks member, outsider and removed-member access against a local copy of the BetTail app, then restores membership and re-checks.

Labs use synthetic identities, dedicated containers and networks, resource limits and no production credentials.

## Testing

The historical September 26 suite receipt records 1,083 tests: 1,030 Python plus 53 Node. New checks exercise capability denial and withdrawal, schema validation, late removals/grants, source boundaries, resource/time limits, console rendering and evaluation metrics. The Node tests use mocked responses. Offline detection checks run fixed scenarios in an in-memory database with network and process calls blocked.

Recorded runs are in `docs/evidence/` as JSON receipts, and the [evidence viewer](../portfolio/index.html) presents them record by record.

### Frozen detection evaluation — September 29

[Readable report and five reference investigations](../portfolio/evaluation.html) · [Execution receipt](evidence/20260929-membership-evaluation.json).

The implementation was frozen before the separate 22-scenario corpus was created. Inputs and labels were sealed before execution. Labels are parsed and joined only after all predictions. The same AI/builder knows the rules and authored the scenarios: this is a separate evaluation set, **not a blind holdout or independent review**. Freeze hashes normalize CRLF to LF for portability; input/label files retain their exact declared bytes in Git without line-ending conversion. Hashes identify content and can detect changes, but do not prevent an administrator replacing the records.

| Measure | Recorded result | Denominator |
| --- | --- | --- |
| True positives / misses | 6 / 2 | 8 suspicious scenarios |
| False positives / true negatives | 2 / 8 | 10 benign scenarios |
| Precision | 75% | 6 true positives / 8 positive predictions |
| Recall | 75% | 6 true positives / 8 suspicious scenarios |
| False-positive rate | 20% | 2 false positives / 10 benign scenarios |
| Inconclusive | 4, excluded from binary scoring | 22 total scenarios |

The unit is one scenario with any currently supported detection. Cases corrected by late grants are reported separately; their historical analyst workload is not hidden. E16 (legitimate stale bookmarks) and E17 (lost re-grant) are false alerts; E07 and E08 remain slow/distributed misses. Do not generalize these small selected proportions to production traffic. All events entered via HMAC-signed Django test-client requests and the real queue/worker, with memory-only SQLite. No actual source-app content was read.

The five report reviews are AI-authored teaching examples, with evidence, decisions, uncertainty and proposed retests. They are not personal work samples or completed source-app remediation. The report gives Aman a separate exercise to author and defend his own decisions.

### Enterprise evaluation and native PostgreSQL — October 1

The current [48-scenario evaluation receipt](evidence/20261001-enterprise-detection-evaluation-format2.json) preserves **TP15 / FP6 / FN8 / TN12**, plus **7 inconclusive scenarios**. Precision is **15/21 (71.4%)**, recall **15/23 (65.2%)**, and false-positive rate **6/18 (33.3%)**. These are selected builder-authored scenarios, not blind or production estimates. The data include owner rights, alternate grants, missing/delayed telemetry, horizon boundaries, errors, slow and same-resource multi-account activity, and cross-app/source controls.

**24 initial review cases**, **23 final active cases** and **one late correction** describe analyst workload; **21 alerted scenarios** is a different unit. Delivery used **181 signed in-process requests**, **174 unique events** and **7 duplicate retries** in memory-only SQLite. Q31's legitimate stale links remain a false positive; Q41's activity across different resources remains a miss. A migration formatting correction required a fresh freeze and repeat of the same 48 scenarios. Both rounds remain; the repeat is not additional accuracy evidence. Neither round replaces the September results or supplies native source-app observations.

The [native PostgreSQL receipt](evidence/20261001-postgresql-in-network-1d8fd148036e43b0915fbbe86606d013.json) records **nine passed methods**, zero failures/errors/skips: concurrent duplicate/conflicting ingestion, two-worker processing with app serialization, concurrent case edits, duplicate/conflicting review-task requests and actual child-process SIGKILL recovery. Evidence and processing completion remained atomic. Tests took 4.297 seconds; the bounded stage took 22.917 seconds. This is a component proof at its exact retained revision, not sustained reliability or enterprise deployment proof.

Two non-root 512 MiB/one-CPU containers ran on an internal network without published ports, runtime egress, host socket or other-project mounts. Cached dependencies were hash-verified and installed in finite temporary storage. Kernel mount checks, main shutdown and independent watchdog shutdown passed. Docker Desktop was stopped afterward. All earlier zero-test failures remain preserved; the [diagnosis](evidence/20261001-postgresql-stage-diagnosis.json) groups them without changing raw receipts. The final 12 GiB whole-stage guard is a detection threshold, not a hard disk quota. PostgreSQL transport was plaintext inside the isolated component network; the enterprise TLS profile remains unfinished.

The current local verification passed **1,177 Python and 62 distinct Node methods**, plus configuration, both migration checks, lint/format and publication scanning. Its exact source and log hashes are linked from `docs/enterprise-milestone.json`. The courier imports eight persistence methods, so they run once, not as a duplicate separate group. Tests use disposable databases, and transport checks use doubles where stated. A passing regression count does not establish accuracy, independent assurance or personal competency.

The console adds assignment, acknowledgement, deadlines, typed notes and evidence-bound tasks, with assigned/unassigned/unacknowledged/overdue queues. Two separate machine capabilities read bounded evidence or create a fixed review task. Native task concurrency passed; genuine Shuffle execution and the matching retest plus reviewer gate remain unfinished. Resolved does not mean verified remediation.

CI runs a separate pinned-image disposable PostgreSQL job and the current frozen evaluation alongside SQLite checks. It uses read-only repository permissions and no production credentials. The [first published run](https://github.com/aman-agarwal6/signalbridge/actions/runs/36954576523) failed: PostgreSQL checkout could not write runner-owned command files, and the historical v1 challenge's shared resources let R5 correlate between scenarios. No native CI tests ran in that attempt. The corrected container matches the hosted runner UID, checks ownership before checkout and installs dependencies in an unprivileged temporary virtual environment, retaining dropped capabilities and resource limits. The corrected historical harness projects only R1/R2; real R5 cases are still retained and tested, while R3–R5 evaluation remains separate. No detector or frozen evaluation source changed. Corrected remote results must be read from the current run; local success does not imply remote success. The one maintained [enterprise handoff PDF](../output/pdf/SignalBridge_Enterprise_Handoff.pdf) groups architecture, current evidence, remaining gates and interview explanations. The paragraphs below retain the historical September context.

### Historical verification and next boundaries — September

The [September 29 verification receipt](evidence/20260929T234005261035Z-7f0549f8.json) records **1,102 passed tests: 1,048 Python and 54 Node, zero failures or skips**. All 11 recorded check groups passed, including configuration, migration drift, lint/format, the publication scan, the frozen evaluation and the original challenge. Source remained unchanged during execution. The existing installed Python environment was reused read-only; all code and disposable storage belonged to this public checkout. An additional publication scan included all 408 tracked and new candidate files and found no known local credentials or forbidden runtime paths; this is a bounded scan, not a universal secret-detection guarantee.

Earlier development checks caught an extra payload read on ordinary traffic and a Windows long-path failure in snapshot fixtures. The final implementation avoids the extra payload fetch; shortened, exclusively created test fixture directories preserve the snapshot tests without changing machine settings or removing assertions. The new evaluation/report was content-checked, including every local link and generated outcome. Browser visual inspection of the new static report was not performed.

The GitHub workflow now declares `push` to main, `pull_request` and manual triggers. It uses the supported SQLite database, read-only repository permissions, pinned actions and no repository secrets or deployments. It validates the frozen evaluation as well as the existing tests. This prepares future CI; local execution does not establish remote CI success. [GitHub trigger reference](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows), [secure workflow reference](https://docs.github.com/en/actions/reference/security/secure-use).

Migration 0008 was exercised in disposable tests only. No running local database was migrated and no signing key was granted new authority. To integrate real v2 observations later, review the source's membership-to-resource semantics and secret handling, apply the migration to the intended local environment, explicitly authorize a dedicated source key, and run member/removal/re-grant/owner controls. Do not enable it merely to make a demonstration alert.

A multi-day native reliability run remains future work: predeclare duration and workload, record received/unique/processed counts, duplicates, age of oldest pending event, processing latency and recovery after bounded interruptions. Keep delivery reliability separate from detection accuracy. Such a run has not been performed here; existing recovery unit tests and historical Wazuh receipts are narrower evidence. A genuinely independent scenario author and human review of Aman's own report would add more hiring value than inflating this fixture set.

## Limits

- Integration results are recorded lab runs, not continuous monitoring.
- Test scenarios were written by the builder with knowledge of the rules; they aren't a blind evaluation.
- SQLite supports lightweight single-worker use. Nine isolated native PostgreSQL concurrency/recovery checks passed; enterprise TLS/source/identity and 24-hour operation remain unfinished.
- A Shuffle SOAR integration was started and paused after a storage startup failure.
