# Evidence guide

Every claim on the [front page](../README.md) points to a **receipt**: a JSON file in [`docs/evidence/`](evidence/) written by the run itself, not by hand. This guide explains, in plain language, what each run did, why it matters and which fields to read. It also says what each run does **not** show.

## How a run is made

1. **Offline gate.** `scripts/record_enterprise_offline.py` runs the Python and Node test suites, Django and migration checks, lint and formatting, and a publication scan that checks publishable files against local credentials. It records a receipt, and a native launcher refuses to start unless that receipt matches the current source.
2. **Native launch.** The launcher starts pinned container images (by digest) on an internal Docker network with no internet route, dropped Linux capabilities and memory/disk limits. A watchdog stops the run if the host runs short of memory or disk.
3. **Receipt.** The run records counts, hashes and pass/fail decisions. Credentials, raw logs and databases stay in a private, ignored folder; the public receipt holds only what is safe to share.
4. **Two shutdown checks.** The launcher stops everything, then a separate check confirms that nothing it started is still running.

## Fields that mean the same thing in every receipt

| Field | Meaning |
| --- | --- |
| `status`, `acceptance_passed` | The run's own verdict against its declared acceptance checks |
| `source_sha256`, `source_unchanged` | Hash of the exact code snapshot, and confirmation that it did not change during the run |
| `runtime_isolation_verified` | The containers matched the reviewed profile: internal network, no egress, no extra privileges |
| `main_shutdown_verified`, `independent_shutdown_verified` | Both shutdown checks passed |
| `limits` | What this run does not establish; read these before quoting a result |
| `approval_reference` | The owner decision that authorized the launch |

Some receipts are **promotions** (`kind: signalbridge-native-receipt-promotion`). These are verbatim copies of a private receipt, wrapped with the private file's hash so the copy can be checked against the original.

## The runs

### Access assurance ([b8667b81](evidence/20261002-reference-access-b8667b816ce8419da7f3d5d9ac9d6ad6.json))

**What happened.** Two synthetic business apps (documents and expenses) ran with a deliberately injected authorization defect: a member removed from a private group could still read its document. The apps sent signed telemetry through a transactional outbox, SignalBridge ingested it, and rule R3 (access after membership removal) opened one investigation.

**Why it matters.** This is the core idea working end to end on real components: a permission change linked to what the account could actually read.

**Read.** `native_proof.collection` (23 outbox claims, 23 committed results), `native_proof.reconciliation` (31 HTTP controls, zero extra claims), `native_proof.source_http_requests`.

**Limits.** One injected defect in synthetic apps; the Wazuh forwarding here is a binding check, not an independent Wazuh rediscovery of R3.

### Login and MFA ([73632025](evidence/20261004-identity-native-73632025aeee400bb7ee49b69fba7c99.json))

**What happened.** A real Keycloak server handled password + TOTP sign-in for analyst, viewer and reviewer accounts. 28 protocol controls covered wrong passwords and codes, callback replay and state tampering, CSRF, per-app scoping, immediate permission withdrawal, signing-key rotation, back-channel logout and session expiry. A real Chromium browser then walked through sign-in by keyboard only and checked cookies, CSP, framing and logout.

**Why it matters.** The browser walkthrough found a real bug: the console's Content-Security-Policy blocked the redirect to the identity provider. That bug was fixed in the product and covered by a regression test.

**Read.** `native_receipt.execution.controls` (28 entries), `native_receipt.browser_result` (5 controls, engine and version), `entire_identity_gate_passed`.

**Limits.** The accessibility check covers keyboard reach and labelled inputs only; it is not a WCAG audit.

### Wazuh ([0d137b47](evidence/20261003-wazuh-native-collection-0d137b4720ad476faa68d36754b7357f.json), [4a5748dc](evidence/20261003-wazuh-native-recovery-4a5748dcc7a74525a7469dc8d802438a.json))

**What happened.** SignalBridge exported SOC records to a real Wazuh manager. The first run checked that all 24 records were archived and all 8 expected alerts fired exactly once. The recovery run stopped the collector mid-stream and rotated the logs, then confirmed nothing was lost or duplicated.

**Read.** Both are promotions; inside `receipt`, see `native_proof`, `preservation_verified` and `profile: recovery_rotation` on the second.

**Limits.** `continuous_delivery_verified` is false: these are bounded runs. Continuous delivery is covered under Endurance.

### ZAP ([d975b97f](evidence/20261003-authenticated-zap-offline-d975b97fad814c9b8e4304e114c776e5.json))

**What happened.** The reference app ran twice, once with a missing security header and once fixed, and its authenticated responses were captured without credentials. The pinned ZAP image imported those captures offline (it sent no requests of its own) and ran one passive rule.

**Read.** `scanner_proof.phases.fault.findings` (one finding, rule 10021) and `scanner_proof.phases.corrected.findings` (none).

**Limits.** This tests ZAP's analysis of authenticated responses, not ZAP's own login engine or an active scan.

### Investigation to fix ([de4f6409](evidence/20261003-console-restoration-de4f6409fdf444a9bc22cf60463cdb05.json), [6bce0948](evidence/20261003-console-restoration-6bce09482a3b430aadb98b589d40f04e.json))

**What happened.** The console database from the access run was backed up and restored into a **separate** database, migrated, and then used for real operator work: acknowledge, assign, create a remediation task, import a retest, refuse a self-review, and approve through an independent reviewer. The second run did the same with the ZAP finding and checked that it attached to the right app only.

**Why it matters.** The workflow is proven on restored data, so backup and restore are shown to be usable, not just to complete.

**Read.** `runner.workflow.case_operations`, `runner.restored`, `restored_into_separate_database`, `runner.pending_migrations` (empty).

### PostgreSQL ([ed3829e7](evidence/20261001-postgresql-in-network-ed3829e7b3dd45379d0c0290e324df85.json))

**What happened.** 14 concurrency and crash-recovery tests ran against real PostgreSQL. They covered two workers processing the same events, duplicate and conflicting ingestion, a sign-in racing a sign-out, two analysts submitting at the same case version, two reviewers deciding at once, and a killed process whose uncommitted work rolls back.

**Read.** `tests` (14 run, 0 failures).

### Monitoring ([0cd4256f](evidence/20261003-monitoring-native-0cd4256f4a1c4f2692f67eae4704bd53.json))

**What happened.** Prometheus scraped the console's metrics and Grafana rendered the dashboards while the lab created a backlog, processed it and recovered. 24 controls checked that the metrics told the truth.

**Read.** `receipt.proof.controls`, `receipt.proof.backlog_phase`, `receipt.proof.recovery_dashboard`.

**Limits.** Uses a standalone SQLite console with a disposable filesystem; the host disk guard is separate.

### Endurance ([rehearsal](evidence/20261004-reliability-rehearsal-8a1889fec8ef49f5acde3c01bfa88e63-remeasured.json), [continuous](evidence/20261004-reliability-continuous-894fb388a2004b43b6b1643e93342df4-summary.json))

**What happened.** The 24-hour schedule was compressed into 40 minutes, with all five interruptions in order: workers stopped, collector stopped, source delivery cut, collector log rotation and the Wazuh connector stopped. All 1,201 reads from the two apps were accepted, processed and seen by Wazuh exactly once, with 8 retries and zero unexpected records. Separately, a continuous run delivered all 27,118 reads over 13.5 hours (68 sent outside their 250 ms slot, zero service errors). Its Wazuh capture covered the first 10.6 hours.

**Read.** Rehearsal: `measurement.recovery`, `measurement.anomalies`, `measurement.processing_all_periods` (p95 249 ms). Continuous: `reads_delivered`, `runner_interruptions_completed`, `wazuh_capture.cause`.

**Limits.** The full 24-hour run was not completed. The first attempt's Wazuh collector stopped at 10.6 hours on a log-folder limit, which has since been fixed; the owner chose not to repeat the day. The rehearsal was re-measured under an owner-approved definition (schedule judged when a read is sent), and the original receipt is kept unchanged. See [lessons learned](LESSONS.md).

### Shuffle ([workflow run](evidence/20261005-shuffle-native-workflow-315cfb85-9c28-4e4e-9cac-8ce455e92448.json))

**What happened.** A fixed Shuffle workflow calls SignalBridge's signed review-task API. Shuffle needs Docker-socket access, which on this PC could reach other projects' containers, so it runs only inside a dedicated VirtualBox VM with no network adapter and no shared folders.

**Result.** Shuffle's own backend, Orborus and workers ran nine scenarios as genuine executions inside the VM; each has a Shuffle execution ID. The first created one review task (HTTP 201); a retry with a new signature returned the same task as a duplicate; a replayed request (409 `request_replayed`), the same key with changed content (409 `idempotency_conflict`), another app's case (404 `case_unavailable`) and stale evidence (409 `case_evidence_changed`) were refused; a receiver that never answered timed out; and after a reply was deliberately lost, the retry recovered the task the receiver had committed. The receiver ended with exactly 2 tasks, 2 idempotency records and 8 accepted nonces. Getting there took 13 VM runs; the fixes are in [lessons learned](LESSONS.md).

**Read.** `dispatcher.scenarios` (per-scenario Shuffle execution ID, HTTP status, duplicate flag and error), `guest.receiver` (task, idempotency and nonce counts), `guest.steps`, `boot_attempts`, `shutdown_verified`.

**Limits.** The guest's report is builder-run, not independent attestation. One fixed workflow with one HTTP action; synthetic cases; the VM runs with one virtual CPU on this PC (see the Shuffle README).

### Leaver signals from AccessOps ([dry run](evidence/20261005-accessops-leaver-dry-run-f567427abbbc4929ad50e25be2c84724.json), [poll](evidence/20261005-accessops-leaver-poll-eefe76ecded04ffe9892bd174c973232.json), [round 2 dry run](evidence/20261005-accessops-leaver-dry-run-18b5f038aaef4f228abe27f8d2719f94.json), [round 2 poll](evidence/20261005-accessops-leaver-poll-931402fb1ee44209b58c60063f63150f.json))

**What happened.** AccessOps, a separate project that runs a departure workflow, signs Shared Signals (SSF 1.0) Security Event Tokens when a leaver's account is disabled, when their sessions are revoked, and when the account is used after the departure. SignalBridge polled its running lab over TLS with a pinned CA. A dry run first verified all 32 queued tokens (ES256 signature, issuer, audience and a closed claim schema) without storing or acknowledging anything. The real poll then stored all 32, acknowledged each only after storing it, and left the queue empty; a second poll was offered nothing. The 10 sign-in signals belonged to 3 departed test accounts, and each opened one critical "access after departure" case. Those three are **test-induced**: AccessOps' intake test backdated each departure by 5 seconds, so the worker's own sign-in just before it counted as after departure. SignalBridge reported correctly what AccessOps signed, and the AccessOps test has since been fixed. In a second round, AccessOps' own end-to-end check re-enabled a contained test account and signed in. The 6 resulting signals went through the same dry run and poll, and opened one new critical case. That one is a **genuine detection**: the sign-in came after the first containment.

**Read.** `by_type`, `refused` (empty), `acknowledged`, `queue_drained`, `case_actions`, and `transmitter` (TLS certificate and signing-key fingerprints). No token or subject identifiers are included.

**Limits.** Synthetic test workers in a local lab. A signal shows what AccessOps observed and signed, not what the session accessed. See the [receiver README](../integrations/ssf/README.md).

### Accessibility ([axe scan](evidence/20261005-accessibility-axe-scan.json))

**What happened.** axe-core 4.13 ran in headless Chrome against 15 console pages (overview, integrations, detections, events, findings, scans, investigations and one case with its printable brief, checks, replay, practice, requirements, the capability lab, a 404 page and sign-in) and the three portfolio pages, each in light and dark color schemes, using WCAG 2.0-2.2 A/AA and best-practice rules. It ran on a disposable copy of the console with synthetic data, signed in as the synthetic analyst. It found six kinds of problem, all fixed: an activity chart whose `role="img"` hid its links from screen readers, invalid definition-list markup, an empty table header, low contrast (a mint link color inherited inside a light panel at 1.29:1, and small grey text just under 4.5:1), a skipped heading level, and a bare default 404 page without a main landmark. After the fixes: 0 violations on all 38 page runs.

**Read.** `found_before_fixes` (cause and fix for each), `pages` (per page and color scheme), `scanner.sha256` for `scripts/accessibility_scan.mjs`.

**Limits.** Automated rules catch only part of WCAG. There was no manual screen-reader, zoom or full keyboard audit, and 40 items axe marks for manual review were not reviewed. One desktop viewport only.

### Detection ([evaluation](evidence/20261005-enterprise-detection-evaluation-public-release.json))

**What happened.** 48 builder-written scenarios ran through the five rules with the final implementation frozen and hashed before the labels were joined: precision 15/21, recall 15/23, false-positive rate 6/18, with 7 scenarios inconclusive.

**Read.** `metrics`, `initial_metrics` (before analyst correction), `scenarios`, `implementation.files` (the frozen hashes).

**Limits.** The rule authors wrote the scenarios, so this is regression evidence, not independent accuracy.

## Older files

The September files in `docs/evidence/` are earlier development checkpoints, kept on purpose, including failed and incomplete runs. Each file states its own status and limits. [Lessons learned](LESSONS.md) explains the failures that came before the passing runs.

## What none of this shows

- Production readiness, high availability or performance at enterprise scale. Everything ran on one PC with synthetic data.
- Independent attestation. Receipts are written by the builder's own tooling; they can be checked for consistency, not for honesty against a hostile operator.
- Coverage of real identity providers, SOC tools or apps beyond the pinned versions listed in each receipt.
