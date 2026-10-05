# SignalBridge engineering reference

This is the technical reference behind the [README](../README.md) and the [evidence guide](EVIDENCE.md). It groups architecture, trust boundaries, rules, integrations and operating commands. The [milestone ledger](enterprise-milestone.json) names current gates and exact receipts; `docs/evidence/` preserves failures and historical revisions.

**Current native access proof:** the October 2 reference run processed 23/23 events across documents and expenses, detected one deliberately injected document-access regression, checked owner/cross-app/re-grant behavior, restored the source and passed both shutdown checks. [Walkthrough](../portfolio/access-assurance.html) | [Receipt](evidence/20261002-reference-access-b8667b816ce8419da7f3d5d9ac9d6ad6.json).

**Native results since October 3** (all with main and independent shutdown verified; see the [evidence guide](EVIDENCE.md)):
- Keycloak MFA, app scoping, back-channel logout, signing-key rotation, HTTP cookie/header policy and real session expiry: 28/28 controls.
- Wazuh: 24/24 archived records and 8/8 alerts exactly once, including a collector stop, input rotation and backlog recovery.
- ZAP: one header finding in the fault phase, none in the corrected retest, imported into a restored console.
- PostgreSQL: 14/14 checks, including identity and retest/reviewer races. Monitoring: 24/24 Prometheus/Grafana controls.
- Separate restoration: retained native consoles copied, backed up, restored into a fresh database and used for a complete investigation-to-fix workflow with independent review.

Still incomplete: the real-browser identity walkthrough, Shuffle workflow execution, copied BetTail runtime and the 24-hour reliability run.

## Architecture and code map

```text
source authorization -> transactional outbox -> signed intake -> durable queue
                                                              -> worker -> case -> analyst/reviewer
```

The local console uses Django, Waitress and SQLite on `127.0.0.1:8741`. The enterprise lab adds isolated PostgreSQL, synthetic source applications and selected security tools. It is a reference lab, not a public deployment recipe.

| Follow this question | Start in | Responsibility |
| --- | --- | --- |
| Did access really change? | `reference_lab/` | Authenticated document/expense paths, effective rights, transactional outbox, reversible defects |
| Can we trust the record? | `bridge/ingestion.py`, `integrations/sender.mjs` | Schema, HMAC, capability/replay checks; durable courier acknowledgement |
| What happens after acceptance? | `bridge/worker.py` | Claims, retries, per-app serialization and atomic processing |
| Why did this alert? | `bridge/engine.py`, `bridge/evaluation.py` | Versioned detection and evidence-linked replay |
| Who may investigate or approve? | `bridge/case_workflow.py`, `bridge/case_verification.py`, `bridge/case_brief.py` | App permissions, assignment/tasks, retest/reviewer gate and readable reports |
| How do tools exchange evidence? | `integrations/wazuh_enterprise/`, `integrations/zap_enterprise/` | Closed profiles, reconciliation and historical report imports |
| Is processing healthy? | `bridge/monitoring.py`, `bridge/worker_health.py`, `integrations/enterprise/reliability_source.py` | Bounded metrics, worker pulses and source workload pacing |
| How was a claim checked? | `tests/`, `reference_lab/test_*.py`, `docs/evidence/` | Denial/regression checks and retained execution identities |

## Evidence contract and delivery

Events use closed JSON schemas of at most 16 KiB: app, environment, ID/time, pseudonymous actor/resource and permitted operation/outcome/reason. Unknown/missing fields, duplicate keys, non-finite values and incorrect types fail validation. Collector-assigned provenance comes from the signing key, never a caller's claimed source. Raw content, names, emails, IP addresses and credentials have no designated fields. Pseudonyms remain linkable; a malicious source could still encode information.

HMAC-SHA-256 binds the version prefix, app, key ID, request timestamp and exact body. Comparison is constant time; a five-minute request window limits replay; key overlap supports rotation. A signature identifies possession of the shared key, not the truth of the observation. The courier removes an outbox file only after its matching acknowledgement.

Version 2 adds `membership.subject` and `membership.state` (`removed`/`granted`) only to successful `membership.change` events. The actor is the operator; the subject is the affected account; the resource is one exact object. A server-controlled `can_assert_membership` capability, false by default, is rechecked transactionally. Existing v1 bodies and signing envelopes remain compatible. Group removal must be translated through effective resource access, including owner/alternate grants, before asserting lost permission.

The reference app commits permission changes and their outbox entries together. Reads record observations after the actual authorization/result path and return the committed observation UUID. Stable app-scoped pseudonyms and known synthetic bodies join requests, outbox records and cases without exporting private content.

| Condition | Result |
| --- | --- |
| Same event ID and identical content | Duplicate acknowledgement; no second logical event |
| Same ID with different content | HTTP 409 conflict |
| More than 600 new events/minute/app | HTTP 429 |
| Valid new event | Queue committed before HTTP 202 |
| Processing failure | Backoff; dead-letter state after five failures |

PostgreSQL workers claim app-level queue work using `SKIP LOCKED` where its queue semantics apply, preserving per-app serialization and atomically committing evidence with completion. SQLite remains a serial fallback. Persistent attempt counts describe committed claims; crashes can roll back a claim, so physical requests/retries must be measured separately. Fourteen native PostgreSQL methods ([ed3829e7](evidence/20261001-postgresql-in-network-ed3829e7b3dd45379d0c0290e324df85.json)) cover concurrent ingestion, duplicates/conflicts, two workers, case/task updates, killed-process recovery, identity callback/logout races and retest/reviewer races. A working restored application is covered separately ([de4f6409](evidence/20261003-console-restoration-de4f6409fdf444a9bc22cf60463cdb05.json)).

## Detection semantics

Correlations preserve app, environment and source boundaries. Candidate loading is bounded; capacity failure becomes a visible retry/dead-letter result, not silent partial evaluation.

| Rule | Declared trigger | Important limitation |
| --- | --- | --- |
| R1 | One actor, at least three distinct unsuccessful private reads in five minutes; denied or not-visible outcomes | Repeated reads of one resource do not count; intent is unknown |
| R2 | Allowed read explicitly labeled `membership_removed` or `policy_regression` by the source | Relies on that label; critical-priority signal is not independent discovery |
| R3 | Latest unambiguous resource assertion says removed; matching subject subsequently reads successfully within 24 hours | High priority pending verification; missing rights, grants or telemetry can mislead |
| R4 | At least five distinct denied resources in an inclusive 30-minute window, spanning at least ten minutes | Fixed endpoint buckets; fast activity followed by a late denial can qualify; stale links can false-alert |
| R5 | At least six distinct denied reads by at least three actors against one exact resource in ten minutes | Does not establish coordinated attackers; activity across different resources is excluded |

R3 uses event time and accepts out-of-order delivery. Re-grants suppress the pattern; equal-time/conflicting assertions are inconclusive. A delayed contradictory grant adds evidence and reopens an existing case for reassessment, preserving the original audit. It never closes a case automatically. The read may have an ordinary `member` reason: the separate removal creates the contradiction. A 10,000-event candidate cap, resource/time indexes and lightweight history probe bound query work.

The native reference run exercised one documents regression. It does not validate a copied BetTail v2 adapter. Historical v1 telemetry lacking an affected subject cannot support R3, even after the newer rule exists.

## Investigation and authorization

Every list, object, export and write requires current app membership; superusers have no implicit app bypass. Viewers read, analysts investigate/propose and reviewers approve another person's proposal. Sensitive writes recheck permission inside the transaction to close the withdrawal race.

Cases support assignment, business owner/criticality, acknowledgement, deadlines, categorized notes and evidence-bound review/remediation tasks. Notes separate facts, interpretation, uncertainty and actions. An independent current reviewer and matching revalidated native retest are required for verified remediation. Historical resolved records do not become verified fixes; operator imports and suggested tasks cannot stand in for human judgment.

Retest submission now refuses to replace a current pending review for the same task. The existing case/task transaction holds the version stable; a valid repeat POST cannot silently invalidate the reviewer decision or consume the 20-submission allowance. Stale and reviewer-rejected submissions remain eligible for a fresh review. The retest and reviewer races later passed natively on PostgreSQL ([ed3829e7](evidence/20261001-postgresql-in-network-ed3829e7b3dd45379d0c0290e324df85.json)), and a restored console ran the whole flow with an independent reviewer ([de4f6409](evidence/20261003-console-restoration-de4f6409fdf444a9bc22cf60463cdb05.json)). [Regression evidence](evidence/20261003-pending-retest-review-regression.json).

Learning checkpoint: explain why repeating a valid authenticated request must not destroy another analyst's pending work. A pending review is a workflow state, not evidence that remediation is already verified.

The printable analyst brief escapes free text, rechecks membership, rejects oversized evidence and flags incomplete narratives. It groups observations, saved notes, tasks and verification. It contains internal notes and account names; review it before sharing.

Two machine capabilities separately authorize bounded evidence reads and one scoped review task. They use separate credentials, signatures, app scope, size/replay limits and transactional idempotency. They cannot change source accounts, send external messages, contain activity, close cases or approve remediation.

Local password sessions last one hour with HttpOnly/SameSite=Strict cookies; login throttles after eight failures per address/username over 15 minutes. Browser writes remain CSRF-protected; signed intake uses HMAC instead. Outside local mode, Secure cookies, HTTPS redirects and HSTS apply. The CSP blocks scripts, external connections and framing.

## Enterprise identity

OIDC is opt-in and disabled in the ordinary loopback HTTP console. An exact HTTPS issuer/opaque subject maps to an explicitly provisioned existing account. Email matching, automatic enrollment and provider role grants are absent; local app permissions remain authoritative.

Authlib handles authorization-code flow with S256 PKCE and nonce. The adapter checks signatures, issuer, audience, expiry, exact stored callback and browser/issuer-bound single-use state. Form-post mode keeps codes out of URLs. Start is CSRF-protected; POST callbacks/logout use state or signed-token validation. Duplicate fields, wrong hosts, arbitrary redirects, oversized inputs and query callbacks are rejected. Logs retain error classes, not provider secrets.

| Boundary | Implemented policy |
| --- | --- |
| Admission | Active account/link; TLS; expiry is the earlier of provider expiry and admission +15 minutes; activity cannot extend it |
| Lifecycle | Cookie rotation; keyed digests instead of raw tokens/session cookies; every request rechecks activation, link version, revocation and expiry |
| Withdrawal | Writes lock/recheck the registry; disable/re-enable cannot resurrect old sessions; database failures fail closed |
| Back-channel logout | Exact issuer/subject/provider session; replay digest; tombstone blocks delayed login replies; a shared lock serializes bounded lab sign-ins |
| Limits | Eight links/active admissions per account; four pending flows/browser; 20 starts/minute; 60 protocol attempts/minute including failures |

The prepared profile separates console `https://127.0.0.1:18842` from provider `https://127.0.0.2:18844/realms/signalbridge`. Host-only session cookies are Secure/HttpOnly/SameSite=None for cross-site POST; CSRF cookies remain Strict. Explicit CA/key files belong under `var/enterprise/identity`. Token exchange has a five-second total deadline, 8 KiB request/64 KiB response bounds and no DNS, proxies, redirects or ambient certificate trust. Native signing-key rotation passed in [73632025](evidence/20261004-identity-native-73632025aeee400bb7ee49b69fba7c99.json).

Trusted local `federated_identity` commands provision/enable/disable links, recover accounts and prune expired state. Recovery reads a password privately from standard input, validates it, disables/versions provider links, revokes old sessions and audits atomically without changing roles. Pruning previews at most 200 eligible rows/table, uses a one-day expiry buffer and requires explicit `--apply`; it preserves identities/audits. These are local operator procedures, not remote enrollment or authenticated human decisions.

Native result: identity run [73632025](evidence/20261004-identity-native-73632025aeee400bb7ee49b69fba7c99.json) passed 28 protocol controls against a real Keycloak with password + TOTP, including role-protected writes, CSRF rejection, callback replay and state tampering, unchanged-session permission withdrawal, back-channel logout, signing-key rotation and real session expiry. A real Chromium walkthrough then passed 5 browser controls (keyboard MFA sign-in, cookie attributes, CSP inline-script block, framing block, sign-out) and found a real CSP `form-action` bug, since fixed. Identity case fixtures remain labeled synthetic; they cannot certify a source finding or verified remediation. [Exact native launch plan](../integrations/identity/native-stage-plan.json).

The host controller requires a current passing source receipt and explicit launch approval. It validates cached images and wheels, provisions fresh private credentials, checks runner kernel restrictions before releasing execution, and retains effective runtime facts. A separate watchdog revokes execution and repeatedly checks scoped shutdown for 60 seconds; an unreachable daemon leaves shutdown unverified. The proposed three-container stage permits 3 GiB combined RAM, a four-GiB whole-stage disk guard measured before Docker/downloads, a 25-GiB disk reserve and four-GiB available host-memory reserve. There are no published ports, runtime internet access or host trust changes. Database/Keycloak restrictions are checked through Docker metadata; only the runner receives an independent kernel probe. The same controls governed the passing native run.

Earlier launch attempts stopped safely on host-environment problems: the launch wrapper omitted Windows' `ProgramData` (crashing Docker's settings loader), and another project's containers were running. The wrapper now preserves `ProgramData` and `SystemDrive`, and a startup guard can request shutdown without a reachable engine while preserving unrelated workloads. Those incidents are retained: [incident](evidence/20261003-keycloak-startup-stopped.json), [correction checks](evidence/20261003-windows-startup-paths-checks.json), [preserved workloads](evidence/20261003-docker-late-return-workloads.json).

The October 3 update adds opt-in public signing-key refresh for the fixed Keycloak lab endpoint. Login and validated back-channel logout share CA/configuration-bound keys, a 300-second expiry, a 15-second per-profile cooldown, one in-flight fetch and an eight-profile process-local cap. Initial/expired fetch failures fail closed; static mode remains the default. Full signature, issuer, audience, expiry, nonce and MFA checks still decide admission. Eight tests use real signatures with in-memory keys, and native rotation passed in [73632025](evidence/20261004-identity-native-73632025aeee400bb7ee49b69fba7c99.json). [Implementation and scoped checks](evidence/20261003-preservation-key-refresh-preparation.json).

Learning checkpoint: explain why an unfamiliar key identifier may justify one bounded refresh, but cannot authorize a login or supply a new key URL. A cached public key is not proof that an account still has application permission.

The identity controller now binds the fresh network ID and database volume metadata before creating containers. Main and watchdog reject resource replacement or a foreign network attachment; only an empty, uncommitted startup window is permitted for at most 90 seconds. Thirty-one focused host/driver methods passed with native operations forbidden. Docker volumes have no immutable identity in this binding, so identical metadata recreated by an engine administrator remains outside the assurance. The passing native run used this binding. [Resource controls](evidence/20261003-identity-resource-isolation-preparation.json).

## Security integrations

### Wazuh

The historical native replay delivered 64/64 records: 31 expected alerts, 33 expected non-alerts and no missing/duplicate logical records. A separate historical run restarted collection twice. These are recorded experiments, not current continuous monitoring.

The enterprise path separates minimal observations from forwarded core signals. Observations omit actor/resource pseudonyms and content. Core signals carry rule/version, case/version, generation and evidence digests, with at most 25 evidence IDs and a completeness flag. R3 routing rule 100222 is a **SignalBridge detection forwarded to Wazuh**, not independent Wazuh rediscovery.

Exports stage at most 100 observations or 25 open cases/sweep. Separate stream IDs, exact-prefix recovery, a 128 KiB batch cap and 16 MiB stream cap bound delivery. `SB_SOC_SEGMENTED_EXPORT=1` applies only to fresh streams and permits eight 2 MiB segments. Local rotation recovery does not establish native rotation. Staged, appended, native-observed and reconciled records are distinct.

Historical imports revalidate source, actual archive/alert bytes, capture journal, isolation and both shutdowns. They create app-scoped reports, no substitute events/cases. Existing evidence links require exact identity/digest/generation matches. An imported report does not become a passed authorization check or current healthy connection.

Current status: [collection run 0d137b47](evidence/20261003-wazuh-native-collection-0d137b4720ad476faa68d36754b7357f.json) archived 24/24 records and raised 8/8 expected alerts exactly once. [Recovery run 4a5748dc](evidence/20261003-wazuh-native-recovery-4a5748dcc7a74525a7469dc8d802438a.json) stopped the log collector after 11 records, rotated the largest input aside and resumed with zero extra copies. The live controller (`enterprise_wazuh_live_verify.py`) creates every monitored file empty before start, because the native collector ignores files absent at its start and skips content already present, then publishes the fixed source-bound packets and reconciles archives, alerts and the capture journal before requiring both shutdown receipts. In the endurance stage a continuous collector captured 10.6 hours before a folder bound stopped it; see [lessons learned](LESSONS.md).

The alternative finite Wazuh controller now has a separately selected preservation profile. Its default remains exclusive. The profile binds the local engine, exact source packets, private run, implementation hashes and at most eight minimal nonsecret workload envelopes. Main and independent controllers abort on missing/new workloads or sampled metadata drift, latch temporary failures, and clean up only their exact collector. A fixed late-operation window catches delayed starts; elapsed time and incomplete shutdown remain evidence. Snapshots do not establish application health, uninterrupted service or protection from an engine administrator. The [original reviewed plan](../integrations/wazuh_enterprise/ready-publication-stage-plan.json) is retained for its historical revision; it cannot authorize changed implementation.

History: the path to those runs included a 0/24 collection caused by first-start file positioning ([diagnosis](evidence/20261003-wazuh-final-attempt-diagnosis.json)), a capacity-guard refusal before any Docker call ([stopped attempt](evidence/20261003-wazuh-preservation-preflight-stopped.json)), a separately approved 30 GiB capacity revision ([plan](../integrations/wazuh_enterprise/ready-publication-capacity-stage-plan.json), [stopped attempt](evidence/20261003-wazuh-capacity-preservation-stopped.json)), and a Windows access-control failure at helper phase 8 ([hardening](evidence/20261003-wazuh-helper-freeze-and-diagnostics.json), [correction](evidence/20261003-private-acl-correction.json)). The phase-8 failure was the coding agent's sandbox token, which cannot change access-control lists, not the script; native stages now run outside that sandbox.

Learning checkpoint: distinguish a successful safeguard from a successful integration test. The capacity stop demonstrated refusal at the boundary; it supplied no Wazuh collection evidence.

Learning checkpoint: a safely stopped or cleaned-up experiment can still fail its functional check. Explain what the phase-8 failure established on its own, and why finding the cause took a comparison outside the sandbox.

### OWASP ZAP

The historical anonymous passive profile preserves a failed offline-target run and its retry. The authenticated profile ran natively: [scanner run d975b97f](evidence/20261003-authenticated-zap-offline-d975b97fad814c9b8e4304e114c776e5.json) found one Low 10021 issue in the fault phase and none in the corrected retest. It captures five requests/phase: member identity/document, denied cross-app expense access, owner identity/document. Exact identities, bodies, paths, results and distinct committed source-event bindings establish coverage independently of HTTP 200 alone.

A fixed operator-only 1-600 second fault removes only `X-Content-Type-Options` from the permitted member's known document response. It cannot grant access or combine with the authorization fault. Reset, unaffected owner/path controls and restoration are mandatory. The corrected phase repeats scope/bodies with later events. Partial/interrupted runs retain attempted/validated counts and cannot be labeled clean.

Credential-free HAR captures retain allowlisted actual headers and known synthetic bodies. ZAP imports responses offline with `sendRequests=false`, five messages, a fresh safe-mode session and only passive rule 10021. This tests authenticated **responses**, not ZAP's login engine. HAR timings are placeholders, not latency evidence. Native message IDs must bind findings to source events; full history must match the profile.

Prepared runners enforce fixed inputs, finite calls/time/resources, explicit TLS trust, isolation and independent shutdown. The scanner never installs add-ons. Imports recompute transcripts and exact eight-event source reconciliation before creating historical scoped checks; duplicates add nothing, conflicts roll back and missing events are never invented. Source capture, the native finding/correction/retest and the operator import into a restored PostgreSQL console ([6bce0948](evidence/20261003-console-restoration-6bce09482a3b430aadb98b589d40f04e.json), finding on documents only) have passed. Concurrent import races were not run natively. Review `integrations/zap_enterprise/` stage plans before launch.

### Shuffle and copied source apps

The offline Shuffle workflow has run natively ([run](evidence/20261005-shuffle-native-workflow-315cfb85-9c28-4e4e-9cac-8ce455e92448.json)). Inside a dedicated VirtualBox VM with no network adapter or shared folder, Shuffle's backend, Orborus and workers executed nine scenarios against the signed review-task API: one task created, idempotent retries returning the original receipt, replay, idempotency conflict, foreign-case and stale-evidence refusals, a receiver timeout and a lost reply recovered by retry. Shuffle's HTTP app re-serializes JSON bodies, so the dispatcher signs that exact form; Orborus runs plain worker containers because the offline host is not a swarm manager; and the VM uses one virtual CPU because VirtualBox on Hyper-V froze the guest's timers with four. [Status and run steps](../integrations/shuffle/README.md).

The existing `integrations/bettail-routes.mjs` harness targets a local BetTail copy and restores membership after member/outsider/removed-member checks. The new `integrations/bettail_enterprise/` adapter prepares a separate, verified derivative of the frozen source: two private-read routes plus three overlays. It observes returned state or the actual downloaded image, distinguishes known denials from service errors, and signs observations with a server-only key. Original BetTail/Netted projects and the frozen snapshot remain unchanged.

The prepared SQL wraps the exact guarded source mutation rather than replacing its policies. It compares effective access before/after the authorized mutation and commits transitions with their outbox entries. Owner/alternate-grant rights therefore affect the assertion. A separate least-privilege delivery role leases immutable events, preserves event identity after lost replies and retires exhausted retries. Delivery uses one fixed loopback TLS destination, a total deadline and strict acknowledgments. Seventeen Python checks, five observer checks, 28 modeled handler controls and a scoped TypeScript compilation pass. **SQL is unapplied and the copied app unlaunched**: real authorization, transactional behavior, role denial, storage and R3 linkage would need a reviewed native run, which was deliberately not pursued (owner decision, October 4, 2026). [Preparation receipt](evidence/20261003-bettail-adapter-preparation.json).

Learning checkpoint: explain why removing a group member may leave effective access intact, why HTTP 503 cannot count as denial, and why accepted ingestion differs from completed processing. These are AI reference prompts; Aman's own analyst answer remains separate.

### AccessOps leaver signals

AccessOps, a separate departure-workflow project, signs Shared Signals (SSF 1.0) Security Event Tokens for account-disabled, session-revoked and sign-in-after-departure events. SignalBridge polls them (RFC 8936) from `127.0.0.1:8443`, using TLS name `accessops.test` and a pinned lab CA. It verifies ES256 against a thumbprint-named P-256 key with `cryptography`, checks typ, iss and aud exactly against a closed claim schema, stores each token once by jti, and acknowledges only after commit. Rule L1 opens a critical case for every reported sign-in after departure. Rule L2 opens one when this console's own records show the same workforce issuer and subject signing in after the account was disabled. Only new access reopens a resolved case; late containment evidence just updates it. A dry run verified all 32 live tokens before the first real poll stored and acknowledged them. [Receiver](../integrations/ssf/README.md), [poll receipt](evidence/20261005-accessops-leaver-poll-eefe76ecded04ffe9892bd174c973232.json).

## Monitoring and reliability

The console shows queue state and one/two configured worker slots as recent, stale, missing or clock-error. Every configured slot must be recent for a healthy pool. An idle pulse does not prove an app's events were processed.

The opt-in `/metrics/` endpoint requires HTTPS and a dedicated credential. `SB_METRICS_APPS` maps at most eight provisioned scopes to fixed `app1`-`app8` labels; `SB_MONITORED_WORKERS` maps at most two slots. Credentials, actor/resource IDs, app names, notes and contents are excluded. Mapping changes require a new scrape identity. Retained counts are gauges because restore/retention can reduce them.

The exporter permits 165 series/64 KiB, one authenticated scrape/five seconds, a cooperative four-second collection budget and PostgreSQL transaction-local two-second read timeouts. This is not a hard process deadline or native timeout proof. Sample p95 uses nearest rank over at most 1,000 valid completions/hour, includes outages/retries and shows its denominator; no samples means no p95. Staged files and synthetic activity do not prove a live feed. Native Prometheus/Grafana validation passed 24/24 controls ([0cd4256f](evidence/20261003-monitoring-native-0cd4256f4a1c4f2692f67eae4704bd53.json)): client-certificate and bearer-token denials, provisioned dashboards whose queries match the database, a scrape interruption and recovery, and worker and queue-delay alerts that fired and cleared. Alerts are evaluated locally; delivery to an external channel is out of scope. [Monitoring profile](../integrations/monitoring/preparation.json).

The immutable 24-hour declaration contains **47,760 events**: 23,880/app, ordinary four-second/app cadence staggered by two seconds, and eight one-minute 10-event/second total bursts replacing normal cadence. Planned interruptions occur at hours 2, 5, 8, 12 and 17 with declared recovery windows. Normal-period targets are p95 intake below 500 ms and processing below five seconds. Physical retries/tool duplicates are distinct from logical event/case/task duplicates.

The real-source driver paces authenticated HTTPS reads, renews sessions and journals intent plus exact committed outbox identity/digest. Known late replies remain evidence; unknown replies are not silently retried. A 40-minute rehearsal with every interruption window scaled in delivered, processed and reconciled all 1,201 events with zero anomalies. A continuous run delivered all 27,118 reads over 13.5 hours, with Wazuh capturing the first 10.6. The full 24-hour run was not completed (owner decision); see the [evidence guide](EVIDENCE.md) and [lessons learned](LESSONS.md). [Declared profile/measurement code](../integrations/enterprise/reliability.py).

## Evaluation and evidence interpretation

The final 48-scenario enterprise round, frozen on the delivered code, covers owner/alternate grants, missing/delayed telemetry, service failures, horizon boundaries, slow/distributed patterns and cross-app/source controls. It produced TP15 / FP6 / FN8 / TN12 plus seven inconclusives: precision **15/21 (71.4%)**, recall **15/23 (65.2%)**, false-positive rate **6/18 (33.3%)**. Inconclusives are outside binary denominators. The builder knew the rules when authoring the dataset; it is not blind, independent or representative of production.

Initial workload was 24 cases, later 23 active cases with one correction; 21 alerted scenarios is a different unit. In-memory delivery used 181 signed requests, 174 unique events and seven duplicate retries. Legitimate stale links remain a false positive; activity spread across different resources remains a miss. Repeating sealed inputs under a new freeze gives regression evidence, not independent accuracy evidence. [Current round](evidence/20261005-enterprise-detection-evaluation-public-release.json) (re-frozen for the public release; the [Shuffle round](evidence/20261005-enterprise-detection-evaluation-shuffle-native.json), the [leaver-receiver round](evidence/20261005-enterprise-detection-evaluation-leaver-receiver.json), the [final-delivery round](evidence/20261005-enterprise-detection-evaluation-final-delivery.json) and the earlier [delivery-preparation round](evidence/20261003-enterprise-detection-evaluation-delivery-preparation.json) gave identical results).

The [September report](../portfolio/evaluation.html) preserves its 22-scenario round and five AI-authored teaching investigations. Historical 16/16 rule-contract checks and 0/3 harder capability probes measure different things. Old results require their original revision and cannot certify newer rules. Independent scenarios and Aman's own defensible analyst report remain learning outcomes.

Receipts identify source/log hashes. Hashes bind bytes; a trusted local administrator can replace records, so they are not external attestation. Test counts are neither detection accuracy nor personal competency. The [public CI receipt](evidence/20261001-github-ci-publication.json) retains two failures and a corrected passing GitHub run; later local edits do not inherit that remote result.

## Verification and operation

Use the [README](../README.md#run-the-lightweight-console) for one setup/start/stop path. The lightweight demo adds synthetic fixtures while preserving existing data; it neither launches Docker nor reproduces native source authorization. Avoid reseeding when simply reopening the console.

For local engineering verification, use the existing trusted environment and one recorder grouping Python/Node checks, configuration, migration consistency, lint/format and publication scanning:

```powershell
$pythonPath = (Resolve-Path -LiteralPath '.venv\Scripts\python.exe').Path
& $pythonPath -B scripts/record_enterprise_offline.py --python $pythonPath
```

It reuses dependencies and writes a fresh scoped receipt without launching native labs. Optional certificate checks require a separately available reviewed runtime. Inspect passed/failed/skipped results instead of reusing an old headline count. For small edits, run affected checks rather than automatically repeating the suite.

`scripts/accessibility_scan.mjs` runs axe-core (fetched separately and checksum-verified, not vendored) in headless Chrome against a disposable console and static pages, in light and dark schemes; it refuses unstyled pages. [Accessibility scan](evidence/20261005-accessibility-axe-scan.json).

Frozen evaluation is separate. `scripts/evaluate_enterprise_detection.py` requires matching declared inputs and implementation. Preserve freezes/receipts; changed frozen code needs a new declaration/identity, not an overwritten result. Reproduction belongs to the selected round and revision. CI uses pinned actions, read-only permissions and separate disposable PostgreSQL verification; it is not a deployment pipeline.

| Action | Boundary |
| --- | --- |
| Read evidence/code, edit docs, run scoped offline checks | Routine local work; no native launch |
| Start the initialized SQLite console | Loopback; intended checkout and its own shutdown marker |
| New downloads, changed native launch/network/trust profile or consequential machine changes | Review exact components, limits, isolation, recovery and shutdown first |
| Native execution | Only the approved stage; verify capacity/owned resources/watchdog; retain failures and shutdown receipts |
| Public deployment, paid services, production credentials or autonomous response | Outside this milestone |

The planning ceiling is 10 GiB combined lab RAM and 30 GiB additional growth, retaining at least 25 GiB free. Stage limits can be tighter. Sampled resource guards are detection thresholds, not hard quotas. Preserve evidence, volumes and unrelated projects.

The maintained human-readable material is the README, the evidence guide and the recorded walkthrough. Raw receipts remain audit material. Aman's next contribution is to explain one real finding, author the analyst judgment, defend uncertainty and conduct the separate reviewer exercise. AI reference narratives remain labeled as such.
