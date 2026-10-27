# Lessons learned

Running SignalBridge against real components found problems that unit tests and mocks had not. This page lists them: what broke, how it was fixed, and what it taught. Exact runs and receipts are in the [evidence guide](EVIDENCE.md).

## Real product bugs the native runs found

| What broke | How it showed up | Fix |
| --- | --- | --- |
| The console's Content-Security-Policy (`form-action 'self'`) blocked the redirect to the identity provider, because browsers apply `form-action` to redirects after a form submit | Only a real Chromium walkthrough failed; all 28 HTTP-level identity controls had passed | With federated sign-in on, the policy now also allows exactly the one fixed provider origin. Local-only mode is unchanged. Regression test added |
| The Wazuh case card compared a JSON key with a text column | Only on PostgreSQL, during the restore-then-work run; SQLite had accepted it | Compare as text; covered by the restoration run |
| On the portfolio page, links inside light evidence panels inherited the dark theme's mint link color (1.29:1 contrast, nearly invisible) | An automated accessibility scan (axe-core); it looked fine on the dark parts of the page | Light-panel links use the existing dark green (6.10:1); the scan also fixed a chart that hid its links from screen readers and invalid list markup |
| In local mode the settings wrote a secret-key file even when `SB_SECRET_KEY` was supplied | The Shuffle receiver, started from a read-only source mount inside the isolated VM, crashed at startup | A supplied key now wins and the file is created only when none is given; a subprocess regression test fails without the fix |
| Distinct Wazuh records written in the same second can share a record id | Native reconciliation could not tell same-second records apart | Reconciliation keys by target; the continuous capture also gives each record its own ordinal |

**Lesson:** each class of bug needed the real component to appear: a real browser, a real database engine and a real SOC tool. That is the case for keeping native runs in the delivery, not just unit tests.

## Found by testing and scanning

| What broke | How it showed up | Fix |
| --- | --- | --- |
| A case write could rely on a permission check made earlier in the same request | Tests that downgraded the user's role, removed their membership or disabled the account after that check: all 4 writes still went through | Account and role are re-read inside the write transaction; 13 regression tests. These were deterministic SQLite tests, not a timed exploit ([record](evidence/20260925-authorization-refresh.json)) |
| The Supabase lab used for the BetTail test copy kept a known default database password, and 3 backend services were set to publish host ports | Scanner triage on 24 September and a hardening preflight check | All 8 database role passwords rotated and each checked (32/32); host-port bindings 3 → 0; memory and CPU capped ([record](evidence/20260925-bettail-hardening-complete.json)) |

**Lesson:** a check made at the start of a request can be stale by the time the write commits. The permission check belongs inside the same transaction as the write.

## Wrong assumptions about third-party tools

- **Wazuh's log collector ignores files that do not exist when it starts**, and does not read content already present. The first smoke test captured nothing. Fix: create all 32 monitored files empty before start and append afterwards.
- **Wazuh rotates its archive every ten minutes.** The continuous collector reused a finder written for a ten-minute bootstrap, which refuses a log folder holding more than 64 entries. After 63 rotations, 10.6 hours into the 24-hour run, it stopped itself. Fix: a separate 4,096-entry bound for the continuous collector, tested with 300 rotated files. The capture it had already sealed stayed intact.
- **Keycloak 26** writes its sign-in hand-off page in uppercase HTML (`TYPE="HIDDEN"`), rate-limits two quick failed sign-ins and adds `revoke_offline_access` to logout tokens. Each was handled without loosening the checks.
- **Docker 29's containerd image store** reports the manifest digest as an image's ID. An image saved by digest loads with no name, so the Shuffle guest could not find its receiver image by reference. Fix: find it by ID, require the ID to equal the pinned digest, then give it a local name.
- **OpenSearch's bundled crypto library** extracts native code into `/tmp`, which Docker's tmpfs mounts `noexec` by default. Fix: a private temp folder that allows execution, plus a keystore created ahead of time for the read-only config.
- **Shuffle's upstream compose turns on swarm mode** (`SHUFFLE_SWARM_CONFIG=run`). On a single offline host that is not a swarm manager, Orborus never started a worker, so every execution timed out. Fix: plain-container mode, where workers copy Orborus' network.
- **Shuffle's HTTP app rewrites JSON bodies** with `json.dumps(ast.literal_eval(body))`, changing the separators. SignalBridge signs the exact body bytes, so every request through Shuffle failed authentication (401). The control worked as designed. Fix: the dispatcher signs the form the app sends and refuses to send a body the app would change.
- **Wazuh's bundled Python 3.10** cannot parse Wazuh's own `+0000` time-zone offsets, which masked a collector failure. Fix: normalize `+HHMM` to `+HH:MM`, verified under that Python by replaying the failed run.
- **pySigma's Splunk query for R5 compiled, but Splunk refused to run it.** The backend chains the correlation as `multisearch` with `stats` inside, and Splunk allows only streaming commands there. The generated SPL also uses fixed time bins, which split windows the Python rules treat as rolling. Fix: hand-written SPL with `streamstats time_window`, labeled apart from the generated queries. See the [detections README](../detections/README.md).
- **Three SigmaHQ Entra rules match a field these exports don't have.** The device code, Temporary Access Pass and app credential rules read `properties.message`, which no record in the Entra diagnostic-settings captures carries, so they can't fire there. My E3, E5 and E7 match fields the records do have (`authenticationProtocol`, the operation name).

**Lesson:** pin exact image digests and record observed behavior in tests. Several of these changed between versions, and a floating tag would have hidden which one ran.

## The lab environment affected the measurements

- **Clock drift.** Docker Desktop's VM wall clock drifted about 50 ppm and was stepped once by −1.1 s. That made reads look late and produced one negative duration. Fix: one step-free lab clock (run origin plus the VM's monotonic clock) shared by every process, with Wazuh's wall-clock times mapped onto it.
- **What "on schedule" means.** The first definition judged a read by the server's recorded time, so slow responses counted as missed slots. Before the measured run, I changed it to judge when the read is sent and to report server response time separately. The rehearsal was re-measured under the new definition, and the original receipt was kept unchanged.
- **Leftover limits from short runs.** Lab TLS servers kept a 360-second lifetime from the short proofs and stopped a long rehearsal at six minutes. The long-run profile now has its own lifetime, inside the 26-hour watchdog.
- **Docker network address pools.** Retained lab networks used up all 31 default ranges. Fix: an explicit run-derived range from 198.18.0.0/15 (a benchmarking range), refused if already in use.
- **Windows file locks.** A heartbeat file renamed every second was briefly locked by a scanner and ended a rehearsal. Fix: write it every 15 seconds and count a locked write instead of failing.
- **VirtualBox on Hyper-V.** Docker Desktop needs Hyper-V, so VirtualBox runs on Windows' hypervisor platform. With four virtual CPUs the guest's timer clock froze: boots stalled about three seconds in, and mid-run the guest fell up to 15 minutes behind until VirtualBox gave up catching up and the jump expired the guest's waits. A Windows restart did not fix it, and neither did moving the disk to another controller. The pattern pointed elsewhere: the stalls came with the first virtual CPU idle while another worked, and VirtualBox services guest timers on the first one. With **one virtual CPU** the clock stayed in step and every boot succeeded first time. The host also retries a boot that never reports in, and the guest reports "started" first so a stall is caught early.
- **A persistent guest disk.** The Shuffle VM keeps its disk between runs, so a second run hit the first run's work folder. Fix: the guest removes only this workflow's own leftovers (folder, named containers, its network) before starting, and the receipt now says "dedicated", not "disposable".

## Process lessons

- **Scan what users actually see.** The first accessibility pass ran before the disposable console served its stylesheets, and reported 68 "target too small" failures that the real CSS does not have. The scanner now records how many stylesheets loaded on each page and stops if a page has none.

- **Test data ages with the rules.** The September simulation fixtures hashed resource IDs without the scenario name, so every scenario's first resource was the same record. That was harmless until rule R5 (six denials by three actors on one resource) arrived on October 1; then unrelated scenarios combined into an R5 case none of them declared, and every fresh simulation failed. Fix: resource IDs are scoped to their case, like actor IDs, with a test that no two cases share one. The frozen challenge catalog keeps its shared IDs on purpose and measures only R1/R2.
- **When the other side treats an error as final, rehearse first.** AccessOps stops offering any token a receiver reports as refused, so a receiver bug would silently lose leaver events. The first live poll was a dry run that verified all 32 tokens and stored, acknowledged and reported nothing; only then did the real poll run. The receiver also acknowledges a token only after storing it.
- **Watch for exits, not just progress.** The run monitor checked that reads kept flowing, and they did, because SignalBridge stayed healthy. It did not check whether each component was still running, so the Wazuh stop went unnoticed for about three hours. The monitor now alerts on any component exit.
- **Report early from slow environments.** The Shuffle guest reported only at the end, so a stalled boot cost 35 minutes per attempt. It now sends a "started" record first, so the host can spot a stalled boot within five minutes.
- **Guards earn their keep.** The memory floor, the disk guard and the "no other project's containers" check each stopped or refused a run during this work. Each time nothing was left running, both shutdown checks passed where something had started, and no other project's data was touched.
- **Keep the failures.** Failed and incomplete receipts stay in `docs/evidence/`. Re-measurements are new files, not edits, and the front page states what was not completed.
- **Copying a community filter copies its blind spot.** My first Kerberoasting rule (W1) skipped computer-account requesters, like SigmaHQ's rule. On a public capture of Kerberoasting run as SYSTEM, the tickets were requested by the computer account, so both missed it. A burst rule doesn't need that filter, so W1 now counts computer requesters. These attack captures can't show how much noise that adds on a real network.
- **Write expectations down before the first score, and say when you didn't.** For my first 12 identity rules (W1–W4, E1–E8) I recorded which should fire on each file before the first scoring run. That run showed an NTLM-only spray no rule could see, so I added W5 and set its expectations after seeing the data. The README and `sources.json` say so, and W5's catch is reported with that caveat.
- **Automation sandboxes are part of the environment.** Early Wazuh runs failed at folder-permission setup because the sandboxed shell they ran in couldn't change access-control lists. It was not a script bug. Native stages now run outside that sandbox.
