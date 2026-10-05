# Detection rules as Sigma, Splunk SPL and KQL

SignalBridge's five detection rules (R1–R5, in [`bridge/engine.py`](../bridge/engine.py)) are
written here as [Sigma](https://sigmahq.io/) rules, so they can run outside SignalBridge.
pySigma compiles them for Splunk and Microsoft Sentinel; where it can't, the query is written by
hand and labeled.

Every version was checked against the same 48 frozen scenarios as the Python rules:
- the Sigma rules, compiled to SQLite;
- the SPL, in Splunk Free;
- the KQL, in Microsoft's Kusto emulator.

## The rules

| Rule | Detects | Sigma form | ATT&CK |
| --- | --- | --- | --- |
| [R1](sigma/rules/r1_repeated_private_access_failures.yml) | One account fails to read 3+ distinct private records in 5 min | `value_count` | T1213 |
| [R2](sigma/rules/r2_allowed_read_after_reported_revocation.yml) | The app reports a read succeeded after the account was removed | single event | T1078, T1213 |
| [R3](sigma/rules/r3_allowed_read_after_membership_removal.yml) | An account removed from a record reads it within 24 h | `temporal_ordered` | T1078, T1213 |
| [R4](sigma/rules/r4_extended_private_resource_probing.yml) | One account is denied 5+ distinct private records in 30 min | `value_count` | T1213 |
| [R5](sigma/rules/r5_private_resource_denials_across_accounts.yml) | 6+ denials by 3+ accounts on one record in 10 min | two correlations, chained | T1213 |

Four base rules in [`sigma/rules/`](sigma/rules/) describe the event types the correlations
count. Every query groups by app, environment and source, as SignalBridge does.

**ATT&CK choices.**
- **T1213 (Data from Information Repositories, Collection):** every rule concerns reading private
  records held in an app. For R1, R4 and R5 the denials show attempts, not success.
- **T1078 (Valid Accounts, Persistence):** in R2 and R3 an account keeps using access that was
  removed.
- The underlying weakness is broken access control (OWASP A01, CWE-284).

**Where each query comes from.**

| Rule | Splunk SPL | Sentinel KQL |
| --- | --- | --- |
| R1 | [generated](sigma/compiled/splunk/R1.spl), [hand-written](handwritten/splunk/R1.spl) | [hand-written](handwritten/kusto/R1.kql) |
| R2 | [generated](sigma/compiled/splunk/R2.spl) | [generated](sigma/compiled/kusto/R2.kql) |
| R3 | [hand-written](handwritten/splunk/R3.spl) | [hand-written](handwritten/kusto/R3.kql) |
| R4 | [generated](sigma/compiled/splunk/R4.spl), [hand-written](handwritten/splunk/R4.spl) | [hand-written](handwritten/kusto/R4.kql) |
| R5 | [generated](sigma/compiled/splunk/R5.spl), [hand-written](handwritten/splunk/R5.spl) | [hand-written](handwritten/kusto/R5.kql) |

"Generated" means produced by pySigma from the Sigma rule. The KQL backend
(pySigma-backend-kusto 1.0.1) cannot compile correlations, and the Splunk backend has no
`temporal_ordered`, so those queries are hand-written.
[`sigma/compiled/support.json`](sigma/compiled/support.json) records each backend's answer.

## Results on the 48 frozen scenarios

Each result compares the set of rules fired in every scenario with the Python rules. It compares
rule logic only. The scenarios were written by the builder, so none of these is an accuracy
measurement.

| Where it ran | Queries | Same result as Python | Differences |
| --- | --- | --- | --- |
| Python rules, replayed directly | `bridge.engine` | 48 / 48 against the published receipt | None. Confirms the scenarios are rebuilt faithfully |
| SQLite (pySigma-backend-sqlite) | Sigma, compiled | 45 / 48 | R3 fires after a re-grant (Q11, Q18, Q20) |
| Splunk Free 10.6.0.5 | Generated (R3 hand-written) | 40 / 48 | Generated R5 is **rejected by Splunk**; fixed bins miss Q27 (R1) and Q28 (R4) |
| Splunk Free 10.6.0.5 | Hand-written (R2 generated) | 45 / 48 | Events exactly on a window edge are left out: Q27, Q28, Q37 |
| Kusto emulator 1.0.9774 | Hand-written (R2 generated) | **48 / 48** | None |

**Findings from the real engines.**
- **Splunk rejects pySigma's chained correlation.** For R5 the backend
  (pySigma-backend-splunk 2.1.0) generates `multisearch` with `stats` inside it. Splunk refuses it:
  "'multisearch' subsearches can contain only streaming commands". Without running it, this
  query looked fine.
- **Fixed bins are not rolling windows.** The generated SPL uses `bin _time span=5m`, so
  failures either side of a bin edge are counted apart. The hand-written SPL uses
  `streamstats time_window` instead.
- **Window edges differ.** The Python rules include an event exactly at the window's edge.
  Splunk's `time_window` leaves it out, which misses the three inclusive-boundary scenarios
  (Q27, Q28, Q37). KQL's `between` includes both ends.
- **KQL can express what Sigma cannot.** The hand-written KQL handles R3's re-grants and
  same-instant conflicts, and R4's ten-minute span, and matches Python in every scenario.
- **KQL column names.** In the emulator, KQL refused `earliest` and `latest` as column names in
  these queries, so they are named `first_seen` and `latest_change`.

**What the Sigma version cannot express.**

| Rule | Python behavior | Effect on the Sigma version |
| --- | --- | --- |
| R3 | A re-grant cancels the removal; the latest assertion decides; same-instant conflicts are inconclusive | Fires on re-grants and conflicts (Q11, Q18, Q20) |
| R4 | The supporting evidence must span at least ten minutes | Also fires on a fast burst of five denials. The frozen round has no such case; a unit test shows it |
| R1, R4, R5 | Cases group into fixed UTC buckets | Alert counts can differ; every comparison here is about which rules fired |
| R5 | A repeated delivery of the same event counts once | A SIEM that stores duplicates can reach six sooner. The hand-written queries deduplicate by `event_id` |

## How the engines ran

Both engines ran on 5 October 2026 in local containers, on one PC, bound to 127.0.0.1. Each got
all 174 stored events of the round. Every scenario has its own app, so each result row maps back
to one scenario.

Receipts:
- [`engines/splunk-run.json`](engines/splunk-run.json)
- [`engines/kusto-run.json`](engines/kusto-run.json)

Each receipt records the image digest, the engine version, each query's file, origin and
SHA-256, and the per-scenario result. A test fails if a query changes after its receipt was
written.

- **Splunk Free:** image `splunk/splunk:10.6.0`, with the Free license (Splunk General Terms
  accepted).
  - Events arrived through the HTTP Event Collector.
  - Splunk Free has no user accounts and refuses management calls from outside its container, so
    the searches ran inside the container, with TLS verified against Splunk's CA.
  - SignalBridge's source class is stored in Splunk's own `source` field.
- **Kusto emulator:** image `mcr.microsoft.com/azuredataexplorer/kustainer-linux`, pinned by
  digest (EULA accepted).
  - The table is `SignalBridgeAccess_CL`.
  - Sentinel runs KQL too, but these queries were run in the emulator, not in Sentinel itself.

To repeat a run, start a **fresh** engine: the runner refuses an index that already holds these
events. Then, from the repository root:

```bash
python -m detections.engines.run splunk --image <reference@digest>
python -m detections.engines.run kusto --image <reference@digest>
```

Splunk needs `SPLUNK_HEC_TOKEN` and `SPLUNK_CA_FILE` in the environment.

## Run the checks

Python 3.14, from the repository root. No engine is needed:

```bash
python -m pip install --require-hashes --only-binary :all: -r detections/requirements.txt
python -m detections.sigma.compile --check
python -m detections.sigma.replay --check
python -m unittest discover -s detections -t . -p "test_*.py"
```

Without `--check`:
- `compile` rewrites [`sigma/compiled/`](sigma/compiled/);
- `replay` rewrites the report.

The [Sigma detections workflow](../.github/workflows/sigma.yml) runs these checks, plus ruff,
whenever the rules, the queries, the Python engine or the frozen round change.
