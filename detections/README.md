# Detection rules as Sigma

SignalBridge's five detection rules (R1–R5, in [`bridge/engine.py`](../bridge/engine.py)), written as
[Sigma](https://sigmahq.io/) rules so they can run outside SignalBridge. pySigma compiles them for
Splunk and Microsoft Sentinel. The Sigma versions were compiled to SQLite and replayed against the
same 48 frozen scenarios as the Python rules, and the results compared scenario by scenario.

## The rules

| Rule | Detects | Sigma form | ATT&CK | Splunk SPL | Sentinel KQL | Same result as Python on 48 scenarios |
| --- | --- | --- | --- | --- | --- | --- |
| [R1](sigma/rules/r1_repeated_private_access_failures.yml) | One account fails to read 3+ distinct private records in 5 min | `value_count` | T1213 | [yes](sigma/compiled/splunk/R1.spl) | no | 3 of 3 fired, no extra |
| [R2](sigma/rules/r2_allowed_read_after_reported_revocation.yml) | The app reports a read succeeded after the account was removed | single event | T1078, T1213 | [yes](sigma/compiled/splunk/R2.spl) | [yes](sigma/compiled/kusto/R2.kql) | 2 of 2 fired, no extra |
| [R3](sigma/rules/r3_allowed_read_after_membership_removal.yml) | An account removed from a record reads it within 24 h | `temporal_ordered` | T1078, T1213 | no | no | 5 of 5 fired, **3 extra** |
| [R4](sigma/rules/r4_extended_private_resource_probing.yml) | One account is denied 5+ distinct private records in 30 min | `value_count` | T1213 | [yes](sigma/compiled/splunk/R4.spl) | no | 6 of 6 fired, no extra |
| [R5](sigma/rules/r5_private_resource_denials_across_accounts.yml) | 6+ denials by 3+ accounts on one record in 10 min | two correlations, chained | T1213 | [yes](sigma/compiled/splunk/R5.spl) | no | 6 of 6 fired, no extra |

Four base rules in [`sigma/rules/`](sigma/rules/) describe the event types the correlations count.
Every correlation groups by app, environment and source, as SignalBridge does.

**ATT&CK choices.** T1213 (Data from Information Repositories, Collection): every rule concerns
reading private records held in an app. For R1, R4 and R5 the denials show attempts, not
success. T1078 (Valid Accounts, Persistence): in R2 and R3 an account keeps using access that
was removed. The underlying weakness is broken access control (OWASP A01, CWE-284).

## Replay result

[`sigma/replay-report.json`](sigma/replay-report.json) holds the full per-scenario result.

- The Python rules, run directly on the rebuilt scenarios, reproduce the published evaluation
  receipt in **48 of 48** scenarios. This confirms the replay rebuilds the events faithfully.
- The Sigma rules give the same set of rules as Python in **45 of 48**. All three differences
  are R3 firing where Python correctly does not:
  - Q11: access was re-granted before the read.
  - Q18: the re-grant arrived late.
  - Q20: "removed" and "granted" were asserted at the same instant.

  Sigma correlations cannot say "unless a later event cancels it".

This compares rule logic only. The scenarios were written by the builder, so neither result is
an accuracy measurement.

## What Sigma cannot express

| Rule | Python behavior that Sigma cannot express | Effect on the Sigma version |
| --- | --- | --- |
| R3 | A re-grant cancels the removal; the latest assertion decides; same-instant conflicts are inconclusive | Fires on re-grants and conflicts (Q11, Q18, Q20) |
| R4 | The supporting evidence must span at least ten minutes | Also fires on a fast burst of five denials. The frozen round has no such case; a unit test shows it |
| R1, R4, R5 | Cases group into fixed UTC buckets | Alert counts can differ; the replay compares which rules fired, not how many cases |
| R5 | A repeated delivery of the same event counts once | A SIEM that stores duplicates can reach the six-denial count sooner. The replay removes repeats first, as SignalBridge's ingestion does |

**Backend limits.**
- The Splunk backend has no `temporal_ordered`, so R3 has no SPL.
- Its correlations use fixed time bins (`bin _time span=5m`), not rolling windows. Two failures
  either side of a bin edge can be missed.
- pySigma-backend-kusto 1.0.1 does not support correlation rules, so only R2 has KQL.
- Neither the SPL nor the KQL has been run against Splunk or Sentinel. Only the SQLite build was
  executed. [`sigma/compiled/support.json`](sigma/compiled/support.json) records each backend's
  answer.

## Run it

Python 3.14, from the repository root:

```bash
python -m pip install --require-hashes --only-binary :all: -r detections/requirements.txt
python -m detections.sigma.compile --check
python -m detections.sigma.replay --check
python -m unittest discover -s detections -t . -p "test_*.py"
```

Without `--check`, `compile` rewrites [`sigma/compiled/`](sigma/compiled/) and `replay` rewrites
the report. The [Sigma detections workflow](../.github/workflows/sigma.yml) runs these checks,
plus ruff, whenever the rules, the Python engine or the frozen round change.
