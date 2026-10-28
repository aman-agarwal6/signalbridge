# Identity attack detections, tested on public attack logs

Thirteen [Sigma](https://sigmahq.io/) rules for the identity attacks behind many current
breaches: password spraying, Kerberoasting, MFA fatigue, device code phishing, help-desk MFA
resets and backdoored app credentials. They read standard logs: Windows domain controller
Security events and Microsoft Entra ID sign-in and audit logs.

I scored them on 23 public attack captures from Splunk's
[attack_data](https://github.com/splunk/attack_data) repository, which I didn't write, and scored
SigmaHQ's community rules for the same attacks on the same files.

| | My rules (12 with test data) | SigmaHQ's rules (9 with test data) |
| --- | --- | --- |
| Attack files flagged | **18 of 21** | 6 of the 12 their rules cover |
| Alerts on files a rule wasn't meant for | 0 | 0 |
| Together | 20 of 21; only a spray spread across many addresses got past both | |

I wrote 13 rules; SigmaHQ has 10 for the same attacks. My E8 and SigmaHQ's sign-in-to-disabled-account
rule have no public capture to catch. Both still ran on all 9 Entra sign-in captures and raised
nothing, but their detection is untested. The other 2 of the 23 captures are attacks that no rule
targets.

The full per-file record is [`score-report.json`](score-report.json). CI downloads the same pinned
files, checks their SHA-256 and fails if the report changes.

I also ran the Windows rules on a week of real network logs from Los Alamos National Laboratory.
W2 raised no alerts. W1 and W5 raised about 20 and 9 a day, each from a single account or
workstation. W3 raised about 8,800 a day, 94% of them from two accounts. The Entra rules have no
public normal-traffic logs to run on. See
[False alarms on a week of real network logs](#false-alarms-on-a-week-of-real-network-logs).

## What the comparison found

| Finding | What happened | My rules |
| --- | --- | --- |
| Three SigmaHQ Entra rules can't fire on these exports | The device code, Temporary Access Pass and app credential rules match a `properties.message` field. No sign-in or audit record in these Entra diagnostic-settings captures has one. Device code sign-ins are recorded as `authenticationProtocol: deviceCode` | I wrote E3, E5 and E7 after looking at these captures, so they match fields the records do have. They weren't changed after the comparison |
| App credential activity name | SigmaHQ's rule spells it with a hyphen. Entra writes `Update application – Certificates and secrets management ` with an en dash and a trailing space, so an exact match fails | E7 matches the stable part of the name |
| Temporary Access Pass | SigmaHQ expects "Admin registered security info". The 2026 capture records "Create Temporary Access Pass method for user" | E5 matches both names |
| Kerberoasting run as SYSTEM | Tickets for 25 services in ten minutes, requested by the computer account `AR-WIN-2$`. SigmaHQ's Kerberoasting rule and my first version of W1 both skip computer requesters. SigmaHQ's RC4 rule expects ticket options `0x40810000`; these tickets carry `0x60810010` | W1 now counts computer requesters (see below) and ignores ticket options |
| Disabled accounts over Kerberos | The domain controller reports the disabled accounts as 4768 with code 0x12. SigmaHQ's disabled-logon rule only reads 4625 and 4776, and the 4625s in this capture say "no such user" | W3 also reads 4768 and 4771 |

**Where my rules miss:**
- **One RC4 ticket.** W1 is a burst rule and needs five services. SigmaHQ's single-event rule
  catches it, so run both.
- **A spray from many addresses.** E1 groups by IP address. This needs a tenant-wide failure
  baseline or Entra ID Protection's spray detection.
- **Two MFA failures.** E2 needs three. SigmaHQ's rule catches it because it alerts on every
  single denial, which is noisier.

## First run and the two changes after it

Before the first scoring run, I wrote down in [`sources.json`](sources.json) which of my first 12
rules (W1–W4, E1–E8) should fire on each file. I had already looked at the captures' event types
and field names while writing the rules. The first run caught 17 of 22 expected rule-file pairs,
with no alerts on files a rule wasn't meant for (its raw output isn't published). It exposed two
design flaws, which I fixed instead of changing any thresholds:

1. **W1 skipped computer requesters**, copying SigmaHQ's noise filter. A burst rule doesn't need
   that filter, and it hid Kerberoasting run as SYSTEM.
2. **W2 couldn't see an NTLM-only spray.** NTLM checks (4776) name a workstation, not an IP
   address. I added W5, which groups by workstation. I set W5's expectations after seeing the
   data, so it gets less credit than the rest.

Now: 22 of 26 expected pairs, still no alerts on files a rule wasn't meant for.

## False alarms on a week of real network logs

Zero alerts on the other attack captures only shows that a rule doesn't misfire. Those captures
hold almost no normal traffic. To count false alarms, I ran the Windows rules on the first 7 days
of the [LANL Unified Host and Network Data Set (2017)](https://csr.lanl.gov/data/2017/):
de-identified Windows logs from most of Los Alamos National Laboratory's Windows computers. That
is about 402 million events, 58 million of them event types the rules read. LANL doesn't label
the data, so I count every alert as a false alarm, which makes these figures an upper bound.

A correlation rule's alert is one run of overlapping 10-minute windows for one account or source.
W3 is a single-event rule, so every matching event is an alert. "Busiest normal count" is the
highest value any account or source reached in 10 minutes, against the rule's threshold.

| Rule | Alerts in 7 days | Per day | Where they came from | Busiest normal count |
| --- | --- | --- | --- | --- |
| W1 Kerberoasting burst | 141 | 20.1 | One account: Administrator in one domain, asking for tickets to the same 6 user-run services all week (1.1 million tickets, 80% of the week's tickets for user-run services) | 6 services vs 5, every day |
| W2 Password spray by source | 0 | 0 | None | 8 accounts vs 10 |
| W3 Disabled account | 61,773 | 8,825 | 22 accounts, 4 to 12 a day. Two account for 94%: one was retried from one workstation for 4 days and then stopped, the other every hour of the week | Single event |
| W4 Pre-authentication turned off | Not measured | | LANL doesn't include account changes (4738) | |
| W5 NTLM spray by workstation | 65 | 9.3 | One workstation failing NTLM about 100 times an hour around the clock, mostly for 23 account names that don't exist | Up to 12 accounts vs 10; 10 or more on 4 of 7 days |

What I take from it:
- **W2 has headroom.** The busiest source reached 8 of the 10 accounts. Only failed logons (4625)
  were tested, though; see the coverage gaps below.
- **W1 and W5 fire on one identity each.** A SOC would handle that with one reviewed exception for
  the Administrator account's six services and one ticket to fix the workstation, not a threshold
  change. LANL has only 48 user-run services in the whole week. A network with more service
  accounts gives W1 more chances to fire.
- **W3 is noisy as a raw event stream.** Grouped to one alert per account per day, which is how
  I'd deploy it, the week has 60 alerts. SigmaHQ's failed-logon-reasons rule matched the same
  61,773 events plus 2, so the noise comes from stale credentials on the network, not from W3's
  extra branches. A device that still holds a disabled account's password is what W3 exists to
  find, but in an ordinary week it's a cleanup ticket, not an incident.

I didn't change any rule after this run, and `changes_after_first_run` in
[`sources.json`](sources.json) still lists only the two attack-scoring changes. Raising W1 to 7
services or W5 to 13 accounts would make this week silent, but that would be tuning the rules to
the test data.

**What this week can't measure:**
- LANL has no 4771 events and no failed 4768 events. W2 ran on failed logons only, and W3's
  Kerberos branch (code 0x12, which also covers locked-out and expired accounts) didn't run.
- LANL gives failed logons (4625) a text reason instead of a status code, so W3 only ran on NTLM
  checks (4776).
- 36% of failed logons have no source address, and 78% of failed NTLM checks name no workstation.
  W2 and W5 can't group those events.
- W4 can't run (no 4738 events). SigmaHQ's Kerberoasting and RC4 rules can't fire either: LANL
  leaves out the ticket encryption type.
- LANL merged all domain controllers into one host and replaced user and computer names.
- **Entra (E1–E8): no baseline.** I found no public data set of an organization's Entra sign-in
  and audit logs in normal operation, and my Entra ID Free test tenant has no regular traffic.
  Their false-alarm rate is unmeasured.

The full record, with alerts, accounts and raw rows per rule per day, is
[`baseline-report.json`](baseline-report.json). The files come from Imperial College London's
mirror of the data set (LANL's own download needs a registration form), each pinned by SHA-256 in
[`sources.json`](sources.json) under `baseline`. The download is about 3 GB, scoring needs about
10 GB of temporary disk and took a little over 2 hours on my PC, so CI doesn't rerun it. A test
fails if a rule changes without the report being regenerated.

```bash
python -m detections.identity.baseline fetch
python -m detections.identity.baseline score
```

## The rules

| ID | Detects | Log | ATT&CK | Level |
| --- | --- | --- | --- | --- |
| [W1](rules/windows/w1_kerberoasting_burst.yml) | One account gets tickets for 5+ user-run services in 10 min (Kerberoasting) | Windows 4769 | T1558.003 | high |
| [W2](rules/windows/w2_password_spray.yml) | One source fails Kerberos or logon for 10+ accounts in 10 min | Windows 4625, 4768, 4771 | T1110.003 | high |
| [W3](rules/windows/w3_disabled_account_logon.yml) | Someone tries a disabled account, such as a leaver's | Windows 4625, 4768, 4771, 4776 | T1078.002 | medium |
| [W4](rules/windows/w4_kerberos_preauth_disabled.yml) | Kerberos pre-authentication turned off for an account (AS-REP roasting setup) | Windows 4738 | T1558.004 | medium |
| [W5](rules/windows/w5_ntlm_password_spray.yml) | One workstation fails NTLM for 10+ accounts in 10 min | Windows 4776 | T1110.003 | high |
| [E1](rules/entra/e1_password_spray.yml) | One IP fails the password for 10+ accounts in 10 min | Entra sign-ins | T1110.003 | high |
| [E2](rules/entra/e2_mfa_fatigue.yml) | 3+ MFA failures for one account in 10 min (MFA fatigue) | Entra sign-ins | T1621 | high |
| [E3](rules/entra/e3_device_code_signin.yml) | Successful sign-in with the device code flow (device code phishing) | Entra sign-ins | T1528 | medium |
| [E4](rules/entra/e4_auth_method_registered.yml) | New MFA method registered for an account | Entra audit | T1098.005 | medium |
| [E5](rules/entra/e5_temporary_access_pass.yml) | Temporary Access Pass issued | Entra audit | T1098 | high |
| [E6](rules/entra/e6_app_consent.yml) | User or admin consented to an app | Entra audit | T1528 | medium |
| [E7](rules/entra/e7_app_credential_added.yml) | Secret, certificate or federated credential added to an app | Entra audit | T1098.001 | medium |
| [E8](rules/entra/e8_disabled_account_signin.yml) | Sign-in attempt with a disabled account (50057) | Entra sign-ins | T1078.004 | medium |

The correlation rules (W1, W2, W5, E1, E2) count events from a base rule in the same file.

**Why these attacks.** Device code phishing hit
[more than 340 Microsoft 365 organizations](https://thehackernews.com/2026/03/device-code-phishing-hits-340-microsoft.html)
in one 2026 campaign, and voice-phishing variants
[target Entra accounts](https://www.bleepingcomputer.com/news/security/hackers-target-microsoft-entra-accounts-in-device-code-vishing-attacks/).
Stolen tokens and app credentials survive a password reset, so E3, E6 and E7 watch for them. E4
and E5 cover the step after a help-desk social engineering call: a new MFA method or a pass that
skips MFA. W3 and E8 tie back to [AccessOps](https://github.com/aman-agarwal6/AccessOps): someone
using a leaver's account after it was disabled.

## How it's scored

- **Inputs.** 23 files from attack_data at commit `7be4e72` and 10 SigmaHQ rules at commit
  `05d1031`, each pinned by SHA-256 in [`sources.json`](sources.json).
  [`fetch.py`](fetch.py) downloads them over HTTPS from two allowed hosts and discards anything
  that doesn't match. They are not stored in this repository.
- **Reading the logs** ([`logs.py`](logs.py)). Windows events keep their EventData field names,
  as SigmaHQ's Windows rules use them. Entra records get Microsoft Sentinel's column names
  (`ResultType`, `IPAddress`, `OperationName`), plus their raw paths and each audit change by
  name, so SigmaHQ's rules get every field name they might expect. Only interactive sign-ins and
  audit records are scored; 41 non-interactive and service principal sign-ins are set aside.
- **Running the rules** ([`score.py`](score.py)). pySigma compiles every rule to SQLite, and each
  runs on that file's events for its log source. Matching ignores letter case, as Sigma
  specifies.

From the repository root, with the pinned tooling from
[`detections/requirements.txt`](../requirements.txt):

```bash
python -m detections.identity.fetch
python -m detections.identity.score --check
python -m unittest detections.identity.test_identity
```

## Limits

- The captures come from Splunk's attack lab and hold little normal traffic. Each of my rules ran
  on 3 to 9 captures it wasn't meant for, and most of those hold none of the events the rule
  reads. Zero alerts there is a misfire check, not a false-positive rate for a real network.
- The false-alarm figures come from one unlabeled week of one organization's logs. They cover
  W1, W2, W3 and W5, some only in part, and none of the Entra rules.
- I decided which rules should fire on each file. For everything except W5, I wrote that down
  before the first run.
- The rules ran in SQLite through pySigma, not in Splunk or Sentinel. Field names follow
  Sentinel; Splunk needs a field mapping.
- Non-interactive sign-ins, where a stolen refresh token gets used, aren't scored yet.
- E8 has no public capture. It needs a sign-in export from a test tenant.
- Three Rubeus and PowerView captures in attack_data are in classic text format, which the reader
  doesn't parse, so they're left out.
