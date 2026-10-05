# Writing scenarios for a blind test of SignalBridge

Thank you for helping. SignalBridge is a security tool that watches how people use two business
apps and raises alerts when access looks wrong. Its rules were tested on scenarios written by
the same person who wrote the rules, which proves little. Your scenarios test it fairly: you
describe situations, and say whether a security analyst **should** be alerted. Afterwards the
rules, fixed before you started, run once on your file, and every result is published, misses
included.

You need about two to four hours and a text editor. No coding is needed.

## Ground rules

- **Work blind.** Read only this guide and `template.yml`. Don't read anything else in the
  SignalBridge repository, its documentation or its website, and don't ask the builder how the
  rules work. If you already know something about them, say so before you start.
- **Write what is true, not what you think gets caught.** Don't try to guess or beat the rules.
  Describe situations as you would expect them to happen, and label them by what really happened.
- **Synthetic only.** Use made-up names such as `alice` or `doc-1`. No real people, emails or
  IP addresses.
- **Credit.** The `author` line is how you'll be credited when results are published. Write
  `anonymous` to stay unnamed.
- **Keep the attestation.** The statement at the top of the template must stay exactly as written.
  It records that you worked blind.

## The world you are writing about

- There are two apps, **documents** and **expenses**.
- Each holds **private records**, for example a document or an expense report. A person can open a
  record if they are a **member** of it or its **owner**.
- **Admins** add people to records and remove them (**membership changes**).
- Every attempt to open a record, and every membership change, is reported as an **event**. A
  scenario is a short list of events: what happened, in order of time.
- Each app reports through a **source**: the real, instrumented test app, or a demo-data
  generator. Each app runs in a **test** or a **lab** environment.
- Names belong to one app: `alice` in documents and `alice` in expenses are unrelated accounts.
  Each scenario is its own world: names and records don't carry over between scenarios.

## Writing a scenario

```yaml
  - id: B01                      # B01, B02, ... in order
    title: One short line saying what happens
    label: suspicious            # suspicious, benign or inconclusive (see below)
    rationale: >-
      What really happened, in a sentence or two. This is the ground truth.
    events:
      - at: "0:00"               # time from the scenario's start
        actor: alice             # who did it
        resource: doc-1          # which record
        operation: private_record.read
        outcome: allowed
        reason: member
```

Each scenario has 1 to 30 events. Times run from `"0:00"` (minutes:seconds) up to `"48:00:00"`
(hours:minutes:seconds); put them in quotes. The time decides when an event happened, so you may
list events in any order, for example to show a report that arrived late.

### Event fields

| Field | Required | Values |
| --- | --- | --- |
| `at` | yes | Time from the scenario's start, such as `"0:45"` or `"2:15:00"` |
| `actor` | yes | Who acted: a short lowercase name such as `alice` |
| `resource` | yes | Which record: a short lowercase name such as `doc-1` or `exp-7` |
| `operation` | yes | `private_record.read`, `membership.change` or `session.verify` |
| `outcome` | yes | `allowed`, `denied`, `not_visible` or `error` |
| `reason` | yes | One of the reasons below |
| `app` | no | `documents` (default) or `expenses` |
| `environment` | no | `test` (default) or `lab` |
| `source` | no | `instrumented_lab` (default, the real test app) or `synthetic_demo` (demo data) |
| `membership` | for membership changes only | `subject` (whose access changed) and `state` (`removed` or `granted`) |

**Operations.**
- `private_record.read`: someone tries to open a private record.
- `membership.change`: an admin adds or removes one person's access to one record. The `actor` is
  the admin, and `membership.subject` is the person affected.
- `session.verify`: the app checks that someone's sign-in session is still valid.

**Outcomes.**
- `allowed`: it succeeded.
- `denied`: it was refused.
- `not_visible`: the app showed nothing, because the record is hidden or missing.
- `error`: the app failed to answer.

**Reasons.**
- `member`: the person is a member of the record.
- `owner`: the person owns the record.
- `membership_required`: refused because the person is not a member.
- `membership_removed`: the person's membership had been removed. Also the reason recorded on a
  removal.
- `resource_unavailable`: the record doesn't exist or isn't available.
- `session_invalid`: the person's session was invalid or expired.
- `mfa_required`: a second sign-in factor was required.
- `dependency_unavailable`: a service the app depends on was down.
- `policy_regression`: the app reports that its own permission check was in a known-faulty state,
  for example after a bad release.

**Membership changes** are always recorded with outcome `allowed`. The reason is
`membership_removed` when the state is `removed`, and `member` when it is `granted`.

## Labels

- **suspicious:** a security analyst should be alerted. For example: possible misuse, someone
  reaching what they shouldn't, or the app's access control failing.
- **benign:** normal activity, or a harmless mistake, that should not create work for an analyst.
- **inconclusive:** even knowing everything, you can't say. Use it sparingly, and explain why.

The rationale is the truth of what happened, written before you know any results.

## What makes a good set

- **Size:** 20 to 60 scenarios; 30 to 50 is ideal.
- **Balance:** at least 8 suspicious and 8 benign.
- **Variety:** think about what normal work looks like in these apps, the mistakes people and
  systems make, and what a careless insider or an attacker might try. Vary who is involved, how
  many records, the timing, and which app, environment and source.
- **Mix of difficulty:** obvious cases, subtle ones, and normal activity that looks suspicious but
  isn't.

## Sending it

Save the file as `scenarios.yml` and send it back to the person who gave you this guide.

They will:
1. Run a **format check only**, which does not run the detector, and tell you about any format
   problems to fix.
2. Seal the file by recording its fingerprint before any scoring.
3. Run the rules once and publish the result, with your scenarios, labels and rationales, under
   the credit you chose.
