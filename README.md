# SignalBridge

SignalBridge is a security workbench for access-control monitoring. It collects signed telemetry from web applications, runs detection rules over it, and gives an analyst a console to investigate cases, review scanner findings and record decisions. I built it to monitor my own apps (BetTail and Netted) and connected it to Wazuh and OWASP ZAP in isolated Docker labs.

[Evidence viewer](https://aman-agarwal6.github.io/signalbridge/portfolio/) · [Design notes](docs/DESIGN.md) · [Case study](https://aman-agarwal6.github.io/projects/signalbridge.html)

![Evidence viewer showing 64 of 64 records delivered to Wazuh](docs/images/evidence-viewer.webp)

## What's in it

- **Signed ingestion.** HMAC-SHA-256 request signing, a closed JSON schema capped at 16 KiB, replay and duplicate handling, and per-app rate limits. The schema has no fields for personal data.
- **Detection rules.** R1 flags one account failing to read three or more distinct private records within five minutes. R2 flags an allowed read after a membership removal or policy regression.
- **Analyst console.** Cases scoped per app, viewer/analyst/reviewer roles, CSRF protection, a no-script CSP, strict session cookies and login throttling. Reviewers can't approve their own rule changes.
- **Wazuh integration.** A recorded backfill delivered 64 of 64 events with the 31 expected alerts and no loss or duplicates. A separate run restarted the collector twice without losing input.
- **ZAP integration.** Passive scan imports. A scan against an unavailable target is recorded as failed, not clean.
- **Tests.** 1,083 automated tests (1,030 Python, 53 Node).

Three harder patterns were written into a detection challenge on purpose, and none of them alerted: slow probing over more than five minutes, probing spread across accounts, and revocations without affected-member context. See the [design notes](docs/DESIGN.md#detection-rules).

## Why a record alerted

The evidence viewer shows each alert field by field against the Wazuh rule that fired.

![Rule explanation table comparing recorded values with the rule's patterns](docs/images/rule-explanation.webp)

## Running it

Requires Python 3.11+. Node 24+ is needed for the courier and its tests. On Windows:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -B scripts/sb.py doctor
.venv\Scripts\python.exe -B scripts/sb.py demo-core
```

Then open http://127.0.0.1:8741/. `demo-core` creates local accounts with random passwords in `var/local-access.txt`, which git ignores. On Linux or macOS, use `.venv/bin/python`.

Tests:

```powershell
.venv\Scripts\python.exe manage.py test tests --exclude-tag offline_simulation
$env:SB_SECRET_KEY = "any-long-random-test-value"
.venv\Scripts\python.exe manage.py test tests --tag offline_simulation --settings config.simulation_settings
node --test integrations/sender.test.mjs integrations/supabase-http.test.mjs integrations/bettail-routes.test.mjs
```

On Windows, clone to a short path such as `C:\src\signalbridge`. A few snapshot tests create deeply nested files that exceed the 260-character path limit in long folders.

The Docker labs are optional. See [integrations/wazuh](integrations/wazuh/README.md) for the Wazuh lab.

## Layout

| Path | Contents |
| --- | --- |
| `bridge/` | Django app: ingestion, detection engine, worker, rule replay, scanner imports, console |
| `integrations/` | Delivery courier, Wazuh rules and backfill, ZAP import, BetTail route harness |
| `tests/` | Python and Node tests |
| `docs/evidence/` | JSON receipts for every recorded run |
| `portfolio/` | The evidence viewer (static HTML, no scripts) |
| `scripts/` | Setup, verification and lab runners |

## Notes

This is a local proof of concept, not a hosted service. The console trusts local administrators and shouldn't be exposed to a network. See [SECURITY.md](SECURITY.md).

Built by [Aman Agarwal](https://aman-agarwal6.github.io/) in September 2026, with AI coding agents writing much of the code under my direction. I developed it in a private repository; this is a cleaned public snapshot, so its history starts here. MIT licensed.
