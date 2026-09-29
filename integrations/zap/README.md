# ZAP integration: bounded synthetic pilot preparation

**Status: parser, fixed request driver and synthetic fixture prepared; actual ZAP
execution is pending.** No live connection or security finding is established by
preparation or mocked tests. [Runtime instructions](RUNTIME.md) require a separate
container inspection gate and retained execution evidence.

The business purpose is to add reviewable web-security observations alongside
SignalBridge's authorization evidence. This first scope concerns three anonymous
GET requests to a disposable synthetic HTTP fixture. It cannot establish authenticated
coverage, authorization correctness, broad application coverage or enterprise parity.

## Target and import API

[profile.json](profile.json) declares exactly `http://signalbridge-zap-target:8000`
and `GET /`, `GET /login/`, `GET /health/`. There are no target overrides. This
initial runtime uses a clearly labelled synthetic fixture for a connectivity and
header-rule demonstration. It contains no SignalBridge application code; a copied
application assessment would require a separately reviewed profile.
The running host console, BetTail, Netted, public sites and production systems are
outside this profile. A fixture result must not be presented as an application scan.

The pure Python API is
`bridge.zap_report.parse_zap_report(raw: bytes) -> ParsedReport`. It uses the
[existing scanner JSON loader](../../bridge/scanner_reports.py), performs no I/O
and accepts a strict subset of ZAP's [traditional JSON format](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/).
The parent import workflow must restrict this fixed profile to the `signalbridge`
application and retain normal permission checks and audited review decisions.

Accepted metadata is deliberately small:

- One exact site identity; only the three literal GET URLs, without query strings,
  fragments, credentials, URL aliases, encoded paths or normalization.
- Numeric release version, plugin ID and matching alert reference; bounded numeric
  reported risk/confidence and reconciled nonempty instance counts.
- Generated titles containing the approved method/path and reported confidence.
  The finding ID is the numeric alert reference, such as `10020` or `10020-1`.
  Fingerprints bind the profile, origin, rule, method and path.
- Blank artifact path, line and package fields: a web endpoint is not a source file.
  Multiple cookie/parameter instances of the same rule at one endpoint consolidate
  only after every instance passes validation.

Free-form alert titles, descriptions, remediation, references, tags, parameter
names, attack strings, evidence, raw headers/bodies and cookies never appear in
normalized findings. Every error message is fixed and omits payload values.
Known optional raw HTTP fields are bounded and discarded. Recorded 3xx status or
`Location` response headers are rejected; unsupported redirect fields or schema
extensions fail closed. Insights are discarded after checking their site and bounds.

The input limit is 2 MiB, with shared limits of 32 JSON nesting levels and 100,000
JSON nodes. Duplicate keys, non-finite numbers and invalid UTF-8 fail. This adapter
adds limits of 250 alert groups, 50 instances per group, 2,000 total instances and
65,536 characters per ignored text field. Unsupported versions/shapes require
explicit adapter review; this is not a universal ZAP report reader.

`format` is `zap`, `tool` is `ZAP`, `coverage_status` is always `unknown`, and
`input_count` is zero because alert instances do not count scanned requests.
An empty report never proves a clean completed scan. Supplied execution, source,
success and suppression claims are refused. Even a ZAP confidence of “confirmed”
or “false positive” remains a labelled tool claim; it does not decide SignalBridge's
review status. The existing local-runner provenance allowlist must remain separate.

## Prepared passive runtime

The official [baseline script](https://www.zaproxy.org/docs/docker/baseline-scan/)
spiders for one minute by default before passive analysis. It offers time controls,
but crawling is broader than three explicit requests. The initial profile therefore
calls for a fixed no-spider, no-active-scan request sequence and passive analysis.
No login submission, Ajax browser, imported script, user-supplied URL or external
add-on update is included.

ZAP's [requestor job](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-requestor/)
supports explicit URLs/methods and expected status checks. Its documented fields
do not include a redirect switch. Current upstream [RequestorJob source](https://github.com/zaproxy/zap-extensions/blob/main/addOns/automation/src/main/java/org/zaproxy/addon/automation/jobs/RequestorJob.java)
uses the default HTTP sender call, whose [API distinguishes redirect configuration](https://github.com/zaproxy/zaproxy/blob/main/zap/src/main/java/org/parosproxy/paros/network/HttpSender.java).
Those moving upstream references are design research, not verification of an
installed image. The prepared driver uses Python's standard HTTP client as an
explicit proxy client; it never follows responses or renders their content.
The separate container gate inspects the fixed destination boundary.

A copied SignalBridge `/` may redirect anonymous requests to its login page.
The prepared synthetic profile requires three 200 responses and fails immediately
on a redirect or `Location` header. It must not relabel a redirect from a future
copied application as a successful all-200 scan.

[run_passive.py](run_passive.py) starts ZAP on container loopback, sets Safe mode,
creates an exact three-URL context, enables passive scanning only in scope, and
sends three ordered GET requests through the proxy. A random 128-bit API key
stays in a private temporary configuration file and API headers. It is absent from
target requests and process arguments, and redacted from retained process logs.
Startup update checks are disabled; the documented [-silent switch](https://www.zaproxy.org/docs/desktop/cmdline/)
prevents unsolicited startup requests. The request driver has no active-scan,
spider, login or arbitrary URL entry point.

[fixture.py](fixture.py) uses Python's standard library. It returns fixed synthetic
bodies and a request ordinal, rejects wrong target headers/order or credentials,
and has no accounts, database or uploaded content. `/` and `/login/` intentionally
omit `X-Content-Type-Options`; `/health/` supplies `nosniff`. The driver requires
ZAP rule `10021` on the first two paths and its absence on the health path. This is
a known header-rule control, not a vulnerability found in SignalBridge. Exact
body hashes, stored HTTP-message inventory and queue completion must agree before the
driver passes. Success still requires independent container checks and the strict
host-side report parser.

The pinned [ZAP 2.17.0 CoreAPI implementation](https://github.com/zaproxy/zaproxy/blob/v2.17.0/zap/src/main/java/org/zaproxy/zap/extension/api/CoreAPI.java)
builds `urls` from Sites-tree nodes; that list is not an exact request ledger.
The driver instead reads unfiltered `messages` with a four-record cap, requires
exactly three unique GET request lines and the fixed Host, and reconciles 200
responses, fixture ordinals and bodies. Raw HTTP remains in memory. ZAP's history
API omits image messages, so this check is explicitly limited to the three fixed
HTML/JSON responses and is paired with target-side accounting and isolation.
Before asserting inventory, the driver retains bounded diagnostics with numeric
counts/record IDs/types, fixed target categories and hashes of unexpected URLs;
raw HTTP, bodies and URL values are omitted. Failed validation can retain a
separate sanitized report summary through the existing read-only API, within
the same deadline. It stays failed and establishes no execution provenance.

[Passive configuration](https://www.zaproxy.org/docs/desktop/addons/passive-scanner/job-pscanconf/)
supports in-scope-only processing, alert caps and a maximum body size to scan.
[Passive wait](https://www.zaproxy.org/docs/desktop/addons/passive-scanner/job-pscanwait/)
can have a finite duration. A body-size-to-scan setting does not itself limit HTTP
download size. A timeout or unfinished passive queue must remain incomplete.
Traditional JSON generation should include all risk/confidence levels and omit
script diagnostics. The [report job's site filter](https://www.zaproxy.org/docs/desktop/addons/report-generation/automation/)
uses substring matching, so it is not the target security boundary; the parser
still checks literal site/instance identities.

## Resource and containment envelope

These are project-selected ceilings for a tiny initial run, not vendor minimums
or measured usage. The profile sets 2.5 GiB RAM, 1.5 CPUs and 256 PIDs for ZAP;
256 MiB, 0.5 CPU and 64 PIDs for the target; three target requests; five seconds
per request; 256 KiB response bodies; 60 seconds passive waiting; 240 seconds total;
and a 2 MiB private report. Combined ceilings are 2.75 GiB and two CPUs; the JVM
heap is 1,536 MiB within its container cap. ZAP documents [JVM memory options](https://www.zaproxy.org/docs/desktop/ui/dialogs/options/jvm/).
Absolute Linux wall-clock deadlines cover each HTTP exchange, including body
consumption; the parent must also enforce the container's overall deadline.
These limits are configuration, not measured peak consumption.

Use a dedicated internal network containing only the scanner and disposable
target, with no published ports, host networking, Docker socket, original
repositories, existing app database or host credentials. Use reviewed immutable
image digests, non-root users, dropped capabilities, no-new-privileges, bounded
temporary storage and minimal mounts. Check actual topology, mounts, privileges,
resource limits, blocked outbound access and source identities before and after.
Network isolation must prevent reaching the host, metadata endpoints and any
other application; a context regex alone cannot do that. Runtime logging and
report paths must be private, bounded and exclusive.

The official [stable Docker image](https://www.zaproxy.org/docs/docker/about/)
changes for releases and monthly refreshes. Resolve and record its digest before
execution; do not use a floating tag as an execution identity. This preparation
neither pulls that image nor estimates its download size as a verified measurement.

A completed runtime receipt must separately reconcile the target identity,
image/add-on versions, plan/source hashes, exact attempted request inventory,
statuses, no-follow behavior, passive queue completion, process exit, isolation
checks and sanitized report digest. A traditional report omits requests with no
alerts and can omit redirect history; parsing alone can prove neither coverage
nor absence of an earlier out-of-scope request. Preserve failures and require
ordinary review of any reported finding. Stop only owned resources and preserve
private evidence; do not run global Docker cleanup.

## Verification

[Parser and driver tests](../../tests/test_zap_report.py) use synthetic reports and
exercise allowed metadata, off-target/redirect refusals, credential stripping,
strict JSON/type/count bounds, stable identities and false provenance claims.
They also mock proxy requests, absolute deadlines, API routes, report controls and
bounded log redaction. They do not run ZAP or contact the target. The 40 focused
tests passed on 2026-09-24; Ruff checks passed for the five owned Python modules.
This is preparation evidence, not a scanner execution result. From the repository root:

```powershell
.venv\Scripts\python.exe -m unittest tests.test_zap_report
```
