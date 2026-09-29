# Fixed ZAP pilot runtime handoff

This is the reviewed execution contract, **not a record of a completed run**.
The pilot makes three anonymous GET requests to a deliberately simple synthetic
fixture and asks ZAP's passive rules to analyze those responses. A successful
result demonstrates a bounded tool connection and known header controls. It does
not assess SignalBridge application security, BetTail, Netted, authenticated
flows, exploit resistance or enterprise parity.

## Preconditions and fixed identities

The operator must verify the approved download/disk budget, at least 25 GiB free
disk at every stage, and no unrelated running containers. Do not stop an unrelated
workload to make the gate pass. The approved total active pilot ceiling is three
GiB RAM and two CPUs; run Wazuh and ZAP stages sequentially.

Use these immutable image references and retain their inspected image IDs:

- Scanner: `zaproxy/zap-stable@sha256:71db37cd5b75663b35758d10aaec05bf6fbac23f5020e3046c70e628a5f84efa`
- Target: `python@sha256:7bf6c3111fe094f8ee1a1cbcdc63c4cfb345b0e3df42d5aa9a90b3b4b022ab6d`

Create a fresh canonical UUIDv4 run directory at
`var/soc/pilot/<run-id>/zap`. The `zap` directory must be empty and private; neither
symlinks nor junctions are allowed. Never reuse a previous run or overwrite its
evidence. Resolve both mount sources within this repository. Freeze every file in
`integrations/zap` before recording the first gate: the gate hashes the whole
directory, including these documents. A changed source requires a new attempt.

## Container contract

Create, but do not start, the exact two containers and an exclusive internal bridge
network named `signalbridge-soc-zap-pilot`. No host port, host network, host PID/IPC
namespace, host service, device, socket, original repository or credential mount
belongs in this profile. No capability additions are allowed. Both containers use:

| Setting | Required value |
|---|---|
| User | `1000:1000` |
| Root filesystem | Read-only |
| Entrypoint | `["python3"]` |
| Working directory | `/pilot` |
| Capabilities | Drop `ALL` |
| Security option | `no-new-privileges` |
| IPC / cgroup namespace | `private` / `private` |
| Restart policy | `no` |
| Log driver | `json-file`, `max-size=2m`, `max-file=2` |
| Source mount | Repository `integrations/zap` to `/pilot`, read-only |

| Setting | Scanner | Target |
|---|---|---|
| Container name | `signalbridge-soc-zap-pilot` | `signalbridge-soc-zap-target` |
| Hostname | `signalbridge-soc-zap-pilot` | `signalbridge-zap-target` |
| Required network alias | Scanner's fixed name | `signalbridge-zap-target` |
| Command | `["-I","-B","/pilot/run_passive.py"]` | `["-I","-B","/pilot/fixture.py"]` |
| Memory / memory+swap | `2684354560` / same | `268435456` / same |
| CPU | `1.5` | `0.5` |
| PID ceiling | `256` | `64` |
| `/tmp` tmpfs | `rw,nosuid,nodev,noexec,size=512m,uid=1000,gid=1000,mode=700` | `rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000,mode=700` |
| Evidence mount | Fresh UUID `zap` directory to `/evidence`, read-write | None |

Python's `-I` ignores environment and user-package injection. Both scripts add
only the fixed `/pilot` path for their reviewed companion module; that mount must
remain read-only. `-B` disables bytecode writes. There is no dependency installation
or shell entrypoint. If Java cannot run under the tmpfs restrictions, retain the
failed attempt and investigate; do not remove `noexec` merely to obtain a pass.

## Gated execution sequence

The inspection command does not start or stop containers. Run it from the
repository root, substituting the freshly created UUID (not a target override):

```powershell
.venv\Scripts\python.exe scripts/verify_soc_pilot.py --profile zap --run-id <run-id> --state created
```

Require success before starting either container. Retain the sanitized JSON gate
receipt beside, not inside, the initially empty `zap` directory. The gate checks
actual image IDs, exact configuration, mounts, source hashes, network membership
and the global running-container inventory. Creation is not proof of runtime
egress behavior; preserve the separate runtime boundary evidence required by the
parent run report.

Then start the fixed target and scanner names promptly. The target's 360-second
lifetime begins at startup, so do not leave it idle while preparing unrelated
work. While both containers are running, require the corresponding gate:

```powershell
.venv\Scripts\python.exe scripts/verify_soc_pilot.py --profile zap --run-id <run-id> --state running
```

The driver has no arguments. It starts `/zap/zap.sh` with daemon and silent options,
listens only on container `127.0.0.1:8080`, and uses a private 128-bit API key in a
temporary properties file. The key is not an argument or evidence field. The API
allowlist contains only configuration, passive status, report and shutdown calls;
it exposes no scanner action to users. The proxy client sends exactly, in order:

1. `GET http://signalbridge-zap-target:8000/`
2. `GET http://signalbridge-zap-target:8000/login/`
3. `GET http://signalbridge-zap-target:8000/health/`

No redirect is followed. The driver refuses a redirect status, `Location` header,
wrong fixture identity or ordinal, unexpected body hash, extra history record,
incomplete passive queue or missing known header control. The unfiltered
read-only history API is capped at eight records and must return exactly six:
three type-1 proxied requests matching the fixed responses and three type-0
internal ancestor records for the bare origin, `/login` and `/health`. The latter
are constructed bookkeeping records, not additional HTTP requests. Each must
have the source request's cloned headers, no body, zero send/response timing,
the default empty response, and no notes or tags. Other types, paths, duplicates
or populated responses fail. The receipt records total, proxied and internal
counts separately; the actual request count remains three.

This follows pinned ZAP 2.17.0
[SiteMap.createReference](https://github.com/zaproxy/zaproxy/blob/v2.17.0/zap/src/main/java/org/parosproxy/paros/model/SiteMap.java#L638),
[HttpMessage.cloneRequest](https://github.com/zaproxy/zaproxy/blob/v2.17.0/zap/src/main/java/org/parosproxy/paros/network/HttpMessage.java#L941)
and the [CoreAPI history inventory](https://github.com/zaproxy/zaproxy/blob/v2.17.0/zap/src/main/java/org/zaproxy/zap/extension/api/CoreAPI.java#L1645).
The driver refuses a different ZAP release. The history API omits image messages;
the fixed target only returns HTML/JSON. Sites-tree `urls` are not counted as
requested pages. Raw history headers/bodies are checked in memory and never
retained in the pilot receipt.
HTTP exchanges have five-second absolute deadlines; ZAP startup allows up to 120
seconds and passive completion up to 60. The 240-second overall budget reserves
30 seconds for cleanup. The operator must enforce an external 240-second scanner
deadline too; a timeout is a failed attempt. Stop only these owned names, capture
their exit/state and bounded logs, and leave unrelated resources untouched.

After both stop, require and retain:

```powershell
.venv\Scripts\python.exe scripts/verify_soc_pilot.py --profile zap --run-id <run-id> --state exited
```

An exited target stopped by the operator is expected; it is not evidence that the
scanner succeeded. Evaluate the scanner exit code and receipts separately. Do not
delete failed containers/evidence or run global Docker cleanup as part of triage.

## Evidence required before claiming success

Reconcile the created/running/exited gate receipts and unchanged source hashes;
actual versions and image IDs; scanner exit code; private `pilot-result.json`;
three target acceptance logs; exact three-request proxy inventory; passive queue
completion; known positive/negative control results; and report SHA-256. The
header control is rule `10021` on `/` and `/login/`, absent on `/health/`.

The private traditional `zap-report.json` is capped at two MiB and process log at
one MiB. A truncated or incomplete log fails the driver; key redaction also covers
read-chunk and truncation boundaries. Raw reports and logs remain private. Parse
the raw report with `bridge.zap_report.parse_zap_report` before importing sanitized
findings. A schema mismatch must be reviewed and tested without relaxing target,
credential or provenance boundaries.

`diagnostics.json` records bounded numeric counts, record IDs/types, fixed target
categories, unexpected-URL hashes and passive scope/rule flags before the strict
history assertions. It contains no raw HTTP or URL values. A failed attempt may
also retain `failure-report-summary.json` from the same read-only API within the
original deadline. That artifact includes only fixed GET paths, numeric rule
metadata and a raw-report digest; it remains a failed diagnostic without execution
provenance. Neither artifact changes the required passing checks.

The application import remains `claimed_report` with unknown coverage, including
when the separate pilot passes. Do not turn tool-supplied report data into verified
execution metadata. Public evidence should contain only sanitized rule/path
metadata and retained execution receipt references. Actual runtime results belong
in a dated parent execution report; leave this source handoff frozen for that run.
