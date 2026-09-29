# Wazuh integration preparation

This package prepares Wazuh to read SignalBridge's sanitized application-security
observations and produce recognizable Wazuh alerts. It is a small interoperability
experiment: a security engineer can trace a rule to its input and see why it did
or did not match. It does not install software, start a container, change Windows,
monitor the host, or take automatic action.

**Current evidence: offline preparation checks only.** Wazuh has not been executed
by this preparation task. A valid XML document and passing Python checks do not
establish that Wazuh accepts the configuration or produces the expected alerts.
The parent task owns actual runtime validation and any resulting evidence.

## Files and contract

| File | Purpose |
| --- | --- |
| `manager-lab.conf` | Complete proposed manager-only configuration, not a fragment to merge into an active installation. |
| `signalbridge_rules.xml` | One grouping rule and five observation rules using the built-in JSON decoder. |
| `fixtures/events.jsonl` | 27 deliberately fabricated inputs, including negative cases. |
| `fixtures/expectations.json` | Separate expected outcomes; never sent into the detector. |
| `image-lock.json` | Fixed manager version/platform and registry manifest identities. |
| `verify_static.py` | Offline source-contract, configuration-safety and simple field-predicate checks. |
| `../../tests/test_wazuh_preparation.py` | Regression tests for unsafe changes and misleading evidence. |
| `run_pilot.py` | Fixed container-only driver for the approved, bounded synthetic pilot. |
| `event-contract.json` | Runtime enum snapshot checked against current application source by the offline check. |

The input shape is the existing `export_soc` command's v1 nested `signalbridge`
object: `export_version`, `app`, `environment`, `event_id`, `occurred_at`,
`operation`, `outcome`, `reason`, and `source`. No actor identity, resource ID,
credential, application record, or benchmark label belongs in that object.
The checker compares those keys against the export command's actual source and
reads the application's operation/outcome/reason enums without loading Django.

All fixtures are synthetic, including fixtures that exercise the `migration_lab`
source branch. A source field in a test file is not proof of a real SQL execution.
`legacy_unclassified` remains a valid historical export value but does not qualify
for these custom alerts. Neither the rules nor the checker authenticate a sender.
The future runner must accept only a scoped export or this known fixture corpus.

## What the rules mean

| ID | Level | Meaning | Analyst interpretation |
| --- | ---: | --- | --- |
| 100200 | 0 | Recognized v1 lab/test observation | Grouping only; no alert. |
| 100201 | 12 | `migration_lab`, private read allowed, reason `membership_removed` or `policy_regression` | The source reports access after revocation. Review the linked SQL test and intentional fault context. |
| 100202 | 5 | Same pattern from `synthetic_demo` | Explicit simulated scenario; not an observed application defect. |
| 100203 | 3 | Private read reported denied | Individual observation, including expected enforcement; not an attack finding. |
| 100204 | 3 | Private read reported not visible | Missing rows alone do not prove authorization denial. |
| 100205 | 4 | Error with `dependency_unavailable` | Coverage may be inconclusive until the dependency recovers. |

The matrix contains **11 expected custom alerts, 6 grouping-only observations and
10 inputs outside the alerting envelope**. These are expected classifications,
not measured true-positive/false-positive rates. The denied and not-visible rules
are informational by design. The package does not recreate SignalBridge's R1
three-distinct-resources correlation: export v1 intentionally omits the actor and
resource identifiers that would be needed. No ATT&CK technique, compliance
certification, production compromise, or enterprise parity is inferred.

Wazuh supports nested JSON fields, multiple field conditions joined with AND,
and custom IDs in the 100000–120000 range. The rules use those documented
mechanisms. `no_full_log` removes the raw event from the alert, but decoded fields
can still be retained; it is **not** a general redaction filter. Strict input
allowlisting remains necessary. [JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html),
[rule syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html),
[custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html).

## Offline verification

From the repository root, using the already installed Python environment:

```powershell
.\.venv\Scripts\python.exe integrations\wazuh\verify_static.py
.\.venv\Scripts\python.exe -m unittest tests.test_wazuh_preparation tests.test_wazuh_pilot -v
```

These checks parse XML, reject enabled response/scanning/network modules or
broadened input paths, check the strict export schema, and compare the simple
anchored field predicates with the separate 27-case expectation matrix. Mutation
tests show that widening observed-source trust, changing revocation matching,
enabling responses, or dropping negative cases fails the checks. Python regular
expressions here are a limited consistency check; they do not validate Wazuh's
PCRE2 behavior, decoder precedence, rule loading, daemon startup, delivery,
deduplication, or alerts written to disk. The result explicitly sets
`wazuh_executed` and `collection_verified` to false.

## Runtime boundary awaiting execution

The official documented single-node Docker deployment contains a manager,
indexer and dashboard. It specifies at least 4 cores, 8 GB host memory and 50 GB
storage capacity. **50 GB is capacity guidance, not an immediate 50 GB download.**
The indexer also requires a host `vm.max_map_count` setting. This proposal omits
the indexer and dashboard, so it does not provide their search/UI/storage
capabilities and proposes no host kernel change. It is a custom limited lab,
not a vendor-validated replacement for the documented full stack.
[Official Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html).

The selected official image is `wazuh/wazuh-manager:4.14.8`, linux/amd64, pinned
by the platform manifest digest in `image-lock.json`. The parent task's read-only
registry check found approximately **906.2 MiB compressed layers**. Unpacked
layers, Docker's retained compressed data and logs consume additional disk;
their actual footprint is unmeasured until the controlled pull. Do not treat
compressed size as an installation-size promise. The version and image choice
match the official [4.14.8 single-node definition](https://github.com/wazuh/wazuh-docker/blob/v4.14.8/single-node/docker-compose.yml).

The proposed first runtime is one disposable manager image with no network,
published ports, host agent, Docker socket, host PID namespace, privileged mode,
cloud credentials, existing lab network, or personal-data mounts. Mount only
these reviewed files and a small dedicated synthetic input/output workspace.
Use an explicit time limit, PID/memory/CPU limits, bounded output, no automatic
restart, and retained private evidence. Approved pilot limits are 1 CPU,
1.5 GiB memory, 256 PIDs and 180 seconds; these are containment budgets, not proven sufficient
runtime requirements. A failed startup under these limits is a blocked check,
not permission to remove them. Runtime ownership and mount paths must be
reviewed before launch. Log rotation is not a cumulative disk quota.

### Why the stock entrypoint is unsuitable for the first check

The upstream image starts `/init`. Its initialization restores numerous files,
generates enrollment certificates, changes ownership, starts Wazuh via
`wazuh-control start`, and separately starts Filebeat. Setting `<indexer>` to
disabled does **not** stop the separate Filebeat service. The runtime must bypass
that general startup and explicitly select only the necessary local processes.
[Dockerfile](https://github.com/wazuh/wazuh-docker/blob/v4.14.8/build-docker-images/wazuh-manager/Dockerfile),
[initialization](https://github.com/wazuh/wazuh-docker/blob/v4.14.8/build-docker-images/wazuh-manager/config/etc/cont-init.d/0-wazuh-init),
[manager startup](https://github.com/wazuh/wazuh-docker/blob/v4.14.8/build-docker-images/wazuh-manager/config/etc/cont-init.d/2-manager),
[Filebeat service](https://github.com/wazuh/wazuh-docker/blob/v4.14.8/build-docker-images/wazuh-manager/config/etc/services.d/filebeat/run).

At image build time, `internal_options.conf` is moved to
`/var/ossec/data_tmp/exclusion/var/ossec/etc/internal_options.conf`; standard
initialization restores it. A custom entrypoint must restore that exact packaged
file into the container's private filesystem or provide its reviewed read-only
mount. It must not copy arbitrary host configuration or execute the entire
initialization script. Other required paths/ownership still need inspection in
the pinned image. [Packaged-file preparation](https://github.com/wazuh/wazuh-docker/blob/v4.14.8/build-docker-images/wazuh-manager/config/permanent_data.sh),
[exclusion list](https://github.com/wazuh/wazuh-docker/blob/v4.14.8/build-docker-images/wazuh-manager/config/permanent_data.env).

Modern `wazuh-logtest` is a Python client of the local analysis daemon's Unix
socket; invoking it by itself does not provide the analyzer. Start only the
required analysis/database processes for that check. The separate
`wazuh-logtest-legacy` executable is not interchangeable evidence for the modern
path. Analysis and legacy testing explicitly change group, chroot and change
user; a blanket capability drop alone is incompatible with those source paths.
The narrow candidate capability set is `SETGID`, `SYS_CHROOT`, `SETUID` after
dropping all capabilities, subject to runtime verification. No `SYS_ADMIN` or
`NET_ADMIN` is proposed. Extra permissions must not be added opportunistically.
[Modern client source](https://github.com/wazuh/wazuh/blob/v4.14.8/framework/scripts/wazuh_logtest.py),
[analysis daemon](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/analysisd.c),
[legacy test implementation](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/testrule.c).

The supplied configuration disables active response, enrollment, clustering,
rootcheck, file integrity monitoring, SCA, inventory, osquery, Docker collection,
vulnerability feeds, indexer integration, email, update checks and archive-all
logging. It defines no remote input, shell commands, cloud integration or
automatic action. Disabled configuration does not itself guarantee absent
processes or sockets: the future runner must verify the effective configuration,
selected processes and isolation before feeding data. [Active response control](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html),
[upstream manager configuration](https://github.com/wazuh/wazuh-docker/blob/v4.14.8/single-node/config/wazuh_cluster/wazuh_manager.conf).

## Acceptance gates for a real integration claim

1. Inspect the pinned image without stock startup; verify its digest, filesystem
   and startup dependencies. Record the exact source/config/rule hashes and
   containment limits. Preserve failures as failures.
2. Run modern `wazuh-logtest` against each input separately with a fixed timeout.
   For cases with an expected rule, compare exact ID, level and decoder `json`.
   Its documented `-U rule:level:decoder` option checks one log line per call.
   Negative cases must produce no SignalBridge child alert, with successful
   parsing/execution verified; a timeout or decoder error is not a negative pass.
3. Separately prove file collection. Create an empty dedicated input file, start
   only the required processes, establish collector readiness, then append a
   bounded validated batch. Compare actual alert event IDs and rule IDs against
   the batch, rejecting missing, unexpected or duplicate results. Inspect the
   negative controls and retain a count of each attempted step.
4. Keep raw tool output private. Publish a reviewed receipt with runtime/version,
   source identities, counts, expected/actual rules, failure codes, input hashes
   and explicit limits. Stop the container after the bounded check and verify
   no owned process remains. A logtest-only success does not establish collection.

These gates have **not** been executed by this package.
[Official logtest options](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html).

### Prepared pilot driver contract

The parent creates and verifies a new container before execution. Its explicit
entrypoint is `/var/ossec/framework/python/bin/python3`, command is
`/pilot/run_pilot.py`, working directory is `/pilot`, and initial user is `0:0`.
It mounts this directory read-only at `/pilot` and one new private run directory
at `/evidence`. No other bind mounts or anonymous volumes are part of this
profile. The external isolation gate remains mandatory: the Python driver is
not an enforcement substitute for Docker network/mount/capability controls.

The driver accepts no arguments or target overrides. It uses clean subprocess
environments and foreground `wazuh-db`, `wazuh-analysisd` and then
`wazuh-logcollector`; it never runs `/init` or a shell. Its normal work deadline
is 165 seconds with a hard 180-second alarm and a separate cleanup period. It
limits each logtest output to 128 KiB and daemon/alert files to 1 MiB, polling
those file bounds during work. The parent also bounds container logging; these
limits are not a hard container filesystem quota. Process cleanup can temporarily
use the packaged Wazuh user identity through the already approved `SETUID`
capability to stop daemons that dropped root, without adding `CAP_KILL`.

The stock collector retains UID 0 but switches to the Wazuh group. With DAC
override capabilities removed, it cannot create `queue/logcollector/file_status.json`
in the image's Wazuh-owned `0750` directory. Before starting processes, the driver
requires that exact container-only directory to be empty, non-linked, owned by
the packaged UID/GID `999:999`, and mode `0750`. It temporarily uses the owner
identity to change only that verified directory inode to `0770`, then restores
root identity. This uses the already approved SETUID/SETGID capabilities; it does
not change host permissions, add capabilities, or recursively change ownership.

The actual logtest stage attempts all 27 cases and records exact expected/observed
rule IDs and levels. It explicitly rejects the CLI's connection-error/exit-zero
failure mode for negatives. The collector stage sends the 18 schema-valid cases
plus one separately counted synthetic tail sentinel. It requires 12 exact
custom alerts and 7 no-custom-alert controls, no duplicate/unexpected custom
alerts, the sentinel, and a three-second
quiet window. Absence observations are bounded by that window. Cases that fail
schema validation are exercised through logtest only, not sent to the collector.

Readiness and consumed-record counts come from the real collector's
`var/run/wazuh-logcollector.state`, with the supported container-local
`logcollector.state_interval=1` setting. Before append, the sole configured input
must have zero events/bytes and the sole `agent` target must report zero drops.
Completion requires exactly 19 global events, the exact expected processed-byte
total, and zero reported drops. Upstream accounts compact JSON bytes plus one
terminating NUL per message; these counts are **not a file-descriptor offset or
an end-of-file assertion**. Incomplete state-file rewrites never count as successful
observations. This avoids `/proc` access that would require broader privileges.
The byte accounting and state format were reviewed in the pinned official
[JSON reader](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/read_json.c),
[collector queue code](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c),
and [state writer](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/state.c).

`result.json` records actual case results, both stage statuses, source hashes,
runtime version and process cleanup. Bounded raw logs stay beside it privately.
Overall `passed` requires both stages and confirmed stopped child processes;
partial success remains failed. The parent must still record image identity,
before/after isolation checks and final container stop. This prepared driver
has passed mocked parser/safety tests only until a separate runtime receipt
demonstrates otherwise.

## Delivery and privacy limits

`export_soc` overwrites its output with all processed events. Do not point a
running collector at that repeatedly rewritten file and claim reliable streaming.
The future runner should copy one validated batch into its private workspace,
start with a fresh empty collector input, and append once after readiness. The
configuration's `only-future-events=yes` deliberately does not guarantee that
pre-existing contents will be read. A later continuous connector needs a durable
cursor, replay handling, failure recovery and an explicit retention policy.
[File collection configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html).

The Wazuh JSON decoder is not a strict JSON-schema gate; rule patterns cannot
reject every extra field or preserve every JSON type distinction. Before feeding
an application export, reject unknown keys, duplicate keys, malformed/oversized
JSON, unsupported versions and unexpected values with the strict validator.
The deliberately invalid corpus cases are solely negative parser/rule tests.
Even synthetic raw alerts remain private until reviewed; `event_id` can link
evidence across systems. No raw credentials, source application content, real
user data, external notification or automated remediation is in scope.

The parent task received approval for the limited image pull and bounded local
pilot; this preparation task does not perform the pull or launch it. Additional
capacity, host settings, broad privileges,
network exposure, host agents, cloud or paid components require a separate
decision. This package requests none of those extensions and performs none of them.
