# Shuffle integration

**Status: October 5, 2026 - passed.** A real Shuffle workflow ran nine scenarios inside the
dedicated network-less VM against SignalBridge's signed review-task API
([run 315cfb85](../../docs/evidence/20261005-shuffle-native-workflow-315cfb85-9c28-4e4e-9cac-8ce455e92448.json)).

| Scenario | Receiver answer | Meaning |
| --- | --- | --- |
| first | 201, task created | A genuine Shuffle execution creates one review task |
| retry_new_nonce | 200, duplicate, same task | A retried request returns the original receipt |
| replayed_request | 409 `request_replayed` | A reused nonce is refused |
| changed_content | 409 `idempotency_conflict` | The same key with different content is refused |
| wrong_scope | 404 `case_unavailable` | Another app's case is refused without confirming it exists |
| stale_evidence | 409 `case_evidence_changed` | A task for evidence that has since changed is refused |
| receiver_timeout | no reply | The execution finishes; nothing is created |
| lost_reply | no reply (task committed) | The receiver committed but the caller never heard |
| retry_after_lost_reply | 200, duplicate, the committed task | The retry recovers the lost receipt |

The receiver ended with exactly 2 tasks, 2 idempotency records and 8 accepted nonces, and
Orborus started 9 worker and app containers. Each scenario has its own Shuffle execution ID.

## What it took

Shuffle needs Docker-socket access, which on this PC could reach other projects' containers,
so everything that executes runs only inside a dedicated VirtualBox guest with no network
adapter and no shared folder. Thirteen VM runs on October 4-5 found and fixed these problems:

- **Transport.** Python on Windows could not read the guest's serial port through a named
  pipe, so VirtualBox now writes it to a file. The guest reports `started` first so a stalled
  boot is noticed early, and the host retries a boot that never reports in (up to three times).
- **VirtualBox on Hyper-V.** Docker Desktop needs Hyper-V, so VirtualBox runs on Windows'
  hypervisor platform. With four virtual CPUs the guest's timer clock froze for minutes, at
  boot and mid-run, even after a Windows restart. With **one virtual CPU** the clock stayed in
  step and every run booted first time. Moving the disk to AHCI did not help.
- **Guest housekeeping.** The side-loaded receiver image loads with no name, so the guest finds
  it by its pinned digest. The guest disk persists between runs, so only this workflow's own
  leftovers are removed before a run.
- **SignalBridge bug.** In local mode the settings wrote a key file even when `SB_SECRET_KEY`
  was supplied, which fails on the guest's read-only source mount. Fixed, with a regression test.
- **Swarm mode.** With `SHUFFLE_SWARM_CONFIG=run`, as in upstream's compose file, Orborus tried
  to deploy workers as a swarm service on a host that is not a swarm manager, so no execution
  ever ran. Without it, Orborus starts plain worker containers that copy its network.
- **Signed body.** Shuffle's HTTP app 1.4.0 rewrites a JSON body with
  `json.dumps(ast.literal_eval(body))`. The signature covers the body bytes, so every request
  first failed with 401. That was the receiver's control working as designed. The dispatcher now
  signs exactly the form the app sends, and refuses to send a body the app would change.

Failures are diagnosable: on a failed run the guest sends the dispatcher's output, filtered
backend and Orborus logs and worker logs over the serial port, with credential values removed.
Earlier September evidence remains preserved:
[storage test](../../docs/evidence/20260925-shuffle-storage-checkpoint.json),
[offline image check](../../docs/evidence/20260925-shuffle-local-images.json),
[restart checkpoint](../../docs/evidence/20260925-shuffle-restart-checkpoint.json).

### Run it

1. Start Docker Desktop (it builds the guest payload from pinned local images) and keep other
   projects' containers stopped; the VM needs about 8 GiB of free memory and one CPU.
2. From the repository root, with the project interpreter:
   `PYTHON -B integrations/shuffle/lab/host_controller.py`. It needs the retained wheel
   cache of run b8667b81 under `var/enterprise/runs/`.
3. The controller prints the receipt path. Success is `"status":
   "guest_completed_pending_review"` with `shutdown_verified: true`; review the nine scenario
   results in `dispatcher.scenarios` before promoting the receipt to `docs/evidence/`.
4. If a run reports `opensearch_not_green` or `guest_not_started`, check `Logs/VBox.log` in the
   VM folder for `Giving up catch-up attempt` (the timer problem) and the VM's CPU count.

## What this folder proves

- `handoff_contract.py`: offline validation and idempotency decisions for one
  synthetic BetTail/lab review request. No task is created.
- `workflow-plan.json`: design only; it is not an importable native workflow.
- `lab/`: the native run - receiver settings and seed, the signing dispatcher
  (nine scenarios as genuine Shuffle executions), the guest orchestrator and the
  host controller. Signature compatibility and isolation checks are in
  `tests/test_shuffle_lab.py`.
- `image_identity.py`: bounded, I/O-free validation of Docker 29 containerd
  metadata, preserving the five reviewed image pins. Twenty synthetic regressions
  are in the core suite. [Preparation evidence](../../docs/evidence/20260925-shuffle-image-verifier.json)
  records separate mocked resume checks and incomplete native verification.

Run the image checks locally with the project interpreter:

```text
PYTHON -B -m unittest tests.test_shuffle_image_identity -v
```

The verifier follows a pinned target/index to exactly one Linux/amd64 manifest,
then to its configuration. It checks digest, descriptor size, repository,
platform and runtime-reported layer identifiers. It reads at most three metadata
blobs per image through a caller-supplied bounded reader; it never downloads,
extracts, executes or reads layer bytes. Its results do not establish signatures,
vulnerability clearance, image compatibility or guest identity.

Docker 29's containerd implementation reports the target digest as the image ID
when inspection omits a platform override. This differs from the configuration
digest. The fixed guest profile must preserve that distinction and independently
check the reviewed HTTP/OpenSearch configuration pins.
[Engine implementation](https://github.com/moby/moby/blob/docker-v29.1.3/daemon/containerd/image_inspect.go),
[OCI manifest](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md),
[OCI index](https://github.com/opencontainers/image-spec/blob/v1.1.1/image-index.md).

`existing_components` only identifies candidates from a bounded partial inventory.
Every candidate needs full metadata verification before reuse. Foreign/dangling
IDs fail closed and require inspection; no cleanup is performed. Private resume
sources and receipts are retained privately. The five-image check establishes
local availability and metadata identity, not compatible execution. Existing
failed sources and ISO files remain unchanged; do not reuse their run identities.

## Intended bounded workflow

One authenticated dispatcher executes one fixed native Shuffle workflow. Its
allowlisted action calls a receiver inside the disposable SignalBridge lab.
That receiver must resolve the original event, app, case, current version and
evidence digest, then transactionally create at most one analyst review task.
Retries return the original receipt; changed content conflicts. Retain the real
Shuffle execution ID and task ID. A successful HTTP status alone is insufficient.

Native acceptance requires wrong-scope, missing/stale evidence, duplicate,
conflict, timeout and lost-reply tests, plus topology/resource and shutdown proof.
No account changes, messages, financial actions, arbitrary URLs/commands,
schedules, recursion or autonomous case closure are allowed. The analyst makes
any investigation decision through SignalBridge's own role checks.

## Isolation and remaining gates

Only the dedicated VM's own Docker daemon may support Shuffle execution.
No personal Docker socket, host folders, production data or shared credentials
enter it. The approved envelope is 8 GiB RAM, up to four CPUs (one is used; see above), a 60 GiB virtual disk,
8 GiB staging and at least 25 GiB host free space. Recheck actual capacity before
use. Networking is limited to reviewed acquisition; remove NICs before workflows.

The reviewed upstream deployment grants backend/Orborus Docker authority. That
can create privileged workloads and host mounts, so a socket proxy or an isolated
web page alone cannot establish the required boundary. Run 315cfb85 now shows the
pinned components working together offline, real app/action IDs, the scoped receiver and
task model, and genuine execution and recovery. Dynamic worker limits remain unverified.
[Reviewed Compose](https://github.com/Shuffle/Shuffle/blob/a106f27312bbb81791a33dfee585a6b8d0ad3289/docker-compose.yml),
[Docker daemon trust](https://docs.docker.com/engine/security/#docker-daemon-attack-surface).
