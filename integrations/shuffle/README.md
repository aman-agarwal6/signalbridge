# Shuffle integration preparation

**Status: September 25, 2026 - deferred; native workflow not verified.** The
[storage startup test](../../docs/evidence/20260925-shuffle-storage-checkpoint.json)
failed and stopped safely. The employer demonstration takes priority; no automatic
retry is scheduled. Following the
Windows restart, all five pinned images passed a separate [offline metadata check](../../docs/evidence/20260925-shuffle-local-images.json)
with verified automatic shutdown. Earlier boot, identity-comparison and truncated
evidence-transfer failures remain preserved. The dedicated VM is powered off with
network adapters and temporary attachments removed.
See the [retained failure record](../../docs/evidence/20260925-shuffle-restart-checkpoint.json).

## What this folder proves

- `handoff_contract.py`: offline validation and idempotency decisions for one
  synthetic BetTail/lab review request. No task is created.
- `workflow-plan.json`: design only; it is not an importable native workflow.
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

Only the dedicated VM's disposable Docker daemon may support Shuffle execution.
No personal Docker socket, host folders, production data or shared credentials
enter it. The approved envelope is 8 GiB RAM, four CPUs, a 60 GiB virtual disk,
8 GiB staging and at least 25 GiB host free space. Recheck actual capacity before
use. Networking is limited to reviewed acquisition; remove NICs before workflows.

The reviewed upstream deployment grants backend/Orborus Docker authority. That
can create privileged workloads and host mounts, so a socket proxy or an isolated
web page alone cannot establish the required boundary. Dynamic worker limits,
compatible pinned components, actual app/action IDs, a scoped receiver and task
model, and genuine execution/recovery evidence remain unverified.
[Reviewed Compose](https://github.com/Shuffle/Shuffle/blob/a106f27312bbb81791a33dfee585a6b8d0ad3289/docker-compose.yml),
[Docker daemon trust](https://docs.docker.com/engine/security/#docker-daemon-attack-surface).
