"""Read one completed native source archive into bounded credential-free input.

No launch, network, package install, private-key read or console mutation. The
trusted operator's retained host receipt is necessary; hashes alone cannot prove
execution against a local administrator who fabricates an entire archive.
"""

from datetime import timedelta

from bridge.contract import timestamp
from integrations.enterprise.network_verification import wheel_expansion, wheel_manifest
from integrations.enterprise.reference_host_controls import same
from integrations.enterprise.reference_host_evidence import safe_path, validate_shutdown
from integrations.enterprise.verification import private_run_directory, validate_identity

from .capture import require
from .scanner_contract import digest, hex_value, validate_input
from .scanner_host_evidence import read_receipt
from .source_host_evidence import validate_native


def load_completed_source(workspace, run, manifest, *, now):
    validate_identity(run)
    directory = private_run_directory(workspace, run)
    receipt, receipt_hash, _ = read_receipt(directory / "receipt.json", directory, 262144)
    require(isinstance(receipt, dict))
    require(
        type(receipt.get("schema_version")) is int
        and receipt["schema_version"] == 1
        and receipt.get("kind") == "signalbridge-native-authenticated-header-capture"
        and receipt.get("run_id") == run
        and receipt.get("status") == "passed"
        and all(
            receipt.get(key) is True
            for key in (
                "acceptance_passed",
                "source_unchanged",
                "runtime_isolation_verified",
                "parsed_configuration_verified",
                "main_shutdown_verified",
                "independent_shutdown_verified",
            )
        )
        and type(receipt.get("runner_exit_code")) is int
        and receipt["runner_exit_code"] == 0
    )
    started, finished = timestamp(receipt.get("started_at")), timestamp(receipt.get("finished_at"))
    require(started < finished <= now and finished - started <= timedelta(minutes=30))
    require(isinstance(manifest, dict) and receipt.get("source_sha256") == manifest.get("sha256"))
    images = receipt.get("images")
    require(isinstance(images, dict) and set(images) == {"database", "runner"})
    for identity in images.values():
        require(isinstance(identity, str) and identity.startswith("sha256:"))
        hex_value(identity.removeprefix("sha256:"))
    wheels = safe_path(directory / "wheels", directory)
    rows = wheel_manifest()
    require(wheels.is_dir() and {p.name for p in wheels.iterdir()} == {r["filename"] for r in rows})
    for row in rows:
        path = safe_path(wheels / row["filename"], directory)
        require(path.is_file() and path.stat().st_size == row["size"])
    footprint = wheel_expansion(wheels)  # Verifies each exact cached wheel hash.
    preparation = receipt.get("preparation")
    require(isinstance(preparation, dict) and same(preparation.get("wheel_footprint"), footprint))
    proof = validate_native(workspace, run, manifest, footprint, now=finished)
    require(same(proof, receipt.get("native_proof")))
    require(same(proof["source_snapshot"], receipt.get("source_snapshot")))
    watchdog, _, _ = read_receipt(directory / "watchdog.json", directory, 4096)
    require(same(watchdog, receipt.get("independent_shutdown")))
    shutdown = validate_shutdown(
        receipt.get("main_shutdown"), watchdog, run, started=started, finished=finished
    )
    execution, _, _ = read_receipt(directory / "evidence/header-execution.json", directory, 262144)
    captures, _, _ = read_receipt(directory / "evidence/source-captures.json", directory, 262144)
    value = {
        "schema_version": 1,
        "profile": execution["profile"],
        "source_run_id": run,
        "source_receipt_sha256": receipt_hash,
        "source_sha256": manifest["sha256"],
        "capture_sha256": digest(captures),
        "execution_sha256": digest(execution),
        "execution": execution,
        "phases": captures,
    }
    validate_input(value, now=now)
    return value, {
        "source_host_receipt_revalidated": True,
        "source_run_id": run,
        "source_receipt_sha256": receipt_hash,
        "source_sha256": manifest["sha256"],
        "source_finished_at": finished.isoformat(),
        "input_sha256": digest(value),
        **shutdown,
        "native_zap_executed": False,
        "assurance_limit": "Retained trusted-operator execution records; not independent attestation against an administrator.",
    }
