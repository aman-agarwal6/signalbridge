"""Fixed native test entry point; install reviewed wheels only into bounded tmpfs."""

import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/workspace")
OUTPUT = Path("/evidence")
DEPENDENCIES = Path("/opt/verification-deps")
RUNTIME = DEPENDENCIES / "runtime"


def verify_kernel_mounts(text):
    """Inspect fixed mounts only; Docker configuration is not kernel enforcement."""
    expected = {"/tmp": True, DEPENDENCIES.as_posix(): False}
    retained = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or fields[4] not in expected or "-" not in fields:
            continue
        separator = fields.index("-")
        if separator + 3 >= len(fields):
            raise RuntimeError("Malformed kernel mount evidence.")
        options = set(fields[5].split(","))
        if (
            fields[separator + 1] != "tmpfs"
            or not {"rw", "nosuid", "nodev"}.issubset(options)
            or ("noexec" in options) != expected[fields[4]]
            or fields[4] in retained
        ):
            raise RuntimeError("Kernel temporary storage differs from the reviewed profile.")
        retained[fields[4]] = {"filesystem": "tmpfs", "noexec": "noexec" in options}
    if set(retained) != set(expected):
        raise RuntimeError("Required kernel temporary mounts are missing.")
    return retained


def main():
    if sys.platform != "linux" or sys.version_info[:2] != (3, 14):
        raise RuntimeError("The reviewed wheel profile requires Linux CPython 3.14.")
    started = time.monotonic()
    gate = OUTPUT / "allow-tests.json"
    deadline = time.monotonic() + 30
    while not gate.exists() and time.monotonic() < deadline:
        time.sleep(0.2)
    if not gate.exists() or json.loads(gate.read_text(encoding="utf8")) != {
        "run_id": os.environ.get("SB_VERIFY_RUN"),
        "runtime_verified": True,
    }:
        raise RuntimeError("The host did not verify effective native isolation before testing.")
    mounts = verify_kernel_mounts(Path("/proc/self/mountinfo").read_text(encoding="ascii"))
    (OUTPUT / "kernel-mounts.json").write_text(json.dumps(mounts, indent=2) + "\n")
    environment = os.environ.copy()
    environment.update(SB_SECRET_KEY=secrets.token_urlsafe(64), PYTHONDONTWRITEBYTECODE="1")
    # pip stages a target installation before moving its files. Keep staging on
    # the same dependency filesystem and disable optional bytecode generation.
    temporary = DEPENDENCIES / "install-tmp"
    temporary.mkdir(mode=0o700, exist_ok=False)
    environment["TMPDIR"] = str(temporary)
    install = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "--isolated",
            "install",
            "--no-index",
            "--no-deps",
            "--no-cache-dir",
            "--no-compile",
            "--only-binary=:all:",
            "--require-hashes",
            "--find-links=/wheels",
            "--target=" + str(RUNTIME),
            "-r",
            str(ROOT / "integrations/enterprise/runner-requirements.lock"),
        ],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=120,
    )
    (OUTPUT / "install.log").write_bytes(install.stdout + install.stderr)
    if install.returncode:
        raise RuntimeError("Offline dependency installation failed.")
    environment["PYTHONPATH"] = str(RUNTIME) + ":/workspace"
    command = [
        sys.executable,
        "-B",
        "manage.py",
        "test",
        "tests.test_postgres_processing",
        "tests.test_postgres_cases",
        "--settings",
        "config.in_network_postgres_settings",
        "--noinput",
        "--verbosity",
        "1",
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=240,
    )
    secret = Path("/run/secrets/verifier_password").read_bytes()
    raw = (result.stdout + result.stderr).replace(secret, b"[REDACTED]")
    raw = raw.replace(environment["SB_SECRET_KEY"].encode(), b"[REDACTED]")
    (OUTPUT / "postgres-tests.log").write_bytes(raw)
    # Keep the final acceptance decision outside the container, against its raw log.
    (OUTPUT / "runner.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "test_exit_code": result.returncode,
                "duration_seconds": round(time.monotonic() - started, 3),
                "python_version": sys.version.split()[0],
                "log_sha256": hashlib.sha256(raw).hexdigest(),
            },
            indent=2,
        )
        + "\n",
        encoding="utf8",
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
