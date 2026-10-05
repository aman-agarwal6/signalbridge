"""Finite native identity runner; requires the separately reviewed Linux profile.

Dependencies install from hash-verified retained wheels only. No runtime egress,
image management, host trust changes or external accounts are supported here.
"""

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import traceback
import zipfile
from pathlib import Path, PurePosixPath

from .native_http import PROVIDER, Budget, NativeClient, check_abort, require
from .native_profile import load_profile

ROOT = Path("/workspace")
OUTPUT = Path("/evidence")
RUNTIME = Path("/opt/identity-deps/runtime")
CA = Path("/run/secrets/lab-ca.pem")


def install():
    manifest = json.loads((ROOT / "integrations/identity/linux-wheels.json").read_bytes())
    rows = manifest["wheels"]
    require(len(rows) == 16 and len({row["filename"] for row in rows}) == 16)
    lock = [row["name"] + "==" + row["version"] + " --hash=sha256:" + row["sha256"] for row in rows]
    require(
        (ROOT / "integrations/identity/linux-cp314-requirements.lock").read_text().splitlines()
        == lock
    )
    expanded = 0
    for row in rows:
        require(re.fullmatch(r"[A-Za-z0-9_.-]+\.whl", row["filename"]))
        wheel = Path("/wheels") / row["filename"]
        require(wheel.is_file() and not wheel.is_symlink() and wheel.stat().st_size == row["size"])
        require(hashlib.sha256(wheel.read_bytes()).hexdigest() == row["sha256"])
        with zipfile.ZipFile(wheel) as archive:
            entries, seen = archive.infolist(), set()
            require(len(entries) <= 20000)
            for entry in entries:
                path = PurePosixPath(entry.filename)
                require(
                    not path.is_absolute()
                    and ".." not in path.parts
                    and "\\" not in entry.filename
                    and ":" not in entry.filename
                )
                require(not stat.S_ISLNK(entry.external_attr >> 16) and not entry.flag_bits & 1)
                require(
                    path.suffix != ".pth"
                    and path.name not in {"sitecustomize.py", "usercustomize.py"}
                )
                require(entry.filename.casefold() not in seen)
                seen.add(entry.filename.casefold())
                expanded += entry.file_size
                require(expanded <= 100 * 1024**2)
    temporary = Path("/opt/identity-deps/install-tmp")
    temporary.mkdir(mode=0o700)
    environment = dict(
        os.environ, TMPDIR=str(temporary), PYTHONDONTWRITEBYTECODE="1", PIP_CONFIG_FILE="/dev/null"
    )
    result = subprocess.run(
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
            str(ROOT / "integrations/identity/linux-cp314-requirements.lock"),
        ],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=120,
    )
    require(result.returncode == 0)
    sys.path.insert(0, str(RUNTIME))
    os.environ["PYTHONPATH"] = str(RUNTIME) + ":/workspace"
    return {
        "wheel_count": len(rows),
        "expanded_bytes": expanded,
        "hashes_verified": True,
        "runtime_downloads": False,
    }


def failure_location(error):
    """Deepest identity-package frames: fixed source coordinates, never values."""
    frames = []
    for frame in traceback.extract_tb(error.__traceback__):
        path = Path(frame.filename)
        if path.parent.name == "identity" and path.parent.parent.name == "integrations":
            frames.append({"file": path.name, "line": frame.lineno, "function": frame.name})
    return frames[-3:]


def write(name, value):
    require(name in {"identity-progress", "identity-native", "identity-browser-ready"})
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")
    require(len(raw) <= 65536)
    target = OUTPUT / (name + ".json")
    temporary = OUTPUT / (name + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(raw)
    temporary.replace(target)


def main():
    receipt, child = {"passed": False, "native_keycloak": False, "server_stopped": False}, None
    try:
        require(sys.platform == "linux" and sys.version_info[:2] == (3, 14))
        require(os.getuid() == 10001 and os.getgid() == 10001)
        require(os.environ.get("SB_IDENTITY_NATIVE") == "1")
        require(not any(k.startswith("PG") and v for k, v in os.environ.items()))
        profile = load_profile("/run/secrets/identity-profile.json")
        require(profile["run_id"] == os.environ.get("SB_IDENTITY_RUN"))
        receipt["run_id"] = profile["run_id"]
        receipt["phase"] = "await_host_gate"
        check_abort()
        gate = OUTPUT / "allow-identity.json"
        # Allow bounded host running-state and actual kernel/mount inspection;
        # this wait makes no identity requests and remains abort-aware.
        deadline = time.monotonic() + 90
        while not gate.exists() and time.monotonic() < deadline:
            check_abort()
            time.sleep(0.2)
        check_abort()
        require(gate.is_file() and not gate.is_symlink() and gate.stat().st_size <= 1024)
        require(
            json.loads(gate.read_bytes()) == {"run_id": profile["run_id"], "runtime_verified": True}
        )
        check_abort()
        receipt["phase"] = "dependencies"
        receipt["dependencies"] = install()
        check_abort()
        os.environ["DJANGO_SETTINGS_MODULE"] = "integrations.identity.native_settings"
        import django

        django.setup()
        from .native_driver import exercise, provision
        from .protocol import _public_keys

        receipt["phase"] = "provider_readiness"
        public = ROOT / "var/enterprise/identity"
        public.mkdir(parents=True, exist_ok=False)
        shutil.copyfile(CA, public / "lab-ca.pem")
        provider = NativeClient(CA, Budget(seconds=180, requests=80))
        deadline = time.monotonic() + 180
        keys = None
        while time.monotonic() < deadline:
            check_abort()
            try:
                reply = provider.request(
                    "GET", PROVIDER + "/realms/signalbridge/protocol/openid-connect/certs"
                )
                require(reply.status == 200 and reply.content_type == "application/json")
                keys = _public_keys(json.loads(reply.body))
                break
            except (OSError, ValueError):
                time.sleep(2)
        require(keys is not None)
        check_abort()
        (public / "jwks.json").write_bytes((json.dumps(keys) + "\n").encode("ascii"))
        receipt["phase"] = "provision_console"
        cases = provision(profile)
        check_abort()
        # Private state mount: fixed route/status and rejection-class lines only.
        server_log = (ROOT / "var/console-server.log").open("xb")
        child = subprocess.Popen(
            [sys.executable, "-B", "-m", "integrations.identity.native_server"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=server_log,
            env=dict(os.environ),
        )
        server_log.close()
        console = NativeClient(CA, Budget(seconds=30, requests=20))
        deadline = time.monotonic() + 30
        ready = False
        while time.monotonic() < deadline:
            check_abort()
            require(child.poll() is None)
            try:
                ready = console.request("GET", "https://127.0.0.1:18842/login/").status == 200
                if ready:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(1)
        require(ready)
        check_abort()
        receipt["phase"] = "native_identity_controls"
        receipt["execution"] = exercise(
            profile,
            cases,
            CA,
            progress=lambda rows: write(
                "identity-progress",
                {"run_id": profile["run_id"], "completed_controls": rows, "complete": False},
            ),
        )
        check_abort()
        # The host starts the separately verified browser container only after
        # this signal; the console stays up until its result or the deadline.
        receipt["phase"] = "real_browser"
        write(
            "identity-browser-ready",
            {"run_id": profile["run_id"], "ready": True, "account": "reviewer"},
        )
        result, deadline = OUTPUT / "identity-browser.json", time.monotonic() + 300
        while not result.exists() and time.monotonic() < deadline:
            check_abort()
            require(child.poll() is None)
            time.sleep(1)
        require(result.is_file() and not result.is_symlink() and result.stat().st_size <= 65536)
        raw = result.read_bytes()
        browser = json.loads(raw)
        require(browser.get("passed") is True and browser.get("run_id") == profile["run_id"])
        receipt["browser"] = {"passed": True, "sha256": hashlib.sha256(raw).hexdigest()}
        check_abort()
        receipt["native_keycloak"] = True
        receipt["passed"] = True
        receipt["phase"] = "complete"
    except Exception as error:
        receipt["error_class"] = type(error).__name__
        receipt["failure_location"] = failure_location(error)
    finally:
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
            receipt["server_stopped"] = child.poll() is not None
        else:
            receipt["server_stopped"] = True
        receipt["passed"] = receipt["passed"] and receipt["server_stopped"]
        write("identity-native", receipt)
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
