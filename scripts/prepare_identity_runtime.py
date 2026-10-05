"""Execute only the separately approved optional Windows identity dependency stage.

Uses official hash-pinned wheels, four retained caches, and one new private venv.
Never changes an existing environment, starts a listener/container, or deletes data.
No action occurs on import. --inspect validates local metadata without downloading.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import ssl
import stat
import subprocess
import sys
import time
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "integrations/identity/dependency-stage.json"
LOCK = ROOT / "integrations/identity/windows-cp314-requirements.lock"
GIB = 1024**3


def require(condition):
    if not condition:
        raise ValueError("Reviewed identity stage control failed.")


def reviewed_plan():
    plan = json.loads(PLAN.read_bytes())
    rows = plan["wheels"]
    require(len(rows) == 14 and len({r["filename"] for r in rows}) == 14)
    expected = []
    for row in rows:
        require(re.fullmatch(r"[A-Za-z0-9_.-]+\.whl", row["filename"]))
        require(re.fullmatch(r"[a-f0-9]{64}", row["sha256"]))
        require(type(row["size"]) is int and 0 < row["size"] <= 9 * 1024**2)
        require(
            re.fullmatch(
                r"https://files\.pythonhosted\.org/packages/[a-f0-9/]+/"
                + re.escape(row["filename"]),
                row["url"],
            )
        )
        require(row["source"] in {"reviewed_download", "retained_cache"})
        expected.append(f"{row['name']}=={row['version']} --hash=sha256:{row['sha256']}")
    actual = [line for line in LOCK.read_text().splitlines() if line and not line.startswith("#")]
    require(actual == expected)
    downloads = [r for r in rows if r["source"] == "reviewed_download"]
    require(len(downloads) == 10 and sum(r["size"] for r in downloads) == 4895036)
    require(plan["limits"]["download_ceiling_bytes"] == 8 * 1024**2)
    require(plan["limits"]["workspace_growth_ceiling_bytes"] == GIB)
    require(plan["limits"]["minimum_free_disk_bytes"] == 25 * GIB)
    return plan


def plain(path):
    path = Path(path)
    require(path.is_relative_to(ROOT))
    for item in (path, *path.parents):
        if item == ROOT:
            break
        if item.exists() or item.is_symlink():
            require(
                not item.is_symlink() and not getattr(item.lstat(), "st_file_attributes", 0) & 0x400
            )
    return path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def checked_wheel(path, row):
    plain(path)
    require(path.is_file() and path.stat().st_size == row["size"])
    require(hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"])
    expanded = 0
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(len(entries) <= 10000)
        seen = set()
        for entry in entries:
            name = PurePosixPath(entry.filename)
            require(
                not name.is_absolute()
                and ".." not in name.parts
                and "\\" not in entry.filename
                and ":" not in entry.filename
            )
            require(not stat.S_ISLNK(entry.external_attr >> 16) and not entry.flag_bits & 1)
            require(
                name.suffix.lower() != ".pth"
                and name.name.lower() not in {"sitecustomize.py", "usercustomize.py"}
            )
            folded = entry.filename.casefold()
            require(folded not in seen)
            seen.add(folded)
            expanded += entry.file_size
            require(expanded <= 100 * 1024**2)
    return expanded


def stage(approval):
    require(sys.platform == "win32" and sys.version_info[:3] == (3, 14, 4))
    require(platform.machine() == "AMD64" and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", approval))
    plan = reviewed_plan()
    baseline, deadline = shutil.disk_usage(ROOT).free, time.monotonic() + 600

    def guard():
        free = shutil.disk_usage(ROOT).free
        require(time.monotonic() < deadline and free >= 25 * GIB and baseline - free <= GIB)

    guard()
    run = uuid.uuid4().hex
    directory = plain(ROOT / "var/enterprise/identity" / run)
    directory.mkdir(parents=True, exist_ok=False)
    wheels = directory / "wheels"
    wheels.mkdir()
    receipt = {
        "schema_version": 1,
        "kind": "signalbridge-isolated-identity-dependencies",
        "run_id": run,
        "approval_reference": approval,
        "passed": False,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "plan_sha256": hashlib.sha256(PLAN.read_bytes()).hexdigest(),
        "lock_sha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
        "free_disk_before_bytes": baseline,
        "downloaded_bytes": 0,
        "phase": "acquire",
        "limits": "Dependency installation only; no Keycloak, login endpoint, SSO/MFA or native protocol acceptance.",
    }
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        footprint = 0
        for row in plan["wheels"]:
            guard()
            target = wheels / row["filename"]
            if row["source"] == "retained_cache":
                original = plain(ROOT / row["cache_relative_path"])
                require(original.name == row["filename"])
                checked_wheel(original, row)
                shutil.copyfile(original, target)
            else:
                request_deadline = min(deadline, time.monotonic() + 20)
                with opener.open(row["url"], timeout=5) as reply, target.open("xb") as output:
                    require(reply.status == 200 and reply.geturl() == row["url"])
                    require(reply.headers.get("Content-Length") == str(row["size"]))
                    count = 0
                    while True:
                        guard()
                        require(time.monotonic() < request_deadline)
                        chunk = reply.read(65536)
                        if not chunk:
                            break
                        count += len(chunk)
                        receipt["downloaded_bytes"] += len(chunk)
                        require(count <= row["size"] and receipt["downloaded_bytes"] <= 8 * 1024**2)
                        output.write(chunk)
            footprint += checked_wheel(target, row)
            require(footprint <= 100 * 1024**2)
        receipt["unpacked_wheel_bytes"] = footprint
        environment = {
            k: v
            for k, v in os.environ.items()
            if k.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "LOCALAPPDATA"}
        }
        environment.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1", PIP_CONFIG_FILE=os.devnull)

        def invoke(arguments, phase):
            guard()
            receipt["phase"] = phase
            result = subprocess.run(
                [str(v) for v in arguments],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=min(120, max(1, deadline - time.monotonic())),
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            (directory / (phase + ".log")).write_bytes(result.stdout + result.stderr)
            guard()
            require(result.returncode == 0)
            return result.stdout

        venv = directory / "venv"
        invoke([sys.executable, "-I", "-m", "venv", str(venv)], "create_venv")
        python = venv / "Scripts/python.exe"
        # Recheck all input hashes immediately before the isolated offline install.
        require(hashlib.sha256(LOCK.read_bytes()).hexdigest() == receipt["lock_sha256"])
        for row in plan["wheels"]:
            checked_wheel(wheels / row["filename"], row)
        invoke(
            [
                python,
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
                "--find-links",
                wheels,
                "-r",
                LOCK,
            ],
            "install",
        )
        invoke([python, "-I", "-m", "pip", "check"], "dependency_closure")
        raw = invoke(
            [
                python,
                "-I",
                "-c",
                "import json,importlib.metadata as m; print(json.dumps({d.metadata['Name'].lower(): d.version for d in m.distributions()}))",
            ],
            "versions",
        )
        versions = json.loads(raw)
        require(all(versions.get(row["name"].lower()) == row["version"] for row in plan["wheels"]))
        receipt.update(
            passed=True,
            versions=versions,
            runtime_relative_path=python.relative_to(ROOT).as_posix(),
        )
    except Exception as error:
        receipt["error_class"] = type(error).__name__
    finally:
        receipt.update(
            finished_at=datetime.now(timezone.utc).isoformat(),
            free_disk_after_bytes=shutil.disk_usage(ROOT).free,
        )
        raw = (json.dumps(receipt, indent=2) + "\n").encode("utf-8")
        (directory / "receipt.json").write_bytes(raw)
        output = (
            ROOT
            / "docs/evidence"
            / (
                datetime.now(timezone.utc).strftime("%Y%m%d")
                + "-identity-dependencies-"
                + run
                + ".json"
            )
        )
        with output.open("xb") as stream:
            stream.write(raw)
        print("Identity dependency receipt: " + output.relative_to(ROOT).as_posix())
    return 0 if receipt["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--inspect", action="store_true")
    group.add_argument(
        "--approved-stage", help="Audit reference; never grants authorization itself."
    )
    options = parser.parse_args()
    if options.inspect:
        plan = reviewed_plan()
        print(
            json.dumps(
                {
                    "wheel_count": len(plan["wheels"]),
                    "new_download_bytes": 4895036,
                    "new_environment_created": False,
                }
            )
        )
        return 0
    return stage(options.approved_stage)


if __name__ == "__main__":
    raise SystemExit(main())
