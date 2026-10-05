"""Run one native Shuffle workflow in the dedicated network-less VirtualBox guest.

Builds a cidata seed ISO (guest script, cloud-init and a hashed payload), checks
the VM is powered off with every network adapter absent, boots it headless,
reads bounded JSON lines from its second serial port and confirms power-off.
Nothing is downloaded and no host folder is shared. The guest's own claims are
recorded as such; they are not independent attestation.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LAB = Path(__file__).resolve().parent
VM = "0f459824-652e-4645-9a1f-c46251ff90ee"
VBOX = Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
DOCKER = Path(r"C:\Users\agarw\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe")
STAGING = Path(r"C:\Users\agarw\SignalBridgeLabs\shuffle-lab\staging")
PYTHON_IMAGE = "python@sha256:7bf6c3111fe094f8ee1a1cbcdc63c4cfb345b0e3df42d5aa9a90b3b4b022ab6d"
HTTP_IMAGE = (
    "frikky/shuffle@sha256:4c5b6a0b44890ddc227a3ded9fee09f216dddd268ee0acc33e31dfa95fa724fb"
)
OPENSEARCH_IMAGE = "opensearchproject/opensearch@sha256:68a688de28fb9bb66601552650b91a52a9fd5e7eac5481dd2b225ecb66fd09b0"
WHEELS = ROOT / "var/enterprise/runs/b8667b816ce8419da7f3d5d9ac9d6ad6/wheels"
PURE_WHEELS = ("django-5.2.17", "asgiref-3.12.1", "sqlparse-0.6.0", "tzdata-2026.4")
SOURCE_DIRS = (
    "bridge",
    "config",
    "integrations",
    "scripts",
    "reference_lab",
    "templates",
    "static",
)
RUN_SECONDS = 1800
BOOT_SECONDS = 300
BOOT_ATTEMPTS = 3
BOOT_DISK = "ubuntu-noble-24.04-cloudimg.vdi"
MIN_FREE = 25 * 1024**3


class HostError(RuntimeError):
    """Closed codes only."""


def require(condition, code):
    if not condition:
        raise HostError(code)


def vbox(*args, timeout=60):
    result = subprocess.run(
        [str(VBOX), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    require(result.returncode == 0, "vbox_" + args[0])
    return result.stdout


def vm_info():
    rows = {}
    for line in vbox("showvminfo", VM, "--machinereadable").splitlines():
        key, _, value = line.partition("=")
        rows[key.strip('"')] = value.strip('"')
    return rows


def assert_isolated(info, state):
    require(info.get("VMState") == state, "vm_state_" + info.get("VMState", "unknown"))
    require(all(info.get(f"nic{n}") == "none" for n in range(1, 9)), "vm_network_adapter_present")
    require(not any(k.startswith("SharedFolder") for k in info), "vm_shared_folder_present")


def assert_boot_disk(info):
    """Root disk on the AHCI controller: under Hyper-V the LSI Logic one stalled the boot."""
    controllers = {
        info.get(f"storagecontrollername{n}"): info.get(f"storagecontrollertype{n}")
        for n in range(8)
    }
    require(controllers.get("SATA") == "IntelAhci", "vm_boot_disk_controller")
    require(info.get("SATA-0-0", "").endswith(BOOT_DISK), "vm_boot_disk")


def docker_output(*args):
    result = subprocess.run(
        [str(DOCKER), *args],
        capture_output=True,
        timeout=300,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    require(result.returncode == 0 and result.stdout, "docker_" + args[0])
    return result.stdout


def build_payload(work, run):
    payload = work / "payload"
    for name in SOURCE_DIRS:
        shutil.copytree(
            ROOT / name,
            payload / "src" / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "node_modules"),
        )
    shutil.copy2(ROOT / "manage.py", payload / "src" / "manage.py")
    (payload / "src" / "var").mkdir()
    for prefix in PURE_WHEELS:
        wheel = next(WHEELS.glob(prefix + "-*.whl"))
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(payload / "site")
    # Offline app definition: reviewed api.yaml/Dockerfile plus the pinned image's own code.
    app = payload / "apps/http/1.4.0"
    (app / "src").mkdir(parents=True)
    for name in ("api.yaml", "Dockerfile"):
        shutil.copy2(LAB / "http-app" / name, app / name)
    (app / "src/app.py").write_bytes(
        docker_output(
            "run", "--rm", "--network", "none", "--entrypoint", "cat", HTTP_IMAGE, "/app/app.py"
        )
    )
    (payload / "opensearch").mkdir()
    shutil.copy2(LAB / "opensearch.yml", payload / "opensearch/opensearch.yml")
    # A fresh keystore: the reviewed profile mounts config read-only, so it is created here.
    (payload / "opensearch/opensearch.keystore").write_bytes(
        docker_output(
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "1000:1000",
            "--entrypoint",
            "sh",
            OPENSEARCH_IMAGE,
            "-c",
            "cp -r /usr/share/opensearch/config /tmp/c && "
            "OPENSEARCH_PATH_CONF=/tmp/c /usr/share/opensearch/bin/opensearch-keystore create "
            ">/dev/null 2>&1 && cat /tmp/c/opensearch.keystore",
        )
    )
    image = payload / "python-image.tar"
    subprocess.run(
        [str(DOCKER), "save", "-o", str(image), PYTHON_IMAGE],
        check=True,
        timeout=600,
        capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    seed = work / "seed"
    seed.mkdir()
    archive = seed / "payload.tar"
    with tarfile.open(archive, "w") as bundle:
        for item in sorted(payload.iterdir()):
            bundle.add(item, arcname=item.name)
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    manifest = {"run_id": run, "payload_sha256": digest.hexdigest()}
    (seed / "payload.json").write_text(json.dumps(manifest) + "\n", encoding="ascii")
    guest = (LAB / "guest_workflow.py").read_bytes()
    (seed / "guest_workflow.py").write_bytes(guest)
    (seed / "meta-data").write_text(
        f"instance-id: signalbridge-shuffle-workflow-{run}\nlocal-hostname: signalbridge-shuffle-lab\n",
        encoding="ascii",
    )
    (seed / "user-data").write_text(USER_DATA, encoding="ascii")
    shutil.rmtree(payload)
    return seed, manifest, hashlib.sha256(guest).hexdigest()


USER_DATA = """#cloud-config
package_update: false
package_upgrade: false
package_reboot_if_required: false
network:
  config: disabled
bootcmd:
  - ['/usr/bin/systemctl', 'mask', '--now', 'serial-getty@ttyS1.service']
  - ['/usr/bin/systemctl', 'mask', '--now', 'ssh.service', 'ssh.socket']
write_files:
  - path: /etc/systemd/system/signalbridge-shuffle-workflow.service
    owner: root:root
    permissions: '0600'
    content: |
      [Unit]
      Description=One bounded offline SignalBridge Shuffle workflow run
      After=cloud-final.service
      [Service]
      Type=oneshot
      ExecStartPre=/usr/bin/mkdir -p /mnt/signalbridge-seed
      ExecStartPre=/usr/bin/mount -o ro /dev/sr0 /mnt/signalbridge-seed
      ExecStart=/usr/bin/python3 -I -B /mnt/signalbridge-seed/guest_workflow.py
      ExecStopPost=/usr/bin/systemctl --no-block poweroff
      TimeoutStartSec=1620
      TimeoutStopSec=20
      KillMode=control-group
      Restart=no
runcmd:
  - ['/usr/bin/systemctl', 'unmask', 'docker.service', 'docker.socket', 'containerd.service']
  - ['/usr/bin/systemctl', 'daemon-reload']
  - ['/usr/bin/systemctl', 'start', '--no-block', 'signalbridge-shuffle-workflow.service']
"""


SERIAL_LIMIT = 128 * 1024


def parse_serial(raw):
    """Bounded JSON records from the guest's second serial port; other bytes ignored."""
    rows = []
    for line in raw[:SERIAL_LIMIT].split(b"\n"):
        line = line.strip().lstrip(b"\x00")
        if line.startswith(b"{"):
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    return rows


def dispatcher_record(rows):
    """The dispatcher summary with its per-scenario lines reassembled."""
    head = next((v for v in rows if v.get("kind") == "dispatcher"), None)
    if head is None:
        return None
    scenarios = {
        v["name"]: {k: x for k, x in v.items() if k not in ("kind", "name")}
        for v in rows
        if v.get("kind") == "scenario" and isinstance(v.get("name"), str)
    }
    return {k: v for k, v in head.items() if k != "kind"} | {"scenarios": scenarios}


def read_serial(path, lines, done):
    """VirtualBox writes UART2 to a file; poll it until the end record or a stop."""
    while not done.is_set():
        try:
            raw = path.read_bytes() if path.exists() else b""
        except OSError:
            raw = b""
        rows = parse_serial(raw)
        lines[:] = rows
        if any(row.get("kind") == "end" for row in rows) or len(raw) >= SERIAL_LIMIT:
            done.set()
            return
        done.wait(2)


def boot(lines, done, receipt):
    """Start the guest; a boot that never sends "started" is powered off and retried.

    Under Hyper-V, VirtualBox intermittently freezes the guest's timer clock early in boot
    (a CPU spins waiting for time to advance). The stall happens before cloud-init runs,
    so a hard power-off and a fresh boot of the same seed are safe.
    """
    for attempt in range(1, BOOT_ATTEMPTS + 1):
        receipt["boot_attempts"] = attempt
        vbox("startvm", VM, "--type", "headless", timeout=120)
        deadline = time.monotonic() + BOOT_SECONDS
        while not lines and not done.is_set() and time.monotonic() < deadline:
            done.wait(5)
        if lines:
            return
        vbox("controlvm", VM, "poweroff")
        until = time.monotonic() + 60
        while vm_info().get("VMState") != "poweroff" and time.monotonic() < until:
            time.sleep(2)
        assert_isolated(vm_info(), "poweroff")
    raise HostError("guest_not_started")


def main():
    require(sys.platform == "win32", "windows_host_required")
    require(shutil.disk_usage("C:\\").free >= MIN_FREE + 2 * 1024**3, "host_disk_floor")
    run = str(uuid.uuid4())
    work = STAGING / ("workflow-" + run)
    work.mkdir(parents=False, exist_ok=False)
    started = datetime.now(timezone.utc)
    receipt = {
        "schema_version": 1,
        "kind": "signalbridge-shuffle-native-workflow",
        "run_id": run,
        "started_at": started.isoformat(),
        "status": "incomplete",
        "limits": [
            "Synthetic data in a dedicated network-less guest whose disk persists; this workflow's "
            "own leftovers from earlier runs are removed first. One fixed workflow and one HTTP action.",
            "Guest-reported results are builder-controlled observations, not independent attestation.",
            "The Docker socket is available only to Shuffle components inside this guest.",
        ],
    }
    attached = started_vm = False
    serial_file = None
    lines = []
    try:
        info = vm_info()
        assert_isolated(info, "poweroff")
        assert_boot_disk(info)
        seed, manifest, guest_sha = build_payload(work, run)
        receipt.update(payload_sha256=manifest["payload_sha256"], guest_script_sha256=guest_sha)
        iso = work / "seed.iso"
        out = subprocess.run(
            [
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(LAB / "build-seed-iso.ps1"),
                "-SeedDirectory",
                str(seed),
                "-IsoPath",
                str(iso),
            ],
            capture_output=True,
            text=True,
            timeout=600,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        require(out.returncode == 0 and iso.is_file(), "seed_iso")
        receipt["seed_iso_bytes"] = iso.stat().st_size
        serial_file = work / "serial.log"
        vbox(
            "storageattach",
            VM,
            "--storagectl",
            "IDE",
            "--port",
            "0",
            "--device",
            "0",
            "--type",
            "dvddrive",
            "--medium",
            str(iso),
        )
        attached = True
        vbox("modifyvm", VM, "--uart2", "0x2F8", "3", "--uartmode2", "file", str(serial_file))
        assert_isolated(vm_info(), "poweroff")
        done = threading.Event()
        reader = threading.Thread(target=read_serial, args=(serial_file, lines, done), daemon=True)
        reader.start()
        started_vm = True
        boot(lines, done, receipt)
        done.wait(RUN_SECONDS)
        summary = next((v for v in lines if v.get("kind") == "summary"), None)
        receipt["guest"] = summary
        receipt["dispatcher"] = dispatcher_record(lines)
        receipt["diagnostics"] = [
            v for v in lines if v.get("kind") in ("log", "containers", "truncated")
        ]
        receipt["end_record_received"] = any(v.get("kind") == "end" for v in lines)
    except Exception as error:
        receipt["error"] = str(error) if isinstance(error, HostError) else type(error).__name__
    finally:
        if started_vm:
            # A guest that never started cannot power itself off; do not wait for it.
            deadline = time.monotonic() + (240 if lines else 0)
            while time.monotonic() < deadline and vm_info().get("VMState") not in (
                "poweroff",
                "aborted",
            ):
                time.sleep(3)
            if vm_info().get("VMState") not in ("poweroff", "aborted"):
                try:
                    vbox("controlvm", VM, "acpipowerbutton")
                    time.sleep(60)
                except HostError:
                    pass
            if vm_info().get("VMState") not in ("poweroff", "aborted"):
                vbox("controlvm", VM, "poweroff")
                time.sleep(5)
        # The guest may finish after the reader's deadline: read the whole record once more.
        if serial_file is not None and serial_file.exists():
            final = parse_serial(serial_file.read_bytes())
            receipt["guest"] = next((v for v in final if v.get("kind") == "summary"), None)
            receipt["dispatcher"] = dispatcher_record(final)
            receipt["diagnostics"] = [
                v for v in final if v.get("kind") in ("log", "containers", "truncated")
            ]
            receipt["end_record_received"] = any(v.get("kind") == "end" for v in final)
            receipt["guest_started"] = any(v.get("kind") == "started" for v in final)
        try:
            vbox("modifyvm", VM, "--uart2", "off")
            if attached:
                vbox(
                    "storageattach",
                    VM,
                    "--storagectl",
                    "IDE",
                    "--port",
                    "0",
                    "--device",
                    "0",
                    "--type",
                    "dvddrive",
                    "--medium",
                    "none",
                )
            final = vm_info()
            assert_isolated(final, "poweroff")
            receipt["shutdown_verified"] = True
        except Exception as error:
            receipt["shutdown_verified"] = False
            receipt["shutdown_error"] = type(error).__name__
        receipt["finished_at"] = datetime.now(timezone.utc).isoformat()
        guest = receipt.get("guest") or {}
        receipt["status"] = (
            "guest_completed_pending_review"
            if guest.get("status") == "completed" and receipt.get("shutdown_verified")
            else "incomplete"
        )
        raw = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("ascii")
        (work / "receipt.json").write_bytes(raw)
        print(json.dumps({"status": receipt["status"], "receipt": str(work / "receipt.json")}))
    return 0 if receipt["status"] != "incomplete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
