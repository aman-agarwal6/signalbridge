#!/usr/bin/python3
"""One native Shuffle workflow run inside the dedicated, network-less Ubuntu guest.

Started once by the seed's systemd unit. It unpacks the reviewed payload from the
seed ISO, starts the pinned Shuffle components, the disposable SignalBridge
receiver and the dispatcher on a guest-internal Docker network, records the
outcome as bounded JSON lines on the second serial port, and powers off.
The Docker socket exists only inside this disposable guest. No host folders,
network adapters, downloads or shared credentials are used.
"""

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tarfile
import termios
import time
import uuid
from pathlib import Path

SEED = Path("/mnt/signalbridge-seed")
WORK = Path("/root/signalbridge-shuffle")
NETWORK = "shuffle_shuffle"
DEADLINE = time.monotonic() + 1500
ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "DOCKER_HOST": "unix:///var/run/docker.sock",
}
IMAGES = {
    "backend": "ghcr.io/shuffle/shuffle-backend@sha256:0cc1775e48b7d94b7f16d0be713aa274ced52be24ad521beaaf58c67023fd2e5",
    "worker": "ghcr.io/shuffle/shuffle-worker@sha256:9541c1fef2bc8511727610b565adbd0f7c817c53afee2dd9fef6aad8a971ffb1",
    "orborus": "ghcr.io/shuffle/shuffle-orborus@sha256:3519810b3ca4fe568acefdf15ce6f2deba0ae6f0ff6b84412354d59d663dff31",
    "http": "frikky/shuffle@sha256:4c5b6a0b44890ddc227a3ded9fee09f216dddd268ee0acc33e31dfa95fa724fb",
    "opensearch": "opensearchproject/opensearch@sha256:68a688de28fb9bb66601552650b91a52a9fd5e7eac5481dd2b225ecb66fd09b0",
    "python": "python@sha256:7bf6c3111fe094f8ee1a1cbcdc63c4cfb345b0e3df42d5aa9a90b3b4b022ab6d",
}
TAGS = {
    "http": "frikky/shuffle:http_1.4.0",
    "worker": "ghcr.io/shuffle/shuffle-worker:latest",
}
# The receiver image is side-loaded from the payload without a name, so it is found by its
# pinned digest (its ID in the containerd image store) and then given this local name.
PYTHON_ID = "sha256:" + IMAGES["python"].rpartition("@sha256:")[2]
PYTHON_TAG = "signalbridge-lab/receiver-python:pinned"
OWN_CONTAINERS = (
    "dispatcher",
    "shuffle-orborus",
    "signalbridge",
    "shuffle-backend",
    "shuffle-opensearch",
)
SERIAL_LINE = 1800
SERIAL_TOTAL = 48 * 1024
sent_bytes = 0


class GuestError(RuntimeError):
    """Closed codes only."""


def require(condition, code):
    if not condition:
        raise GuestError(code)


def remaining():
    left = DEADLINE - time.monotonic()
    require(left > 0, "guest_deadline")
    return left


def run(argv, timeout=120, check=True, stdin=None):
    result = subprocess.run(
        argv,
        input=stdin,
        capture_output=True,
        env=ENV,
        timeout=min(timeout, remaining()),
    )
    if check and result.returncode:
        raise GuestError("command_failed_" + re.sub(r"[^a-z0-9]+", "_", argv[1])[:24])
    return result


def docker(*args, timeout=120, check=True):
    return run(["/usr/bin/docker", *args], timeout=timeout, check=check)


def serial(value):
    """Bounded JSON lines on ttyS1; the host reads until the end record."""
    global sent_bytes
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(raw) > SERIAL_LINE or sent_bytes + len(raw) > SERIAL_TOTAL:
        raw = json.dumps({"kind": "truncated"}).encode() + b"\n"
    descriptor = os.open("/dev/ttyS1", os.O_WRONLY | os.O_NOCTTY)
    try:
        attrs = termios.tcgetattr(descriptor)
        attrs[0] = attrs[1] = attrs[3] = 0
        attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        attrs[4] = attrs[5] = termios.B115200
        termios.tcsetattr(descriptor, termios.TCSANOW, attrs)
        os.write(descriptor, raw)
        termios.tcdrain(descriptor)
    finally:
        os.close(descriptor)
    sent_bytes += len(raw)


def redact(text):
    """Remove credential-bearing lines' values before anything reaches the serial port."""
    return re.sub(
        r"(?i)(api ?key|authorization|password|bearer|token|secret)[^\n]*", r"\1 [removed]", text
    )


def tail(name, lines=12, keep=1000):
    """Last log lines of a lab container with credentials and tokens removed."""
    result = docker("logs", "--tail", str(lines), name, check=False, timeout=20)
    return redact((result.stdout + result.stderr).decode("utf8", "replace"))[-keep:]


def matching(name, pattern, exclude, lines=400, keep=1000):
    """Recent log lines of a container that match pattern and not exclude (noise)."""
    result = docker("logs", "--tail", str(lines), name, check=False, timeout=20)
    text = (result.stdout + result.stderr).decode("utf8", "replace")
    kept = [
        line
        for line in text.splitlines()
        if re.search(pattern, line) and not re.search(exclude, line)
    ]
    return redact("\n".join(kept))[-keep:]


def unpack():
    require(
        not any(n for n in os.listdir("/sys/class/net") if n.startswith(("en", "eth", "wl"))),
        "network_adapter_present",
    )
    SEED.mkdir(exist_ok=True)
    if not os.path.ismount(SEED):
        run(["/usr/bin/mount", "-o", "ro", "/dev/sr0", str(SEED)])
    manifest = json.loads((SEED / "payload.json").read_text())
    archive = SEED / "payload.tar"
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    require(digest.hexdigest() == manifest["payload_sha256"], "payload_digest")
    # The guest disk persists between runs; only this workflow's own folder is replaced.
    require(not WORK.is_symlink(), "work_symlink")
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(mode=0o700)
    with tarfile.open(archive) as bundle:
        for member in bundle.getmembers():
            target = (WORK / member.name).resolve()
            require(
                target.is_relative_to(WORK) and not member.issym() and not member.islnk(),
                "payload_member",
            )
        bundle.extractall(WORK, filter="data")
    return manifest


def start_images():
    run(["/usr/bin/systemctl", "start", "docker.service"], timeout=120)
    docker("load", "-i", str(WORK / "python-image.tar"), timeout=300)
    inventory = {}
    for name, reference in IMAGES.items():
        lookup = PYTHON_ID if name == "python" else reference
        result = docker("image", "inspect", lookup, "--format", "{{.Id}}", check=False, timeout=30)
        require(result.returncode == 0, "image_missing_" + name)
        inventory[name] = result.stdout.decode().strip()[:71]
    require(inventory["python"] == PYTHON_ID, "image_identity_python")
    docker("tag", PYTHON_ID, PYTHON_TAG)
    for name, tag in TAGS.items():
        docker("tag", IMAGES[name], tag)
    # Leftovers of an earlier run of this workflow only: its named containers, containers
    # Orborus started from the pinned worker/app images, and its network.
    leftovers = set(OWN_CONTAINERS)
    for reference in (IMAGES["worker"], IMAGES["http"]):
        listed = docker("ps", "-aq", "--filter", "ancestor=" + reference, check=False)
        leftovers.update(listed.stdout.decode().split())
    for container in sorted(leftovers):
        docker("rm", "-f", container, check=False, timeout=60)
    docker("network", "rm", NETWORK, check=False)
    docker("network", "create", "--internal", "--subnet", "10.213.0.0/24", NETWORK)
    return inventory


def wait_http(container, url, needle, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = docker("exec", container, "curl", "-s", "-m", "5", url, check=False, timeout=15)
        if needle in result.stdout:
            return True
        time.sleep(3)
    return False


def main():
    record = {"kind": "summary", "run": os.environ.get("SB_SHUFFLE_RUN", ""), "steps": {}}
    steps = record["steps"]
    try:
        # First record: lets the host stop a stalled boot early instead of waiting the full run.
        serial({"kind": "started"})
        manifest = unpack()
        record["run"] = manifest["run_id"]
        steps["payload"] = "verified"
        record["images"] = start_images()
        steps["images"] = "verified"
        shuffle_key, admin = str(uuid.uuid4()), secrets.token_urlsafe(24)
        receiver_env = {
            "SB_SECRET_KEY": secrets.token_urlsafe(60),
            "SB_SERVICE_SHUFFLE_READ": secrets.token_urlsafe(40),
            "SB_SERVICE_SHUFFLE_TASK": secrets.token_urlsafe(40),
        }
        common = [
            "--network",
            NETWORK,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--label",
            "org.signalbridge.scope=shuffle-guest",
        ]
        os_dir = WORK / "opensearch"
        docker(
            "run",
            "-d",
            "--name",
            "shuffle-opensearch",
            "--hostname",
            "shuffle-opensearch",
            *common,
            "--read-only",
            "--user",
            "1000:1000",
            "--memory",
            "3g",
            "--memory-swap",
            "3g",
            "--ulimit",
            "nofile=65536:65536",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=268435456,mode=1777",
            "--tmpfs",
            "/opt/os-tmp:rw,exec,nosuid,nodev,size=67108864,uid=1000,gid=1000,mode=0700",
            "--tmpfs",
            "/usr/share/opensearch/logs:rw,nosuid,nodev,noexec,size=67108864,uid=1000,gid=1000",
            "--tmpfs",
            "/usr/share/opensearch/data:rw,nosuid,nodev,size=1073741824,uid=1000,gid=1000",
            "-v",
            f"{os_dir}/opensearch.yml:/usr/share/opensearch/config/opensearch.yml:ro",
            "-v",
            f"{os_dir}/opensearch.keystore:/usr/share/opensearch/config/opensearch.keystore:ro",
            "-e",
            "OPENSEARCH_TMPDIR=/opt/os-tmp",
            "-e",
            "OPENSEARCH_JAVA_OPTS=-Xms768m -Xmx768m -Djava.io.tmpdir=/opt/os-tmp",
            "-e",
            "DISABLE_INSTALL_DEMO_CONFIG=true",
            "-e",
            "DISABLE_SECURITY_PLUGIN=true",
            "-e",
            "DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true",
            "--entrypoint",
            "/usr/share/opensearch/bin/opensearch",
            IMAGES["opensearch"],
        )
        require(
            wait_http(
                "shuffle-opensearch",
                "http://localhost:9200/_cluster/health",
                b'"status":"green"',
                180,
            ),
            "opensearch_not_green",
        )
        steps["opensearch"] = "green"
        docker(
            "run",
            "-d",
            "--name",
            "shuffle-backend",
            "--hostname",
            "shuffle-backend",
            *common,
            "--memory",
            "1g",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-v",
            f"{WORK}/apps:/shuffle-apps:ro",
            "--tmpfs",
            "/shuffle-files:rw,size=67108864",
            "-e",
            "BACKEND_HOSTNAME=shuffle-backend",
            "-e",
            "BACKEND_PORT=5001",
            "-e",
            "SHUFFLE_OPENSEARCH_URL=http://shuffle-opensearch:9200",
            "-e",
            "SHUFFLE_ELASTIC=true",
            "-e",
            "SHUFFLE_APP_HOTLOAD_FOLDER=/shuffle-apps",
            "-e",
            "SHUFFLE_APP_HOTLOAD_LOCATION=/shuffle-apps",
            "-e",
            "SHUFFLE_FILE_LOCATION=/shuffle-files",
            "-e",
            "SHUFFLE_APP_DOWNLOAD_LOCATION=",
            "-e",
            "SHUFFLE_DOWNLOAD_WORKFLOW_LOCATION=",
            "-e",
            "SHUFFLE_DOWNLOAD_AUTH_LOCATION=",
            "-e",
            "SHUFFLE_DEFAULT_USERNAME=lab-admin",
            "-e",
            "SHUFFLE_DEFAULT_PASSWORD=" + admin,
            "-e",
            "SHUFFLE_DEFAULT_APIKEY=" + shuffle_key,
            "-e",
            "SHUFFLE_ENCRYPTION_MODIFIER=" + secrets.token_hex(16),
            IMAGES["backend"],
        )
        deadline = time.monotonic() + 240
        while b"Finished INIT" not in (
            docker("logs", "shuffle-backend", check=False).stdout
            + docker("logs", "shuffle-backend", check=False).stderr
        ):
            require(time.monotonic() < deadline, "backend_init_deadline")
            time.sleep(5)
        steps["backend"] = "initialized"
        site, src = WORK / "site", WORK / "src"
        env_args = [arg for key, value in receiver_env.items() for arg in ("-e", f"{key}={value}")]
        docker(
            "run",
            "-d",
            "--name",
            "signalbridge",
            "--hostname",
            "signalbridge",
            *common,
            "--user",
            "10001:10001",
            "--read-only",
            "--memory",
            "512m",
            "--tmpfs",
            "/receiver:rw,size=67108864,uid=10001,gid=10001",
            "--tmpfs",
            "/tmp:rw,size=33554432",
            *env_args,
            "-e",
            "PYTHONPATH=/site:/src",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            "-e",
            "DJANGO_SETTINGS_MODULE=integrations.shuffle.lab.receiver_settings",
            "-v",
            f"{src}:/src:ro",
            "-v",
            f"{site}:/site:ro",
            "-w",
            "/src",
            "--entrypoint",
            "sh",
            PYTHON_TAG,
            "-c",
            "python3 -B integrations/shuffle/lab/receiver_seed.py > /receiver/seed.json && exec python3 -B manage.py runserver 0.0.0.0:8000 --noreload",
        )
        deadline = time.monotonic() + 120
        while docker(
            "exec", "signalbridge", "test", "-s", "/receiver/seed.json", check=False
        ).returncode:
            require(time.monotonic() < deadline, "receiver_seed_deadline")
            time.sleep(2)
        seed = docker("exec", "signalbridge", "cat", "/receiver/seed.json").stdout
        (WORK / "seed.json").write_bytes(seed)
        steps["receiver"] = "seeded"
        docker(
            "run",
            "-d",
            "--name",
            "shuffle-orborus",
            "--hostname",
            "shuffle-orborus",
            *common,
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            "-e",
            "SHUFFLE_APP_SDK_TIMEOUT=300",
            "-e",
            "ENVIRONMENT_NAME=Shuffle",
            "-e",
            "ORG_ID=Shuffle",
            "-e",
            "BASE_URL=http://shuffle-backend:5001",
            "-e",
            "DOCKER_API_VERSION=1.44",
            "-e",
            "SHUFFLE_STATS_DISABLED=true",
            "-e",
            "SHUFFLE_LOGS_DISABLED=true",
            # No SHUFFLE_SWARM_CONFIG: this single offline host is not a swarm manager, so
            # Orborus runs workers as plain containers that copy its network (shuffle_shuffle).
            "-e",
            "CLEANUP=false",
            "-e",
            "SHUFFLE_AUTO_IMAGE_DOWNLOAD=false",
            "-e",
            "SHUFFLE_WORKER_IMAGE=" + TAGS["worker"],
            IMAGES["orborus"],
        )
        steps["orborus"] = "started"
        result = docker(
            "run",
            "--rm",
            "--name",
            "dispatcher",
            "--hostname",
            "dispatcher",
            *common,
            "--read-only",
            "--tmpfs",
            "/tmp:rw,size=16777216",
            "-e",
            "SHUFFLE_APIKEY=" + shuffle_key,
            *[
                arg
                for key in ("SB_SERVICE_SHUFFLE_READ", "SB_SERVICE_SHUFFLE_TASK")
                for arg in ("-e", f"{key}={receiver_env[key]}")
            ],
            "-v",
            f"{src}/integrations/shuffle/lab:/lab:ro",
            "-v",
            f"{WORK}/seed.json:/seed.json:ro",
            "-w",
            "/lab",
            "--entrypoint",
            "python3",
            IMAGES["http"],
            "-B",
            "dispatcher.py",
            "/seed.json",
            timeout=900,
            check=False,
        )
        lines = result.stdout.decode("utf8", "replace").strip().splitlines()
        if result.returncode != 0 or not lines:
            record["dispatcher_output"] = redact(
                (result.stdout + result.stderr).decode("utf8", "replace")
            )[-1000:]
        require(result.returncode == 0 and lines, "dispatcher_failed")
        record["dispatcher"] = json.loads(lines[-1])
        steps["dispatcher"] = "completed"
        report = docker(
            "exec",
            "signalbridge",
            "python3",
            "-B",
            "manage.py",
            "shell",
            "-c",
            "import json;from bridge.models import CaseTask,ServiceRequest,ServiceNonce;"
            "print(json.dumps({'review_tasks':CaseTask.objects.filter(kind='review').count(),"
            "'idempotent_requests':ServiceRequest.objects.count(),'nonces':ServiceNonce.objects.count()}))",
            check=False,
        )
        record["receiver"] = json.loads(report.stdout.decode().strip().splitlines()[-1])
        record["containers_started_by_orborus"] = len(
            docker("ps", "-a", "--filter", "ancestor=" + TAGS["worker"], "--quiet").stdout.split()
        )
        record["status"] = "completed"
    except Exception as error:
        record["status"] = "failed"
        record["failure"] = str(error) if isinstance(error, GuestError) else type(error).__name__
    finally:
        try:
            output = record.pop("dispatcher_output", None)
            serial({k: v for k, v in record.items() if k != "dispatcher"})
            if "dispatcher" in record:
                # One line per scenario: the whole summary exceeds the serial line bound.
                dispatched = record["dispatcher"]
                head = {k: v for k, v in dispatched.items() if k != "scenarios"}
                serial({"kind": "dispatcher", **head})
                for name, row in (dispatched.get("scenarios") or {}).items():
                    serial({"kind": "scenario", "name": name, **row})
            if output is not None:
                serial({"kind": "log", "container": "dispatcher", "tail": output})
            if record.get("status") != "completed":
                noise = r"(?i)tenzir|datastore_category"
                for name, pattern in (
                    ("shuffle-backend", r"(?i)execut|workflow|orborus|worker|queue|error"),
                    ("shuffle-orborus", r"(?i)execut|worker|job|container|error|image"),
                ):
                    serial(
                        {"kind": "log", "container": name, "tail": matching(name, pattern, noise)}
                    )
                serial({"kind": "log", "container": "signalbridge", "tail": tail("signalbridge")})
                started = []
                for reference in (IMAGES["worker"], IMAGES["http"]):
                    listed = docker("ps", "-aq", "--filter", "ancestor=" + reference, check=False)
                    started.extend(listed.stdout.decode().split())
                for container in started[:3]:
                    serial(
                        {
                            "kind": "log",
                            "container": "started-" + container[:12],
                            "tail": tail(container, 30),
                        }
                    )
                listing = docker(
                    "ps", "-a", "--format", "{{.Names}} {{.Image}} {{.Status}}", check=False
                )
                serial({"kind": "containers", "list": listing.stdout.decode()[-1500:]})
        finally:
            docker("ps", "-aq", check=False)
            for container in docker("ps", "-q", check=False).stdout.decode().split():
                docker("stop", "-t", "5", container, check=False, timeout=30)
            run(
                ["/usr/bin/systemctl", "stop", "docker.service", "docker.socket"],
                check=False,
                timeout=60,
            )
            serial({"kind": "end", "docker_stopped": True})


if __name__ == "__main__":
    main()
