"""Portable developer commands. Run with SignalBridge's virtual-environment Python."""

import argparse
import errno
import http.client
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.runtime_identity import runtime_file, workspace_id
from scripts.record_verification import NODE_TEST_TARGETS

MIN_NODE_MAJOR = 24
HEALTH_URL = "http://127.0.0.1:8741/health/"
MAX_HEALTH_BYTES = 4096
HEALTH_TIMEOUT_SECONDS = 3


def local_environment():
    """The convenience launcher is the native SQLite path, never a hosted DB selector."""
    if (
        os.environ.get("SB_MODE", "local") != "local"
        or any(value for name, value in os.environ.items() if name.startswith("SB_DB_"))
        or os.environ.get("DJANGO_SETTINGS_MODULE", "config.settings") != "config.settings"
        or os.environ.get("SB_PORT", "8741") != "8741"
    ):
        raise SystemExit(
            "This convenience command requires local SQLite mode and port 8741. "
            "Clear SB_MODE/SB_DB_*/SB_PORT or custom DJANGO_SETTINGS_MODULE overrides in this "
            "terminal before retrying. Use the separate reviewed runbook for PostgreSQL."
        )
    env = os.environ.copy()
    env.update(SB_MODE="local", DJANGO_SETTINGS_MODULE="config.settings", PYTHONUTF8="1")
    for name in ("NODE_OPTIONS", "NODE_PATH", "NODE_V8_COVERAGE"):
        env.pop(name, None)
    return env


def project_python():
    return Path(sys.prefix).resolve() == (ROOT / ".venv").resolve()


def node_ready():
    """Probe a version only. Do not import project modules or start a service."""
    node = shutil.which("node")
    if not node:
        return False
    env = os.environ.copy()
    for name in ("NODE_OPTIONS", "NODE_PATH", "NODE_V8_COVERAGE"):
        env.pop(name, None)
    try:
        result = subprocess.run(
            [node, "--version"],
            capture_output=True,
            text=True,
            timeout=3,
            stdin=subprocess.DEVNULL,
            env=env,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    version = re.fullmatch(r"v(\d+)\.\d+\.\d+", result.stdout.strip())
    return result.returncode == 0 and bool(version) and int(version[1]) >= MIN_NODE_MAJOR


def require_node():
    if not node_ready():
        raise SystemExit("Node 24 or newer is required for this command. Run scripts/sb.py doctor.")


def pinned_runtime_ready():
    """Inspect installed distribution metadata without importing Django or creating local state."""
    try:
        lines = (ROOT / "requirements.txt").read_text(encoding="utf8").splitlines()
        pins = []
        for line in lines:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            pin = re.fullmatch(
                r"([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([A-Za-z0-9_.+!-]+)", line.strip()
            )
            if not pin:
                return False
            pins.append(pin.groups())
        return bool(pins) and all(
            importlib.metadata.version(name) == version for name, version in pins
        )
    except (OSError, importlib.metadata.PackageNotFoundError):
        return False


def source_available(app):
    source = Path(os.environ.get(app.upper() + "_REPO") or ROOT.parent / app)
    migrations = source / "supabase" / "migrations"
    return migrations.is_dir() and any(migrations.glob("*.sql"))


def run(*args):
    try:
        result = subprocess.run(args, cwd=ROOT, env=local_environment(), shell=False)
    except OSError:
        raise SystemExit(
            "A required executable could not start. Run scripts/sb.py doctor."
        ) from None
    if result.returncode:
        raise SystemExit(result.returncode)


def manage(*args):
    run(sys.executable, "manage.py", *args)


def doctor():
    try:
        local_environment()
        local = True
    except SystemExit:
        local = False
    checks = {
        "Python 3.11 or newer": sys.version_info >= (3, 11),
        "This checkout's .venv interpreter": project_python(),
        "Pinned Python runtime packages": pinned_runtime_ready(),
        "Native local SQLite / port 8741 configuration": local,
    }
    print("Local console prerequisites (doctor's exit status covers this group):")
    for name, ok in checks.items():
        print(("OK " if ok else "MISSING ") + name)
    console = all(checks.values())
    node = node_ready()
    fixtures = all((ROOT / "fixtures" / name).is_file() for name in ("events.json", "labels.json"))
    ruff = ROOT / ".venv" / ("Scripts/ruff.exe" if os.name == "nt" else "bin/ruff")
    git = bool(shutil.which("git")) and (ROOT / ".git").exists()
    print(("OK " if node else "MISSING ") + "Node 24 or newer (synthetic demo and offline proof)")
    print(("OK " if fixtures else "MISSING ") + "Bundled synthetic events and separate labels")
    print(
        "Synthetic demo prerequisites: "
        + ("ready" if console and node and fixtures else "incomplete")
    )
    print(
        "Offline proof prerequisites: "
        + ("ready" if console and node and git and ruff.is_file() else "incomplete")
    )
    print(("OK " if git else "MISSING ") + "Git and checkout metadata (for source-bound proof)")
    print(
        ("OK " if ruff.is_file() else "MISSING ")
        + "Project Ruff executable (install requirements-dev.txt for proof)"
    )
    print("Optional source-app labs (not required for the console or synthetic demo):")
    for app in ("bettail", "netted"):
        print(
            ("AVAILABLE " if source_available(app) else "NOT PROVIDED ") + app + " migration inputs"
        )
    pglite = (ROOT / "node_modules/@electric-sql/pglite/package.json").is_file()
    print(
        ("AVAILABLE " if pglite else "NOT PROVIDED ")
        + "PGlite package (source-app database labs only)"
    )
    print(
        "Docker CLI: "
        + ("on PATH" if shutil.which("docker") else "not on PATH")
        + "; engine, capacity and isolation not checked."
    )
    print(
        "Existing local access file: "
        + (
            "present; contents not checked"
            if (ROOT / "var/local-access.txt").is_file()
            else "not created; run setup after installing runtime requirements"
        )
    )
    print(
        "Doctor checks prerequisites only; it does not prove a running server, migrations, authentication or integration coverage."
    )
    if not all(checks.values()):
        raise SystemExit(1)


def setup():
    local_environment()
    manage("migrate", "--noinput")
    manage("bootstrap")
    manage(
        "setup_scanners",
        "--grant",
        "analyst:analyst",
        "--grant",
        "reviewer:reviewer",
        "--grant",
        "viewer:viewer",
    )


class NoHealthRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise urllib.error.HTTPError(
            request.full_url, code, "Health redirects are refused.", headers, response
        )


def probe_server():
    """False means connection refused; every responding/unknown listener fails closed."""
    expected = workspace_id(ROOT)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoHealthRedirect())
    request = urllib.request.Request(HEALTH_URL, headers={"Accept": "application/json"})
    try:
        with opener.open(request, timeout=HEALTH_TIMEOUT_SECONDS) as response:
            if response.geturl() != HEALTH_URL or response.status != 200:
                raise ValueError("Unexpected health response.")
            raw = response.read(MAX_HEALTH_BYTES + 1)
        if len(raw) > MAX_HEALTH_BYTES:
            raise ValueError("Oversized health response.")
        data = json.loads(raw)
        if (
            not isinstance(data, dict)
            or data.get("service") != "signalbridge"
            or data.get("status") != "running"
            or data.get("workspace_id") != expected
        ):
            raise ValueError("Different or unidentified workspace.")
        return True
    except urllib.error.URLError as error:
        if isinstance(error, urllib.error.HTTPError):
            error.close()
        reason = error.reason
        if isinstance(reason, ConnectionRefusedError) or (
            isinstance(reason, OSError)
            and (reason.errno == errno.ECONNREFUSED or getattr(reason, "winerror", None) == 10061)
        ):
            return False
        raise SystemExit(
            "Port 8741 could not be safely identified. Startup was not confirmed. "
            "Health checks refuse proxies, redirects and unknown listeners."
        ) from None
    except (OSError, ValueError, http.client.HTTPException):
        raise SystemExit(
            "Port 8741 responded unexpectedly or belongs to another checkout. "
            "Startup was not confirmed. A legacy server without a workspace ID must be stopped "
            "using its own checkout's down command before restarting."
        ) from None


def guarded_runtime(name, *, create_directory=False):
    try:
        return runtime_file(ROOT, name, create_directory=create_directory)
    except (OSError, ValueError):
        raise SystemExit(
            "Runtime paths must be ordinary files in this checkout's var directory. "
            "No linked or redirected runtime path is allowed."
        ) from None


def up():
    env = local_environment()
    guarded_runtime("server.log")
    guarded_runtime("stop.request")
    if probe_server():
        print("This SignalBridge checkout is already running on port 8741.")
        return
    log_path = guarded_runtime("server.log", create_directory=True)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    with log_path.open("a", encoding="utf8") as log:
        process = subprocess.Popen(
            [sys.executable, "-B", "scripts/serve.py"],
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=log,
            creationflags=flags,
            start_new_session=os.name != "nt",
        )
    for _ in range(40):
        if process.poll() is not None:
            raise SystemExit("Server did not start. Read var/server.log.")
        if probe_server():
            print("Open http://127.0.0.1:8741/ · Credentials: var/local-access.txt")
            return
        time.sleep(0.25)
    raise SystemExit("Startup not confirmed. Read var/server.log.")


def down():
    local_environment()
    stop = guarded_runtime("stop.request", create_directory=True)
    try:
        with stop.open("x", encoding="utf-8") as marker:
            marker.write("Stop this workspace's local development server.\n")
    except FileExistsError:
        guarded_runtime("stop.request")
    print("Requested shutdown through this checkout's local marker. Data is preserved.")


def test():
    require_node()
    manage("check")
    manage("test", "tests", "--verbosity", "1")
    for target in NODE_TEST_TARGETS.values():
        run("node", "--test", "--test-isolation=none", "--test-reporter=tap", target)


def test_apps(app="all"):
    require_node()
    if app not in ("all", "bettail", "netted"):
        raise SystemExit("Choose a supported source-app lab.")
    selected = ("bettail", "netted") if app == "all" else (app,)
    if not all(source_available(name) for name in selected):
        raise SystemExit(
            "Source-app migrations are missing. Use demo-core/verify-core without private checkouts."
        )
    if not (ROOT / "node_modules/@electric-sql/pglite/package.json").is_file():
        raise SystemExit(
            "The optional PGlite package is missing. See docs/GETTING_STARTED.md for source-app labs."
        )
    run("node", "integrations/check-apps.mjs", app)


def demo():
    test_apps()
    setup()
    manage("import_checks")
    up()
    run("node", "integrations/deliver-lab.mjs")
    manage("seed_replays")
    manage("evidence")


def demo_core():
    local_environment()
    require_node()
    if not all((ROOT / "fixtures" / name).is_file() for name in ("events.json", "labels.json")):
        raise SystemExit(
            "Bundled synthetic fixture files are missing. Restore this checkout before running a demo."
        )
    print(
        "Synthetic demo: fixtures/events.json + separate fixtures/labels.json; source class synthetic_demo."
    )
    print(
        "This adds fresh synthetic events to this checkout's local database; existing data is preserved. It does not test source-app authorization."
    )
    setup()
    up()
    run("node", "integrations/demo-synthetic.mjs")
    manage("work", "--once")
    manage("seed_replays")
    manage("evidence")


def verify(strict):
    if strict not in ("core", "m1"):
        raise SystemExit("Choose core or m1 verification.")
    if strict == "core":
        run(sys.executable, "scripts/record_verification.py")
        return
    test()
    test_apps("bettail")
    if strict == "m1":
        print(
            "BLOCKED full M1: this command covers core tests and the BetTail database subset only. "
            "It does not execute or reconcile the complete source-route, signed-URL and instrumentation gates. "
            "Separately recorded HTTP/Auth/Storage evidence does not complete that gate."
        )
        raise SystemExit(2)


commands = [
    "doctor",
    "setup",
    "up",
    "down",
    "test",
    "test-apps",
    "test-bettail",
    "verify-m1",
    "verify-core",
    "demo",
    "demo-core",
    "evidence",
]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=commands)
    args = parser.parse_args(argv)
    if args.command != "doctor":
        if not project_python():
            raise SystemExit("Use this checkout's .venv Python. See docs/GETTING_STARTED.md.")
        local_environment()
    {
        "doctor": doctor,
        "setup": setup,
        "up": up,
        "down": down,
        "test": test,
        "test-apps": test_apps,
        "test-bettail": lambda: test_apps("bettail"),
        "verify-m1": lambda: verify("m1"),
        "verify-core": lambda: verify("core"),
        "demo": demo,
        "demo-core": demo_core,
        "evidence": lambda: manage("evidence"),
    }[args.command]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
