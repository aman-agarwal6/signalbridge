"""Run only the fixed offline simulation in a separate, bounded Python process."""

import argparse
import hashlib
import json
import os
import secrets
import socket
import stat
import subprocess
import sys
import uuid
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def blocked(*args, **kwargs):
    raise PermissionError("Offline simulation prohibits network access and child processes.")


def output_directory(run_id, *, create=False):
    """Reject path redirection before touching any simulation artifacts."""
    if len(run_id) != 32 or any(char not in "0123456789abcdef" for char in run_id):
        raise ValueError("Invalid fixed simulation identity.")
    root = ROOT.resolve(strict=True)
    output = root / "artifacts/local/simulation" / run_id
    ancestors = [root / "artifacts", root / "artifacts/local", output.parent, output]
    for candidate in ancestors:
        if candidate.is_symlink() or (
            hasattr(candidate, "is_junction") and candidate.is_junction()
        ):
            raise ValueError("Simulation evidence directories cannot be links or junctions.")
        if candidate.exists():
            attributes = getattr(candidate.lstat(), "st_file_attributes", 0)
            if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024):
                raise ValueError("Simulation evidence directories cannot be reparse points.")
            if not candidate.is_dir():
                raise ValueError("Simulation evidence ancestors must be directories.")
        if not candidate.resolve().is_relative_to(root):
            raise ValueError("Simulation evidence escaped the repository.")
    if create:
        output.mkdir(parents=True, exist_ok=False)
        return output_directory(run_id)
    if not output.is_dir():
        raise ValueError("The parent must create a fresh simulation evidence directory.")
    return output


def require_memory_database(databases):
    if set(databases) != {"default"}:
        raise RuntimeError("Simulation permits exactly one disposable database.")
    database = databases["default"]
    if (
        database.get("ENGINE") != "django.db.backends.sqlite3"
        or database.get("NAME") != ":memory:"
        or database.get("TEST", {}).get("NAME") != ":memory:"
    ):
        raise RuntimeError("Simulation database must be in-memory SQLite.")


def offline_guards(stack):
    for attribute in ("connect", "connect_ex", "sendto", "bind", "listen", "sendmsg"):
        if hasattr(socket.socket, attribute):
            stack.enter_context(patch.object(socket.socket, attribute, blocked))
    for attribute in (
        "create_connection",
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "gethostbyaddr",
    ):
        stack.enter_context(patch.object(socket, attribute, blocked))
    stack.enter_context(patch.object(subprocess, "Popen", blocked))
    for attribute in (
        "system",
        "popen",
        "startfile",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "execv",
        "execve",
        "execl",
        "execle",
    ):
        if hasattr(os, attribute):
            stack.enter_context(patch.object(os, attribute, blocked))


def verify_guards():
    def tcp():
        with socket.socket() as client:
            client.connect(("192.0.2.1", 443))

    def udp():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(b"", ("192.0.2.1", 53))

    for operation in (
        tcp,
        udp,
        lambda: socket.getaddrinfo("invalid.example", 443),
        lambda: subprocess.run([sys.executable, "--version"], check=False),
    ):
        try:
            operation()
        except PermissionError:
            continue
        raise RuntimeError("An offline guard did not fail closed.")


def child(run_id, *, challenge=False):
    if type(challenge) is not bool:
        raise ValueError("Only fixed simulation profiles are supported.")
    if len(run_id) != 32 or any(char not in "0123456789abcdef" for char in run_id):
        raise ValueError("Invalid fixed simulation identity.")
    if os.environ.get("SB_SIMULATION_RUN_ID") != run_id:
        raise ValueError("Simulation must be launched by its fixed parent.")
    output_directory(run_id)
    os.environ["DJANGO_SETTINGS_MODULE"] = "config.simulation_settings"
    os.environ["SB_MODE"] = "local"
    with ExitStack() as stack:
        offline_guards(stack)
        verify_guards()
        import django
        from django.conf import settings

        require_memory_database(settings.DATABASES)
        django.setup()
        from django.test.runner import DiscoverRunner

        runner = DiscoverRunner(verbosity=1, interactive=False, parallel=0)
        suite = "simulations.challenge_suite" if challenge else "simulations.enterprise_suite"
        return bool(runner.run_tests([suite]))


def clean_environment(run_id):
    allowed = {
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    environment.update(
        SB_MODE="local",
        SB_SECRET_KEY=secrets.token_urlsafe(64),
        SB_SIMULATION_KEY=secrets.token_urlsafe(48),
        SB_SIMULATION_RUN_ID=run_id,
        PYTHONDONTWRITEBYTECODE="1",
        DJANGO_SETTINGS_MODULE="config.simulation_settings",
        GIT_OPTIONAL_LOCKS="0",
        GIT_CONFIG_COUNT="1",
        GIT_CONFIG_KEY_0="core.fsmonitor",
        GIT_CONFIG_VALUE_0="false",
    )
    return environment


def run(*, challenge=False):
    """Execute one fixed profile and return its private receipt and directory."""
    if type(challenge) is not bool:
        raise ValueError("Only fixed simulation profiles are supported.")
    from scripts.record_verification import git_state, source_manifest

    run_id = uuid.uuid4().hex
    output = output_directory(run_id, create=True)
    environment = clean_environment(run_id)
    before = source_manifest(ROOT)
    revision = git_state(ROOT, environment)
    declared = None
    if challenge:
        from bridge.contract import canonical
        from simulations.challenge_cases import declaration

        declared = canonical(declaration())
        with (output / "declaration.json").open("xb") as handle:
            handle.write(declared)
    try:
        with (
            (output / "stdout.txt").open("xb") as stdout,
            (output / "stderr.txt").open("xb") as stderr,
        ):
            result = subprocess.run(
                [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child", run_id]
                + (["--challenge"] if challenge else []),
                cwd=ROOT,
                env=environment,
                stdout=stdout,
                stderr=stderr,
                timeout=120,
                check=False,
            )
        returncode = result.returncode
    except subprocess.TimeoutExpired:
        returncode = None
    after = source_manifest(ROOT)
    output = output_directory(run_id)
    receipt = {
        "schema_version": 1,
        "run_id": run_id,
        "exit_code": returncode,
        "source_before": before,
        "source_after": after,
        "source_unchanged": before == after,
        "git": revision,
        "python": sys.version.split()[0],
        "logs": {
            name: hashlib.sha256((output / name).read_bytes()).hexdigest()
            for name in ("stdout.txt", "stderr.txt")
        },
        "limits": [
            "Offline guards catch accidental use in this fixed trusted harness; they are not an OS sandbox against arbitrary hostile Python.",
            "No user code, remote configuration, external URLs, shell commands, exploit payloads or plugins are accepted.",
            "The workload is bounded to 750 in-process requests, 700 records per worker drain and a 120-second child timeout.",
        ],
    }
    if challenge:
        receipt["profile"] = "detection-challenge-v1"
        receipt["declaration_sha256"] = hashlib.sha256(declared).hexdigest()
        receipt["limits"][2] = (
            "The fixed challenge is bounded to 150 requests, 150 processed records and a 120-second child timeout."
        )
    result_path = output / "result.json"
    complete = False
    if result_path.is_file():
        raw = result_path.read_bytes()
        receipt["result_sha256"] = hashlib.sha256(raw).hexdigest()
        try:
            from bridge.simulation_evidence import json_document

            simulation = json_document(raw)
        except ValueError:
            simulation = {}
        complete = simulation.get("execution_status") in {
            "completed_with_known_coverage_gap",
            "completed",
        }
        if challenge:
            from bridge.challenge_evidence import validate_result

            try:
                coverage_status, _ = validate_result(simulation)
                receipt["declaration_unchanged"] = (
                    output / "declaration.json"
                ).read_bytes() == declared
                complete = (
                    simulation["declaration_sha256"] == receipt["declaration_sha256"]
                    and receipt["declaration_unchanged"]
                )
                receipt["coverage_status"] = coverage_status
            except (ValueError, TypeError, KeyError):
                complete = False
    receipt["execution_verified"] = returncode == 0 and before == after and complete
    with (output / "provenance.json").open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(receipt, indent=2) + "\n")
    return receipt, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", help=argparse.SUPPRESS)
    parser.add_argument(
        "--challenge",
        action="store_true",
        help="Run the fixed predeclared detection challenge matrix.",
    )
    args = parser.parse_args()
    if args.child:
        return int(child(args.child, challenge=args.challenge))
    receipt, output = run(challenge=args.challenge)
    print(
        f"Offline simulation {'completed; inspect the recorded coverage result' if receipt['execution_verified'] else 'failed verification'}. Private evidence: {output.relative_to(ROOT)}"
    )
    if args.challenge and receipt["execution_verified"]:
        print(
            f"Challenge coverage: {receipt['coverage_status']}; {json.dumps(json.loads((output / 'result.json').read_text())['summary'], sort_keys=True)}"
        )
    return 0 if receipt["execution_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
