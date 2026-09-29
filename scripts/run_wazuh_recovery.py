"""Fixed-scope native recovery pilot; no downloads or remote targets."""

import hashlib
import json
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrations.wazuh import run_context
from scripts import verify_soc_pilot as gate

IMAGE = (
    "wazuh/wazuh-manager@sha256:f74021c1275393aa094b6f6bb57f9bac240cba7ddb35f2a841e430341f5fc6a0"
)
SOURCE_FILES = (
    "run_pilot.py",
    "run_context.py",
    "verify_static.py",
    "event-contract.json",
    "manager-lab.conf",
    "signalbridge_rules.xml",
    "image-lock.json",
    "fixtures/events.jsonl",
    "fixtures/expectations.json",
)


def require(value, code):
    if not value:
        raise ValueError(code)


def docker(*args, timeout=10):
    return gate.base.docker(list(args), timeout=timeout)


def save(path, value):
    with path.open("x", encoding="utf8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    require(len(sys.argv) == 1, "no_arguments")
    start_free = shutil.disk_usage(ROOT).free

    def capacity():
        free = shutil.disk_usage(ROOT).free
        require(free >= 25 * 1024**3 and start_free - free <= 10 * 1024**3, "disk_budget")
        return free

    capacity()
    require(not docker("ps", "--format", "{{.Names}}"), "another_container_active")
    run = str(uuid.uuid4())
    name = "signalbridge-wazuh-recovery-" + run[:8]
    require(not docker("ps", "-aq", "--filter", "name=^/" + name + "$"), "container_exists")
    parent = ROOT / "var/soc/pilot"
    gate._safe(parent, directory=True)
    directory = parent / run
    directory.mkdir()
    package = directory / "source"
    output = directory / "wazuh-recovery"
    package.mkdir()
    output.mkdir()
    (package / "fixtures").mkdir()
    sources = {}
    for relative in SOURCE_FILES:
        source = ROOT / "integrations/wazuh" / relative
        gate._safe(source, directory=False)
        require(source.stat().st_size <= 1024**2, "source_bound")
        raw = source.read_bytes()
        with (package / relative).open("xb") as handle:
            handle.write(raw)
        sources[relative] = digest(raw)
    driver = ROOT / "integrations/wazuh_recovery/run_delivery.py"
    gate._safe(driver, directory=False)
    raw = driver.read_bytes()
    with (package / "run_delivery.py").open("xb") as handle:
        handle.write(raw)
    sources["run_delivery.py"] = digest(raw)
    source_digest = digest(json.dumps(sources, sort_keys=True, separators=(",", ":")).encode())
    save(directory / "source-manifest.json", {"files": sources, "sha256": source_digest})
    with (directory / "executed-controller.py").open("xb") as handle:
        handle.write(Path(__file__).read_bytes())
    context = {
        "schema_version": 1,
        "kind": "signalbridge-wazuh-run-context",
        "run_id": run,
        "prepared_at": datetime.now(timezone.utc).isoformat(),
        "source_sha256": source_digest,
    }
    run_context.parse(json.dumps(context).encode())
    save(output / "run-context.json", context)
    profile = gate.profiles(run)[gate.WAZUH]
    profile["command"] = ["/pilot/run_delivery.py"]
    profile["mounts"] = {"/pilot": (package, False), "/evidence": (output, True)}
    # Reuse the complete pure isolation evaluator with one fixed private profile.
    # These values affect this controller process only; no repository gate is edited.
    gate.WAZUH = name
    gate.NAMES["wazuh"] = (name,)
    gate.IMAGES[name] = IMAGE
    gate.profiles = lambda requested: {name: profile} if requested == run else {}

    def check(state):
        topology = gate.gather_topology("wazuh")
        errors = gate.verify_topology(topology, "wazuh", run, state=state)
        actual = {relative: digest((package / relative).read_bytes()) for relative in sources}
        require(actual == sources and set(gate._tree(package)) == set(sources), "source_changed")
        record = {
            "state": state,
            "errors": errors,
            "source_sha256": source_digest,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "topology": topology,
        }
        save(directory / (state + "-gate.json"), record)
        require(not errors, "isolation_gate_" + state)
        return record

    args = [
        "create",
        "--pull=never",
        "--name",
        name,
        "--hostname",
        name,
        "--label",
        "signalbridge.pilot.run=" + run,
        "--network=none",
        "--restart=no",
        "--ipc=private",
        "--cgroupns=private",
        "--security-opt=no-new-privileges:true",
        "--cap-drop=ALL",
        "--log-driver=json-file",
        "--log-opt=max-size=2m",
        "--log-opt=max-file=2",
        "--no-healthcheck",
        "--user=0:0",
        "--workdir=/pilot",
        "--memory",
        str(profile["memory"]),
        "--memory-swap",
        str(profile["memory"]),
        "--cpus=1",
        "--pids-limit=256",
    ]
    for cap in profile["capabilities"]:
        args.extend(["--cap-add", cap])
    for destination, (path, writable) in profile["mounts"].items():
        gate._safe(path, directory=True)
        args.extend(
            [
                "--mount",
                f"type=bind,src={path},dst={destination}" + ("" if writable else ",readonly"),
            ]
        )
    args.extend(["--entrypoint", profile["entrypoint"][0], IMAGE, *profile["command"]])
    cid = None
    failure = None
    stopped = False
    observed = None
    try:
        cid = docker(*args)
        require(gate._id(cid), "container_id")
        check("created")
        capacity()
        started = time.monotonic()
        docker("start", cid, timeout=5)
        check("running")
        while time.monotonic() - started < 160:
            capacity()
            if docker("inspect", cid, "--format", "{{.State.Status}}", timeout=3) == "exited":
                break
            time.sleep(1)
        else:
            raise ValueError("parent_runtime_deadline")
    except Exception as error:
        failure = type(error).__name__
        save(
            directory / "host-failure.json",
            {
                "class": type(error).__name__,
                "code": str(error) if type(error) is ValueError else "native_operation_failed",
            },
        )
    finally:
        if cid and gate._id(cid):
            try:
                # Stop targets the returned immutable ID even if an inspection failed.
                docker("stop", "--timeout", "5", cid, timeout=10)
            except Exception:
                try:
                    docker("kill", cid, timeout=5)
                except Exception:
                    pass
            try:
                observed = json.loads(
                    docker(
                        "inspect",
                        cid,
                        "--format",
                        '{"status":{{json .State.Status}},"exit_code":{{json .State.ExitCode}},"oom":{{json .State.OOMKilled}}}',
                        timeout=3,
                    )
                )
                stopped = observed["status"] == "exited"
                check("exited" if stopped else observed["status"])
                with (directory / "container.log").open("x", encoding="utf8") as handle:
                    handle.write(docker("logs", cid))
            except Exception as error:
                failure = failure or type(error).__name__
    summary = {
        "run_id": run,
        "container_id": cid,
        "stopped": stopped,
        "failure": failure,
        "state": observed,
        "free_bytes_after": shutil.disk_usage(ROOT).free,
        "source_sha256": source_digest,
    }
    save(directory / "host-result.json", summary)
    print(json.dumps(summary), flush=True)
    if (output / "recovery-result.json").exists():
        result = json.loads((output / "recovery-result.json").read_text())
        print(
            json.dumps(
                {
                    key: result.get(key)
                    for key in ("status", "failure_code", "duration_seconds", "recovery_phases")
                }
            ),
            flush=True,
        )
    else:
        result = {}
    return (
        0
        if not failure
        and stopped
        and observed["exit_code"] == 0
        and not observed["oom"]
        and result.get("status") == "passed"
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
