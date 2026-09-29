"""Repeat the approved three-GET ZAP pilot with fresh owned resources and evidence.

No downloads, target overrides, application database, public ports or automatic
retry. --unavailable-target stops only this run's synthetic target before traffic.
That exercise must remain a failed scan even when failure handling is verified.
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.assurance import timestamp
from bridge.scanner_reports import _load
from bridge.soc_pilot_evidence import zap_result
from scripts import verify_soc_pilot as gate
from scripts.local_backup import bounded_read, make_directory, safe, write_new
from scripts.record_verification import source_manifest

FILES = {"README.md", "RUNTIME.md", "contract.py", "fixture.py", "profile.json", "run_passive.py"}
FREE_FLOOR = 25 * 1024**3
GROWTH = 10 * 1024**3
ACTIVE_SECONDS = 180  # Reserve 60 seconds for bounded cleanup within 240 seconds.
ROUTE_PROBE = (
    "import json;from pathlib import Path;"
    "rows=Path('/proc/net/route').read_text().splitlines()[1:];"
    "v6=Path('/proc/net/ipv6_route');"
    "print(json.dumps({'default_ipv4':sum(r.split()[1]=='00000000' for r in rows),"
    "'default_ipv6':sum(r.split()[0]=='0'*32 and r.split()[1]=='00' "
    "and r.split()[9]!='lo' for r in v6.read_text().splitlines()) if v6.exists() else 0}))"
)
LIMITS = [
    "Historical builder-operated three-request synthetic fixture, not an application scan.",
    "No active scanning, crawling, authentication, automatic response or continuous connection.",
    "Isolation and routes are sampled; no continuous packet or hostile-administrator proof.",
    "Known header controls do not measure general scanner accuracy or enterprise parity.",
    "Failed scans are incomplete; findings remain claimed reports with unknown coverage.",
    "Failed/interrupted attempts retain their lock and evidence for operator inspection.",
]


class PilotError(ValueError):
    pass


def require(value, code):
    if not value:
        raise PilotError(code)


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    write_new(ROOT, path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def docker(*args, timeout=5):
    return gate.base.docker(list(args), timeout=timeout)


def capacity(initial):
    free = shutil.disk_usage(ROOT).free
    require(free >= FREE_FLOOR and initial - free <= GROWTH, "disk_budget")
    return free


def package_files(directory, *, snapshot=False):
    found = gate._tree(directory)
    extras = set(found) - FILES
    # Interpreter caches in the original checkout are not source and are never
    # copied into the executed snapshot. All other unexpected files fail closed.
    require(
        not extras
        or (
            not snapshot
            and all(
                name.startswith("__pycache__/") and name.count("/") == 1 and name.endswith(".pyc")
                for name in extras
            )
        ),
        "unexpected_package_files",
    )
    require(FILES.issubset(found), "missing_package_files")
    return {name: found[name] for name in sorted(FILES)}


def create_args(run, name, directory):
    names = gate.profile_names("zap-repeat", run)
    require(name in names, "container_scope")
    target = name == names[1]
    profile = gate.profiles(run)[name]
    args = [
        "create",
        "--pull=never",
        "--name",
        name,
        "--hostname",
        "signalbridge-zap-target" if target else name,
        "--label",
        "signalbridge.pilot.run=" + run,
        "--cidfile",
        str(directory / ("target.cid" if target else "scanner.cid")),
        "--network",
        profile["network"],
        "--restart=no",
        "--read-only",
        "--ipc=private",
        "--cgroupns=private",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--user=1000:1000",
        "--workdir=/pilot",
        "--log-driver=json-file",
        "--log-opt=max-size=2m",
        "--log-opt=max-file=2",
        "--no-healthcheck",
        "--memory",
        str(profile["memory"]),
        "--memory-swap",
        str(profile["memory"]),
        "--cpus",
        "0.5" if target else "1.5",
        "--pids-limit",
        str(profile["pids"]),
        "--tmpfs",
        "/tmp:" + profile["tmpfs"]["/tmp"],
    ]
    if target:
        args += ["--network-alias", "signalbridge-zap-target"]
    for destination, (path, writable) in profile["mounts"].items():
        safe(ROOT, path, directory=True)
        require("," not in str(path), "mount_path_separator")
        args += [
            "--mount",
            f"type=bind,src={path},dst={destination}" + ("" if writable else ",readonly"),
        ]
    return args + [
        "--entrypoint",
        "python3",
        gate.image_references("zap-repeat", run)[name],
        *profile["command"],
    ]


def owned_id(run, name, directory):
    """Recover only a created ID whose name and run label still match."""
    target = name == gate.profile_names("zap-repeat", run)[1]
    path = directory / ("target.cid" if target else "scanner.cid")
    if not path.exists():
        return None
    cid = bounded_read(ROOT, path, 128).decode("ascii").strip()
    require(gate._id(cid), "invalid_owned_id")
    identity = _load(
        docker(
            "inspect",
            cid,
            "--format",
            gate.base.template(
                {
                    "id": ".Id",
                    "name": ".Name",
                    "run": '(index .Config.Labels "signalbridge.pilot.run")',
                }
            ),
        ).encode()
    )
    require(identity == {"id": cid, "name": "/" + name, "run": run}, "owned_identity_changed")
    return cid


def state(cid):
    return _load(
        docker(
            "inspect",
            cid,
            "--format",
            gate.base.template(
                {
                    "status": ".State.Status",
                    "exit_code": ".State.ExitCode",
                    "oom": ".State.OOMKilled",
                }
            ),
            timeout=3,
        ).encode()
    )


def stop_owned(cid):
    if state(cid)["status"] in {"created", "exited"}:
        return
    try:
        docker("stop", "--timeout", "3", cid, timeout=5)
    except gate.VerificationError:
        docker("kill", cid, timeout=3)
    require(state(cid)["status"] == "exited", "owned_container_not_stopped")


def fixture_log(raw, *, unavailable=False):
    require(len(raw) <= 4096, "fixture_log_bound")
    rows = [_load(line.encode()) for line in raw.splitlines()]
    expected = [{"fixture": "ready", "synthetic_only": True, "request_budget": 3}]
    if not unavailable:
        expected += [{"request_ordinal": n, "accepted": True} for n in (1, 2, 3)]
    require(gate.base.canonical(rows) == gate.base.canonical(expected), "fixture_request_inventory")
    return len(rows) - 1


def classify(report, raw, times, states, target_log, *, unavailable=False):
    require(
        len(states) == 2 and all(v["status"] == "exited" and v["oom"] is False for v in states),
        "runtime_not_stopped",
    )
    accepted = fixture_log(target_log, unavailable=unavailable)
    if not unavailable:
        require(states[0]["exit_code"] == 0, "scanner_exit")
        version, counts = zap_result(report, raw, times)
        return {
            "scan_status": "passed",
            "exercise_verified": True,
            "version": version,
            "counts": counts,
            "target_accepted": accepted,
        }
    require(
        type(states[0]["exit_code"]) is int
        and states[0]["exit_code"] == 1
        and report.get("schema_version") == 1
        and report.get("kind") == "signalbridge-zap-synthetic-pilot"
        and report.get("target_kind") == "synthetic-fixture-not-signalbridge-application"
        and report.get("profile") == "signalbridge-disposable-web-v1"
        and report.get("status") == "failed"
        and report.get("zap_version") == "2.17.0"
        and report.get("zap_exit_code") == 0
        and report.get("errors")
        in (["unexpected_http_status"], ["network_wall_deadline"], ["pilot_operation_failed"])
        and report.get("requests") == [{"method": "GET", "path": "/", "status": "attempted"}]
        and "controls" not in report
        and "report_sha256" not in report
        and raw is None,
        "unavailable_target_not_proved",
    )
    started, finished = timestamp(report["started_at"]), timestamp(report["finished_at"])
    require(
        times[0] <= started < finished <= times[2]
        and times[1] <= finished
        and (finished - started).total_seconds() <= 240,
        "failure_runtime_window",
    )
    return {
        "scan_status": "failed",
        "exercise_verified": True,
        "version": "2.17.0",
        "failure_code": "target_unavailable",
        "driver_errors": report["errors"],
        "target_accepted": accepted,
        "coverage": "incomplete",
        "counts": None,
    }


def execute(run, *, unavailable=False):
    gate.validate_request("zap-repeat", run, "created")
    initial = capacity(shutil.disk_usage(ROOT).free)
    require(not docker("ps", "-q"), "another_container_active")
    names = gate.profile_names("zap-repeat", run)
    network = gate.network_name("zap-repeat", run)
    for name in names:
        require(not docker("ps", "-aq", "--filter", "name=^/" + name + "$"), "container_exists")
    require(
        not docker("network", "ls", "-q", "--filter", "name=^" + network + "$"), "network_exists"
    )
    # Inspect installed immutable references before creating any native resource.
    for reference in gate.image_references("zap-repeat", run).values():
        image = _load(
            docker(
                "image",
                "inspect",
                reference,
                "--format",
                gate.base.template(
                    {
                        "digests": ".RepoDigests",
                        "os": ".Os",
                        "arch": ".Architecture",
                    }
                ),
            ).encode()
        )
        require(
            reference in image["digests"] and image["os"] == "linux" and image["arch"] == "amd64",
            "installed_image_identity",
        )
    parent = ROOT / "var/soc/pilot"
    safe(ROOT, parent, directory=True)
    directory = parent / run
    make_directory(ROOT, directory)
    package, output = directory / "source", directory / "zap"
    make_directory(ROOT, package)
    make_directory(ROOT, output)
    source_dir = ROOT / "integrations/zap"
    original = package_files(source_dir)
    for name in sorted(FILES):
        raw = bounded_read(ROOT, source_dir / name, 1024**2)
        require(sha(raw) == original[name], "source_changed")
        write_new(ROOT, package / name, raw)
    source = source_manifest(ROOT)
    save(directory / "execution-source.json", source)
    save(directory / "source-manifest.json", original)
    save(
        directory / "plan.json",
        {
            "run_id": run,
            "mode": "unavailable-target" if unavailable else "normal",
            "names": names,
            "network": network,
            "limits": LIMITS,
            "prepared_at": now(),
        },
    )
    evidence, identities, failure, observation = {}, None, None, None
    gate_times = []
    began = None

    def inspect(phase):
        nonlocal identities
        capacity(initial)
        checked = now()
        topology = gate.gather_topology("zap-repeat", run)
        errors = gate.verify_topology(topology, "zap-repeat", run, state=phase)
        require(
            source_manifest(ROOT) == source
            and package_files(package, snapshot=True) == original
            and package_files(source_dir) == original,
            "source_changed",
        )
        observed = (
            [r["Id"] for r in topology["containers"]],
            [r["Id"] for r in topology["networks"]],
        )
        if identities is None:
            identities = observed
        require(identities == observed, "native_identity_changed")
        save(
            directory / (phase + "-gate.json"),
            {"checked_at": checked, "errors": errors, "topology": topology},
        )
        require(not errors, "isolation_" + phase)
        gate_times.append(timestamp(checked))

    try:
        docker(
            "network",
            "create",
            "--internal",
            "--driver",
            "bridge",
            "--label",
            "signalbridge.pilot.run=" + run,
            "--opt",
            "com.docker.network.bridge.host_binding_ipv4=127.0.0.1",
            network,
        )
        for name in names:
            docker(*create_args(run, name, directory))
        inspect("created")
        scanner, target = [owned_id(run, name, directory) for name in names]
        require(scanner and target, "created_identity_missing")
        began = time.monotonic()
        docker("start", target)
        deadline = began + ACTIVE_SECONDS
        ready_until = time.monotonic() + 10
        while time.monotonic() < ready_until:
            logs = docker("logs", "--tail", "5", target)
            if logs:
                fixture_log(logs, unavailable=True)
                break
            time.sleep(0.25)
        else:
            raise PilotError("fixture_not_ready")
        docker("start", scanner)
        inspect("running")
        routes = []
        for cid in (scanner, target):
            row = _load(docker("exec", cid, "python3", "-I", "-B", "-c", ROUTE_PROBE).encode())
            require(row == {"default_ipv4": 0, "default_ipv6": 0}, "default_route_present")
            routes.append(row)
        save(directory / "route-samples.json", routes)
        if unavailable:
            stop_owned(target)
            require(
                fixture_log(docker("logs", "--tail", "5", target), unavailable=True) == 0,
                "fault_too_late",
            )
            save(
                directory / "target-unavailable.json",
                {"target_id": target, "observed_at": now(), "state": state(target)},
            )
        while time.monotonic() < deadline:
            capacity(initial)
            if state(scanner)["status"] == "exited":
                break
            time.sleep(0.5)
        else:
            raise PilotError("parent_deadline")
    except BaseException as error:
        failure = str(error) if isinstance(error, PilotError) else type(error).__name__
    finally:
        for name in names:
            try:
                cid = owned_id(run, name, directory)
                if cid:
                    stop_owned(cid)
                    evidence[name] = {"id": cid, "state": state(cid)}
            except Exception:
                failure = failure or "cleanup_incomplete"
        if not failure:
            try:
                inspect("exited")
                target_log = docker("logs", "--tail", "5", evidence[names[1]]["id"])
                write_new(ROOT, directory / "target.log", target_log.encode())
                report = _load(bounded_read(ROOT, output / "pilot-result.json", 64 * 1024))
                report_path = output / "zap-report.json"
                raw = bounded_read(ROOT, report_path, 2 * 1024**2) if report_path.exists() else None
                observation = classify(
                    report,
                    raw,
                    gate_times,
                    [evidence[n]["state"] for n in names],
                    target_log,
                    unavailable=unavailable,
                )
                capacity(initial)
                require(not docker("ps", "-q"), "another_container_active")
            except Exception as error:
                failure = str(error) if isinstance(error, PilotError) else type(error).__name__
                observation = None
        summary = {
            "schema_version": 1,
            "kind": "signalbridge-zap-repeat",
            "run_id": run,
            "mode": "unavailable-target" if unavailable else "normal",
            "failure": failure,
            "observation": observation,
            "containers": evidence,
            "source_sha256": source["sha256"],
            "package_sha256": sha(gate.base.canonical(original)),
            "duration_seconds": round(time.monotonic() - began, 3) if began else None,
            "finished_at": now(),
            "limits": LIMITS,
        }
        save(directory / "host-result.json", summary)
        print(
            json.dumps(
                {
                    k: summary[k]
                    for k in ("run_id", "mode", "failure", "observation", "duration_seconds")
                }
            ),
            flush=True,
        )
    return 0 if failure is None and observation and observation["exercise_verified"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unavailable-target", action="store_true")
    args = parser.parse_args()
    run = str(uuid.uuid4())
    lock = ROOT / "var/soc/zap-pilot.lock"
    body = json.dumps({"run_id": run, "pid": os.getpid()}).encode()
    try:
        write_new(ROOT, lock, body)
    except (FileExistsError, ValueError, OSError):
        print(json.dumps({"status": "blocked", "code": "zap_lock_requires_inspection"}))
        return 1
    try:
        result = execute(run, unavailable=args.unavailable_target)
        if result == 0:
            require(bounded_read(ROOT, lock, 1024) == body, "lock_changed")
            lock.unlink()
        return result
    except Exception as error:
        print(
            json.dumps(
                {
                    "run_id": run,
                    "status": "failed",
                    "class": type(error).__name__,
                    "code": str(error) if isinstance(error, PilotError) else "preparation_failed",
                    "lock_retained": True,
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
