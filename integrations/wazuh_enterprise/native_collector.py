"""Finite native bootstrap, only inside the reviewed isolated manager container.

The host controller and explicit launch approval are still required. It never
starts stock /init, opens a network, changes source accounts or claims ongoing
application delivery. A durable capture journal drains open log generations at
rotation; the fixed input bootstrap remains separate from a continuous profile.
"""

import hashlib
import os
import re
import signal
import sqlite3
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from bridge.contract import canonical, parse_json, timestamp
from integrations.wazuh import run_pilot as base

from .capture_journal import CaptureJournal, PinnedCapture
from .collector_kernel import observe_kernel, verify_kernel
from .collector_profile import DAEMONS, verify_configuration
from .contract import EnterpriseWazuhError, identifier, require
from .native_reconciliation import MAX_NATIVE_FILE_BYTES, expected_exports, reconcile

WORKSPACE = Path("/workspace")
EVIDENCE = Path("/evidence")
INPUT = Path("/signalbridge/input")
WAZUH = Path("/var/ossec")
RUNTIME_SECONDS = 600
HARD_SECONDS = 660
CONTEXT_FIELDS = {"context_version", "run_id", "prepared_at", "source_sha256", "manifest_sha256"}
SOURCE_FILES = (
    "bridge/contract.py",
    "bridge/runtime_identity.py",
    "integrations/wazuh/run_pilot.py",
    "integrations/wazuh/run_context.py",
    "integrations/wazuh/verify_static.py",
    "integrations/wazuh_enterprise/collector_profile.py",
    "integrations/wazuh_enterprise/collector_kernel.py",
    "integrations/wazuh_enterprise/export_snapshot.py",
    "integrations/wazuh_enterprise/contract.py",
    "integrations/wazuh_enterprise/native_reconciliation.py",
    "integrations/wazuh_enterprise/native_collector.py",
    "integrations/wazuh_enterprise/capture_journal.py",
    "integrations/wazuh_enterprise/manager-lab.conf",
    "integrations/wazuh_enterprise/local_internal_options.conf",
    "integrations/wazuh_enterprise/signalbridge_rules.xml",
)


def _directory(path):
    require(stat.S_ISDIR(path.lstat().st_mode), "native_collector_directory")


def _file(path, limit):
    for parent in path.parents:
        _directory(parent)
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
        "native_collector_file",
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        opened = os.fstat(handle.fileno())
        require(
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_nlink)
            == (info.st_dev, info.st_ino, info.st_size, 1),
            "native_collector_file_race",
        )
        raw = handle.read(limit + 1)
    require(len(raw) == info.st_size <= limit, "native_collector_file_changed")
    return raw


def validate_context(raw, *, now):
    require(type(raw) is bytes and 0 < len(raw) <= 4096, "native_collector_context_size")
    value = parse_json(raw)
    require(type(value) is dict and set(value) == CONTEXT_FIELDS, "native_collector_context_fields")
    require(
        type(value["context_version"]) is int and value["context_version"] == 1,
        "native_collector_context_version",
    )
    identifier(value["run_id"])
    require(
        0 <= (now - timestamp(value["prepared_at"])).total_seconds() <= 900,
        "native_collector_context_age",
    )
    for name in ("source_sha256", "manifest_sha256"):
        require(
            isinstance(value[name], str) and re.fullmatch(r"[a-f0-9]{64}", value[name]),
            "native_collector_context_digest",
        )
    return value


def _entries(path, maximum):
    result = []
    with os.scandir(path) as iterator:
        for entry in iterator:
            require(len(result) < maximum, "native_collector_log_directory_limit")
            result.append(Path(entry.path))
    return result


def current_native_file(kind, *, read_bytes=True):
    """Accept the native current/daily hardlink pair; no arbitrary link following."""
    require(kind in {"archive", "alert"}, "native_collector_log_kind")
    folder = WAZUH / "logs" / ("archives" if kind == "archive" else "alerts")
    path = folder / ("archives.json" if kind == "archive" else "alerts.json")
    for parent in (folder, *folder.parents):
        _directory(parent)
    if not path.exists():
        return None, b""
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 2 and info.st_size <= MAX_NATIVE_FILE_BYTES,
        "native_collector_log_file",
    )
    identity = info.st_dev, info.st_ino
    aliases = []
    prefix = "ossec-archive-" if kind == "archive" else "ossec-alerts-"
    for year in _entries(folder, 16):
        if not re.fullmatch(r"[0-9]{4}", year.name):
            continue
        _directory(year)
        for month in _entries(year, 12):
            _directory(month)
            for candidate in _entries(month, 64):
                if not (candidate.name.startswith(prefix) and candidate.name.endswith(".json")):
                    continue
                other = candidate.lstat()
                require(stat.S_ISREG(other.st_mode), "native_collector_daily_log")
                if (other.st_dev, other.st_ino) == identity:
                    aliases.append(candidate)
    require(len(aliases) == 1, "native_collector_log_alias")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        opened = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 2
            and (opened.st_dev, opened.st_ino) == identity,
            "native_collector_log_race",
        )
        raw = handle.read(MAX_NATIVE_FILE_BYTES + 1) if read_bytes else b""
        require(len(raw) <= MAX_NATIVE_FILE_BYTES, "native_collector_log_size")
    for candidate in (path, aliases[0]):
        final = candidate.lstat()
        require(
            stat.S_ISREG(final.st_mode)
            and final.st_nlink == 2
            and (final.st_dev, final.st_ino) == identity,
            "native_collector_log_race",
        )
    return identity, raw


class NativeCollector(base.Pilot):
    source_files = SOURCE_FILES
    configuration_relative = "integrations/wazuh_enterprise/manager-lab.conf"

    def load_expected(self, raw_manifest):
        return expected_exports(INPUT, raw_manifest)

    def verify_config(self, raw, internal):
        return verify_configuration(raw, internal)

    def on_started(self):
        pass

    def verify_inputs(self):
        current = expected_exports(INPUT, self.raw_manifest)
        require(current == self.expected, "native_collector_inputs_changed")

    def collection_complete(self, coverage):
        return False

    def __init__(self):
        super().__init__()
        self.deadline = self.started + RUNTIME_SECONDS
        self.evidence_bound = False
        self.last = {"archive": (None, b""), "alert": (None, b"")}
        self.sequence = 0
        self.expected = {}
        self.journal = None
        self.captures = {}
        self.report = {
            "kind": "signalbridge-wazuh-native-bootstrap-v1",
            "status": "failed",
            "failure_code": "not_started",
            "owned_processes_stopped": False,
            "native_runtime_execution_verified": False,
            "genuine_source_execution_verified": False,
            "continuous_delivery_verified": False,
        }

    def prepare(self):
        require(
            sys.platform == "linux" and os.geteuid() == 0 and os.getegid() == 0,
            "isolated_linux_root_required",
        )
        require(
            Path(__file__).resolve()
            == WORKSPACE / "integrations/wazuh_enterprise/native_collector.py"
            and Path.cwd() == WORKSPACE
            and Path("/.dockerenv").is_file(),
            "native_collector_fixed_container_path",
        )
        _directory(EVIDENCE)
        require(
            {p.name for p in EVIDENCE.iterdir()}
            == {"run-context.json", "source-manifest.json", "manifest.json"},
            "native_collector_fresh_evidence",
        )
        context_raw = _file(EVIDENCE / "run-context.json", 4096)
        context = validate_context(context_raw, now=datetime.now(timezone.utc))
        require(
            os.environ.get("SB_WAZUH_ENTERPRISE_RUN") == context["run_id"],
            "native_collector_run_binding",
        )
        source = parse_json(_file(EVIDENCE / "source-manifest.json", 32768))
        require(
            type(source) is dict
            and set(source) == {"files"}
            and type(source["files"]) is dict
            and set(source["files"]) == set(self.source_files),
            "native_collector_source_manifest",
        )
        actual = {
            name: hashlib.sha256(_file(WORKSPACE / name, 256 * 1024)).hexdigest()
            for name in self.source_files
        }
        require(
            actual == source["files"]
            and hashlib.sha256(canonical(actual)).hexdigest() == context["source_sha256"],
            "native_collector_source_changed",
        )
        raw_manifest = _file(EVIDENCE / "manifest.json", 32768)
        require(
            hashlib.sha256(raw_manifest).hexdigest() == context["manifest_sha256"],
            "native_collector_export_manifest_changed",
        )
        self.expected = self.load_expected(raw_manifest)
        self.raw_manifest = raw_manifest
        # This is not a private-ACL, image or kernel attestation. The reviewed
        # host must provide those separately; the report never invents them.
        self.evidence_bound = True
        self.report.update(
            run_id=context["run_id"],
            context_sha256=hashlib.sha256(context_raw).hexdigest(),
            source_sha256=context["source_sha256"],
            manifest_sha256=context["manifest_sha256"],
        )
        self.journal = CaptureJournal(EVIDENCE, context["run_id"], create=True)
        self.captures = {kind: PinnedCapture(self.journal, kind) for kind in self.last}
        kernel = observe_kernel()
        raw_kernel = canonical(kernel) + b"\n"
        self.save("kernel-observed.json", raw_kernel)
        self.report.update(
            kernel_sha256=hashlib.sha256(raw_kernel).hexdigest(),
            kernel_controls=verify_kernel(kernel),
        )
        import grp
        import pwd

        self.wazuh_uid = pwd.getpwnam("wazuh").pw_uid
        gid = grp.getgrnam("wazuh").gr_gid
        os.setgroups([gid])
        base.prepare_collector_directory(self.wazuh_uid, gid)
        package = WORKSPACE / "integrations/wazuh_enterprise"
        conf = _file(WORKSPACE / self.configuration_relative, 32768)
        options = _file(package / "local_internal_options.conf", 4096)
        self.verify_config(conf, options)
        copies = (
            (
                WAZUH / "data_tmp/exclusion/var/ossec/etc/internal_options.conf",
                WAZUH / "etc/internal_options.conf",
            ),
            (WORKSPACE / self.configuration_relative, WAZUH / "etc/ossec.conf"),
            (package / "local_internal_options.conf", WAZUH / "etc/local_internal_options.conf"),
            (
                package / "signalbridge_rules.xml",
                WAZUH / "etc/rules/signalbridge_enterprise_rules.xml",
            ),
        )
        for source_path, destination in copies:
            raw = _file(source_path, 256 * 1024)
            _directory(destination.parent)
            if destination.exists() or destination.is_symlink():
                _file(destination, 256 * 1024)
            with destination.open("wb") as output:
                output.write(raw)
            destination.chmod(0o644)
        for name, raw in (
            ("effective-config.xml", conf),
            ("effective-internal-options.conf", options),
        ):
            self.save(name, raw)
        self.report.update(
            configuration_sha256=hashlib.sha256(conf).hexdigest(),
            internal_options_sha256=hashlib.sha256(options).hexdigest(),
        )

    def save(self, name, raw):
        require(
            self.evidence_bound and re.fullmatch(r"[a-z0-9-]+\.(json|jsonl|xml|conf)", name),
            "native_collector_evidence_name",
        )
        require(len(raw) <= MAX_NATIVE_FILE_BYTES, "native_collector_evidence_limit")
        with (EVIDENCE / name).open("xb") as output:
            require(output.write(raw) == len(raw), "native_collector_short_write")
            output.flush()
            os.fsync(output.fileno())

    def check_budget(self):
        require(time.monotonic() < self.started + HARD_SECONDS, "native_collector_hard_limit")
        for path in self.files:
            require(path.stat().st_size <= base.FILE_LIMIT, "native_collector_process_log_limit")
        for process, _, daemon in self.children:
            if daemon:
                require(process.poll() is None, "native_collector_daemon_exited")
        log = WAZUH / "logs/ossec.log"
        if log.exists():
            info = log.lstat()
            require(
                stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 4 * 1024**2,
                "native_collector_manager_log_limit",
            )
        require(
            sum(p.stat().st_size for p in EVIDENCE.iterdir() if p.is_file()) <= 128 * 1024**2,
            "native_collector_private_output_limit",
        )

    def poll_records(self):
        require(self.journal is not None, "native_collector_capture_unprepared")
        for kind in self.last:
            try:
                identity, _ = current_native_file(kind, read_bytes=False)
            except FileNotFoundError:
                # Native unlink/link handoff can briefly remove the current
                # name. The old descriptor remains pinned; never reset its
                # offset or invent an empty successful capture.
                identity = None
            captured = self.captures[kind]
            if identity is not None:
                folder = "archives" if kind == "archive" else "alerts"
                captured.attach(
                    WAZUH / "logs" / folder / (folder + ".json"), f"{identity[0]:x}:{identity[1]:x}"
                )
            captured.drain()
            self.last[kind] = identity, self.journal.captured(kind, limit=MAX_NATIVE_FILE_BYTES)
        return reconcile(
            self.last["archive"][1],
            self.last["alert"][1],
            self.expected,
            now=datetime.now(timezone.utc),
        )

    def close_capture(self):
        """After daemon shutdown, seal complete files and retain failed prefixes."""
        if self.journal is None:
            return
        failed = False
        try:
            for kind, captured in self.captures.items():
                try:
                    captured.drain(seal=True)
                except (OSError, ValueError, sqlite3.Error):
                    failed = True
                finally:
                    captured.close()
                self.last[kind] = (
                    self.last[kind][0],
                    self.journal.captured(kind, limit=MAX_NATIVE_FILE_BYTES),
                )
            self.journal.verify()
        finally:
            for captured in self.captures.values():
                captured.close()
            self.journal.close()
        require(not failed, "native_collector_capture_incomplete")

    def heartbeat(self, coverage):
        self.sequence += 1
        daemons = [p for p, _, daemon in self.children if daemon]
        value = {
            "run_id": self.report["run_id"],
            "sequence": self.sequence,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "supervisor_children_alive": len(daemons) == len(DAEMONS)
            and all(p.poll() is None for p in daemons),
            "coverage": coverage,
            "native_runtime_execution_verified": False,
        }
        path = EVIDENCE / "heartbeat.json"
        if path.exists():
            _file(path, 32768)
        temporary = EVIDENCE / "heartbeat-next.json"
        with temporary.open("xb") as output:
            output.write(canonical(value) + b"\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)

    def run(self):
        self.prepare()
        # Real native configuration validation; no user-supplied executable.
        log = self.new_log("analysisd-config.log")
        command = subprocess.Popen(
            [str(WAZUH / "bin/wazuh-analysisd"), "-t"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=base.SUBPROCESS_ENV,
            cwd=WAZUH,
            start_new_session=True,
        )
        self.children.append((command, log, False))
        require(command.wait(timeout=8) == 0, "native_collector_config_rejected")
        self.check_budget()
        for daemon in DAEMONS[:2]:
            self.start_daemon(daemon)
            self.wait_socket(base.SOCKETS[daemon])
        self.start_daemon(DAEMONS[2])
        self.on_started()
        coverage = None
        while time.monotonic() < self.deadline:
            self.check_budget()
            # Snapshot inputs are fixed for this bootstrap; change is an
            # incomplete run, not permission to rewrite expected observations.
            self.verify_inputs()
            coverage = self.poll_records()
            self.heartbeat(coverage)
            if self.collection_complete(coverage):
                break
            time.sleep(min(1, max(0, self.deadline - time.monotonic())))
        self.report["coverage"] = coverage
        require(
            coverage and coverage["bootstrap_counts_match"], "native_collector_coverage_incomplete"
        )


def run_main(pilot):
    """Common bounded process shutdown and sealed native capture finalization."""

    def limit(_signal, _frame):
        raise base.PilotFailure("native_collector_hard_limit")

    if sys.platform == "linux":
        signal.signal(signal.SIGALRM, limit)
        signal.alarm(HARD_SECONDS)
    try:
        pilot.run()
        pilot.report["status"], pilot.report["failure_code"] = (
            "counts_matched_pending_host_verification",
            None,
        )
    except (base.PilotFailure, ValueError) as error:
        safe_control = isinstance(error, EnterpriseWazuhError) and re.fullmatch(
            r"(?:native_collector|collector_kernel|native_bootstrap)_[a-z_]{1,64}", str(error)
        )
        pilot.report["failure_code"] = (
            str(error)
            if isinstance(error, base.PilotFailure) or safe_control
            else "native_collector_control_rejected"
        )
    except (OSError, KeyError, TypeError, subprocess.SubprocessError, sqlite3.Error):
        pilot.report["failure_code"] = "native_collector_dependency_or_filesystem_failure"
    finally:
        try:
            pilot.cleanup()
        except (OSError, ValueError, base.PilotFailure):
            pilot.report["owned_processes_stopped"] = False
            pilot.report["failure_code"] = "native_collector_cleanup_failed"
        if sys.platform == "linux":
            signal.alarm(0)
    if not pilot.report["owned_processes_stopped"]:
        pilot.report["failure_code"] = "native_collector_process_shutdown_incomplete"
    if pilot.evidence_bound:
        try:
            if pilot.report["failure_code"] is None:
                pilot.poll_records()
                # Daemons are stopped now; final output must have complete lines.
                final = reconcile(
                    pilot.last["archive"][1],
                    pilot.last["alert"][1],
                    pilot.expected,
                    now=datetime.now(timezone.utc),
                    final=True,
                )
                require(
                    final["bootstrap_counts_match"], "native_collector_final_coverage_incomplete"
                )
                pilot.report["coverage"] = final
        except (OSError, ValueError, sqlite3.Error):
            pilot.report["failure_code"] = "native_collector_final_evidence_failed"
        try:
            pilot.close_capture()
        except (OSError, ValueError, sqlite3.Error):
            pilot.report["failure_code"] = (
                pilot.report["failure_code"] or "native_collector_capture_incomplete"
            )
        if pilot.report["failure_code"]:
            pilot.report["status"] = "failed"
        pilot.report["finished_at"] = datetime.now(timezone.utc).isoformat()
        pilot.report["duration_seconds"] = round(time.monotonic() - pilot.started, 3)
        try:
            for kind, (_, raw) in pilot.last.items():
                pilot.save(f"native-{kind}s.jsonl", raw)
            pilot.save("native-report.json", canonical(pilot.report) + b"\n")
        except (OSError, ValueError):
            pilot.report["failure_code"] = "native_collector_final_evidence_failed"
            pilot.report["status"] = "failed"
    passed = pilot.report["failure_code"] is None and pilot.report["owned_processes_stopped"]
    print(
        canonical(
            {
                "status": pilot.report["status"],
                "owned_processes_stopped": pilot.report["owned_processes_stopped"],
                "native_runtime_execution_verified": False,
                "passed_pending_host_verification": passed,
            }
        ).decode()
    )
    return 0 if passed else 1


def main():
    require(len(sys.argv) == 1, "native_collector_arguments_not_supported")
    return run_main(NativeCollector())


if __name__ == "__main__":
    raise SystemExit(main())
