"""Bounded collector-recovery experiment. Run only inside the fixed pilot."""

import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

if __package__:
    from integrations.wazuh import run_pilot as base
else:
    import run_pilot as base

ARCHIVES = Path("/var/ossec/logs/archives/archives.json")
require = base.require


def archive_bytes():
    # Only the documented current/day hard-link pair inside this fresh container.
    root = ARCHIVES.parent
    for parent in (root, *root.parents):
        require(stat.S_ISDIR(parent.lstat().st_mode), "archive_directory")
    try:
        info = ARCHIVES.lstat()
    except FileNotFoundError:
        return b""
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 2 and info.st_size <= base.FILE_LIMIT,
        "archive_file",
    )
    daily = []
    entries = list(root.iterdir())
    require(len(entries) <= 16, "archive_directory_bound")
    for year in entries:
        if not (year.name.isdigit() and len(year.name) == 4):
            continue
        require(stat.S_ISDIR(year.lstat().st_mode), "archive_year")
        months = list(year.iterdir())
        require(len(months) <= 12, "archive_month_bound")
        for month in months:
            require(stat.S_ISDIR(month.lstat().st_mode), "archive_month")
            paths = list(month.iterdir())
            require(len(paths) <= 64, "archive_day_bound")
            for path in paths:
                if not path.name.startswith("ossec-archive-") or not path.name.endswith(".json"):
                    continue
                meta = path.lstat()
                require(stat.S_ISREG(meta.st_mode), "archive_link")
                if (meta.st_dev, meta.st_ino) == (info.st_dev, info.st_ino):
                    daily.append(path)
    require(len(daily) == 1, "archive_hardlink_identity")
    descriptor = os.open(ARCHIVES, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        require(
            (opened.st_dev, opened.st_ino, opened.st_nlink) == (info.st_dev, info.st_ino, 2),
            "archive_race",
        )
        raw = handle.read(base.FILE_LIMIT + 1)
    require(len(raw) <= base.FILE_LIMIT, "archive_size")
    for path in (ARCHIVES, daily[0]):
        current = path.lstat()
        require(
            (current.st_dev, current.st_ino, current.st_nlink) == (info.st_dev, info.st_ino, 2),
            "archive_rotation",
        )
    return raw


def reconcile(raw, expected):
    require(type(raw) is bytes and len(raw) <= base.FILE_LIMIT, "archive_size")
    counts = Counter()
    for line in raw.split(b"\n")[:-1]:
        if not line:
            continue
        row = base.prep.parse_json(line.decode("utf8"))
        require(type(row) is dict, "archive_record")
        if row.get("location") != str(base.INPUT):
            # Any unrelated archive input violates this single-source experiment.
            raise base.PilotFailure("foreign_archive_location")
        require(row.get("decoder", {}).get("name") == "json", "archive_decoder")
        record = base.prep.parse_json(row.get("full_log", ""))
        require(type(record) is dict and set(record) == {"signalbridge"}, "archive_input_shape")
        data = row.get("data", {}).get("signalbridge")
        require(
            type(data) is dict and set(data) == base.prep.EXPORT_FIELDS, "archive_decoded_shape"
        )
        normalized = {key: str(value) for key, value in record["signalbridge"].items()}
        require(
            {key: str(value) for key, value in data.items()} == normalized,
            "archive_decoded_mismatch",
        )
        identity = record["signalbridge"].get("event_id")
        require(identity in expected and record == expected[identity], "archive_input_mismatch")
        counts[identity] += 1
        require(counts[identity] <= 3 and sum(counts.values()) <= 32, "archive_duplicate_bound")
    return counts


class RecoveryPilot(base.Pilot):
    def __init__(self):
        super().__init__()
        self.launches = Counter()
        self.expected = {}
        self.alert_expectations = {}
        self.report.update(
            kind="signalbridge-wazuh-collector-recovery",
            scope="bounded_synthetic_collector_recovery",
            recovery_phases=[],
        )

    def prepare(self):
        super().prepare()
        require(Path(__file__).resolve() == base.PILOT / "run_delivery.py", "driver_path")
        conf = base.WAZUH / "etc/ossec.conf"
        original = base.regular_file(conf)
        require(
            original.count(b"<logall_json>no</logall_json>") == 1
            and original.count(b"<only-future-events>yes</only-future-events>") == 1,
            "configuration_shape",
        )
        changed = original.replace(
            b"<logall_json>no</logall_json>", b"<logall_json>yes</logall_json>"
        ).replace(
            b"<only-future-events>yes</only-future-events>",
            b'<only-future-events max-size="1MB">no</only-future-events>',
        )
        # The entire effective configuration is retained; only these two reviewed settings change.
        with conf.open("wb") as handle:
            handle.write(changed)
        with (base.EVIDENCE / "effective-config.xml").open("xb") as handle:
            handle.write(changed)
        self.report["effective_config_sha256"] = hashlib.sha256(changed).hexdigest()
        self.report["driver_sha256"] = hashlib.sha256(base.regular_file(Path(__file__))).hexdigest()

    def start_daemon(self, name):
        require(name in base.DAEMONS, "unexpected_daemon")
        self.launches[name] += 1
        log = self.new_log(name + "-" + str(self.launches[name]) + ".log")
        process = subprocess.Popen(
            [str(base.WAZUH / "bin" / name), "-f"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=base.SUBPROCESS_ENV,
            cwd=base.WAZUH,
            start_new_session=True,
        )
        self.children.append((process, log, True))
        return process

    def stop_collector(self, process):
        self.signal_process(process, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            raise base.PilotFailure("collector_stop_timeout") from error
        # Pinned Wazuh HandleSIG calls exit(1), then its registered save hook.
        # Require the expected signal log AND the actual persisted input checkpoint.
        log_path = base.EVIDENCE / (
            "wazuh-logcollector-" + str(self.launches["wazuh-logcollector"]) + ".log"
        )
        log = base.regular_file(log_path)
        require(
            process.returncode == 1
            and b"SIGNAL [(15)-(Terminated)] Received. Exit Cleaning..." in log,
            "collector_stop_failed",
        )
        saved = base.regular_file(base.COLLECTOR_DIRECTORY / "file_status.json")
        checkpoint = base.prep.parse_json(saved.decode("utf8"))
        require(
            type(checkpoint) is dict
            and set(checkpoint) == {"files"}
            and type(checkpoint["files"]) is list
            and len(checkpoint["files"]) == 1,
            "checkpoint_shape",
        )
        item = checkpoint["files"][0]
        payload = base.regular_file(base.INPUT)
        require(
            item
            == {
                "path": str(base.INPUT),
                "offset": str(len(payload)),
                "hash": hashlib.sha1(payload, usedforsecurity=False).hexdigest(),
            },
            "checkpoint_content",
        )
        self.report.setdefault("collector_stops", []).append(
            {
                "exit_code": process.returncode,
                "offset": len(payload),
                "checkpoint_sha256": hashlib.sha256(saved).hexdigest(),
            }
        )
        self.children = [
            (p, log, False if p is process else daemon) for p, log, daemon in self.children
        ]

    def row(self, index, name):
        packet = base.prep.parse_json(self.lines[index])
        packet["signalbridge"]["event_id"] = base.run_context.event_id(self.report["run_id"], name)
        base.prep.validate_export(packet, self.values)
        identity = packet["signalbridge"]["event_id"]
        require(identity not in self.expected, "duplicate_fixture")
        self.expected[identity] = packet
        case = self.cases[index]
        if case["expected_alert"]:
            self.alert_expectations[identity] = (case["expected_rule"], case["expected_level"])
        return (json.dumps(packet, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")

    def append(self, raw):
        require(type(raw) is bytes and len(raw) <= 8192, "append_bound")
        info = base.INPUT.lstat()
        require(
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size < 16384, "input_file"
        )
        with base.INPUT.open("ab") as handle:
            require(handle.write(raw) == len(raw), "short_append")
            handle.flush()
            os.fsync(handle.fileno())

    def observe(self, phase, target, quiet=2):
        until = min(self.deadline, time.monotonic() + 25)
        stable_at = None
        previous = None
        while time.monotonic() < until:
            self.check_budget()
            raw = archive_bytes()
            counts = reconcile(raw, self.expected)
            alerts = base.alert_file(optional=True)
            observed = base.collection_observations(
                alerts, self.alert_expectations, set(self.expected)
            )
            complete = (
                set(counts) == target
                and set(observed) == (target & set(self.alert_expectations))
                and raw.endswith(b"\n")
            )
            state = (raw, alerts)
            if complete:
                if previous != state:
                    stable_at = time.monotonic()
                if stable_at is not None and time.monotonic() - stable_at >= quiet:
                    self.report["recovery_phases"].append(
                        {
                            "phase": phase,
                            "unique_archived_records": len(counts),
                            "archive_copies": sum(counts.values()),
                            "duplicate_copies": sum(counts.values()) - len(counts),
                            "alert_count": len(observed),
                            "quiet_seconds": quiet,
                            "archives_sha256": hashlib.sha256(raw).hexdigest(),
                        }
                    )
                    return raw, alerts
            else:
                stable_at = None
            previous = state
            time.sleep(0.25)
        raise base.PilotFailure("recovery_incomplete_" + phase)

    def collect(self):
        require(not archive_bytes() and not base.alert_file(optional=True), "stale_records")
        collector = self.start_daemon("wazuh-logcollector")
        limit = time.monotonic() + 20
        while base.collector_state() is None:
            self.check_budget()
            require(time.monotonic() < limit, "collector_readiness")
            time.sleep(0.25)
        require(
            base.collector_state() == {"events": 0, "processed_bytes": 0, "drops": 0},
            "initial_collector_state",
        )
        self.append(self.row(2, "live-alert") + self.row(12, "live-control"))
        self.observe("live_append", set(self.expected))
        self.stop_collector(collector)
        self.append(self.row(6, "downtime-alert") + self.row(12, "downtime-control"))
        collector = self.start_daemon("wazuh-logcollector")
        self.observe("graceful_restart_backlog", set(self.expected))
        before = set(self.expected)
        partial = self.row(2, "split-line")
        midpoint = len(partial) // 2
        self.append(partial[:midpoint])
        until = time.monotonic() + 3
        while time.monotonic() < until:
            self.check_budget()
            require(
                set(reconcile(archive_bytes(), self.expected)) == before, "partial_line_consumed"
            )
            time.sleep(0.25)
        self.append(partial[midpoint:])
        self.observe("split_line_completed", set(self.expected))
        self.stop_collector(collector)
        retained = base.INPUT.with_name("retained-before-rotation.jsonl")
        require(not retained.exists() and not retained.is_symlink(), "rotation_collision")
        # Both fixed paths are in the fresh synthetic container directory; no host file is renamed.
        require(
            base.INPUT.parent == Path("/signalbridge/input") and not base.INPUT.parent.is_symlink(),
            "rotation_scope",
        )
        base.INPUT.rename(retained)
        with base.INPUT.open("xb"):
            pass
        base.INPUT.chmod(0o644)
        self.append(self.row(2, "rotated-alert") + self.row(12, "rotated-control"))
        collector = self.start_daemon("wazuh-logcollector")
        raw, alerts = self.observe("rotation_while_stopped", set(self.expected))
        for name, body in [
            ("archives.jsonl", raw),
            ("alerts.jsonl", alerts),
            ("expected-inputs.json", json.dumps(self.expected, sort_keys=True).encode()),
        ]:
            with (base.EVIDENCE / name).open("xb") as handle:
                handle.write(body)
        self.report.update(
            collection_verified=True,
            recovery_verified=True,
            unique_input_count=7,
            partial_line_hold_seconds=3,
            collector_restart_count=2,
            archives_sha256=hashlib.sha256(raw).hexdigest(),
            alerts_sha256=hashlib.sha256(alerts).hexdigest(),
        )


def main():
    require(len(sys.argv) == 1, "no_arguments")
    pilot = RecoveryPilot()

    def alarm(_signal, _frame):
        raise base.PilotFailure("hard_runtime_limit")

    signal.signal(signal.SIGALRM, alarm)
    signal.alarm(base.TOTAL_SECONDS)
    try:
        pilot.run()
        pilot.report["failure_code"] = None
    except base.PilotFailure as error:
        pilot.report["failure_code"] = str(error)
    except Exception as error:
        pilot.report["failure_code"] = type(error).__name__
    finally:
        try:
            pilot.cleanup()
        except Exception:
            pilot.report["failure_code"] = "cleanup_failure"
        signal.alarm(0)
    pilot.report["finished_at"] = datetime.now(timezone.utc).isoformat()
    pilot.report["duration_seconds"] = round(time.monotonic() - pilot.started, 3)
    if (
        pilot.report["failure_code"] is None
        and pilot.report.get("recovery_verified")
        and pilot.report["owned_processes_stopped"]
    ):
        pilot.report["status"] = "passed"
    with (base.EVIDENCE / "recovery-result.json").open("x", encoding="utf8") as handle:
        json.dump(pilot.report, handle, indent=2, sort_keys=True)
    print(
        json.dumps(
            {key: pilot.report[key] for key in ("status", "failure_code", "duration_seconds")}
        )
    )
    return 0 if pilot.report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
