"""Fixed, bounded synthetic Wazuh pilot. Only the parent launches this in Docker.

No command-line options, network requests, shell commands, or stock /init.
Raw subprocess output stays in the dedicated private /evidence mount.
"""

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path

if __package__:
    from . import run_context
    from . import verify_static as prep
else:
    import run_context
    import verify_static as prep

PILOT = Path("/pilot")
EVIDENCE = Path("/evidence")
WAZUH = Path("/var/ossec")
INPUT = Path("/signalbridge/input/events.jsonl")
ALERTS = WAZUH / "logs/alerts/alerts.json"
COLLECTOR_DIRECTORY = WAZUH / "queue/logcollector"
COLLECTOR_STATE = WAZUH / "var/run/wazuh-logcollector.state"
SOCKETS = {"wazuh-db": WAZUH / "queue/db/wdb", "wazuh-analysisd": WAZUH / "queue/sockets/logtest"}
DAEMONS = ("wazuh-db", "wazuh-analysisd", "wazuh-logcollector")
SUBPROCESS_ENV = {
    "PATH": "/var/ossec/bin:/usr/bin:/bin",
    "HOME": "/var/ossec",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}
FILE_LIMIT = 1024 * 1024
COMMAND_LIMIT = 128 * 1024
NORMAL_SECONDS = 165
TOTAL_SECONDS = 180
CUSTOM_IDS = {str(n) for n in range(100200, 100206)}
SENTINEL_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff"


class PilotFailure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise PilotFailure(code)


def parse_logtest_output(output, expected_rule, expected_level, returncode):
    """Parse only the official CLI's phase sections; input text cannot supply them."""
    require(len(output) <= COMMAND_LIMIT, "logtest_output_limit")
    text = output.decode("utf8", errors="strict")
    require("** Wazuh-logtest error" not in text, "logtest_execution_error")
    require(text.count("**Phase 2: Completed decoding.") == 1, "logtest_decoding_missing")
    phase2 = text.split("**Phase 2: Completed decoding.", 1)[1].split("**Phase 3:", 1)[0]
    names = re.findall(r"^\s*name: '([^']+)'\s*$", phase2, re.M)
    require(names == ["json"], "logtest_wrong_decoder")
    phase3 = text.split("**Phase 3:", 1)[1] if "**Phase 3:" in text else ""
    ids = re.findall(r"^\s*id: '([0-9]+)'\s*$", phase3, re.M)
    levels = re.findall(r"^\s*level: '([0-9]+)'\s*$", phase3, re.M)
    require(len(ids) <= 1 and len(levels) == len(ids), "logtest_ambiguous_rule")
    observed_rule = ids[0] if ids else None
    observed_level = int(levels[0]) if levels else None
    require(returncode == 0, "logtest_nonzero_exit")
    if expected_rule is None:
        require(observed_rule not in CUSTOM_IDS, "logtest_unexpected_custom_rule")
    else:
        require(
            observed_rule == expected_rule and observed_level == expected_level,
            "logtest_rule_mismatch",
        )
    return {"observed_rule": observed_rule, "observed_level": observed_level, "decoder": "json"}


def collection_observations(data, expected_by_event, all_event_ids):
    """Validate every custom alert, not only the favorable ones."""
    require(len(data) <= FILE_LIMIT, "alerts_output_limit")
    seen = {}
    # A live append may have an incomplete final line; wait for its newline.
    lines = data.split(b"\n")[:-1]
    for line in lines:
        if not line:
            continue
        try:
            row = prep.parse_json(line.decode("utf8"))
        except (ValueError, UnicodeError) as exc:
            raise PilotFailure("invalid_alert_json") from exc
        require(type(row) is dict and type(row.get("rule", {})) is dict, "invalid_alert_structure")
        rule = row.get("rule", {})
        rule_id = str(rule.get("id", ""))
        if rule_id not in CUSTOM_IDS:
            continue
        require(
            type(row.get("data")) is dict and type(row["data"].get("signalbridge")) is dict,
            "invalid_alert_structure",
        )
        event = row["data"]["signalbridge"]
        event_id = event.get("event_id")
        require(event_id in all_event_ids, "unexpected_custom_event")
        require(event_id in expected_by_event, "negative_control_alerted")
        require(event_id not in seen, "duplicate_custom_alert")
        expected_rule, expected_level = expected_by_event[event_id]
        require(
            rule_id == expected_rule and rule.get("level") == expected_level,
            "collection_rule_mismatch",
        )
        require("full_log" not in row, "raw_log_not_suppressed")
        require(set(event) == prep.EXPORT_FIELDS, "unexpected_decoded_fields")
        seen[event_id] = rule_id
    return seen


def regular_file(path, *, limit=FILE_LIMIT, optional=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if optional:
            return b""
        raise PilotFailure("required_file_missing") from None
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "unsafe_file")
    require(info.st_size <= limit, "file_output_limit")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    require(len(data) <= limit, "file_output_limit")
    return data


def alert_file(*, optional=False):
    """Accept only Wazuh's documented current/daily regular-file hard-link pair."""
    root = ALERTS.parent

    def directory(path):
        require(stat.S_ISDIR(path.lstat().st_mode), "unsafe_alert_directory")

    def bounded_entries(path, maximum):
        entries = []
        with os.scandir(path) as iterator:
            for entry in iterator:
                require(len(entries) < maximum, "alert_directory_limit")
                entries.append(Path(entry.path))
        return entries

    for parent in (root, *root.parents):
        directory(parent)
    try:
        info = ALERTS.lstat()
    except FileNotFoundError:
        if optional:
            return b""
        raise PilotFailure("required_alert_file_missing") from None
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 2, "unsafe_alert_hardlink")
    require(info.st_size <= FILE_LIMIT, "alerts_output_limit")
    identity = (info.st_dev, info.st_ino)
    months = {
        name: index
        for index, name in enumerate(
            ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
        )
    }
    matches = []
    years = [entry for entry in bounded_entries(root, 16) if re.fullmatch(r"[0-9]{4}", entry.name)]
    require(len(years) <= 4, "alert_directory_limit")
    for year in years:
        directory(year)
        for month in bounded_entries(year, 12):
            require(month.name in months, "unexpected_alert_month")
            directory(month)
            for candidate in bounded_entries(month, 64):
                name = re.fullmatch(r"ossec-alerts-([0-9]{2})(?:-[0-9]{3})?\.json", candidate.name)
                if name is None:
                    continue
                try:
                    date(int(year.name), months[month.name], int(name.group(1)))
                except ValueError as exc:
                    raise PilotFailure("unexpected_alert_date") from exc
                candidate_info = candidate.lstat()
                require(stat.S_ISREG(candidate_info.st_mode), "unsafe_daily_alert_file")
                if (candidate_info.st_dev, candidate_info.st_ino) == identity:
                    require(candidate_info.st_nlink == 2, "unsafe_alert_hardlink")
                    matches.append(candidate)
    require(len(matches) == 1, "unverified_alert_hardlink")
    daily = matches[0]
    descriptor = os.open(ALERTS, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_nlink == 2
            and (opened.st_dev, opened.st_ino) == identity,
            "alert_rotation_race",
        )
        data = handle.read(FILE_LIMIT + 1)
        after = os.fstat(handle.fileno())
    require(len(data) <= FILE_LIMIT and after.st_size <= FILE_LIMIT, "alerts_output_limit")
    for path in (ALERTS, daily):
        current = path.lstat()
        require(
            stat.S_ISREG(current.st_mode)
            and current.st_nlink == 2
            and (current.st_dev, current.st_ino) == identity,
            "alert_rotation_race",
        )
    for parent in (daily.parent, daily.parent.parent, root, *root.parents):
        directory(parent)
    return data


def prepare_collector_directory(uid, gid):
    """Allow only the packaged collector group to write its empty private queue."""
    require((uid, gid) == (999, 999), "unexpected_packaged_identity")
    require(os.geteuid() == 0 and os.getegid() == 0, "unexpected_preparation_identity")
    for parent in (COLLECTOR_DIRECTORY, *COLLECTOR_DIRECTORY.parents):
        require(stat.S_ISDIR(parent.lstat().st_mode), "unsafe_collector_directory")
    before = COLLECTOR_DIRECTORY.lstat()
    require(
        (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (uid, gid, 0o750),
        "unexpected_collector_directory_permissions",
    )
    descriptor = os.open(COLLECTOR_DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        require(
            (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino)
            and stat.S_ISDIR(opened.st_mode)
            and not os.listdir(descriptor),
            "unsafe_collector_directory",
        )
        try:
            os.setegid(gid)
            os.seteuid(uid)
            # fchmod acts on the already verified container-only inode. No CHOWN,
            # DAC override or FOWNER capability, and no host bind, is involved.
            os.fchmod(descriptor, 0o770)
        finally:
            os.seteuid(0)
            os.setegid(0)
        after = os.fstat(descriptor)
        current = COLLECTOR_DIRECTORY.lstat()
        require(
            (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)) == (uid, gid, 0o770)
            and (current.st_dev, current.st_ino) == (before.st_dev, before.st_ino),
            "collector_directory_permission_check_failed",
        )
    finally:
        os.close(descriptor)


def collector_observations(data):
    """Read the real collector's global counts, never an inferred file offset."""
    require(len(data) <= COMMAND_LIMIT, "collector_state_output_limit")
    # Upstream overwrites the state file in place once a second. An incomplete
    # final write is pending, not a successful observation or a relaxed parse.
    if not data.endswith(b"\n"):
        return None
    try:
        row = prep.parse_json(data.decode("utf8"))
    except (ValueError, UnicodeError) as exc:
        raise PilotFailure("invalid_collector_state_json") from exc
    require(type(row) is dict and set(row) == {"global", "interval"}, "invalid_collector_state")
    section = row["global"]
    require(type(section) is dict and type(section.get("files")) is list, "invalid_collector_state")
    require(len(section["files"]) == 1, "unexpected_collector_files")
    entry = section["files"][0]
    require(
        type(entry) is dict and entry.get("location") == str(INPUT), "unexpected_collector_file"
    )
    for name in ("events", "bytes"):
        require(
            type(entry.get(name)) is int and 0 <= entry[name] <= FILE_LIMIT,
            "invalid_collector_count",
        )
    targets = entry.get("targets")
    require(
        type(targets) is list
        and len(targets) == 1
        and type(targets[0]) is dict
        and set(targets[0]) == {"name", "drops"}
        and targets[0]["name"] == "agent"
        and type(targets[0]["drops"]) is int
        and targets[0]["drops"] == 0,
        "collector_drops_or_target",
    )
    return {"events": entry["events"], "processed_bytes": entry["bytes"], "drops": 0}


def collector_state():
    for parent in (COLLECTOR_STATE.parent, *COLLECTOR_STATE.parent.parents):
        require(stat.S_ISDIR(parent.lstat().st_mode), "unsafe_collector_state_directory")
    return collector_observations(regular_file(COLLECTOR_STATE, limit=COMMAND_LIMIT, optional=True))


class Pilot:
    def __init__(self):
        self.started = time.monotonic()
        self.deadline = self.started + NORMAL_SECONDS
        self.children = []
        self.files = []
        self.wazuh_uid = None
        self.report = {
            "schema_version": 2,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "tool": "wazuh",
            "status": "failed",
            "scope": "isolated_synthetic_manager_pilot",
            "synthetic_only": True,
            "logtest_verified": False,
            "collection_verified": False,
            "expected_logtest_case_count": 27,
            "logtest_cases": [],
            "collector": {"verified": False},
            "owned_processes_stopped": False,
            "failure_code": "not_started",
        }

    def check_budget(self):
        require(time.monotonic() < self.deadline, "runtime_budget_exceeded")
        for path in self.files:
            require(path.stat().st_size <= FILE_LIMIT, "process_output_limit")
        for process, _, daemon in self.children:
            if daemon:
                require(process.poll() is None, "daemon_exited")
        for path in (WAZUH / "logs/ossec.log", ALERTS):
            if path.exists():
                require(path.stat().st_size <= FILE_LIMIT, "wazuh_output_limit")

    def new_log(self, name):
        require(re.fullmatch(r"[a-z0-9_-]+\.log", name) is not None, "invalid_log_name")
        path = EVIDENCE / name
        handle = path.open("xb", buffering=0)
        self.files.append(path)
        return handle

    def start_daemon(self, name):
        require(name in DAEMONS, "unexpected_daemon")
        log = self.new_log(name + ".log")
        process = subprocess.Popen(
            [str(WAZUH / "bin" / name), "-f"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=SUBPROCESS_ENV,
            cwd=WAZUH,
            start_new_session=True,
        )
        self.children.append((process, log, True))
        return process

    def signal_process(self, process, signum):
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signum)
        except PermissionError:
            # SETUID is already required by analysisd; no CAP_KILL expansion.
            require(self.wazuh_uid is not None, "cleanup_identity_missing")
            try:
                os.seteuid(self.wazuh_uid)
                try:
                    os.killpg(process.pid, signum)
                except ProcessLookupError:
                    pass
            finally:
                os.seteuid(0)
        except ProcessLookupError:
            pass

    def command(self, args, input_data, log_name, timeout=8):
        require(args[0] == str(WAZUH / "bin/wazuh-logtest"), "unexpected_command")
        self.check_budget()
        log = self.new_log(log_name)
        process = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=SUBPROCESS_ENV,
            cwd=WAZUH,
            start_new_session=True,
        )
        self.children.append((process, log, False))
        output = bytearray()
        limit = min(self.deadline, time.monotonic() + timeout)
        selector = selectors.DefaultSelector()
        try:
            process.stdin.write(input_data)
            process.stdin.close()
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                self.check_budget()
                require(time.monotonic() < limit, "logtest_timeout")
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    require(len(output) + len(chunk) <= COMMAND_LIMIT, "logtest_output_limit")
                    output.extend(chunk)
                    log.write(chunk)
            code = process.wait(timeout=max(0.1, limit - time.monotonic()))
            return code, bytes(output)
        finally:
            selector.close()
            if process.poll() is None:
                self.signal_process(process, signal.SIGTERM)
            process.stdout.close()
            log.close()

    def wait_socket(self, path):
        limit = min(self.deadline, time.monotonic() + 20)
        while time.monotonic() < limit:
            self.check_budget()
            try:
                if stat.S_ISSOCK(path.stat().st_mode):
                    return
            except FileNotFoundError:
                pass
            time.sleep(0.1)
        raise PilotFailure("daemon_readiness_timeout")

    def prepare(self):
        require(sys.platform == "linux" and os.geteuid() == 0, "isolated_linux_root_required")
        require(
            Path(__file__).resolve() == PILOT / "run_pilot.py" and Path.cwd() == PILOT,
            "fixed_runtime_path_required",
        )
        require(
            EVIDENCE.is_dir()
            and not EVIDENCE.is_symlink()
            and {p.name for p in EVIDENCE.iterdir()} == {"run-context.json"},
            "fresh_evidence_directory_required",
        )
        context_raw = regular_file(
            EVIDENCE / "run-context.json", limit=run_context.MAX_CONTEXT_BYTES
        )
        context = run_context.parse(context_raw)
        age = (
            run_context.utc_time(self.report["started_at"])
            - run_context.utc_time(context["prepared_at"])
        ).total_seconds()
        require(0 <= age <= 900, "run_context_expired_or_future")
        self.report.update(
            run_id=context["run_id"], context_sha256=hashlib.sha256(context_raw).hexdigest()
        )
        # Membership in the packaged group permits reading analyzer-owned logs.
        import grp
        import pwd

        self.wazuh_uid = pwd.getpwnam("wazuh").pw_uid
        wazuh_gid = grp.getgrnam("wazuh").gr_gid
        os.setgroups([wazuh_gid])
        prepare_collector_directory(self.wazuh_uid, wazuh_gid)
        hashes = {}
        for relative in (
            "run_pilot.py",
            "run_context.py",
            "verify_static.py",
            "event-contract.json",
            "manager-lab.conf",
            "signalbridge_rules.xml",
            "image-lock.json",
            "fixtures/events.jsonl",
            "fixtures/expectations.json",
        ):
            data = regular_file(PILOT / relative, limit=prep.MAX_BYTES)
            hashes[relative] = hashlib.sha256(data).hexdigest()
        self.report["source_sha256"] = hashes
        prep.verify_config(prep.parse_xml(regular_file(PILOT / "manager-lab.conf")))
        prep.read_rules(regular_file(PILOT / "signalbridge_rules.xml"))
        copies = [
            (
                WAZUH / "data_tmp/exclusion/var/ossec/etc/internal_options.conf",
                WAZUH / "etc/internal_options.conf",
            ),
            (PILOT / "manager-lab.conf", WAZUH / "etc/ossec.conf"),
            (PILOT / "signalbridge_rules.xml", WAZUH / "etc/rules/signalbridge_rules.xml"),
        ]
        for source, target in copies:
            data = regular_file(source, limit=prep.MAX_BYTES)
            require(target.parent.is_dir() and not target.is_symlink(), "unsafe_runtime_copy")
            # Existing packaged config is root-owned; never change host ownership.
            with target.open("wb") as handle:
                handle.write(data)
            target.chmod(0o644)
        # Official internal option, only in this container's disposable config.
        options = WAZUH / "etc/local_internal_options.conf"
        if options.exists() or options.is_symlink():
            original = regular_file(options, limit=prep.MAX_BYTES)
            require(
                all(
                    not line.strip() or line.lstrip().startswith(b"#")
                    for line in original.splitlines()
                ),
                "unexpected_local_internal_options",
            )
        with options.open("wb") as handle:
            handle.write(b"logcollector.state_interval=1\n")
        options.chmod(0o644)
        INPUT.parent.mkdir(parents=True, exist_ok=False)
        with INPUT.open("xb"):
            pass
        INPUT.chmod(0o644)
        values = prep.parse_json(regular_file(PILOT / "event-contract.json").decode())
        self.values = {key: set(value) for key, value in values.items()}
        self.lines = regular_file(PILOT / "fixtures/events.jsonl").decode().splitlines()
        self.cases = prep.parse_json(regular_file(PILOT / "fixtures/expectations.json").decode())[
            "cases"
        ]
        require(len(self.lines) == len(self.cases) == 27, "fixture_inventory_changed")
        require([c["line"] for c in self.cases] == list(range(1, 28)), "fixture_order_changed")
        for line, case in zip(self.lines, self.cases, strict=True):
            require(re.fullmatch(r"[a-z0-9_]{1,64}", case["id"]) is not None, "invalid_case_id")
            require(
                case["expected_rule"] is None or case["expected_rule"] in CUSTOM_IDS,
                "invalid_expected_rule",
            )
            require(
                case["expected_level"] is None
                or type(case["expected_level"]) is int
                and 0 <= case["expected_level"] <= 15,
                "invalid_expected_level",
            )
            valid = True
            try:
                prep.validate_export(prep.parse_json(line), self.values)
            except prep.PreparationError:
                valid = False
            require(valid is case["export_contract_valid"], "fixture_schema_changed")

    def run(self):
        self.prepare()
        for daemon in DAEMONS[:2]:
            self.start_daemon(daemon)
            self.wait_socket(SOCKETS[daemon])
        code, output = self.command([str(WAZUH / "bin/wazuh-logtest"), "-V"], b"", "version.log")
        require(code == 0 and b"Wazuh v4.14.8" in output, "runtime_version_mismatch")
        self.report["runtime_version"] = "4.14.8"
        for index, (line, case) in enumerate(zip(self.lines, self.cases, strict=True), 1):
            entry = {
                "id": case["id"],
                "status": "failed",
                "expected_rule": case["expected_rule"],
                "expected_level": case["expected_level"],
            }
            self.report["logtest_cases"].append(entry)
            args = [str(WAZUH / "bin/wazuh-logtest")]
            if case["expected_rule"] is not None:
                args += ["-U", f"{case['expected_rule']}:{case['expected_level']}:json"]
            code, output = self.command(args, (line + "\n").encode(), f"logtest-{index:02d}.log")
            entry.update(
                parse_logtest_output(output, case["expected_rule"], case["expected_level"], code)
            )
            entry["status"] = "passed"
        self.report["logtest_verified"] = True
        self.collect()

    def collect(self):
        expected = {}
        all_ids = set()
        batch = []
        for line, case in zip(self.lines, self.cases, strict=True):
            if not case["export_contract_valid"]:
                continue
            record = prep.parse_json(line)
            event = prep.validate_export(record, self.values)
            event["event_id"] = run_context.event_id(self.report["run_id"], event["event_id"])
            all_ids.add(event["event_id"])
            batch.append(json.dumps(record, separators=(",", ":"), ensure_ascii=False))
            if case["expected_alert"]:
                expected[event["event_id"]] = (case["expected_rule"], case["expected_level"])
        sentinel = prep.parse_json(self.lines[2])
        sentinel_id = run_context.event_id(self.report["run_id"], SENTINEL_ID)
        sentinel["signalbridge"]["event_id"] = sentinel_id
        prep.validate_export(sentinel, self.values)
        batch.append(json.dumps(sentinel, separators=(",", ":")))
        all_ids.add(sentinel_id)
        expected[sentinel_id] = ("100202", 5)
        require(
            len(batch) == 19 and len(all_ids) == 19 and len(expected) == 12,
            "collection_inventory_changed",
        )
        require(
            not collection_observations(alert_file(optional=True), {}, set()),
            "stale_custom_alerts",
        )
        self.start_daemon("wazuh-logcollector")
        ready_limit = min(self.deadline, time.monotonic() + 20)
        baseline = None
        while baseline is None:
            self.check_budget()
            require(time.monotonic() < ready_limit, "collector_readiness_timeout")
            baseline = collector_state()
            if baseline is None:
                time.sleep(1)
        require(
            baseline == {"events": 0, "processed_bytes": 0, "drops": 0},
            "collector_not_at_empty_input",
        )
        payload = ("\n".join(batch) + "\n").encode()
        # read_json.c compacts JSON, then accounts strlen(json)+1 (terminating
        # NUL). Here each compact UTF-8 record also has exactly one newline.
        expected_bytes = sum(len(line.encode("utf8")) + 1 for line in batch)
        require(len(payload) <= prep.MAX_BYTES, "collection_input_limit")
        with INPUT.open("ab") as handle:
            handle.write(payload)
            handle.flush()
        self.report["collector"] = {
            "verified": False,
            "input_count": 19,
            "fixture_input_count": 18,
            "tail_sentinel_count": 1,
            "expected_alert_count": 12,
            "negative_control_count": 7,
            "batch_sha256": hashlib.sha256(payload).hexdigest(),
            "quiet_window_seconds": 3,
            "expected_processed_bytes": expected_bytes,
            "state_interval_seconds": 1,
        }
        complete_since = None
        last_data = None
        limit = min(self.deadline, time.monotonic() + 40)
        while time.monotonic() < limit:
            self.check_budget()
            data = alert_file(optional=True)
            observed = collection_observations(data, expected, all_ids)
            counters = collector_state()
            if counters is not None:
                require(
                    counters["events"] <= 19 and counters["processed_bytes"] <= expected_bytes,
                    "unexpected_collector_counts",
                )
            complete = (
                data.endswith(b"\n")
                and len(observed) == len(expected)
                and counters == {"events": 19, "processed_bytes": expected_bytes, "drops": 0}
            )
            if complete:
                if complete_since is None or data != last_data:
                    complete_since = time.monotonic()
                if time.monotonic() - complete_since >= 3:
                    with (EVIDENCE / "alerts.jsonl").open("xb") as handle:
                        handle.write(data)
                    self.report["alerts_sha256"] = hashlib.sha256(data).hexdigest()
                    self.report["collector"].update(
                        verified=True,
                        observed_alert_count=len(observed),
                        collector_counts_verified=True,
                        observed_event_count=counters["events"],
                        observed_processed_bytes=counters["processed_bytes"],
                        observed_drop_count=counters["drops"],
                        duplicate_count=0,
                        unexpected_custom_alert_count=0,
                    )
                    self.report["collection_verified"] = True
                    return
            else:
                complete_since = None
            last_data = data
            time.sleep(1)
        raise PilotFailure("collection_timeout_or_incomplete")

    def cleanup(self):
        processes = list(reversed(self.children))
        for process, _, _ in processes:
            self.signal_process(process, signal.SIGTERM)
        stop_by = time.monotonic() + 5
        while any(p.poll() is None for p, _, _ in processes) and time.monotonic() < stop_by:
            time.sleep(0.1)
        for process, log, _ in processes:
            if process.poll() is None:
                self.signal_process(process, signal.SIGKILL)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            if not log.closed:
                log.close()
        self.report["owned_processes_stopped"] = all(p.poll() is not None for p, _, _ in processes)


def main():
    require(len(sys.argv) == 1, "arguments_not_supported")
    pilot = Pilot()

    def time_limit(_signal, _frame):
        raise PilotFailure("hard_runtime_limit")

    signal.signal(signal.SIGALRM, time_limit)
    signal.alarm(TOTAL_SECONDS)
    try:
        pilot.run()
        pilot.report["failure_code"] = None
    except PilotFailure as exc:
        pilot.report["failure_code"] = str(exc)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        pilot.report["failure_code"] = "runtime_dependency_or_filesystem_failure"
    finally:
        try:
            pilot.cleanup()
        except (OSError, PilotFailure):
            pilot.report["failure_code"] = "cleanup_failed"
        signal.alarm(0)
    pilot.report["duration_seconds"] = round(time.monotonic() - pilot.started, 3)
    pilot.report["finished_at"] = datetime.now(timezone.utc).isoformat()
    pilot.report["passed_logtest_case_count"] = sum(
        c["status"] == "passed" for c in pilot.report["logtest_cases"]
    )
    if (
        pilot.report["failure_code"] is None
        and pilot.report["logtest_verified"]
        and pilot.report["collection_verified"]
        and pilot.report["owned_processes_stopped"]
    ):
        pilot.report["status"] = "passed"
    if EVIDENCE.is_dir() and not EVIDENCE.is_symlink():
        with (EVIDENCE / "result.json").open("x", encoding="utf8") as handle:
            json.dump(pilot.report, handle, indent=2, sort_keys=True)
            handle.write("\n")
    print(
        json.dumps(
            {
                "tool": "wazuh",
                "status": pilot.report["status"],
                "failure_code": pilot.report["failure_code"],
            }
        )
    )
    return 0 if pilot.report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
