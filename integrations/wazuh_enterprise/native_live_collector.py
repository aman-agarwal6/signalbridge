"""Finite native collection after host publication; never launches on the host.

The fixed frozen input is used for expected output only. Actual monitored files
start empty and are writable only by the reviewed host. Native zero counters
are retained before the host publishes, eliminating first-start EOF loss.
"""

import hashlib
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

from bridge.contract import canonical, digest, parse_json, timestamp

from . import native_collector as core
from .contract import EnterpriseWazuhError, expected_rule, require
from .native_reconciliation import _identity, expected_exports
from .ready_contract import (
    empty_readiness,
    recovery_binding,
    recovery_completion,
    recovery_initial,
    recovery_split,
    validate_stopped,
    verify_delivery_configuration,
)

SOURCE_FILES = (
    *core.SOURCE_FILES,
    "integrations/wazuh_enterprise/ready_contract.py",
    "integrations/wazuh_enterprise/native_live_collector.py",
    "delivery/plan.json",
    "delivery/manager-lab.conf",
)
KIND = "signalbridge-wazuh-native-ready-publication-v1"
RECOVERY_KIND = "signalbridge-wazuh-native-recovery-rotation-v1"
LOGCOLLECTOR = "wazuh-logcollector"


class LiveCollector(core.NativeCollector):
    source_files = SOURCE_FILES
    configuration_relative = "delivery/manager-lab.conf"

    def __init__(self):
        super().__init__()
        self.report["kind"] = KIND
        self.matched_since = None
        self.recovery, self.phases, self.phase = None, None, None

    def load_expected(self, raw_manifest):
        self.plan = parse_json(core._file(core.WORKSPACE / "delivery/plan.json", 32768))
        expected = expected_exports(core.WORKSPACE / "delivery/frozen-input", raw_manifest)
        require(
            self.plan["run_id"] == self.report_run_id()
            and self.plan["manifest_sha256"] == hashlib.sha256(raw_manifest).hexdigest()
            and self.plan["expected_packets_sha256"]
            == digest(
                sorted([[*key, packet, location] for key, (packet, location) in expected.items()])
            ),
            "native_collector_publication_binding",
        )
        require(
            {row["location"] for row in self.plan["files"]}
            == {location for _, location in expected.values()},
            "native_collector_publication_locations",
        )
        for row in self.plan["files"]:
            require(
                row["location"] == "/signalbridge/input/" + row["relative"]
                and ".." not in row["relative"].split("/"),
                "native_collector_publication_path",
            )
            require(
                core._file(core.INPUT / row["relative"], 128 * 1024) == b"",
                "native_collector_input_not_empty",
            )
        if "recovery" in self.plan:
            # Recompute the reviewed split from frozen bytes; never trust the plan alone.
            frozen = {
                row["relative"]: core._file(
                    core.WORKSPACE / "delivery/frozen-input" / row["relative"], 128 * 1024
                )
                for row in self.plan["files"]
            }
            base_plan = {key: value for key, value in self.plan.items() if key != "recovery"}
            require(
                canonical(self.plan["recovery"]) == canonical(recovery_binding(base_plan, frozen)),
                "native_collector_recovery_binding",
            )
            self.recovery = self.plan["recovery"]
            self.phases = recovery_split(self.plan, frozen)
            self.report["kind"] = RECOVERY_KIND
        return expected

    def report_run_id(self):
        # Core validated this exact context/environment before load_expected.
        return parse_json(core._file(core.EVIDENCE / "run-context.json", 4096))["run_id"].replace(
            "-", ""
        )

    def verify_config(self, raw, internal):
        return verify_delivery_configuration(self.plan, raw, internal)

    def on_started(self):
        deadline = min(self.deadline, time.monotonic() + 60)
        while time.monotonic() < deadline:
            self.check_budget()
            try:
                raw = core._file(core.base.COLLECTOR_STATE, 128 * 1024)
                ready = empty_readiness(self.plan, raw, observed_at=datetime.now(timezone.utc))
            except (FileNotFoundError, EnterpriseWazuhError, ValueError):
                # State is overwritten by the native writer; partial or not-yet
                # registered files are never treated as readiness.
                time.sleep(0.1)
                continue
            self.save("collector-ready-state.json", raw)
            self.save("collector-ready-next.json", canonical(ready) + b"\n")
            os.rename(
                core.EVIDENCE / "collector-ready-next.json", core.EVIDENCE / "collector-ready.json"
            )
            self.report["readiness_sha256"] = digest(ready)
            break
        else:
            raise EnterpriseWazuhError("native_collector_readiness_timeout")
        if self.recovery is not None:
            self.recover(ready)
            return
        deadline = min(self.deadline, time.monotonic() + 60)
        while time.monotonic() < deadline:
            self.check_budget()
            path = core.EVIDENCE / "publication-complete.json"
            if path.exists():
                publication = parse_json(core._file(path, 32768))
                require(
                    publication["kind"] == "signalbridge-wazuh-frozen-publication-v1"
                    and publication["run_id"] == self.plan["run_id"]
                    and publication["plan_sha256"] == digest(self.plan)
                    and publication["readiness_sha256"] == digest(ready)
                    and publication["published_records"] == len(self.expected)
                    and publication["native_execution_verified"] is False
                    and publication["tool_receipt_verified"] is False,
                    "native_collector_publication_receipt",
                )
                require(
                    timestamp(ready["observed_at"]) <= datetime.now(timezone.utc),
                    "native_collector_publication_time",
                )
                self.verify_inputs()
                self.report["publication_sha256"] = digest(publication)
                return
            time.sleep(0.1)
        raise EnterpriseWazuhError("native_collector_publication_timeout")

    def verify_inputs(self):
        if self.recovery is None:
            return super().verify_inputs()
        target, phases = self.phases
        for row in self.plan["files"]:
            name = row["relative"]
            first, rest = phases[name]
            current = core._file(core.INPUT / name, 128 * 1024)
            if self.phase == "initial":
                require(current == first, "native_collector_recovery_initial_input")
            elif name == target:
                rotated = core.INPUT / (name + self.recovery["rotated_suffix"])
                require(
                    core._file(rotated, 128 * 1024) == first and current == rest,
                    "native_collector_recovery_rotated_input",
                )
            else:
                require(current == first + rest, "native_collector_recovery_backlog_input")

    def await_record(self, name, seconds):
        deadline = min(self.deadline, time.monotonic() + seconds)
        path = core.EVIDENCE / name
        while time.monotonic() < deadline:
            self.check_budget()
            if path.exists():
                return parse_json(core._file(path, 32768))
            time.sleep(0.1)
        raise EnterpriseWazuhError("native_collector_recovery_handshake_timeout")

    def first_phase(self):
        """Logical records and expected alerts that phase one must produce."""
        _, phases = self.phases
        keys = [
            _identity(parse_json(line))
            for first, _ in phases.values()
            for line in first.splitlines(keepends=True)
        ]
        require(all(key in self.expected for key in keys), "native_collector_recovery_keys")
        alerts = sum(1 for key in keys if expected_rule(self.expected[key][0]) is not None)
        return len(keys), alerts

    def stop_logcollector(self):
        binary = str(core.WAZUH / "bin" / LOGCOLLECTOR)
        for index, (process, log, daemon) in enumerate(self.children):
            if daemon and process.args[0] == binary:
                self.signal_process(process, signal.SIGTERM)
                code = process.wait(timeout=20)
                # Deliberately stopped: no longer a supervised live daemon.
                self.children[index] = (process, log, False)
                return code
        raise EnterpriseWazuhError("native_collector_recovery_no_collector")

    def restart_logcollector(self):
        log = self.new_log(LOGCOLLECTOR + "-restart.log")
        process = subprocess.Popen(
            [str(core.WAZUH / "bin" / LOGCOLLECTOR), "-f"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=core.base.SUBPROCESS_ENV,
            cwd=core.WAZUH,
            start_new_session=True,
        )
        self.children.append((process, log, True))

    def recover(self, ready):
        """Interrupt the collector after phase one; resume after rotation and backlog."""
        initial = self.await_record("publication-initial.json", 60)
        require(initial == recovery_initial(self.plan, ready), "native_collector_recovery_initial")
        self.phase = "initial"
        records, alerts = self.first_phase()
        deadline = min(self.deadline, time.monotonic() + 120)
        while True:
            self.check_budget()
            self.verify_inputs()
            coverage = self.poll_records()
            self.heartbeat(coverage)
            if (
                coverage["archived_logical_inputs"] == records
                and coverage["alerted_logical_inputs"] == alerts
            ):
                break
            require(time.monotonic() < deadline, "native_collector_recovery_initial_timeout")
            time.sleep(0.2)
        code = self.stop_logcollector()
        stopped = {
            "kind": "signalbridge-wazuh-collector-stopped-v1",
            "run_id": self.plan["run_id"],
            "plan_sha256": digest(self.plan),
            "initial_sha256": digest(initial),
            "stopped_at": datetime.now(timezone.utc).isoformat(),
            "archived_before_stop": records,
            "alerted_before_stop": alerts,
            "collector_exit_code": code,
            "native_execution_verified": False,
        }
        validate_stopped(self.plan, initial, stopped)
        self.save("collector-stopped-next.json", canonical(stopped) + b"\n")
        os.rename(
            core.EVIDENCE / "collector-stopped-next.json", core.EVIDENCE / "collector-stopped.json"
        )
        completion = self.await_record("publication-complete.json", 60)
        require(
            completion == recovery_completion(self.plan, initial, stopped),
            "native_collector_recovery_completion",
        )
        self.phase = "backlog"
        self.verify_inputs()
        self.restart_logcollector()
        self.report["publication_sha256"] = digest(completion)
        self.report["recovery_sha256"] = digest(stopped)

    def collection_complete(self, coverage):
        if not coverage["bootstrap_counts_match"]:
            self.matched_since = None
            return False
        if self.matched_since is None:
            self.matched_since = time.monotonic()
        # Preserve later native duplicates; final drain runs after child stop.
        return time.monotonic() - self.matched_since >= 2


def main():
    require(len(sys.argv) == 1, "native_collector_arguments_not_supported")
    return core.run_main(LiveCollector())


if __name__ == "__main__":
    raise SystemExit(main())
