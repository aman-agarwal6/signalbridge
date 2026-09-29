"""Read the exact read-only local ledger file in a fresh bounded Wazuh container."""

import hashlib
import json
import os
import signal
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

if __package__:
    from integrations.wazuh import run_pilot as base
    from integrations.wazuh_recovery import run_delivery as recovery

    from . import contract
else:
    import backfill_contract as contract
    import run_delivery as recovery
    import run_pilot as base

require = base.require
INPUT = Path("/handoff/events.jsonl")


class BackfillPilot(recovery.RecoveryPilot):
    def prepare(self):
        # Invoke frozen preparation directly; this separate driver changes only its guest copy.
        base.Pilot.prepare(self)
        require(Path(__file__).resolve() == base.PILOT / "run_backfill.py", "driver_path")
        self.report.update(
            kind="signalbridge-wazuh-ledger-backfill",
            scope="retained_local_lab_metadata",
            synthetic_only=False,
        )
        manifest = contract.load_manifest(base.regular_file(base.PILOT / "backfill-input.json"))
        self.hostname = "signalbridge-wazuh-backfill-" + self.report["run_id"][:8]
        require(
            manifest["kind"] == "signalbridge-wazuh-backfill-input"
            and manifest["app"] == "bettail",
            "handoff_scope",
        )
        raw = base.regular_file(INPUT, limit=128 * 1024)
        require(
            len(raw) == manifest["offset"]
            and hashlib.sha256(raw).hexdigest() == manifest["sha256"],
            "handoff_file_identity",
        )
        self.input_digest = manifest["sha256"]
        self.input_bytes = raw
        self.expected, self.alert_expectations = contract.validate_input(manifest, raw, self.values)
        conf = base.WAZUH / "etc/ossec.conf"
        original = base.regular_file(conf)
        require(
            original.count(b"<logall_json>no</logall_json>") == 1
            and original.count(b"<only-future-events>yes</only-future-events>") == 1
            and original.count(str(base.INPUT).encode()) == 1,
            "config_shape",
        )
        changed = original.replace(
            b"<logall_json>no</logall_json>", b"<logall_json>yes</logall_json>"
        ).replace(
            b"<only-future-events>yes</only-future-events>",
            b'<only-future-events max-size="1MB">no</only-future-events>',
        )
        with conf.open("wb") as handle:
            handle.write(changed)
        with (base.EVIDENCE / "effective-config.xml").open("xb") as handle:
            handle.write(changed)
        self.report.update(
            transport="read_only_ledger_snapshot_to_fresh_collector_spool",
            input_sha256=self.input_digest,
            input_count=len(self.expected),
            expected_alert_count=len(self.alert_expectations),
            effective_config_sha256=hashlib.sha256(changed).hexdigest(),
            input_manifest_sha256=hashlib.sha256(
                base.regular_file(base.PILOT / "backfill-input.json")
            ).hexdigest(),
            source_counts=dict(
                Counter(p["signalbridge"]["source"] for p in self.expected.values())
            ),
        )

    def collect(self):
        require(
            not recovery.archive_bytes() and not base.alert_file(optional=True), "stale_records"
        )
        self.start_daemon("wazuh-logcollector")
        readiness_limit = min(self.deadline, time.monotonic() + 20)
        while base.collector_state() is None:
            self.check_budget()
            require(time.monotonic() < readiness_limit, "collector_readiness")
            time.sleep(0.25)
        require(
            base.collector_state() == {"events": 0, "processed_bytes": 0, "drops": 0},
            "collector_not_empty",
        )
        require(base.regular_file(base.INPUT) == b"", "spool_not_empty")
        # Fresh collectors skip existing files. Preserve the host ledger, wait for
        # real collector readiness, then replay the exact committed bytes into a
        # new container-only spool. No saved Wazuh checkpoint is manufactured.
        with base.INPUT.open("ab") as handle:
            require(handle.write(self.input_bytes) == len(self.input_bytes), "spool_short_write")
            handle.flush()
            os.fsync(handle.fileno())
        require(
            hashlib.sha256(base.regular_file(base.INPUT)).hexdigest() == self.input_digest,
            "spool_identity",
        )
        until = min(self.deadline, time.monotonic() + 40)
        stable_at = None
        previous = None
        while time.monotonic() < until:
            self.check_budget()
            raw = recovery.archive_bytes()
            counts = contract.observations(
                raw, self.expected, complete=False, hostname=self.hostname
            )
            alerts = base.alert_file(optional=True)
            observed = contract.observations(
                alerts, self.expected, alerts=True, complete=False, hostname=self.hostname
            )
            complete = (
                set(counts) == set(self.expected)
                and set(observed) == set(self.alert_expectations)
                and raw.endswith(b"\n")
                and (not alerts or alerts.endswith(b"\n"))
            )
            state = (raw, alerts)
            if complete:
                if state != previous:
                    stable_at = time.monotonic()
                if stable_at is not None and time.monotonic() - stable_at >= 3:
                    require(
                        hashlib.sha256(base.regular_file(INPUT, limit=128 * 1024)).hexdigest()
                        == self.input_digest,
                        "input_changed",
                    )
                    for name, body in [("archives.jsonl", raw), ("alerts.jsonl", alerts)]:
                        with (base.EVIDENCE / name).open("xb") as handle:
                            handle.write(body)
                    self.report.update(
                        collection_verified=True,
                        handoff_verified=True,
                        archived_records=len(counts),
                        alerts=len(observed),
                        nonalert_records=len(counts) - len(observed),
                        duplicates=0,
                        quiet_seconds=3,
                        archives_sha256=hashlib.sha256(raw).hexdigest(),
                        alerts_sha256=hashlib.sha256(alerts).hexdigest(),
                    )
                    return
            else:
                stable_at = None
            previous = state
            time.sleep(0.25)
        raise base.PilotFailure("handoff_incomplete")


def main():
    require(len(sys.argv) == 1, "no_arguments")
    pilot = BackfillPilot()

    def alarm(*_):
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
        and pilot.report.get("handoff_verified")
        and pilot.report["owned_processes_stopped"]
    ):
        pilot.report["status"] = "passed"
    with (base.EVIDENCE / "backfill-result.json").open("x", encoding="utf8") as handle:
        json.dump(pilot.report, handle, sort_keys=True, indent=2)
    print(
        json.dumps(
            {
                key: pilot.report.get(key)
                for key in (
                    "status",
                    "failure_code",
                    "duration_seconds",
                    "archived_records",
                    "alerts",
                )
            }
        )
    )
    return 0 if pilot.report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
