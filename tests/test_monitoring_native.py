"""Offline modeled host controls plus real disposable application/worker checks.

Every native process/socket primitive is forbidden. These checks cannot provide
Docker, TLS handshake, Prometheus/Grafana, browser or shutdown execution proof.
"""

import copy
import json
import os
import ssl
import unittest
from pathlib import Path
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from bridge.models import Event, Integration, MetricsScrapeState, WorkerHeartbeat
from bridge.monitoring import collect
from integrations.enterprise import verification as base
from integrations.monitoring import native_host as host
from integrations.monitoring import native_material as material
from integrations.monitoring import native_profile as profile
from integrations.monitoring import native_runtime as runtime

RUN = "b" * 32
IDS = {role: str(index) * 64 for index, role in enumerate(profile.ROLES, 1)}


class ForbiddenNative:
    def forbid_native(self):
        for target in (
            "socket.socket",
            "subprocess.run",
            "subprocess.Popen",
            "integrations.enterprise.verification.docker_result",
            "integrations.enterprise.windows_capacity.available_memory",
            "integrations.monitoring.native_host.available_memory",
        ):
            self.enterContext(
                patch(
                    target,
                    side_effect=AssertionError(
                        "Native primitive is forbidden in this offline check."
                    ),
                )
            )


class ProfileTests(ForbiddenNative, unittest.TestCase):
    def setUp(self):
        self.forbid_native()

    def test_original_baseline_and_separate_stage_budget(self):
        observation = profile.capacity(59184041984, 8656474112, 59184041984, before_launch=True)
        self.assertEqual(observation["cumulative_loss_bytes"], 21314382562)
        for values in (
            (
                profile.INITIAL_DISK - profile.MILESTONE_GROWTH + 1,
                8 * profile.GIB,
                profile.INITIAL_DISK - profile.MILESTONE_GROWTH + 1,
            ),
            (50 * profile.GIB, 5 * profile.GIB, 50 * profile.GIB),
            (25 * profile.GIB, 8 * profile.GIB, 25 * profile.GIB),
            (50 * profile.GIB, 8 * profile.GIB, 50 * profile.GIB + profile.STAGE_GROWTH),
            (True, 8 * profile.GIB, 50 * profile.GIB),
        ):
            with self.subTest(values=values), self.assertRaises(base.LabControlError):
                profile.capacity(*values, before_launch=True)
        with self.assertRaises(base.LabControlError):
            profile.capacity(
                50 * profile.GIB, 8 * profile.GIB, 50 * profile.GIB, original=50 * profile.GIB
            )

    def test_fixed_images_and_cached_only_closed_create_arguments(self):
        lock = profile.image_lock()
        self.assertGreater(lock["compressed_layer_bytes"], profile.STAGE_GROWTH)
        directory = host.ROOT / "var/enterprise/runs" / RUN
        rows = profile.specifications(RUN, directory, IDS["runner"])
        self.assertEqual(sum(row["memory"] for row in rows.values()), 1536 * profile.MIB)
        for component in profile.ROLES:
            args = host.create_arguments(
                RUN, directory, component, lock["images"][component]["config_digest"], IDS["runner"]
            )
            self.assertIn("--pull=never", args)
            self.assertIn("--read-only", args)
            self.assertNotIn("--publish", args)
            self.assertNotIn("--volume", args)
            self.assertFalse(any("docker.sock" in arg for arg in args))
            self.assertEqual(
                rows[component]["network_mode"],
                "none" if component == "runner" else "container:" + IDS["runner"],
            )
        with self.assertRaises(base.LabControlError):
            host.create_arguments(
                RUN,
                directory,
                "grafana",
                lock["images"]["grafana"]["config_digest"],
                "foreign-name",
            )

    def test_tls_auth_and_no_external_delivery_configuration(self):
        value = material.configuration()
        job = value["prometheus"]["scrape_configs"][0]
        self.assertEqual(job["static_configs"], [{"targets": ["127.0.0.1:18843"]}])
        self.assertFalse(job["tls_config"]["insecure_skip_verify"])
        self.assertFalse(job["follow_redirects"])
        self.assertFalse(job["proxy_from_environment"])
        self.assertEqual(job["authorization"]["credentials_file"], "/run/secrets/metrics-token")
        self.assertEqual(
            value["web"]["tls_server_config"]["client_auth_type"], "RequireAndVerifyClientCert"
        )
        self.assertNotIn("remote_write", value["prometheus"])
        self.assertNotIn("alerting", value["prometheus"])
        ini = material.grafana_ini()
        self.assertIn("preinstall_disabled = true", ini)
        self.assertIn("admin_password = $__file{/run/secrets/admin-password}", ini)

    def test_dashboard_queries_are_existing_observational_queries(self):
        panels = [p for p in profile.dashboard()["panels"] if p.get("targets")]
        self.assertEqual(len(panels), 12)
        self.assertFalse(any("vector(0)" in p["targets"][0]["expr"] for p in panels))

    def test_connection_refuses_unreviewed_port_and_insecure_tls(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with self.assertRaises(ValueError):
            runtime.Connection(443, context=context, seconds=1)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with self.assertRaises(ValueError):
            runtime.Connection(profile.PORTS["exporter"], context=context, seconds=1)


class QueryEvidenceTests(ForbiddenNative, unittest.TestCase):
    def setUp(self):
        self.forbid_native()
        self.prom = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [
                    {
                        "metric": {"__name__": "signalbridge_retained_events", "scope": "app1"},
                        "value": [1000, "6"],
                    }
                ],
            },
        }
        self.graf = {
            "results": {
                "A": {
                    "status": 200,
                    "frames": [
                        {
                            "schema": {
                                "fields": [
                                    {"type": "time"},
                                    {"type": "number", "labels": {"scope": "app1"}},
                                ]
                            },
                            "data": {"values": [[1000000], [6]]},
                        }
                    ],
                }
            }
        }

    def test_verified_vector_and_range_samples_match(self):
        self.assertEqual(
            profile.compare_query(self.prom, self.graf),
            {"series": 1, "samples": 1, "empty_evidence": False},
        )
        self.prom["data"]["resultType"] = "matrix"
        row = self.prom["data"]["result"][0]
        row["values"] = [row.pop("value"), [1015, "7"]]
        self.graf["results"]["A"]["frames"][0]["data"]["values"] = [[1000000, 1015000], [6, 7]]
        self.assertEqual(profile.compare_query(self.prom, self.graf)["samples"], 2)

    def test_empty_evidence_preserved_not_zero_filled(self):
        self.prom["data"]["result"] = []
        self.graf["results"]["A"]["frames"] = []
        self.assertEqual(
            profile.compare_query(self.prom, self.graf),
            {"series": 0, "samples": 0, "empty_evidence": True},
        )

    def test_missing_labels_values_timestamps_and_boolean_samples_deny(self):
        for path, value in (
            (("schema", "fields", 1, "labels"), {"scope": "app2"}),
            (("data", "values", 0), [1000001]),
            (("data", "values", 1), [0]),
            (("data", "values", 1), [True]),
            (("data", "values", 1), [None]),
            (("data", "values", 1), ["NaN"]),
        ):
            graf = copy.deepcopy(self.graf)
            target = graf["results"]["A"]["frames"][0]
            for step in path[:-1]:
                target = target[step]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(base.LabControlError):
                profile.compare_query(self.prom, graf)

    def test_duplicate_series_and_samples_deny(self):
        self.prom["data"]["result"].append(copy.deepcopy(self.prom["data"]["result"][0]))
        with self.assertRaises(base.LabControlError):
            profile.compare_query(self.prom, self.graf)
        self.prom["data"]["result"].pop()
        frame = self.graf["results"]["A"]["frames"][0]
        frame["data"]["values"] = [[1000000, 1000000], [6, 6]]
        with self.assertRaises(base.LabControlError):
            profile.compare_query(self.prom, self.graf)

    def test_http_success_with_plugin_error_or_oversized_evidence_deny(self):
        self.graf["results"]["A"]["error"] = "modeled datasource failure"
        with self.assertRaises(base.LabControlError):
            profile.compare_query(self.prom, self.graf)
        self.graf["results"]["A"].pop("error")
        self.graf["results"]["A"]["frames"] *= 257
        with self.assertRaises(base.LabControlError):
            profile.compare_query(self.prom, self.graf)

    def test_partial_receipt_is_bounded_and_never_accepted_as_success(self):
        partial = {
            "status": "partial",
            "scope": "standalone_synthetic_sqlite",
            "controls": {"signed_intake_committed": True},
            "actions": {
                "accepted": 6,
                "processed": 0,
                "duplicates": 1,
                "rejections": 1,
                "source": "synthetic_demo",
            },
            "requests": 256,
            "error_category": "validation",
        }
        runtime.validate_partial(partial)
        with self.assertRaises(base.LabControlError):
            runtime.validate_proof(partial)
        for replacement in (
            {"requests": 257},
            {"error_category": "arbitrary-native-exception"},
            {"unexpected": "synthetic"},
            {"actions": {**partial["actions"], "processed": True}},
        ):
            with self.subTest(fields=tuple(replacement)), self.assertRaises(base.LabControlError):
                runtime.validate_partial({**partial, **replacement})


class HostIsolationTests(ForbiddenNative, unittest.TestCase):
    def setUp(self):
        self.forbid_native()

    def test_explicit_reviewed_executable_and_closed_failure_categories(self):
        with self.assertRaises(base.LabControlError):
            host.executable("docker.exe")
        with self.assertRaises(base.LabControlError):
            host.executable("C:/reviewed/not-docker.exe")
        with (
            patch.object(host, "safe_path") as checked,
            patch.object(Path, "is_file", return_value=True),
        ):
            path = host.executable("C:/reviewed/docker.exe")
        self.assertEqual(path.name, "docker.exe")
        self.assertTrue(checked.called)
        self.assertEqual(profile.failure_category(ValueError()), "validation")
        self.assertEqual(profile.failure_category(OSError()), "filesystem_or_transport")
        self.assertEqual(profile.failure_category(Exception()), "internal")

    def test_fresh_directory_created_before_acl_and_collisions_denied(self):
        directory = host.ROOT / "var/enterprise/runs" / RUN
        calls = []

        def mkdir(path, *args, **kwargs):
            calls.append((path, kwargs))

        with (
            patch.object(base, "private_run_directory", return_value=directory),
            patch.object(Path, "exists", return_value=False),
            patch.object(Path, "is_symlink", return_value=False),
            patch.object(Path, "mkdir", mkdir),
        ):
            self.assertEqual(host.fresh_directory(RUN), directory)
        self.assertEqual(
            calls,
            [
                (directory.parent, {"parents": True, "exist_ok": True}),
                (directory, {"exist_ok": False}),
            ],
        )
        with (
            patch.object(base, "private_run_directory", return_value=directory),
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "mkdir") as create,
            self.assertRaises(base.LabControlError),
        ):
            host.fresh_directory(RUN)
        self.assertFalse(create.called)

    def test_container_replacement_and_missing_commit_component_deny(self):
        seen = {"runner": IDS["runner"]}
        with (
            patch.object(host, "owned", return_value={"runner": "9" * 64}),
            self.assertRaises(base.LabControlError),
        ):
            host.guard_runtime("forbidden", RUN, Path("unused"), {}, seen)
        with (
            patch.object(host, "owned", return_value=seen),
            self.assertRaises(base.LabControlError),
        ):
            host.guard_runtime("forbidden", RUN, Path("unused"), {}, seen, committed=True)

    def test_foreign_running_container_refuses_shared_engine(self):
        with (
            patch.object(host, "owned", return_value=IDS),
            patch.object(host, "listing", return_value=["9" * 64]),
            self.assertRaises(base.LabControlError),
        ):
            host.guard_runtime("forbidden", RUN, Path("unused"), {}, {})

    def test_stopped_foreign_namespace_attachment_denied(self):
        def listing(_docker, *, all_containers=False):
            return [*IDS.values(), "9" * 64] if all_containers else list(IDS.values())

        with (
            patch.object(host, "owned", return_value=IDS),
            patch.object(host, "listing", side_effect=listing),
            patch.object(host, "call", return_value="container:" + IDS["runner"]),
            self.assertRaises(base.LabControlError),
        ):
            host.guard_runtime("forbidden", RUN, Path("unused"), {}, {})

    def test_stop_skips_foreign_ownership_but_stops_other_verified_targets(self):
        commands = []

        def role(_docker, identifier, _run):
            if identifier == "9" * 64:
                raise base.LabControlError("Modeled foreign owner.")
            return next(key for key, value in IDS.items() if value == identifier)

        def call(_docker, arguments, timeout=5):
            commands.append(arguments)
            return "false" if arguments[0] == "inspect" else ""

        with (
            patch.object(host, "listing", return_value=["9" * 64, *IDS.values()]),
            patch.object(host, "role", side_effect=role),
            patch.object(host, "call", side_effect=call),
            self.assertRaises(base.LabControlError),
        ):
            host.stop_scope("forbidden", RUN)
        stopped = [args[-1] for args in commands if args[0] == "stop"]
        self.assertEqual(set(stopped), set(IDS.values()))
        self.assertEqual(stopped[-1], IDS["runner"])

    def test_effective_runtime_controls_deny_mutation(self):
        directory = host.ROOT / "var/enterprise/runs" / RUN
        row = profile.specifications(RUN, directory, IDS["runner"])["prometheus"]
        images = {"prometheus": {"id": "sha256:" + "a" * 64, "environment": ["PATH=/bin"]}}
        data = {
            key: row[key]
            for key in (
                "memory",
                "swap",
                "cpu",
                "pids",
                "readonly",
                "privileged",
                "cap_drop",
                "security",
                "restart",
                "user",
                "log",
                "workdir",
                "command",
                "tmpfs",
            )
        }
        data.update(
            image=images["prometheus"]["id"],
            entrypoint=[row["entrypoint"]],
            network_mode=row["network_mode"],
            running=True,
            pid_mode="",
            ipc_mode="private",
            uts_mode="",
            cgroup_mode="private",
            environment=["PATH=/bin"],
            labels=row["labels"],
            networks={},
            mounts=[
                {"Type": "bind", "Destination": target, "Source": str(source), "RW": False}
                for target, source in row["binds"].items()
            ],
        )
        with (
            patch.object(host, "role", return_value="prometheus"),
            patch.object(host, "call", return_value=json.dumps(data)),
        ):
            host.verify_runtime(
                "forbidden", IDS["prometheus"], RUN, directory, images, IDS["runner"], running=True
            )
        for key, value in (
            ("network_mode", "bridge"),
            ("privileged", True),
            ("memory", True),
            ("readonly", False),
            ("restart", "always"),
            ("cap_add", ["NET_ADMIN"]),
            ("port_bindings", {"19090/tcp": [{"HostPort": "19090"}]}),
            ("environment", ["PATH=/bin", "HTTPS_PROXY=http://foreign.invalid"]),
            ("running", False),
            ("devices", [{"PathOnHost": "/dev/null"}]),
            ("entrypoint", ["/bin/sh"]),
            ("tmpfs", {}),
        ):
            modified = {**data, key: value}
            with (
                self.subTest(key=key),
                patch.object(host, "role", return_value="prometheus"),
                patch.object(host, "call", return_value=json.dumps(modified)),
                self.assertRaises(base.LabControlError),
            ):
                host.verify_runtime(
                    "forbidden",
                    IDS["prometheus"],
                    RUN,
                    directory,
                    images,
                    IDS["runner"],
                    running=True,
                )

    def test_watchdog_arms_before_runtime_and_always_runs_late_stop_drain(self):
        directory = Path("offline-modeled-private-directory")
        records = {
            "monitoring-plan.json": {
                "run_id": RUN,
                "deadline": 10,
                "created_at_epoch": 0,
                "stage_initial": 50 * profile.GIB,
                "images": {},
            }
        }
        calls = []

        def guarded(*_args, **_kwargs):
            self.assertIn("monitoring-watchdog-ready.json", records)
            calls.append("guard")
            raise base.LabControlError("Modeled foreign namespace attachment.")

        with (
            patch.object(base, "private_run_directory", return_value=directory),
            patch.object(host, "read_json", side_effect=lambda p, *_args: records[p.name]),
            patch.object(host, "write_json", side_effect=lambda p, v: records.update({p.name: v})),
            patch.object(Path, "exists", lambda p: p.name in records),
            patch.object(host, "inputs"),
            patch.object(host, "sample_capacity"),
            patch.object(host, "guard_runtime", side_effect=guarded),
            patch.object(host, "stop_scope", return_value=3) as stop,
            patch.object(host, "owned", return_value=IDS),
            patch.object(host, "listing", return_value=[]),
            patch.object(host.time, "time", return_value=1),
            patch.object(host.time, "monotonic", side_effect=[0, 0, 1, 61]),
            patch.object(host.time, "sleep"),
        ):
            result = host.watchdog("forbidden", RUN)
        self.assertEqual(calls, ["guard"])
        self.assertTrue(result["shutdown_verified"])
        self.assertEqual(result["reason"], "control_error")
        self.assertTrue(stop.called)
        self.assertIn("monitoring-abort.json", records)


@override_settings(
    ROOT_URLCONF="integrations.monitoring.native_urls", MONITORED_WORKERS=(runtime.WORKER,)
)
class ActualApplicationTests(ForbiddenNative, TestCase):
    def setUp(self):
        self.forbid_native()
        self.enterContext(
            patch.dict(
                os.environ,
                {
                    "SB_MONITORING_INGEST": "synthetic-monitoring-ingest-control-" * 2,
                    "SB_METRICS_ENABLED": "1",
                    "SB_METRICS_TOKEN": "synthetic_monitoring_export_control_" * 2,
                    "SB_METRICS_APPS": runtime.APP,
                },
            )
        )

    def post(self, raw, headers):
        response = self.client.post(
            "/api/v1/events/" + runtime.APP + "/",
            raw,
            content_type="application/json",
            headers={k: v for k, v in headers.items() if k != "Content-Type"},
            secure=True,
        )
        return response.status_code, response.content

    def test_actual_signed_intake_worker_and_exporter_reconcile(self):
        result = runtime.controlled_actions(self.post)
        self.assertEqual(result["accepted"], 6)
        self.assertEqual(result["processed"], 6)
        body = collect(timezone.now(), [runtime.APP]).decode()
        self.assertTrue(
            'signalbridge_retained_events{scope="app1",state="processed"} 6.000000' in body,
            "Actual exporter did not reconcile committed events.",
        )
        self.assertTrue(
            'signalbridge_ingestion_rejections{scope="app1"} 1.000000' in body,
            "Actual exporter did not reconcile the signature denial.",
        )
        self.assertTrue(
            'signalbridge_processing_sample_count{scope="app1"} 6.000000' in body,
            "Actual exporter did not reconcile actual worker completions.",
        )
        self.assertTrue(
            'signalbridge_worker_state{slot="primary",state="recent"} 1.000000' in body,
            "Actual worker pulse was unavailable.",
        )
        self.assertEqual(Event.objects.count(), 6)

    def test_paused_worker_leaves_real_pending_records_then_drains_and_pulses(self):
        actions = runtime.controlled_intake(self.post)
        self.assertEqual(Event.objects.filter(state="pending").count(), 6)
        self.assertEqual(WorkerHeartbeat.objects.count(), 0)
        now = timezone.now()
        self.assertTrue(
            all(
                0 <= (now - t).total_seconds() < 5
                for t in Event.objects.values_list("received_at", flat=True)
            ),
            "Intake used altered or old receipt timestamps.",
        )
        body = collect(now, [runtime.APP]).decode()
        self.assertTrue(
            'signalbridge_retained_events{scope="app1",state="pending"} 6.000000' in body,
            "Paused-worker backlog was hidden.",
        )
        self.assertTrue(
            'signalbridge_worker_state{slot="primary",state="missing"} 1.000000' in body,
            "Missing worker evidence was hidden.",
        )
        self.assertTrue(
            'signalbridge_queue_oldest_received_timestamp_seconds{scope="app1"}' in body,
            "Actual oldest queue receipt was absent.",
        )
        self.assertEqual(runtime.process_actions(actions)["processed"], 6)
        body = collect(timezone.now(), [runtime.APP]).decode()
        self.assertTrue(
            'signalbridge_queue_eligible_events{scope="app1"} 0.000000' in body,
            "Resumed worker did not empty its eligible queue.",
        )
        self.assertTrue(
            'signalbridge_worker_state{slot="primary",state="recent"} 1.000000' in body,
            "Actual resumed worker pulse was absent.",
        )

    def test_bad_acknowledgment_cannot_generate_success_evidence(self):
        with self.assertRaises(ValueError):
            runtime.controlled_actions(
                lambda _raw, _headers: (202, b'{"status":"accepted","status":"duplicate"}')
            )
        self.assertEqual(Event.objects.count(), 0)

    def test_actual_exporter_denial_and_success_under_disposable_settings(self):
        runtime.controlled_actions(self.post)
        self.assertEqual(self.client.get("/metrics/", secure=True).status_code, 401)
        self.assertEqual(
            self.client.get(
                "/metrics/", secure=True, headers={"Authorization": "Bearer " + "wrong" * 10}
            ).status_code,
            401,
        )
        headers = {"Authorization": "Bearer " + os.environ["SB_METRICS_TOKEN"]}
        self.assertEqual(self.client.get("/metrics/", headers=headers).status_code, 403)
        response = self.client.get("/metrics/", headers=headers, secure=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self.client.get("/metrics/", headers=headers, secure=True).status_code, 429
        )
        self.assertEqual(MetricsScrapeState.objects.count(), 1)
        self.assertEqual(Integration.objects.get(slug=runtime.APP).rejected, 1)
