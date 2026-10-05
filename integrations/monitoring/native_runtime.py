"""Actual application, TLS exporter and query driver inside the finite anchor.

Only main() installs the three verified offline wheels into container tmpfs,
migrates its fresh SQLite DB and opens loopback sockets. Imports are inert.
No fixed metric fixtures are served. Failure receipts contain fixed fields only.
"""

import base64
import hashlib
import json
import logging
import os
import shutil
import ssl
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlencode
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from bridge.contract import canonical, parse_json, signature
from integrations.enterprise.https_deadline import BoundedHTTPSConnection, lab_context

from .native_profile import (
    HERE,
    PORTS,
    compare_query,
    dashboard,
    failure_category,
    failure_location,
    finite,
    require,
    valid_failure_location,
)

SECRETS = Path("/run/secrets")
APP, KEY, WORKER = "monitoring-proof", "monitoring-proof-key", "monitoring-proof"
CONTROL_NAMES = {
    "exporter_missing_bearer_denied",
    "exporter_wrong_bearer_denied",
    "wrong_ca_denied",
    "prometheus_missing_client_certificate_denied",
    "grafana_anonymous_query_denied",
    "signed_intake_committed",
    "duplicate_did_not_inflate",
    "bad_signature_rejected",
    "actual_worker_processed",
    "exporter_database_reconciled",
    "dashboard_provisioned",
    "all_dashboard_queries_match",
    "scrape_interruption_observed",
    "local_alert_fired",
    "scrape_recovered",
    "local_alert_cleared",
    "all_recovery_queries_match",
    "backlog_pending_and_eligible_observed",
    "backlog_oldest_age_observed",
    "worker_missing_observed",
    "worker_missing_alert_fired",
    "queue_delay_alert_fired",
    "resumed_queue_empty_and_worker_recent",
    "worker_and_queue_alerts_cleared",
}


class Connection(BoundedHTTPSConnection):
    ALLOWED_PORTS = tuple(PORTS.values())


class Driver:
    def __init__(self, deadline):
        self.deadline, self.requests = deadline, 0
        # Last unexpected JSON reply: fixed service label and status code only.
        self.unexpected = None
        self.context = lab_context(SECRETS / "ca.pem")
        self.mutual = lab_context(SECRETS / "ca.pem")
        self.mutual.load_cert_chain(SECRETS / "client.pem", SECRETS / "client-key.pem")
        password = (SECRETS / "admin-password").read_text(encoding="ascii")
        self.basic = (
            "Basic " + base64.b64encode(("sb-monitoring-verifier:" + password).encode()).decode()
        )
        self.metrics = "Bearer " + (SECRETS / "metrics-token").read_text(encoding="ascii")

    def request(
        self, service, path, *, method="GET", body=None, headers=None, context=None, auth=True
    ):
        require(
            service in PORTS
            and path.startswith("/")
            and len(path) <= 4096
            and not path.startswith("//")
        )
        require(method in ("GET", "POST") and self.requests < 256)
        require(time.time() < self.deadline)
        self.requests += 1
        request_headers = {"Connection": "close", **(headers or {})}
        if service == "grafana" and auth:
            request_headers["Authorization"] = self.basic
        connection = Connection(
            PORTS[service],
            context=context or (self.mutual if service == "prometheus" else self.context),
            seconds=min(5, self.deadline - time.time()),
        )
        try:
            connection.start()
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            require(response.status not in (301, 302, 303, 307, 308))
            require(response.headers.get("Content-Encoding", "identity") == "identity")
            raw = response.read(1048577)
            connection.remaining()
            require(len(raw) <= 1048576)
            return response.status, raw
        finally:
            connection.finish()

    def json(self, service, path, *, payload=None):
        status, raw = self.request(
            service,
            path,
            method="POST" if payload is not None else "GET",
            body=canonical(payload) if payload is not None else None,
            headers={"Content-Type": "application/json"} if payload is not None else {},
        )
        if status != 200:
            self.unexpected = {"service": service, "status": status}
        require(status == 200)
        return parse_json(raw)

    def query(self, expr, end=None):
        return self.json(
            "prometheus", "/api/v1/query?" + urlencode({"query": expr, "time": end or time.time()})
        )

    def await_query(self, expr, predicate, seconds, *, worker_pulse=True):
        stop = min(self.deadline, time.time() + seconds)
        while time.time() < stop:
            if worker_pulse:
                pulse()
            try:
                value = self.query(expr)
                if predicate(value):
                    return value
            except (OSError, ValueError):
                pass
            time.sleep(min(5, max(0, stop - time.time())))
        raise ValueError("Expected monitoring observation did not arrive within its bound.")


def singleton(value, expected):
    data = value.get("data", {})
    rows = data.get("result")
    return (
        value.get("status") == "success"
        and data.get("resultType") == "vector"
        and type(rows) is list
        and len(rows) == 1
        and finite(rows[0]["value"][1]) == expected
    )


def empty(value):
    return (
        value.get("status") == "success"
        and value.get("data", {}).get("resultType") == "vector"
        and value["data"].get("result") == []
    )


def pulse():
    from bridge.worker import drain

    require(drain(limit=1, worker_id=WORKER) == 0)


def controlled_intake(post):
    """Real signed intake; deliberately leave the named worker unstarted."""
    from django.utils import timezone

    from bridge.models import Event, IngestKey, Integration

    app = Integration.objects.create(slug=APP, name="Standalone monitoring synthetic proof")
    IngestKey.objects.create(
        integration=app,
        key_id=KEY,
        secret_env="SB_MONITORING_INGEST",
        source="synthetic_demo",
        environment="test",
    )
    secret = os.environ["SB_MONITORING_INGEST"]
    bodies = []
    for index in range(6):
        sent = timezone.now().isoformat()
        data = {
            "schema_version": 1,
            "event_id": str(uuid.uuid4()),
            "app": APP,
            "environment": "test",
            "occurred_at": sent,
            "actor": hashlib.sha256(f"synthetic-monitoring-actor-{index}".encode()).hexdigest(),
            "resource": hashlib.sha256(
                f"synthetic-monitoring-resource-{index}".encode()
            ).hexdigest(),
            "episode": str(uuid.uuid4()),
            "operation": "private_record.read",
            "outcome": "denied",
            "reason": "membership_required",
            "context": None,
        }
        raw = canonical(data)
        headers = {
            "Content-Type": "application/json",
            "X-SB-Key": KEY,
            "X-SB-Time": sent,
            "X-SB-Signature": signature(secret, APP, KEY, sent, raw),
        }
        status, result = post(raw, headers)
        require(status == 202 and parse_json(result).get("status") == "accepted")
        bodies.append((raw, headers))
    status, result = post(*bodies[0])
    require(status == 200 and parse_json(result).get("status") == "duplicate")
    raw, headers = bodies[0]
    bad = {**headers, "X-SB-Signature": "0" * 64}
    require(post(raw, bad)[0] == 401)
    require(Event.objects.filter(integration=app).count() == 6)
    require(
        Event.objects.filter(integration=app, state="pending", source="synthetic_demo").count() == 6
    )
    app.refresh_from_db()
    require(app.rejected == 1)
    return {
        "accepted": 6,
        "processed": 0,
        "duplicates": 1,
        "rejections": app.rejected,
        "source": "synthetic_demo",
    }


def process_actions(actions):
    from bridge.models import Event, Integration
    from bridge.worker import drain

    app = Integration.objects.get(slug=APP)
    processed = drain(limit=6, worker_id=WORKER)
    require(processed == 6)
    rows = list(
        Event.objects.filter(integration=app).values_list(
            "state", "source", "processed_by", "processing_attempts"
        )
    )
    require(
        len(rows) == 6 and all(row == ("processed", "synthetic_demo", WORKER, 1) for row in rows)
    )
    app.refresh_from_db()
    require(app.rejected == 1)
    return {
        **actions,
        "processed": processed,
    }


def controlled_actions(post):
    """Offline application tests can exercise both genuine actions without waiting."""
    return process_actions(controlled_intake(post))


def backlog_observations(driver, controls):
    """Real elapsed time only; no pulse/drain or stored timestamp manipulation."""
    phase_deadline = min(driver.deadline, time.time() + 180)

    def observe(expr, predicate):
        require(time.time() < phase_deadline)
        return driver.await_query(expr, predicate, phase_deadline - time.time(), worker_pulse=False)

    for expr in (
        'signalbridge_retained_events{job="signalbridge",scope="app1",state="pending"}',
        'signalbridge_queue_eligible_events{job="signalbridge",scope="app1"}',
    ):
        observe(expr, lambda v: singleton(v, 6))
    controls["backlog_pending_and_eligible_observed"] = True
    observe(
        'signalbridge_worker_state{job="signalbridge",slot="primary",state="missing"}',
        lambda v: singleton(v, 1),
    )
    controls["worker_missing_observed"] = True
    age = observe(
        'time() - signalbridge_queue_oldest_received_timestamp_seconds{job="signalbridge",scope="app1"}',
        lambda v: (
            v.get("status") == "success"
            and len(v.get("data", {}).get("result", [])) == 1
            and finite(v["data"]["result"][0]["value"][1]) >= 30
        ),
    )
    controls["backlog_oldest_age_observed"] = True
    observed_age = finite(age["data"]["result"][0]["value"][1])
    for name, control in (
        ("SignalBridgeWorkerPulseUnavailable", "worker_missing_alert_fired"),
        ("SignalBridgeQueueDelayed", "queue_delay_alert_fired"),
    ):
        observe('ALERTS{alertname="' + name + '",alertstate="firing"}', lambda v: singleton(v, 1))
        controls[control] = True
    return {
        "pending_count": 6,
        "oldest_age_seconds": observed_age,
        "worker_state": "missing",
        "worker_alert_firing": True,
        "queue_alert_firing": True,
    }


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *_args):
        pass

    def get_environ(self):
        value = super().get_environ()
        value["HTTPS"] = "on"
        return value


class FiniteServer(WSGIServer):
    allow_reuse_address = True

    def get_request(self):
        channel, address = super().get_request()
        channel.settimeout(5)
        try:
            return self.context.wrap_socket(channel, server_side=True), address
        except Exception:
            channel.close()
            raise

    def handle_error(self, *_args):
        pass


def start_exporter(application):
    server = make_server(
        "127.0.0.1",
        PORTS["exporter"],
        application,
        server_class=FiniteServer,
        handler_class=QuietHandler,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(SECRETS / "server.pem", SECRETS / "server-key.pem")
    server.context = context
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    return server, worker


def stop_exporter(server, worker):
    server.shutdown()
    server.server_close()
    worker.join(timeout=6)
    require(not worker.is_alive())


def panel_queries(driver):
    end = (int(time.time()) // 15) * 15
    results = []
    for panel in dashboard()["panels"]:
        if not panel.get("targets"):
            continue
        target = panel["targets"][0]
        if target["instant"]:
            prom = driver.query(target["expr"], end)
        else:
            prom = driver.json(
                "prometheus",
                "/api/v1/query_range?"
                + urlencode({"query": target["expr"], "start": end - 300, "end": end, "step": 15}),
            )
        graf = driver.json(
            "grafana",
            "/api/ds/query",
            payload={
                "from": str((end - 300) * 1000),
                "to": str(end * 1000),
                "queries": [
                    {
                        **target,
                        "datasource": {"type": "prometheus", "uid": "signalbridge-prometheus"},
                        "format": "time_series",
                        "intervalMs": 15000,
                        "maxDataPoints": 256,
                    }
                ],
            },
        )
        results.append({"panel_id": panel["id"], **compare_query(prom, graf)})
    require(len(results) == 12 and any(row["samples"] > 0 for row in results))
    return results


def bootstrap():
    """Hash-verified offline installation within the approved runner, no acquisition."""
    value = parse_json((HERE / "wheels.json").read_bytes())
    require(len(value["wheels"]) == 3)
    files, expanded = [], 0
    for row in value["wheels"]:
        require(restricted_filename(row["filename"]))
        path = Path("/wheels") / row["filename"]
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == row["size"])
        require(hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"])
        files.append(str(path))
        with zipfile.ZipFile(path) as archive:
            require(len(archive.infolist()) <= 10000)
            for entry in archive.infolist():
                part = PurePosixPath(entry.filename)
                require(
                    not part.is_absolute()
                    and ".." not in part.parts
                    and "\\" not in entry.filename
                    and ":" not in entry.filename
                    and not entry.flag_bits & 1
                )
                require((entry.external_attr >> 16) & 0o170000 != 0o120000)
                expanded += entry.file_size
                require(expanded <= 96 * 1024**2)
    staging = Path("/deps/.pip-staging")
    staging.mkdir(mode=0o700)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--no-cache-dir",
            "--no-compile",
            "--only-binary=:all:",
            "--disable-pip-version-check",
            "--target",
            "/deps",
            *files,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=120,
        shell=False,
        # pip --target unpacks into TMPDIR first; the 16 MiB /tmp is too small
        # for Django, so stage inside the 192 MiB /deps tmpfs instead.
        env={**os.environ, "TMPDIR": str(staging)},
    )
    require(result.returncode == 0)
    shutil.rmtree(staging)


def restricted_filename(value):
    return (
        type(value) is str
        and PurePosixPath(value).name == value
        and value.endswith(".whl")
        and ":" not in value
        and "\\" not in value
    )


def validate_proof(value):
    require(
        type(value) is dict
        and set(value)
        == {
            "status",
            "scope",
            "controls",
            "actions",
            "dashboard",
            "recovery_dashboard",
            "requests",
            "filesystem_metric_scope",
            "backlog_phase",
        }
    )
    require(value["status"] == "passed" and value["scope"] == "standalone_synthetic_sqlite")
    require(value["filesystem_metric_scope"] == "disposable_application_tmpfs_host_guard_separate")
    require(
        type(value["controls"]) is dict
        and set(value["controls"]) == CONTROL_NAMES
        and all(v is True for v in value["controls"].values())
    )
    require(
        json.dumps(value["actions"], sort_keys=True)
        == json.dumps(
            {
                "accepted": 6,
                "processed": 6,
                "duplicates": 1,
                "rejections": 1,
                "source": "synthetic_demo",
            },
            sort_keys=True,
        )
    )
    require(type(value["requests"]) is int and 0 < value["requests"] <= 256)
    phase = value["backlog_phase"]
    require(
        type(phase) is dict
        and set(phase)
        == {
            "pending_count",
            "oldest_age_seconds",
            "worker_state",
            "worker_alert_firing",
            "queue_alert_firing",
        }
    )
    require(type(phase["pending_count"]) is int and phase["pending_count"] == 6)
    require(30 <= finite(phase["oldest_age_seconds"]) <= 900 and phase["worker_state"] == "missing")
    require(phase["worker_alert_firing"] is True and phase["queue_alert_firing"] is True)
    for key in ("dashboard", "recovery_dashboard"):
        rows = value[key]
        require(
            type(rows) is list
            and len(rows) == 12
            and {r.get("panel_id") for r in rows} == set(range(2, 14))
        )
        for row in rows:
            require(set(row) == {"panel_id", "series", "samples", "empty_evidence"})
            require(
                all(type(row[k]) is int and 0 <= row[k] <= 65536 for k in ("series", "samples"))
            )
            require(
                type(row["empty_evidence"]) is bool
                and row["empty_evidence"] == (row["series"] == 0)
            )
        require(any(row["samples"] > 0 for row in rows))


def validate_partial(value):
    fields = {"status", "scope", "controls", "actions", "requests", "error_category"}
    optional = {"failure_location", "unexpected_reply"}
    require(type(value) is dict and fields <= set(value) <= fields | optional)
    require("failure_location" not in value or valid_failure_location(value["failure_location"]))
    reply = value.get("unexpected_reply")
    require(
        reply is None
        or type(reply) is dict
        and set(reply) == {"service", "status"}
        and reply["service"] in PORTS
        and type(reply["status"]) is int
        and 100 <= reply["status"] <= 599
    )
    require(value["status"] == "partial" and value["scope"] == "standalone_synthetic_sqlite")
    require(
        type(value["controls"]) is dict
        and set(value["controls"]).issubset(CONTROL_NAMES)
        and all(v is True for v in value["controls"].values())
    )
    require(type(value["requests"]) is int and 0 <= value["requests"] <= 256)
    require(
        value["error_category"] in ("validation", "timeout", "filesystem_or_transport", "internal")
    )
    actions = value["actions"]
    require(
        type(actions) is dict
        and (
            not actions
            or set(actions) == {"accepted", "processed", "duplicates", "rejections", "source"}
        )
    )
    if actions:
        require(
            actions["source"] == "synthetic_demo"
            and all(
                type(actions[k]) is int and 0 <= actions[k] <= 6
                for k in ("accepted", "processed", "duplicates", "rejections")
            )
        )


def run_proof(driver, application):
    controls, actions = {}, {}
    server, worker = start_exporter(application)
    try:
        actions = controlled_intake(
            lambda raw, headers: driver.request(
                "exporter", "/api/v1/events/" + APP + "/", method="POST", body=raw, headers=headers
            )
        )
        controls.update(
            {
                name: True
                for name in (
                    "signed_intake_committed",
                    "duplicate_did_not_inflate",
                    "bad_signature_rejected",
                )
            }
        )
        driver.await_query(
            'up{job="signalbridge"}', lambda v: singleton(v, 1), 180, worker_pulse=False
        )
        backlog = backlog_observations(driver, controls)
        actions = process_actions(actions)
        controls["actual_worker_processed"] = True
        for expr in (
            'signalbridge_retained_events{job="signalbridge",scope="app1",state="pending"}',
            'signalbridge_queue_eligible_events{job="signalbridge",scope="app1"}',
        ):
            driver.await_query(expr, lambda v: singleton(v, 0), 45)
        driver.await_query(
            'signalbridge_worker_state{job="signalbridge",slot="primary",state="recent"}',
            lambda v: singleton(v, 1),
            45,
        )
        controls["resumed_queue_empty_and_worker_recent"] = True
        for name in ("SignalBridgeWorkerPulseUnavailable", "SignalBridgeQueueDelayed"):
            driver.await_query('ALERTS{alertname="' + name + '",alertstate="firing"}', empty, 45)
        controls["worker_and_queue_alerts_cleared"] = True
        require(driver.request("exporter", "/metrics/")[0] == 401)
        controls["exporter_missing_bearer_denied"] = True
        require(
            driver.request(
                "exporter", "/metrics/", headers={"Authorization": "Bearer " + "invalid" * 8}
            )[0]
            == 401
        )
        controls["exporter_wrong_bearer_denied"] = True
        wrong_ca = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        wrong_ca.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            driver.request("exporter", "/metrics/", context=wrong_ca)
            raise ValueError("Untrusted TLS unexpectedly accepted.")
        except ssl.SSLCertVerificationError:
            controls["wrong_ca_denied"] = True
        try:
            driver.request("prometheus", "/api/v1/query?query=up", context=driver.context)
            raise ValueError("Unauthenticated Prometheus unexpectedly accepted.")
        except ssl.SSLError as error:
            require(
                error.reason in ("TLSV13_ALERT_CERTIFICATE_REQUIRED", "SSLV3_ALERT_BAD_CERTIFICATE")
            )
            controls["prometheus_missing_client_certificate_denied"] = True
        require(
            driver.request("grafana", "/api/dashboards/uid/signalbridge-pipeline", auth=False)[0]
            == 401
        )
        controls["grafana_anonymous_query_denied"] = True
        for expr, expected in (
            ('signalbridge_accepted_records{job="signalbridge",scope="app1"}', actions["accepted"]),
            (
                'signalbridge_retained_events{job="signalbridge",scope="app1",state="processed"}',
                actions["processed"],
            ),
            (
                'signalbridge_ingestion_rejections{job="signalbridge",scope="app1"}',
                actions["rejections"],
            ),
            (
                'signalbridge_processing_sample_count{job="signalbridge",scope="app1"}',
                actions["processed"],
            ),
        ):
            driver.await_query(expr, lambda v, count=expected: singleton(v, count), 60)
        controls["exporter_database_reconciled"] = True
        observed = driver.json("grafana", "/api/dashboards/uid/signalbridge-pipeline")["dashboard"]
        require(
            observed["uid"] == dashboard()["uid"]
            and [p.get("targets") for p in observed["panels"]]
            == [p.get("targets") for p in dashboard()["panels"]]
        )
        controls["dashboard_provisioned"] = True
        queries = panel_queries(driver)
        controls["all_dashboard_queries_match"] = True
        stop_exporter(server, worker)
        server = None
        driver.await_query('up{job="signalbridge"}', lambda v: singleton(v, 0), 45)
        controls["scrape_interruption_observed"] = True
        alert = 'ALERTS{alertname="SignalBridgeMetricsUnavailable",alertstate="firing"}'
        driver.await_query(alert, lambda v: singleton(v, 1), 120)
        controls["local_alert_fired"] = True
        server, worker = start_exporter(application)
        driver.await_query('up{job="signalbridge"}', lambda v: singleton(v, 1), 60)
        controls["scrape_recovered"] = True
        driver.await_query(alert, empty, 60)
        controls["local_alert_cleared"] = True
        recovery = panel_queries(driver)
        controls["all_recovery_queries_match"] = True
        proof = {
            "status": "passed",
            "scope": "standalone_synthetic_sqlite",
            "controls": controls,
            "actions": actions,
            "dashboard": queries,
            "recovery_dashboard": recovery,
            "requests": driver.requests,
            "filesystem_metric_scope": "disposable_application_tmpfs_host_guard_separate",
            "backlog_phase": backlog,
        }
        validate_proof(proof)
        return proof
    except Exception as error:
        partial = {
            "status": "partial",
            "scope": "standalone_synthetic_sqlite",
            "controls": controls,
            "actions": actions,
            "requests": driver.requests,
            "error_category": failure_category(error),
            "failure_location": failure_location(error),
        }
        if driver.unexpected is not None:
            partial["unexpected_reply"] = driver.unexpected
        validate_partial(partial)
        return partial
    finally:
        if server is not None:
            stop_exporter(server, worker)


def main():
    proof = {
        "status": "partial",
        "scope": "standalone_synthetic_sqlite",
        "controls": {},
        "actions": {},
        "requests": 0,
    }
    deadline = time.time() + 30
    try:
        deadline = finite((SECRETS / "stop-at").read_text(encoding="ascii"))
        require(0 < deadline - time.time() <= 900)
        bootstrap()
        os.environ.update(
            DJANGO_SETTINGS_MODULE="integrations.monitoring.native_settings",
            SB_SECRET_KEY=(SECRETS / "django-secret").read_text(encoding="ascii"),
            SB_MONITORING_INGEST=(SECRETS / "ingest-secret").read_text(encoding="ascii"),
            SB_METRICS_ENABLED="1",
            SB_METRICS_TOKEN=(SECRETS / "metrics-token").read_text(encoding="ascii"),
            SB_METRICS_APPS=APP,
        )
        import django
        from django.core.management import call_command
        from django.core.wsgi import get_wsgi_application

        django.setup()
        logging.disable(logging.CRITICAL)
        require(not Path("/state/monitoring.sqlite3").exists())
        (Path("/state") / "var").mkdir()
        call_command("migrate", interactive=False, verbosity=0)
        application = get_wsgi_application()
        proof = run_proof(Driver(deadline), application)
    except Exception as error:
        proof["error_category"] = failure_category(error)
        proof["failure_location"] = failure_location(error)
    raw = (json.dumps(proof, sort_keys=True) + "\n").encode("ascii")
    require(len(raw) <= 16384)
    temporary = Path("/state/proof.tmp")
    with temporary.open("xb") as stream:
        stream.write(raw)
    temporary.replace("/state/proof.json")
    # Keep the namespace alive until the controller/watchdog captures the receipt.
    while time.time() < deadline:
        time.sleep(1)


if __name__ == "__main__":
    main()
