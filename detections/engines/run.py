"""Run the SPL and KQL versions of R1-R5 in real engines on the 48 frozen scenarios.

The scenarios are rebuilt exactly as detections.sigma.replay rebuilds them. Each engine gets all
events in one table or index. Every scenario has its own app, so each result row maps back to
one scenario. The receipt records which rules each engine fired per scenario, beside the
Python engine's result.

Needs a running engine (see detections/README.md). From the repository root:
    python -m detections.engines.run splunk --image splunk/splunk:10.6.0@sha256:...
    python -m detections.engines.run kusto --image mcr.microsoft.com/...@sha256:...

Splunk reads SPLUNK_HEC_TOKEN and SPLUNK_CA_FILE (the container's CA certificate) from the
environment and never prints them.
"""

import argparse
import csv
import hashlib
import io
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from ..sigma.replay import REPORT, ROOT, frozen_round, scenario_events

HERE = Path(__file__).parent
DETECTIONS = ("R1", "R2", "R3", "R4", "R5")
GENERATED, HAND = "sigma-generated", "hand-written"
COMPILED, HANDWRITTEN = "detections/sigma/compiled", "detections/handwritten"
# Each engine runs one or more query sets. Where pySigma produced no query, the hand-written
# one stands in, and its origin says so.
VARIANTS = {
    "splunk": {
        "sigma-generated": {
            "R1": (f"{COMPILED}/splunk/R1.spl", GENERATED),
            "R2": (f"{COMPILED}/splunk/R2.spl", GENERATED),
            "R3": (f"{HANDWRITTEN}/splunk/R3.spl", HAND),
            "R4": (f"{COMPILED}/splunk/R4.spl", GENERATED),
            "R5": (f"{COMPILED}/splunk/R5.spl", GENERATED),
        },
        "hand-written": {
            "R1": (f"{HANDWRITTEN}/splunk/R1.spl", HAND),
            "R2": (f"{COMPILED}/splunk/R2.spl", GENERATED),
            "R3": (f"{HANDWRITTEN}/splunk/R3.spl", HAND),
            "R4": (f"{HANDWRITTEN}/splunk/R4.spl", HAND),
            "R5": (f"{HANDWRITTEN}/splunk/R5.spl", HAND),
        },
    },
    "kusto": {
        "hand-written": {
            "R1": (f"{HANDWRITTEN}/kusto/R1.kql", HAND),
            "R2": (f"{COMPILED}/kusto/R2.kql", GENERATED),
            "R3": (f"{HANDWRITTEN}/kusto/R3.kql", HAND),
            "R4": (f"{HANDWRITTEN}/kusto/R4.kql", HAND),
            "R5": (f"{HANDWRITTEN}/kusto/R5.kql", HAND),
        },
    },
}
TABLE = "SignalBridgeAccess_CL"
SOURCETYPE = "signalbridge:access"
COLUMNS = (
    ("TimeGenerated", "datetime"),
    ("event_id", "string"),
    ("app", "string"),
    ("environment", "string"),
    ("source", "string"),
    ("actor", "string"),
    ("resource", "string"),
    ("operation", "string"),
    ("outcome", "string"),
    ("reason", "string"),
    ("membership", "dynamic"),
)


class QueryError(Exception):
    """The engine rejected a query."""


def sha256(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def load_events():
    """All stored events of the frozen round, plus the app -> scenario map."""
    round_id, scenarios, inputs_sha256 = frozen_round()
    events, apps = [], {}
    for index, scenario in enumerate(scenarios):
        for source, event in scenario_events(round_id, index, scenario):
            apps[event["app"]] = scenario["id"]
            events.append((source, event))
    return round_id, inputs_sha256, [s["id"] for s in scenarios], events, apps


def request(url, body=None, headers=None, context=None, timeout=120):
    data = body if body is None or isinstance(body, bytes) else body.encode()
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with urllib.request.urlopen(req, context=context, timeout=timeout) as response:
        return response.read()


class Splunk:
    """Splunk Free has no user accounts and refuses management calls from outside its
    container. Management and search requests therefore run inside the container, through
    curl as the splunk user, with TLS verified against Splunk's CA. Events arrive through the
    HTTP Event Collector, which uses its own token."""

    def __init__(self, container, hec_url):
        self.container, self.hec_url = container, hec_url.rstrip("/")
        # The default certificate names "SplunkServerDefaultCert", not 127.0.0.1; the chain is
        # still verified against the container's own CA file.
        self.context = ssl.create_default_context(cafile=os.environ["SPLUNK_CA_FILE"])
        self.context.check_hostname = False
        self.hec = {"Authorization": f"Splunk {os.environ['SPLUNK_HEC_TOKEN']}"}

    def rest(self, path, fields=None, timeout=300):
        command = ["docker", "exec", "-i", "-u", "splunk", self.container, "curl", "-sS"]
        command += ["--cacert", "/opt/splunk/etc/auth/cacert.pem"]
        command += ["--resolve", "SplunkServerDefaultCert:8089:127.0.0.1"]
        # The container's curl predates --fail-with-body; append the status code instead.
        command += ["--write-out", "\n%{http_code}"]
        command.append(f"https://SplunkServerDefaultCert:8089{path}")
        body = None
        if fields is not None:
            command += ["--data-binary", "@-"]
            body = urllib.parse.urlencode({**fields, "output_mode": "json"}).encode()
        result = subprocess.run(command, input=body, capture_output=True, timeout=timeout)
        content, _, status = result.stdout.rpartition(b"\n")
        if result.returncode or not status.startswith(b"2"):
            raise RuntimeError(
                f"Splunk {path} failed ({status!r}): {content[:300]!r} {result.stderr[:300]!r}"
            )
        return content

    def version(self):
        raw = self.rest("/services/server/info?output_mode=json")
        return json.loads(raw)["entry"][0]["content"]["version"]

    def prepare(self):
        # Search-time JSON field extraction for the SignalBridge sourcetype.
        path = "/servicesNS/nobody/search/configs/conf-props"
        existing = self.rest(f"{path}?output_mode=json&count=0&search=name%3D{SOURCETYPE}")
        if any(e["name"] == SOURCETYPE for e in json.loads(existing)["entry"]):
            self.rest(f"{path}/{urllib.parse.quote(SOURCETYPE, safe='')}", {"KV_MODE": "json"})
        else:
            self.rest(path, {"name": SOURCETYPE, "KV_MODE": "json"})

    def load(self, events):
        lines = []
        for source, event in events:
            at = datetime.fromisoformat(event["occurred_at"]).timestamp()
            fields = ("event_id", "app", "environment", "actor", "resource", "operation")
            body = {key: event[key] for key in fields + ("outcome", "reason")}
            if event.get("membership"):
                body["membership"] = event["membership"]
            # SignalBridge's source class becomes Splunk's own source field.
            lines.append(
                json.dumps(
                    {"time": at, "index": "main", "sourcetype": SOURCETYPE, "source": source}
                    | {"host": "signalbridge-replay", "event": body}
                )
            )
        request(
            self.hec_url + "/services/collector/event", "\n".join(lines), self.hec, self.context
        )

    def search(self, query, only=None):
        # A one-shot job returns Splunk's error messages; the export endpoint hides them, so
        # a rejected query would look like "no matches".
        text = query if query.lstrip().startswith("|") else "search " + query
        fields = {"search": text, "exec_mode": "oneshot", "count": "0"}
        fields |= {"earliest_time": "0", "latest_time": "now"}
        if only:
            # A raw-event search returns only the fields it mentions; "f" requests app, which
            # maps each row to its scenario, and drops the rest. The query text is unchanged.
            fields["f"] = only
        try:
            answer = json.loads(self.rest("/servicesNS/nobody/search/search/jobs", fields))
        except RuntimeError as error:
            raise QueryError(str(error)) from None
        problems = [
            m["text"] for m in answer.get("messages", []) if m["type"] in ("ERROR", "FATAL")
        ]
        if problems:
            raise QueryError("; ".join(problems))
        return answer.get("results", [])

    def count(self):
        rows = self.search(f'sourcetype="{SOURCETYPE}" | stats count')
        return int(rows[0]["count"]) if rows else 0


class Kusto:
    def __init__(self, url, database="NetDefaultDB"):
        self.url, self.database = url.rstrip("/"), database

    def call(self, kind, text):
        body = json.dumps({"db": self.database, "csl": text})
        headers = {"Content-Type": "application/json"}
        raw = request(f"{self.url}/v1/rest/{kind}", body, headers, timeout=300)
        table = json.loads(raw)["Tables"][0]
        names = [column["ColumnName"] for column in table["Columns"]]
        return [dict(zip(names, row, strict=True)) for row in table["Rows"]]

    def version(self):
        return self.call("mgmt", ".show version")[0]["BuildVersion"]

    def prepare(self):
        schema = ", ".join(f"{name}:{kind}" for name, kind in COLUMNS)
        self.call("mgmt", f".create-merge table {TABLE} ({schema})")
        self.call("mgmt", f".clear table {TABLE} data")

    def load(self, events):
        buffer = io.StringIO()
        writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\n")
        for source, event in events:
            at = datetime.fromisoformat(event["occurred_at"]).astimezone(timezone.utc)
            writer.writerow(
                [
                    at.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    event["event_id"],
                    event["app"],
                    event["environment"],
                    source,
                    event["actor"],
                    event["resource"],
                    event["operation"],
                    event["outcome"],
                    event["reason"],
                    json.dumps(event["membership"]) if event.get("membership") else "",
                ]
            )
        self.call("mgmt", f".ingest inline into table {TABLE} <|\n{buffer.getvalue()}")

    def search(self, query, only=None):
        # Kusto returns every projected column, so "only" needs no request option here.
        try:
            return self.call("query", query)
        except urllib.error.HTTPError as error:
            raise QueryError(error.read()[:500].decode(errors="replace")) from None

    def count(self):
        return int(self.search(f"{TABLE} | count")[0]["Count"])


def evaluate(client, queries, order, apps, python):
    """Run one query set; a query the engine rejects is recorded, not read as "no matches"."""
    fired = {scenario: set() for scenario in order}
    recorded = {}
    for rule in DETECTIONS:
        path, origin = queries[rule]
        entry = {"file": path, "origin": origin, "sha256": sha256(ROOT / path)}
        try:
            rows = client.search((ROOT / path).read_text(encoding="utf-8"), only="app")
        except QueryError as error:
            entry["error"] = str(error)
            rows = []
        unknown = {row.get("app") for row in rows} - set(apps)
        if unknown:
            raise ValueError(
                f"{rule} returned rows without a known scenario app: {sorted(unknown)}"
            )
        for row in rows:
            fired[apps[row["app"]]].add(rule)
        recorded[rule] = entry
    results = [
        {
            "id": scenario,
            "python_rules": python[scenario],
            "engine_rules": sorted(fired[scenario]),
            "agrees": python[scenario] == sorted(fired[scenario]),
        }
        for scenario in order
    ]
    per_rule = {}
    for rule in DETECTIONS:
        pairs = [(rule in r["python_rules"], rule in r["engine_rules"]) for r in results]
        per_rule[rule] = {
            "both": sum(p and e for p, e in pairs),
            "python_only": sum(p and not e for p, e in pairs),
            "engine_only": sum(e and not p for p, e in pairs),
        }
    summary = {
        "scenarios": len(results),
        "matches_python": sum(r["agrees"] for r in results),
        "failed_queries": sorted(rule for rule, entry in recorded.items() if "error" in entry),
        "per_rule": per_rule,
    }
    return {"queries": recorded, "summary": summary, "scenarios": results}


def run(engine_name, client, image):
    started = datetime.now(timezone.utc)
    round_id, inputs_sha256, order, events, apps = load_events()
    client.prepare()
    # Splunk cannot clear its index here, so a rerun needs a fresh engine. Loading twice
    # would double every count and let the "all loaded" check pass on the old copy.
    if client.count():
        raise RuntimeError("The engine already holds SignalBridge events; start a fresh one.")
    client.load(events)
    deadline = time.monotonic() + 300
    while client.count() != len(events):
        if time.monotonic() > deadline:
            raise TimeoutError("The engine did not report every loaded event within 5 minutes.")
        time.sleep(3)
    python = {row["id"]: row["python_rules"] for row in json.loads(REPORT.read_text())["scenarios"]}
    variants = {
        name: evaluate(client, queries, order, apps, python)
        for name, queries in VARIANTS[engine_name].items()
    }
    return {
        "kind": "signalbridge-engine-run",
        "engine": engine_name,
        "engine_version": client.version(),
        "image": image,
        "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "round_id": round_id,
        "inputs_sha256": inputs_sha256,
        "events_loaded": len(events),
        "variants": variants,
        "limits": [
            "A local, single-node engine in a container on one PC, with synthetic events.",
            "Compares which rules fired per scenario with the Python engine; it is not an accuracy measurement.",
            "Each query records its origin: generated by pySigma from the Sigma rules, or hand-written.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", choices=("splunk", "kusto"))
    parser.add_argument("--image", required=True, help="image reference, recorded in the receipt")
    parser.add_argument("--splunk-container", default="sigma-check-splunk")
    parser.add_argument("--splunk-hec-url", default="https://127.0.0.1:8088")
    parser.add_argument("--kusto-url", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    client = (
        Splunk(args.splunk_container, args.splunk_hec_url)
        if args.engine == "splunk"
        else Kusto(args.kusto_url)
    )
    receipt = run(args.engine, client, args.image)
    target = HERE / f"{args.engine}-run.json"
    target.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
    summaries = {name: variant["summary"] for name, variant in receipt["variants"].items()}
    print(json.dumps({"engine_version": receipt["engine_version"], **summaries}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
