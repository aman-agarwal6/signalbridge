"""Closed standalone operational proof; import performs no native operations.

This profile observes synthetic intake and actual worker/exporter behavior in a
fresh SQLite application. It does not monitor the retained reference run or
establish the 24-hour SLA, enterprise-source connectivity or browser rendering.
"""

import json
import math
import re
import subprocess
import traceback
from pathlib import Path

from integrations.enterprise.reference_host_controls import INITIAL_DISK
from integrations.enterprise.verification import LabControlError, validate_identity

MIB, GIB = 1024**2, 1024**3
SCOPE, PREFIX = "standalone-monitoring-proof", "sb-monitoring-"
ROLES = ("runner", "prometheus", "grafana")
SECONDS, DRAIN_SECONDS = 900, 60
RAM, STAGE_GROWTH, MILESTONE_GROWTH = 1536 * MIB, 512 * MIB, 30 * GIB
PORTS = {"exporter": 18843, "prometheus": 19090, "grafana": 13000}
HERE = Path(__file__).parent


def require(condition):
    if not condition:
        raise LabControlError("Monitoring profile or evidence escaped its reviewed bounds.")


def failure_category(error):
    """Closed receipt vocabulary; never expose arbitrary exception class names."""
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return "timeout"
    if isinstance(error, ValueError):
        return "validation"
    if isinstance(error, OSError):
        return "filesystem_or_transport"
    return "internal"


def failure_location(error):
    """Up to three project frames as fixed source coordinates, never values."""
    frames = []
    for frame in traceback.extract_tb(error.__traceback__):
        path = Path(frame.filename)
        if path.parent.name in {"monitoring", "bridge", "enterprise"} and frame.name != "require":
            frames.append({"file": path.name, "line": frame.lineno, "function": frame.name})
    return frames[-3:]


def valid_failure_location(value):
    return (
        type(value) is list
        and len(value) <= 3
        and all(
            type(row) is dict
            and set(row) == {"file", "line", "function"}
            and type(row["file"]) is str
            and re.fullmatch(r"[a-z_]{1,64}\.py", row["file"])
            and type(row["line"]) is int
            and 0 < row["line"] < 100000
            and type(row["function"]) is str
            and re.fullmatch(r"[A-Za-z_<>][A-Za-z0-9_<>]{0,63}", row["function"])
            for row in value
        )
    )


def capacity(disk, memory, stage_initial, *, before_launch=False, original=INITIAL_DISK):
    require(all(type(value) is int and value > 0 for value in (disk, memory, stage_initial)))
    require(type(original) is int and original == INITIAL_DISK)
    spent = max(0, stage_initial - disk)
    total = max(0, original - disk)
    require(spent < STAGE_GROWTH and total < MILESTONE_GROWTH)
    reserve = STAGE_GROWTH - spent if before_launch else 0
    require(total + reserve < MILESTONE_GROWTH and disk >= 25 * GIB + reserve)
    require(memory >= 4 * GIB + (RAM if before_launch else 0))
    return {"stage_growth_bytes": spent, "cumulative_loss_bytes": total}


def labels(run, role):
    validate_identity(run)
    require(role in ROLES)
    return {
        "org.signalbridge.enterprise.run": run,
        "org.signalbridge.enterprise.scope": SCOPE,
        "com.docker.compose.project": PREFIX + run,
        "com.docker.compose.service": role,
    }


def specifications(run, directory, anchor=None):
    """Exact create inputs; no networks/volumes/port publications are created."""
    validate_identity(run)
    directory = Path(directory)
    common = {
        "memory": 512 * MIB,
        "swap": 512 * MIB,
        "cpu": 10**9,
        "pids": 96,
        "readonly": True,
        "privileged": False,
        "cap_drop": ["ALL"],
        "security": ["no-new-privileges:true"],
        "restart": "no",
        "log": {"Type": "json-file", "Config": {"max-size": "5m", "max-file": "2"}},
    }
    rows = {}
    for role in ROLES:
        binds = {"/run/secrets": directory / role / "secrets"}
        tmpfs = {"/tmp": "rw,noexec,nosuid,nodev,size=16m,mode=1777"}
        if role == "runner":
            binds.update({"/workspace": directory / "source", "/wheels": directory / "wheels"})
            tmpfs.update(
                {
                    "/deps": "rw,noexec,nosuid,nodev,size=192m,mode=1777",
                    "/state": "rw,noexec,nosuid,nodev,size=32m,mode=1777",
                }
            )
            entry, command, user = (
                "/usr/local/bin/python3",
                ["-B", "-m", "integrations.monitoring.native_runtime"],
                "10001:10001",
            )
            environment = {
                "PYTHONPATH": "/workspace:/deps",
                "PYTHONDONTWRITEBYTECODE": "1",
                "MONITORING_RUN": run,
            }
        else:
            binds["/config"] = directory / role / "config"
            environment = {}
            if role == "prometheus":
                tmpfs["/prometheus"] = "rw,noexec,nosuid,nodev,size=128m,mode=1777"
                entry, command, user = (
                    "/bin/prometheus",
                    [
                        "--config.file=/config/prometheus.yml",
                        "--web.config.file=/config/web.yml",
                        "--web.listen-address=127.0.0.1:19090",
                        "--storage.tsdb.path=/prometheus",
                        "--storage.tsdb.retention.time=30m",
                        "--storage.tsdb.retention.size=64MB",
                        "--query.timeout=5s",
                        "--query.max-concurrency=2",
                        "--query.max-samples=10000",
                        "--web.max-connections=16",
                    ],
                    "65534:65534",
                )
            else:
                tmpfs["/var/lib/grafana"] = "rw,noexec,nosuid,nodev,size=64m,mode=1777"
                # The image's GF_PATHS_PROVISIONING env overrides grafana.ini;
                # without this the mounted dashboards are never provisioned.
                environment = {"GF_PATHS_PROVISIONING": "/config/provisioning"}
                entry, command, user = (
                    "/usr/share/grafana/bin/grafana",
                    [
                        "server",
                        "--homepath=/usr/share/grafana",
                        "--config=/config/grafana.ini",
                        "cfg:default.paths.logs=/tmp",
                    ],
                    "472:472",
                )
        rows[role] = {
            **common,
            # Grafana starts separate backend-plugin processes; 96 tasks exhausted
            # its threads natively (errno 11). Still a fixed, bounded ceiling.
            **({"pids": 512} if role == "grafana" else {}),
            "name": PREFIX + run + "-" + role,
            "labels": labels(run, role),
            "user": user,
            "network_mode": "none" if role == "runner" else "container:" + (anchor or "PENDING"),
            "binds": binds,
            "tmpfs": tmpfs,
            "entrypoint": entry,
            "command": command,
            "environment": environment,
            "workdir": "/workspace" if role == "runner" else "/",
        }
    require(sum(row["memory"] for row in rows.values()) == RAM and RAM <= 10 * GIB)
    # 464 MiB tmpfs charged within the 1.5 GiB combined container memory cap.
    return rows


def image_lock():
    value = json.loads((HERE / "image-lock.json").read_text(encoding="utf8"))
    require(value["platform"] == "linux/amd64" and set(value["images"]) == set(ROLES))
    require(sum(row["compressed_layer_bytes"] for row in value["images"].values()) == 632483374)
    return value


def dashboard():
    value = json.loads((HERE / "signalbridge-dashboard.json").read_text(encoding="utf8"))
    require(value["uid"] == "signalbridge-pipeline")
    targets = [p for p in value["panels"] if p.get("targets")]
    require(len(targets) == 12 and all(len(p["targets"]) == 1 for p in targets))
    return value


def finite(value):
    require(type(value) in (int, float, str))
    try:
        result = float(value)
    except (ValueError, OverflowError):
        raise LabControlError("Non-numeric monitoring sample.") from None
    require(math.isfinite(result))
    return result


def series_labels(value):
    require(type(value) is dict and len(value) <= 8)
    require(
        all(
            type(k) is str and type(v) is str and len(k) <= 64 and len(v) <= 128
            for k, v in value.items()
        )
    )
    return tuple(sorted((k, v) for k, v in value.items() if k != "__name__"))


def prometheus_samples(value):
    require(type(value) is dict and value.get("status") == "success")
    data = value.get("data", {})
    require(data.get("resultType") in ("vector", "matrix"))
    rows = data.get("result")
    require(type(rows) is list and len(rows) <= 256)
    result = {}
    for row in rows:
        identity = series_labels(row["metric"])
        samples = [row["value"]] if data["resultType"] == "vector" else row["values"]
        require(type(samples) is list and len(samples) <= 256 and identity not in result)
        result[identity] = []
        for sample in samples:
            require(type(sample) is list and len(sample) == 2)
            result[identity].append((round(finite(sample[0]) * 1000), finite(sample[1])))
        require(len(set(t for t, _v in result[identity])) == len(result[identity]))
    return result


def grafana_samples(value):
    require(type(value) is dict and set(value.get("results", {})) == {"A"})
    data = value["results"]["A"]
    require(data.get("status", 200) == 200 and not data.get("error"))
    frames, result = data.get("frames"), {}
    require(type(frames) is list and len(frames) <= 256)
    for frame in frames:
        fields, values = frame["schema"]["fields"], frame["data"]["values"]
        require(type(fields) is list and len(fields) == 2 and len(values) == 2)
        require(fields[0]["type"] == "time" and fields[1]["type"] == "number")
        require(
            type(values[0]) is list
            and type(values[1]) is list
            and len(values[0]) == len(values[1]) <= 256
        )
        identity = series_labels(fields[1].get("labels", {}))
        require(identity not in result)
        result[identity] = [(round(finite(t)), finite(v)) for t, v in zip(*values, strict=True)]
        require(len(set(t for t, _v in result[identity])) == len(result[identity]))
    return result


def compare_query(prometheus, grafana):
    expected, observed = prometheus_samples(prometheus), grafana_samples(grafana)
    require(set(expected) == set(observed))
    count = 0
    for labels_key, samples in expected.items():
        other = observed[labels_key]
        require(len(samples) == len(other))
        for (t, v), (other_t, other_v) in zip(samples, other, strict=True):
            require(t == other_t and math.isclose(v, other_v, rel_tol=0, abs_tol=0.000001))
            count += 1
    return {"series": len(expected), "samples": count, "empty_evidence": not expected}
