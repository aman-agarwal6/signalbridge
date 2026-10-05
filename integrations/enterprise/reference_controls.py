"""Closed parsed source recipe checks; no daemon calls, launch or authorization.

Effective container/kernel checks and an independent host watchdog remain
mandatory. A parsed recipe alone proves neither isolation nor execution.
"""

import copy
import json
import posixpath
from pathlib import Path

from .verification import LabControlError, validate_identity

SCOPE = "reference-access-verification"
PREFIX = "sb-enterprise-reference-"
SECRETS = {
    "bootstrap_password": "bootstrap-password",
    "source_password": "source-password",
    "console_password": "console-password",
    "source_profile": "source-profile",
    "lab_ca": "lab-ca.pem",
    "source_certificate": "source-certificate.pem",
    "source_private_key": "source-private-key.pem",
    "console_certificate": "console-certificate.pem",
    "console_private_key": "console-private-key.pem",
}


def path(value):
    if not isinstance(value, str) or "\x00" in value:
        raise LabControlError("Invalid source profile path.")
    return posixpath.normpath(value.replace("\\", "/"))


PROFILES = ("access", "header", "reliability")


def reliability_subnet(run):
    """One run-derived /24 in 198.18.0.0/15 (benchmarking range, never a LAN)."""
    validate_identity(run)
    index = int(run[:8], 16) % 512
    return f"198.{18 + index // 256}.{index % 256}.0/24"


def expected_config(images, run, directory, *, profile="access", rehearsal_ms=0):
    if profile not in PROFILES or type(rehearsal_ms) is not int or rehearsal_ms < 0:
        raise LabControlError("Unknown closed native source profile.")
    validate_identity(run)
    roles = {"database", "runner"} | ({"wazuh"} if profile == "reliability" else set())
    if set(images) != roles:
        raise LabControlError("Unexpected source image inventory.")
    root = path(Path(directory).as_posix())
    project, labels = (
        PREFIX + run,
        {"org.signalbridge.enterprise.run": run, "org.signalbridge.enterprise.scope": SCOPE},
    )
    services = {}
    for role in ("database", "runner"):
        database = role == "database"
        keys = (
            ["bootstrap_password", "source_password", "console_password"]
            if database
            else [k for k in SECRETS if k != "bootstrap_password"]
        )
        service = {
            "image": images[role],
            "pull_policy": "never",
            "restart": "no",
            "user": "postgres" if database else "10001:10001",
            "mem_limit": "536870912",
            "memswap_limit": "536870912",
            "cpus": 1,
            "pids_limit": 128 if database else 96,
            "read_only": True,
            "cgroup": "private",
            "ipc": "private",
            "security_opt": ["no-new-privileges:true"],
            "cap_drop": ["ALL"],
            "labels": labels,
            "entrypoint": None,
            "networks": {"reference": None},
            "logging": {"driver": "json-file", "options": {"max-file": "2", "max-size": "5m"}},
            "secrets": [{"source": k, "target": "/run/secrets/" + k} for k in keys],
            "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
        }
        if database:
            service.update(
                environment={
                    "POSTGRES_DB": "postgres",
                    "POSTGRES_USER": "postgres",
                    "POSTGRES_PASSWORD_FILE": "/run/secrets/bootstrap_password",
                    "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256 --auth-local=peer",
                },
                command=[
                    "postgres",
                    "-c",
                    "shared_buffers=64MB",
                    "-c",
                    "max_connections=20",
                    "-c",
                    "log_statement=none",
                ],
                shm_size="67108864",
                healthcheck={
                    "test": [
                        "CMD",
                        "pg_isready",
                        "-h",
                        "127.0.0.1",
                        "-U",
                        "postgres",
                        "-d",
                        "postgres",
                    ],
                    "interval": "2s",
                    "timeout": "2s",
                    "retries": 30,
                },
                volumes=[
                    {
                        "type": "volume",
                        "source": "reference_data",
                        "target": "/var/lib/postgresql/data",
                        "volume": {},
                    },
                    {
                        "type": "bind",
                        "source": root + "/source/integrations/enterprise/init-reference.sh",
                        "target": "/docker-entrypoint-initdb.d/10-reference.sh",
                        "read_only": True,
                        "bind": {},
                    },
                ],
            )
            service["tmpfs"].append("/var/run/postgresql:rw,noexec,nosuid,nodev,size=16m")
        else:
            service.update(
                environment={
                    "SB_SOURCE_PROOF": "1",
                    "SB_SOURCE_RUN": run,
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PIP_CONFIG_FILE": "/dev/null",
                    "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                },
                command=["python", "-B", "-m", "integrations.enterprise.reference_runner"],
                working_dir="/workspace",
                depends_on={"database": {"condition": "service_healthy", "required": True}},
                volumes=[
                    {
                        "type": "bind",
                        "source": root + "/" + name,
                        "target": target,
                        **({"read_only": True} if name != "evidence" else {}),
                        "bind": {},
                    }
                    for name, target in (
                        ("source", "/workspace"),
                        ("wheels", "/wheels"),
                        ("evidence", "/evidence"),
                    )
                ],
            )
            service["tmpfs"].append(
                "/opt/verification-deps:rw,exec,nosuid,nodev,size=128m,mode=0700,uid=10001,gid=10001"
            )
        services[role] = service
    if profile == "reliability":
        # Seven supervised runner processes for the paced 24-hour profile.
        services["runner"].update(
            mem_limit="1610612736", memswap_limit="1610612736", cpus=2, pids_limit=256
        )
        services["runner"]["environment"].update(
            SB_RELIABILITY_RUNTIME="1", SB_RELIABILITY_REHEARSAL_MS=str(rehearsal_ms)
        )
        services["runner"]["command"] = [
            "python",
            "-B",
            "-m",
            "integrations.enterprise.reliability_runner",
        ]
        # The shared run clock is the only path the runner and manager both see.
        services["runner"]["volumes"].append(
            {"type": "bind", "source": root + "/clock", "target": "/clock", "bind": {}}
        )
        from .reliability_wazuh import service as wazuh_service

        services["wazuh"] = wazuh_service(images, run, root)
    elif rehearsal_ms:
        raise LabControlError("Only the reliability profile accepts a rehearsal length.")
    if profile == "header":
        services["runner"]["environment"]["SB_HEADER_PROOF"] = "1"
        services["runner"]["command"] = [
            "python",
            "-B",
            "-m",
            "integrations.zap_enterprise.source_runner",
        ]
    ipam = {"config": [{"subnet": reliability_subnet(run)}]} if profile == "reliability" else {}
    return {
        "name": project,
        "services": services,
        "networks": {
            "reference": {
                "name": "sb-enterprise-reference-internal-" + run,
                "ipam": ipam,
                "internal": True,
                "labels": labels,
            }
        },
        "volumes": {"reference_data": {"name": project, "labels": labels}},
        "secrets": {
            name: {"name": project + "_" + name, "file": root + "/secrets/" + filename}
            for name, filename in SECRETS.items()
        },
    }


def verify_compose_config(data, images, run, directory, *, profile="access", rehearsal_ms=0):
    expected = expected_config(images, run, directory, profile=profile, rehearsal_ms=rehearsal_ms)
    actual = copy.deepcopy(data)
    try:
        for name, service in actual["services"].items():
            limit = expected["services"][name]["cpus"]
            if type(service.get("cpus")) not in (int, float) or service["cpus"] != limit:
                raise LabControlError("Unexpected source CPU limit.")
            service["cpus"] = limit
            for mount in service["volumes"]:
                if mount.get("type") == "bind":
                    mount["source"] = path(mount["source"])
            if "secrets" in service:
                service["secrets"] = sorted(service["secrets"], key=lambda item: item["source"])
        for value in actual["secrets"].values():
            value["file"] = path(value["file"])
        for service in expected["services"].values():
            if "secrets" in service:
                service["secrets"] = sorted(service["secrets"], key=lambda item: item["source"])
    except (KeyError, TypeError, AttributeError):
        raise LabControlError("Malformed parsed source recipe.") from None
    if json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise LabControlError("Parsed source recipe differs from the closed reviewed preparation.")
    return {
        "parsed_recipe_verified": True,
        "services": len(expected["services"]),
        "published_ports": 0,
        "runtime_verified": False,
    }
