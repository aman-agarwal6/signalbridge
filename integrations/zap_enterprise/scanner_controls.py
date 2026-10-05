"""Closed scanner recipe checks; daemon/kernel/host execution remains separate."""

import copy
import json
from pathlib import Path

from integrations.enterprise.reference_controls import path
from integrations.enterprise.verification import LabControlError

from .scanner_contract import MEMORY, hex_value

PREFIX, SCOPE = "sb-enterprise-zap-offline-", "authenticated-zap-offline"


def expected_config(image, run, directory):
    hex_value(run, 32)
    if not isinstance(image, str):
        raise LabControlError("The inspected cached scanner image ID is required.")
    hex_value(image.removeprefix("sha256:"))
    if not image.startswith("sha256:"):
        raise LabControlError("The inspected cached scanner image ID is required.")
    root = path(Path(directory).as_posix())
    return {
        "name": PREFIX + run,
        "services": {
            "scanner": {
                "image": image,
                "pull_policy": "never",
                "container_name": PREFIX + run,
                "labels": {
                    "org.signalbridge.enterprise.run": run,
                    "org.signalbridge.enterprise.scope": SCOPE,
                },
                "entrypoint": ["python3"],
                "command": ["-I", "-B", "/workspace/integrations/zap_enterprise/scanner_runner.py"],
                "working_dir": "/workspace",
                "environment": {
                    "SB_ZAP_SOURCE_PROOF": "1",
                    "SB_ZAP_RUN": run,
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
                "user": "1000:1000",
                "network_mode": "none",
                "read_only": True,
                "init": True,
                "restart": "no",
                "mem_limit": MEMORY,
                "memswap_limit": MEMORY,
                "cpus": 1.5,
                "pids_limit": 256,
                "ipc": "private",
                "cgroup": "private",
                "shm_size": 16 * 1024**2,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "healthcheck": {"disable": True},
                "logging": {"driver": "json-file", "options": {"max-size": "2m", "max-file": "2"}},
                "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=512m,mode=0700,uid=1000,gid=1000"],
                "volumes": [
                    {
                        "type": "bind",
                        "source": root + "/" + name,
                        "target": target,
                        **({"read_only": True} if name != "evidence" else {}),
                        "bind": {"create_host_path": False},
                    }
                    for name, target in (
                        ("source", "/workspace"),
                        ("input", "/input"),
                        ("evidence", "/evidence"),
                    )
                ],
            },
        },
    }


def verify_compose_config(value, image, run, directory):
    if not isinstance(value, dict):
        raise LabControlError("Invalid scanner recipe structure.")
    actual = copy.deepcopy(value)
    try:
        if set(actual) != {"name", "services"} or set(actual["services"]) != {"scanner"}:
            raise LabControlError("Unexpected scanner services or networks.")
        config = actual["services"]["scanner"]
        for key in ("mem_limit", "memswap_limit", "shm_size", "pids_limit"):
            if isinstance(config[key], str) and config[key].isascii() and config[key].isdecimal():
                config[key] = int(config[key])
        if isinstance(config["cpus"], str) and config["cpus"] == "1.5":
            config["cpus"] = 1.5
        for item in config["volumes"]:
            item["source"] = path(item["source"])
        if json.dumps(actual, sort_keys=True) != json.dumps(
            expected_config(image, run, directory), sort_keys=True
        ):
            raise LabControlError("The scanner recipe changed the closed isolation profile.")
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        if isinstance(error, LabControlError):
            raise
        raise LabControlError("Malformed scanner isolation recipe.") from None
    return {"fixed_scanner_profile_verified": True, "native_execution": False}
