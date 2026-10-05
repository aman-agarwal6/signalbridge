"""Fixed four-container identity recipe and effective Docker validation.

No operation is performed on import. The reviewed Windows controller invokes
these functions with private per-run paths. It never pulls images or removes data.
"""

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

from integrations.enterprise import verification as base
from integrations.enterprise.network_verification import host_path
from integrations.enterprise.reference_host_controls import runtime_fields, same
from integrations.wazuh_enterprise.collector_host_controls import environment

PREFIX, SCOPE = "sb-enterprise-identity-", "native-keycloak-identity"
NETWORK = "sb-enterprise-identity-internal-"
IMAGES = {
    "database": "postgres@sha256:e31e3d5327d1806f6177827c9710643e4f35f7ab3f14d26d05332753d3e95ee0",
    "keycloak": "quay.io/keycloak/keycloak@sha256:d79bc4bf1c54e802735ef91926b5c003de1fbb50b1a93382611972277219c9ad",
    "runner": "python@sha256:7bf6c3111fe094f8ee1a1cbcdc63c4cfb345b0e3df42d5aa9a90b3b4b022ab6d",
    "browser": "mcr.microsoft.com/playwright/python@sha256:72bd171a9ffc2b4b59532aaa6210e21014d07093120dc25528870c0b840da1f0",
}
# Containers that join Keycloak's network namespace for the fixed loopback issuer.
SHARED_NAMESPACE = ("runner", "browser")
ROLES = {
    "database": {"user": "postgres", "memory": 512 * 1024**2, "pids": 128, "readonly": True},
    "keycloak": {"user": "1000:1000", "memory": 2048 * 1024**2, "pids": 256, "readonly": False},
    "runner": {"user": "10001:10001", "memory": 512 * 1024**2, "pids": 96, "readonly": True},
    # Chromium runs several processes with many threads each.
    "browser": {"user": "1000:1000", "memory": 1536 * 1024**2, "pids": 512, "readonly": True},
}
COMMANDS = {
    "database": [
        "postgres",
        "-c",
        "shared_buffers=64MB",
        "-c",
        "max_connections=30",
        "-c",
        "log_statement=none",
    ],
    "keycloak": ["--config-file=/run/secrets/keycloak.conf", "start", "--import-realm"],
    "runner": ["python", "-B", "-m", "integrations.identity.native_runner"],
    "browser": ["python3", "-B", "-m", "integrations.identity.native_browser"],
}
TMPFS = {
    "database": {
        "/tmp": "rw,noexec,nosuid,nodev,size=64m",
        "/var/run/postgresql": "rw,noexec,nosuid,nodev,size=16m",
    },
    "keycloak": {},
    "runner": {
        "/tmp": "rw,noexec,nosuid,nodev,size=64m",
        "/opt/identity-deps": "rw,exec,nosuid,nodev,size=256m,mode=0700,uid=10001,gid=10001",
    },
    # Chromium profile/shared memory stay noexec; only installed wheels may map code.
    "browser": {
        "/tmp": "rw,noexec,nosuid,nodev,size=256m",
        "/opt/browser-deps": "rw,exec,nosuid,nodev,size=384m,mode=0700,uid=1000,gid=1000",
    },
}


def require(condition):
    if not condition:
        raise base.LabControlError("Native identity host control rejected an unreviewed state.")


def request(docker, run, workspace, arguments, timeout=10):
    directory = base.private_run_directory(workspace, run)
    return base.docker_result(
        docker, ["--config", str(directory / "docker-config"), *arguments], timeout=timeout
    )


def labels(run, component=None):
    base.validate_identity(run)
    value = {"org.signalbridge.enterprise.run": run, "org.signalbridge.enterprise.scope": SCOPE}
    if component is not None:
        require(component in ROLES)
        value["org.signalbridge.enterprise.component"] = component
    return value


def env(component, run):
    return {
        "database": {
            "POSTGRES_USER": "postgres",
            "POSTGRES_DB": "postgres",
            "POSTGRES_PASSWORD_FILE": "/run/secrets/bootstrap-password",
            "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256 --auth-local=peer",
        },
        "keycloak": {"JAVA_OPTS_KC_HEAP": "-XX:InitialRAMPercentage=25 -XX:MaxRAMPercentage=60"},
        "runner": {
            "SB_IDENTITY_NATIVE": "1",
            "SB_IDENTITY_RUN": run,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
            "PIP_CONFIG_FILE": "/dev/null",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        },
        "browser": {
            "SB_IDENTITY_NATIVE": "1",
            "SB_IDENTITY_RUN": run,
            "HOME": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUTF8": "1",
            "PIP_CONFIG_FILE": "/dev/null",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        },
    }[component]


def mounts(component, directory):
    directory = Path(directory)
    secret_names = {
        "database": ("bootstrap-password", "console-password", "keycloak-password"),
        "keycloak": (
            "keycloak.conf",
            "lab-ca.pem",
            "provider-certificate.pem",
            "provider-private-key.pem",
        ),
        "runner": (
            "identity-profile.json",
            "lab-ca.pem",
            "console-certificate.pem",
            "console-private-key.pem",
        ),
        # Public server certificates only, to pin their keys; no private keys.
        "browser": (
            "identity-profile.json",
            "console-certificate.pem",
            "provider-certificate.pem",
        ),
    }[component]
    result = {
        "/run/secrets/" + name: (directory / "secrets" / name, False) for name in secret_names
    }
    if component == "database":
        result["/docker-entrypoint-initdb.d/10-identity.sh"] = (
            directory / "source/integrations/identity/init-databases.sh",
            False,
        )
    elif component == "keycloak":
        result["/opt/keycloak/data/import/signalbridge-realm.json"] = (
            directory / "secrets/signalbridge-realm.json",
            False,
        )
    elif component == "runner":
        result.update(
            {
                "/workspace": (directory / "source", False),
                "/workspace/var": (directory / "state", True),
                "/wheels": (directory / "wheels", False),
                "/evidence": (directory / "evidence", True),
            }
        )
    else:
        result.update(
            {
                "/workspace": (directory / "source", False),
                "/browser-wheels": (directory / "browser-wheels", False),
                "/evidence": (directory / "evidence", True),
            }
        )
    return result


def inspect_images(docker, run, workspace):
    result = {}
    # The containerd image store omits empty config keys; direct field access
    # then fails the whole template, while index returns null.
    template = '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},"digests":{{json .RepoDigests}},"entrypoint":{{json (index .Config "Entrypoint")}},"environment":{{json (index .Config "Env")}},"workdir":{{json (index .Config "WorkingDir")}},"volumes":{{json (index .Config "Volumes")}}}'
    for component, reference in IMAGES.items():
        raw = request(docker, run, workspace, ["image", "inspect", reference, "--format", template])
        require(len(raw) <= 65536)
        value = json.loads(raw)
        require(
            value["os"] == "linux"
            and value["architecture"] == "amd64"
            and re.fullmatch(r"sha256:[a-f0-9]{64}", value["id"])
        )
        alternatives = {reference, "docker.io/library/" + reference}
        require(
            type(value["digests"]) is list and bool(alternatives.intersection(value["digests"]))
        )
        require(
            value["volumes"] in (None, {})
            if component != "database"
            else value["volumes"] == {"/var/lib/postgresql/data": {}}
        )
        environment(value["environment"])
        if component == "keycloak":
            # The classic store reports the config digest; the containerd store
            # reports the pinned target digest. Accept only these two identities.
            require(
                value["id"]
                in (
                    "sha256:43ebe9d4e97c2e5483b7637edf474e6adc1bbf4832a7396686cf90259c396d42",
                    "sha256:" + reference.rsplit("@sha256:", 1)[1],
                )
            )
            require(value["entrypoint"] == ["/opt/keycloak/bin/kc.sh"])
        result[component] = value
    return result


def create_arguments(component, image, run, directory, keycloak_id=None):
    require(component in ROLES and re.fullmatch(r"sha256:[a-f0-9]{64}", image["id"]))
    controls = ROLES[component]
    if component in SHARED_NAMESPACE:
        require(isinstance(keycloak_id, str) and re.fullmatch(r"[a-f0-9]{64}", keycloak_id))
    args = [
        "create",
        "--pull=never",
        "--name",
        PREFIX + run + "-" + component,
        "--network",
        "container:" + keycloak_id if component in SHARED_NAMESPACE else NETWORK + run,
        "--restart",
        "no",
        "--user",
        controls["user"],
        "--memory",
        str(controls["memory"]),
        "--memory-swap",
        str(controls["memory"]),
        "--cpus",
        "1",
        "--pids-limit",
        str(controls["pids"]),
        "--ipc",
        "private",
        "--cgroupns",
        "private",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--no-healthcheck",
        "--log-driver",
        "json-file",
        "--log-opt",
        "max-size=2m",
        "--log-opt",
        "max-file=2",
        "--shm-size",
        "64m",
    ]
    if controls["readonly"]:
        args.append("--read-only")
    if component == "database":
        args += [
            "--network-alias",
            "database",
            "--mount",
            "type=volume,source=" + PREFIX + run + ",target=/var/lib/postgresql/data",
        ]
    if component in SHARED_NAMESPACE:
        args += ["--workdir", "/workspace"]
    for name, value in labels(run, component).items():
        args += ["--label", name + "=" + value]
    for name, value in env(component, run).items():
        args += ["--env", name + "=" + value]
    for target, (source, writable) in mounts(component, directory).items():
        require(not any(c in str(source) for c in (",", "\x00", "\r", "\n", '"')))
        args += [
            "--mount",
            "type=bind,source="
            + str(source)
            + ",target="
            + target
            + ("" if writable else ",readonly"),
        ]
    for target, flags in TMPFS[component].items():
        args += ["--tmpfs", target + ":" + flags]
    return [*args, image["id"], *COMMANDS[component]]


def role(docker, run, workspace, identifier):
    require(isinstance(identifier, str) and re.fullmatch(r"[a-f0-9]{64}", identifier))
    raw = request(
        docker,
        run,
        workspace,
        [
            "inspect",
            identifier,
            "--format",
            '{"labels":{{json .Config.Labels}},"name":{{json .Name}}}',
        ],
    )
    require(len(raw) <= 16384)
    value = json.loads(raw)
    component = value["labels"].get("org.signalbridge.enterprise.component")
    require(
        component in ROLES
        and all(value["labels"].get(k) == v for k, v in labels(run, component).items())
    )
    require(value["name"] == "/" + PREFIX + run + "-" + component)
    return component


def inventory(docker, run, workspace):
    args = ["ps", "--all", "--quiet", "--no-trunc"]
    for name, value in labels(run).items():
        args += ["--filter", "label=" + name + "=" + value]
    raw = request(docker, run, workspace, args)
    values = raw.splitlines() if raw else []
    require(len(values) <= 8 and len(set(values)) == len(values))
    require(all(re.fullmatch(r"[a-f0-9]{64}", value) for value in values))
    return values


def owned(docker, run, workspace):
    values = inventory(docker, run, workspace)
    require(len(values) <= 4)
    result = {value: role(docker, run, workspace, value) for value in values}
    require(len(set(result.values())) == len(result))
    return result


def runtime_template():
    return (
        runtime_fields().replace("json .HostConfig.Tmpfs", 'json (index .HostConfig "Tmpfs")')[:-1]
        + ',"network_mode":{{json .HostConfig.NetworkMode}},"health":{{json (index .Config "Healthcheck")}},"shm":{{json .HostConfig.ShmSize}}}'
    )


def validate_runtime(value, component, image, run, directory, keycloak_id=None):
    controls = ROLES[component]
    fixed = {
        "image": image["id"],
        "memory": controls["memory"],
        "swap": controls["memory"],
        "cpu": 10**9,
        "pids": controls["pids"],
        "readonly": controls["readonly"],
        "privileged": False,
        "cap_drop": ["ALL"],
        "security": ["no-new-privileges:true"],
        "restart": "no",
        "user": controls["user"],
        "pid_mode": "",
        "ipc_mode": "private",
        "uts_mode": "",
        "cgroup_mode": "private",
        "command": COMMANDS[component],
        "entrypoint": image["entrypoint"],
        # An image without WorkingDir inspects as null; its container reports "".
        "workdir": "/workspace" if component in SHARED_NAMESPACE else image["workdir"] or "",
        "network_mode": (
            "container:" + str(keycloak_id) if component in SHARED_NAMESPACE else NETWORK + run
        ),
        "log": {"Type": "json-file", "Config": {"max-file": "2", "max-size": "2m"}},
        "health": {"Test": ["NONE"]},
        "shm": 64 * 1024**2,
    }
    other = {
        "cap_add",
        "devices",
        "device_requests",
        "port_bindings",
        "ports",
        "networks",
        "environment",
        "tmpfs",
        "mounts",
    }
    require(type(value) is dict and set(value) == set(fixed) | other)
    require(all(same(value[key], expected) for key, expected in fixed.items()))
    require(
        all(
            value[key] in (None, [], {})
            for key in ("cap_add", "devices", "device_requests", "port_bindings")
        )
    )
    require(
        value["ports"] is None
        or type(value["ports"]) is dict
        and all(p is None for p in value["ports"].values())
    )
    require(
        same(
            environment(value["environment"]),
            {**environment(image["environment"]), **env(component, run)},
        )
    )
    require(same(value["tmpfs"] or {}, TMPFS[component]))
    require(
        set(value["networks"] or {})
        == (set() if component in SHARED_NAMESPACE else {NETWORK + run})
    )
    require(type(value["mounts"]) is list)
    actual = {}
    for mount in value["mounts"]:
        require(type(mount) is dict and mount.get("Destination") not in actual)
        actual[mount["Destination"]] = mount
    for target in TMPFS[component]:
        if target in actual:
            require(actual.pop(target)["Type"] == "tmpfs")
    if component == "database":
        volume = actual.pop("/var/lib/postgresql/data", None)
        require(
            volume is not None
            and volume["Type"] == "volume"
            and volume["RW"] is True
            and volume.get("Name") == PREFIX + run
        )
    expected = mounts(component, directory)
    require(set(actual) == set(expected))
    for target, (source, writable) in expected.items():
        require(
            actual[target]["Type"] == "bind"
            and actual[target]["RW"] is writable
            and actual[target].get("Propagation") == "rprivate"
        )
        require(host_path(actual[target]["Source"]) == host_path(source))
    return True


def verify_runtime(docker, run, workspace, images, targets, *, capture=None, binding=None):
    if binding is not None:
        validate_resource_binding(binding, run)
    directory = base.private_run_directory(workspace, run)
    keycloak = next((key for key, value in targets.items() if value == "keycloak"), None)
    proofs = {}
    for identifier, component in targets.items():
        require(role(docker, run, workspace, identifier) == component)
        raw = request(
            docker, run, workspace, ["inspect", identifier, "--format", runtime_template()]
        )
        require(len(raw) <= 65536)
        value = json.loads(raw)
        validate_runtime(value, component, images[component], run, directory, keycloak)
        if binding is not None:
            if component not in SHARED_NAMESPACE:
                network_id = value["networks"][NETWORK + run].get("NetworkID")
                # Docker 29 attaches the endpoint at start: a created container
                # names the committed network but reports an empty NetworkID.
                require(
                    network_id == binding["network"]["id"]
                    or network_id == ""
                    and request(
                        docker,
                        run,
                        workspace,
                        ["inspect", identifier, "--format", "{{.State.Status}}"],
                    )
                    == "created"
                )
            if component == "database":
                volume = next(
                    row
                    for row in value["mounts"]
                    if row["Destination"] == "/var/lib/postgresql/data"
                )
                require(volume.get("Source") == binding["volume"]["mountpoint"])
        if capture is not None:
            capture[component] = {"container_id": identifier, "effective": value}
        proofs[component] = hashlib.sha256(raw.encode()).hexdigest()
    return proofs


def no_foreign_running(docker, run, workspace, targets=()):
    raw = request(docker, run, workspace, ["ps", "--quiet", "--no-trunc"])
    rows = raw.splitlines() if raw else []
    require(len(rows) <= 4 and len(set(rows)) == len(rows) and set(rows) <= set(targets))


def resource_time(value):
    require(
        type(value) is str
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})",
            value,
        )
    )
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        raise base.LabControlError("Invalid native resource creation identity.") from None


def validate_resource_binding(value, run):
    base.validate_identity(run)
    require(type(value) is dict and set(value) == {"network", "volume"})
    network, volume = value["network"], value["volume"]
    require(type(network) is dict and set(network) == {"name", "id", "created"})
    require(type(volume) is dict and set(volume) == {"name", "created", "mountpoint"})
    require(network["name"] == NETWORK + run and volume["name"] == PREFIX + run)
    require(type(network["id"]) is str and re.fullmatch(r"[a-f0-9]{64}", network["id"]))
    resource_time(network["created"])
    resource_time(volume["created"])
    mountpoint = volume["mountpoint"]
    require(
        type(mountpoint) is str
        and 0 < len(mountpoint) <= 1024
        and mountpoint.startswith("/")
        and mountpoint.endswith("/volumes/" + PREFIX + run + "/_data")
        and all(32 < ord(char) < 127 for char in mountpoint)
        and "\\" not in mountpoint
        and not set(mountpoint.split("/")) & {".", ".."}
    )
    return value


def resources(docker, run, workspace, targets, *, capture=None, binding=None):
    if binding is not None:
        validate_resource_binding(binding, run)
    require(type(targets) is dict and set(targets.values()) <= set(ROLES))
    identities = {}

    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result)
            result[key] = value
        return result

    for kind, name in (("network", NETWORK + run), ("volume", PREFIX + run)):
        raw = request(docker, run, workspace, [kind, "inspect", name])
        require(len(raw) <= 65536)
        rows = json.loads(raw, object_pairs_hook=pairs)
        require(type(rows) is list and len(rows) == 1)
        value = rows[0]
        require(type(value) is dict and value.get("Name") == name)
        require(same(value.get("Labels"), labels(run)))
        # Docker 29 records its default address-family options on every new
        # network. Accept only that exact pair (IPv6 off); volumes stay empty.
        require(
            value.get("Options") in (None, {})
            or kind == "network"
            and value.get("Options")
            == {"com.docker.network.enable_ipv4": "true", "com.docker.network.enable_ipv6": "false"}
        )
        if kind == "network":
            require(
                value.get("Internal") is True
                and value.get("Ingress") is False
                and value.get("Driver") == "bridge"
                and value.get("EnableIPv6") is False
            )
            members = value.get("Containers")
            require(type(members) is dict)
            require(
                set(members)
                <= {key for key, role in targets.items() if role not in SHARED_NAMESPACE}
            )
            identities[kind] = {
                "name": name,
                "id": value.get("Id"),
                "created": value.get("Created"),
            }
        else:
            require(value.get("Driver") == "local" and value.get("Scope") == "local")
            # Local volumes have no immutable Docker Id. Bind all available
            # creation identity; this is not proof against a dishonest daemon.
            identities[kind] = {
                "name": name,
                "created": value.get("CreatedAt"),
                "mountpoint": value.get("Mountpoint"),
            }
        if capture is not None:
            capture[kind] = value
    validate_resource_binding(identities, run)
    require(binding is None or same(identities, binding))
    return identities


def verify_kernel(value):
    """Runner's actual kernel state; other components retain metadata-only proof."""
    from integrations.enterprise.reference_kernel import CGROUPS, STATUS

    require(type(value) is dict and set(value) == {"status", "cgroups", "mountinfo"})
    require(type(value["status"]) is str and len(value["status"]) <= 16384)
    require(type(value["mountinfo"]) is str and len(value["mountinfo"]) <= 131072)
    fields = {}
    for line in value["status"].splitlines():
        key, separator, data = line.partition(":")
        if separator and key in STATUS:
            require(key not in fields)
            fields[key] = data.strip()
    require(set(fields) == STATUS)
    require(all(fields[key].split() == ["10001"] * 4 for key in ("Uid", "Gid")))
    require(fields["Groups"].split() in ([], ["10001"]))
    require(
        all(
            fields[key] == "0000000000000000"
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        )
    )
    require(fields["NoNewPrivs"] == "1" and fields["Seccomp"] == "2")
    cgroups = value["cgroups"]
    require(type(cgroups) is dict and set(cgroups) == CGROUPS)
    require(all(type(item) is str and 0 < len(item) <= 64 for item in cgroups.values()))
    require(cgroups["memory.max"].strip() == str(512 * 1024**2))
    require(cgroups["memory.swap.max"].strip() == "0" and cgroups["pids.max"].strip() == "96")
    cpu = cgroups["cpu.max"].split()
    require(len(cpu) == 2 and all(re.fullmatch(r"[0-9]{4,7}", part) for part in cpu))
    require(cpu[0] == cpu[1] and 1000 <= int(cpu[0]) <= 1000000)
    expected = {
        target: not writable for target, (_, writable) in mounts("runner", Path("unused")).items()
    }
    expected.update({"/": True, "/tmp": False, "/opt/identity-deps": False})
    observed = {}
    for line in value["mountinfo"].splitlines():
        columns = line.split()
        if len(columns) < 10 or columns[4] not in expected:
            continue
        target = columns[4]
        options = set(columns[5].split(","))
        require(target not in observed and "-" in columns)
        separator = columns.index("-")
        require(separator + 3 < len(columns))
        require(("ro" in options) is expected[target] and ("rw" in options) is not expected[target])
        if target in ("/tmp", "/opt/identity-deps"):
            require(columns[separator + 1] == "tmpfs" and {"nosuid", "nodev"} <= options)
            require(("noexec" in options) == (target == "/tmp"))
            super_options = set(columns[separator + 3].split(","))
            sizes = [item[5:] for item in super_options if item.startswith("size=")]
            require(len(sizes) == 1 and re.fullmatch(r"[1-9][0-9]*[kmg]?", sizes[0]))
            suffix = sizes[0][-1]
            size = (
                int(sizes[0][:-1]) * {"k": 1024, "m": 1024**2, "g": 1024**3}[suffix]
                if suffix in "kmg"
                else int(sizes[0])
            )
            require(size == (64 if target == "/tmp" else 256) * 1024**2)
            if target == "/opt/identity-deps":
                require({"uid=10001", "gid=10001", "mode=700"} <= super_options)
        observed[target] = expected[target]
    require(set(observed) == set(expected))
    return {
        "component": "runner",
        "uid": 10001,
        "gid": 10001,
        "capabilities_zero": True,
        "no_new_privileges": True,
        "seccomp_filter": True,
        "cgroup_v2_limits_verified": True,
        "readonly_root_and_inputs_verified": True,
        "scratch_noexec_64_mib": True,
        "dependency_exec_private_256_mib": True,
        "database_keycloak_kernel_probe": False,
    }


def inspect_kernel(docker, run, workspace, identifier):
    require(role(docker, run, workspace, identifier) == "runner")
    # Fixed reads only; no environment, command-line credentials or application
    # data enter this probe. It runs before releasing the native runner gate.
    code = (
        "import json;from pathlib import Path;"
        "r=lambda p,n:Path(p).open(encoding='ascii').read(n+1);"
        "print(json.dumps({'status':r('/proc/1/status',16384),"
        "'mountinfo':r('/proc/self/mountinfo',131072),"
        "'cgroups':{n:r('/sys/fs/cgroup/'+n,64) for n in "
        "('memory.max','memory.swap.max','pids.max','cpu.max')}}))"
    )
    raw = request(
        docker, run, workspace, ["exec", identifier, "python", "-I", "-c", code], timeout=10
    )
    require(len(raw) <= 196608)
    value = json.loads(raw)
    return value, verify_kernel(value)


def stop_scope(docker, run, workspace):
    errors, stopped = [], []
    targets = {}
    for identifier in inventory(docker, run, workspace):
        try:
            targets[identifier] = role(docker, run, workspace, identifier)
        except Exception:
            errors.append("ownership")
    order = {"browser": 0, "runner": 1, "keycloak": 2, "database": 3}
    for identifier, component in sorted(targets.items(), key=lambda row: order[row[1]]):
        try:
            require(role(docker, run, workspace, identifier) == component)
            request(docker, run, workspace, ["stop", "--time", "10", identifier], timeout=20)
            require(
                request(
                    docker,
                    run,
                    workspace,
                    ["inspect", identifier, "--format", "{{.State.Running}}"],
                )
                == "false"
            )
            stopped.append(component)
        except Exception:
            errors.append(component)
    require(not errors)
    return stopped
