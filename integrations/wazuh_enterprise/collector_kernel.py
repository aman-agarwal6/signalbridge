"""Actual kernel observations for the fixed, networkless manager container."""

from .collector_profile import APPS, CHANNELS, recipe
from .contract import require

STATUS = {
    "Uid",
    "Gid",
    "Groups",
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapBnd",
    "CapAmb",
    "NoNewPrivs",
    "Seccomp",
}
CGROUPS = {"memory.max", "memory.swap.max", "pids.max", "cpu.max"}


def verify_kernel(value):
    require(
        type(value) is dict and set(value) == {"status", "cgroups", "mountinfo", "interfaces"},
        "collector_kernel_fields",
    )
    status, groups, mounts = value["status"], value["cgroups"], value["mountinfo"]
    require(
        type(status) is str
        and len(status) <= 16384
        and type(mounts) is str
        and len(mounts) <= 131072,
        "collector_kernel_size",
    )
    fields = {}
    for line in status.splitlines():
        key, separator, text = line.partition(":")
        if separator and key in STATUS:
            require(key not in fields, "collector_kernel_duplicate")
            fields[key] = text.strip()
    require(set(fields) == STATUS, "collector_kernel_status")
    require(
        all(fields[k].split() == ["0"] * 4 for k in ("Uid", "Gid")), "collector_kernel_identity"
    )
    require(fields["Groups"].split() in ([], ["0"]), "collector_kernel_groups")
    require(
        all(fields[k] == "0000000000000000" for k in ("CapInh", "CapAmb")),
        "collector_kernel_capabilities",
    )
    require(
        all(fields[k] == "00000000000400c0" for k in ("CapEff", "CapPrm", "CapBnd")),
        "collector_kernel_capabilities",
    )
    require(fields["NoNewPrivs"] == "1" and fields["Seccomp"] == "2", "collector_kernel_filter")
    require(
        type(groups) is dict
        and set(groups) == CGROUPS
        and all(type(v) is str and 0 < len(v) <= 64 for v in groups.values()),
        "collector_kernel_cgroups",
    )
    container = recipe()["container"]
    require(
        groups["memory.max"].strip() == str(container["memory_bytes"])
        and groups["memory.swap.max"].strip() == "0"
        and groups["pids.max"].strip() == str(container["pids"]),
        "collector_kernel_limits",
    )
    cpu = groups["cpu.max"].split()
    require(
        len(cpu) == 2
        and all(v.isascii() and v.isdecimal() for v in cpu)
        and cpu[0] == cpu[1]
        and 1000 <= int(cpu[0]) <= 1000000,
        "collector_kernel_cpu",
    )
    expected = {"/": False, "/workspace": True, "/evidence": False}
    expected.update(
        {f"/signalbridge/input/{app}/{channel}": True for app in APPS for channel in CHANNELS}
    )
    found = {}
    for line in mounts.splitlines():
        columns = line.split()
        if len(columns) < 10 or columns[4] not in expected:
            continue
        name, options = columns[4], set(columns[5].split(","))
        require(
            name not in found
            and ("ro" in options) == expected[name]
            and ("rw" in options) != expected[name],
            "collector_kernel_mounts",
        )
        found[name] = expected[name]
    require(set(found) == set(expected), "collector_kernel_mounts")
    require(value["interfaces"] == ["lo"], "collector_kernel_network")
    return {
        "uid": 0,
        "gid": 0,
        "capabilities": ["SETGID", "SETUID", "SYS_CHROOT"],
        "no_new_privileges": True,
        "seccomp_filter": True,
        "cgroup_version": 2,
        "memory_bytes": container["memory_bytes"],
        "swap_bytes": 0,
        "pids": container["pids"],
        "cpu_quota_equals_period": True,
        "source_and_four_inputs_readonly": True,
        "disposable_root_and_evidence_writable": True,
        "network_interfaces": ["lo"],
    }


def observe_kernel():
    """Fixed proc/sys files only; called inside the container before daemon start."""
    from pathlib import Path

    def read(name, bound):
        with Path(name).open("rb") as stream:
            raw = stream.read(bound + 1)
        require(len(raw) <= bound, "collector_kernel_read_limit")
        return raw.decode("ascii")

    value = {
        "status": read("/proc/self/status", 16384),
        "mountinfo": read("/proc/self/mountinfo", 131072),
        "cgroups": {name: read("/sys/fs/cgroup/" + name, 64) for name in CGROUPS},
        "interfaces": sorted(p.name for p in Path("/sys/class/net").iterdir()),
    }
    verify_kernel(value)
    return value
