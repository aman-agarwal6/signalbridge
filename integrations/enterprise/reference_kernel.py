"""Closed Linux kernel evidence for the fixed reference runner; no IO on import."""

from .reference_controls import SECRETS

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


def verify_identity(status, cgroups, mountinfo):
    """Validate actual /proc and cgroup v2 values, not recipe assertions."""
    if (
        not isinstance(status, str)
        or len(status) > 16384
        or not isinstance(mountinfo, str)
        or len(mountinfo) > 131072
        or not isinstance(cgroups, dict)
        or set(cgroups) != CGROUPS
    ):
        raise ValueError("Kernel identity evidence escaped the fixed profile.")
    fields = {}
    for line in status.splitlines():
        key, separator, value = line.partition(":")
        if separator and key in STATUS:
            if key in fields:
                raise ValueError("Duplicate kernel identity field.")
            fields[key] = value.strip()
    if (
        set(fields) != STATUS
        or any(fields[k].split() != ["10001"] * 4 for k in ("Uid", "Gid"))
        or fields["Groups"].split() not in ([], ["10001"])
        or any(
            fields[k] != "0000000000000000"
            for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        )
        or fields["NoNewPrivs"] != "1"
        or fields["Seccomp"] != "2"
    ):
        raise ValueError("Effective kernel identity or privileges differ from the runner profile.")
    if (
        any(type(v) is not str or not 1 <= len(v) <= 64 for v in cgroups.values())
        or cgroups["memory.max"].strip() != str(512 * 1024**2)
        or cgroups["memory.swap.max"].strip() != "0"
        or cgroups["pids.max"].strip() != "96"
    ):
        raise ValueError("Effective cgroup v2 memory, swap or process limits changed.")
    parts = cgroups["cpu.max"].split()
    if (
        len(parts) != 2
        or any(not v.isascii() or not v.isdecimal() for v in parts)
        or parts[0] != parts[1]
        or not 1000 <= int(parts[0]) <= 1000000
    ):
        raise ValueError("Effective cgroup CPU budget changed.")
    expected = {"/": True, "/workspace": True, "/wheels": True, "/evidence": False}
    expected.update(
        {"/run/secrets/" + name: True for name in SECRETS if name != "bootstrap_password"}
    )
    observed = {}
    for line in mountinfo.splitlines():
        columns = line.split()
        if len(columns) < 10 or columns[4] not in expected:
            continue
        target = columns[4]
        options = set(columns[5].split(","))
        if (
            target in observed
            or ("ro" in options) != expected[target]
            or ("rw" in options) == expected[target]
        ):
            raise ValueError("Effective kernel source/secrets/data mount permissions changed.")
        observed[target] = expected[target]
    if set(observed) != set(expected):
        raise ValueError("Required effective kernel mounts are missing.")
    return {
        "uid": 10001,
        "gid": 10001,
        "supplementary_groups": [int(v) for v in fields["Groups"].split()],
        "all_capabilities_zero": True,
        "no_new_privileges": True,
        "seccomp_filter": True,
        "cgroup_version": 2,
        "memory_bytes": 512 * 1024**2,
        "swap_bytes": 0,
        "pids": 96,
        "cpu_quota_equals_period": True,
        "read_only_root_source_wheels_secrets": True,
        "reviewed_evidence_mount_writable": True,
    }
