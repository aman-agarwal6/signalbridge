"""Hostile kernel-evidence models; genuine Linux execution remains required."""

from django.test import SimpleTestCase

from integrations.enterprise.reference_controls import SECRETS
from integrations.enterprise.reference_kernel import verify_identity


class ReferenceKernelTests(SimpleTestCase):
    def setUp(self):
        self.status = "\n".join(
            [
                "Uid:\t10001 10001 10001 10001",
                "Gid:\t10001 10001 10001 10001",
                "Groups:\t10001",
                *[
                    k + ":\t0000000000000000"
                    for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
                ],
                "NoNewPrivs:\t1",
                "Seccomp:\t2",
            ]
        )
        self.groups = {
            "memory.max": "536870912\n",
            "memory.swap.max": "0\n",
            "pids.max": "96\n",
            "cpu.max": "100000 100000\n",
        }
        targets = [
            "/",
            "/workspace",
            "/wheels",
            "/evidence",
            *["/run/secrets/" + k for k in SECRETS if k != "bootstrap_password"],
        ]
        self.mounts = "\n".join(
            f"{i + 1} 0 0:1 / {p} {'rw' if p == '/evidence' else 'ro'},nosuid - bind none ro"
            for i, p in enumerate(targets)
        )

    def test_reviewed_kernel_model_is_accepted(self):
        result = verify_identity(self.status, self.groups, self.mounts)
        self.assertTrue(result["all_capabilities_zero"])
        self.assertEqual(result["memory_bytes"], 536870912)
        # OCI may supply no supplementary groups when uid:gid is explicit.
        empty = verify_identity(
            self.status.replace("Groups:\t10001", "Groups:"), self.groups, self.mounts
        )
        self.assertEqual(empty["supplementary_groups"], [])

    def test_root_extra_groups_capabilities_and_missing_seccomp_rejected(self):
        for original, replacement in (
            ("Uid:\t10001 10001 10001 10001", "Uid:\t0 0 0 0"),
            ("Groups:\t10001", "Groups:\t10001 0"),
            ("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            ("Seccomp:\t2", "Seccomp:\t0"),
        ):
            with self.subTest(original=original), self.assertRaises(ValueError):
                verify_identity(
                    self.status.replace(original, replacement), self.groups, self.mounts
                )
        with self.assertRaises(ValueError):
            verify_identity(self.status + "\nSeccomp:\t2", self.groups, self.mounts)

    def test_unlimited_changed_wrong_type_cgroup_and_cpu_rejected(self):
        for key, value in (
            ("memory.max", "max"),
            ("memory.swap.max", "1"),
            ("pids.max", "max"),
            ("cpu.max", "max 100000"),
            ("cpu.max", "200000 100000"),
            ("cpu.max", "100000 100000 extra"),
            ("memory.max", True),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                verify_identity(self.status, {**self.groups, key: value}, self.mounts)

    def test_writable_secrets_missing_readonly_bind_and_duplicate_mount_rejected(self):
        for original, replacement in (
            ("/workspace ro,", "/workspace rw,"),
            ("/run/secrets/source_profile ro,", "/run/secrets/source_profile rw,"),
            ("/evidence rw,", "/evidence ro,"),
        ):
            with self.subTest(original=original), self.assertRaises(ValueError):
                verify_identity(
                    self.status, self.groups, self.mounts.replace(original, replacement)
                )
        with self.assertRaises(ValueError):
            verify_identity(self.status, self.groups, self.mounts.splitlines()[0])
        with self.assertRaises(ValueError):
            verify_identity(
                self.status, self.groups, self.mounts + "\n" + self.mounts.splitlines()[0]
            )
