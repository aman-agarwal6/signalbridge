"""Credential file boundary checks with disposable synthetic values only."""

import os
import shutil
import stat
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from scripts import lab_credentials as credential


class LabCredentialTests(TestCase):
    def setUp(self):
        self.parent = credential.ROOT / "var/tests"
        self.root = self.parent / ("lab-credential-" + uuid.uuid4().hex)
        self.path = self.root / credential.RELATIVE
        self.path.parent.mkdir(parents=True)
        self.addCleanup(self.cleanup)
        self.value = "0123456789abcdef" * 4

    def cleanup(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.parent.resolve()) or not target.name.startswith(
            "lab-credential-"
        ):
            raise RuntimeError("Unsafe credential test cleanup")
        shutil.rmtree(target)

    def write(self, value):
        self.path.write_bytes(value.encode("utf8"))

    def test_literal_value_is_loaded_without_environment_override(self):
        self.write(f"# Synthetic test\nIGNORED=non-secret\n{credential.KEY}={self.value}\n")
        with patch.dict(os.environ, {credential.KEY: "environment-must-not-win"}):
            self.assertEqual(credential.read_database_password(self.root), self.value)

    def test_missing_default_empty_quoted_expansion_and_duplicate_values_fail(self):
        for assignment in (
            "IGNORED=non-secret",
            f"{credential.KEY}=postgres",
            f"{credential.KEY}=",
            f'{credential.KEY}="{self.value}"',
            f"{credential.KEY}=$(malicious-command)",
            f"{credential.KEY}={self.value}\n{credential.KEY}={self.value}",
            f"export {credential.KEY}={self.value}",
        ):
            with self.subTest(kind=assignment.split("=", 1)[0]):
                self.write(assignment)
                with self.assertRaises(credential.LabCredentialError) as raised:
                    credential.read_database_password(self.root)
                self.assertNotIn(self.value, str(raised.exception))
                self.assertNotIn("malicious-command", str(raised.exception))

    def test_missing_file_and_bad_encoding_or_oversized_file_fail(self):
        for raw in (None, b"\xff\xfe", b"x" * (credential.MAX_BYTES + 1)):
            with self.subTest(kind=type(raw).__name__):
                if raw is not None:
                    self.path.write_bytes(raw)
                with self.assertRaises(credential.LabCredentialError):
                    credential.read_database_password(self.root)

    def test_linked_parent_and_hard_linked_credential_are_refused(self):
        self.write(f"{credential.KEY}={self.value}")
        real = Path.lstat
        for target, changed in (
            (self.path.parent, {"st_file_attributes": 1024}),
            (self.path, {"st_mode": stat.S_IFLNK}),
            (self.path, {"st_nlink": 2}),
        ):

            def altered(path, *args, target=target, changed=changed, **kwargs):
                info = real(path, *args, **kwargs)
                if path != target:
                    return info
                fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                return SimpleNamespace(**{**fields, **changed})

            with (
                patch.object(Path, "lstat", altered),
                self.assertRaises(credential.LabCredentialError),
            ):
                credential.read_database_password(self.root)

    def test_changed_file_identity_is_refused(self):
        self.write(f"{credential.KEY}={self.value}")
        with patch.object(os, "fstat", return_value=SimpleNamespace(st_dev=-1, st_ino=-1)):
            with self.assertRaises(credential.LabCredentialError):
                credential.read_database_password(self.root)
