"""Mocked bounded source preservation, without Docker or filesystem mutations."""

import copy
import hashlib
import io
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock

from scripts import snapshot_soc_pilot as snapshot

RUN = "3c900877-8bf7-49f4-bcaa-531d1baf57d3"
RAW = b"synthetic source\n"
HASH = hashlib.sha256(RAW).hexdigest()


def manifest():
    return {"package": {"run_pilot.py": HASH}, **dict.fromkeys(snapshot.SCRIPTS, HASH)}


class SnapshotTests(TestCase):
    def test_plan_has_only_fixed_package_and_gate_paths(self):
        rows = snapshot.copy_plan("wazuh", manifest())
        self.assertEqual(len(rows), 3)
        self.assertEqual(
            {row[0] for row in rows},
            {
                "package/run_pilot.py",
                "scripts/verify_soc_pilot.py",
                "scripts/verify_supabase_isolation.py",
            },
        )
        self.assertTrue(all(row[1].is_relative_to(snapshot.ROOT) for row in rows))

    def test_unknown_schema_traversal_ambiguity_and_bad_hashes_are_rejected(self):
        for name in ("../outside", "a//b", "/absolute", "C:/outside", "a\\b", "a/./b"):
            value = manifest()
            value["package"] = {name: HASH}
            with self.subTest(name=name), self.assertRaises(snapshot.SnapshotError):
                snapshot.copy_plan("wazuh", value)
        for value in (
            {},
            {**manifest(), "extra": HASH},
            {**manifest(), "verify_soc_pilot.py": "bad"},
            {**manifest(), "package": {"A.py": HASH, "a.py": HASH}},
        ):
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.copy_plan("wazuh", value)

    def run_mocked(self, *, changed=False, mkdir_error=None):
        before = manifest()
        after = copy.deepcopy(before)
        if changed:
            after["package"]["run_pilot.py"] = "a" * 64
        with ExitStack() as stack:
            source = stack.enter_context(
                mock.patch.object(snapshot.gate, "source_hashes", side_effect=[before, after])
            )
            read = stack.enter_context(
                mock.patch.object(snapshot, "read_checked", return_value=RAW)
            )
            stack.enter_context(mock.patch.object(snapshot.gate, "_safe"))
            stack.enter_context(mock.patch.object(Path, "exists", return_value=True))
            stack.enter_context(mock.patch.object(Path, "read_bytes", return_value=RAW))
            mkdir = stack.enter_context(
                mock.patch.object(snapshot, "_mkdir", side_effect=mkdir_error)
            )
            write = stack.enter_context(mock.patch.object(snapshot, "_write"))
            if changed or mkdir_error:
                with self.assertRaises((snapshot.SnapshotError, FileExistsError)):
                    snapshot.snapshot("wazuh", RUN)
                self.assertFalse(
                    any(call.args[0].name == "manifest.json" for call in write.call_args_list)
                )
                return
            result = snapshot.snapshot("wazuh", RUN)
            self.assertEqual(result["status"], "passed")
            self.assertEqual(
                result["source_sha256"],
                snapshot.gate.base.sha256(snapshot.gate.base.canonical(before)),
            )
            self.assertEqual(result["file_count"], 3)
            self.assertEqual(result["byte_count"], 3 * len(RAW))
            self.assertEqual(source.call_count, 2)
            self.assertEqual(read.call_count, 9)  # Prevalidate, read original, verify copied file.
            self.assertEqual(write.call_args_list[-1].args[0].name, "manifest.json")
            self.assertEqual(write.call_args_list[-2].args[0].name, "manifest.sha256")
            self.assertEqual(
                mkdir.call_args_list[0].args[0],
                snapshot.ROOT / "var/soc/pilot" / RUN / "source/wazuh",
            )

    def test_snapshot_matches_gate_digest_and_publishes_completion_last(self):
        self.run_mocked()

    def test_changed_sources_leave_no_completion_manifest(self):
        self.run_mocked(changed=True)

    def test_existing_or_incomplete_destination_is_never_overwritten(self):
        self.run_mocked(mkdir_error=FileExistsError("synthetic"))

    def test_failed_prevalidation_and_total_bounds_create_no_destination(self):
        with (
            mock.patch.object(snapshot.gate, "source_hashes", return_value=manifest()),
            mock.patch.object(snapshot, "_mkdir") as mkdir,
        ):
            with (
                mock.patch.object(
                    snapshot,
                    "read_checked",
                    side_effect=snapshot.SnapshotError("soc_snapshot_content_changed"),
                ),
                self.assertRaises(snapshot.SnapshotError),
            ):
                snapshot.snapshot("wazuh", RUN)
            with (
                mock.patch.object(snapshot, "read_checked", return_value=RAW),
                mock.patch.object(snapshot, "MAX_TOTAL_BYTES", 1),
                self.assertRaises(snapshot.SnapshotError),
            ):
                snapshot.snapshot("wazuh", RUN)
            mkdir.assert_not_called()

    def test_read_rejects_inode_link_size_and_content_changes(self):
        info = SimpleNamespace(st_dev=1, st_ino=2, st_nlink=1, st_size=len(RAW))

        class Handle(io.BytesIO):
            def fileno(self):
                return 10

        for issue in ("content", "inode", "links", "size"):
            opened = copy.copy(info)
            expected = HASH
            if issue == "content":
                expected = "a" * 64
            elif issue == "inode":
                opened.st_ino = 99
            elif issue == "links":
                opened.st_nlink = 2
            initial = copy.copy(info)
            if issue == "size":
                initial.st_size = snapshot.MAX_FILE_BYTES + 1
            with (
                self.subTest(issue=issue),
                mock.patch.object(snapshot.gate, "_safe", return_value=initial),
                mock.patch.object(snapshot.os, "fstat", return_value=opened),
                mock.patch.object(Path, "open", return_value=Handle(RAW)),
                self.assertRaises(snapshot.SnapshotError),
            ):
                snapshot.read_checked(snapshot.ROOT / "synthetic.py", expected)

    def test_invalid_run_identity_is_rejected_before_source_reads(self):
        with mock.patch.object(snapshot.gate, "source_hashes") as source:
            with self.assertRaises(snapshot.SnapshotError):
                snapshot.snapshot("wazuh", "../other")
            source.assert_not_called()
