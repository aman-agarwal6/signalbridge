"""Independent snapshot safety checks with disposable synthetic source only."""

import hashlib
import json
import shutil
import stat
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from scripts import snapshot_app as snapshot


class SnapshotTests(TestCase):
    def setUp(self):
        self.test_root = snapshot.ROOT / "var" / "tests"
        # Keep nested content-addressed fixtures below Windows' legacy path limit.
        # Exclusive mkdir still fails safely on the unlikely random collision.
        self.case = self.test_root / ("snapshot-" + uuid.uuid4().hex[:16])
        self.case.mkdir(parents=True)
        self.addCleanup(self.cleanup_case)
        self.workspace = self.case / "w"
        self.source = self.case / "source"
        self.workspace.mkdir()
        self.source.mkdir()
        for name, value in {
            "package.json": '{"name":"synthetic-source"}',
            "package-lock.json": '{"lockfileVersion":3}',
            "tsconfig.json": "{}",
            "next.config.ts": "export default {};",
            "next-env.d.ts": '/// <reference types="next" />',
            "postcss.config.mjs": "export default {};",
            "src/app/page.tsx": "export default function Page() { return null; }",
            "src/app/style.css": "body { color: black; }",
            "supabase/migrations/001_create.sql": "select 1;",
        }.items():
            self.write(name, value)
        self.provenance = {"source_revision": "a" * 40, "source_dirty": True}
        self.git = patch.object(snapshot, "git_provenance", return_value=self.provenance.copy())
        self.git.start()
        self.addCleanup(self.git.stop)

    def cleanup_case(self):
        # Delete only this test's uniquely named directory after checking its boundary.
        target = self.case.resolve()
        if not target.is_relative_to(self.test_root.resolve()) or not target.name.startswith(
            "snapshot-"
        ):
            raise RuntimeError("Unsafe test cleanup target")
        shutil.rmtree(target)

    def write(self, name, value):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
        return path

    def create(self, **changes):
        return snapshot.create_snapshot("bettail", self.source, workspace=self.workspace, **changes)

    def test_allowlist_excludes_secrets_runtime_uploads_and_unrelated_data(self):
        for name in (
            ".env",
            ".env.local",
            ".npmrc",
            ".git/config",
            ".vercel/project.json",
            "node_modules/package/index.js",
            "public/uploads/person.json",
            "private.sqlite3",
            "src/.env.local",
            "src/.env.local.json",
            "src/exports/user.json",
            "src/databases/users.json",
            "src/logs/activity.json",
            "src/uploads/private.json",
            "src/secrets.pem",
            "supabase/config.toml",
            "supabase/seed.sql",
        ):
            self.write(name, "private-sentinel")
        destination, created = self.create()
        self.assertTrue(created)
        data = snapshot.verify_snapshot(destination, self.workspace)
        self.assertEqual(data["source_revision"], "a" * 40)
        self.assertTrue(data["source_dirty"])
        self.assertIn("postcss.config.mjs", data["files"])
        self.assertEqual(len(data["files"]), 9)
        for path in destination.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"private-sentinel", path.read_bytes())
        self.assertEqual((self.source / ".env").read_text(), "private-sentinel")

    def test_content_hashes_are_exact_and_deterministic_and_repeat_does_not_rewrite(self):
        destination, _ = self.create()
        data = snapshot.verify_snapshot(destination, self.workspace)
        self.assertEqual(destination.name, snapshot.content_digest("bettail", data["files"]))
        self.assertEqual(
            data["files"]["package.json"],
            hashlib.sha256((self.source / "package.json").read_bytes()).hexdigest(),
        )
        before = {
            path.relative_to(destination).as_posix(): path.stat().st_mtime_ns
            for path in destination.rglob("*")
            if path.is_file()
        }
        repeated, created = self.create()
        self.assertFalse(created)
        self.assertEqual(repeated, destination)
        after = {
            path.relative_to(destination).as_posix(): path.stat().st_mtime_ns
            for path in destination.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)

    def test_changed_content_gets_new_directory_preserving_original(self):
        first, _ = self.create()
        previous = (first / "src/app/page.tsx").read_bytes()
        self.write("src/app/page.tsx", "export default function Page() { return 'changed'; }")
        second, created = self.create()
        self.assertTrue(created)
        self.assertNotEqual(first, second)
        self.assertEqual((first / "src/app/page.tsx").read_bytes(), previous)
        snapshot.verify_snapshot(first, self.workspace)

    def test_output_must_be_exact_private_workspace_destination(self):
        for output in (
            self.case / "escape",
            "../escape",
            "private-source/netted/" + "a" * 64,
            "private-source/bettail/" + "a" * 64,
        ):
            with self.subTest(output=output), self.assertRaises(snapshot.SnapshotError):
                self.create(output=output)
        self.assertFalse((self.workspace / "private-source").exists())

    def test_missing_lockfile_source_or_migrations_fails_before_copy(self):
        for name in (
            "package-lock.json",
            "supabase/migrations/001_create.sql",
        ):
            path = self.source / name
            saved = path.read_bytes()
            path.unlink()
            with self.subTest(missing=name), self.assertRaises(snapshot.SnapshotError):
                self.create()
            path.write_bytes(saved)
        (self.source / "src/app/page.tsx").unlink()
        (self.source / "src/app/style.css").unlink()
        with self.assertRaises(snapshot.SnapshotError):
            self.create()
        self.assertFalse((self.workspace / "private-source").exists())

    def test_reparse_file_and_symbolic_link_metadata_are_rejected(self):
        original = Path.lstat
        target = self.source / "src/app/page.tsx"
        for mode, attributes in (
            (stat.S_IFLNK, 0),
            (stat.S_IFREG, stat.FILE_ATTRIBUTE_REPARSE_POINT),
        ):

            def altered(path, mode=mode, attributes=attributes, **kwargs):
                if path == target:
                    return SimpleNamespace(st_mode=mode, st_file_attributes=attributes, st_size=5)
                return original(path, **kwargs)

            with patch.object(Path, "lstat", altered), self.assertRaises(snapshot.SnapshotError):
                self.create()
        self.assertFalse((self.workspace / "private-source").exists())

    def test_source_change_during_copy_never_creates_ready_record(self):
        original = snapshot._read
        target = self.source / "src/app/page.tsx"
        calls = 0

        def changing(path, root):
            nonlocal calls
            if path == target:
                calls += 1
                if calls == 2:
                    self.write("src/app/page.tsx", "changed while copying")
            return original(path, root)

        with patch.object(snapshot, "_read", changing), self.assertRaises(snapshot.SnapshotError):
            self.create()
        destinations = list((self.workspace / "private-source/bettail").iterdir())
        self.assertEqual(len(destinations), 1)
        self.assertTrue((destinations[0] / snapshot.INCOMPLETE).is_file())
        self.assertFalse((destinations[0] / snapshot.READY).exists())
        with self.assertRaises(snapshot.SnapshotError):
            snapshot.verify_snapshot(destinations[0], self.workspace)

    def test_linked_output_parent_is_rejected_without_writing_snapshot(self):
        target = self.workspace / "private-source"
        target.mkdir()
        original = Path.lstat

        def linked(path, **kwargs):
            if path == target:
                return SimpleNamespace(
                    st_mode=stat.S_IFDIR, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT
                )
            return original(path, **kwargs)

        with patch.object(Path, "lstat", linked), self.assertRaises(snapshot.SnapshotError):
            self.create()
        self.assertEqual(list(target.iterdir()), [])

    def test_source_provenance_change_during_copy_leaves_incomplete_evidence(self):
        with patch.object(
            snapshot,
            "git_provenance",
            side_effect=[self.provenance, {**self.provenance, "source_revision": "b" * 40}],
        ):
            with self.assertRaises(snapshot.SnapshotError):
                self.create()
        self.assertFalse(list((self.workspace / "private-source").rglob(snapshot.READY)))

    def test_existing_snapshot_conflict_never_overwrites_evidence(self):
        destination, _ = self.create()
        before = (destination / snapshot.READY).read_bytes()
        with patch.object(
            snapshot,
            "git_provenance",
            return_value={**self.provenance, "source_revision": "b" * 40},
        ):
            with self.assertRaises(snapshot.SnapshotError):
                self.create()
        self.assertEqual((destination / snapshot.READY).read_bytes(), before)

    def test_verifier_rejects_modified_and_unexpected_files(self):
        destination, _ = self.create()
        path = destination / "src/app/page.tsx"
        before = path.read_bytes()
        path.write_bytes(b"tampered")
        with self.assertRaises(snapshot.SnapshotError):
            snapshot.verify_snapshot(destination, self.workspace)
        path.write_bytes(before)
        (destination / ".env").write_text("unexpected-private-data")
        with self.assertRaises(snapshot.SnapshotError):
            snapshot.verify_snapshot(destination, self.workspace)

    def test_manifest_cannot_reference_outside_file(self):
        destination, _ = self.create()
        path = destination / snapshot.READY
        data = json.loads(path.read_bytes())
        data["files"]["../outside.json"] = "a" * 64
        path.write_text(json.dumps(data))
        with self.assertRaises(snapshot.SnapshotError):
            snapshot.verify_snapshot(destination, self.workspace)

    def test_git_provenance_uses_read_only_commands_and_stores_no_status_paths(self):
        self.git.stop()
        with (
            patch.object(snapshot.shutil, "which", return_value="git"),
            patch.object(
                snapshot.subprocess,
                "check_output",
                side_effect=[str(self.source), "c" * 40, " M .env.local"],
            ) as query,
        ):
            value = snapshot.git_provenance(self.source)
        self.assertEqual(value, {"source_revision": "c" * 40, "source_dirty": True})
        self.assertNotIn(".env", json.dumps(value))
        for call in query.call_args_list:
            self.assertIn("--no-optional-locks", call.args[0])
            self.assertIn("core.fsmonitor=false", call.args[0])
