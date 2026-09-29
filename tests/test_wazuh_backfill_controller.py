"""Controller locking checks with a disposable folder and no native execution."""

import contextlib
import io
import shutil
import unittest
import uuid
from unittest.mock import patch

from scripts import run_wazuh_backfill as runner
from scripts.local_backup import safe


class BackfillControllerTests(unittest.TestCase):
    def setUp(self):
        self.parent = runner.ROOT / "artifacts/local"
        self.root = self.parent / ("backfill-controller-test-" + uuid.uuid4().hex)
        self.root.mkdir()
        (self.root / "var/soc").mkdir(parents=True)
        self.addCleanup(self.cleanup)
        self.lock = self.root / "var/soc/backfill.lock"

    def cleanup(self):
        safe(self.parent, self.root, directory=True)
        for child in self.root.rglob("*"):
            safe(self.root, child, directory=child.is_dir())
        shutil.rmtree(self.root)

    def invoke(self, execute):
        with (
            patch.object(runner, "ROOT", self.root),
            patch.object(runner.sys, "argv", ["runner"]),
            patch.object(runner, "execute", side_effect=execute) as native,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = runner.main()
        return result, native.call_count

    def test_existing_lock_preserved_without_execution(self):
        self.lock.write_bytes(b"preserve existing attempt")
        self.assertEqual(self.invoke(lambda _run: 0), (1, 0))
        self.assertEqual(self.lock.read_bytes(), b"preserve existing attempt")

    def test_failed_or_interrupted_attempt_retains_lock_success_releases_only_own_lock(self):
        self.assertEqual(self.invoke(lambda _run: 1), (1, 1))
        self.assertTrue(self.lock.is_file())
        self.lock.unlink()  # This fixture has never started a process.
        self.assertEqual(self.invoke(lambda _run: 0), (0, 1))
        self.assertFalse(self.lock.exists())

        def fail(_run):
            raise ValueError("simulated interruption")

        self.assertEqual(self.invoke(fail), (1, 1))
        self.assertTrue(self.lock.is_file())

    def test_changed_lock_is_never_removed_on_success(self):
        def changed(_run):
            self.lock.write_bytes(b"another identity")
            return 0

        self.assertEqual(self.invoke(changed), (1, 1))
        self.assertEqual(self.lock.read_bytes(), b"another identity")
