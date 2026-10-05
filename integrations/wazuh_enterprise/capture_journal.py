"""Durable native-log capture, independent of parsing or delivery attestation.

Bytes and their source offset commit together. A replacement log is admitted only
after the previous open file is drained and checked. Recovery never skips a lost
old generation. No processes, network, log deletion or automatic repair.
"""

import hashlib
import os
import re
import sqlite3
import stat
import time
from pathlib import Path

from bridge.runtime_identity import _plain_path

from .contract import identifier, require

CHUNK_BYTES = 128 * 1024
MAX_BYTES = 64 * 1024**2
MAX_DATABASE_BYTES = 96 * 1024**2
MAX_GENERATIONS = 512
EMPTY = hashlib.sha256(b"").hexdigest()


def identity(info):
    return f"{info.st_dev:x}:{info.st_ino:x}"


def plain(path, *, directory=False):
    for parent in path.parents:
        _plain_path(parent, directory=True)
    _plain_path(path, directory=directory)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "capture_path")
    return info


class CaptureJournal:
    def __init__(self, directory, run_id, *, create=False, readonly=False):
        require(not (create and readonly), "capture_readonly_creation")
        identifier(run_id)
        self.directory = Path(directory)
        plain(self.directory, directory=True)
        self.path = self.directory / "capture.sqlite3"
        if create:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        info = plain(self.path)
        require(info.st_nlink == 1 and info.st_size <= MAX_DATABASE_BYTES, "capture_database_file")
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                other = plain(sidecar)
                require(
                    other.st_nlink == 1 and other.st_size <= MAX_DATABASE_BYTES, "capture_sidecar"
                )
        self.db = (
            sqlite3.connect(self.path.absolute().as_uri() + "?mode=ro", uri=True, timeout=1)
            if readonly
            else sqlite3.connect(self.path, timeout=1)
        )
        try:
            deadline = time.monotonic() + 10
            self.db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            self.db.execute("PRAGMA trusted_schema=OFF")
            if readonly:
                self.db.execute("PRAGMA query_only=ON")
                require(
                    self.db.execute("PRAGMA journal_mode").fetchone() == ("delete",),
                    "capture_journal_mode",
                )
            else:
                self.db.execute("PRAGMA synchronous=FULL")
                self.db.execute("PRAGMA journal_mode=DELETE")
                page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
                self.db.execute(f"PRAGMA max_page_count={MAX_DATABASE_BYTES // page_size}")
            if create:
                self.db.executescript(
                    "CREATE TABLE metadata (run_id TEXT NOT NULL, version INTEGER NOT NULL);"
                    "CREATE TABLE sources (sequence INTEGER PRIMARY KEY, kind TEXT NOT NULL, "
                    "identity TEXT NOT NULL, offset INTEGER NOT NULL DEFAULT 0, "
                    "digest TEXT NOT NULL, sealed INTEGER NOT NULL DEFAULT 0);"
                    "CREATE TABLE chunks (source INTEGER NOT NULL, offset INTEGER NOT NULL, "
                    "body BLOB NOT NULL, PRIMARY KEY(source,offset));"
                )
                with self.db:
                    self.db.execute("INSERT INTO metadata VALUES (?,1)", (run_id,))
            require(
                self.db.execute("SELECT * FROM metadata LIMIT 2").fetchall() == [(run_id, 1)],
                "capture_run",
            )
            self.verify()
            self.db.set_progress_handler(None, 0)
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def verify(self):
        require(self.db.execute("PRAGMA quick_check").fetchall() == [("ok",)], "capture_integrity")
        self.hashes = {}
        rows = self.db.execute(
            "SELECT sequence,kind,identity,offset,digest,sealed FROM sources ORDER BY sequence LIMIT ?",
            (MAX_GENERATIONS + 1,),
        ).fetchall()
        require(len(rows) <= MAX_GENERATIONS, "capture_generation_limit")
        total, previous = 0, {}
        for sequence, kind, inode, offset, expected, sealed in rows:
            require(
                kind in ("archive", "alert")
                and isinstance(inode, str)
                and re.fullmatch(r"[0-9a-f]{1,32}:[0-9a-f]{1,32}", inode),
                "capture_source",
            )
            require(
                type(offset) is int and 0 <= offset <= MAX_BYTES and sealed in (0, 1),
                "capture_offset",
            )
            require(kind not in previous or previous[kind], "capture_unsealed_predecessor")
            previous[kind] = sealed
            digest, size = hashlib.sha256(), 0
            for position, raw in self.db.execute(
                "SELECT offset,body FROM chunks WHERE source=? ORDER BY offset", (sequence,)
            ):
                require(
                    position == size and isinstance(raw, bytes) and 0 < len(raw) <= CHUNK_BYTES,
                    "capture_chunk",
                )
                digest.update(raw)
                size += len(raw)
            require(size == offset and digest.hexdigest() == expected, "capture_checkpoint_digest")
            self.hashes[sequence] = (offset, digest)
            total += size
        require(total <= MAX_BYTES, "capture_capacity")
        require(
            self.db.execute(
                "SELECT COUNT(*) FROM chunks WHERE source NOT IN (SELECT sequence FROM sources)"
            ).fetchone()[0]
            == 0,
            "capture_orphan_chunk",
        )

    def active(self, kind):
        require(kind in ("archive", "alert"), "capture_kind")
        return self.db.execute(
            "SELECT sequence,identity,offset,digest,sealed FROM sources WHERE kind=? ORDER BY sequence DESC LIMIT 1",
            (kind,),
        ).fetchone()

    def begin(self, kind, inode):
        require(
            kind in ("archive", "alert")
            and isinstance(inode, str)
            and re.fullmatch(r"[0-9a-f]{1,32}:[0-9a-f]{1,32}", inode),
            "capture_source",
        )
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            current = self.active(kind)
            if current and current[1] == inode:
                require(not current[4], "capture_sealed_source_reopened")
                return current
            require(current is None or current[4], "capture_previous_generation_unsealed")
            require(
                self.db.execute("SELECT COUNT(*) FROM sources").fetchone()[0] < MAX_GENERATIONS,
                "capture_generation_limit",
            )
            self.db.execute(
                "INSERT INTO sources (kind,identity,digest) VALUES (?,?,?)", (kind, inode, EMPTY)
            )
        return self.active(kind)

    def _advance(self, sequence, offset, digest):
        self.db.execute(
            "UPDATE sources SET offset=?,digest=? WHERE sequence=?", (offset, digest, sequence)
        )

    def append(self, sequence, offset, raw, *, prefix_digest):
        require(
            type(offset) is int
            and offset >= 0
            and isinstance(raw, bytes)
            and 0 < len(raw) <= CHUNK_BYTES,
            "capture_append",
        )
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT offset,digest,sealed FROM sources WHERE sequence=?", (sequence,)
            ).fetchone()
            require(row is not None and not row[2], "capture_source_not_active")
            if offset < row[0]:
                existing = self.db.execute(
                    "SELECT body FROM chunks WHERE source=? AND offset=?", (sequence, offset)
                ).fetchone()
                require(existing == (raw,), "capture_retry_conflict")
                return False
            require(row[:2] == (offset, prefix_digest), "capture_append_checkpoint")
            total = self.db.execute("SELECT COALESCE(SUM(offset),0) FROM sources").fetchone()[0]
            require(total + len(raw) <= MAX_BYTES, "capture_capacity")
            cached = self.hashes.get(sequence)
            if cached and cached[0] == offset:
                digest = cached[1].copy()
            else:
                digest = hashlib.sha256()
                for (chunk,) in self.db.execute(
                    "SELECT body FROM chunks WHERE source=? ORDER BY offset", (sequence,)
                ):
                    digest.update(chunk)
            require(digest.hexdigest() == prefix_digest, "capture_checkpoint_digest")
            digest.update(raw)
            self.db.execute("INSERT INTO chunks VALUES (?,?,?)", (sequence, offset, raw))
            self._advance(sequence, offset + len(raw), digest.hexdigest())
        # Cache only after a successful commit. Restart reconstructs these hashes
        # from retained chunks; no opaque hash objects enter durable storage.
        self.hashes[sequence] = (offset + len(raw), digest)
        return True

    def seal(self, sequence, offset, digest):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT offset,digest FROM sources WHERE sequence=?", (sequence,)
            ).fetchone()
            require(row == (offset, digest), "capture_seal_checkpoint")
            final = self.db.execute(
                "SELECT body FROM chunks WHERE source=? ORDER BY offset DESC LIMIT 1", (sequence,)
            ).fetchone()
            require(final is None or final[0].endswith(b"\n"), "capture_rotated_partial_line")
            self.db.execute("UPDATE sources SET sealed=1 WHERE sequence=?", (sequence,))

    def captured(self, kind, *, limit):
        require(
            kind in ("archive", "alert") and type(limit) is int and 0 <= limit <= MAX_BYTES,
            "capture_read_scope",
        )
        total = self.db.execute(
            "SELECT COALESCE(SUM(offset),0) FROM sources WHERE kind=?", (kind,)
        ).fetchone()[0]
        require(total <= limit, "capture_read_limit")
        return b"".join(
            row[0]
            for row in self.db.execute(
                "SELECT c.body FROM chunks c JOIN sources s ON s.sequence=c.source WHERE s.kind=? ORDER BY s.sequence,c.offset",
                (kind,),
            )
        )


class PinnedCapture:
    """Keep a verified regular file open through rename/unlink and checkpoint it.

    The caller admits only fixed native locations. On process restart it must
    locate any unfinished old inode first; compressed/missing generations are
    explicitly incomplete, never silently replaced by a new current file.
    """

    def __init__(self, journal, kind):
        require(kind in ("archive", "alert"), "capture_kind")
        self.journal, self.kind, self.file = journal, kind, None
        self.inode = None

    def close(self):
        if self.file:
            self.file.close()
        self.file = None

    def attach(self, path, expected_identity):
        path = Path(path)
        before = plain(path)
        require(
            identity(before) == expected_identity and before.st_nlink in (1, 2),
            "capture_native_identity",
        )
        if self.file and self.inode == expected_identity:
            return
        if self.file:
            self.drain(seal=True)
            self.close()
        previous = self.journal.active(self.kind)
        require(
            previous is None or previous[4] or previous[1] == expected_identity,
            "capture_previous_generation_missing",
        )
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        handle = os.fdopen(fd, "rb")
        try:
            opened = os.fstat(handle.fileno())
            require(
                stat.S_ISREG(opened.st_mode)
                and identity(opened) == expected_identity
                and opened.st_nlink in (1, 2),
                "capture_native_open_race",
            )
            row = self.journal.begin(self.kind, expected_identity)
            require(opened.st_size >= row[2], "capture_native_truncated")
            digest = hashlib.sha256()
            remaining = row[2]
            while remaining:
                raw = handle.read(min(remaining, CHUNK_BYTES))
                require(bool(raw), "capture_native_truncated")
                digest.update(raw)
                remaining -= len(raw)
            require(digest.hexdigest() == row[3], "capture_native_prefix_changed")
            self.file, self.inode = handle, expected_identity
        except BaseException:
            handle.close()
            raise

    def drain(self, *, seal=False):
        if self.file is None:
            return
        row = self.journal.active(self.kind)
        require(
            row is not None and row[1] == self.inode and not row[4], "capture_native_checkpoint"
        )
        info = os.fstat(self.file.fileno())
        require(
            stat.S_ISREG(info.st_mode)
            and identity(info) == self.inode
            and info.st_nlink in (0, 1, 2)
            and row[2] <= info.st_size <= MAX_BYTES,
            "capture_native_truncated_or_oversized",
        )
        # Take one finite size snapshot; a hot writer cannot prolong this poll.
        stop = info.st_size
        self.file.seek(row[2])
        offset, digest = row[2], row[3]
        while offset < stop:
            raw = self.file.read(min(stop - offset, CHUNK_BYTES))
            require(bool(raw), "capture_native_short_read")
            self.journal.append(row[0], offset, raw, prefix_digest=digest)
            row = self.journal.active(self.kind)
            offset, digest = row[2], row[3]
        if seal:
            self.file.seek(0)
            actual, remaining = hashlib.sha256(), offset
            while remaining:
                raw = self.file.read(min(remaining, CHUNK_BYTES))
                require(bool(raw), "capture_native_short_read")
                actual.update(raw)
                remaining -= len(raw)
            final = os.fstat(self.file.fileno())
            require(
                final.st_size == offset and actual.hexdigest() == digest,
                "capture_native_changed_at_rotation",
            )
            self.journal.seal(row[0], offset, digest)
