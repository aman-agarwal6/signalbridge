"""Copy allowlisted local source into a verified, immutable lab evidence snapshot.

This utility never executes source configuration, installs packages or applies SQL.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APPS = ("bettail", "netted")
ROOT_FILES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "tsconfig.json",
        "next-env.d.ts",
        "next.config.ts",
        "postcss.config.mjs",
        "eslint.config.mjs",
    }
)
REQUIRED_ROOT_FILES = frozenset(
    {"package.json", "package-lock.json", "tsconfig.json", "next.config.ts"}
)
SOURCE_SUFFIXES = frozenset({".ts", ".tsx", ".js", ".mjs", ".json", ".css"})
EXCLUDED_NAMES = frozenset(
    {
        "node_modules",
        "database",
        "databases",
        "exports",
        "logs",
        "uploads",
        "backups",
        "public",
    }
)
MAX_FILES = 10000
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 200 * 1024 * 1024
INCOMPLETE = "snapshot.incomplete.json"
READY = "snapshot.json"


class SnapshotError(ValueError):
    """A bounded operator error that never includes file contents."""


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _excluded(name):
    return name.startswith(".") or name.casefold() in EXCLUDED_NAMES


def _safe_path(path, root):
    """Reject links, Windows junctions/reparse points, and resolved escapes."""
    try:
        info = path.lstat()
    except OSError:
        raise SnapshotError("A required source or snapshot path is unreadable.") from None
    if (
        stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        or not path.resolve().is_relative_to(root)
    ):
        raise SnapshotError("Links, reparse points and directory escapes are not permitted.")
    return info


def _root(path):
    candidate = Path(os.path.abspath(path))
    if candidate.resolve() != candidate or not candidate.is_dir():
        raise SnapshotError("Use an existing local directory without linked ancestors.")
    _safe_path(candidate, candidate)
    return candidate


def _source_paths(source):
    paths = []
    for name in sorted(ROOT_FILES):
        path = source / name
        if path.exists() or path.is_symlink():
            if not stat.S_ISREG(_safe_path(path, source).st_mode):
                raise SnapshotError("Root configuration must be a regular file.")
            paths.append(path)
        elif name in REQUIRED_ROOT_FILES:
            raise SnapshotError(
                "Source requires package.json, package-lock.json, tsconfig.json and next.config.ts."
            )
    src = source / "src"
    if not stat.S_ISDIR(_safe_path(src, source).st_mode):
        raise SnapshotError("Source requires a src directory.")
    pending = [src]
    while pending:
        directory = pending.pop()
        _safe_path(directory, source)
        for path in sorted(directory.iterdir()):
            if _excluded(path.name):
                continue
            info = _safe_path(path, source)
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
            elif stat.S_ISREG(info.st_mode) and path.suffix.casefold() in SOURCE_SUFFIXES:
                paths.append(path)
        if len(paths) + len(pending) > MAX_FILES:
            raise SnapshotError("Source exceeds the bounded snapshot file count.")
    if not any(path.is_relative_to(src) for path in paths):
        raise SnapshotError("No allowlisted application source files were found.")
    supabase = source / "supabase"
    _safe_path(supabase, source)
    migrations = supabase / "migrations"
    if not stat.S_ISDIR(_safe_path(migrations, source).st_mode):
        raise SnapshotError("Source requires a migrations directory.")
    sql = []
    for path in sorted(migrations.iterdir()):
        if path.suffix.casefold() == ".sql" and not _excluded(path.name):
            if not stat.S_ISREG(_safe_path(path, source).st_mode):
                raise SnapshotError("Migrations must be regular SQL files.")
            sql.append(path)
    if not sql:
        raise SnapshotError("No SQL migrations were found.")
    paths.extend(sql)
    if len(paths) > MAX_FILES:
        raise SnapshotError("Source exceeds the bounded snapshot file count.")
    return sorted(paths)


def _read(path, root):
    info = _safe_path(path, root)
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
        raise SnapshotError("Snapshot input is not a bounded regular file.")
    with path.open("rb") as handle:
        raw = handle.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise SnapshotError("Snapshot file exceeds the size limit.")
    return raw


def source_manifest(source):
    source = _root(source)
    manifest, total = {}, 0
    for path in _source_paths(source):
        raw = _read(path, source)
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise SnapshotError("Source exceeds the total snapshot size limit.")
        manifest[path.relative_to(source).as_posix()] = _hash(raw)
    return manifest


def git_provenance(source):
    git = shutil.which("git")
    if not git:
        raise SnapshotError("Git is required to record local source provenance.")

    def query(*arguments):
        try:
            return subprocess.check_output(
                [git, "--no-optional-locks", "-c", "core.fsmonitor=false", *arguments],
                cwd=source,
                text=True,
                encoding="utf-8",
                stderr=subprocess.DEVNULL,
                timeout=15,
            ).strip()
        except (OSError, subprocess.SubprocessError):
            raise SnapshotError("Local Git provenance could not be read.") from None

    if Path(query("rev-parse", "--show-toplevel")).resolve() != source:
        raise SnapshotError("Source must be the root of its own Git repository.")
    revision = query("rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40,64}", revision):
        raise SnapshotError("Source repository has no valid committed revision.")
    return {
        "source_revision": revision,
        "source_dirty": bool(query("status", "--porcelain=v1", "--untracked-files=normal")),
    }


def content_digest(app, files):
    return _hash(_json_bytes({"schema": 1, "app": app, "files": files}))


def _parents(destination, workspace, create=False):
    current = workspace
    for part in destination.relative_to(workspace).parts:
        current = current / part
        if create and not current.exists():
            try:
                current.mkdir()
            except FileExistsError:
                pass
        info = _safe_path(current, workspace)
        if not stat.S_ISDIR(info.st_mode):
            raise SnapshotError("Snapshot parent must be a regular directory.")


def _allowed_relative(value):
    if not isinstance(value, str) or "\\" in value or ":" in value:
        return False
    parts = value.split("/")
    if any(not part or part in (".", "..") or _excluded(part) for part in parts):
        return False
    if len(parts) == 1:
        return value in ROOT_FILES
    if parts[0] == "src":
        return Path(parts[-1]).suffix.casefold() in SOURCE_SUFFIXES
    return (
        len(parts) == 3
        and parts[:2] == ["supabase", "migrations"]
        and parts[-1].casefold().endswith(".sql")
    )


def _verify_payload(destination, files, completed):
    actual, pending = set(), [destination]
    while pending:
        for path in pending.pop().iterdir():
            info = _safe_path(path, destination)
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
            elif stat.S_ISREG(info.st_mode):
                actual.add(path.relative_to(destination).as_posix())
            else:
                raise SnapshotError("Snapshot contains an unsupported filesystem object.")
        if len(actual) + len(pending) > MAX_FILES + 2:
            raise SnapshotError("Snapshot contents exceed the manifest bounds.")
    expected = set(files) | {INCOMPLETE} | ({READY} if completed else set())
    if actual != expected:
        raise SnapshotError("Snapshot contains missing or unexpected files.")
    total = 0
    for path, digest in files.items():
        raw = _read(destination / path, destination)
        total += len(raw)
        if total > MAX_TOTAL_BYTES or _hash(raw) != digest:
            raise SnapshotError("Snapshot content differs from its recorded hashes.")


def verify_snapshot(destination, workspace=ROOT):
    workspace = _root(workspace)
    destination = Path(os.path.abspath(destination))
    try:
        relative = destination.relative_to(workspace)
    except ValueError:
        raise SnapshotError(
            "Snapshot is outside this workspace's private-source directory."
        ) from None
    parts = relative.parts
    if (
        len(parts) != 3
        or parts[0] != "private-source"
        or parts[1] not in APPS
        or not re.fullmatch(r"[0-9a-f]{64}", parts[2])
    ):
        raise SnapshotError("Snapshot must use private-source/app/content-digest.")
    _parents(destination, workspace)
    try:
        metadata = json.loads(_read(destination / READY, destination))
    except (OSError, ValueError):
        raise SnapshotError("Snapshot has no readable completion record; do not use it.") from None
    if (
        not isinstance(metadata, dict)
        or metadata.get("state") != "ready"
        or metadata.get("schema") != 1
    ):
        raise SnapshotError("Snapshot is incomplete or uses an unsupported format.")
    files = metadata.get("files")
    if (
        metadata.get("app") != parts[1]
        or metadata.get("snapshot_digest") != parts[2]
        or not isinstance(files, dict)
        or not 1 <= len(files) <= MAX_FILES
        or any(
            not _allowed_relative(path)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            for path, digest in files.items()
        )
        or content_digest(parts[1], files) != parts[2]
        or not isinstance(metadata.get("source_revision"), str)
        or not re.fullmatch(r"[0-9a-f]{40,64}", metadata["source_revision"])
        or type(metadata.get("source_dirty")) is not bool
    ):
        raise SnapshotError("Snapshot manifest or provenance is invalid.")
    if (
        not REQUIRED_ROOT_FILES.issubset(files)
        or not any(path.startswith("src/") for path in files)
        or not any(path.startswith("supabase/migrations/") for path in files)
    ):
        raise SnapshotError("Snapshot lacks required source, lockfile or migrations.")
    _verify_payload(destination, files, completed=True)
    return metadata


def create_snapshot(app, source=None, output=None, workspace=ROOT):
    if app not in APPS:
        raise SnapshotError("Choose bettail or netted.")
    workspace = _root(workspace)
    source = _root(source if source is not None else workspace.parent / app)
    before = git_provenance(source)
    files = source_manifest(source)
    digest = content_digest(app, files)
    destination = workspace / "private-source" / app / digest
    if output is not None:
        chosen = Path(output)
        chosen = Path(os.path.abspath(chosen if chosen.is_absolute() else workspace / chosen))
        if chosen != destination:
            raise SnapshotError(
                "Output must be this workspace's exact private-source/app/content-digest path."
            )
    if destination.is_relative_to(source):
        raise SnapshotError("Snapshot destination must be separate from the source repository.")
    _parents(destination.parent, workspace, create=True)
    if destination.exists() or destination.is_symlink():
        existing = verify_snapshot(destination, workspace)
        if existing["files"] != files or any(
            existing[key] != value for key, value in before.items()
        ):
            raise SnapshotError("An immutable snapshot already exists with different provenance.")
        if source_manifest(source) != files or git_provenance(source) != before:
            raise SnapshotError("Source changed while verifying the existing snapshot.")
        return destination, False
    destination.mkdir()
    metadata = dict(schema=1, app=app, snapshot_digest=digest, files=files, **before)
    with (destination / INCOMPLETE).open("xb") as handle:
        handle.write(_json_bytes(dict(metadata, state="incomplete")))
    for relative, expected in files.items():
        raw = _read(source / relative, source)
        if _hash(raw) != expected:
            raise SnapshotError("Source changed during copy; incomplete snapshot was preserved.")
        target = destination / relative
        _parents(target.parent, workspace, create=True)
        with target.open("xb") as handle:
            handle.write(raw)
    if source_manifest(source) != files or git_provenance(source) != before:
        raise SnapshotError("Source changed during copy; incomplete snapshot was preserved.")
    _verify_payload(destination, files, completed=False)
    with (destination / READY).open("xb") as handle:
        handle.write(_json_bytes(dict(metadata, state="ready")))
    verify_snapshot(destination, workspace)
    return destination, True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", choices=APPS, required=True)
    parser.add_argument(
        "--source", type=Path, help="Local repository root; defaults to the sibling app"
    )
    parser.add_argument(
        "--output", type=Path, help="Optional exact private-source/app/content-digest destination"
    )
    options = parser.parse_args(argv)
    try:
        path, created = create_snapshot(options.app, options.source, options.output)
    except SnapshotError as error:
        parser.exit(
            1,
            f"Snapshot blocked: {error} Any incomplete snapshot is preserved and must not be used. No source files were changed.\n",
        )
    except OSError:
        parser.exit(
            1,
            "Snapshot failed safety or consistency checks; any incomplete snapshot is preserved and must not be used. No source files were changed.\n",
        )
    print(f"{'Created' if created else 'Verified existing'} immutable source snapshot: {path}")
    print(
        "Source was copied only; no configuration, dependencies, migrations or services were executed."
    )


if __name__ == "__main__":
    main()
