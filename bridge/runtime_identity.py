"""Local checkout identity and fixed runtime paths; no Django, secrets or process actions."""

import hashlib
import os
import stat
from pathlib import Path

RUNTIME_NAMES = {"stop.request", "server.log", "lab-keys.json"}


def workspace_id(root):
    """A location fingerprint, not authentication against a hostile local process."""
    resolved = Path(root).resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("The workspace must be an existing directory.")
    identity = "signalbridge-workspace-v1\0" + os.path.normcase(str(resolved))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _plain_path(path, *, directory):
    if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
        raise ValueError("Runtime paths cannot be links or junctions.")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if getattr(metadata, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024
    ):
        raise ValueError("Runtime paths cannot be reparse points.")
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(metadata.st_mode):
        raise ValueError("Runtime paths have an unexpected file type.")


def runtime_file(root, name, *, create_directory=False):
    """Validate an allowlisted file under this checkout's plain var directory."""
    if name not in RUNTIME_NAMES:
        raise ValueError("Unknown runtime file.")
    resolved = Path(root).resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("The workspace must be an existing directory.")
    directory = resolved / "var"
    path = directory / name
    _plain_path(directory, directory=True)
    _plain_path(path, directory=False)
    if not path.resolve().is_relative_to(resolved):
        raise ValueError("Runtime path escaped this workspace.")
    if create_directory:
        directory.mkdir(exist_ok=True)
        _plain_path(directory, directory=True)
        _plain_path(path, directory=False)
    return path
