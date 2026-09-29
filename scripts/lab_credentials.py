"""Read the fixed private lab credential; no default, shell expansion or remote target."""

import os
import re
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELATIVE = Path("var/labs/bettail/.env")
KEY = "SUPABASE_DB_PASSWORD"
MAX_BYTES = 16 * 1024


class LabCredentialError(ValueError):
    """Diagnostics contain no credential values or caller-controlled paths."""


def read_database_password(root=ROOT):
    """Accept the generated 256-bit hex format only, from this checkout's lab file."""
    root = Path(os.path.abspath(root))
    path = root / RELATIVE
    try:
        for current in (root, root / "var", root / "var/labs", path.parent, path):
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or (
                getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024)
            ):
                raise LabCredentialError("Linked lab credential paths are refused.")
        if (
            not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_nlink", 1) != 1
            or not 0 < info.st_size <= MAX_BYTES
        ):
            raise LabCredentialError("The lab credential file has an unsupported size or type.")
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise LabCredentialError("The lab credential file changed while opening.")
            raw = handle.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise LabCredentialError("The lab credential file exceeds its limit.")
        text = raw.decode("utf8")
    except (OSError, UnicodeError):
        raise LabCredentialError(
            "The private lab credential file is unavailable or unreadable."
        ) from None
    values = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(.*)", line)
        if not match:
            raise LabCredentialError("The lab credential file must contain literal assignments.")
        name, value = match.groups()
        if name == KEY:
            values.append(value)
    if len(values) != 1 or not re.fullmatch(r"[0-9a-f]{64}", values[0]):
        raise LabCredentialError(
            "A generated lab database password is required; complete coordinated hardening first."
        )
    return values[0]
