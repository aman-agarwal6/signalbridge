"""Download the public attack logs and SigmaHQ rules pinned in sources.json, and verify them.

Files land in detections/identity/data/, which git ignores. A file counts only if its size and
SHA-256 match sources.json; anything else is discarded and the run fails. Files already present
and verified are not downloaded again.

Run from the repository root:
    python -m detections.identity.fetch
"""

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).parent
SOURCES = HERE / "sources.json"
DATA = HERE / "data"
ALLOWED_HOSTS = {"media.githubusercontent.com", "raw.githubusercontent.com"}
MAX_BYTES = 2_000_000
SAFE_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")


def load_sources():
    return json.loads(SOURCES.read_text(encoding="utf-8"))


def safe_relative(path):
    """A manifest path may only name a file below its source folder."""
    if not SAFE_PATH.fullmatch(path) or any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError(f"unsafe path in sources.json: {path!r}")
    return path


def local_file(kind, path):
    return DATA / kind / safe_relative(path)


def pinned_files(sources):
    """(local path, URL, SHA-256, size) for every file sources.json pins."""
    for kind, items in (
        ("attack_data", sources["datasets"]),
        ("sigmahq", sources["sigmahq_rules"]),
    ):
        origin = sources[kind]
        for item in items:
            url = origin["url"].format(commit=origin["commit"], path=safe_relative(item["path"]))
            yield local_file(kind, item["path"]), url, item["sha256"], item["bytes"]


def matches(body, sha256, size):
    return len(body) == size and hashlib.sha256(body).hexdigest() == sha256


def is_verified(path, sha256, size):
    return path.is_file() and matches(path.read_bytes(), sha256, size)


def check_url(url, hosts=ALLOWED_HOSTS):
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in hosts:
        raise ValueError(f"refusing to fetch from {parts.scheme}://{parts.hostname}")


def download(url):
    check_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "signalbridge-identity-fetch"})
    with urllib.request.urlopen(request, timeout=60) as response:
        check_url(response.geturl())
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError(f"{url} is larger than {MAX_BYTES} bytes")
    return body


def fetch_all():
    """Return the number of files that could not be fetched and verified."""
    failures = 0
    for path, url, sha256, size in pinned_files(load_sources()):
        if is_verified(path, sha256, size):
            continue
        try:
            body = download(url)
        except (OSError, ValueError) as error:
            print(f"failed: {url}: {error}")
            failures += 1
            continue
        if not matches(body, sha256, size):
            print(f"failed: {url}: size or SHA-256 does not match sources.json")
            failures += 1
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        partial = path.with_name(path.name + ".partial")
        partial.write_bytes(body)
        partial.replace(path)
        print(f"fetched {path.relative_to(HERE).as_posix()}")
    return failures


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    failures = fetch_all()
    if failures:
        print(f"{failures} file(s) failed")
        return 1
    print("all pinned files present and verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
