"""Create one ignored derivative of an exact verified snapshot; never launch it."""

import hashlib
import json
import os
import re
import stat
from pathlib import Path

from scripts.snapshot_app import _allowed_relative, content_digest, verify_snapshot

ROOT = Path(__file__).resolve().parents[2]
DIGEST = "1b53511c58642fec4d1d4351e66689662f99bc6986e5067f5f08c0990b603ad0"
MAX_BYTES = 25 * 1024 * 1024
ADAPTER = Path(__file__).parent
OVERLAYS = {
    "observer.mjs": "src/lib/signalbridge/observer.mjs",
    "telemetry.ts": "src/lib/signalbridge/telemetry.ts",
    "202610020001_signalbridge_access.sql": "supabase/migrations/202610020001_signalbridge_access.sql",
}
PRIVATE_NAMES = ("credential", "secret", ".env", ".pem", ".key", "token.json", "password")
PRIVATE_CONTENT = re.compile(
    rb"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|"
    rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
    rb"\b(?:postgres(?:ql)?|mysql|amqps?|rediss?)://[^\s/@:]+:[^\s/@]+@|"
    rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,})\b"
)


def ordinary(path, directory=False):
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        or (not directory and info.st_nlink != 1)
    ):
        raise ValueError("Copy requires ordinary unlinked files and directories.")
    return info


def parents(path):
    for current in (*reversed(path.parents), path):
        ordinary(current, directory=True)


def read(path):
    parents(path.parent)
    info = ordinary(path)
    if info.st_size > MAX_BYTES:
        raise ValueError("Copy input exceeds the source budget.")
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) != info.st_size or len(raw) > MAX_BYTES:
        raise ValueError("Copy input changed or exceeds the source budget.")
    return raw


def public_source(relative, raw):
    """Reject obvious credential artifacts before copying any bytes."""
    if any(word in part.casefold() for part in Path(relative).parts for word in PRIVATE_NAMES):
        raise ValueError("A private or unreviewed filename is forbidden.")
    if PRIVATE_CONTENT.search(raw):
        raise ValueError("Source contains private credential material; no copy was made.")
    raw.decode("utf-8")  # This profile contains only bounded UTF-8 source/configuration.


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("Frozen route patch does not match exactly once.")
    return text.replace(old, new, 1)


def instrument_routes(files):
    """Patch only the two verified response paths; preserve POST and mutation code."""
    path = "src/app/api/state/route.ts"
    text = files[path].decode("utf-8").replace("\r\n", "\n")
    text = 'import { observeAccess } from "@/lib/signalbridge/telemetry";\n' + text
    text = replace_once(
        text,
        "    if (error)\n      return Response.json(",
        """    if (error) {
      // Only the two reviewed snapshot denials establish a source denial.
      const membershipDenied = error.code === "P0001" &&
        ["Bet unavailable.", "Group unavailable."].includes(error.message);
      await observeAccess(supabase, user.id, "post", options.post_id,
        membershipDenied ? "denied" : "error");
      return Response.json(""",
    )
    if text.count('["P0001", "42501", "PGRST301"].includes(error.code)') != 2:
        raise ValueError("Frozen snapshot error mapping changed.")
    text = text.replace('["P0001", "42501", "PGRST301"].includes(error.code)', "membershipDenied")
    text = replace_once(
        text,
        "    const postIds = (data?.posts ?? [])",
        "    }\n    const postIds = (data?.posts ?? [])",
    )
    text = replace_once(
        text,
        "    return Response.json(\n      {\n        ...data,",
        "    const response = Response.json(\n      {\n        ...data,",
    )
    text = replace_once(
        text,
        "        headers: responseHeaders,\n      },\n    );",
        """        headers: responseHeaders,
      },
    );
    // A successful snapshot with no matching private record is not an allowed read.
    await observeAccess(supabase, user.id, "post", options.post_id,
      (data?.posts ?? []).some((post: { id: string }) => post.id === options.post_id)
        ? "allowed" : "not_visible");
    return response;""",
    )
    files[path] = text.encode("utf-8")
    path = "src/app/api/chat-image/route.ts"
    text = files[path].decode("utf-8").replace("\r\n", "\n")
    text = 'import { observeAccess } from "@/lib/signalbridge/telemetry";\n' + text
    # Restrict edits to GET, leaving the upload handler byte-for-byte unchanged.
    head, get = text.split("export async function GET(request: Request) {", 1)
    get = replace_once(
        get,
        "    if (!user) return new Response(null, { status: 401, headers });",
        """    if (!user) return new Response(null, { status: 401, headers });
    const note = async (outcome: "allowed" | "denied" | "not_visible" | "error") => {
      if (!groupChat && !directChat) await observeAccess(client, user.id, "image", id.data, outcome);
    };""",
    )
    get = replace_once(
        get,
        "    if (!comment.data?.image_id)\n      return new Response(null, { status: 404, headers });",
        """    if (comment.error && !groupChat && !directChat) {
      await note("error");
      return new Response(null, { status: 503, headers });
    }
    if (!comment.data?.image_id) {
      await note("not_visible");
      return new Response(null, { status: 404, headers });
    }""",
    )
    get = replace_once(
        get,
        "    if (!path.data || path.error)\n      return new Response(null, { status: 404, headers });",
        """    if (path.error && !groupChat && !directChat) {
      await note("error");
      return new Response(null, { status: 503, headers });
    }
    if (!path.data || path.error) {
      await note("not_visible");
      return new Response(null, { status: 404, headers });
    }""",
    )
    get = replace_once(
        get,
        "    if (!image.data || image.error)\n      return new Response(null, { status: 404, headers });\n    return new Response(image.data, {",
        """    if (!image.data || image.error) {
      await note("error");
      return new Response(null, { status: groupChat || directChat ? 404 : 503, headers });
    }
    const response = new Response(image.data, {""",
    )
    get = replace_once(
        get,
        """        "Content-Disposition": 'inline; filename="chat-photo.webp"',
      },
    });""",
        """        "Content-Disposition": 'inline; filename="chat-photo.webp"',
      },
    });
    // Storage.download has returned the actual Blob; path lookup alone is insufficient.
    await note("allowed");
    return response;""",
    )
    files[path] = (head + "export async function GET(request: Request) {" + get).encode("utf-8")


def payload(snapshot, workspace):
    parents(snapshot)
    metadata = verify_snapshot(snapshot, workspace)
    if metadata["snapshot_digest"] != DIGEST or metadata["app"] != "bettail":
        raise ValueError("Only the reviewed frozen BetTail snapshot is supported.")
    result, total = {}, 0
    for relative, expected in sorted(metadata["files"].items()):
        if not _allowed_relative(relative):
            raise ValueError("A private or unreviewed filename is forbidden.")
        raw = read(snapshot / relative)
        public_source(relative, raw)
        total += len(raw)
        if total > MAX_BYTES or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("Frozen source changed or exceeds the 25 MiB copy budget.")
        result[relative] = raw
    instrument_routes(result)
    for source, target in OVERLAYS.items():
        if target in result:
            raise ValueError("Adapter would overwrite an existing source file.")
        raw = read(ADAPTER / source)
        public_source(target, raw)
        result[target] = raw
    if sum(map(len, result.values())) > MAX_BYTES:
        raise ValueError("Derived source exceeds the 25 MiB copy budget.")
    return result, metadata


def prepare():
    """No configurable destinations: never overwrite an existing copy or runtime."""
    workspace = ROOT.parent / "signalbridge"
    snapshot = workspace / "private-source" / "bettail" / DIGEST
    files, metadata = payload(snapshot, workspace)  # Entire verification before any writes.
    parents(ROOT)
    destination = ROOT / "var" / "enterprise" / "bettail-access"
    for path in (ROOT / "var", ROOT / "var" / "enterprise"):
        if not path.exists():
            path.mkdir()
        parents(path)
    destination.mkdir()  # Exclusive: partial or prior copies require explicit review.
    incomplete = destination / "copy.incomplete.json"
    with incomplete.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write('{"state":"incomplete"}\n')
    source = destination / "source"
    source.mkdir()
    for relative, raw in sorted(files.items()):
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        parents(target.parent)
        with target.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    derived = {}
    for relative, raw in files.items():
        actual = read(source / relative)
        if actual != raw:
            raise ValueError("Derived source verification failed; incomplete copy retained.")
        derived[relative] = hashlib.sha256(actual).hexdigest()
    manifest = {
        "schema": 1,
        "state": "prepared_not_executed",
        "profile": "bettail-access-v1",
        "source_snapshot_digest": DIGEST,
        "source_revision": metadata["source_revision"],
        "source_dirty": metadata["source_dirty"],
        "original_files": metadata["files"],
        "derived_files": derived,
        "derived_source_digest": content_digest("bettail", derived),
        "copied_bytes": sum(map(len, files.values())),
        "native_proof": False,
    }
    with (destination / "copy-manifest.json").open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, sort_keys=True, indent=2)
        handle.write("\n")
    return {"files": len(files), "bytes": manifest["copied_bytes"], "native_proof": False}


if __name__ == "__main__":
    print(json.dumps(prepare(), sort_keys=True))
