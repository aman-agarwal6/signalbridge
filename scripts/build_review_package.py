"""Create a local review ZIP from a clean, checked checkout; never publish or run it.

Requires pypdf from docs/publishing/requirements.txt for PDF content review.
No app settings, credentials in output, arbitrary source/output paths or extraction.
"""

import hashlib
import html
import io
import json
import os
import re
import stat
import subprocess
import sys
import uuid
import zipfile
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.simulation_evidence import json_document
from scripts.check_publication import PublicationError, collect_secrets, scan_publishable
from scripts.portfolio import (
    PortfolioError,
    recheck_evidence,
    render_portfolio,
    unlinked,
    verify_metrics,
)
from scripts.record_verification import source_manifest

MAX_FILES = 1000
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MANIFEST_NAME = "PACKAGE_MANIFEST.json"
DIRECTORIES = {
    ".github",
    "bridge",
    "config",
    "docs",
    "fixtures",
    "integrations",
    "output",
    "portfolio",
    "READ_FIRST_TOMORROW",
    "scripts",
    "simulations",
    "starter",
    "static",
    "templates",
    "tests",
}
ROOT_FILES = {
    ".dockerignore",
    ".env.example",
    ".gitattributes",
    ".gitignore",
    "AGENTS.md",
    "compose.yaml",
    "Dockerfile",
    "LICENSE",
    "Makefile",
    "manage.py",
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "README.md",
    "requirements.txt",
    "requirements-dev.txt",
    "RUNBOOK.md",
    "SECURITY.md",
    "START_HERE.html",
    "start-signalbridge.cmd",
    "stop-signalbridge.cmd",
}
TEXT_SUFFIXES = {
    ".py",
    ".json",
    ".md",
    ".html",
    ".mjs",
    ".css",
    ".txt",
    ".toml",
    ".cmd",
    ".example",
    ".yml",
    ".yaml",
    ".jsonl",
    ".conf",
    ".xml",
}
LIMITS = [
    "Local review package only. No public hosting, upload, deployment or release approval.",
    "Contains tracked working-tree bytes; no Git history, private data, copied apps or installed dependencies.",
    "Known local secret matching and PDF text/actions were checked; unknown secrets, all encodings and Git history are not certified clean.",
    "Core evidence is builder-operated local verification, not a remote CI run or independent audit.",
    "Historical receipts and archived procedures keep their original scope; incomplete integrations and coverage remain incomplete.",
    "Hashes identify bytes, not independent attestation. A trusted local administrator can replace the package and manifest.",
    "Static link checks do not establish accessibility, browser behavior or production readiness.",
]


class PackageError(ValueError):
    """Fixed, non-sensitive diagnostic."""


def require(condition, message):
    if not condition:
        raise PackageError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git(root, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        GIT_OPTIONAL_LOCKS="0",
        GIT_CONFIG_COUNT="1",
        GIT_CONFIG_KEY_0="core.fsmonitor",
        GIT_CONFIG_VALUE_0="false",
    )
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
        check=False,
    )
    require(result.returncode == 0, "Unable to inspect the local Git checkout.")
    return result.stdout


def tracked_snapshot(root):
    require(
        not git(root, "status", "--porcelain", "--untracked-files=all").strip(),
        "Commit or preserve the reviewed changes before packaging; checkout must be clean.",
    )
    revision = git(root, "rev-parse", "HEAD").decode().strip()
    require(re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", revision), "Invalid source revision.")
    names = git(root, "ls-files", "-z", "--cached").decode("utf8").split("\0")
    names = sorted(name for name in names if name)
    require(
        0 < len(names) <= MAX_FILES and len({n.casefold() for n in names}) == len(names),
        "Unsupported, duplicate or excessive package inventory.",
    )
    for name in names:
        parts = PurePosixPath(name).parts
        require(
            name == PurePosixPath(name).as_posix()
            and re.fullmatch(r"[A-Za-z0-9_./-]+", name)
            and parts
            and ".." not in parts
            and not name.startswith("/")
            and not re.search(r"[\\:\x00-\x1f]", name),
            "Unsupported package path.",
        )
        require(
            not any(
                p.endswith((".", " "))
                or re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", p)
                for p in parts
            ),
            "Package names must be portable across supported platforms.",
        )
        require(
            name in ROOT_FILES or len(parts) > 1 and parts[0] in DIRECTORIES,
            "An unreviewed top-level path requires a package policy update.",
        )
        require(
            parts[0] != "output" or parts[:2] == ("output", "pdf"),
            "Only reviewed PDF outputs may be included.",
        )
        require(
            not any(
                p.casefold()
                in {
                    "var",
                    "artifacts",
                    ".git",
                    ".venv",
                    "node_modules",
                    "private-source",
                    "__pycache__",
                }
                or p.casefold().startswith(".env")
                and p != ".env.example"
                for p in parts
            ),
            "Private or generated runtime files cannot enter a review package.",
        )
        require(
            name in ROOT_FILES or PurePosixPath(name).suffix in TEXT_SUFFIXES | {".pdf"},
            "An unsupported file type requires explicit review.",
        )
    return revision, names


def read_file(root, name):
    path = root / name
    unlinked(root, path)
    info = path.stat()
    require(
        stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_FILE_BYTES,
        "A package file is linked, non-regular or too large.",
    )
    with path.open("rb") as handle:
        raw = handle.read(MAX_FILE_BYTES + 1)
    require(len(raw) <= MAX_FILE_BYTES, "A package file exceeded its limit while reading.")
    return raw


def check_pdf(raw, secrets):
    try:
        from pypdf import PdfReader
    except ImportError:
        raise PackageError(
            "PDF review requires the existing optional pypdf publishing dependency."
        ) from None
    try:
        pdf = PdfReader(io.BytesIO(raw), strict=True)
        require(
            not pdf.is_encrypted and 0 < len(pdf.pages) <= 100,
            "Unsupported PDF encryption or page count.",
        )
        root = pdf.trailer["/Root"]
        names = root.get("/Names", {})
        names = names.get_object() if hasattr(names, "get_object") else names
        require(
            not root.get("/OpenAction")
            and not root.get("/AA")
            and not root.get("/AcroForm")
            and not names.get("/JavaScript")
            and not names.get("/EmbeddedFiles"),
            "PDF active content or attachments require review.",
        )
        texts = [str(pdf.metadata)]
        links = []
        for page in pdf.pages:
            require(not page.get("/AA"), "PDF page actions require review.")
            texts.append(page.extract_text())
            for reference in page.get("/Annots", []):
                annotation = reference.get_object()
                require(
                    annotation.get("/Subtype") == "/Link" and not annotation.get("/AA"),
                    "Unexpected PDF annotation requires review.",
                )
                action = annotation.get("/A")
                if action:
                    require(
                        action.get("/S") == "/URI"
                        and set(action) <= {"/S", "/URI", "/Type", "/IsMap"},
                        "Unexpected PDF action requires review.",
                    )
                    links.append(str(action["/URI"]))
        text = "\n".join(texts + links)
        require(len(text) <= 2 * 1024 * 1024, "PDF text exceeds review bounds.")
        compact = re.sub(r"\s+", "", text)
        require(
            not any(secret in text or re.sub(r"\s+", "", secret) in compact for secret in secrets),
            "A known private value occurs in PDF content; package withheld.",
        )
        require(
            all(
                urlsplit(link).scheme in ("", "https", "http") and not urlsplit(link).netloc
                if not urlsplit(link).scheme
                else urlsplit(link).scheme in ("https", "http")
                for link in links
            ),
            "Unexpected PDF link destination requires review.",
        )
        return {"pages": len(pdf.pages), "links": links}
    except PackageError:
        raise
    except Exception:
        raise PackageError("PDF content could not be fully reviewed; package withheld.") from None


class PageLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.ids = [], set()
        self.csp_count = 0
        self.in_style = False
        self.css = []

    @staticmethod
    def check_css(css):
        # These two offline documents use only inline CSS. Reject escaped CSS and
        # resource constructs rather than trying to resolve arbitrary CSS URLs.
        compact = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
        require(
            not re.search(
                r"url\s*\(|@import|expression\s*\(|-moz-binding|(?<![-\w])behavior\s*:|\\",
                compact,
                re.I,
            ),
            "Offline HTML contains unreviewed CSS resources or behavior.",
        )

    def handle_starttag(self, tag, attributes):
        require(
            tag
            in {
                "html",
                "head",
                "title",
                "meta",
                "style",
                "body",
                "main",
                "header",
                "footer",
                "nav",
                "section",
                "article",
                "aside",
                "div",
                "span",
                "p",
                "a",
                "h1",
                "h2",
                "h3",
                "h4",
                "h5",
                "h6",
                "strong",
                "b",
                "em",
                "i",
                "small",
                "mark",
                "s",
                "del",
                "ins",
                "sub",
                "sup",
                "code",
                "pre",
                "blockquote",
                "ul",
                "ol",
                "li",
                "dl",
                "dt",
                "dd",
                "table",
                "caption",
                "thead",
                "tbody",
                "tfoot",
                "tr",
                "th",
                "td",
                "colgroup",
                "col",
                "br",
                "hr",
                "wbr",
                "details",
                "summary",
                "label",
                "fieldset",
                "legend",
                "input",
                "time",
                "figure",
                "figcaption",
                "abbr",
                "cite",
                "kbd",
                "samp",
                "q",
            },
            "Offline HTML contains active, embedded or unsupported elements.",
        )
        attrs = dict(attributes)
        require(len(attrs) == len(attributes), "Duplicate HTML attributes require review.")
        common = {"id", "class", "title", "lang", "dir", "role", "tabindex", "hidden", "style"}
        specific = {
            "a": {"href", "rel", "target"},
            "meta": {"charset", "name", "content", "http-equiv"},
            "input": {"type", "name", "checked", "value", "disabled"},
            "label": {"for"},
            "details": {"open"},
            "th": {"scope", "colspan", "rowspan"},
            "td": {"colspan", "rowspan"},
            "col": {"span"},
            "ol": {"start", "reversed", "type"},
            "li": {"value"},
            "time": {"datetime"},
            "style": {"media", "type"},
        }
        require(
            all(
                key in common | specific.get(tag, set()) or key.startswith("aria-") for key in attrs
            ),
            "Offline HTML contains active, resource-loading or unsupported attributes.",
        )
        if "style" in attrs:
            self.check_css(attrs["style"] or "")
        if tag == "input":
            require(
                attrs.get("type") == "radio", "Only native offline radio controls are approved."
            )
        if tag == "style":
            require(not self.in_style, "Nested HTML styles require review.")
            self.in_style = True
            self.css = []
        if tag == "meta" and "http-equiv" in attrs:
            require(
                (attrs["http-equiv"] or "").lower() == "content-security-policy",
                "Offline HTML metadata must not redirect or change browser behavior.",
            )
            directives = {}
            for part in (attrs.get("content") or "").split(";"):
                fields = part.strip().split()
                if not fields:
                    continue
                require(fields[0] not in directives, "Duplicate HTML security directives.")
                directives[fields[0]] = fields[1:]
            require(
                directives
                == {
                    "default-src": ["'none'"],
                    "style-src": ["'unsafe-inline'"],
                    "base-uri": ["'none'"],
                    "form-action": ["'none'"],
                },
                "Offline HTML security policy is missing or weakened.",
            )
            self.csp_count += 1
        if tag == "a" and "target" in attrs:
            require(
                attrs["target"] == "_self"
                or attrs["target"] == "_blank"
                and "noopener" in (attrs.get("rel") or "").split(),
                "Offline links must preserve the browsing context safely.",
            )
        if "id" in attrs:
            require(attrs["id"] not in self.ids, "Duplicate document anchor.")
            self.ids.add(attrs["id"])
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])

    def handle_data(self, value):
        if self.in_style:
            self.css.append(value)

    def handle_endtag(self, tag):
        if tag == "style":
            require(self.in_style, "Unexpected HTML style boundary.")
            self.check_css("".join(self.css))
            self.in_style = False

    def handle_decl(self, declaration):
        require(declaration.lower() == "doctype html", "Unexpected HTML declaration.")

    def handle_pi(self, data):
        raise PackageError("HTML processing instructions require review.")

    def finish(self):
        self.close()
        require(
            self.csp_count == 1 and not self.in_style,
            "Offline HTML needs one complete security policy and stylesheet.",
        )


def check_links(files, pdfs):
    pages = {}
    for name in ("START_HERE.html", "portfolio/index.html"):
        require(name in files, "A primary reader or demo file is missing.")
        parser = PageLinks()
        parser.feed(files[name].decode("utf8"))
        parser.finish()
        pages[name] = parser
    checked = 0
    for name, links in [(n, p.links) for n, p in pages.items()] + [
        (n, p["links"]) for n, p in pdfs.items()
    ]:
        for link in links:
            parsed = urlsplit(link)
            if parsed.scheme:
                require(parsed.scheme in ("http", "https"), "Unsupported document link scheme.")
                continue
            require(
                not parsed.netloc and not parsed.query and "\\" not in link,
                "Unsupported local document link.",
            )
            parts = list(PurePosixPath(name).parent.parts)
            for part in PurePosixPath(unquote(parsed.path)).parts:
                if part == "..":
                    require(parts, "A document link escapes the package.")
                    parts.pop()
                elif part != ".":
                    require(part != "/" and ":" not in part, "Unsupported local document target.")
                    parts.append(part)
            target = "/".join(parts) if parsed.path else name
            require(
                target in files or any(n.startswith(target.rstrip("/") + "/") for n in files),
                "A reader or PDF link is missing from the package.",
            )
            if parsed.fragment and target in pages:
                require(
                    unquote(parsed.fragment) in pages[target].ids, "A document anchor is missing."
                )
            checked += 1
    return checked


def verify_portfolio(root, source, now):
    metrics = verify_metrics(
        root, source, now, json_document(read_file(root, "portfolio/metrics.json"))
    )
    expected = render_portfolio(root, metrics)
    actual = read_file(root, "portfolio/index.html").decode("utf8")
    # Git may convert text line endings. No other whitespace/content normalization
    # is allowed: even a small altered claim must withhold the completed package.
    require(
        actual.replace("\r\n", "\n") == expected.replace("\r\n", "\n"),
        "Visible portfolio differs from the verified receipt rendering; rebuild it.",
    )
    recheck_evidence(root, metrics)
    return {
        key: metrics[key]["receipt"]
        for key in ("core", "current_simulation", "detection_challenge")
    }


def verify_zip(path, files, manifest_raw):
    with zipfile.ZipFile(path) as archive:
        require(
            len(archive.infolist()) == len(files) + 1
            and set(archive.namelist()) == set(files) | {MANIFEST_NAME},
            "Archive inventory mismatch.",
        )
        for name, expected in {**files, MANIFEST_NAME: manifest_raw}.items():
            info = archive.getinfo(name)
            require(
                info.file_size == len(expected) and archive.read(name) == expected,
                "Archive content or checksum mismatch.",
            )


def build(root=ROOT):
    root = Path(root).resolve(strict=True)
    revision, names = tracked_snapshot(root)
    source = source_manifest(root)
    now = datetime.now(timezone.utc)
    receipts = verify_portfolio(root, source, now)
    secrets = collect_secrets(root)
    require(
        not scan_publishable(root, names, secrets),
        "Known private content detected; package withheld.",
    )
    files, pdfs, total = {}, {}, 0
    needles = {
        secret.encode(encoding)
        for secret in secrets
        for encoding in ("utf-8", "utf-16-le", "utf-16-be")
    }
    for name in names:
        raw = read_file(root, name)
        require(
            not any(needle in raw for needle in needles),
            "Known private content in captured bytes; package withheld.",
        )
        total += len(raw)
        require(total <= MAX_TOTAL_BYTES, "Package content exceeds the total size limit.")
        files[name] = raw
        if name.endswith(".pdf"):
            pdfs[name] = check_pdf(raw, secrets)
        else:
            raw.decode("utf8")
    checked_links = check_links(files, pdfs)
    manifest = {
        "schema_version": 1,
        "kind": "signalbridge-local-review-package",
        "created_at": now.isoformat(),
        "revision": revision,
        "source_sha256": source["sha256"],
        "source_file_count": source["file_count"],
        "files": {n: {"bytes": len(raw), "sha256": sha(raw)} for n, raw in files.items()},
        "receipt_files": receipts,
        "pdf_pages_reviewed": sum(p["pages"] for p in pdfs.values()),
        "local_links_checked": checked_links,
        "limits": LIMITS,
    }
    manifest_raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    require(
        not any(secret.encode() in manifest_raw for secret in secrets),
        "Private value in manifest; package withheld.",
    )
    output = root / "output/review" / uuid.uuid4().hex
    unlinked(root, output)
    output.mkdir(parents=True, exist_ok=False)
    pending = output / "SignalBridge_Review.zip.partial"
    with zipfile.ZipFile(
        pending, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, raw in {**files, MANIFEST_NAME: manifest_raw}.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, raw, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    verify_zip(pending, files, manifest_raw)
    require(
        tracked_snapshot(root) == (revision, names)
        and source_manifest(root) == source
        and all(read_file(root, n) == raw for n, raw in files.items()),
        "Checkout changed while packaging; partial output retained and not approved.",
    )
    unlinked(root, output)
    target = output / "SignalBridge_Review.zip"
    pending.rename(target)
    digest = sha(target.read_bytes())
    (output / MANIFEST_NAME).write_bytes(manifest_raw)
    (output / "SHA256SUMS.txt").write_text(f"{digest}  SignalBridge_Review.zip\n", encoding="ascii")
    page = f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>SignalBridge review package</title><style>body{{margin:0;background:#102539;color:#eef5fa;font:17px/1.6 system-ui,sans-serif}}main{{max-width:850px;margin:auto;padding:50px 30px}}a{{color:#8ae3e4}}section{{background:#193447;padding:25px;border-radius:12px}}code{{overflow-wrap:anywhere;font-size:13px}}li{{margin:12px 0}}</style><main><p>LOCAL REVIEW / NOT PUBLISHED</p><h1>SignalBridge handoff package</h1><p>{len(files)} reviewed tracked files, source and evidence. Extract the ZIP into a new folder; open <code>portfolio/index.html</code> for the employer demo or <code>START_HERE.html</code> for the guides.</p><section><p><a href="SignalBridge_Review.zip">SignalBridge review ZIP</a> · <a href="PACKAGE_MANIFEST.json">File manifest</a> · <a href="../../../START_HERE.html">Read the current guides</a></p><p>Revision: <code>{revision}</code><br>ZIP SHA-256: <code>{digest}</code></p></section><h2>Review boundaries</h2><ul>{"".join("<li>" + html.escape(v) + "</li>" for v in LIMITS)}</ul></main></html>"""
    (output / "REVIEW.html").write_text(page, encoding="utf8")
    return {
        "directory": output.relative_to(root).as_posix(),
        "revision": revision,
        "files": len(files),
        "zip_bytes": target.stat().st_size,
        "zip_sha256": digest,
        "source_sha256": source["sha256"],
        "pdf_pages_reviewed": manifest["pdf_pages_reviewed"],
        "local_links_checked": checked_links,
    }


def main():
    try:
        require(len(sys.argv) == 1, "This command accepts no arbitrary paths or targets.")
        result = build()
    except (
        ValueError,
        OSError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
        zipfile.BadZipFile,
        PublicationError,
    ) as error:
        diagnostic = (
            str(error)
            if isinstance(error, (PackageError, PublicationError, PortfolioError))
            else "Check the clean checkout, current evidence, document links and optional PDF dependency."
        )
        print(
            f"Review package withheld. {diagnostic} No upload occurred.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
