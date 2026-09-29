"""Package boundaries using synthetic fixtures; no real package or private keys."""

import copy
import json
import os
import shutil
import stat
import sys
import uuid
import zipfile
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from scripts import build_review_package as package
from scripts import portfolio

CSP = "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"


def static_page(body):
    return (
        "<!doctype html><html><head>" + CSP + "</head><body>" + body + "</body></html>"
    ).encode()


class ReviewPackageTests(TestCase):
    def setUp(self):
        self.parent = package.ROOT / "var/tests"
        self.root = self.parent / ("review-package-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup)
        self.revision = "a" * 40
        self.secret = "synthetic-package-secret-" + uuid.uuid4().hex
        self.source = {"sha256": "b" * 64, "file_count": 2}
        self.write("README.md", b"Synthetic package fixture.")
        self.write(
            "START_HERE.html",
            static_page('<h1 id="start">Guide</h1><a href="portfolio/index.html#case">Demo</a>'),
        )
        self.write(
            "portfolio/index.html",
            static_page(
                '<h1 id="case">Synthetic demo</h1><a href="../START_HERE.html#start">Guide</a>'
            ),
        )
        self.names = ["README.md", "START_HERE.html", "portfolio/index.html"]

    def cleanup(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.parent.resolve()) or not target.name.startswith(
            "review-package-"
        ):
            raise RuntimeError("Unsafe package test cleanup target.")
        shutil.rmtree(target)

    def write(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def gates(self):
        stack = ExitStack()
        stack.enter_context(
            patch.object(package, "tracked_snapshot", return_value=(self.revision, self.names))
        )
        stack.enter_context(patch.object(package, "source_manifest", return_value=self.source))
        stack.enter_context(
            patch.object(package, "verify_portfolio", return_value={"core": "synthetic.json"})
        )
        stack.enter_context(patch.object(package, "collect_secrets", return_value={self.secret}))
        return stack

    def test_verified_zip_contains_exact_files_manifest_and_safe_regular_members(self):
        with self.gates():
            result = package.build(self.root)
        output = self.root / result["directory"]
        archive = output / "SignalBridge_Review.zip"
        self.assertEqual(package.sha(archive.read_bytes()), result["zip_sha256"])
        with zipfile.ZipFile(archive) as zipped:
            self.assertEqual(set(zipped.namelist()), set(self.names) | {package.MANIFEST_NAME})
            for name in self.names:
                self.assertEqual(zipped.read(name), (self.root / name).read_bytes())
                self.assertTrue(stat.S_ISREG(zipped.getinfo(name).external_attr >> 16))
            manifest = json.loads(zipped.read(package.MANIFEST_NAME))
        self.assertEqual(manifest["revision"], self.revision)
        self.assertEqual(manifest["local_links_checked"], 2)
        self.assertEqual(set(manifest["files"]), set(self.names))
        self.assertNotIn(self.secret, (output / "REVIEW.html").read_text())
        self.assertFalse((output / "SignalBridge_Review.zip.partial").exists())

    def test_private_value_blocks_output_without_echoing_it(self):
        self.write("README.md", self.secret.encode())
        with self.gates(), self.assertRaises(package.PackageError) as error:
            package.build(self.root)
        self.assertNotIn(self.secret, str(error.exception))
        self.assertFalse((self.root / "output").exists())

    def test_captured_bytes_are_checked_even_if_the_preliminary_scan_misses_a_copy(self):
        self.write("README.md", self.secret.encode("utf-16-le"))
        with self.gates(), patch.object(package, "scan_publishable", return_value=[]):
            with self.assertRaises(package.PackageError):
                package.build(self.root)
        self.assertFalse((self.root / "output").exists())

    def test_corrupted_archive_stays_partial_and_never_gets_a_ready_page(self):
        with (
            self.gates(),
            patch.object(
                package, "verify_zip", side_effect=package.PackageError("synthetic failure")
            ),
        ):
            with self.assertRaises(package.PackageError):
                package.build(self.root)
        self.assertEqual(len(list(self.root.glob("output/review/*/*.partial"))), 1)
        self.assertEqual(list(self.root.glob("output/review/*/*.zip")), [])
        self.assertEqual(list(self.root.glob("output/review/*/REVIEW.html")), [])

    def test_source_drift_after_archive_creation_withholds_completed_output(self):
        with (
            self.gates(),
            patch.object(
                package,
                "source_manifest",
                side_effect=[self.source, {**self.source, "sha256": "c" * 64}],
            ),
        ):
            with self.assertRaises(package.PackageError):
                package.build(self.root)
        self.assertEqual(list(self.root.glob("output/review/*/*.zip")), [])

    def test_existing_output_directory_is_not_overwritten(self):
        directory = self.root / "output/review" / ("a" * 32)
        directory.mkdir(parents=True)
        sentinel = directory / "SignalBridge_Review.zip"
        sentinel.write_bytes(b"existing review")
        with (
            self.gates(),
            patch.object(package.uuid, "uuid4", return_value=SimpleNamespace(hex="a" * 32)),
        ):
            with self.assertRaises(FileExistsError):
                package.build(self.root)
        self.assertEqual(sentinel.read_bytes(), b"existing review")

    def test_dirty_untracked_or_unreviewed_inventory_is_rejected(self):
        with patch.object(package, "git", return_value=b"?? unreviewed.txt"):
            with self.assertRaises(package.PackageError):
                package.tracked_snapshot(self.root)
        for names in (
            "../escape.md",
            "var/secrets.json",
            "docs/.env.local",
            "docs/node_modules/x.json",
            "output/review/old.json",
            "unreviewed/file.md",
            "docs/data.sqlite3",
            "docs/CON.md",
            "docs/back\\slash.md",
            "docs/colon:bad.md",
            "docs/a.md\0docs/A.md",
        ):
            with (
                self.subTest(names=names),
                patch.object(
                    package, "git", side_effect=[b"", self.revision.encode(), names.encode()]
                ),
            ):
                with self.assertRaises(package.PackageError):
                    package.tracked_snapshot(self.root)

    def test_hardlinked_or_oversized_content_is_rejected(self):
        original = self.root / "README.md"
        os.link(original, self.root / "copy.md")
        with self.assertRaises(package.PackageError):
            package.read_file(self.root, "README.md")
        self.write("large.md", b"12345")
        with patch.object(package, "MAX_FILE_BYTES", 4), self.assertRaises(package.PackageError):
            package.read_file(self.root, "large.md")

    def test_links_cannot_escape_or_refer_to_missing_files_or_anchors(self):
        for link in (
            "../../outside.html",
            "../missing.html",
            "../START_HERE.html#missing",
            "file:///C:/private",
            "//remote.invalid/private",
        ):
            files = {n: (self.root / n).read_bytes() for n in self.names}
            files["portfolio/index.html"] = static_page(f'<a href="{link}">bad</a>')
            with self.subTest(link=link), self.assertRaises(package.PackageError):
                package.check_links(files, {})

    def test_zip_verification_rejects_missing_extra_or_altered_members(self):
        for values in ({"a.txt": b"wrong"}, {"b.txt": b"extra"}, {}):
            target = self.root / (uuid.uuid4().hex + ".zip")
            with zipfile.ZipFile(target, "x") as archive:
                for name, value in {**values, package.MANIFEST_NAME: b"{}"}.items():
                    archive.writestr(name, value)
            with self.assertRaises(package.PackageError):
                package.verify_zip(target, {"a.txt": b"right"}, b"{}")

    def complete_portfolio(self):
        # Reuse the disposable, explicitly synthetic receipt factory. Exercise
        # the real reconstruction/rendering gates, rather than mocking them out.
        from tests.test_portfolio import PortfolioTests

        fixture = PortfolioTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.copy_integration_receipts()
        fixture.write(portfolio.BASELINE, fixture.baseline)
        fixture.write(portfolio.CURRENT, fixture.rolling())
        fixture.write("challenge.json", fixture.challenge())
        metrics = portfolio.build(
            fixture.root,
            now=fixture.now,
            simulation_receipt=portfolio.CURRENT,
            challenge_receipt="challenge.json",
        )
        return fixture, metrics

    def test_portfolio_checks_latest_core_run_and_does_not_pin_older_success(self):
        fixture, _ = self.complete_portfolio()
        with patch.object(
            portfolio, "select_core", side_effect=portfolio.PortfolioError("newer failed run")
        ) as select:
            with self.assertRaises(portfolio.PortfolioError):
                package.verify_portfolio(fixture.root, fixture.current, fixture.now)
            select.assert_called_once_with(fixture.root, fixture.current, fixture.now, None)

    def test_complete_metrics_are_reconstructed_including_history_comparison_and_limits(self):
        fixture, metrics = self.complete_portfolio()
        path = fixture.root / "portfolio/metrics.json"
        self.assertEqual(
            package.verify_portfolio(fixture.root, fixture.current, fixture.now)["core"],
            metrics["core"]["receipt"],
        )
        for change in (
            "integration",
            "history",
            "comparison",
            "limits",
            "extra",
            "missing_profile",
            "bool_count",
            "predates_execution",
        ):
            edited = copy.deepcopy(metrics)
            if change == "integration":
                edited["integrations"]["wazuh"]["counts"]["received"] += 1
            elif change == "history":
                edited["historical_baseline"] = None
            elif change == "comparison":
                edited["same_declared_scenarios"] = False
            elif change == "limits":
                edited["limits"] = []
            elif change == "extra":
                edited["independent_audit"] = True
            elif change == "missing_profile":
                edited["detection_challenge"] = None
            elif change == "predates_execution":
                edited["generated_at"] = "2020-01-01T00:00:00+00:00"
            else:
                edited["integrations"]["wazuh"]["counts"]["duplicates"] = False
            path.write_text(json.dumps(edited), encoding="utf8")
            with self.subTest(change=change), self.assertRaises(portfolio.PortfolioError):
                package.verify_portfolio(fixture.root, fixture.current, fixture.now)

    def test_visible_claims_must_equal_receipt_rendering_only_crlf_conversion_is_tolerated(self):
        fixture, _ = self.complete_portfolio()
        path = fixture.root / "portfolio/index.html"
        original = path.read_bytes()
        path.write_bytes(original.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        package.verify_portfolio(fixture.root, fixture.current, fixture.now)
        for altered in (
            original.replace(b"64", b"999", 1),
            original + b"<p>Independently audited enterprise parity.</p>",
        ):
            self.assertNotEqual(original, altered)
            path.write_bytes(altered)
            with self.assertRaises(package.PackageError):
                package.verify_portfolio(fixture.root, fixture.current, fixture.now)

    def test_duplicate_metrics_keys_cannot_override_reviewed_claims(self):
        fixture, _ = self.complete_portfolio()
        path = fixture.root / "portfolio/metrics.json"
        raw = path.read_text(encoding="utf8")
        path.write_text(raw.replace("{", '{"schema_version": 999,', 1), encoding="utf8")
        with self.assertRaises(ValueError):
            package.verify_portfolio(fixture.root, fixture.current, fixture.now)

    def test_reader_and_viewer_reject_active_resources_and_missing_or_weakened_csp(self):
        unsafe = (
            "<script>window.__unreviewed=true</script>",
            '<body onload="alert(1)">',
            '<form action="https://example.invalid/"><input name="secret"></form>',
            '<iframe src="https://example.invalid/"></iframe>',
            '<object data="local.html"></object>',
            '<img src="https://example.invalid/track">',
            '<link rel="stylesheet" href="https://example.invalid/style.css">',
            '<style>@import "https://example.invalid/style.css";</style>',
            "<style>body{background:u/**/rl(https://example.invalid/track)}</style>",
            '<p style="background:u\\72l(https://example.invalid/track)">Example</p>',
            '<meta http-equiv="refresh" content="0;url=https://example.invalid/">',
            '<a href="https://example.invalid/" ping="https://example.invalid/track">Link</a>',
            '<input type="image" src="https://example.invalid/track">',
            '<svg><a href="javascript:alert(1)">Click</a></svg>',
        )
        for name in ("START_HERE.html", "portfolio/index.html"):
            for body in unsafe:
                files = {n: (self.root / n).read_bytes() for n in self.names}
                files[name] = static_page(body)
                with self.subTest(name=name, body=body), self.assertRaises(package.PackageError):
                    package.check_links(files, {})
            for old, new in (
                (CSP.encode(), b""),
                (b"default-src 'none'", b"default-src *"),
                (CSP.encode(), (CSP + CSP).encode()),
            ):
                files = {n: (self.root / n).read_bytes() for n in self.names}
                files[name] = files[name].replace(old, new)
                with self.subTest(name=name, policy=new), self.assertRaises(package.PackageError):
                    package.check_links(files, {})

    def test_native_controls_and_manual_external_links_remain_usable(self):
        files = {n: (self.root / n).read_bytes() for n in self.names}
        files["portfolio/index.html"] = static_page(
            '<style>:root{scroll-behavior:smooth}@media(prefers-reduced-motion:reduce){:root{scroll-behavior:auto}}</style><fieldset><legend>Tool</legend><input type="radio" name="tool" id="case" checked aria-controls="details"><label for="case">Wazuh</label></fieldset><details id="details"><summary>Evidence</summary><p>Recorded result.</p></details><a href="https://example.invalid/">Manual reference</a>'
        )
        self.assertEqual(package.check_links(files, {}), 1)


class PdfPackageTests(TestCase):
    def reader(self, text="Synthetic report", root=None, annotations=None):
        class Page(dict):
            def extract_text(self):
                return text

        return SimpleNamespace(
            is_encrypted=False,
            metadata={},
            trailer={"/Root": root or {}},
            pages=[Page({"/Annots": annotations or []})],
        )

    def check(self, reader, secrets=None):
        with patch.dict(sys.modules, {"pypdf": SimpleNamespace(PdfReader=lambda *a, **kw: reader)}):
            return package.check_pdf(b"synthetic bytes", secrets or set())

    def test_pdf_text_and_wrapped_private_value_are_checked_without_echoing_content(self):
        secret = "synthetic-secret-value"
        for text in (secret, "synthetic-secret-\nvalue"):
            with self.assertRaises(package.PackageError) as error:
                self.check(self.reader(text), {secret})
            self.assertNotIn(secret, str(error.exception))
        self.assertEqual(self.check(self.reader())["pages"], 1)

    def test_pdf_actions_attachments_forms_and_nonweb_links_are_rejected(self):
        roots = (
            {"/OpenAction": {"x": 1}},
            {"/AA": {"x": 1}},
            {"/AcroForm": {"x": 1}},
            {"/Names": {"/JavaScript": {"x": 1}}},
            {"/Names": {"/EmbeddedFiles": {"x": 1}}},
        )
        for root in roots:
            with self.subTest(root=root), self.assertRaises(package.PackageError):
                self.check(self.reader(root=root))
        annotation = {"/Subtype": "/Link", "/A": {"/S": "/URI", "/URI": "file:///C:/private"}}
        reference = SimpleNamespace(get_object=lambda: annotation)
        with self.assertRaises(package.PackageError):
            self.check(self.reader(annotations=[reference]))
        annotation["/A"] = {
            "/S": "/URI",
            "/URI": "https://example.invalid/",
            "/Next": {"/S": "/JavaScript"},
        }
        with self.assertRaises(package.PackageError):
            self.check(self.reader(annotations=[reference]))

    def test_pdf_failure_or_encryption_cannot_be_reported_as_a_reviewed_document(self):
        reader = self.reader()
        reader.is_encrypted = True
        with self.assertRaises(package.PackageError):
            self.check(reader)
        malformed = copy.deepcopy(reader)
        del malformed.pages
        with self.assertRaises(package.PackageError):
            self.check(malformed)
