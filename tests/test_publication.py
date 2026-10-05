"""Synthetic credential-copy and fail-closed publication checks; no real keys in fixtures."""

import base64
import copy
import json
import shutil
import stat
import uuid
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from scripts import check_publication as publication


class PublicationTests(TestCase):
    def setUp(self):
        self.test_root = publication.ROOT / "var/tests"
        self.root = self.test_root / ("publication-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.addCleanup(self.cleanup)
        self.secret = "synthetic-credential-" + uuid.uuid4().hex
        self.private = "synthetic-private-jwk-" + uuid.uuid4().hex
        self.public = "synthetic-public-coordinate-" + uuid.uuid4().hex
        self.write("var/labs/bettail/.env", f"SUPABASE_AUTH_SECRET_KEY={self.secret}\n")
        self.write(
            "var/labs/bettail/supabase/signing_keys.json",
            json.dumps(
                [
                    {
                        "kty": "EC",
                        "crv": "P-256",
                        "d": self.private,
                        "x": self.public,
                        "kid": "public-key-id",
                    }
                ]
            ),
        )

    def cleanup(self):
        target = self.root.resolve()
        if not target.is_relative_to(self.test_root.resolve()) or not target.name.startswith(
            "publication-"
        ):
            raise RuntimeError("Unsafe test cleanup target")
        shutil.rmtree(target)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value.encode("utf-8") if isinstance(value, str) else value)
        return path

    def scan(self, files):
        return publication.scan_publishable(
            self.root, files, publication.collect_secrets(self.root)
        )

    def test_enterprise_generated_password_copy_is_detected_without_value_output(self):
        value = "synthetic-only-" + uuid.uuid4().hex + "x" * 17
        self.assertEqual(len(value), 64)
        directory = "var/enterprise/runs/" + "a" * 32 + "/secrets/"
        self.write(directory + "bootstrap-password", value)
        self.write(directory + "verifier-password", "synthetic-only-" + uuid.uuid4().hex + "y" * 17)
        self.write("docs/accidental-copy.json", json.dumps({"copied": value}))
        self.assertEqual(self.scan(["docs/accidental-copy.json"]), ["docs/accidental-copy.json"])

    def test_enterprise_unknown_credential_shape_fails_closed(self):
        directory = "var/enterprise/runs/" + "a" * 32 + "/secrets/"
        self.write(directory + "unreviewed-secret", "synthetic-only")
        with self.assertRaises(publication.PublicationError):
            publication.collect_secrets(self.root)

    def test_restoration_passwords_are_collected_and_extra_files_fail_closed(self):
        directory = "var/enterprise/runs/" + "a" * 32 + "/secrets/"
        password = "R" * 32 + "s" * 32
        self.write(directory + "bootstrap-password", "B" * 64)
        self.write(directory + "console-password", password)
        self.write(directory + "restoration-plan.json", json.dumps({"profile": "access"}))
        self.write(directory + "tool-scope.json", "null")
        self.write("docs/copied.txt", password)
        self.assertEqual(self.scan(["docs/copied.txt"]), ["docs/copied.txt"])
        self.write(directory + "unreviewed-secret", "synthetic-only")
        with self.assertRaises(publication.PublicationError):
            publication.collect_secrets(self.root)

    def test_enterprise_invalid_run_path_fails_closed(self):
        self.write("var/enterprise/runs/not-a-run/file", "synthetic-only")
        with self.assertRaises(publication.PublicationError):
            publication.collect_secrets(self.root)

    def source_profile(self):
        from integrations.enterprise.reference_native_support import ACCOUNTS, FIELDS

        value = {k: uuid.uuid4().hex + uuid.uuid4().hex for k in FIELDS if k != "accounts"}
        value["accounts"] = {k: uuid.uuid4().hex + uuid.uuid4().hex for k in ACCOUNTS}
        return value

    def test_source_profile_passwords_collected_after_incomplete_certificate_preparation(self):
        profile = self.source_profile()
        self.write(
            "var/enterprise/runs/" + "a" * 32 + "/secrets/source-profile", json.dumps(profile)
        )
        credential = profile["accounts"]["document_member"]
        self.write("docs/copied.txt", credential)
        self.assertEqual(self.scan(["docs/copied.txt"]), ["docs/copied.txt"])

    def test_source_private_key_body_is_detected_but_public_certificate_is_not_secret(self):
        directory = "var/enterprise/runs/" + "a" * 32 + "/secrets/"
        self.write(directory + "source-profile", json.dumps(self.source_profile()))
        body = base64.b64encode(
            b"synthetic-test-material-not-a-real-key-" + uuid.uuid4().hex.encode()
        ).decode()
        key = "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n"
        cert = "-----BEGIN CERTIFICATE-----\nc3ludGhldGljLXRlc3Q=\n-----END CERTIFICATE-----\n"
        self.write(directory + "source-private-key.pem", key)
        self.write(directory + "lab-ca.pem", cert)
        self.write("docs/key-copy.txt", body)
        self.write("docs/public-certificate.txt", cert)
        self.assertEqual(
            self.scan(["docs/key-copy.txt", "docs/public-certificate.txt"]), ["docs/key-copy.txt"]
        )

    def test_source_profile_and_private_key_bad_inventory_fail_closed(self):
        directory = "var/enterprise/runs/" + "a" * 32 + "/secrets/"
        profile = self.source_profile()
        target = self.write(directory + "source-profile", json.dumps(profile))
        for value in (
            {**profile, "extra": "unexpected"},
            {**profile, "accounts": {}},
            {**profile, "source_secret": True},
        ):
            target.write_text(json.dumps(value))
            with self.assertRaises(publication.PublicationError):
                publication.collect_secrets(self.root)
        target.write_text(json.dumps(profile))
        self.write(directory + "source-private-key.pem", "not-a-key")
        with self.assertRaises(publication.PublicationError):
            publication.collect_secrets(self.root)

    def identity_fixture(self, *, complete=True):
        """Actual preparation shape with nonfunctional synthetic test values only."""
        from integrations.identity import native_profile

        run = "b" * 32
        base = f"var/enterprise/runs/{run}/"
        realm = json.loads((publication.ROOT / "integrations/identity/realm.json").read_bytes())
        plan = json.loads(
            (publication.ROOT / "integrations/identity/native-stage-plan.json").read_bytes()
        )

        def synthetic_token(size):
            length = (size * 4 + 2) // 3
            return ("synthetic-test-" + uuid.uuid4().hex).ljust(length, "x")

        with (
            patch.object(native_profile.secrets, "token_urlsafe", side_effect=synthetic_token),
            patch.object(
                native_profile.secrets,
                "token_bytes",
                side_effect=lambda size: (b"synthetic-totp-" + uuid.uuid4().bytes + b"xx")[:size],
            ),
        ):
            prepared, profile = native_profile.material(realm, run)
        self.write(base + "source/integrations/identity/realm.json", json.dumps(realm))
        self.write(base + "source/integrations/identity/native-stage-plan.json", json.dumps(plan))
        config = {
            **plan["required_keycloak_config"],
            "db-password": profile["keycloak_database_password"],
            "bootstrap-admin-username": profile["operator_username"],
            "bootstrap-admin-password": profile["operator_password"],
        }
        files = {
            "identity-profile.json": json.dumps(profile),
            "signalbridge-realm.json": json.dumps(prepared),
            "bootstrap-password": profile["bootstrap_database_password"],
            "console-password": profile["database_password"],
            "keycloak-password": profile["keycloak_database_password"],
            "keycloak.conf": "".join(
                key + "=" + value + "\n" for key, value in sorted(config.items())
            ),
        }
        cert = "-----BEGIN CERTIFICATE-----\nc3ludGhldGljLXRlc3Q=\n-----END CERTIFICATE-----\n"
        files["lab-ca.pem"] = cert
        for name in ("provider", "console"):
            body = base64.b64encode(
                ("synthetic-non-key-" + name + uuid.uuid4().hex).encode()
            ).decode()
            files[name + "-certificate.pem"] = cert
            files[name + "-private-key.pem"] = (
                "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n"
            )
        directory = base + "secrets/"
        if complete:
            for name, value in files.items():
                self.write(directory + name, value)
        return directory, profile, files

    def test_identity_all_generated_passwords_totp_and_private_key_encodings_are_covered(self):
        directory, profile, files = self.identity_fixture()
        sensitive = {
            profile[key]
            for key in (
                "django_secret",
                "database_password",
                "keycloak_database_password",
                "bootstrap_database_password",
                "operator_password",
            )
        }
        for account in profile["accounts"].values():
            sensitive.update((account["password"], account["totp_base32"]))
        for name in ("provider", "console"):
            key = files[name + "-private-key.pem"]
            sensitive.update((key, "".join(key.splitlines()[1:-1])))
        self.assertEqual(len(sensitive), 23)
        discovered = publication.collect_secrets(self.root)
        self.assertTrue(sensitive.issubset(discovered))
        for index, value in enumerate(sensitive):
            name = f"docs/identity-copy-{index}.txt"
            self.write(name, value.encode("utf-16-le" if index % 2 else "utf8"))
            self.assertEqual(publication.scan_publishable(self.root, [name], discovered), [name])
        public = (
            profile["issuer"]
            + profile["run_id"]
            + profile["operator_username"]
            + files["lab-ca.pem"]
        )
        public += "".join(
            account["subject"] + account["username"] for account in profile["accounts"].values()
        )
        self.write("docs/identity-public.txt", public)
        self.assertEqual(
            publication.scan_publishable(self.root, ["docs/identity-public.txt"], discovered), []
        )
        self.assertEqual(
            self.scan([directory + "identity-profile.json"]), [directory + "identity-profile.json"]
        )

    def test_identity_partial_preparation_collects_profile_secrets_at_every_step(self):
        directory, profile, files = self.identity_fixture(complete=False)
        for name, value in files.items():
            with self.subTest(last_written=name):
                self.write(directory + name, value)
                collected = publication.collect_secrets(self.root)
                self.assertIn(profile["operator_password"], collected)
                self.assertIn(profile["accounts"]["analyst"]["totp_base32"], collected)
        self.write(directory + "keycloak.conf", files["keycloak.conf"][:-10])
        with self.assertRaises(publication.PublicationError):
            publication.collect_secrets(self.root)

    def test_identity_profile_unknown_fields_scopes_or_malformed_credentials_fail_closed(self):
        directory, profile, _ = self.identity_fixture()
        for alter in (
            lambda value: value.update(extra_password="synthetic-hidden-password"),
            lambda value: value.update(run_id="c" * 32),
            lambda value: value.update(operator_password=True),
            lambda value: value["accounts"].pop("viewer"),
            lambda value: value["accounts"].update({"analy\u0455t": {}}),
            lambda value: value["accounts"]["analyst"].update(username="sb-lab-analy\u0455t"),
            lambda value: value["accounts"]["analyst"].update(new_token="synthetic-hidden-token"),
            lambda value: value["accounts"]["analyst"].update(
                totp_base32="lowercase-not-supported"
            ),
        ):
            value = copy.deepcopy(profile)
            alter(value)
            self.write(directory + "identity-profile.json", json.dumps(value))
            with self.assertRaises(publication.PublicationError):
                publication.collect_secrets(self.root)

    def test_identity_realm_nested_credentials_and_configuration_must_match_profile(self):
        directory, _, files = self.identity_fixture()
        realm = json.loads(files["signalbridge-realm.json"])
        changed = copy.deepcopy(realm)
        changed["users"][0]["credentials"][1]["secretData"] = (
            '{"value":"synthetic-hidden","value":"synthetic-other"}'
        )
        for name, bad in (
            ("signalbridge-realm.json", json.dumps(changed)),
            ("signalbridge-realm.json", json.dumps({**realm, "clientSecret": "synthetic-hidden"})),
            ("bootstrap-password", "changed-synthetic-password".ljust(64, "x")),
            ("keycloak.conf", files["keycloak.conf"] + "extra-password=synthetic-hidden\n"),
            ("keycloak.conf", files["keycloak.conf"] + "db-password=synthetic-hidden\n"),
        ):
            with self.subTest(file=name):
                self.write(directory + name, bad)
                with self.assertRaises(publication.PublicationError):
                    publication.collect_secrets(self.root)
                self.write(directory + name, files[name])

    def test_identity_inventory_missing_profile_and_linked_key_fail_closed(self):
        directory, _, files = self.identity_fixture(complete=False)
        self.write(directory + "signalbridge-realm.json", files["signalbridge-realm.json"])
        with self.assertRaises(publication.PublicationError):
            publication.collect_secrets(self.root)
        self.write(directory + "identity-profile.json", files["identity-profile.json"])
        unknown = self.write(directory + "unreviewed-private-file", "synthetic-only")
        with self.assertRaises(publication.PublicationError):
            publication.collect_secrets(self.root)
        unknown.unlink()
        target = self.write(directory + "console-private-key.pem", files["console-private-key.pem"])
        original = Path.lstat
        for blocked in (target, target.parent, target.parent.parent):

            def linked(path, blocked=blocked, **kwargs):
                if path == blocked:
                    return SimpleNamespace(
                        st_mode=stat.S_IFREG if path == target else stat.S_IFDIR,
                        st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
                    )
                return original(path, **kwargs)

            with (
                self.subTest(linked=blocked.name),
                patch.object(Path, "lstat", linked),
                self.assertRaises(publication.PublicationError),
            ):
                publication.collect_secrets(self.root)

    def test_identity_secret_inspection_failure_is_fixed_error_and_count_is_bounded(self):
        directory, _, _ = self.identity_fixture()
        profile = self.root / directory / "identity-profile.json"
        original = Path.stat

        def denied(path, **kwargs):
            if path == profile:
                raise PermissionError("synthetic-sensitive-diagnostic")
            return original(path, **kwargs)

        with (
            patch.object(Path, "stat", denied),
            self.assertRaises(publication.PublicationError) as error,
        ):
            publication.collect_secrets(self.root)
        self.assertNotIn("synthetic-sensitive-diagnostic", str(error.exception))
        self.write(directory + "twelfth-file", "synthetic-only")
        with self.assertRaisesRegex(publication.PublicationError, "entries exceed"):
            publication.collect_secrets(self.root)

    def test_identity_sizes_and_malformed_pem_are_bounded_before_publication(self):
        directory, _, files = self.identity_fixture()
        for name, bad in (
            ("identity-profile.json", "x" * 16385),
            ("signalbridge-realm.json", "x" * 65537),
            ("keycloak.conf", "x" * 16385),
            ("provider-private-key.pem", "not-a-private-key"),
            ("lab-ca.pem", "x" * 4097),
        ):
            with self.subTest(file=name):
                self.write(directory + name, bad)
                with self.assertRaises(publication.PublicationError):
                    publication.collect_secrets(self.root)
                self.write(directory + name, files[name])

    def test_identity_publication_failure_messages_and_filenames_do_not_expose_values(self):
        directory, profile, _ = self.identity_fixture()
        sensitive = profile["operator_password"]
        name = "docs/" + sensitive + ".txt"
        self.write(name, sensitive)
        output = StringIO()
        with (
            patch.object(publication, "publication_files", return_value=[name]),
            redirect_stdout(output),
        ):
            self.assertEqual(publication.main(self.root), 1)
        self.assertIn("[redacted]", output.getvalue())
        self.assertNotIn(sensitive, output.getvalue())
        self.write(directory + "identity-profile.json", '{"operator_password":"' + sensitive)
        output = StringIO()
        with (
            patch.object(publication, "publication_files", return_value=[]),
            redirect_stdout(output),
        ):
            self.assertEqual(publication.main(self.root), 1)
        self.assertNotIn(sensitive, output.getvalue())

    def test_duplicate_private_json_fields_rejected_without_values(self):
        path = self.write(
            "var/synthetic-keys.json", '{"scope":"synthetic-original","scope":"synthetic-hidden"}'
        )
        with self.assertRaises(publication.PublicationError) as error:
            publication.collect_secrets(self.root)
        self.assertNotIn("synthetic-original", str(error.exception))
        self.assertNotIn("synthetic-hidden", str(error.exception))
        self.assertTrue(path.is_file())

    def test_known_lab_env_and_private_jwk_values_are_detected_in_renamed_public_files(self):
        self.write("docs/env-copy.md", "Example: " + self.secret)
        self.write("docs/jwk-copy.json", json.dumps({"moved": self.private}))
        self.assertEqual(
            self.scan(["docs/env-copy.md", "docs/jwk-copy.json"]),
            ["docs/env-copy.md", "docs/jwk-copy.json"],
        )

    def test_key_names_and_public_jwk_fields_do_not_trigger_false_positives(self):
        self.write(
            "docs/safe.md",
            'SUPABASE_AUTH_SECRET_KEY SUPABASE_DB_ROOT_KEY "kty" "d" '
            + self.public
            + " public-key-id",
        )
        self.assertEqual(self.scan(["docs/safe.md"]), [])

    def test_original_collector_login_and_django_secrets_remain_covered(self):
        known = [
            "collector-" + uuid.uuid4().hex,
            "login-" + uuid.uuid4().hex,
            "django-" + uuid.uuid4().hex,
            "fixture-" + uuid.uuid4().hex,
        ]
        self.write("var/lab-keys.json", json.dumps({"bettail": known[0]}))
        self.write("var/local-access.txt", "analyst: " + known[1])
        self.write("var/django-secret", known[2])
        self.write("var/synthetic-keys.json", json.dumps({"demo": known[3]}))
        secrets = publication.collect_secrets(self.root)
        self.assertTrue(set(known).issubset(secrets))
        for index, value in enumerate(known):
            name = f"copy-{index}.txt"
            self.write(name, value)
            self.assertEqual(publication.scan_publishable(self.root, [name], secrets), [name])

    def test_private_path_names_are_blocked_even_if_new_credential_is_not_known(self):
        names = [
            "var/unknown.txt",
            "artifacts/local/report.json",
            "private-source/bettail/code.ts",
            ".venv/example.txt",
            "node_modules/package.json",
            ".env",
            "docs/.env.local",
            "copied/signing_keys.json",
            ".npmrc",
        ]
        self.assertEqual(self.scan(names), sorted(names))
        self.write(".env.example", "SUPABASE_AUTH_SECRET_KEY=replace-for-your-local-lab")
        self.assertEqual(self.scan([".env.example"]), [])

    def test_utf16_and_binary_copies_are_detected(self):
        for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
            self.write("copy.bin", b"\x00\x01" + self.secret.encode(encoding) + b"\xff")
            self.assertEqual(self.scan(["copy.bin"]), ["copy.bin"])

    def test_legacy_windows_login_text_and_bom_marked_private_files_remain_readable(self):
        self.write(
            "var/local-access.txt",
            ("Local accounts — private\nanalyst: " + self.secret).encode("cp1252"),
        )
        self.write(
            "var/labs/bettail/.env", ("SUPABASE_AUTH_SECRET_KEY=" + self.private).encode("utf-16")
        )
        values = publication.collect_secrets(self.root)
        self.assertIn(self.secret, values)
        self.assertIn(self.private, values)

    def test_private_names_are_case_insensitive_and_include_environment_variants(self):
        names = ["VAR/a.txt", "Private-Source/a.json", ".env-secret", "Docs/.ENV.production"]
        self.assertEqual(self.scan(names), sorted(names))

    def test_env_parser_handles_quotes_comments_and_literal_jwt_without_key_name_matching(self):
        values = publication.env_secrets(
            f"# comment\nexport AUTH_TOKEN='{self.secret}' # retained value\n"
            f'LOCAL_JWT="eyJhbGci.synthetic.signature"\nDB_PASSWORD=literal#hash-secret\n'
            "API_URL=http://127.0.0.1:55321\nPORT=55321\nEMPTY_KEY=\n"
        )
        self.assertEqual(
            values, {self.secret, "eyJhbGci.synthetic.signature", "literal#hash-secret"}
        )
        self.assertNotIn("AUTH_TOKEN", values)
        self.assertNotIn("55321", values)

    def test_env_parser_fails_closed_for_expansion_malformed_or_short_credentials(self):
        for line in (
            "SECRET_KEY=$(execute-something)",
            "SECRET_KEY=${OTHER_SECRET}",
            "SECRET_KEY=`command-output`",
            "SECRET_KEY=short",
            "SECRET_KEY='not-terminated",
            "malformed assignment",
        ):
            with (
                self.subTest(kind=line.split("=", 1)[0]),
                self.assertRaises(publication.PublicationError),
            ):
                publication.env_secrets(line)

    def test_rsa_symmetric_and_nested_private_factors_are_detected_but_public_parts_are_not(self):
        private_fields = {
            field: field + "-synthetic-" + uuid.uuid4().hex
            for field in ("d", "p", "q", "dp", "dq", "qi")
        }
        factor = {field: field + "-factor-" + uuid.uuid4().hex for field in ("r", "d", "t")}
        result = publication.jwk_secrets(
            {
                "keys": [
                    {
                        "kty": "RSA",
                        "n": self.public,
                        "e": "AQAB",
                        "oth": [factor],
                        **private_fields,
                    },
                    {"kty": "oct", "k": self.secret},
                    {"kty": "OKP", "d": self.private, "x": self.public},
                ]
            }
        )
        self.assertEqual(
            result,
            set(private_fields.values()) | set(factor.values()) | {self.secret, self.private},
        )
        self.assertNotIn(self.public, result)

    def test_corrupt_private_json_fails_without_printing_parser_payload(self):
        self.write("var/labs/bettail/supabase/signing_keys.json", '{"secret":' + self.private)
        output = StringIO()
        with (
            patch.object(publication, "publication_files", return_value=[]),
            redirect_stdout(output),
        ):
            self.assertEqual(publication.main(self.root), 1)
        self.assertIn("BLOCKED", output.getvalue())
        self.assertNotIn(self.private, output.getvalue())

    def test_blocked_output_never_echoes_values_even_in_filenames(self):
        name = "docs/" + self.secret + ".txt"
        self.write(name, self.private)
        output = StringIO()
        with (
            patch.object(publication, "publication_files", return_value=[name]),
            redirect_stdout(output),
        ):
            self.assertEqual(publication.main(self.root), 1)
        self.assertIn("[redacted]", output.getvalue())
        self.assertNotIn(self.secret, output.getvalue())
        self.assertNotIn(self.private, output.getvalue())

    def test_file_and_total_byte_limits_fail_closed(self):
        self.write("large.txt", "x" * 20)
        with (
            patch.object(publication, "MAX_PUBLIC_BYTES", 10),
            self.assertRaises(publication.PublicationError),
        ):
            self.scan(["large.txt"])
        with (
            patch.object(publication, "MAX_TOTAL_BYTES", 10),
            self.assertRaises(publication.PublicationError),
        ):
            self.scan(["large.txt"])
        with (
            patch.object(publication, "MAX_FILES", 0),
            self.assertRaises(publication.PublicationError),
        ):
            self.scan(["large.txt"])
        with (
            patch.object(publication, "MAX_PRIVATE_BYTES", 10),
            self.assertRaises(publication.PublicationError),
        ):
            publication.collect_secrets(self.root)

    def test_linked_public_files_are_rejected_before_reading(self):
        target = self.write("linked.txt", "safe synthetic text")
        original = Path.lstat

        def linked(path, **kwargs):
            if path == target:
                return SimpleNamespace(
                    st_mode=stat.S_IFREG, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT
                )
            return original(path, **kwargs)

        with patch.object(Path, "lstat", linked), self.assertRaises(publication.PublicationError):
            self.scan(["linked.txt"])

    def test_git_listing_uses_nul_boundaries_for_unusual_filenames(self):
        with (
            patch.object(publication.shutil, "which", return_value="git"),
            patch.object(
                publication.subprocess,
                "check_output",
                return_value=b"docs/line\nbreak.md\0README.md\0README.md\0",
            ) as command,
        ):
            self.assertEqual(
                publication.publication_files(self.root), ["README.md", "docs/line\nbreak.md"]
            )
        self.assertIn("-z", command.call_args.args[0])

    def test_external_paths_are_rejected_and_deleted_tracked_content_is_not_read(self):
        for name in ("../outside", "C:/outside", "/absolute", "docs\\outside", ".", ""):
            with self.assertRaises(publication.PublicationError):
                self.scan([name])
        self.assertEqual(self.scan(["deleted.txt"]), [])

    def test_http_run_credentials_are_detected_without_collecting_synthetic_identity_fields(self):
        run_id = str(uuid.uuid4())
        identity = str(uuid.uuid4())
        email = "synthetic-member@example.test"
        self.write(
            f"var/labs/bettail/http-runs/{run_id}.private.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "run_id": run_id,
                    "actors": {
                        "owner": {
                            "password": self.secret,
                            "token": self.private,
                            "email": email,
                            "id": identity,
                        },
                        "member": {"password": self.public},
                    },
                    "group_id": str(uuid.uuid4()),
                    "hash": "f" * 64,
                }
            ),
        )
        secrets = publication.collect_secrets(self.root)
        self.assertTrue({self.secret, self.private, self.public}.issubset(secrets))
        self.assertFalse({email, identity, run_id, "f" * 64} & secrets)
        self.write("password-copy.txt", self.secret)
        self.write("jwt-copy.txt", self.private)
        self.write("identity-only.txt", email + identity)
        self.assertEqual(
            publication.scan_publishable(
                self.root, ["password-copy.txt", "jwt-copy.txt", "identity-only.txt"], secrets
            ),
            ["jwt-copy.txt", "password-copy.txt"],
        )

    def test_http_run_credentials_fail_closed_on_bad_shape_or_excessive_run_count(self):
        run_id = str(uuid.uuid4())
        name = f"var/labs/bettail/http-runs/{run_id}.private.json"
        valid = {
            "schema_version": 1,
            "run_id": run_id,
            "actors": {"owner": {"password": self.secret}},
        }
        for actors in (
            ["owner"],
            {"administrator": {"password": self.secret}},
            {"owner": {}},
            {"owner": {"password": self.secret, "token": None}},
        ):
            self.write(name, json.dumps({**valid, "actors": actors}))
            with self.assertRaises(publication.PublicationError):
                publication.collect_secrets(self.root)
        self.write(name, json.dumps(valid))
        with (
            patch.object(publication, "MAX_HTTP_RUNS", 0),
            self.assertRaises(publication.PublicationError),
        ):
            publication.collect_secrets(self.root)

    def route_fixture(self, *, chunked=False):
        run_id = str(uuid.uuid4())
        password = "route-password-" + uuid.uuid4().hex
        service_token = "route-service-token-" + uuid.uuid4().hex
        token = "route-session-token-" + uuid.uuid4().hex
        refresh = "route-refresh-token-" + uuid.uuid4().hex
        encoded = "base64-" + base64.urlsafe_b64encode(
            json.dumps(
                {"access_token": token, "refresh_token": refresh, "user": {"id": str(uuid.uuid4())}}
            ).encode()
        ).decode().rstrip("=")
        values = [encoded[:80], encoded[80:]] if chunked else [encoded]
        names = (
            [f"sb-127-auth-token.{index}" for index in range(len(values))]
            if chunked
            else ["sb-127-auth-token"]
        )
        cookie = "; ".join(f"{name}={value}" for name, value in zip(names, values, strict=True))
        data = {
            "schema_version": 1,
            "run_id": run_id,
            "service": {
                "schema_version": 1,
                "run_id": run_id,
                "actors": {
                    "owner": {
                        "password": password,
                        "token": service_token,
                        "email": "synthetic@example.test",
                        "id": str(uuid.uuid4()),
                    }
                },
                "restore_required": False,
            },
            "sessions": {"owner": {"cookie": cookie, "token": token}},
            "route_restore_required": False,
            "restore_required": False,
        }
        return data, {password, service_token, token, refresh, encoded, cookie, *values}

    def test_route_recovery_credentials_cookies_and_embedded_refresh_tokens_block_public_copies(
        self,
    ):
        for chunked in (False, True):
            with self.subTest(chunked=chunked):
                data, sensitive = self.route_fixture(chunked=chunked)
                self.write(
                    f"var/labs/bettail/routes/evidence/{data['run_id']}.private.json",
                    json.dumps(data),
                )
                secrets = publication.collect_secrets(self.root)
                self.assertTrue(sensitive.issubset(secrets))
                self.assertNotIn("synthetic@example.test", secrets)
                self.assertNotIn(data["run_id"], secrets)
                for index, value in enumerate(sorted(sensitive)):
                    name = f"docs/route-copy-{index}.txt"
                    self.write(name, value)
                    self.assertEqual(
                        publication.scan_publishable(self.root, [name], secrets), [name]
                    )

    def test_interrupted_route_pending_file_is_also_checked_for_new_session_credentials(self):
        data, sensitive = self.route_fixture()
        run_id = data["run_id"]
        self.write(
            f"var/labs/bettail/routes/evidence/{run_id}.private.json",
            json.dumps({"schema_version": 1, "run_id": run_id, "state": "starting"}),
        )
        pending = f"var/labs/bettail/routes/evidence/{run_id}.{uuid.uuid4()}.pending"
        self.write(pending, json.dumps(data))
        self.assertTrue(sensitive.issubset(publication.collect_secrets(self.root)))
        self.write(pending, '{"password":"' + next(iter(sensitive)))
        output = StringIO()
        with (
            patch.object(publication, "publication_files", return_value=[]),
            redirect_stdout(output),
        ):
            self.assertEqual(publication.main(self.root), 1)
        self.assertIn("BLOCKED", output.getvalue())
        for value in sensitive:
            self.assertNotIn(value, output.getvalue())

    def test_route_starting_and_partial_setup_records_collect_only_issued_credentials(self):
        data, _ = self.route_fixture()
        run_id = data["run_id"]
        self.assertEqual(
            publication.route_run_secrets(
                {"schema_version": 1, "run_id": run_id, "state": "starting"}, run_id
            ),
            set(),
        )
        data["sessions"] = {}
        actor = data["service"]["actors"]["owner"]
        del actor["token"]
        data["service"]["restore_required"] = data["restore_required"] = True
        self.assertEqual(publication.route_run_secrets(data, run_id), {actor["password"]})

    def test_route_unknown_schema_session_actor_or_inconsistent_recovery_shape_fails_closed(self):
        for change in (
            lambda data: data.update(schema_version=True),
            lambda data: data.update(unknown_credential="synthetic-unknown-secret"),
            lambda data: data["service"].update(run_id=str(uuid.uuid4())),
            lambda data: data.update(restore_required=True),
            lambda data: data.update(sessions=[]),
            lambda data: data["sessions"]["owner"].update(token=None),
            lambda data: data["sessions"]["owner"].update(cookie="unsupported-cookie-value"),
            lambda data: data["service"]["actors"].update(
                administrator={"password": "synthetic-password"}
            ),
            lambda data: data["service"]["actors"]["owner"].update(
                new_token="synthetic-unknown-token"
            ),
        ):
            data, _ = self.route_fixture()
            change(data)
            with self.assertRaises(publication.PublicationError):
                publication.route_run_secrets(data, data["run_id"])

    def test_route_cookie_chunks_must_be_complete_decodable_and_match_retained_session(self):
        data, _ = self.route_fixture(chunked=True)
        session = data["sessions"]["owner"]
        cookie, token = session["cookie"], session["token"]
        for invalid in (
            cookie.replace("auth-token.1=", "auth-token.2="),
            cookie.replace("auth-token.1=", "auth-token.0="),
            cookie.replace("sb-127-auth-token.1=", "sb-other-auth-token.1="),
            cookie.split("; ")[0],
            "sb-127-auth-token=base64-a",
            cookie + "\r\nInjected: value",
        ):
            with self.assertRaises(publication.PublicationError):
                publication.route_cookie_secrets(invalid, token)
        with self.assertRaises(publication.PublicationError):
            publication.route_cookie_secrets(cookie, "different-synthetic-session-token")

    def test_route_private_count_filename_and_link_bounds_fail_closed(self):
        data, _ = self.route_fixture()
        name = f"var/labs/bettail/routes/evidence/{data['run_id']}.private.json"
        target = self.write(name, json.dumps(data))
        with (
            patch.object(publication, "MAX_ROUTE_PRIVATE_FILES", 0),
            self.assertRaises(publication.PublicationError),
        ):
            publication.collect_secrets(self.root)
        original = Path.lstat

        def linked(path, **kwargs):
            if path == target:
                return SimpleNamespace(
                    st_mode=stat.S_IFREG, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT
                )
            return original(path, **kwargs)

        with patch.object(Path, "lstat", linked), self.assertRaises(publication.PublicationError):
            publication.collect_secrets(self.root)
        self.write("var/labs/bettail/routes/evidence/unknown.private.json", json.dumps(data))
        with self.assertRaises(publication.PublicationError):
            publication.collect_secrets(self.root)

    def test_unreadable_route_evidence_directory_cannot_silently_omit_credentials(self):
        data, _ = self.route_fixture()
        target = self.write(
            f"var/labs/bettail/routes/evidence/{data['run_id']}.private.json", json.dumps(data)
        ).parent
        original = Path.iterdir

        def unreadable(path):
            if path == target:
                raise PermissionError("synthetic private detail must not reach output")
            return original(path)

        with (
            patch.object(Path, "iterdir", unreadable),
            self.assertRaisesRegex(
                publication.PublicationError, "Private route evidence could not be enumerated"
            ),
        ):
            publication.collect_secrets(self.root)
