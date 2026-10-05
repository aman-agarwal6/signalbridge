"""Receive AccessOps leaver signals (SSF, RFC 8936 polling) and open access-after-departure cases.

setup  --receiver-env PATH --ca PATH --grant USER:ROLE ...
       Copies the receiver token and the lab CA certificate into var/ssf (the token is never
       printed) and grants access to the separate "accessops" workspace.
poll   [--dry-run] [--max-polls N] [--receipt]
       Polls the transmitter on 127.0.0.1:8443 (TLS name accessops.test, pinned CA). Needs
       the identity runtime, which provides the cryptography package for ES256.
status Counts of stored signals and leaver cases.
"""

import hashlib
import json
import os
import re
import ssl
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from bridge.leaver import RULE_CONSOLE, RULE_REPORTED, departed_subjects, detect, workspace
from bridge.models import Audit, Investigation, LeaverSignal, Membership

TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{32,512}")
MAX_FILE = 16 * 1024


def ssf_dir():
    directory = Path(settings.VAR_DIR) / "ssf"
    if directory.is_symlink():
        raise CommandError("var/ssf must be a plain folder.")
    return directory


def read_small(path, what):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_FILE:
        raise CommandError(f"{what} must be a small regular file.")
    return path.read_text(encoding="utf-8")


def write_private(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise CommandError("Refusing to write through a link.")
    temporary = path.with_suffix(".tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


class Command(BaseCommand):
    help = "Receive AccessOps leaver signals and open access-after-departure cases."

    def add_arguments(self, parser):
        actions = parser.add_subparsers(dest="action", required=True)
        setup = actions.add_parser("setup")
        setup.add_argument("--receiver-env", required=True)
        setup.add_argument("--ca", required=True)
        setup.add_argument("--grant", action="append", default=[], metavar="USERNAME:ROLE")
        poll = actions.add_parser("poll")
        poll.add_argument("--dry-run", action="store_true")
        poll.add_argument("--max-polls", type=int, default=40)
        poll.add_argument("--receipt", action="store_true")
        actions.add_parser("status")

    def handle(self, *args, **options):
        if not settings.LOCAL:
            raise CommandError("The AccessOps lab receiver is local-only.")
        getattr(self, options["action"])(options)

    def setup(self, options):
        token = None
        for line in read_small(options["receiver_env"], "The receiver env file").splitlines():
            name, separator, value = line.strip().partition("=")
            if separator and name.strip() == "SSF_RECEIVER_TOKEN":
                token = value.strip().strip('"').strip("'")
        if not token or not TOKEN.fullmatch(token):
            raise CommandError("The env file has no usable SSF_RECEIVER_TOKEN.")
        certificate = read_small(options["ca"], "The CA certificate")
        if "-----BEGIN CERTIFICATE-----" not in certificate or "PRIVATE KEY" in certificate:
            raise CommandError("The CA file must hold only a public PEM certificate.")
        try:
            ssl.create_default_context(cadata=certificate)
        except ssl.SSLError as error:
            raise CommandError("The CA certificate does not load.") from error
        grants = []
        for value in options["grant"]:
            username, separator, role = value.rpartition(":")
            if not separator or role not in ("viewer", "analyst", "reviewer"):
                raise CommandError("Each grant must be USERNAME:viewer, analyst, or reviewer.")
            try:
                grants.append(
                    (get_user_model().objects.get(username=username, is_active=True), role)
                )
            except get_user_model().DoesNotExist as error:
                raise CommandError("A grant requires an existing active user.") from error
        directory = ssf_dir()
        write_private(directory / "receiver-token", token + "\n")
        write_private(directory / "accessops-root.crt", certificate)
        with transaction.atomic():
            app = workspace()
            for user, role in grants:
                membership, added = Membership.objects.get_or_create(
                    user=user, integration=app, defaults={"role": role}
                )
                if membership.role != role:
                    raise CommandError("An existing membership has a different role.")
                if added:
                    Audit.objects.create(
                        integration=app,
                        actor=user,
                        action="leaver.access_granted",
                        object_id=str(user.pk),
                        detail={"role": role, "via": "local_operator"},
                    )
        fingerprint = hashlib.sha256(certificate.encode()).hexdigest()[:16]
        self.stdout.write(
            f"Receiver configured. Token stored in var/ssf (not shown); CA file sha256 "
            f"{fingerprint}...; workspace '{app.slug}'; {len(grants)} grants checked."
        )

    def poll(self, options):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            raise CommandError(
                "ES256 verification needs the cryptography package: run this command with the "
                "identity runtime (var/enterprise/identity/<id>/venv)."
            ) from None
        from bridge.leaver_receiver import Receiver
        from integrations.ssf.transport import Transmitter, TransmitterError

        if not 1 <= options["max_polls"] <= 100:
            raise CommandError("--max-polls must be between 1 and 100.")
        directory = ssf_dir()
        token_file, ca_file = directory / "receiver-token", directory / "accessops-root.crt"
        if not token_file.is_file() or not ca_file.is_file():
            raise CommandError("Run 'accessops_signals setup' first.")
        token = token_file.read_text(encoding="utf-8").strip()
        transmitter = Transmitter(ca_file)
        started = datetime.now(timezone.utc)
        receiver = Receiver(
            transmitter, token, dry_run=options["dry_run"], max_polls=options["max_polls"]
        )
        failure = None
        try:
            receiver.run()
        except TransmitterError as error:
            failure = str(error)
        cases = {}
        if not options["dry_run"]:
            cases = detect(receiver.subjects | departed_subjects())
        finished = datetime.now(timezone.utc)
        summary = {
            "dry_run": options["dry_run"],
            "failure": failure,
            "polls": receiver.polls,
            "offered": receiver.counts["offered"],
            "stored": receiver.counts["stored"],
            "duplicates": receiver.counts["duplicate"],
            "by_type": {
                key: value
                for key, value in receiver.counts.items()
                if key not in ("offered", "stored", "duplicate")
            },
            "refused": dict(receiver.errors),
            "acknowledged": receiver.acknowledged,
            "reported_as_errors": receiver.reported,
            "queue_drained": receiver.drained,
            "key_fetches": receiver.key_fetches,
            "case_actions": cases,
        }
        self.stdout.write(json.dumps(summary, indent=2, sort_keys=True))
        if options["receipt"]:
            receipt = {
                "schema_version": 1,
                "kind": "signalbridge-accessops-leaver-poll",
                "run_id": uuid.uuid4().hex,
                "started_at": started.isoformat(),
                "finished_at": finished.isoformat(),
                "duration_seconds": round((finished - started).total_seconds(), 3),
                "transmitter": {
                    "issuer": "https://accessops.test:8443",
                    "address": "127.0.0.1:8443",
                    "tls_server_name": "accessops.test",
                    "ca_file_sha256": hashlib.sha256(ca_file.read_bytes()).hexdigest(),
                    "server_certificate_sha256": hashlib.sha256(
                        transmitter.peer_certificate
                    ).hexdigest()
                    if transmitter.peer_certificate
                    else None,
                    "signing_key_ids": sorted(receiver.keys),
                },
                **summary,
                "stored_totals": dict(
                    Counter(LeaverSignal.objects.values_list("event_type", flat=True))
                ),
                "open_cases": {
                    rule: Investigation.objects.filter(
                        integration__slug="accessops", rule=rule, status="open"
                    ).count()
                    for rule in (RULE_REPORTED, RULE_CONSOLE)
                },
                "limits": [
                    "One poll run against the local AccessOps lab with synthetic test workers.",
                    "Signals prove what AccessOps reported and signed, not what a session accessed.",
                    "Builder-run receipt; the receiver token and subject identifiers are omitted.",
                ],
            }
            path = directory / "receipts" / f"{started:%Y%m%dT%H%M%SZ}-{receipt['run_id']}.json"
            write_private(path, json.dumps(receipt, indent=2, sort_keys=True) + "\n")
            self.stdout.write("Receipt: " + str(path.relative_to(settings.VAR_DIR.parent)))
        if failure:
            raise CommandError("The poll stopped: " + failure)

    def status(self, options):
        self.stdout.write(
            json.dumps(
                {
                    "signals": dict(
                        Counter(LeaverSignal.objects.values_list("event_type", flat=True))
                    ),
                    "cases": {
                        f"{rule}/{status}": count
                        for rule, status, count in (
                            (
                                r,
                                s,
                                Investigation.objects.filter(
                                    integration__slug="accessops", rule=r, status=s
                                ).count(),
                            )
                            for r in (RULE_REPORTED, RULE_CONSOLE)
                            for s in ("open", "resolved", "false_positive")
                        )
                        if count
                    },
                },
                indent=2,
                sort_keys=True,
            )
        )
