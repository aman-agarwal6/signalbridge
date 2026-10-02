"""Provision only a fresh PostgreSQL service inside a disposable hosted CI job.

This preparation is not a workstation launcher or a production migration tool.
"""

import os
import secrets
import sys
from pathlib import Path


def hosted_job(environment, platform, root):
    if (
        platform != "linux"
        or environment.get("GITHUB_ACTIONS") != "true"
        or environment.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or environment.get("SB_CI_POSTGRES_PROFILE") != "signalbridge-enterprise-ci-v1"
        or Path(environment.get("GITHUB_WORKSPACE", "")).resolve() != root.resolve()
    ):
        raise RuntimeError("Only the declared fresh GitHub-hosted service job is allowed.")
    if any(name.startswith("PG") and value for name, value in environment.items()):
        raise RuntimeError("Inherited database settings are forbidden.")


def main():
    hosted_job(os.environ, sys.platform, Path(__file__).resolve().parents[1])
    import psycopg
    from psycopg import sql

    bootstrap = os.environ.get("SB_CI_BOOTSTRAP_PASSWORD", "")
    if len(bootstrap) < 32:
        raise RuntimeError("The disposable service bootstrap credential is missing.")
    directory = Path("/run/secrets")
    if directory.is_symlink():
        raise RuntimeError("The job secret directory cannot be redirected.")
    directory.mkdir(mode=0o700, exist_ok=True)
    secret = directory / "verifier_password"
    if secret.exists() or secret.is_symlink():
        raise RuntimeError("CI will not replace an existing database credential.")
    password = secrets.token_urlsafe(48)
    # GitHub processes this workflow command to redact the generated job secret.
    print("::add-mask::" + password, flush=True)
    with psycopg.connect(
        host="database",
        port=5432,
        dbname="postgres",
        user="postgres",
        password=bootstrap,
        connect_timeout=3,
        autocommit=True,
        options="-c statement_timeout=5000",
        sslmode="disable",
        gssencmode="disable",
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='sb_verifier'), EXISTS(SELECT 1 FROM pg_database WHERE datname='sb_enterprise_verification')"
            )
            if any(cursor.fetchone()):
                raise RuntimeError("CI refuses a non-fresh role or database.")
            cursor.execute(
                sql.SQL(
                    "CREATE ROLE sb_verifier LOGIN CREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION PASSWORD {}"
                ).format(sql.Literal(password))
            )
            cursor.execute("CREATE DATABASE sb_enterprise_verification OWNER sb_verifier")
    with secret.open("x", encoding="ascii") as handle:
        handle.write(password)
    secret.chmod(0o600)
    print("Fresh non-superuser disposable verification database prepared.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # Driver errors may contain connection details; do not log a traceback.
        print("Disposable CI database preparation failed; no native pass claimed.", file=sys.stderr)
        raise SystemExit(1) from None
