#!/bin/bash
set -euo pipefail
# The image entrypoint runs this once inside the disposable database. Credentials
# are read from private secret mounts, never passed as command-line arguments.
SB_VERIFIER_PASSWORD="$(cat /run/secrets/verifier_password)"
export SB_VERIFIER_PASSWORD
psql --username "$POSTGRES_USER" --dbname postgres --no-psqlrc --set ON_ERROR_STOP=1 <<'SQL'
\getenv verifier_password SB_VERIFIER_PASSWORD
CREATE ROLE sb_verifier LOGIN CREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION PASSWORD :'verifier_password';
CREATE DATABASE sb_enterprise_verification OWNER sb_verifier;
SQL
unset SB_VERIFIER_PASSWORD
