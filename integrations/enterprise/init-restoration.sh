#!/bin/bash
set -euo pipefail
# First initialization of the separate restoration database only. The retained
# backup is restored afterwards by the host controller into this owned database.
# Secret values never occur in arguments or diagnostic output.
SB_CONSOLE_PASSWORD="$(cat /run/secrets/console_password)"
export SB_CONSOLE_PASSWORD
psql --username "$POSTGRES_USER" --dbname postgres --no-psqlrc --set ON_ERROR_STOP=1 <<'SQL'
\getenv console_password SB_CONSOLE_PASSWORD
CREATE ROLE sb_restored_console LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'console_password';
CREATE DATABASE sb_enterprise_access OWNER sb_restored_console;
REVOKE CONNECT ON DATABASE sb_enterprise_access FROM PUBLIC;
GRANT CONNECT ON DATABASE sb_enterprise_access TO sb_restored_console;
SQL
unset SB_CONSOLE_PASSWORD
