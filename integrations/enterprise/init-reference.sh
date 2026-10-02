#!/bin/bash
set -euo pipefail
# Dedicated non-superuser roles, created only by the disposable image's first
# initialization. Secret values never occur in arguments or diagnostic output.
SB_SOURCE_PASSWORD="$(cat /run/secrets/source_password)"
SB_CONSOLE_PASSWORD="$(cat /run/secrets/console_password)"
export SB_SOURCE_PASSWORD SB_CONSOLE_PASSWORD
psql --username "$POSTGRES_USER" --dbname postgres --no-psqlrc --set ON_ERROR_STOP=1 <<'SQL'
\getenv source_password SB_SOURCE_PASSWORD
\getenv console_password SB_CONSOLE_PASSWORD
CREATE ROLE sb_reference LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'source_password';
CREATE ROLE sb_access_console LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'console_password';
CREATE DATABASE sb_reference OWNER sb_reference;
CREATE DATABASE sb_enterprise_access OWNER sb_access_console;
REVOKE CONNECT ON DATABASE sb_reference FROM PUBLIC;
REVOKE CONNECT ON DATABASE sb_enterprise_access FROM PUBLIC;
GRANT CONNECT ON DATABASE sb_reference TO sb_reference;
GRANT CONNECT ON DATABASE sb_enterprise_access TO sb_access_console;
SQL
unset SB_SOURCE_PASSWORD SB_CONSOLE_PASSWORD
