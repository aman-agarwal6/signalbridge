#!/bin/bash
set -euo pipefail
# Fresh disposable database only. No secret appears in process arguments.
SB_IDENTITY_CONSOLE_PASSWORD="$(cat /run/secrets/console-password)"
SB_IDENTITY_PROVIDER_PASSWORD="$(cat /run/secrets/keycloak-password)"
export SB_IDENTITY_CONSOLE_PASSWORD SB_IDENTITY_PROVIDER_PASSWORD
psql --username "$POSTGRES_USER" --dbname postgres --no-psqlrc --set ON_ERROR_STOP=1 <<'SQL'
\getenv console_password SB_IDENTITY_CONSOLE_PASSWORD
\getenv provider_password SB_IDENTITY_PROVIDER_PASSWORD
CREATE ROLE identity_console LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'console_password';
CREATE ROLE identity_keycloak LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'provider_password';
CREATE DATABASE identity_console OWNER identity_console;
CREATE DATABASE identity_keycloak OWNER identity_keycloak;
REVOKE CONNECT ON DATABASE identity_console FROM PUBLIC;
REVOKE CONNECT ON DATABASE identity_keycloak FROM PUBLIC;
GRANT CONNECT ON DATABASE identity_console TO identity_console;
GRANT CONNECT ON DATABASE identity_keycloak TO identity_keycloak;
SQL
unset SB_IDENTITY_CONSOLE_PASSWORD SB_IDENTITY_PROVIDER_PASSWORD
