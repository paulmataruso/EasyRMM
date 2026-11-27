#!/bin/sh
# Creates the log store's roles and database on the first start of the
# log store's PostgreSQL container (docker-entrypoint-initdb.d; ADR-0060). It
# is a PostgreSQL instance of its own, apart from the main database. For an
# external server, run the same statements as a superuser.
#
#   easyrmm_logs_owner  owns the schema; used only to run migrations
#   easyrmm_logs_app    runtime role; reads and writes blocks, subject to
#                       row-level security, and cannot delete or change the
#                       schema
set -eu

: "${EASYRMM_LOGS_DB_OWNER_PASSWORD:?EASYRMM_LOGS_DB_OWNER_PASSWORD must be set}"
: "${EASYRMM_LOGS_DB_APP_PASSWORD:?EASYRMM_LOGS_DB_APP_PASSWORD must be set}"
db="${EASYRMM_LOGS_DB_NAME:-easyrmm_logs}"

# Values are passed as psql variables and quoted by psql (:'var'), never
# interpolated into SQL by the shell.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_pw="$EASYRMM_LOGS_DB_OWNER_PASSWORD" -v app_pw="$EASYRMM_LOGS_DB_APP_PASSWORD" -v db="$db" <<'SQL'
SET password_encryption = 'scram-sha-256';
CREATE ROLE easyrmm_logs_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE easyrmm_logs_app LOGIN PASSWORD :'app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE :"db" OWNER easyrmm_logs_owner ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO easyrmm_logs_app;
\connect :"db"
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
