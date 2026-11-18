#!/bin/sh
# Creates the EasyRMM roles and database on the first start of the
# PostgreSQL container (docker-entrypoint-initdb.d). For an external
# PostgreSQL server, run the same statements as a superuser.
#
#   easyrmm_owner  owns the schema; used only to run migrations
#   easyrmm_app    runtime role; DML only, subject to row-level security
set -eu

: "${EASYRMM_DB_OWNER_PASSWORD:?EASYRMM_DB_OWNER_PASSWORD must be set}"
: "${EASYRMM_DB_APP_PASSWORD:?EASYRMM_DB_APP_PASSWORD must be set}"
db="${EASYRMM_DB_NAME:-easyrmm}"

# Values are passed as psql variables and quoted by psql (:'var'), never
# interpolated into SQL by the shell.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_pw="$EASYRMM_DB_OWNER_PASSWORD" -v app_pw="$EASYRMM_DB_APP_PASSWORD" -v db="$db" <<'SQL'
SET password_encryption = 'scram-sha-256';
CREATE ROLE easyrmm_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE easyrmm_app LOGIN PASSWORD :'app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE :"db" OWNER easyrmm_owner ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO easyrmm_app;
\connect :"db"
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
