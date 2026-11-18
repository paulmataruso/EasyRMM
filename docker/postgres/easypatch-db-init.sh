#!/bin/sh
# Creates the database and roles of EasyRMM's patching engine (EasyPatch) in
# EasyRMM's PostgreSQL, or brings them up to date. The easypatch-db-init
# service runs it before every start of the engine. Unlike the scripts in
# init/, which PostgreSQL runs only on an empty data directory, it also runs
# on an existing install, and running it again changes nothing but the
# passwords, which it sets from .env each time.
#
#   easypatch_owner  owns the database and its schema; used only for migrations
#   easypatch_app    the engine's runtime role: reads and writes rows, no DDL
#
# Connects as the PostgreSQL superuser over loopback (PGPASSWORD).
set -eu

: "${PGPASSWORD:?PGPASSWORD (the PostgreSQL superuser password) must be set}"
: "${EASYPATCH_DB_OWNER_PASSWORD:?is empty in deploy/.env: run deploy/scripts/setup.sh to add it}"
: "${EASYPATCH_DB_APP_PASSWORD:?is empty in deploy/.env: run deploy/scripts/setup.sh to add it}"
export PGHOST="${PGHOST:-127.0.0.1}" PGPORT="${PGPORT:-15432}" PGUSER="${PGUSER:-postgres}"

# Values are passed as psql variables and quoted by psql (:'var'), never
# interpolated into SQL by the shell.
psql -v ON_ERROR_STOP=1 --quiet --dbname postgres \
  -v owner_pw="$EASYPATCH_DB_OWNER_PASSWORD" -v app_pw="$EASYPATCH_DB_APP_PASSWORD" <<'SQL'
SET password_encryption = 'scram-sha-256';
SELECT 'CREATE ROLE easypatch_owner LOGIN'
  WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'easypatch_owner') \gexec
SELECT 'CREATE ROLE easypatch_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS'
  WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'easypatch_app') \gexec
ALTER ROLE easypatch_owner PASSWORD :'owner_pw';
ALTER ROLE easypatch_app PASSWORD :'app_pw';
SELECT 'CREATE DATABASE easypatch OWNER easypatch_owner ENCODING ''UTF8'' TEMPLATE template0'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'easypatch') \gexec
REVOKE ALL ON DATABASE easypatch FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE easypatch TO easypatch_app;
\connect easypatch
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO easypatch_app;
-- Tables and sequences the migrations create from now on...
ALTER DEFAULT PRIVILEGES FOR ROLE easypatch_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO easypatch_app;
ALTER DEFAULT PRIVILEGES FOR ROLE easypatch_owner IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO easypatch_app;
-- ...and those that already exist.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO easypatch_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO easypatch_app;
SQL
echo "easypatch-db-init: database easypatch and its roles are ready."
