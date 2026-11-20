#!/bin/sh
# Creates Authentik's database and role in EasyRMM's PostgreSQL, or brings
# them up to date (ADR-0044). The authentik-db-init service runs it before
# every start of Authentik. Like easypatch-db-init.sh, it also runs on an
# existing install, where PostgreSQL's init scripts never run again, and
# running it again changes nothing but the password, which it sets from .env
# each time.
#
#   authentik  owns the database: Authentik applies its own migrations
#
# Connects as the PostgreSQL superuser over loopback (PGPASSWORD).
set -eu

: "${PGPASSWORD:?PGPASSWORD (the PostgreSQL superuser password) must be set}"
: "${AUTHENTIK_DB_PASSWORD:?is empty in deploy/.env: run deploy/scripts/setup.sh --with-authentik}"
export PGHOST="${PGHOST:-127.0.0.1}" PGPORT="${PGPORT:-15432}" PGUSER="${PGUSER:-postgres}"

# The password is passed as a psql variable and quoted by psql (:'var'),
# never interpolated into SQL by the shell.
psql -v ON_ERROR_STOP=1 --quiet --dbname postgres -v pw="$AUTHENTIK_DB_PASSWORD" <<'SQL'
SET password_encryption = 'scram-sha-256';
SELECT 'CREATE ROLE authentik LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS'
  WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authentik') \gexec
ALTER ROLE authentik PASSWORD :'pw';
SELECT 'CREATE DATABASE authentik OWNER authentik ENCODING ''UTF8'' TEMPLATE template0'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'authentik') \gexec
REVOKE ALL ON DATABASE authentik FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE authentik TO authentik;
SQL
echo "authentik-db-init: database authentik and its role are ready."
