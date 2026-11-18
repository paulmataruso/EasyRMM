#!/bin/sh
# Starts a throwaway EasyRMM server for the browser end-to-end tests.
#
# Each run gets a fresh database, fresh role passwords, a fresh secret key and
# an empty data directory, so the suite always begins at first-run setup.
# Nothing here is used outside tests; the credentials die with the run.
#
#   EASYRMM_E2E_ADMIN_URL  superuser URL of a disposable PostgreSQL (make test-db)
#   EASYRMM_E2E_RUN_DIR    where to keep the data directory (default web/e2e/.run)
#   EASYRMM_E2E_PORT       offload listener (default 18180); health is PORT+11
#
# Remote access is enabled but no MeshCentral runs: the console shows devices
# and reports remote access as unavailable.
#
# Playwright starts this script (web/playwright.config.ts) and stops it when the
# suite ends. It expects bin/easyrmm-server to be built with the web UI embedded
# (make e2e does both).
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
admin_url=${EASYRMM_E2E_ADMIN_URL:-postgres://postgres:easyrmm-test-only@127.0.0.1:55432/postgres?sslmode=disable}
run_dir=${EASYRMM_E2E_RUN_DIR:-$root/web/e2e/.run}
port=${EASYRMM_E2E_PORT:-18180}
db=easyrmm_e2e
binary=$root/bin/easyrmm-server

[ -x "$binary" ] || { echo "start-server: $binary is missing; run make build (or make e2e)" >&2; exit 1; }

owner_pw=$(openssl rand -hex 24)
app_pw=$(openssl rand -hex 24)

# Roles are cluster-wide and may exist from earlier runs; their passwords are reset every time.
psql "$admin_url" -v ON_ERROR_STOP=1 -q -v owner_pw="$owner_pw" -v app_pw="$app_pw" -v db="$db" <<'SQL'
SET password_encryption = 'scram-sha-256';
SELECT format('CREATE ROLE easyrmm_owner LOGIN') WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'easyrmm_owner') \gexec
SELECT format('CREATE ROLE easyrmm_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS') WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'easyrmm_app') \gexec
ALTER ROLE easyrmm_owner PASSWORD :'owner_pw';
ALTER ROLE easyrmm_app PASSWORD :'app_pw';
DROP DATABASE IF EXISTS :"db" WITH (FORCE);
CREATE DATABASE :"db" OWNER easyrmm_owner ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO easyrmm_app;
\connect :"db"
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL

# The database host and port come from the admin URL.
hostport=$(printf '%s' "$admin_url" | sed -E 's#^[a-z]+://[^@]*@([^/?]+).*#\1#')

rm -rf "$run_dir"
mkdir -p "$run_dir/data" "$run_dir/meshcentral"
chmod 700 "$run_dir/data" "$run_dir/meshcentral"

EASYRMM_PUBLIC_URL=https://rmm.localhost \
EASYRMM_TLS_MODE=offload \
EASYRMM_TRUSTED_PROXIES=127.0.0.1/32 \
EASYRMM_LISTEN_OFFLOAD=127.0.0.1:$port \
EASYRMM_LISTEN_HEALTH=127.0.0.1:$((port + 11)) \
EASYRMM_DEV_INSECURE_COOKIES=true \
EASYRMM_DATA_DIR=$run_dir/data \
EASYRMM_MESH_CONFIG_DIR=$run_dir/meshcentral \
EASYRMM_MESH_INTERNAL_URL=http://127.0.0.1:$((port + 12)) \
EASYRMM_AGENT_DIR=$root/bin/agents \
EASYRMM_DATABASE_URL="postgres://easyrmm_app:$app_pw@$hostport/$db?sslmode=disable" \
EASYRMM_DATABASE_MIGRATION_URL="postgres://easyrmm_owner:$owner_pw@$hostport/$db?sslmode=disable" \
EASYRMM_SECRET_KEY=$(openssl rand -base64 32) \
EASYRMM_LOG_LEVEL=warn \
exec "$binary" serve
