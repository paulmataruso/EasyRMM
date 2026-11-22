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
#   EASYRMM_E2E_DB         database name (default easyrmm_e2e)
#   EASYRMM_E2E_PUBLIC_URL public address (default https://rmm.localhost)
#   EASYRMM_E2E_INSECURE_COOKIES  true (default) for plain HTTP on loopback;
#                          false behind a TLS proxy
#
# Remote access is enabled but no MeshCentral runs: the console reports remote
# access as unavailable. The patching engine is a stand-in (bin/eptest-engine,
# eptest's server in a process of its own) on PORT+13, with the run's key; the
# tests add its endpoints and finish its jobs through its /__eptest/ calls.
#
# Playwright starts this script (web/playwright.config.ts) and stops it when the
# suite ends. It expects bin/easyrmm-server to be built with the web UI embedded,
# and bin/eptest-engine (make e2e builds them).
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
admin_url=${EASYRMM_E2E_ADMIN_URL:-postgres://postgres:easyrmm-test-only@127.0.0.1:55432/postgres?sslmode=disable}
run_dir=${EASYRMM_E2E_RUN_DIR:-$root/web/e2e/.run}
port=${EASYRMM_E2E_PORT:-18180}
db=${EASYRMM_E2E_DB:-easyrmm_e2e}
public_url=${EASYRMM_E2E_PUBLIC_URL:-https://rmm.localhost}
insecure_cookies=${EASYRMM_E2E_INSECURE_COOKIES:-true}
binary=$root/bin/easyrmm-server
engine=$root/bin/eptest-engine

[ -x "$binary" ] || { echo "start-server: $binary is missing; run make build (or make e2e)" >&2; exit 1; }
[ -x "$engine" ] || { echo "start-server: $engine is missing; run make e2e" >&2; exit 1; }

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
GRANT CONNECT ON DATABASE :"db" TO easyrmm_app;
\connect :"db"
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL

# The database host and port come from the admin URL.
hostport=$(printf '%s' "$admin_url" | sed -E 's#^[a-z]+://[^@]*@([^/?]+).*#\1#')

rm -rf "$run_dir"
mkdir -p "$run_dir/data" "$run_dir/meshcentral"
chmod 700 "$run_dir/data" "$run_dir/meshcentral"

patching_key=$(openssl rand -base64 32)
EASYRMM_PATCHING_KEY=$patching_key "$engine" -listen "127.0.0.1:$((port + 13))" &
engine_pid=$!
server_pid=
trap 'kill $server_pid $engine_pid 2>/dev/null' EXIT INT TERM

EASYRMM_PUBLIC_URL=$public_url \
EASYRMM_TLS_MODE=offload \
EASYRMM_TRUSTED_PROXIES=127.0.0.1/32 \
EASYRMM_LISTEN_OFFLOAD=127.0.0.1:$port \
EASYRMM_LISTEN_HEALTH=127.0.0.1:$((port + 11)) \
EASYRMM_DEV_INSECURE_COOKIES=$insecure_cookies \
EASYRMM_DATA_DIR=$run_dir/data \
EASYRMM_MESH_CONFIG_DIR=$run_dir/meshcentral \
EASYRMM_MESH_INTERNAL_URL=http://127.0.0.1:$((port + 12)) \
EASYRMM_AGENT_DIR=$root/bin/agents \
EASYRMM_DATABASE_URL="postgres://easyrmm_app:$app_pw@$hostport/$db?sslmode=disable" \
EASYRMM_DATABASE_MIGRATION_URL="postgres://easyrmm_owner:$owner_pw@$hostport/$db?sslmode=disable" \
EASYRMM_SECRET_KEY=$(openssl rand -base64 32) \
EASYRMM_PATCHING_KEY=$patching_key \
EASYRMM_PATCHING_URL=http://127.0.0.1:$((port + 13)) \
EASYRMM_LOG_LEVEL=warn \
"$binary" serve &
server_pid=$!
wait "$server_pid"
