#!/usr/bin/env bash
# Runs EasyRMM's EasyPatch contract tests against a real EasyPatch server
# built from this commit's easypatch/ directory (make test-contract; CI's
# "EasyPatch contract" job), or against a release's (CI's "EasyPatch
# contract, last release's engine": edge builds run it, ADR-0052).
#
# 1. Builds EasyPatch's server image, or uses EASYPATCH_CONTRACT_IMAGE, whose
#    version EASYPATCH_CONTRACT_VERSION gives.
# 2. Starts PostgreSQL and the API, both on the host network and listening
#    on 127.0.0.1 only. The API serves plain HTTP with a gateway key, as the
#    patching engine in EasyRMM's deployment does (ADR-0038): EasyRMM's
#    calls, each with a statement signed with that key. It also serves TLS
#    with a certificate made for this run, as the engine's public address,
#    which the simulated agents enroll and check in at.
# 3. Runs the contract tests (Go build tag "contract").
#
# Everything is removed afterwards. The database password, the TLS key and
# the gateway key are made for the run and are never printed.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
image=${EASYPATCH_CONTRACT_IMAGE:-easyrmm-contract/easypatch-server:local}
# The PostgreSQL image EasyRMM's deployment runs, the engine's database
# with it: the first in deploy/docker-compose.yml.
pg_image=$(sed -n 's/^ *image: \(postgres:[^ ]*\)$/\1/p' "$root/deploy/docker-compose.yml" | head -n1)
pg_port=${EASYPATCH_CONTRACT_PG_PORT:-55433}
api_port=${EASYPATCH_CONTRACT_PORT:-18443}
engine_port=${EASYPATCH_CONTRACT_ENGINE_PORT:-18444}
if [ -n "${EASYPATCH_CONTRACT_IMAGE:-}" ]; then
  version=${EASYPATCH_CONTRACT_VERSION:?the version of EASYPATCH_CONTRACT_IMAGE}
else
  version=$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$root/easypatch/Directory.Build.props" | head -n1)
fi
name=easyrmm-contract
work=$(mktemp -d)

cleanup() {
  status=$?
  if [ "$status" -ne 0 ] && docker inspect "$name-api" >/dev/null 2>&1; then
    echo "--- EasyPatch API log (last 60 lines) ---" >&2
    docker logs --tail 60 "$name-api" >&2 || true
  fi
  docker rm -f -v "$name-api" "$name-postgres" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

[ -n "$pg_image" ] || { echo "no postgres image in deploy/docker-compose.yml" >&2; exit 1; }
for port in "$pg_port" "$api_port" "$engine_port"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "127.0.0.1:$port is in use; set EASYPATCH_CONTRACT_PG_PORT, EASYPATCH_CONTRACT_PORT or EASYPATCH_CONTRACT_ENGINE_PORT" >&2
    exit 1
  fi
done
docker rm -f -v "$name-api" "$name-postgres" >/dev/null 2>&1 || true

if [ -z "${EASYPATCH_CONTRACT_IMAGE:-}" ]; then
  echo "Building EasyPatch's server image from easypatch/ ..."
  docker build -q -f "$root/easypatch/deployment/server/Dockerfile" -t "$image" "$root/easypatch" >/dev/null
fi

# A database password and a TLS certificate for this run. The containers
# run as other users, so the files are world-readable inside $work (0700).
umask 077
head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' >"$work/db_password"
gateway_key=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
mkdir "$work/tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj "/CN=EasyRMM contract test CA" \
  -keyout "$work/tls/ca.key" -out "$work/tls/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=127.0.0.1" \
  -keyout "$work/tls/tls.key" -out "$work/tls/tls.csr" 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' >"$work/tls/ext"
openssl x509 -req -in "$work/tls/tls.csr" -CA "$work/tls/ca.pem" -CAkey "$work/tls/ca.key" -CAcreateserial -days 1 \
  -extfile "$work/tls/ext" -out "$work/tls/tls.pem" 2>/dev/null
chmod 0644 "$work/db_password" "$work/tls/tls.key" "$work/tls/tls.pem"
chmod 0755 "$work/tls"

echo "Starting PostgreSQL ($pg_image) on 127.0.0.1:$pg_port ..."
docker run -d --name "$name-postgres" --network host \
  -e POSTGRES_USER=easypatch -e POSTGRES_DB=easypatch -e POSTGRES_PASSWORD_FILE=/run/secrets/db_password -e PGPORT="$pg_port" \
  -v "$work/db_password:/run/secrets/db_password:ro" \
  "$pg_image" -c listen_addresses=127.0.0.1 >/dev/null
for _ in $(seq 60); do
  docker exec "$name-postgres" pg_isready -q -h 127.0.0.1 -p "$pg_port" -U easypatch && break
  sleep 1
done
docker exec "$name-postgres" pg_isready -q -h 127.0.0.1 -p "$pg_port" -U easypatch

server_env=(
  -e ASPNETCORE_ENVIRONMENT=Production
  -e Database__Host=127.0.0.1 -e Database__Port="$pg_port" -e Database__Name=easypatch -e Database__User=easypatch
  -e Database__PasswordFile=/run/secrets/db_password
  -e EasyPatch__PublicUrl="https://127.0.0.1:$api_port"
  -v "$work/db_password:/run/secrets/db_password:ro"
)
easypatch() { docker run --rm --network host "${server_env[@]}" "$image" "$@"; }

echo "Migrating the database ..."
easypatch migrate >/dev/null

echo "Starting EasyPatch $version on https://127.0.0.1:$api_port and http://127.0.0.1:$engine_port ..."
docker run -d --name "$name-api" --network host "${server_env[@]}" \
  -e ASPNETCORE_HTTP_PORTS= -e ASPNETCORE_URLS="https://127.0.0.1:$api_port;http://127.0.0.1:$engine_port" \
  -e EasyRmm__GatewayKey="$gateway_key" \
  -e Kestrel__Certificates__Default__Path=/tls/tls.pem -e Kestrel__Certificates__Default__KeyPath=/tls/tls.key \
  -v "$work/tls/tls.pem:/tls/tls.pem:ro" -v "$work/tls/tls.key:/tls/tls.key:ro" \
  "$image" >/dev/null
for _ in $(seq 90); do
  curl -fsS -o /dev/null --cacert "$work/tls/ca.pem" "https://127.0.0.1:$api_port/health/ready" && break
  sleep 1
done
curl -fsS -o /dev/null --cacert "$work/tls/ca.pem" "https://127.0.0.1:$api_port/health/ready"

echo "Running the contract tests ..."
cd "$root"
EASYRMM_CONTRACT_EASYPATCH_URL="https://127.0.0.1:$api_port" \
EASYRMM_CONTRACT_EASYPATCH_CA="$work/tls/ca.pem" \
EASYRMM_CONTRACT_EASYPATCH_VERSION="$version" \
EASYRMM_CONTRACT_ENGINE_URL="http://127.0.0.1:$engine_port" \
EASYRMM_CONTRACT_ENGINE_KEY="$gateway_key" \
  ${GO:-go} test -count=1 -tags contract -run '^TestContract$' -v ./server/internal/easypatch/
