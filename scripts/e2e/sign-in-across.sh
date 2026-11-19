#!/usr/bin/env bash
# Signing in once across EasyRMM and EasyPatch, end to end in a browser
# (make e2e-sign-in; CI's "Sign in across the consoles" job). The integration
# plan's P4 test: both consoles over TLS on different registrable domains,
#
#   https://rmm.easyrmm.localhost:28443      EasyRMM, bin/easyrmm-server
#   https://patch.easypatch.localhost:29443  EasyPatch, built from easypatch/
#
# so EasyRMM's SameSite=Strict session cookie never crosses between them, as
# in production with two domains.
#
# * *.localhost names resolve to loopback (RFC 6761) in Chromium, Go, glibc
#   and systemd-resolved, so nothing is added to /etc/hosts. EasyPatch's api
#   container (musl) also gets an --add-host entry.
# * One Caddy terminates TLS for both, with a certificate made for this run:
#   EasyPatch's own proxy image and site configuration (headers, CSP, the
#   console), pointed at the api on loopback; EasyRMM behind a plain
#   reverse_proxy, in EasyRMM's offload mode.
# * EasyPatch's api trusts the run's CA through SSL_CERT_FILE, the way the
#   co-hosting guide has administrators trust a private CA. EasyRMM trusts it
#   through Settings → EasyPatch → CA certificate. Chromium accepts the
#   run's certificate by its key (--ignore-certificate-errors-spki-list).
#
# EasyPatch's super administrator and an operator API token are made with
# EasyPatch's CLI. Playwright (web/playwright.sign-in.config.ts) then sets up
# EasyRMM and connects it to EasyPatch, sets up sign-in on both sides, and
# switches between the consoles.
#
# Needs Docker, a PostgreSQL for EasyRMM (make test-db), bin/easyrmm-server
# built with the console, and Playwright's Chromium. Everything is removed
# afterwards; passwords, keys and tokens are made for the run and never
# printed.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
name=easyrmm-signin
rmm_host=rmm.easyrmm.localhost
ep_host=patch.easypatch.localhost
rmm_port=${EASYRMM_SIGNIN_RMM_PORT:-28443}
ep_port=${EASYRMM_SIGNIN_EASYPATCH_PORT:-29443}
rmm_upstream=${EASYRMM_SIGNIN_UPSTREAM_PORT:-28180} # EasyRMM's offload listener; health is +11
ep_api=${EASYRMM_SIGNIN_API_PORT:-28181}
pg_port=${EASYRMM_SIGNIN_PG_PORT:-55434}
server_image=${EASYPATCH_SERVER_IMAGE:-easyrmm-signin/easypatch-server:local}
proxy_image=${EASYPATCH_PROXY_IMAGE:-easyrmm-signin/easypatch-proxy:local}
pg_image=$(sed -n 's/^ *image: \(postgres:[^ ]*\)$/\1/p' "$root/easypatch/docker-compose.yml" | head -n1)
work=$(mktemp -d)
rmm_pid=

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    for c in api proxy; do
      if docker inspect "$name-$c" >/dev/null 2>&1; then
        echo "--- $name-$c log (last 40 lines) ---" >&2
        docker logs --tail 40 "$name-$c" >&2 || true
      fi
    done
  fi
  [ -n "$rmm_pid" ] && kill "$rmm_pid" 2>/dev/null && wait "$rmm_pid" 2>/dev/null
  docker rm -f -v "$name-api" "$name-postgres" "$name-proxy" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

[ -n "$pg_image" ] || { echo "no postgres image in easypatch/docker-compose.yml" >&2; exit 1; }
[ -x "$root/bin/easyrmm-server" ] || { echo "bin/easyrmm-server is missing; run make build (make e2e-sign-in does)" >&2; exit 1; }
for port in "$rmm_port" "$ep_port" "$rmm_upstream" "$((rmm_upstream + 11))" "$ep_api" "$pg_port"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "127.0.0.1:$port is in use; see the EASYRMM_SIGNIN_*_PORT settings at the top of $0" >&2
    exit 1
  fi
done
docker rm -f -v "$name-api" "$name-postgres" "$name-proxy" >/dev/null 2>&1 || true

if [ -z "${EASYPATCH_SERVER_IMAGE:-}" ]; then
  echo "Building EasyPatch's server image from easypatch/ ..."
  docker build -q -f "$root/easypatch/deployment/server/Dockerfile" -t "$server_image" "$root/easypatch" >/dev/null
fi
if [ -z "${EASYPATCH_PROXY_IMAGE:-}" ]; then
  echo "Building EasyPatch's proxy image (Caddy and the console) from easypatch/ ..."
  docker build -q -f "$root/easypatch/deployment/caddy/Dockerfile" -t "$proxy_image" "$root/easypatch" >/dev/null
fi

# A CA and one certificate for both names. The containers run as other
# users, so the files are world-readable inside $work (0700).
umask 077
mkdir "$work/tls" "$work/secrets"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj "/CN=EasyRMM sign-in test CA" \
  -keyout "$work/tls/ca.key" -out "$work/tls/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$rmm_host" \
  -keyout "$work/tls/tls.key" -out "$work/tls/tls.csr" 2>/dev/null
printf 'subjectAltName=DNS:%s,DNS:%s\nextendedKeyUsage=serverAuth\n' "$rmm_host" "$ep_host" >"$work/tls/ext"
openssl x509 -req -in "$work/tls/tls.csr" -CA "$work/tls/ca.pem" -CAkey "$work/tls/ca.key" -CAcreateserial -days 1 \
  -extfile "$work/tls/ext" -out "$work/tls/tls.pem" 2>/dev/null
spki=$(openssl x509 -in "$work/tls/tls.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)
head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' >"$work/secrets/db_password"
printf '%s-Aa1\n' "$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')" >"$work/secrets/easypatch_admin_password"
chmod 0755 "$work/tls" "$work/secrets"
chmod 0644 "$work/tls/ca.pem" "$work/tls/tls.pem" "$work/tls/tls.key" "$work/secrets/db_password"

echo "Starting EasyPatch's PostgreSQL ($pg_image) on 127.0.0.1:$pg_port ..."
docker run -d --name "$name-postgres" --network host \
  -e POSTGRES_USER=easypatch -e POSTGRES_DB=easypatch -e POSTGRES_PASSWORD_FILE=/run/secrets/db_password -e PGPORT="$pg_port" \
  -v "$work/secrets/db_password:/run/secrets/db_password:ro" \
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
  -e EasyPatch__PublicUrl="https://$ep_host:$ep_port"
  -e ForwardedHeaders__KnownNetworks=127.0.0.0/8
  # EasyRMM's certificate comes from the run's CA (co-hosting guide: trusting a private CA).
  -e SSL_CERT_FILE=/tls/ca.pem
  --add-host "$rmm_host:127.0.0.1"
  -v "$work/secrets/db_password:/run/secrets/db_password:ro"
  -v "$work/tls/ca.pem:/tls/ca.pem:ro"
)
easypatch() { docker run --rm -i --network host "${server_env[@]}" "$server_image" "$@"; }

echo "Migrating EasyPatch's database ..."
easypatch migrate >/dev/null

echo "Starting EasyPatch's api on 127.0.0.1:$ep_api ..."
docker run -d --name "$name-api" --network host "${server_env[@]}" \
  -e ASPNETCORE_HTTP_PORTS= -e ASPNETCORE_URLS="http://127.0.0.1:$ep_api" \
  "$server_image" >/dev/null

easypatch create-admin --email patch-admin@example.com --name patch-admin --password-stdin \
  <"$work/secrets/easypatch_admin_password" >/dev/null
easypatch create-api-token --name EasyRMM --role operator --expires-days 1 |
  sed -n 's/^Token (shown once, only its hash is stored): //p' >"$work/secrets/easypatch_token"
[ -s "$work/secrets/easypatch_token" ] || { echo "create-api-token printed no token" >&2; exit 1; }

# EasyPatch's site configuration, as its proxy image ships it, with the api on loopback.
sed "s/reverse_proxy api:8080/reverse_proxy 127.0.0.1:$ep_api/" "$root/easypatch/deployment/caddy/easypatch.caddy" >"$work/easypatch.caddy"
grep -q "reverse_proxy 127.0.0.1:$ep_api" "$work/easypatch.caddy" || { echo "EasyPatch's Caddy site no longer proxies api:8080" >&2; exit 1; }
cat >"$work/Caddyfile" <<EOF
{
	admin off
	auto_https disable_redirects
	default_bind 127.0.0.1 [::1]
}

import /etc/caddy/easypatch.caddy

https://$ep_host:$ep_port {
	tls /tls/tls.pem /tls/tls.key
	import easypatch
}

https://$rmm_host:$rmm_port {
	tls /tls/tls.pem /tls/tls.key
	reverse_proxy 127.0.0.1:$rmm_upstream
}
EOF
chmod 0644 "$work/easypatch.caddy" "$work/Caddyfile"

echo "Starting Caddy on $rmm_host:$rmm_port and $ep_host:$ep_port ..."
docker run -d --name "$name-proxy" --network host \
  -v "$work/Caddyfile:/etc/caddy/Caddyfile:ro" -v "$work/easypatch.caddy:/etc/caddy/easypatch.caddy:ro" \
  -v "$work/tls/tls.pem:/tls/tls.pem:ro" -v "$work/tls/tls.key:/tls/tls.key:ro" \
  "$proxy_image" >/dev/null

echo "Starting EasyRMM behind it ..."
# Signing in across the two products is the connector's (ADR-0036), which
# phase R removes with this test.
EASYRMM_PATCHING=connector \
EASYRMM_E2E_PORT=$rmm_upstream \
EASYRMM_E2E_DB=easyrmm_signin \
EASYRMM_E2E_PUBLIC_URL="https://$rmm_host:$rmm_port" \
EASYRMM_E2E_INSECURE_COOKIES=false \
EASYRMM_E2E_RUN_DIR="$work/easyrmm" \
  "$root/scripts/e2e/start-server.sh" &
rmm_pid=$!

ready() { curl -fsS -o /dev/null --cacert "$work/tls/ca.pem" --resolve "$1:$2:127.0.0.1" "https://$1:$2$3"; }
rmm_ready() { curl -fsS -o /dev/null "http://127.0.0.1:$((rmm_upstream + 11))/readyz"; }
for _ in $(seq 90); do
  ready "$ep_host" "$ep_port" /health/ready && rmm_ready && break
  sleep 1
done
ready "$ep_host" "$ep_port" /health/ready
rmm_ready
ready "$rmm_host" "$rmm_port" / # the console, through the proxy

echo "Running the browser test ..."
cd "$root/web"
EASYRMM_SIGNIN_RMM_URL="https://$rmm_host:$rmm_port" \
EASYRMM_SIGNIN_EASYPATCH_URL="https://$ep_host:$ep_port" \
EASYRMM_SIGNIN_SPKI="$spki" \
EASYRMM_SIGNIN_CA="$work/tls/ca.pem" \
EASYRMM_SIGNIN_SETUP_TOKEN="$work/easyrmm/data/setup-token" \
EASYRMM_SIGNIN_EASYPATCH_ADMIN_PASSWORD="$work/secrets/easypatch_admin_password" \
EASYRMM_SIGNIN_EASYPATCH_TOKEN="$work/secrets/easypatch_token" \
  npx playwright test -c playwright.sign-in.config.ts "$@"
