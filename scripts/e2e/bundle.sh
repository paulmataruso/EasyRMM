#!/usr/bin/env bash
# The bundle test (make e2e-bundle; CI's "Bundle end to end" job; ADR-0043):
# EasyRMM with its patching engine, brought up from deploy/docker-compose.yml
# itself on host networking, as an IP-addressed install with EasyRMM's own
# certificate authority.
#
#  1. The deployment tree a release ships (scripts/release/deploy-tree.sh) is
#     set up with setup.sh, for https://127.0.0.1 and, by IP access, also
#     127.0.0.2, prepared again with
#     setup.sh --upgrade as a release's bundle runs it, and
#     brought up with images built from this checkout: EasyRMM's server, and
#     EasyPatch's server carrying Linux agent packages signed with a key made
#     for the run.
#  2. Nothing but the edge (:80, :443 and MeshCentral's :4443) listens beyond
#     loopback.
#  3. A Debian machine with systemd as init runs on the host's network, with
#     one package source: a local repository offering easyrmm-e2e-demo 1.1.0
#     over the installed 1.0.0 (scripts/e2e/bundle-host/).
#  4. Playwright (web/playwright.bundle.config.ts) makes the first account on
#     the first-run page, runs the console's install command on the machine,
#     installs the EasyPatch agent through EasyRMM, scans, and installs the
#     update; signed in on 127.0.0.2, it opens a terminal session, which runs
#     on that address's MeshCentral origin.
#  5. The engine on loopback refuses missing, forged, expired, replayed and
#     out-of-scope statements, and the edge does not reach its API
#     (server/internal/easypatch/bundle_test.go).
#  6. The updater's hold (ADR-0052): setup.sh --upgrade made its status
#     directory, root's with mode 755; the server and the engine's worker
#     mount it read-only and, as their own users, see the hold file; a
#     server started held is healthy for `docker compose up --wait` while
#     its edge answers 503, until the hold file goes.
#
# Needs Docker, Go, the .NET SDK (for the test agent packages), Playwright's
# Chromium (npx playwright install chromium in web/), root or sudo, and ports
# 80, 443 and 4443 free. Prebuilt images can be given with
# EASYRMM_BUNDLE_SERVER_IMAGE and EASYRMM_BUNDLE_ENGINE_IMAGE (the engine's
# must carry agent packages). Keys, passwords and tokens are made for the run
# and never printed; everything is removed afterwards, also on failure.
set -euo pipefail
# .NET's build servers (MSBuild nodes, the compiler server) outlive a build
# and keep every file descriptor the caller passed down open, such as a lock
# held around this test. This run starts none.
export MSBUILDDISABLENODEREUSE=1 DOTNET_CLI_USE_MSBUILD_SERVER=0 UseSharedCompilation=false

root=$(cd "$(dirname "$0")/../.." && pwd)
project=easyrmm-e2e-bundle
host=$project-linux
hostname=bundle-linux-01
public=https://127.0.0.1
# A second address of the server's (IP access, ADR-0016): a session started
# there runs on its own MeshCentral origin, https://127.0.0.2:4443.
second=https://127.0.0.2
server_image=${EASYRMM_BUNDLE_SERVER_IMAGE:-$project/easyrmm-server:local}
engine_image=${EASYRMM_BUNDLE_ENGINE_IMAGE:-$project/easypatch-server:local}
host_image=$project/linux:local
work=$(mktemp -d)
deploy=$work/easyrmm/deploy
up=false

as_root() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}
compose() {
  (cd "$deploy" && as_root docker compose -p "$project" "$@")
}

cleanup() {
  status=$?
  set +e
  if [ "$status" -ne 0 ]; then
    if [ "$up" = true ]; then
      compose ps -a >&2
      for service in server easypatch-api easypatch-worker easypatch-migrate meshcentral; do
        echo "--- $service log (last 60 lines) ---" >&2
        compose logs --no-color --tail 60 "$service" >&2
      done
    fi
    if docker inspect "$host" > /dev/null 2>&1; then
      for unit in easyrmm-agent easypatch-agent; do
        echo "--- $unit on the machine (last 60 lines) ---" >&2
        docker exec "$host" journalctl -u "$unit" --no-pager -n 60 >&2
      done
    fi
  fi
  docker rm -f -v "$host" > /dev/null 2>&1
  [ "$up" = true ] && compose down -v --remove-orphans > /dev/null 2>&1
  as_root rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

for tool in docker go curl openssl ss npx; do
  command -v "$tool" > /dev/null || { echo "$tool is required" >&2; exit 1; }
done
# The edge's ports and the loopback ports of the deployment's programs.
for port in 80 443 4443 15432 14430 18080 18081 18180 18181; do
  if (exec 3<> "/dev/tcp/127.0.0.1/$port") 2> /dev/null; then
    echo "127.0.0.1:$port is in use; the bundle test needs it" >&2
    exit 1
  fi
done
docker rm -f -v "$host" > /dev/null 2>&1 || true

# --- Images -------------------------------------------------------------------
if [ -z "${EASYRMM_BUNDLE_SERVER_IMAGE:-}" ]; then
  echo "Building EasyRMM's server image ..."
  docker build -q -f "$root/docker/server/Dockerfile" --build-arg VERSION=v0.0.0-bundle -t "$server_image" "$root" > /dev/null
fi
if [ -z "${EASYRMM_BUNDLE_ENGINE_IMAGE:-}" ]; then
  echo "Building EasyPatch's Linux agent packages, signed with a key made for this run ..."
  "$root/easypatch/scripts/build-test-agent-packages.sh" --arch x64 > "$work/packages.log" 2>&1 ||
    { tail -n 40 "$work/packages.log" >&2; exit 1; }
  echo "Building EasyPatch's server image with them ..."
  docker build -q -f "$root/easypatch/deployment/server/Dockerfile" -t "$engine_image" "$root/easypatch" > /dev/null
  "$root/easypatch/scripts/check-image-agent-packages.sh" "$engine_image" > /dev/null
fi
echo "Building the Linux machine ..."
docker build -q -t "$host_image" "$root/scripts/e2e/bundle-host" > /dev/null

# --- The deployment -----------------------------------------------------------
"$root/scripts/release/deploy-tree.sh" "$work/easyrmm"
(cd "$deploy" && as_root ./scripts/setup.sh --hostname 127.0.0.1 --ip-addresses "127.0.0.1,${second#https://}" \
  --data-root "$work/data" > /dev/null)
# setup.sh --upgrade, as a release's bundle runs it: every setting from .env
# (here the data root, which is not the default), and the server version the
# bundle's .env.example names.
srv_before=$(test -e /srv/easyrmm && echo yes || echo no)
as_root sed -i 's/^EASYRMM_VERSION=.*/EASYRMM_VERSION=9.9.9-bundle-test/' "$deploy/.env.example"
as_root rm -rf "$work/data/meshcentral/backups" "$work/data/updater"
(cd "$deploy" && as_root ./scripts/setup.sh --upgrade > /dev/null < /dev/null)
as_root grep -qx 'EASYRMM_VERSION=9.9.9-bundle-test' "$deploy/.env" ||
  { echo "setup.sh --upgrade did not set the bundle's server version" >&2; exit 1; }
[ "$(as_root stat -c '%u %a' "$work/data/meshcentral/backups")" = "65532 700" ] ||
  { echo "setup.sh --upgrade did not make the data directories under .env's data root" >&2; exit 1; }
[ "$srv_before" = yes ] || ! test -e /srv/easyrmm ||
  { echo "setup.sh --upgrade made directories under the default data root" >&2; exit 1; }
as_root sed -i \
  -e "s|^EASYRMM_IMAGE=.*|EASYRMM_IMAGE=${server_image%:*}|" -e "s|^EASYRMM_VERSION=.*|EASYRMM_VERSION=${server_image##*:}|" \
  -e "s|^EASYPATCH_IMAGE=.*|EASYPATCH_IMAGE=${engine_image%:*}|" -e "s|^EASYPATCH_VERSION=.*|EASYPATCH_VERSION=${engine_image##*:}|" \
  "$deploy/.env"

ss -ltnH | awk '{print $4}' | sort -u > "$work/listening.before"
echo "Starting the deployment (docker compose, project $project) ..."
up=true
compose up -d --no-build --quiet-pull
for _ in $(seq 1 150); do
  if curl -fsS http://127.0.0.1:18081/readyz > /dev/null 2>&1 &&
    curl -fsS http://127.0.0.1:18180/health/ready > /dev/null 2>&1 &&
    curl -fsSk "$public/api/v1/auth/session" -o /dev/null -w '%{http_code}' 2> /dev/null | grep -q '^[24]'; then
    break
  fi
  sleep 2
done
curl -fsS http://127.0.0.1:18081/readyz > /dev/null || { echo "EasyRMM did not become ready" >&2; exit 1; }
curl -fsS http://127.0.0.1:18180/health/ready > /dev/null || { echo "the patching engine did not become ready" >&2; exit 1; }

# --- Only the edge beyond loopback ---------------------------------------------
sleep 5
ss -ltnH | awk '{print $4}' | sort -u > "$work/listening.after"
outside=$(comm -13 "$work/listening.before" "$work/listening.after" | grep -Ev '^(127\.[0-9.]+|\[::1\]|\[::ffff:127\.[0-9.]+\]):[0-9]+$' |
  grep -Ev ':(80|443|4443)$' || true)
if [ -n "$outside" ]; then
  printf "Listening beyond loopback, other than the edge:\n%s\n" "$outside" >&2
  exit 1
fi
echo "Beyond loopback, only the edge listens: $(comm -13 "$work/listening.before" "$work/listening.after" |
  grep -Ev '^(127\.[0-9.]+|\[::1\]):' | tr '\n' ' ')"

# The server's certificate, by its public key, for the browser and the gateway test.
spki=$(openssl s_client -connect 127.0.0.1:443 < /dev/null 2> /dev/null | openssl x509 -pubkey -noout |
  openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)
[ -n "$spki" ] || { echo "could not read the server's certificate" >&2; exit 1; }

# --- The Linux machine ----------------------------------------------------------
docker run -d --name "$host" --hostname "$hostname" --network host --privileged --cgroupns=private \
  --tmpfs /run --tmpfs /run/lock "$host_image" > /dev/null
for _ in $(seq 1 60); do
  state=$(docker exec "$host" systemctl is-system-running 2> /dev/null || true)
  case $state in running | degraded) break ;; esac
  sleep 1
done
case $state in running | degraded) ;; *)
  echo "systemd did not start on the machine ($state)" >&2
  exit 1
  ;;
esac

# --- The story ------------------------------------------------------------------
setup_token=$(as_root cat "$work/data/server/setup-token")
echo "Running the story in a browser ..."
(cd "$root/web" && EASYRMM_BUNDLE_URL=$public EASYRMM_BUNDLE_SECOND_URL=$second EASYRMM_BUNDLE_SPKI=$spki \
  EASYRMM_BUNDLE_SETUP_TOKEN=$setup_token EASYRMM_BUNDLE_HOST=$host EASYRMM_BUNDLE_HOSTNAME=$hostname \
  npx playwright test -c playwright.bundle.config.ts)

# --- The gateway ----------------------------------------------------------------
echo "Checking the engine's refusals ..."
key=$(as_root sed -n 's/^EASYRMM_PATCHING_KEY=//p' "$deploy/.env")
(cd "$root" && EASYRMM_BUNDLE_ENGINE_URL=http://127.0.0.1:18180 EASYRMM_BUNDLE_ENGINE_KEY=$key EASYRMM_BUNDLE_URL=$public \
  EASYRMM_BUNDLE_SPKI=$spki go test -tags bundle -count=1 -run TestBundleGateway ./server/internal/easypatch/)

# --- The updater's hold -----------------------------------------------------------
echo "Checking the updater's hold ..."
status=$work/data/updater/status
[ "$(as_root stat -c '%U %a' "$status")" = "root 755" ] ||
  { echo "setup.sh --upgrade did not make $status root's, mode 755" >&2; exit 1; }
for service in server easypatch-worker; do
  mount=$(as_root docker inspect -f '{{range .Mounts}}{{if eq .Destination "/run/easyrmm-updater"}}{{.Source}} {{.RW}}{{end}}{{end}}' \
    "$(compose ps -q "$service")")
  [ "$mount" = "$status false" ] ||
    { echo "$service mounts the updater's status as '$mount', want '$status false'" >&2; exit 1; }
done
# answer URL: the status code, and whether Retry-After came with it.
answer() {
  rm -f "$work/headers"
  curl -sk -o /dev/null -D "$work/headers" -w '%{http_code}' "$1" || true
  if grep -qi '^retry-after:' "$work/headers" 2> /dev/null; then printf ' retry-after'; fi
}
as_root touch "$status/hold"
compose up -d --no-deps --force-recreate --wait --wait-timeout 300 server > /dev/null
# The server, as its own user, sees the file through its mount, and so does
# the engine's worker.
[ "$(as_root docker top "$(compose ps -q server)" -eo pid,uid | awk 'NR > 1 { print $2 }' | sort -u | paste -sd ' ' -)" = 65532 ] ||
  { echo "the server does not run as 65532" >&2; exit 1; }
[ "$(curl -fsS http://127.0.0.1:18081/readyz)" = "ready, held by the updater" ] ||
  { echo "the server started held does not say so" >&2; exit 1; }
[ "$(compose exec -T easypatch-worker sh -c 'id -u && ls /run/easyrmm-updater' | paste -sd ' ' -)" = "1654 hold" ] ||
  { echo "the engine's worker, as 1654, does not see the hold file through its mount" >&2; exit 1; }
for url in "$public/api/v1/health" "$public/" "https://127.0.0.1:4443/" "http://127.0.0.1/"; do
  got=$(answer "$url")
  [ "$got" = "503 retry-after" ] || { echo "$url while held: $got, want 503 with Retry-After" >&2; exit 1; }
done
as_root rm "$status/hold"
for _ in $(seq 1 20); do
  [ "$(answer "$public/api/v1/health")" = 200 ] && break
  sleep 1
done
[ "$(answer "$public/api/v1/health")" = 200 ] || { echo "the server still answers 503 after the hold" >&2; exit 1; }
echo "The hold: held from its start and healthy, every listener 503 with Retry-After, then served again."
echo "The bundle test passed."
