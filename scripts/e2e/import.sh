#!/usr/bin/env bash
# The import test (make e2e-import; CI's "Bundle end to end" job), the
# one-product plan's S4 check: a standalone EasyPatch 1.10 server, with a
# real agent, imported into an EasyRMM deployment with
# deploy/scripts/import-easypatch.sh (ADR-0045).
#
#  1. EasyPatch 1.10.0 is built from its release commit: its server image,
#     and its Linux agent package, signed with a key made for the run. It
#     runs as a standalone server would (PostgreSQL, the API, and Caddy with
#     its site configuration in front) at https://patch.import.test, with a
#     certificate from a CA made for the run, on host networking.
#  2. Its first administrator, made with its CLI, signs in through its
#     console API and enrolls an authenticator; then makes organizations
#     (two whose names differ only in case, one archived), sites, a webhook
#     and an enrollment token (TestImportSeedEasyPatch).
#  3. A Debian machine with systemd, trusting the run's CA, installs the
#     1.10 agent and enrolls it with that token.
#  4. The server is backed up as its scripts/backup.sh does, and stopped.
#  5. EasyRMM's deployment tree (scripts/release/deploy-tree.sh) is set up
#     for https://rmm.import.test with a certificate that also names
#     patch.import.test (the old name's DNS now points here), brought up,
#     and the backup imported with deploy/scripts/import-easypatch.sh.
#  6. EasyRMM has the organizations and sites, case collisions named; the
#     old server's accounts are disabled; the old name answers agents and
#     sends people to EasyRMM's console; the agent checks in and scans
#     through EasyRMM's edge; the old server's webhook decrypts with its
#     keys; the engine takes EasyRMM's names (TestImportedEngine).
#
# Needs Docker, Go, the .NET SDK, root or sudo, git history with EasyPatch
# 1.10.0's commit (fetched if missing), and ports 80, 443 and 4443 free.
# Prebuilt EasyRMM images can be given with EASYRMM_IMPORT_SERVER_IMAGE and
# EASYRMM_IMPORT_ENGINE_IMAGE (CI passes the bundle test's). Keys, passwords
# and tokens are made for the run and never printed; everything is removed
# afterwards, also on failure.
set -euo pipefail
# .NET's build servers (MSBuild nodes, the compiler server) outlive a build
# and keep every file descriptor the caller passed down open, such as a lock
# held around this test. This run starts none.
export MSBUILDDISABLENODEREUSE=1 DOTNET_CLI_USE_MSBUILD_SERVER=0 UseSharedCompilation=false

root=$(cd "$(dirname "$0")/../.." && pwd)
project=easyrmm-e2e-import
old_commit=9ac6d3cd072638f76eae7f8886da622b9e3c7d9c # easypatch-v1.10.0
old_version=1.10.0
old_name=patch.import.test
rmm_name=rmm.import.test
host=$project-linux
hostname=import-linux-01
server_image=${EASYRMM_IMPORT_SERVER_IMAGE:-$project/easyrmm-server:local}
engine_image=${EASYRMM_IMPORT_ENGINE_IMAGE:-$project/easypatch-server:local}
old_image=$project/easypatch-server:$old_version
host_image=$project/linux:local
pg_image=$(sed -n 's/^ *image: \(postgres:[^ ]*\)$/\1/p' "$root/deploy/docker-compose.yml" | head -n1)
work=$(mktemp -d)
deploy=$work/easyrmm/deploy
up=false

as_root() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}
compose() {
  (cd "$deploy" && as_root docker compose -p "$project" "$@")
}
old_psql() {
  docker exec "$project-old-db" psql -p 25432 -U easypatch -d easypatch -X -tA -v ON_ERROR_STOP=1 -c "$1"
}

cleanup() {
  status=$?
  set +e
  if [ "$status" -ne 0 ]; then
    for c in "$project-old-api" "$project-old-proxy"; do
      docker inspect "$c" > /dev/null 2>&1 && { echo "--- $c (last 15 lines) ---" >&2; docker logs --tail 15 "$c" >&2 2>&1; }
    done
    if [ "$up" = true ]; then
      compose ps -a >&2
      for service in server easypatch-api easypatch-worker easypatch-migrate; do
        echo "--- $service log (last 60 lines) ---" >&2
        compose logs --no-color --tail 60 "$service" >&2
      done
    fi
    if docker inspect "$host" > /dev/null 2>&1; then
      echo "--- easypatch-agent on the machine (last 60 lines) ---" >&2
      docker exec "$host" journalctl -u easypatch-agent --no-pager -n 60 >&2
    fi
  fi
  docker rm -f -v "$host" "$project-old-db" "$project-old-api" "$project-old-proxy" > /dev/null 2>&1
  [ "$up" = true ] && compose down -v --remove-orphans > /dev/null 2>&1
  as_root rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

for tool in docker go curl openssl dotnet git; do
  command -v "$tool" > /dev/null || { echo "$tool is required" >&2; exit 1; }
done
for port in 80 443 4443 15432 14430 18080 18081 18180 18181 25432 28180; do
  if (exec 3<> "/dev/tcp/127.0.0.1/$port") 2> /dev/null; then
    echo "127.0.0.1:$port is in use; the import test needs it" >&2
    exit 1
  fi
done
docker rm -f -v "$host" "$project-old-db" "$project-old-api" "$project-old-proxy" > /dev/null 2>&1 || true
umask 077
secret() { openssl rand -hex 24; }

# --- EasyPatch 1.10.0 ------------------------------------------------------------
git -C "$root" cat-file -e "$old_commit^{commit}" 2> /dev/null ||
  git -C "$root" fetch -q --depth 1 origin "$old_commit"
mkdir -p "$work/old"
git -C "$root" archive "$old_commit" | tar -x -C "$work/old"
grep -q "version=\"$old_version\"" "$work/old/scripts/build-linux-packages.sh" ||
  { echo "$old_commit is not EasyPatch $old_version" >&2; exit 1; }
caddy_image=$(sed -n 's/^FROM \(caddy:[^ ]*\)$/\1/p' "$work/old/deployment/caddy/Dockerfile")

echo "Building EasyPatch $old_version's Linux agent package, signed with a key made for this run ..."
(cd "$work/old" && dotnet run --project tools/EasyPatch.ReleaseSigner -c Release -- generate-key --out "$work/old-release-key.pem" \
  > "$work/old-agent.log" 2>&1 &&
  EASYPATCH_RELEASE_KEY="$work/old-release-key.pem" EASYPATCH_RELEASE_PUBLIC_KEY="$work/old-release-key.pub.pem" \
    scripts/build-linux-packages.sh --version "$old_version" --arch x64 --no-test >> "$work/old-agent.log" 2>&1) ||
  { tail -n 40 "$work/old-agent.log" >&2; exit 1; }
rm -f "$work/old-release-key.pem"
old_deb="$work/old/artifacts/linux/EasyPatchAgent-$old_version-x64.deb"
[ -f "$old_deb" ] || { echo "no $old_deb" >&2; exit 1; }
echo "Building EasyPatch $old_version's server image ..."
docker build -q -f "$work/old/deployment/server/Dockerfile" -t "$old_image" "$work/old" > /dev/null

# --- EasyRMM ----------------------------------------------------------------------
if [ -z "${EASYRMM_IMPORT_SERVER_IMAGE:-}" ]; then
  echo "Building EasyRMM's server image ..."
  docker build -q -f "$root/docker/server/Dockerfile" --build-arg VERSION=v0.0.0-import -t "$server_image" "$root" > /dev/null
fi
if [ -z "${EASYRMM_IMPORT_ENGINE_IMAGE:-}" ]; then
  echo "Building the patching engine's image ..."
  "$root/easypatch/scripts/build-test-agent-packages.sh" --arch x64 > "$work/packages.log" 2>&1 ||
    { tail -n 40 "$work/packages.log" >&2; exit 1; }
  docker build -q -f "$root/easypatch/deployment/server/Dockerfile" -t "$engine_image" "$root/easypatch" > /dev/null
fi
echo "Building the Linux machine ..."
docker build -q -t "$host_image" "$root/scripts/e2e/bundle-host" > /dev/null

# --- Certificates: one CA for the run, as a public CA would be ---------------------
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=EasyRMM import test CA" \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign" \
  -keyout "$work/ca-key.pem" -out "$work/ca.pem" 2> /dev/null
leaf() { # leaf <name> <subjectAltName>
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -keyout "$work/$1-key.pem" -out "$work/$1.csr" 2> /dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$2" > "$work/$1.ext"
  openssl x509 -req -in "$work/$1.csr" -CA "$work/ca.pem" -CAkey "$work/ca-key.pem" -CAcreateserial -days 2 \
    -extfile "$work/$1.ext" -out "$work/$1.pem" 2> /dev/null
}
leaf "$old_name" "DNS:$old_name"
leaf "$rmm_name" "DNS:$rmm_name,DNS:mesh.$rmm_name,DNS:$old_name"
rm -f "$work/ca-key.pem"

# --- The standalone server -----------------------------------------------------------
echo "Starting EasyPatch $old_version at https://$old_name ..."
db_pw=$(secret)
admin_pw="Import-$(secret)"
old_env=(-e Database__Host=127.0.0.1 -e Database__Port=25432 -e Database__Name=easypatch -e Database__User=easypatch
  -e "Database__Password=$db_pw" -e "EasyPatch__PublicUrl=https://$old_name" -e TZ=UTC)
docker run -d --name "$project-old-db" --network host -e POSTGRES_USER=easypatch -e POSTGRES_DB=easypatch \
  -e "POSTGRES_PASSWORD=$db_pw" "$pg_image" -c listen_addresses=127.0.0.1 -c port=25432 > /dev/null
for _ in $(seq 1 60); do
  docker exec "$project-old-db" pg_isready -h 127.0.0.1 -p 25432 -U easypatch > /dev/null 2>&1 && break
  sleep 1
done
# The folders this script writes first, as the caller: install -d run as
# root would make old-data root's, and a runner that is not root (CI's)
# could then not add agent-packages to it.
mkdir -p "$work/old-data/agent-packages"
chmod 0755 "$work/old-data" "$work/old-data/agent-packages"
as_root install -d -m 0700 -o 1654 -g 1654 "$work/old-data/keys"
docker run --rm --network host "${old_env[@]}" "$old_image" migrate > /dev/null
printf '%s' "$admin_pw" | docker run --rm -i --network host "${old_env[@]}" -v "$work/old-data/keys:/app/keys" "$old_image" \
  create-admin --email admin@import.test --name admin --password-stdin > /dev/null
docker run -d --name "$project-old-api" --network host "${old_env[@]}" -e ASPNETCORE_URLS=http://127.0.0.1:28180 \
  -e ASPNETCORE_HTTP_PORTS= -e ForwardedHeaders__KnownNetworks=127.0.0.1/32 \
  -v "$work/old-data/keys:/app/keys" -v "$work/old-data/agent-packages:/app/agent-packages:ro" "$old_image" > /dev/null
# Its own site configuration, with the API on loopback and the run's
# certificate instead of an ACME one.
sed "s/reverse_proxy api:8080/reverse_proxy 127.0.0.1:28180/" "$work/old/deployment/caddy/easypatch.caddy" > "$work/easypatch.caddy"
grep -q "reverse_proxy 127.0.0.1:28180" "$work/easypatch.caddy" || { echo "EasyPatch's Caddy site no longer proxies api:8080" >&2; exit 1; }
cat > "$work/Caddyfile" << EOF
{
	admin off
	auto_https off
	servers {
		protocols h1 h2
	}
}

import /etc/caddy/easypatch.caddy

https://$old_name:443 {
	tls /certs/$old_name.pem /certs/$old_name-key.pem
	import easypatch
}
EOF
mkdir -p "$work/old-certs"
cp "$work/$old_name.pem" "$work/$old_name-key.pem" "$work/old-certs/"
chmod 0755 "$work/old-certs"
chmod 0644 "$work/Caddyfile" "$work/easypatch.caddy" "$work/old-certs/"*
docker run -d --name "$project-old-proxy" --network host -v "$work/Caddyfile:/etc/caddy/Caddyfile:ro" \
  -v "$work/easypatch.caddy:/etc/caddy/easypatch.caddy:ro" -v "$work/old-certs:/certs:ro" "$caddy_image" > /dev/null
old_get() { curl -fsS --cacert "$work/ca.pem" --resolve "$old_name:443:127.0.0.1" "https://$old_name$1"; }
for _ in $(seq 1 90); do
  old_get /health/ready > /dev/null 2>&1 && break
  sleep 2
done
old_get /health/ready > /dev/null || { echo "EasyPatch $old_version did not become ready" >&2; exit 1; }

echo "Giving it organizations, sites, a webhook and an enrollment token through its console API ..."
mkdir -p "$work/seed"
(cd "$root" && EASYRMM_IMPORT_OLD_URL="https://$old_name" EASYRMM_IMPORT_CA="$work/ca.pem" EASYRMM_IMPORT_ADMIN_EMAIL=admin@import.test \
  EASYRMM_IMPORT_ADMIN_PASSWORD="$admin_pw" EASYRMM_IMPORT_OUT="$work/seed" \
  go test -tags bundle -count=1 -run '^TestImportSeedEasyPatch$' ./server/internal/easypatch/ > "$work/seed.log" 2>&1) ||
  { cat "$work/seed.log" >&2; exit 1; }

# --- The machine, with EasyPatch's agent -----------------------------------------------
echo "Enrolling EasyPatch $old_version's agent on a Debian machine ..."
docker run -d --name "$host" --hostname "$hostname" --network host --privileged --cgroupns=private \
  --add-host "$old_name:127.0.0.1" --add-host "$rmm_name:127.0.0.1" --add-host "mesh.$rmm_name:127.0.0.1" \
  --tmpfs /run --tmpfs /run/lock "$host_image" > /dev/null
for _ in $(seq 1 60); do
  state=$(docker exec "$host" systemctl is-system-running 2> /dev/null || true)
  case $state in running | degraded) break ;; esac
  sleep 1
done
docker cp "$work/ca.pem" "$host:/usr/local/share/ca-certificates/easyrmm-import-test.crt"
docker exec "$host" update-ca-certificates > /dev/null 2>&1
docker cp "$old_deb" "$host:/tmp/easypatch-agent.deb"
docker exec "$host" dpkg -i /tmp/easypatch-agent.deb > "$work/dpkg.log" 2>&1 || { cat "$work/dpkg.log" >&2; exit 1; }
docker exec -i "$host" easypatch-agent enroll --server "https://$old_name" --token-file - < "$work/seed/token"
endpoint=""
for _ in $(seq 1 60); do
  endpoint=$(old_psql "SELECT id FROM endpoints WHERE lower(hostname) = '$hostname' AND status = 'Active'")
  [ -n "$endpoint" ] && break
  sleep 2
done
[ -n "$endpoint" ] || { echo "the agent did not enroll with EasyPatch $old_version" >&2; exit 1; }
echo "Enrolled: endpoint $endpoint."

# --- Backup, as its scripts/backup.sh does; then the server is retired --------------
echo "Backing it up as its scripts/backup.sh does, and stopping it ..."
mkdir -p "$work/backup"
# (-p: this server's PostgreSQL listens on 25432, beside EasyRMM's.)
docker exec "$project-old-db" pg_dump -p 25432 -U easypatch -d easypatch --format=custom --no-owner > "$work/backup/easypatch.dump"
docker exec "$project-old-api" tar -C /app/keys -cf - . > "$work/backup/dpkeys.tar"
tar -C "$work/old-data" -cf "$work/backup/agent-packages.tar" agent-packages
(cd "$work/backup" && sha256sum easypatch.dump dpkeys.tar agent-packages.tar > SHA256SUMS)
docker rm -f -v "$project-old-api" "$project-old-proxy" "$project-old-db" > /dev/null
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# --- EasyRMM -------------------------------------------------------------------------
echo "Setting up EasyRMM at https://$rmm_name ..."
"$root/scripts/release/deploy-tree.sh" "$work/easyrmm"
(cd "$deploy" && as_root ./scripts/setup.sh --hostname "$rmm_name" --tls-mode manual --no-ip-access \
  --cert-file /etc/easyrmm/tls/fullchain.pem --key-file /etc/easyrmm/tls/privkey.pem --data-root "$work/data" > /dev/null)
as_root install -m 0640 -o root -g 65532 "$work/$rmm_name.pem" "$work/data/tls/fullchain.pem"
as_root install -m 0640 -o root -g 65532 "$work/$rmm_name-key.pem" "$work/data/tls/privkey.pem"
as_root sed -i \
  -e "s|^EASYRMM_IMAGE=.*|EASYRMM_IMAGE=${server_image%:*}|" -e "s|^EASYRMM_VERSION=.*|EASYRMM_VERSION=${server_image##*:}|" \
  -e "s|^EASYPATCH_IMAGE=.*|EASYPATCH_IMAGE=${engine_image%:*}|" -e "s|^EASYPATCH_VERSION=.*|EASYPATCH_VERSION=${engine_image##*:}|" \
  "$deploy/.env"
up=true
compose up -d --no-build --quiet-pull
rmm_get() { curl -sS --cacert "$work/ca.pem" --resolve "$1:443:127.0.0.1" -o /dev/null -w '%{http_code} %{redirect_url}' "https://$1$2"; }
for _ in $(seq 1 150); do
  if curl -fsS http://127.0.0.1:18081/readyz > /dev/null 2>&1 && curl -fsS http://127.0.0.1:18180/health/ready > /dev/null 2>&1 &&
    rmm_get "$rmm_name" /api/v1/auth/session | grep -q '^[24]'; then
    break
  fi
  sleep 2
done
curl -fsS http://127.0.0.1:18081/readyz > /dev/null || { echo "EasyRMM did not become ready" >&2; exit 1; }
# Before the import, the old name is not EasyRMM's.
before=$(rmm_get "$old_name" /api/v1/agent/heartbeat || true)
case $before in 421*) ;; *) echo "the old name before the import: $before" >&2; exit 1 ;; esac

# --- The import ----------------------------------------------------------------------
echo "Importing ..."
(cd "$deploy" && as_root env COMPOSE_PROJECT_NAME="$project" ./scripts/import-easypatch.sh --backup "$work/backup" \
  --hostname "$old_name" --yes) | tee "$work/import.log"

# --- What came across -----------------------------------------------------------------
rmm_sql() { compose exec -T -u postgres postgres psql -p 15432 -d "$1" -X -tA -v ON_ERROR_STOP=1 -c "$2"; }
check() { # check <what> <got> <want>
  if [ "$2" != "$3" ]; then
    echo "$1: got '$2', want '$3'" >&2
    exit 1
  fi
  echo "ok: $1"
}
check "EasyRMM's organizations" "$(rmm_sql easyrmm "SELECT string_agg(name, ',' ORDER BY name COLLATE \"C\") FROM organizations")" \
  "Contoso,Fabrikam,fabrikam (2)"
check "Contoso's sites" "$(rmm_sql easyrmm "SELECT string_agg(s.name || '@' || s.address, ',' ORDER BY s.name)
  FROM sites s JOIN organizations o ON o.id = s.organization_id WHERE o.name = 'Contoso'")" "Branch@1 Harbor Road,HQ@"
check "Contoso's time zone" "$(rmm_sql easyrmm "SELECT timezone FROM organizations WHERE name = 'Contoso'")" "Europe/Oslo"
check "linked organizations, installing automatically" \
  "$(rmm_sql easyrmm "SELECT count(*) FROM easypatch_organizations WHERE auto_install")" "3"
check "the old server's accounts" "$(rmm_sql easypatch "SELECT count(*) FILTER (WHERE is_active) || '/' || count(*) FROM users")" "0/1"
check "the engine's database from before, kept" \
  "$(rmm_sql postgres "SELECT count(*) FROM pg_database WHERE datname LIKE 'easypatch_before_import_%'")" "1"
check "the old name in .env" "$(as_root sed -n 's/^EASYRMM_PATCHING_AGENT_HOSTNAMES=//p' "$deploy/.env")" "$old_name"
grep -q 'organization "fabrikam", now "fabrikam (2)" (new)' "$work/import.log" ||
  { echo "the import's report does not name the collision" >&2; exit 1; }
# People who follow an old link land on EasyRMM's Patching page.
check "the old name's console" "$(rmm_get "$old_name" /)" "302 https://$rmm_name/patching"

echo "Waiting for the agent to come back through EasyRMM's edge, scan, and for the webhook ..."
key=$(as_root sed -n 's/^EASYRMM_PATCHING_KEY=//p' "$deploy/.env")
(cd "$root" && EASYRMM_IMPORT_ENGINE_URL=http://127.0.0.1:18180 EASYRMM_IMPORT_ENGINE_KEY=$key EASYRMM_IMPORT_ENDPOINT=$endpoint \
  EASYRMM_IMPORT_CHANNEL=$(cat "$work/seed/channel") EASYRMM_IMPORT_SINCE=$since \
  go test -tags bundle -count=1 -timeout 40m -v -run '^TestImportedEngine$' ./server/internal/easypatch/)
echo "The import test passed."
