#!/usr/bin/env bash
# The Authentik test (make e2e-authentik; CI's "Authentik end to end" job):
# a deployment set up with setup.sh --with-authentik, brought up from
# deploy/docker-compose.yml itself on host networking, with the patching
# engine (ADR-0044).
#
#  1. The deployment tree a release ships (scripts/release/deploy-tree.sh) is
#     set up with setup.sh --with-authentik, for
#     https://127.0.0.1 with EasyRMM's own certificate authority and
#     Authentik at https://auth.easyrmm.test, and brought up with images
#     built from this checkout. Authentik's name resolves nowhere: the
#     browser is told it is 127.0.0.1, and EasyRMM reaches it through its
#     own edge on loopback. Before it starts, links planted where root's
#     setup.sh writes, as authentik-setup could plant them, are written
#     through by neither setup.sh --upgrade nor --new-invitation.
#  2. Nothing but the edge (:80, :443 and MeshCentral's :4443) listens beyond
#     loopback, and Authentik's metrics listen nowhere.
#  3. Playwright (web/playwright.authentik.config.ts) opens the invitation
#     setup.sh printed, makes the administrator's account with an
#     authenticator app, lands on the dashboard as super administrator,
#     makes an organization and an alert rule in the patching engine for
#     it, then checks that the invitation is used up, that
#     setup.sh --new-invitation issues another, that an Authentik user
#     without an EasyRMM account is refused, that signing in again asks for
#     the second factor, and that easyrmm-server recover signs in with
#     Authentik stopped.
#  4. EASYRMM_PUBLIC_URL is changed in .env to https://rmm.easyrmm.test (also
#     told to the browser as 127.0.0.1), with a new
#     EASYRMM_AUTHENTIK_CLIENT_SECRET, and docker compose up -d run, as
#     docs/deployment/docker.md says: authentik-setup applies EasyRMM's
#     blueprint again, Authentik's provider, enrollment redirect and launch
#     URL move to the new URL, the provider takes the new secret, and the
#     administrator signs in there. docker compose up -d run again, with
#     .env unchanged, applies nothing.
#
# Needs Docker, curl, openssl, ss, Playwright's Chromium (npx playwright
# install chromium in web/), root or sudo, and ports 80, 443 and 4443 free.
# Prebuilt images can be given with EASYRMM_AUTHENTIK_SERVER_IMAGE and
# EASYRMM_AUTHENTIK_ENGINE_IMAGE. Keys, passwords, tokens and links are made
# for the run and never printed; everything is removed afterwards, also on
# failure.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
project=easyrmm-e2e-authentik
public=https://127.0.0.1
moved=https://rmm.easyrmm.test
signin_host=auth.easyrmm.test
admin_email=admin@easyrmm.test
server_image=${EASYRMM_AUTHENTIK_SERVER_IMAGE:-$project/easyrmm-server:local}
engine_image=${EASYRMM_AUTHENTIK_ENGINE_IMAGE:-$project/easypatch-server:local}
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
  if [ "$status" -ne 0 ] && [ "$up" = true ]; then
    compose ps -a >&2
    for service in server authentik-server authentik-worker authentik-setup authentik-db-init easypatch-api; do
      echo "--- $service log (last 60 lines) ---" >&2
      compose logs --no-color --tail 60 "$service" >&2
    done
  fi
  [ "$up" = true ] && compose down -v --remove-orphans > /dev/null 2>&1
  as_root rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

for tool in docker curl openssl ss npx; do
  command -v "$tool" > /dev/null || { echo "$tool is required" >&2; exit 1; }
done
# The edge's ports and the loopback ports of the deployment's programs.
for port in 80 443 4443 15432 14430 18080 18081 18180 18181 18280 18243 18281; do
  if (exec 3<> "/dev/tcp/127.0.0.1/$port") 2> /dev/null; then
    echo "127.0.0.1:$port is in use; the Authentik test needs it" >&2
    exit 1
  fi
done

# --- Images -------------------------------------------------------------------
if [ -z "${EASYRMM_AUTHENTIK_SERVER_IMAGE:-}" ]; then
  echo "Building EasyRMM's server image ..."
  docker build -q -f "$root/docker/server/Dockerfile" --build-arg VERSION=v0.0.0-authentik -t "$server_image" "$root" > /dev/null
fi
if [ -z "${EASYRMM_AUTHENTIK_ENGINE_IMAGE:-}" ]; then
  # No agent packages: this test enrolls no machine (the bundle test does).
  echo "Building EasyPatch's server image ..."
  docker build -q -f "$root/easypatch/deployment/server/Dockerfile" -t "$engine_image" "$root/easypatch" > /dev/null
fi

# --- The deployment -----------------------------------------------------------
"$root/scripts/release/deploy-tree.sh" "$work/easyrmm"
# setup.sh's output holds the invitation link: kept, not printed.
(cd "$deploy" && as_root ./scripts/setup.sh --hostname 127.0.0.1 --ip-addresses 127.0.0.1 \
  --data-root "$work/data" \
  --with-authentik --authentik-hostname "$signin_host" --admin-email "$admin_email") > "$work/setup.out" < /dev/null
invitation=$(grep -o "https://$signin_host/if/flow/easyrmm-enrollment/?itoken=[0-9a-f-]*" "$work/setup.out" || true)
[ -n "$invitation" ] || { echo "setup.sh printed no invitation link" >&2; exit 1; }
# The patching engine has no profile, since it always runs: Authentik's is the
# only one.
as_root grep -qx 'COMPOSE_PROFILES=authentik' "$deploy/.env" ||
  { echo "setup.sh did not turn on the authentik profile" >&2; exit 1; }
[ "$(as_root stat -c '%a %u' "$work/data/authentik/secrets/akadmin-password")" = "600 1000" ] ||
  { echo "akadmin's password file is not 0600 and Authentik's" >&2; exit 1; }

# authentik-setup (uid 1000) can write in invitations/. Links planted where
# setup.sh writes as root, and in place of the record of the first invitation
# that releases up to 1.0.0-rc.4 kept there; setup.sh --upgrade (every
# setting from .env, nothing asked, no invitation) and --new-invitation:
# root must write nothing through them.
inv=$work/data/authentik/invitations
as_root sh -c "printf canary > '$work/canary' && rm -f '$inv/issued' &&
  ln -s '$work/made-by-root' '$inv/issued' && ln -s '$work/canary' '$inv/pending.tmp' &&
  ln -sfn '$work/canary' '$inv/pending' && chown -h 1000:1000 '$inv/issued' '$inv/pending.tmp' '$inv/pending' &&
  ln -sfn '$work/canary' '$work/data/authentik/secrets/akadmin-password'"
(cd "$deploy" && as_root ./scripts/setup.sh --upgrade) > "$work/setup-again.out" < /dev/null
if grep -q 'itoken=' "$work/setup-again.out"; then
  echo "setup.sh --upgrade issued an invitation" >&2
  exit 1
fi
(cd "$deploy" && as_root ./scripts/setup.sh --new-invitation) > "$work/setup-invitation.out" < /dev/null
invitation=$(grep -o "https://$signin_host/if/flow/easyrmm-enrollment/?itoken=[0-9a-f-]*" "$work/setup-invitation.out" || true)
[ -n "$invitation" ] || { echo "setup.sh --new-invitation printed no invitation link" >&2; exit 1; }
if [ "$(as_root cat "$work/canary")" != canary ] || [ "$(as_root stat -c '%u' "$work/canary")" != 0 ] ||
  as_root test -e "$work/made-by-root"; then
  echo "setup.sh wrote through a link in Authentik's directories" >&2
  exit 1
fi
for f in "$inv/pending" "$work/data/authentik/secrets/akadmin-password"; do
  [ "$(as_root stat -c '%F %a %u' "$f")" = "regular file 600 1000" ] ||
    { echo "$f is not Authentik's regular file" >&2; exit 1; }
done
as_root sed -i \
  -e "s|^EASYRMM_IMAGE=.*|EASYRMM_IMAGE=${server_image%:*}|" -e "s|^EASYRMM_VERSION=.*|EASYRMM_VERSION=${server_image##*:}|" \
  -e "s|^EASYPATCH_IMAGE=.*|EASYPATCH_IMAGE=${engine_image%:*}|" -e "s|^EASYPATCH_VERSION=.*|EASYPATCH_VERSION=${engine_image##*:}|" \
  "$deploy/.env"

ss -ltnH | awk '{print $4}' | sort -u > "$work/listening.before"
echo "Starting the deployment (docker compose, project $project) ..."
up=true
compose up -d --no-build --quiet-pull
setup_state() {
  local id
  id=$(compose ps -a -q authentik-setup)
  [ -n "$id" ] && docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$id"
}
ready() {
  curl -fsS http://127.0.0.1:18081/readyz > /dev/null 2>&1 &&
    curl -fsS http://127.0.0.1:18180/health/ready > /dev/null 2>&1 &&
    curl -fsS http://127.0.0.1:18280/-/health/ready/ > /dev/null 2>&1 &&
    [ "$(setup_state)" = "exited 0" ]
}
# Authentik's first start migrates its database and applies its blueprints.
for _ in $(seq 1 300); do
  ready && break
  case $(setup_state) in "exited "[1-9]*) echo "authentik-setup failed" >&2; exit 1 ;; esac
  sleep 2
done
ready || { echo "the deployment did not become ready (authentik-setup: $(setup_state))" >&2; exit 1; }
# Authentik through EasyRMM's edge, by its name.
issuer=$(curl -fsSk --resolve "$signin_host:443:127.0.0.1" \
  "https://$signin_host/application/o/easyrmm/.well-known/openid-configuration" | sed -n 's/.*"issuer": *"\([^"]*\)".*/\1/p' || true)
[ "$issuer" = "https://$signin_host/application/o/easyrmm/" ] ||
  { echo "Authentik's discovery document through the edge is wrong: $issuer" >&2; exit 1; }

# --- Only the edge beyond loopback ---------------------------------------------
sleep 5
ss -ltnH | awk '{print $4}' | sort -u > "$work/listening.after"
outside=$(comm -13 "$work/listening.before" "$work/listening.after" | grep -Ev '^(127\.[0-9.]+|\[::1\]|\[::ffff:127\.[0-9.]+\]):[0-9]+$' |
  grep -Ev ':(80|443|4443)$' || true)
if [ -n "$outside" ]; then
  printf "Listening beyond loopback, other than the edge:\n%s\n" "$outside" >&2
  exit 1
fi
for port in 18280 18243 18281; do
  grep -qx "127.0.0.1:$port" "$work/listening.after" || { echo "Authentik does not listen on 127.0.0.1:$port" >&2; exit 1; }
done
if grep -q ':9300$' "$work/listening.after"; then
  echo "Authentik's metrics listen (:9300); they should be off" >&2
  exit 1
fi
echo "Beyond loopback, only the edge listens: $(comm -13 "$work/listening.before" "$work/listening.after" |
  grep -Ev '^(127\.[0-9.]+|\[::1\]):' | tr '\n' ' ')"

# The certificates of both names, by public key, for the browser.
spki_of() {
  openssl s_client -connect 127.0.0.1:443 "$@" < /dev/null 2> /dev/null | openssl x509 -pubkey -noout |
    openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
}
spki=$(spki_of)
spki_signin=$(spki_of -servername "$signin_host")
[ -n "$spki" ] && [ -n "$spki_signin" ] || { echo "could not read the edge's certificates" >&2; exit 1; }
[ "$spki" = "$spki_signin" ] || spki="$spki,$spki_signin"

# --- The story ------------------------------------------------------------------
# The browser test runs commands in the deployment through this.
cat > "$work/ctl" << EOF
#!/bin/sh
# Runs docker compose or setup.sh in the test's deployment, as root, or sets
# EASYRMM_PUBLIC_URL or a new EASYRMM_AUTHENTIK_CLIENT_SECRET in its .env.
set -eu
cd "$deploy"
sudo=""
[ "\$(id -u)" -eq 0 ] || sudo=sudo
case "\${1:-}" in
  compose) shift; exec \$sudo docker compose -p "$project" "\$@" ;;
  setup) shift; exec \$sudo ./scripts/setup.sh "\$@" ;;
  public-url) exec \$sudo sed -i "s|^EASYRMM_PUBLIC_URL=.*|EASYRMM_PUBLIC_URL=$moved|" .env ;;
  client-secret)
    \$sudo grep -q "^EASYRMM_AUTHENTIK_CLIENT_SECRET=." .env
    secret=\$(openssl rand -hex 32)
    exec \$sudo sed -i "s|^EASYRMM_AUTHENTIK_CLIENT_SECRET=.*|EASYRMM_AUTHENTIK_CLIENT_SECRET=\$secret|" .env ;;
  *) echo "usage: ctl compose|setup ...|public-url|client-secret" >&2; exit 2 ;;
esac
EOF
chmod 0755 "$work/ctl"

echo "Running the story in a browser ..."
# The edge keeps its key when EASYRMM_PUBLIC_URL changes (pki.Authority), so
# the moved name's certificate has the same public key as these.
(cd "$root/web" && EASYRMM_AUTHENTIK_URL=$public EASYRMM_AUTHENTIK_MOVED_URL=$moved EASYRMM_AUTHENTIK_SIGNIN_HOST=$signin_host \
  EASYRMM_AUTHENTIK_SPKI=$spki EASYRMM_AUTHENTIK_INVITATION=$invitation EASYRMM_AUTHENTIK_ADMIN_EMAIL=$admin_email \
  EASYRMM_AUTHENTIK_CTL=$work/ctl npx playwright test -c playwright.authentik.config.ts)
echo "The Authentik test passed."
