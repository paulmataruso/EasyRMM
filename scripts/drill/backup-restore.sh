#!/usr/bin/env bash
# Backup and restore drill: follows docs/operations/backup-restore.md on a
# disposable deployment and checks that the restored server is the same
# server to its users and agents.
#
#   sudo scripts/drill/backup-restore.sh [--authentik] [--in-place] WORKDIR
#
# 1. A source host: this checkout, deploy/scripts/setup.sh and the Compose
#    stack, on DRILL_ADDR (127.0.0.2 by default) so it does not collide with
#    anything on the host's own addresses. With --authentik, set up with
#    setup.sh --with-authentik, Authentik at auth.drill.invalid on the same
#    edge.
# 2. Real state: first-run setup, an administrator with an authenticator, a
#    site, a deployment token, and a real agent in a container that enrolls
#    and runs a job. With --authentik, the administrator is made in
#    Authentik instead, from setup.sh's invitation, with a password and an
#    authenticator app, and signs in to EasyRMM through it.
# 3. The backup, with the guide's commands.
# 4. The host is lost: the stack, its data root and its checkout go.
# 5. A new host: a fresh checkout, then the guide's restore steps.
#    With --in-place, 4 and 5 are instead the guide's "Restore in place",
#    over the running deployment and in its checkout: stop it, set its data
#    root and .env aside, then the same restore steps.
# 6. Checks against the restored server:
#    - TLS against the authority saved before the backup;
#    - sign-in with the same password and authenticator, with --authentik
#      through Authentik, as the same Authentik user and the same EasyRMM
#      account;
#    - with --authentik, the same key signing EasyRMM's ID tokens, read
#      from Authentik and from the keys it publishes, and akadmin's password
#      file still opening akadmin;
#    - the audit chain;
#    - the same agent, never re-enrolled, reconnecting and running a new
#      job signed by the restored key;
#    - MeshCentral's identity;
#    - the patching engine's organization, read from the engine, and its
#      data-protection keys.
# 7. With --in-place: the set-aside data root and .env are as they were
#    when the deployment stopped, entry by entry and file by file. Then the
#    guide's way back: the restored deployment set aside, the set-aside one
#    put back and started, and the checks of 6 again, with the changes made
#    after the backup back.
#
# Needs root (setup.sh sets the data directories' owners), Docker Compose,
# curl, jq, openssl, and network access for the device container's
# packages. See lib.sh for the ports it uses.
set -Eeuo pipefail
# shellcheck source=scripts/drill/lib.sh
source "$(dirname "$0")/lib.sh"

authentik=false
in_place=false
while [[ ${1:-} == --* ]]; do
  case $1 in
    --authentik) authentik=true ;;
    --in-place) in_place=true ;;
    *)
      echo "unknown option $1" >&2
      exit 2
      ;;
  esac
  shift
done
drill_workdir "${1:?usage: backup-restore.sh [--authentik] [--in-place] WORKDIR}"
[[ $authentik == false ]] || setup_args=(--with-authentik --authentik-hostname "$signin_host" --admin-email "$admin_email")
device_image=${DRILL_DEVICE_IMAGE:-debian:13}
device="$COMPOSE_PROJECT_NAME-device"
backups="$work/backups"
# .env holds the key that seals the database's secrets, so it is backed up apart
# from the dumps (the guide's /var/backups/easyrmm-keys).
keys="$work/backup-keys"
mkdir -p "$keys"
mkdir -p "$backups"
chmod 700 "$backups"
cleanup_device() { docker rm -f "$device" >/dev/null 2>&1 || true; }

# wait_authentik: Authentik answers at its name through the edge, and
# authentik-setup, which runs after every start, has finished.
wait_authentik() {
  local s _
  for _ in $(seq 1 300); do
    s=$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$(compose ps -a -q authentik-setup)" 2>/dev/null || true)
    case $s in
      "exited 0")
        curl -fsS --cacert "$state/ca.pem" --resolve "$signin_host:443:$addr" -o /dev/null "$signin/-/health/ready/" 2>/dev/null &&
          return 0
        ;;
      "exited "*) fail "authentik-setup failed ($s): docker compose logs authentik-setup" ;;
    esac
    sleep 2
  done
  fail "Authentik did not become ready: docker compose logs authentik-worker authentik-setup"
}

# sign_in_again: sign-in as it starts on EasyRMM's sign-in page, in a
# browser with no session at EasyRMM or at Authentik.
sign_in_again() {
  local start
  rm -f "$state/cookies"
  csrf=""
  start=$(call 200 GET /api/v1/auth/sso | jq -r '.providers[] | select(.name == "Authentik") | .startUrl')
  [[ -n "$start" ]] || fail "EasyRMM's sign-in page offers no Authentik: $(call 200 GET /api/v1/auth/sso)"
  [[ $start != /* ]] || start="$url$start"
  sign_in_authentik "$start"
  [[ $stages == "ak-stage-identification ak-stage-password ak-stage-authenticator-validate" ]] ||
    fail "signing in through Authentik went through: $stages"
}

# authentik_facts: what Authentik itself holds, read with its own shell, as
# one JSON line: the key EasyRMM's provider signs ID tokens with (name, key
# id, SHA-256 fingerprint of its certificate); the administrator's user (id,
# uuid, and the subject EasyRMM links the account to) and confirmed
# authenticator apps; whether akadmin's password file opens akadmin; and
# whether the user made after the backup exists.
authentik_facts() {
  compose exec -T -e DRILL_EMAIL="$admin_email" authentik-worker /bin/sh /easyrmm/bin/start.sh shell -c '
import json, os
from authentik.core.models import User
from authentik.providers.oauth2.models import OAuth2Provider
from authentik.stages.authenticator_totp.models import TOTPDevice
key = OAuth2Provider.objects.get(name="EasyRMM").signing_key
user = User.objects.get(username=os.environ["DRILL_EMAIL"])
with open("/easyrmm/secrets/akadmin-password", encoding="utf-8") as f:
    akadmin = User.objects.get(username="akadmin").check_password(f.read().rstrip("\n"))
print("easyrmm-drill: " + json.dumps({
    "key": {"name": key.name, "kid": key.kid, "sha256": key.fingerprint_sha256},
    "user": {"id": user.pk, "uuid": str(user.uuid), "subject": user.uid,
             "authenticators": TOTPDevice.objects.filter(user=user, confirmed=True).count()},
    "akadminPasswordFile": akadmin,
    "afterBackup": User.objects.filter(username="after-backup@drill.invalid").exists(),
}, sort_keys=True))
' 2>>"$work/compose.log" | sed -n 's/^easyrmm-drill: //p'
}

# published_keys: the keys Authentik publishes for EasyRMM's provider, which
# EasyRMM verifies ID tokens with: each one's key id and the SHA-256
# fingerprint of its certificate, computed here.
published_keys() {
  local kid cert
  curl -fsS --cacert "$state/ca.pem" --resolve "$signin_host:443:$addr" "$signin/application/o/easyrmm/jwks/" |
    jq -r '.keys[] | "\(.kid) \(.x5c[0])"' | while read -r kid cert; do
    printf '%s %s\n' "$kid" "$(printf %s "$cert" | base64 -d | openssl dgst -sha256 -r | cut -d' ' -f1)"
  done
}

# tree_manifest DIR: every entry under DIR with its type, owner, mode, size,
# modification time and name, then every file's SHA-256: what setting DIR
# aside must leave as it was.
tree_manifest() {
  (
    cd "$1"
    find . -mindepth 1 -printf '%y %U:%G %m %s %T@ %p\n' | LC_ALL=C sort -k6
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum
  )
}

# ---------------------------------------------------------------- source
step "Source host: setup.sh and the Compose stack on $addr"
stack_up "$work/host-a"
ok "certificate authority saved"

if [[ $authentik == true ]]; then
  wait_authentik
  ok "Authentik ready at $signin, through the edge"
  step "Real state: an administrator made in Authentik, an agent, a job"
  invitation=$(grep -o "$signin/if/flow/easyrmm-enrollment/?itoken=[0-9a-f-]*" "$state/setup.out" || true)
  [[ -n "$invitation" ]] || fail "setup.sh printed no invitation"
  sign_in_authentik "$invitation"
  [[ $stages == "ak-stage-prompt ak-stage-authenticator-validate ak-stage-authenticator-totp" ]] ||
    fail "the invitation's sign-up went through: $stages"
  ok "administrator made in Authentik from setup.sh's invitation ($stages), signed in to EasyRMM through it"
  sign_in_again
  ok "signed in again through Authentik with the same email, password and authenticator ($stages)"
  org=$(call 201 POST /api/v1/organizations '{"name":"Drill Org","timezone":"UTC"}' | jq -r .id)
else
  step "Real state: setup, an administrator with an authenticator, an agent, a job"
  first_admin
  ok "administrator signed in with an authenticator"
  org=$(call 200 GET /api/v1/organizations | jq -r '.items[0].id')
fi
site=$(call 201 POST "/api/v1/organizations/$org/sites" '{"name":"Drill site","timezone":"UTC"}' | jq -r .id)
token=$(call 201 POST "/api/v1/sites/$site/enrollment-tokens" '{"name":"Drill","expiresInDays":1}' | jq -r .secret)

# What install.sh does over its pinned connection, minus the systemd unit
# (the container has none). The container lives through the whole drill:
# the same agent, with the same device key, must reach the restored server.
cleanup_device
docker run -d --name "$device" --hostname drill-device --network host \
  -e EASYRMM_TOKEN="$token" -e PIN="sha256//$pin" -e SERVER="$url" "$device_image" sh -c '
set -e
apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null
case $(uname -m) in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) echo "unsupported $(uname -m)"; exit 1 ;; esac
mkdir -p /opt/easyrmm && cd /opt/easyrmm
get() { curl -fsSL --proto =https --insecure --pinnedpubkey "$PIN" -o "$1" "$SERVER/api/agent/v1/$2"; }
get easyrmm-agent "download/easyrmm-agent-linux-$arch"
get SHA256SUMS download/SHA256SUMS
grep " easyrmm-agent-linux-$arch\$" SHA256SUMS | sed "s/easyrmm-agent-linux-$arch/easyrmm-agent/" | sha256sum -c - >/dev/null
get ca.pem ca.pem
chmod 755 easyrmm-agent
./easyrmm-agent enroll --server "$SERVER" --ca-file /opt/easyrmm/ca.pem
exec ./easyrmm-agent run' >/dev/null

device_json() { call 200 GET /api/v1/devices | jq -c '[.items[] | select(.hostname == "drill-device")][0] // empty'; }
dev=""
for _ in $(seq 1 120); do
  d=$(device_json)
  if [[ -n "$d" && $(jq -r .online <<<"$d") == true ]]; then
    dev=$(jq -r .id <<<"$d")
    break
  fi
  sleep 3
done
[[ -n "$dev" ]] || fail "the agent did not enroll (docker logs $device)"
ok "agent enrolled and online: device $dev"

script=$(call 201 POST /api/v1/scripts "$(jq -nc --arg o "$org" \
  '{organizationId:$o, name:"Drill", shell:"bash", body:"echo \"drill-$1\"", timeoutSeconds:60}')" | jq -r .id)

# run_job ARG: runs the script on the device and checks its output.
run_job() {
  local job j status out
  job=$(call 201 POST /api/v1/jobs "$(jq -nc --arg s "$script" --arg d "$dev" --arg a "$1" '{scriptId:$s, deviceIds:[$d], args:[$a]}')" | jq -r .id)
  for _ in $(seq 1 60); do
    j=$(call 200 GET "/api/v1/jobs/$job")
    [[ $(jq -r .finished <<<"$j") == true ]] && break
    sleep 2
  done
  status=$(jq -r '.runs[0].status' <<<"$j")
  [[ "$status" == succeeded ]] || fail "job $job ended $status: $j"
  # Output has an endpoint of its own, each read audited (ADR-0063).
  out=$(call 200 GET "/api/v1/job-runs/$(jq -r '.runs[0].id' <<<"$j")/output" | jq -r .stdout)
  [[ "$out" == *"drill-$1"* ]] || fail "job $job printed $out"
  ok "job ran on the agent and printed drill-$1"
}
run_job before

remote_agent=$(device_json | jq -r .remoteAgent)
before_audit=$(call 200 GET /api/v1/audit/verify)
[[ $(jq -r '.firstBadId // empty' <<<"$before_audit") == "" ]] || fail "audit chain broken before the backup: $before_audit"
audit_checked=$(jq -r .checked <<<"$before_audit")
ok "audit chain intact: $audit_checked records"
compgen -G "$data/meshcentral/data/*-cert-public.crt" >/dev/null || fail "no MeshCentral certificates in $data/meshcentral/data"
(cd "$data/meshcentral/data" && sha256sum ./*-cert-public.crt) >"$state/meshcentral-identity"
ok "MeshCentral identity recorded ($(wc -l <"$state/meshcentral-identity") certificates); MeshAgent on the device: $remote_agent"

# engine_org: the patching engine's organization linked to the drill's,
# when the engine also lists it itself.
engine_org() {
  call 200 GET /api/v1/settings/easypatch/organizations | jq -r --arg o "$org" \
    '(.links[] | select(.organizationId == $o) | .easyPatchId) as $id | select([.easyPatch[]?.id] | index($id)) | $id'
}
ep_org=""
for _ in $(seq 1 60); do
  ep_org=$(engine_org)
  [[ -n "$ep_org" ]] && break
  sleep 3
done
[[ -n "$ep_org" ]] || fail "the patching engine has no organization for the drill's: $(call 200 GET /api/v1/settings/easypatch/organizations)"
compgen -G "$data/easypatch/keys/*" >/dev/null || fail "no data-protection keys in $data/easypatch/keys"
(cd "$data/easypatch/keys" && sha256sum ./*) >"$state/engine-keys"
ok "patching engine: organization $ep_org, $(wc -l <"$state/engine-keys") data-protection keys recorded"

if [[ $authentik == true ]]; then
  authentik_facts >"$state/authentik-facts"
  jq -e '.user.authenticators == 1 and .akadminPasswordFile == true and .afterBackup == false' "$state/authentik-facts" >/dev/null ||
    fail "Authentik before the backup: $(cat "$state/authentik-facts")"
  published_keys >"$state/authentik-keys"
  [[ $(wc -l <"$state/authentik-keys") == 1 &&
    $(cut -d' ' -f2 "$state/authentik-keys") == $(jq -r '.key.sha256 | gsub(":"; "") | ascii_downcase' "$state/authentik-facts") ]] ||
    fail "Authentik publishes other keys than its provider's: $(cat "$state/authentik-keys"); $(jq -c .key "$state/authentik-facts")"
  call 200 GET /api/v1/auth/session | jq -r .user.id >"$state/user-id"
  call 200 GET /api/v1/auth/identities | jq -c '[.items[] | {providerName, createdAt}]' >"$state/identities"
  [[ $(jq -r 'map(.providerName) | join(",")' "$state/identities") == Authentik ]] ||
    fail "the administrator's linked identities: $(cat "$state/identities")"
  sha256sum <"$data/authentik/secrets/akadmin-password" >"$state/akadmin-password"
  ok "Authentik: user $(jq -r .user.id "$state/authentik-facts") with $(jq -r .user.authenticators "$state/authentik-facts") authenticator app, linked to EasyRMM account $(cat "$state/user-id") since $(jq -r '.[0].createdAt' "$state/identities")"
  ok "Authentik: EasyRMM's provider signs with \"$(jq -r .key.name "$state/authentik-facts")\", SHA-256 $(jq -r .key.sha256 "$state/authentik-facts"), the one key it publishes; akadmin's password file opens akadmin"
fi

# ---------------------------------------------------------------- backup
step "Backup with the guide's commands"
# From docs/operations/backup-restore.md, "Back up", with this drill's
# backup directory and data root.
cd "$work/host-a/deploy"
ts=$(date -u +%Y%m%dT%H%M%SZ)
compose exec -T -u postgres postgres pg_dump -p 15432 \
  --format=custom easyrmm >"$backups/db-$ts.dump" || fail "pg_dump failed"
compose exec -T -u postgres postgres pg_dump -p 15432 \
  --format=custom easypatch >"$backups/easypatch-db-$ts.dump" || fail "pg_dump of the engine's database failed"
tar -C "$work/host-a/deploy" -czf "$keys/env-$ts.tgz" .env
tar -C "$data" -czf "$backups/server-$ts.tgz" server
tar -C "$data" -czf "$backups/easypatch-keys-$ts.tgz" easypatch/keys
if [[ -d "$data/authentik" ]]; then
  compose exec -T -u postgres postgres pg_dump -p 15432 \
    --format=custom authentik >"$backups/authentik-db-$ts.dump" || fail "pg_dump of Authentik's database failed"
  tar -C "$data" -czf "$backups/authentik-$ts.tgz" authentik
fi
compose stop meshcentral >>"$work/compose.log" 2>&1
tar -C "$data" -czf "$backups/meshcentral-$ts.tgz" meshcentral
compose start meshcentral >>"$work/compose.log" 2>&1
ok "backup written: $(find "$backups" -type f -printf '%f (%s bytes) ')"
if [[ $authentik == true ]]; then
  [[ -s "$backups/authentik-db-$ts.dump" && -s "$backups/authentik-$ts.tgz" ]] || fail "the backup has no Authentik"
else
  [[ ! -e "$backups/authentik-db-$ts.dump" && ! -e "$backups/authentik-$ts.tgz" ]] || fail "a backup without Authentik has Authentik's files"
fi

# Changes after the backup: they must not survive the restore.
call 201 POST "/api/v1/organizations/$org/sites" '{"name":"After the backup","timezone":"UTC"}' >/dev/null
if [[ $authentik == true ]]; then
  compose exec -T authentik-worker /bin/sh /easyrmm/bin/start.sh shell -c '
from authentik.core.models import User
User.objects.create(username="after-backup@drill.invalid", email="after-backup@drill.invalid", name="After the backup")
' >>"$work/compose.log" 2>&1 || fail "could not make a user in Authentik"
fi

# --------------------------------------------------------------- restore
# restore DEPLOY: the guide's restore steps 1 to 5, in the deploy/ directory
# DEPLOY, onto an empty data root and an empty PostgreSQL.
restore() {
  cd "$1"
  # 1. Restore deploy/.env, the server directory, MeshCentral's data, the
  #    engine's keys and, with Authentik, its directory, keeping owners by
  #    number.
  tar -C "$1" -xzf "$keys/env-$ts.tgz"
  mkdir -p "$data"
  tar --numeric-owner -C "$data" -xzf "$backups/server-$ts.tgz"
  tar --numeric-owner -C "$data" -xzf "$backups/meshcentral-$ts.tgz"
  tar --numeric-owner -C "$data" -xzf "$backups/easypatch-keys-$ts.tgz"
  if [[ -f "$backups/authentik-$ts.tgz" ]]; then
    tar --numeric-owner -C "$data" -xzf "$backups/authentik-$ts.tgz"
  fi
  # 2. setup.sh with the same options keeps the restored .env and, with
  #    Authentik, akadmin's password, and issues no invitation.
  out=$(./scripts/setup.sh --hostname "$addr" --data-root "$data" "${setup_args[@]}" </dev/null)
  [[ "$out" == *"leaving it unchanged"* ]] || fail "setup.sh did not keep the restored .env: $out"
  [[ "$out" != *itoken=* ]] || fail "setup.sh issued another invitation on the restored host"
  # 3. PostgreSQL alone; its first start creates the roles and database.
  compose up -d postgres >>"$work/compose.log" 2>&1
  for _ in $(seq 1 60); do
    [[ $(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q postgres)") == healthy ]] && break
    sleep 2
  done
  # 4. The dump, as the superuser.
  compose exec -T -u postgres postgres pg_restore -p 15432 \
    --dbname=easyrmm --exit-on-error <"$backups/db-$ts.dump" || fail "pg_restore failed"
  compose run --rm easypatch-db-init >>"$work/compose.log" 2>&1 || fail "easypatch-db-init failed"
  compose exec -T -u postgres postgres pg_restore -p 15432 \
    --dbname=easypatch --exit-on-error <"$backups/easypatch-db-$ts.dump" || fail "pg_restore of the engine's database failed"
  if [[ -f "$backups/authentik-db-$ts.dump" ]]; then
    compose run --rm authentik-db-init >>"$work/compose.log" 2>&1 || fail "authentik-db-init failed"
    compose exec -T -u postgres postgres pg_restore -p 15432 \
      --dbname=authentik --exit-on-error <"$backups/authentik-db-$ts.dump" || fail "pg_restore of Authentik's database failed"
  fi
  # 5. Everything else.
  compose up -d >>"$work/compose.log" 2>&1
  wait_ready
  ok "restored server ready"
  if [[ $authentik == true ]]; then
    wait_authentik
    ok "Authentik ready on its restored database"
  fi
}

if [[ $in_place == true ]]; then
  # -------------------------------------------------------------- in place
  step "In place: the guide's steps over the running deployment"
  aside_audit=$(call 200 GET /api/v1/audit/verify | jq -r .checked)
  # From docs/operations/backup-restore.md, "Restore in place".
  # 1. Stop the deployment, never with -v.
  compose down >>"$work/compose.log" 2>&1
  [[ -z $(compose ps -a -q) ]] || fail "docker compose down left containers: $(compose ps -a)"
  [[ -n $(find "$data/postgres" -name PG_VERSION -print -quit) ]] || fail "no PostgreSQL data in $data/postgres"
  tree_manifest "$data" >"$state/set-aside"
  sha256sum <.env >"$state/set-aside-env"
  # 2. The data root, PostgreSQL's data with it, and .env set aside under
  #    one timestamp.
  aside=$(date -u +%Y%m%dT%H%M%SZ)
  mv "$data" "$data.before-restore-$aside"
  mv .env ".env.before-restore-$aside"
  ok "deployment stopped; data root set aside as ${data##*/}.before-restore-$aside ($(grep -c '^[a-z] ' "$state/set-aside") entries, PostgreSQL's data among them), .env as .env.before-restore-$aside"
  # 3. The restore steps, in the same directory.
  restore "$work/host-a/deploy"
else
  # ------------------------------------------------------------------ loss
  step "The host is lost"
  compose down >>"$work/compose.log" 2>&1
  cd "$work"
  rm -rf "$data" "$work/host-a"
  ok "stack removed, data root and checkout deleted; the agent keeps trying"

  step "New host: the guide's restore steps"
  checkout "$work/host-b"
  restore "$work/host-b/deploy"
fi

# --------------------------------------------------------------- checks
# same_server WHEN: the deployment started from the backup (WHEN=restore),
# or the set-aside one put back (WHEN=rollback), is the same server to its
# users and agents. What changed after the backup is gone after the restore
# and back after the rollback.
same_server() {
  local when=$1 back=false audit_min=$audit_checked job=after
  if [[ $when == rollback ]]; then
    back=true
    audit_min=$aside_audit
    job=rollback
  fi
  curl -fsS --cacert "$state/ca.pem" -o /dev/null "$url/" || fail "TLS against the saved authority failed"
  ok "TLS verifies against the authority saved before the backup"

  if [[ $authentik == true ]]; then
    signed_in_at=$(date -u +%s)
    sign_in_again
    [[ $(call 200 GET /api/v1/auth/session | jq -r .user.id) == $(cat "$state/user-id") ]] ||
      fail "signed in to another EasyRMM account than $(cat "$state/user-id")"
    ok "signed in through Authentik with the same email, password and authenticator ($stages), to the same EasyRMM account"
  else
    sign_in
    ok "signed in with the same password and authenticator (the sealed secret opens)"
  fi

  after_audit=$(call 200 GET /api/v1/audit/verify)
  [[ $(jq -r '.firstBadId // empty' <<<"$after_audit") == "" ]] || fail "audit chain broken after the $when: $after_audit"
  [[ $(jq -r .checked <<<"$after_audit") -ge $audit_min ]] || fail "audit records lost: $after_audit, wanted at least $audit_min"
  ok "audit chain intact: $(jq -r .checked <<<"$after_audit") records"

  after_sites=$(call 200 GET "/api/v1/organizations/$org/sites" | jq '[.items[] | select(.name == "After the backup")] | length')
  if [[ $back == true ]]; then
    [[ $after_sites == 1 ]] || fail "the site created after the backup is not back: $after_sites"
    ok "the set-aside data is back: the site created after the backup is there again"
  else
    [[ $after_sites == 0 ]] || fail "a site created after the backup survived"
    ok "the restored data is the backup's: a site created after it is gone"
  fi

  if [[ $authentik == true ]]; then
    ids=$(call 200 GET /api/v1/auth/identities)
    [[ $(jq -c '[.items[] | {providerName, createdAt}]' <<<"$ids") == "$(cat "$state/identities")" ]] ||
      fail "the account's link to Authentik is not the backup's: $ids"
    used=$(jq -r '.items[0].lastUsedAt // empty' <<<"$ids")
    [[ -n "$used" && $(date -u -d "$used" +%s) -ge $signed_in_at ]] || fail "the sign-in did not go through the $when's link: $ids"
    ok "EasyRMM found Authentik's identity in the link made before the backup (linked $(jq -r '.[0].createdAt' "$state/identities"), used $used)"
    facts=$(authentik_facts)
    [[ $(jq -cS 'del(.afterBackup)' <<<"$facts") == "$(jq -cS 'del(.afterBackup)' "$state/authentik-facts")" &&
      $(jq -r .afterBackup <<<"$facts") == "$back" ]] ||
      fail "Authentik is not the one wanted after the $when: before the backup $(cat "$state/authentik-facts"), now $facts"
    if [[ $back == true ]]; then
      ok "Authentik: the same user $(jq -r .user.id <<<"$facts") with the same subject and authenticator app; the user made after the backup is back"
    else
      ok "Authentik: the same user $(jq -r .user.id <<<"$facts") with the same subject and authenticator app; the user made after the backup is gone"
    fi
    published_keys | cmp -s - "$state/authentik-keys" || fail "Authentik publishes other keys: $(published_keys); before: $(cat "$state/authentik-keys")"
    ok "the provider's signing key is unchanged: \"$(jq -r .key.name <<<"$facts")\", SHA-256 $(jq -r .key.sha256 <<<"$facts"), published as key $(cut -c1-16 "$state/authentik-keys")..."
    [[ $(sha256sum <"$data/authentik/secrets/akadmin-password") == "$(cat "$state/akadmin-password")" &&
      $(stat -c '%u:%g %a' "$data/authentik/secrets/akadmin-password") == "1000:1000 600" ]] ||
      fail "akadmin's password file is not the backup's, owned by Authentik: $(stat -c '%u:%g %a' "$data/authentik/secrets/akadmin-password")"
    ok "akadmin's password file is the backup's (Authentik's, mode 600) and still opens akadmin"
  fi

  started_at=$(date -u +%s)
  seen=""
  for _ in $(seq 1 100); do
    d=$(device_json)
    last=$(jq -r '.lastSeenAt // empty' <<<"$d")
    if [[ -n "$last" && $(date -u -d "$last" +%s) -gt $started_at ]]; then
      seen=$last
      break
    fi
    sleep 3
  done
  [[ -n "$seen" && $(jq -r .id <<<"$d") == "$dev" ]] || fail "the agent did not come back (docker logs $device)"
  ok "the same agent reconnected with its device key: device $dev, last seen $seen"
  run_job "$job"

  if [[ "$remote_agent" == true ]]; then
    for _ in $(seq 1 60); do
      [[ $(device_json | jq -r .remoteOnline) == true ]] && break
      sleep 3
    done
    [[ $(device_json | jq -r .remoteOnline) == true ]] || fail "MeshAgent did not reconnect"
    ok "MeshAgent reconnected to MeshCentral"
  fi
  (cd "$data/meshcentral/data" && sha256sum -c --quiet "$state/meshcentral-identity") || fail "MeshCentral's identity changed"
  ok "MeshCentral's identity is unchanged"

  conn=$(call 200 POST /api/v1/settings/easypatch/check)
  [[ $(jq -r .configured <<<"$conn") == true && $(jq -r '.lastError // ""' <<<"$conn") == "" ]] ||
    fail "the patching engine does not answer after the $when: $conn"
  [[ $(engine_org) == "$ep_org" ]] || fail "the engine's organization is not the backup's: $(call 200 GET /api/v1/settings/easypatch/organizations)"
  (cd "$data/easypatch/keys" && sha256sum -c --quiet "$state/engine-keys") || fail "the engine's data-protection keys changed"
  ok "the patching engine has the backup's organization ($ep_org) and keys"
}

step "The restored server is the same server"
same_server restore

if [[ $in_place == true ]]; then
  # -------------------------------------------------------------- rollback
  step "The set-aside deployment is as it stopped"
  tree_manifest "$data.before-restore-$aside" >"$state/set-aside-now"
  cmp -s "$state/set-aside" "$state/set-aside-now" ||
    fail "the set-aside data root changed: diff $state/set-aside $state/set-aside-now"
  [[ $(sha256sum <"$work/host-a/deploy/.env.before-restore-$aside") == "$(cat "$state/set-aside-env")" ]] ||
    fail "the set-aside .env changed"
  ok "the set-aside data root is as it stopped: $(grep -c '^[a-z] ' "$state/set-aside") entries with the same owners, modes, sizes and times, $(grep -vc '^[a-z] ' "$state/set-aside") files with the same contents; .env.before-restore-$aside too"

  step "The guide's way back: the set-aside deployment put back"
  # From "Restore in place", step 4.
  cd "$work/host-a/deploy"
  compose down >>"$work/compose.log" 2>&1
  mv "$data" "$data.failed-restore-$aside"
  mv .env ".env.failed-restore-$aside"
  mv "$data.before-restore-$aside" "$data"
  mv ".env.before-restore-$aside" .env
  compose up -d >>"$work/compose.log" 2>&1
  wait_ready
  ok "the set-aside deployment started again; the restored one set aside as ${data##*/}.failed-restore-$aside"
  if [[ $authentik == true ]]; then
    wait_authentik
    ok "Authentik ready on the set-aside database"
  fi

  step "The deployment put back is the one set aside"
  same_server rollback
fi

# --------------------------------------------------------------- cleanup
step "Clean up"
cleanup_device
compose down >>"$work/compose.log" 2>&1
rm -rf "$data"
[[ $in_place == false ]] || rm -rf "$data.failed-restore-$aside"
ok "drill passed; report in $report"
