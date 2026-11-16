#!/usr/bin/env bash
# Backup and restore drill: follows docs/operations/backup-restore.md on a
# disposable deployment and checks that the restored server is the same
# server to its users and agents.
#
#   sudo scripts/drill/backup-restore.sh WORKDIR
#
# 1. A source host: this checkout, deploy/scripts/setup.sh and the Compose
#    stack, on DRILL_ADDR (127.0.0.2 by default) so it does not collide with
#    anything on the host's own addresses.
# 2. Real state: first-run setup, an administrator with an authenticator, a
#    site, a deployment token, and a real agent in a container that enrolls
#    and runs a job.
# 3. The backup, with the guide's commands.
# 4. The host is lost: the stack, its data root and its checkout go.
# 5. A new host: a fresh checkout, then the guide's restore steps.
# 6. Checks against the restored server:
#    - TLS against the authority saved before the backup;
#    - sign-in with the same password and authenticator;
#    - the audit chain;
#    - the same agent, never re-enrolled, reconnecting and running a new
#      job signed by the restored key;
#    - MeshCentral's identity.
#
# Needs root (setup.sh sets the data directories' owners), Docker Compose,
# curl, jq, openssl, and network access for the device container's
# packages. See lib.sh for the ports it uses.
set -Eeuo pipefail
# shellcheck source=scripts/drill/lib.sh
source "$(dirname "$0")/lib.sh"

drill_workdir "${1:?usage: backup-restore.sh WORKDIR}"
device_image=${DRILL_DEVICE_IMAGE:-debian:13}
device="$COMPOSE_PROJECT_NAME-device"
backups="$work/backups"
mkdir -p "$backups"
chmod 700 "$backups"
cleanup_device() { docker rm -f "$device" >/dev/null 2>&1 || true; }

# ---------------------------------------------------------------- source
step "Source host: setup.sh and the Compose stack on $addr"
stack_up "$work/host-a"
ok "certificate authority saved"

step "Real state: setup, an administrator with an authenticator, an agent, a job"
first_admin
ok "administrator signed in with an authenticator"
org=$(call 200 GET /api/v1/organizations | jq -r '.items[0].id')
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
  out=$(call 200 GET "/api/v1/job-runs/$(jq -r '.runs[0].id' <<<"$j")" | jq -r '.stdout // ""')
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

# ---------------------------------------------------------------- backup
step "Backup with the guide's commands"
# From docs/operations/backup-restore.md, "Back up", with this drill's
# backup directory and data root.
cd "$work/host-a/deploy"
ts=$(date -u +%Y%m%dT%H%M%SZ)
compose exec -T -u postgres postgres pg_dump -p 15432 \
  --format=custom easyrmm >"$backups/db-$ts.dump" || fail "pg_dump failed"
tar -C "$work/host-a/deploy" -czf "$backups/env-$ts.tgz" .env
tar -C "$data" -czf "$backups/server-$ts.tgz" server
compose stop meshcentral >>"$work/compose.log" 2>&1
tar -C "$data" -czf "$backups/meshcentral-$ts.tgz" meshcentral
compose start meshcentral >>"$work/compose.log" 2>&1
ok "backup written: $(find "$backups" -type f -printf '%f (%s bytes) ')"

# A change after the backup: it must not survive the restore.
call 201 POST "/api/v1/organizations/$org/sites" '{"name":"After the backup","timezone":"UTC"}' >/dev/null

# ---------------------------------------------------------------- loss
step "The host is lost"
compose down >>"$work/compose.log" 2>&1
cd "$work"
rm -rf "$data" "$work/host-a"
ok "stack removed, data root and checkout deleted; the agent keeps trying"

# --------------------------------------------------------------- restore
step "New host: the guide's restore steps"
checkout "$work/host-b"
cd "$work/host-b/deploy"
# 1. Restore deploy/.env, the server directory and MeshCentral's data.
tar -C "$work/host-b/deploy" -xzf "$backups/env-$ts.tgz"
mkdir -p "$data"
tar -C "$data" -xzf "$backups/server-$ts.tgz"
tar -C "$data" -xzf "$backups/meshcentral-$ts.tgz"
# 2. setup.sh with the same host name keeps the restored .env.
out=$(./scripts/setup.sh --hostname "$addr" --data-root "$data")
[[ "$out" == *"leaving it unchanged"* ]] || fail "setup.sh did not keep the restored .env: $out"
# 3. PostgreSQL alone; its first start creates the roles and database.
compose up -d postgres >>"$work/compose.log" 2>&1
for _ in $(seq 1 60); do
  [[ $(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q postgres)") == healthy ]] && break
  sleep 2
done
# 4. The dump, as the superuser.
compose exec -T -u postgres postgres pg_restore -p 15432 \
  --dbname=easyrmm --exit-on-error <"$backups/db-$ts.dump" || fail "pg_restore failed"
# 5. Everything else.
compose up -d >>"$work/compose.log" 2>&1
wait_ready
ok "restored server ready"

# --------------------------------------------------------------- checks
step "The restored server is the same server"
curl -fsS --cacert "$state/ca.pem" -o /dev/null "$url/" || fail "TLS against the saved authority failed"
ok "TLS verifies against the authority saved before the backup"

sign_in
ok "signed in with the same password and authenticator (the sealed secret opens)"

after_audit=$(call 200 GET /api/v1/audit/verify)
[[ $(jq -r '.firstBadId // empty' <<<"$after_audit") == "" ]] || fail "audit chain broken after the restore: $after_audit"
[[ $(jq -r .checked <<<"$after_audit") -ge $audit_checked ]] || fail "audit records lost: $after_audit"
ok "audit chain intact: $(jq -r .checked <<<"$after_audit") records"

[[ $(call 200 GET "/api/v1/organizations/$org/sites" | jq '[.items[] | select(.name == "After the backup")] | length') == 0 ]] ||
  fail "a site created after the backup survived"
ok "the restored data is the backup's: a site created after it is gone"

restored_at=$(date -u +%s)
seen=""
for _ in $(seq 1 100); do
  d=$(device_json)
  last=$(jq -r '.lastSeenAt // empty' <<<"$d")
  if [[ -n "$last" && $(date -u -d "$last" +%s) -gt $restored_at ]]; then
    seen=$last
    break
  fi
  sleep 3
done
[[ -n "$seen" && $(jq -r .id <<<"$d") == "$dev" ]] || fail "the agent did not come back (docker logs $device)"
ok "the same agent reconnected with its device key: device $dev, last seen $seen"
run_job after

if [[ "$remote_agent" == true ]]; then
  for _ in $(seq 1 60); do
    [[ $(device_json | jq -r .remoteOnline) == true ]] && break
    sleep 3
  done
  [[ $(device_json | jq -r .remoteOnline) == true ]] || fail "MeshAgent did not reconnect"
  ok "MeshAgent reconnected to the restored MeshCentral"
fi
(cd "$data/meshcentral/data" && sha256sum -c --quiet "$state/meshcentral-identity") || fail "MeshCentral's identity changed"
ok "MeshCentral's identity is unchanged"

# --------------------------------------------------------------- cleanup
step "Clean up"
cleanup_device
compose down >>"$work/compose.log" 2>&1
rm -rf "$data"
ok "drill passed; report in $report"
