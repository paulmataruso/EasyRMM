#!/usr/bin/env bash
# Load and soak test: a fleet of simulated agents (tools/agentsim) against
# a disposable Compose deployment of this checkout, with the console in use.
#
#   sudo scripts/drill/soak.sh WORKDIR [DEVICES] [DURATION]
#
# DEVICES (2000) simulated agents enroll, then for DURATION (1h) each sends
# a heartbeat with metrics every minute, uploads its inventory once, and
# holds a job long poll open, each over its own TLS connection. Meanwhile,
# every minute, the drill:
# - lists the online devices as the console does, and times it;
# - samples the containers' CPU and memory and the database's size.
# Every ten minutes it runs a job on up to 500 devices and times it until
# every run has reported.
#
# Results in WORKDIR: report.txt, samples.csv, jobs.csv, agentsim.log and
# summary.json (per request type: counts, errors, latency percentiles).
#
# Needs root, Docker Compose, Go, curl, jq and openssl. See lib.sh for the
# ports it uses.
set -Eeuo pipefail
# shellcheck source=scripts/drill/lib.sh
source "$(dirname "$0")/lib.sh"

devices=${2:-2000}
duration=${3:-1h}
drill_workdir "${1:?usage: soak.sh WORKDIR [DEVICES] [DURATION]}"
command -v go >/dev/null || fail "missing go (to build tools/agentsim)"

step "Server: setup.sh and the Compose stack on $addr"
stack_up "$work/host"
first_admin
org=$(call 200 GET /api/v1/organizations | jq -r '.items[0].id')
site=$(call 201 POST "/api/v1/organizations/$org/sites" '{"name":"Soak","timezone":"UTC"}' | jq -r .id)
token=$(call 201 POST "/api/v1/sites/$site/enrollment-tokens" '{"name":"Simulated agents","expiresInDays":1}' | jq -r .secret)
script=$(call 201 POST /api/v1/scripts "$(jq -nc --arg o "$org" \
  '{organizationId:$o, name:"Soak", shell:"bash", body:"hostname", timeoutSeconds:60}')" | jq -r .id)
ok "administrator, site, deployment token and script ready"

step "$devices simulated agents for $duration"
(cd "$repo" && go build -o "$work/agentsim" ./tools/agentsim)
"$work/agentsim" -server "$url" -ca-file "$state/ca.pem" -token "$token" -devices "$devices" \
  -duration "$duration" -state "$state/agentsim.json" -out "$work/summary.json" -report 60s \
  >"$work/agentsim.log" 2>&1 &
sim=$!
trap 'kill "$sim" 2>/dev/null || true' EXIT

container() { compose ps -q "$1"; }
echo "time,online,list_seconds,server_cpu,server_mem,postgres_cpu,postgres_mem,meshcentral_mem,db_bytes" >"$work/samples.csv"
echo "time,devices,milliseconds,succeeded" >"$work/jobs.csv"
all_online_at=""
last_job=0
while kill -0 "$sim" 2>/dev/null; do
  started=$(date +%s)
  list=$(curl -sS --cacert "$state/ca.pem" -b "$state/cookies" -H "Origin: $url" -w '\n%{time_total}' "$url/api/v1/devices?status=online")
  list_seconds=${list##*$'\n'}
  online=$(jq '.items | length' <<<"${list%$'\n'*}" 2>/dev/null || echo 0)
  stats=$(docker stats --no-stream --format '{{.ID}} {{.CPUPerc}} {{.MemUsage}}' \
    "$(container server)" "$(container postgres)" "$(container meshcentral)")
  field() { awk -v id="${1:0:12}" -v f="$2" 'index($1, id) == 1 { print $f }' <<<"$stats"; }
  db_bytes=$(compose exec -T -u postgres postgres psql -p 15432 -Atc "select pg_database_size('easyrmm')" easyrmm)
  echo "$(date -u +%FT%TZ),$online,$list_seconds,$(field "$(container server)" 2),$(field "$(container server)" 3),$(field "$(container postgres)" 2),$(field "$(container postgres)" 3),$(field "$(container meshcentral)" 3),$db_bytes" >>"$work/samples.csv"

  if [[ -z "$all_online_at" && $online -ge $devices ]]; then
    all_online_at=$(date +%s)
    ok "all $devices devices online"
  fi
  # A job on up to 500 online devices every ten minutes once all are online.
  if [[ -n "$all_online_at" && $(($(date +%s) - last_job)) -ge 600 ]]; then
    last_job=$(date +%s)
    ids=$(jq -c '[.items[:500][].id]' <<<"${list%$'\n'*}")
    t0=$(date +%s%N)
    job=$(call 201 POST /api/v1/jobs "$(jq -nc --arg s "$script" --argjson d "$ids" '{scriptId:$s, deviceIds:$d}')" | jq -r .id)
    for _ in $(seq 1 150); do
      j=$(call 200 GET "/api/v1/jobs/$job")
      [[ $(jq -r .finished <<<"$j") == true ]] && break
      sleep 2
    done
    ms=$((($(date +%s%N) - t0) / 1000000))
    echo "$(date -u +%FT%TZ),$(jq length <<<"$ids"),$ms,$(jq -r '.counts.succeeded // 0' <<<"$j")" >>"$work/jobs.csv"
    ok "job on $(jq length <<<"$ids") devices: $(jq -r '.counts.succeeded // 0' <<<"$j") succeeded in ${ms} ms"
  fi
  sleep $((60 - ($(date +%s) - started) % 60))
done
wait "$sim" || fail "agentsim failed: $work/agentsim.log"
trap - EXIT

step "Results"
ok "agentsim: $(jq -c '.ops | with_entries(.value |= {ok, errors, p50, p95, p99})' "$work/summary.json")"
median() { tail -n +2 "$1" | cut -d, -f"$2" | sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }'; }
ok "online-device list: median $(median "$work/samples.csv" 3) s"
[[ $(wc -l <"$work/jobs.csv") -lt 2 ]] || ok "jobs: median $(median "$work/jobs.csv" 3) ms over $(($(wc -l <"$work/jobs.csv") - 1)) jobs"
ok "server memory at the end: $(tail -1 "$work/samples.csv" | cut -d, -f5); database: $(($(tail -1 "$work/samples.csv" | cut -d, -f9) / 1048576)) MiB"
compose exec -T -u postgres postgres psql -p 15432 -Atc \
  "select relname || ' ' || pg_size_pretty(pg_total_relation_size(c.oid)) from pg_class c join pg_namespace n on n.oid = c.relnamespace
   where n.nspname = 'public' and c.relkind = 'r' order by pg_total_relation_size(c.oid) desc limit 8" easyrmm | sed 's/^/   table /' | tee -a "$report"

step "Clean up"
compose down >>"$work/compose.log" 2>&1
rm -rf "$data"
ok "done; results in $work"
