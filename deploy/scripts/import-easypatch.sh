#!/usr/bin/env bash
# Imports a standalone EasyPatch server (1.4 to 1.10) into this EasyRMM
# deployment's patching engine (ADR-0045). Its organizations, sites,
# endpoints, policies, update history, schedules, reports and notification
# settings come across; its organizations and sites become EasyRMM's; its
# agents keep working on its old name, which this server then answers. Its
# user accounts and API tokens are not imported: people sign in to EasyRMM.
#
# Usage (run from the deploy/ directory, as root, after setup.sh):
#   ./scripts/import-easypatch.sh --backup /root/easypatch-backup --hostname patch.example.com
#
#   --backup DIR      a folder made by EasyPatch's scripts/backup.sh:
#                     easypatch.dump, dpkeys.tar and SHA256SUMS
#   --hostname NAME   the name EasyPatch's agents connect to (its
#                     EASYPATCH_DOMAIN); repeat it for further names
#   --yes             do not ask before replacing the patching engine's data
#
# Before: stop the old EasyPatch server for good and back it up with its
# scripts/backup.sh. After: point the old name's DNS at this server. The
# patching engine must have no agents of its own yet. The engine's database
# before the import is kept, renamed. See docs/operations/import-easypatch.md.
set -euo pipefail

self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(dirname "$0")/.."

backup=""
names=()
assume_yes=false

usage() {
  # The comment block at the top of this file.
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$self"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backup) backup="${2:-}"; shift 2 ;;
    --hostname) names+=("${2:-}"); shift 2 ;;
    --yes) assume_yes=true; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

# After the engine's database is replaced, a failure says how to finish or
# go back.
before=""
unpacked=""
on_exit() {
  local status=$?
  if [[ -n "$unpacked" ]]; then
    rm -rf -- "$unpacked"
  fi
  if [[ $status -ne 0 && -n "$before" ]]; then
    cat >&2 <<EOF

The import stopped after the patching engine's database was replaced; its
database from before is kept as ${before}. To finish, fix the problem above
and run, from deploy/:
  docker compose up -d --wait easypatch-api
  docker compose run --rm --no-deps server import-easypatch
  docker compose up -d
To go back instead: docker compose stop server easypatch-worker easypatch-api;
rename the database ${before} back to easypatch (see
docs/operations/import-easypatch.md); remove the names from
EASYRMM_PATCHING_AGENT_HOSTNAMES in .env; docker compose up -d.
EOF
  fi
}
trap on_exit EXIT

# ------------------------------------------------------------------ checks

[[ $(id -u) -eq 0 ]] || die "run as root: the engine's key ring is owned by its container user"
[[ -f .env ]] || die "deploy/.env is missing: run scripts/setup.sh first"
[[ -n "$backup" ]] || die "--backup is required"
[[ ${#names[@]} -gt 0 ]] || die "--hostname is required: the name EasyPatch's agents connect to"
backup="$(cd "$backup" 2>/dev/null && pwd)" || die "--backup: no such folder"
docker compose version >/dev/null 2>&1 || die "docker compose is not available"

setting() { sed -n "s/^$1=//p" .env | tail -n 1; }
[[ -z "$(setting EASYRMM_EASYPATCH_HOSTNAME)" ]] ||
  die "EASYRMM_EASYPATCH_HOSTNAME is set in .env: a co-hosted EasyPatch is replaced by the patching engine; remove the setting first"

valid_host='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
for i in "${!names[@]}"; do
  n="${names[$i],,}"
  n="${n%.}"
  [[ "$n" =~ $valid_host ]] || die "--hostname ${names[$i]}: must be a DNS name such as patch.example.com"
  names[i]="$n"
done
# The names this server answers for imported agents: those already there,
# and these.
merged="$(setting EASYRMM_PATCHING_AGENT_HOSTNAMES)"
for n in "${names[@]}"; do
  [[ ",$merged," == *",$n,"* ]] || merged="${merged:+$merged,}$n"
done

for f in easypatch.dump dpkeys.tar SHA256SUMS; do
  [[ -f "$backup/$f" ]] || die "$backup/$f is missing: is this a folder made by EasyPatch's scripts/backup.sh?"
done
step "Checking the backup"
(cd "$backup" && sha256sum --check --ignore-missing --quiet SHA256SUMS) || die "the backup's checksums do not match: it is damaged"
[[ "$(head -c 5 "$backup/easypatch.dump")" == "PGDMP" ]] || die "easypatch.dump is not a PostgreSQL custom-format dump"
# The key ring: key-<id>.xml files only. Anything else (links, other
# paths) is refused rather than unpacked as root.
keys=()
while read -r perms _ _ _ _ name rest; do
  if [[ "$perms" == d* && "$name" == "./" && -z "$rest" ]]; then
    continue
  fi
  [[ "$perms" == -* && -z "$rest" && "$name" =~ ^(\./)?key-[0-9a-f-]{36}\.xml$ ]] ||
    die "dpkeys.tar holds something other than Data Protection keys: $perms $name $rest"
  keys+=("${name#./}")
done < <(tar -tvf "$backup/dpkeys.tar")
[[ ${#keys[@]} -gt 0 ]] || die "dpkeys.tar holds no keys"
echo "The backup is complete: a database and ${#keys[@]} Data Protection key(s)."

if [[ "$(setting EASYRMM_TLS_MODE)" == "manual" ]]; then
  # The edge refuses to start when its certificate does not cover a name
  # it answers.
  cert="$(setting EASYRMM_TLS_CERT_FILE)"
  tls_dir="$(setting EASYRMM_TLS_DIR)"
  host_cert="${tls_dir:-/srv/easyrmm/tls}/${cert#/etc/easyrmm/tls/}"
  if [[ "$cert" == /etc/easyrmm/tls/* && -r "$host_cert" ]]; then
    for n in "${names[@]}"; do
      openssl x509 -in "$host_cert" -noout -checkhost "$n" | grep -q "does match" ||
        die "the certificate in EASYRMM_TLS_CERT_FILE is not valid for $n: add the name to it first"
    done
  else
    echo "warning: could not read $cert to check it covers ${names[*]}; it must, or the server will not start" >&2
  fi
fi

compose() { docker compose "$@"; }
# psql and pg_restore in the PostgreSQL container, as its superuser over
# the local socket.
psql_super() { compose exec -T -u postgres postgres psql -p 15432 -X -q -v ON_ERROR_STOP=1 "$@"; }

step "Starting PostgreSQL"
compose up -d --wait postgres
compose run --rm --no-deps easypatch-db-init

# EasyRMM checks its settings with the new names before anything changes.
if ! checked="$(compose run --rm --no-deps -e EASYRMM_PATCHING_AGENT_HOSTNAMES="$merged" server migrate 2>&1)"; then
  echo "$checked" >&2
  die "EasyRMM does not accept these settings (see above); nothing was changed"
fi

has_endpoints="$(psql_super -d easypatch -tAc "SELECT to_regclass('public.endpoints') IS NOT NULL")"
if [[ "$has_endpoints" == "t" ]]; then
  active="$(psql_super -d easypatch -tAc "SELECT count(*) FROM endpoints WHERE status = 'Active'")"
  [[ "$active" == "0" ]] ||
    die "the patching engine here already has $active agent(s); an import replaces its data, so it is only possible before EasyRMM patches any device"
fi

echo
echo "This replaces the patching engine's data with the backup's, and has this"
echo "server answer EasyPatch's agents on: ${names[*]}."
echo "EasyRMM stops for a minute or two. The engine's data before the import is kept."
if ! $assume_yes; then
  [[ -t 0 ]] || die "not a terminal: pass --yes to go ahead"
  read -r -p "Type 'import' to go ahead: " answer
  [[ "$answer" == "import" ]] || die "not imported"
fi

step "Restoring the database (as easypatch_import)"
psql_super -d postgres <<'SQL'
DROP DATABASE IF EXISTS easypatch_import WITH (FORCE);
CREATE DATABASE easypatch_import OWNER easypatch_owner ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE easypatch_import FROM PUBLIC;
\connect easypatch_import
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
compose exec -T -u postgres postgres pg_restore -p 15432 -d easypatch_import --no-owner --no-privileges \
  --role=easypatch_owner --exit-on-error --single-transaction < "$backup/easypatch.dump"

step "Preparing it for the patching engine"
# Checks the release, brings it to the engine's schema and disables
# EasyPatch's own accounts (exit 3: refused, with the reason).
if ! compose run --rm --no-deps -e Database__Name=easypatch_import easypatch-migrate prepare-import; then
  psql_super -d postgres -c "DROP DATABASE IF EXISTS easypatch_import WITH (FORCE)"
  die "the backup cannot be imported (see above); nothing was changed"
fi

step "Replacing the patching engine's database"
compose stop server easypatch-worker easypatch-api
stamp="easypatch_before_import_$(date -u +%Y%m%d%H%M%S)"
psql_super -d postgres <<SQL
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname IN ('easypatch', 'easypatch_import') AND pid <> pg_backend_pid();
ALTER DATABASE easypatch RENAME TO ${stamp};
ALTER DATABASE easypatch_import RENAME TO easypatch;
SQL
before="$stamp"
echo "The engine's database before the import is kept as ${before}."
# Grants the engine's runtime role the restored tables.
compose run --rm --no-deps easypatch-db-init

step "Adding EasyPatch's Data Protection keys"
data_root="$(setting EASYRMM_DATA_ROOT)"
keys_dir="${data_root:-/srv/easyrmm}/easypatch/keys"
install -d -m 0700 -o 1654 -g 1654 "$keys_dir"
unpacked="$(mktemp -d)"
# Every entry was checked above: key files, and the folder itself.
tar -xf "$backup/dpkeys.tar" -C "$unpacked" --no-same-owner --no-same-permissions
for k in "${keys[@]}"; do
  [[ -f "$unpacked/$k" && ! -L "$unpacked/$k" ]] || die "dpkeys.tar: $k did not unpack as a file"
  if [[ -e "$keys_dir/$k" ]]; then
    echo "  $k is there already"
  else
    install -m 0600 -o 1654 -g 1654 "$unpacked/$k" "$keys_dir/$k"
    echo "  added $k"
  fi
done

step "Answering EasyPatch's agents on ${names[*]}"
if grep -q '^EASYRMM_PATCHING_AGENT_HOSTNAMES=' .env; then
  sed -i "s|^EASYRMM_PATCHING_AGENT_HOSTNAMES=.*|EASYRMM_PATCHING_AGENT_HOSTNAMES=${merged}|" .env
else
  printf 'EASYRMM_PATCHING_AGENT_HOSTNAMES=%s\n' "$merged" >> .env
fi
echo "EASYRMM_PATCHING_AGENT_HOSTNAMES=${merged} in .env."

step "Making EasyPatch's organizations and sites EasyRMM's"
compose up -d --wait easypatch-api
compose run --rm --no-deps server import-easypatch

step "Starting EasyRMM"
compose up -d
compose up -d --wait server easypatch-worker
before=""

cat <<EOF

Imported. Next:
  1. Point DNS for ${names[*]} at this server (and keep TCP 443 open to it).
     EasyPatch's agents reconnect within minutes once the name resolves here.
  2. Install EasyRMM's agent on the imported devices, in the organization
     the report above shows for them: Patching links each device to its
     EasyPatch agent as EasyRMM's agent reports it.
  3. Retire the old EasyPatch server. Keep its backup until the agents have
     all come across.
People sign in to EasyRMM; EasyPatch's accounts were disabled. Mail goes
through EasyRMM's mail server (Settings > Email).
EOF
