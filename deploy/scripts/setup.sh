#!/usr/bin/env bash
# Prepares a host for the EasyRMM Docker deployment:
#   - writes deploy/.env from .env.example with freshly generated secrets
#   - creates the data directories with the ownership the containers expect
#
# Usage (run from the deploy/ directory, as root or with sudo):
#   ./scripts/setup.sh --hostname rmm.example.com --acme-email you@example.com
#   ./scripts/setup.sh --hostname rmm.example.com --tls-mode offload --trusted-proxies 127.0.0.1/32
#   ./scripts/setup.sh --hostname rmm.example.com --tls-mode manual \
#       --cert-file /etc/easyrmm/tls/fullchain.pem --key-file /etc/easyrmm/tls/privkey.pem
#   ./scripts/setup.sh --hostname 203.0.113.10        (no DNS: the server's own CA)
#   ./scripts/setup.sh --hostname rmm.example.com --with-authentik
#
# Options for IP access (ADR-0016): --ip-addresses 203.0.113.10,... lists the
# addresses to answer on (default: detected); --no-ip-access turns it off.
#
# Patching runs in this deployment: EasyPatch's engine, on loopback. To
# bring a standalone EasyPatch's data over, see scripts/import-easypatch.sh.
#
# --with-authentik makes Authentik everyone's sign-in (ADR-0044): it asks for
# Authentik's name (such as auth.example.com) and the administrator's email,
# or takes them from --authentik-hostname and --admin-email, and prints the
# administrator's invitation link. --new-invitation prints another.
#
# An existing .env is never overwritten (its secrets protect existing data):
# setup.sh only adds secrets that later versions need and it lacks, and
# removes settings that no longer exist.
set -euo pipefail

self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(dirname "$0")/.."

hostname=""
mesh_hostname=""
tls_mode=""
acme_email=""
trusted_proxies=""
cert_file=""
key_file=""
data_root="/srv/easyrmm"
ip_access="true"
ip_addresses=""

with_authentik=false
authentik_hostname=""
admin_email=""
new_invitation=false

usage() {
  # The comment block at the top of this file.
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$self"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hostname) hostname="${2:-}"; shift 2 ;;
    --mesh-hostname) mesh_hostname="${2:-}"; shift 2 ;;
    --tls-mode) tls_mode="${2:-}"; shift 2 ;;
    --acme-email) acme_email="${2:-}"; shift 2 ;;
    --trusted-proxies) trusted_proxies="${2:-}"; shift 2 ;;
    --cert-file) cert_file="${2:-}"; shift 2 ;;
    --key-file) key_file="${2:-}"; shift 2 ;;
    --data-root) data_root="${2:-}"; shift 2 ;;
    --ip-addresses) ip_addresses="${2:-}"; shift 2 ;;
    --no-ip-access) ip_access="false"; shift ;;
    --with-authentik) with_authentik=true; shift ;;
    --authentik-hostname) with_authentik=true; authentik_hostname="${2:-}"; shift 2 ;;
    --admin-email) admin_email="${2:-}"; shift 2 ;;
    --new-invitation) new_invitation=true; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }

# --- Authentik (--with-authentik, --new-invitation; ADR-0044) -----------------
# Authentik as everyone's sign-in. Its services are in docker-compose.yml
# (profile "authentik"), its blueprint and start-up in docker/authentik/.
# setup.sh cannot reach Authentik before it runs, so it decides the
# administrator's invitation here (id, email, expiry) and leaves it in
# ${data_root}/authentik/invitations/pending; the authentik-setup service
# creates it in Authentik at the next `docker compose up -d`.
authentik_valid_email='^[A-Za-z0-9._%+-]+@([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'

# authentik_ask fills in what --with-authentik needs, asking when it can.
authentik_ask() {
  [[ $(id -u) -eq 0 ]] || die "--with-authentik needs root (sudo): Authentik's files belong to its own user"
  if [[ -z "$authentik_hostname" ]]; then
    [[ -t 0 ]] || die "--authentik-hostname is required when setup.sh cannot ask"
    read -r -p "Sign-in name for Authentik (such as auth.example.com): " authentik_hostname
  fi
  if [[ -z "$admin_email" ]]; then
    [[ -t 0 ]] || die "--admin-email is required when setup.sh cannot ask"
    read -r -p "Administrator's email address: " admin_email
  fi
  authentik_hostname="${authentik_hostname,,}"
  authentik_hostname="${authentik_hostname%.}"
  admin_email="${admin_email,,}"
  [[ "$authentik_hostname" =~ $valid_host ]] || die "the sign-in name must be a DNS name such as auth.example.com"
  [[ "$authentik_hostname" != "$hostname" && "$authentik_hostname" != "${mesh_hostname:-mesh.$hostname}" ]] ||
    die "the sign-in name must differ from EasyRMM's own names"
  [[ "$admin_email" =~ $authentik_valid_email ]] || die "the administrator's email must be an address such as admin@example.com"
  [[ "$tls_mode" != "offload" ]] || die "--with-authentik needs EasyRMM's own TLS (acme, manual or internal): its edge serves Authentik's name"
  # ACME's account address, when none is given: the administrator's.
  [[ -n "$acme_email" ]] || acme_email="$admin_email"
}

# authentik_env writes Authentik's settings and secrets to .env.
authentik_env() {
  set_setting EASYRMM_AUTHENTIK_HOSTNAME "$authentik_hostname"
  set_setting EASYRMM_AUTHENTIK_ADMIN_EMAIL "$admin_email"
  fill_secret EASYRMM_AUTHENTIK_CLIENT_SECRET "$(openssl rand -hex 32)"
  fill_secret AUTHENTIK_SECRET_KEY "$(openssl rand -hex 50)"
  fill_secret AUTHENTIK_DB_PASSWORD "$(openssl rand -hex 32)"
  local profiles
  profiles=$(sed -n 's/^COMPOSE_PROFILES=//p' .env | tail -n 1)
  case ",$profiles," in
    *,authentik,*) ;;
    ,,) set_setting COMPOSE_PROFILES authentik ;;
    *) set_setting COMPOSE_PROFILES "$profiles,authentik" ;;
  esac
  echo "Sign-in: Authentik at https://${authentik_hostname} (COMPOSE_PROFILES=$(sed -n 's/^COMPOSE_PROFILES=//p' .env | tail -n 1))."
}

# authentik_invite decides a 7-day, single-use invitation for the
# administrator's email and prints its link. Authentik's user (uid 1000)
# owns the pending file; the authentik-setup service creates the invitation
# from it and removes it.
authentik_invite() {
  local dir="$1" host="$2" email="$3" h id expires
  h=$(openssl rand -hex 16)
  id="${h:0:8}-${h:8:4}-4${h:13:3}-$(printf '%x' $(( (0x${h:16:1} & 3) | 8 )))${h:17:3}-${h:20:12}"
  expires=$(( $(date +%s) + 7 * 24 * 3600 ))
  (umask 077 && printf 'id=%s\nemail=%s\nexpires=%s\n' "$id" "$email" "$expires" > "$dir/pending.tmp")
  chown 1000:1000 "$dir/pending.tmp"
  mv "$dir/pending.tmp" "$dir/pending"
  authentik_link="https://${host}/if/flow/easyrmm-enrollment/?itoken=${id}"
  echo "Invitation for ${email}, valid for 7 days and once:"
  echo "  ${authentik_link}"
}

# authentik_files makes Authentik's directories, akadmin's password (only
# once) and the administrator's first invitation.
authentik_files() {
  install -d -m 0755 "$data_root/authentik"
  for d in data secrets invitations; do
    install -d -m 0700 -o 1000 -g 1000 "$data_root/authentik/$d"
  done
  local pw="$data_root/authentik/secrets/akadmin-password"
  if [[ ! -s "$pw" ]]; then
    (umask 077 && openssl rand -base64 30 | tr '+/' '-_' > "$pw")
    chown 1000:1000 "$pw"
    chmod 0600 "$pw"
    echo "Authentik's own administrator is akadmin; its password is in ${pw} (mode 600)."
  fi
  if [[ ! -e "$data_root/authentik/invitations/issued" ]]; then
    authentik_invite "$data_root/authentik/invitations" "$authentik_hostname" "$admin_email"
    touch "$data_root/authentik/invitations/issued"
  else
    authentik_link=""
    echo "An invitation was issued before; ./scripts/setup.sh --new-invitation prints another."
  fi
}

authentik_next() {
  echo
  echo "Next:"
  if [[ "$is_ip" == true ]]; then
    echo "  1. Point DNS for ${authentik_hostname} at this server (${hostname})."
  else
    echo "  1. Point DNS for ${hostname}, ${mesh_hostname:-mesh.${hostname}} and ${authentik_hostname} at this server."
  fi
  echo "  2. Allow inbound TCP 443 (and 80 for ACME HTTP-01), and outbound HTTPS to"
  echo "     github.com for MeshCentral's first-start agent download."
  echo "  3. docker compose up -d"
  if [[ -n "$authentik_link" ]]; then
    echo "  4. Open the invitation link above, choose a password and set up a second factor."
    echo "     You land in EasyRMM as its super administrator."
  else
    echo "  4. Sign in at https://${hostname}/ with Authentik."
  fi
}

# new_invitation_only is --new-invitation: another invitation for the
# administrator, for when the first expired or was lost.
new_invitation_only() {
  [[ $(id -u) -eq 0 ]] || die "--new-invitation needs root (sudo)"
  [[ -e .env ]] || die "no .env here: run setup.sh --with-authentik first"
  local host email root
  host=$(sed -n 's/^EASYRMM_AUTHENTIK_HOSTNAME=//p' .env | tail -n 1)
  email=$(sed -n 's/^EASYRMM_AUTHENTIK_ADMIN_EMAIL=//p' .env | tail -n 1)
  root=$(sed -n 's/^EASYRMM_DATA_ROOT=//p' .env | tail -n 1)
  [[ -n "$host" && -n "$email" ]] || die "Authentik is not set up in .env: run setup.sh --with-authentik"
  [[ -d "${root:-/srv/easyrmm}/authentik/invitations" ]] || die "${root:-/srv/easyrmm}/authentik/invitations is missing: run setup.sh --with-authentik"
  authentik_invite "${root:-/srv/easyrmm}/authentik/invitations" "$host" "$email"
  touch "${root:-/srv/easyrmm}/authentik/invitations/issued"
  echo "It works after the next: docker compose up -d"
  echo "(Any earlier invitation of setup.sh's that is still unused stops working then.)"
}
if [[ "$new_invitation" == true ]]; then
  new_invitation_only
  exit 0
fi

valid_host='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
valid_ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
valid_ipv6='^[0-9a-f]*:[0-9a-f:.]*$'
hostname="${hostname,,}"
mesh_hostname="${mesh_hostname,,}"
[[ -n "$hostname" ]] || die "--hostname is required"
url_host="$hostname"
is_ip=false
if [[ "$hostname" =~ $valid_ipv4 ]]; then
  is_ip=true
elif [[ "$hostname" =~ $valid_ipv6 ]]; then
  is_ip=true
  url_host="[$hostname]"
elif ! [[ "$hostname" =~ $valid_host ]]; then
  die "--hostname must be a DNS name such as rmm.example.com, or an IP address"
fi
if [[ -z "$tls_mode" ]]; then
  tls_mode="acme"
  [[ "$is_ip" == true ]] && tls_mode="internal"
fi
if [[ "$is_ip" == true ]]; then
  [[ -z "$mesh_hostname" ]] || die "--mesh-hostname does not apply to an IP address: remote sessions use port 4443 of the same address"
  [[ "$tls_mode" != "acme" ]] || die "an IP address cannot get a certificate from ACME: use --tls-mode internal (the default) or manual"
fi
[[ -z "$ip_addresses" || "$ip_addresses" =~ ^[0-9A-Fa-f:.,]+$ ]] || die "--ip-addresses must be a comma-separated list of IP addresses"
if [[ -n "$mesh_hostname" ]]; then
  [[ "$mesh_hostname" =~ $valid_host ]] || die "--mesh-hostname must be a DNS name"
  [[ "$mesh_hostname" != "$hostname" ]] || die "--mesh-hostname must differ from --hostname"
fi
if [[ "$with_authentik" == true ]]; then
  authentik_ask
fi
case "$tls_mode" in
  acme) [[ -n "$acme_email" ]] || die "--acme-email is required for --tls-mode acme" ;;
  manual) [[ -n "$cert_file" && -n "$key_file" ]] || die "--cert-file and --key-file are required for --tls-mode manual" ;;
  offload) [[ -n "$trusted_proxies" ]] || die "--trusted-proxies is required for --tls-mode offload" ;;
  internal) ;;
  *) die "--tls-mode must be acme, manual, internal or offload" ;;
esac
[[ "$data_root" =~ ^/[A-Za-z0-9_./-]*$ ]] || die "--data-root must be an absolute path (letters, digits, _ . / - only)"
[[ -z "$acme_email" || "$acme_email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "--acme-email is not a valid address"
[[ -z "$trusted_proxies" || "$trusted_proxies" =~ ^[0-9A-Fa-f:.,/]+$ ]] || die "--trusted-proxies must be a comma-separated list of addresses or CIDR ranges"
for f in "$cert_file" "$key_file"; do
  [[ -z "$f" || "$f" =~ ^/[A-Za-z0-9_./-]+$ ]] || die "certificate paths must be absolute paths inside the container (letters, digits, _ . / - only)"
done
command -v openssl >/dev/null || die "openssl is required"

if [[ -e .env ]]; then
  echo ".env already exists; leaving it unchanged."
else
  umask 077
  # Hex passwords are safe inside connection URLs without escaping.
  pg_pw=$(openssl rand -hex 32)
  owner_pw=$(openssl rand -hex 32)
  app_pw=$(openssl rand -hex 32)
  secret_key=$(openssl rand -base64 32)
  listen_http=":80"
  [[ "$tls_mode" == "offload" ]] && listen_http=""
  # Values are restricted above to characters that need no escaping in sed.
  sed -e "s|^EASYRMM_PUBLIC_URL=.*|EASYRMM_PUBLIC_URL=https://${url_host}|" \
      -e "s|^EASYRMM_MESH_PUBLIC_URL=.*|EASYRMM_MESH_PUBLIC_URL=${mesh_hostname:+https://${mesh_hostname}}|" \
      -e "s|^EASYRMM_TLS_MODE=.*|EASYRMM_TLS_MODE=${tls_mode}|" \
      -e "s|^EASYRMM_ACME_EMAIL=.*|EASYRMM_ACME_EMAIL=${acme_email}|" \
      -e "s|^EASYRMM_LISTEN_HTTP=.*|EASYRMM_LISTEN_HTTP=${listen_http}|" \
      -e "s|^EASYRMM_TLS_CERT_FILE=.*|EASYRMM_TLS_CERT_FILE=${cert_file}|" \
      -e "s|^EASYRMM_TLS_KEY_FILE=.*|EASYRMM_TLS_KEY_FILE=${key_file}|" \
      -e "s|^EASYRMM_TRUSTED_PROXIES=.*|EASYRMM_TRUSTED_PROXIES=${trusted_proxies}|" \
      -e "s|^EASYRMM_IP_ACCESS=.*|EASYRMM_IP_ACCESS=${ip_access}|" \
      -e "s|^EASYRMM_IP_ADDRESSES=.*|EASYRMM_IP_ADDRESSES=${ip_addresses}|" \
      -e "s|^EASYRMM_DATA_ROOT=.*|EASYRMM_DATA_ROOT=${data_root}|" \
      -e "s|^EASYRMM_TLS_DIR=.*|EASYRMM_TLS_DIR=${data_root}/tls|" \
      -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${pg_pw}|" \
      -e "s|^EASYRMM_DB_OWNER_PASSWORD=.*|EASYRMM_DB_OWNER_PASSWORD=${owner_pw}|" \
      -e "s|^EASYRMM_DB_APP_PASSWORD=.*|EASYRMM_DB_APP_PASSWORD=${app_pw}|" \
      -e "s|^EASYRMM_SECRET_KEY=.*|EASYRMM_SECRET_KEY=${secret_key}|" \
      .env.example > .env
  chmod 600 .env
  echo "Wrote deploy/.env (mode 600). Back it up somewhere safe: it holds the encryption key."
fi

# fill_secret KEY VALUE: sets KEY in .env if it is missing or empty, and
# leaves it alone otherwise. Secrets later versions need reach an older .env
# this way without touching the ones that protect existing data.
fill_secret() {
  if grep -q "^$1=." .env; then
    return
  elif grep -q "^$1=\$" .env; then
    sed -i "s|^$1=\$|$1=$2|" .env
  else
    printf '%s=%s\n' "$1" "$2" >> .env
  fi
  echo "Added $1 to .env."
}
# set_setting KEY VALUE: sets KEY in .env, replacing any value it has.
set_setting() {
  if grep -q "^$1=" .env; then
    sed -i "s|^$1=.*|$1=$2|" .env
  else
    printf '%s=%s\n' "$1" "$2" >> .env
  fi
}
umask 077
fill_secret EASYPATCH_DB_OWNER_PASSWORD "$(openssl rand -hex 32)"
fill_secret EASYPATCH_DB_APP_PASSWORD "$(openssl rand -hex 32)"
fill_secret EASYRMM_PATCHING_KEY "$(openssl rand -base64 32)"
# Settings from before the patching engine always ran here: it no longer
# has a switch, nor its services a profile.
if grep -q '^EASYRMM_PATCHING=' .env; then
  sed -i '/^EASYRMM_PATCHING=/d' .env
  echo "Removed EASYRMM_PATCHING from .env: patching always runs in this deployment."
fi
profiles=$(sed -n 's/^COMPOSE_PROFILES=//p' .env | tail -n 1)
if [[ ",$profiles," == *,patching,* ]]; then
  profiles=$(printf '%s\n' "${profiles//,/$'\n'}" | grep -vx patching | paste -sd , - || true)
  if [[ -n "$profiles" ]]; then
    set_setting COMPOSE_PROFILES "$profiles"
  else
    sed -i '/^COMPOSE_PROFILES=/d' .env
  fi
  echo "Removed the patching profile from COMPOSE_PROFILES in .env: its services have none."
fi
if [[ "$with_authentik" == true ]]; then
  authentik_env
fi

if [[ $(id -u) -ne 0 ]]; then
  echo "Not running as root: create these directories yourself:" >&2
  echo "  ${data_root}/server (owner 65532:65532, mode 700)" >&2
  echo "  ${data_root}/postgres (owner 70:70, mode 700)" >&2
  echo "  ${data_root}/tls (mode 750)" >&2
  echo "  ${data_root}/meshcentral-config (owner 65532:65532, mode 700)" >&2
  echo "  ${data_root}/meshcentral/{data,files,backups} (owner 65532:65532, mode 700)" >&2
  echo "  ${data_root}/easypatch/{keys,winget} (owner 1654:1654, mode 700)" >&2
  exit 0
fi
install -d -m 0755 "$data_root"
install -d -m 0700 -o 65532 -g 65532 "$data_root/server"
# The PostgreSQL 18 image mounts this directory above its data directory
# (/var/lib/postgresql) and runs as postgres, uid 70 in the Alpine image:
# owned by root with mode 700, PostgreSQL could not reach its data.
install -d -m 0700 -o 70 -g 70 "$data_root/postgres"
install -d -m 0750 -o root -g 65532 "$data_root/tls"
install -d -m 0700 -o 65532 -g 65532 "$data_root/meshcentral-config"
install -d -m 0755 "$data_root/meshcentral"
for d in data files backups; do
  install -d -m 0700 -o 65532 -g 65532 "$data_root/meshcentral/$d"
done
# The patching engine's image runs as its "app" user, uid 1654. Its agent
# packages come with the image.
install -d -m 0755 "$data_root/easypatch"
for d in keys winget; do
  install -d -m 0700 -o 1654 -g 1654 "$data_root/easypatch/$d"
done
echo "Data directories ready under ${data_root}."
if [[ "$with_authentik" == true ]]; then
  authentik_files
  authentik_next
  exit 0
fi
echo
echo "Next:"
echo "  1. Point DNS for ${hostname} and ${mesh_hostname:-mesh.${hostname}} at this server."
echo "  2. Allow inbound TCP 443 (and 80 for ACME HTTP-01), and outbound HTTPS to"
echo "     github.com for MeshCentral's first-start agent download."
echo "  3. docker compose up -d"
echo "  4. Open https://${hostname}/ and enter the setup token from:"
echo "       ${data_root}/server/setup-token"
