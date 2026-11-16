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
#
# Options for IP access (ADR-0016): --ip-addresses 203.0.113.10,... lists the
# addresses to answer on (default: detected); --no-ip-access turns it off.
#
# An existing .env is never overwritten (its secrets protect existing data).
set -euo pipefail

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

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
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
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }

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

if [[ $(id -u) -ne 0 ]]; then
  echo "Not running as root: create these directories yourself:" >&2
  echo "  ${data_root}/server (owner 65532:65532, mode 700)" >&2
  echo "  ${data_root}/postgres (mode 700)" >&2
  echo "  ${data_root}/tls (mode 750)" >&2
  echo "  ${data_root}/meshcentral-config (owner 65532:65532, mode 700)" >&2
  echo "  ${data_root}/meshcentral/{data,files,backups} (owner 65532:65532, mode 700)" >&2
  exit 0
fi
install -d -m 0755 "$data_root"
install -d -m 0700 -o 65532 -g 65532 "$data_root/server"
install -d -m 0700 "$data_root/postgres"
install -d -m 0750 -o root -g 65532 "$data_root/tls"
install -d -m 0700 -o 65532 -g 65532 "$data_root/meshcentral-config"
install -d -m 0755 "$data_root/meshcentral"
for d in data files backups; do
  install -d -m 0700 -o 65532 -g 65532 "$data_root/meshcentral/$d"
done
echo "Data directories ready under ${data_root}."
echo
echo "Next:"
echo "  1. Point DNS for ${hostname} and ${mesh_hostname:-mesh.${hostname}} at this server."
echo "  2. Allow inbound TCP 443 (and 80 for ACME HTTP-01), and outbound HTTPS to"
echo "     github.com for MeshCentral's first-start agent download."
echo "  3. docker compose up -d"
echo "  4. Open https://${hostname}/ and enter the setup token from:"
echo "       ${data_root}/server/setup-token"
