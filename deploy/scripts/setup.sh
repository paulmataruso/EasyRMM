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
# --smtp-host, --smtp-from and the other --smtp-* options set the mail
# server, a Microsoft 365 application's sign-in included (ADR-0053; see
# scripts/setup-mail.sh). With an existing .env they may be given alone.
#
# --upgrade, run in a new release's deploy/ directory with the deployment's
# .env copied in, takes every setting from that .env (no other options but
# --no-updater, and nothing is asked), sets the release's server version,
# lists settings the release adds, and gives the data directories their
# owners (ADR-0052).
#
# Run as root, setup.sh installs the host updater (ADR-0052;
# docs/operations/updater.md): /usr/local/sbin/easyrmm-updater from
# deploy/updater/ (a release's bundle carries it; a clone builds it with
# `make updater`), its systemd units, and /etc/easyrmm/updater.conf naming
# this deployment. --no-updater installs none. --auto-upgrade turns its
# automatic upgrades on (they are off unless something turns them on).
# While an updater attempt runs, setup.sh, run as root, changes nothing.
#
# An existing .env is never overwritten (its secrets protect existing data):
# setup.sh only adds secrets that later versions need and it lacks, and
# removes settings that no longer exist.
set -euo pipefail

self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
# shellcheck source-path=SCRIPTDIR source=setup-mail.sh
. "${self%/*}/setup-mail.sh"
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
upgrade=false
install_updater=true
auto_upgrade=false
nargs=$#

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
    --upgrade) upgrade=true; shift ;;
    --smtp-*) mail_option "$1" "${2:-}" || { echo "unknown option: $1" >&2; usage 2; }; shift 2 ;;
    # The one option --upgrade takes along: the updater runs it so.
    --no-updater) install_updater=false; nargs=$((nargs - 1)); shift ;;
    --auto-upgrade) auto_upgrade=true; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }

# --- .env (docs/operations/updater.md#env) -----------------------------------
# setup.sh reads .env by Compose's rules, as the host updater does: blank
# lines, comments, and KEY=value lines, KEY at the start of the line. A value
# is unquoted, ending at a " #" that starts a comment, the blanks around it
# trimmed; or in single or double quotes, which end on the same line, a
# backslash escaping the character after it, and nothing but blanks and a
# comment after them. check_env refuses what Compose would read otherwise,
# and, in the settings setup.sh reads (env_read), a backslash, a $ or a
# quote, which env_value does not read as Compose does.
env_read=" EASYRMM_PUBLIC_URL EASYRMM_MESH_PUBLIC_URL EASYRMM_TLS_MODE EASYRMM_ACME_EMAIL EASYRMM_TRUSTED_PROXIES EASYRMM_TLS_CERT_FILE EASYRMM_TLS_KEY_FILE EASYRMM_DATA_ROOT EASYRMM_IP_ACCESS EASYRMM_IP_ADDRESSES COMPOSE_PROFILES EASYRMM_AUTHENTIK_HOSTNAME EASYRMM_AUTHENTIK_ADMIN_EMAIL EASYRMM_EASYPATCH_HOSTNAME EASYRMM_VERSION "
check_env() {
  local LC_ALL=C file=$1 n=0 line key value
  local control=$'[\001-\010\013-\037\177]'
  local blank='^[[:blank:]]*(#.*)?$'
  local setting='^([A-Za-z_][A-Za-z0-9_]*)=[[:blank:]]*(.*)$'
  local double='^"(([^"\\]|\\.)*)"[[:blank:]]*(#.*)?$'
  local single="^'(([^'\\\\]|\\\\.)*)'[[:blank:]]*(#.*)?\$"
  while IFS= read -r line || [[ -n "$line" ]]; do
    n=$((n + 1))
    [[ ! "$line" =~ $control ]] || die "$file line $n holds a control character (a Windows line end?): setup.sh reads .env with Unix line ends only"
    [[ ! "$line" =~ $blank ]] || continue
    [[ "$line" =~ $setting ]] ||
      die "$file line $n is not KEY=value at the start of the line: setup.sh does not read export, spaces around the key or other forms Compose takes"
    key=${BASH_REMATCH[1]}
    value=${BASH_REMATCH[2]}
    [[ "$value" != $'\xc2\x85'* && "$value" != $'\xc2\xa0'* ]] || die "$file line $n: ${key}'s value starts with a blank other than a space or a tab"
    case "$value" in
      \"*|\'*)
        [[ "$value" =~ $double || "$value" =~ $single ]] ||
          die "$file line $n: ${key}'s quoted value does not end on its line, or text follows its closing quote: write it on one line, its closing quote followed by nothing but a comment"
        value=${BASH_REMATCH[1]}
        ;;
      *)
        value=${value%% #*}
        value=${value%"${value##*[![:blank:]]}"}
        ;;
    esac
    [[ "$env_read" != *" $key "* || "$value" != *[\\\$\"\']* ]] ||
      die "$file line $n: ${key}'s value holds a backslash, a \$ or a quote, which setup.sh does not read as Compose does"
  done < "$file"
}
# env_value KEY [FILE]: KEY's value in .env, or FILE, read as check_env
# reads it (the last, if KEY is there twice). In quotes, a backslash before
# the quote or, in double quotes, before a backslash is taken off, as Compose
# does, and any other backslash kept, as Compose keeps it; but in double
# quotes Compose also decodes \a \b \f \n \r \t \v \$ and \0 (octal), which
# env_value refuses rather than misreads. Compose's ${...} and $$ are not
# read: check_env refuses a $ in what setup.sh reads.
env_value() {
  local value quote out='' decoded="abfnrtv\$0"
  value=$(sed -n "s/^$1=//p" "${2:-.env}" | tail -n 1)
  value=${value#"${value%%[![:blank:]]*}"}
  case "$value" in
    \"*|\'*)
      quote=${value:0:1}
      value=${value:1}
      while [[ -n "$value" && "${value:0:1}" != "$quote" ]]; do
        if [[ "$quote" == \" && "${value:0:1}" == \\ && -n "${value:1:1}" && "$decoded" == *"${value:1:1}"* ]]; then
          die "${2:-.env}: $1's double-quoted value holds \\${value:1:1}, which Compose reads as another character and setup.sh does not read: write the character itself, or quote the value with single quotes (docs/operations/updater.md#env)"
        fi
        if [[ "${value:0:1}" == \\ && ( "${value:1:1}" == "$quote" || ( "$quote" == \" && "${value:1:1}" == \\ ) ) ]]; then
          value=${value:1}
        fi
        out+=${value:0:1}
        value=${value:1}
      done
      value=$out
      ;;
    *) value=${value%% #*}; value=${value%"${value##*[![:blank:]]}"} ;;
  esac
  printf '%s\n' "$value"
}

# --- The updater's lock (ADR-0052) -------------------------------------------
# Run as root, setup.sh holds the host updater's lock for its whole run: an
# attempt changes .env, the data root and the updater's own files itself,
# so setup.sh changes nothing while one runs. The updater runs a new
# version's setup.sh --upgrade --no-updater under its lock and hands it
# over, open, as EASYRMM_UPDATER_LOCK_FD: setup.sh takes it again, which
# succeeds at once (a lock belongs to the open file, not to the process),
# and never releases it, so neither waits for the other. Without an
# updater's state directory, no updater runs here, unless this run installs
# it.
updater_state=/var/lib/easyrmm-updater
updater_lock() {
  local fd
  if [[ -n "${EASYRMM_UPDATER_LOCK_FD:-}" ]]; then
    fd=$EASYRMM_UPDATER_LOCK_FD
    [[ "$fd" =~ ^[0-9]+$ && /proc/self/fd/$fd -ef "${updater_state}/lock" ]] ||
      die "EASYRMM_UPDATER_LOCK_FD=${fd} is not the updater's lock, ${updater_state}/lock"
  else
    [[ -d "$updater_state" || "$install_updater" == true ]] || return 0
    [[ -d "$updater_state" ]] || install -d -m 0700 -o root -g root "$updater_state"
    exec {fd}>> "${updater_state}/lock"
  fi
  flock -n "$fd" ||
    die "an updater attempt is running (easyrmm-updater status): setup.sh changes nothing while one does. Run it again once it has ended."
}
[[ $(id -u) -ne 0 ]] || updater_lock
if [[ -e .env ]]; then
  [[ -r .env ]] || die "cannot read .env: run setup.sh with sudo"
  check_env .env
fi

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
  profiles=$(env_value COMPOSE_PROFILES)
  case ",$profiles," in
    *,authentik,*) ;;
    ,,) set_setting COMPOSE_PROFILES authentik ;;
    *) set_setting COMPOSE_PROFILES "$profiles,authentik" ;;
  esac
  echo "Sign-in: Authentik at https://${authentik_hostname} (COMPOSE_PROFILES=$(env_value COMPOSE_PROFILES))."
}

# authentik_put writes its input to a file in one of Authentik's
# directories, as Authentik's file (uid 1000, mode 600). Authentik's
# containers can write in some of them (authentik-setup in invitations/), and
# root must write nothing through a link one of them planted: the file is
# written in authentik/, which only root can write, and renamed into place.
# A rename replaces whatever has the name, a link included.
authentik_put() {
  local path="$1" dir tmp
  dir=${path%/*}
  tmp=$(mktemp "${dir%/*}/.new.XXXXXX")
  if ! { cat > "$tmp" && chown 1000:1000 "$tmp" && mv -T -f "$tmp" "$path"; }; then
    rm -f "$tmp"
    die "could not write ${path}"
  fi
}

# authentik_issued says whether setup.sh issued the administrator's first
# invitation. Its record is authentik/invitation-issued, which only root can
# write. Releases up to 1.0.0-rc.4 kept it in invitations/, where
# authentik-setup can remove or replace it; a regular file there still counts.
authentik_issued() {
  local a="$1/authentik"
  if [[ ! -e "$a/invitation-issued" && -f "$a/invitations/issued" && ! -L "$a/invitations/issued" ]]; then
    touch "$a/invitation-issued"
  fi
  [[ -e "$a/invitation-issued" ]]
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
  printf 'id=%s\nemail=%s\nexpires=%s\n' "$id" "$email" "$expires" | authentik_put "$dir/pending"
  touch "${dir%/*}/invitation-issued"
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
  if [[ ! -f "$pw" || -L "$pw" || ! -s "$pw" ]]; then
    openssl rand -base64 30 | tr '+/' '-_' | authentik_put "$pw"
    echo "Authentik's own administrator is akadmin; its password is in ${pw} (mode 600)."
  fi
  if [[ "$upgrade" == true ]]; then
    authentik_link=""
  elif ! authentik_issued "$data_root"; then
    authentik_invite "$data_root/authentik/invitations" "$authentik_hostname" "$admin_email"
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
  host=$(env_value EASYRMM_AUTHENTIK_HOSTNAME)
  email=$(env_value EASYRMM_AUTHENTIK_ADMIN_EMAIL)
  root=$(env_value EASYRMM_DATA_ROOT)
  [[ -n "$host" && -n "$email" ]] || die "Authentik is not set up in .env: run setup.sh --with-authentik"
  [[ -d "${root:-/srv/easyrmm}/authentik/invitations" ]] || die "${root:-/srv/easyrmm}/authentik/invitations is missing: run setup.sh --with-authentik"
  authentik_invite "${root:-/srv/easyrmm}/authentik/invitations" "$host" "$email"
  echo "It works after the next: docker compose up -d"
  echo "(Any earlier invitation of setup.sh's that is still unused stops working then.)"
}
if [[ "$new_invitation" == true ]]; then
  new_invitation_only
  exit 0
fi

# --upgrade: the options the deployment was installed with, read back from
# the .env that install wrote.
if [[ "$upgrade" == true ]]; then
  [[ $nargs -eq 1 ]] || die "--upgrade takes no other options but --no-updater: every setting comes from .env"
  [[ $(id -u) -eq 0 ]] || die "--upgrade needs root (sudo)"
  [[ -e .env ]] || die "--upgrade needs the deployment's .env here: copy it from the release you are upgrading from"
  url=$(env_value EASYRMM_PUBLIC_URL)
  url=${url#https://}
  url=${url%%/*}
  if [[ "$url" == \[* ]]; then
    hostname=${url#[}
    hostname=${hostname%%]*}
  else
    hostname=${url%%:*}
  fi
  [[ -n "$hostname" ]] || die ".env has no EASYRMM_PUBLIC_URL to take the host name from"
  url=$(env_value EASYRMM_MESH_PUBLIC_URL)
  url=${url#https://}
  url=${url%%/*}
  mesh_hostname=${url%%:*}
  tls_mode=$(env_value EASYRMM_TLS_MODE)
  acme_email=$(env_value EASYRMM_ACME_EMAIL)
  trusted_proxies=$(env_value EASYRMM_TRUSTED_PROXIES)
  cert_file=$(env_value EASYRMM_TLS_CERT_FILE)
  key_file=$(env_value EASYRMM_TLS_KEY_FILE)
  data_root=$(env_value EASYRMM_DATA_ROOT)
  data_root=${data_root:-/srv/easyrmm}
  [[ "$(env_value EASYRMM_IP_ACCESS)" != false ]] || ip_access=false
  ip_addresses=$(env_value EASYRMM_IP_ADDRESSES)
  case ",$(env_value COMPOSE_PROFILES)," in
    *,authentik,*)
      with_authentik=true
      authentik_hostname=$(env_value EASYRMM_AUTHENTIK_HOSTNAME)
      admin_email=$(env_value EASYRMM_AUTHENTIK_ADMIN_EMAIL)
      [[ -n "$authentik_hostname" && -n "$admin_email" ]] ||
        die "COMPOSE_PROFILES has authentik, but .env lacks EASYRMM_AUTHENTIK_HOSTNAME or EASYRMM_AUTHENTIK_ADMIN_EMAIL"
      ;;
  esac
fi

valid_host='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
valid_ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
valid_ipv6='^[0-9a-f]*:[0-9a-f:.]*$'
hostname="${hostname,,}"
mesh_hostname="${mesh_hostname,,}"
if [[ -z "$hostname" && $mail_args -gt 0 && $mail_args -eq $nargs ]]; then
  mail_only
  exit 0
fi
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
[[ $mail_args -eq 0 ]] || mail_validate

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
  local value
  # Not in a condition: env_value's refusal stops setup.sh rather than
  # leave a secret it could not read to be replaced.
  value=$(env_value "$1")
  if [[ -n "$value" ]]; then
    return
  elif grep -q "^$1=" .env; then
    sed -i "s|^$1=.*|$1=$2|" .env
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
profiles=$(env_value COMPOSE_PROFILES)
if [[ ",$profiles," == *,patching,* ]]; then
  profiles=$(printf '%s\n' "${profiles//,/$'\n'}" | grep -vx patching | paste -sd , - || true)
  if [[ -n "$profiles" ]]; then
    set_setting COMPOSE_PROFILES "$profiles"
  else
    sed -i '/^COMPOSE_PROFILES=/d' .env
  fi
  echo "Removed the patching profile from COMPOSE_PROFILES in .env: its services have none."
fi
# EasyPatch on the same server (ADR-0035) is gone (ADR-0046). Empty settings
# are tidied away; a name is left for the operator, and the server refuses
# to start with it.
if [[ -n "$(env_value EASYRMM_EASYPATCH_HOSTNAME)" ]]; then
  echo "EASYRMM_EASYPATCH_HOSTNAME is set: EasyPatch on this server is replaced by the patching engine." >&2
  echo "EasyRMM does not start while it is set. Remove it, then import that EasyPatch (docs/operations/import-easypatch.md)." >&2
elif grep -q '^EASYRMM_EASYPATCH_' .env; then
  sed -i '/^EASYRMM_EASYPATCH_/d' .env
  echo "Removed the empty EASYRMM_EASYPATCH_* settings from .env: EasyPatch no longer shares the server that way."
fi
if [[ "$with_authentik" == true ]]; then
  authentik_env
fi
[[ $mail_args -eq 0 ]] || mail_env

if [[ "$upgrade" == true ]]; then
  # A release's bundle names its server image in .env.example; a clone's
  # says latest, and the version is the operator's to set.
  version=$(env_value EASYRMM_VERSION .env.example)
  if [[ -n "$version" && "$version" != latest ]]; then
    set_setting EASYRMM_VERSION "$version"
    echo "EASYRMM_VERSION=${version}: this release's server image."
  else
    echo "EASYRMM_VERSION stays $(env_value EASYRMM_VERSION): set it to the release you checked out."
  fi
  added=$(comm -13 <(grep -o '^[A-Z0-9_]*=' .env | sort -u) <(grep -o '^[A-Z0-9_]*=' .env.example | sort -u) | tr -d = | paste -sd ' ' -)
  [[ -z "$added" ]] || echo "Settings in .env.example that .env lacks (copy any you need): ${added}"
fi

# --- The host updater (ADR-0052) -------------------------------------------
# updater_install installs easyrmm-updater, its units and its configuration
# for this deployment, as root. Each file is written beside its place and
# renamed into it. An existing configuration keeps every setting but the
# deployment (this directory), and automatic upgrades with --auto-upgrade.
# setup.sh holds the updater's lock (updater_lock): an attempt rewrites
# updater.conf, and replaces the updater and its units, itself.
updater_conf=/etc/easyrmm/updater.conf
updater_install() {
  local arch bin deployment tmp auto
  case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *)
      echo "The updater: there is none for $(uname -m); not installed."
      return
      ;;
  esac
  bin="updater/easyrmm-updater-linux-${arch}"
  if [[ ! -f "$bin" ]]; then
    echo "The updater: $(pwd)/${bin} is missing (a Git clone builds it with make updater); not installed."
    return
  fi
  if [[ ! -d /run/systemd/system ]]; then
    echo "The updater: this host does not run systemd; not installed."
    return
  fi
  deployment=$(pwd -P)
  if [[ ! "$deployment" =~ ^/[A-Za-z0-9_./+@-]*$ ]]; then
    echo "The updater: it takes a deployment directory of letters, digits and ._+@-/ only, not ${deployment}; not installed."
    return
  fi
  updater_put 0755 "$bin" /usr/local/sbin/easyrmm-updater
  updater_put 0644 updater/easyrmm-updater.service /etc/systemd/system/easyrmm-updater.service
  updater_put 0644 updater/easyrmm-updater.timer /etc/systemd/system/easyrmm-updater.timer
  [[ -d /etc/easyrmm ]] || install -d -m 0755 -o root -g root /etc/easyrmm
  tmp=$(mktemp /etc/easyrmm/.updater.conf.XXXXXX)
  if [[ -f "$updater_conf" && ! -L "$updater_conf" ]]; then
    awk -v d="$deployment" -v auto="$auto_upgrade" '
      /^[ \t]*deployment[ \t]*=/ { print "deployment = " d; seen_d = 1; next }
      auto == "true" && /^[ \t]*auto_upgrade[ \t]*=/ { print "auto_upgrade = yes"; seen_a = 1; next }
      { print }
      END {
        if (!seen_d) print "deployment = " d
        if (auto == "true" && !seen_a) print "auto_upgrade = yes"
      }' "$updater_conf" > "$tmp"
  else
    auto=no
    [[ "$auto_upgrade" != true ]] || auto=yes
    cat > "$tmp" <<CONF
# The EasyRMM host updater (docs/operations/updater.md). Root's, mode 600:
# the server never writes it.
deployment = ${deployment}
# stable (full releases), pre-release (also release candidates) or edge
# (also builds of main, for test instances).
channel = stable
# The hourly timer upgrades to the newest version of the channel, in the
# hours given (the host's time zone, from-to: 2-5 is 02:00 to 05:00).
auto_upgrade = ${auto}
auto_upgrade_hours = 2-5
backup_dir = /var/backups/easyrmm-updater
CONF
  fi
  chmod 0600 "$tmp"
  mv -f "$tmp" "$updater_conf"
  systemctl daemon-reload
  systemctl enable --now easyrmm-updater.timer > /dev/null 2>&1 ||
    echo "The updater: systemctl could not start easyrmm-updater.timer." >&2
  auto=$(sed -n 's/^[ \t]*auto_upgrade[ \t]*=[ \t]*//p' "$updater_conf" | tail -n 1)
  echo "The updater: installed as /usr/local/sbin/easyrmm-updater, configured in ${updater_conf}" \
    "(automatic upgrades: ${auto:-no}). See docs/operations/updater.md."
}

# updater_put MODE SOURCE TARGET: SOURCE to TARGET, root's, renamed into place.
updater_put() {
  install -m "$1" -o root -g root "$2" "${3%/*}/.${3##*/}.new"
  mv -f "${3%/*}/.${3##*/}.new" "$3"
}

if [[ $(id -u) -ne 0 && "$install_updater" == true ]]; then
  echo "Not running as root: the updater (easyrmm-updater) is not installed. Run setup.sh with sudo to install it." >&2
fi

if [[ $(id -u) -ne 0 ]]; then
  echo "Not running as root: create these directories yourself:" >&2
  echo "  ${data_root}/server (owner 65532:65532, mode 700)" >&2
  echo "  ${data_root}/postgres (owner 70:70, mode 700)" >&2
  echo "  ${data_root}/tls (mode 750)" >&2
  echo "  ${data_root}/meshcentral-config (owner 65532:65532, mode 700)" >&2
  echo "  ${data_root}/meshcentral/{data,files,backups} (owner 65532:65532, mode 700)" >&2
  echo "  ${data_root}/easypatch/{keys,winget} (owner 1654:1654, mode 700)" >&2
  echo "  ${data_root}/updater/status (owner root, mode 755)" >&2
  echo "  ${data_root}/secrets (owner root:65532, mode 750)" >&2
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
# The updater's status (ADR-0052): root's alone. The server and the engine's
# worker mount it read-only; while its hold file exists the server answers
# its health check and nothing else.
install -d -m 0755 -o root -g root "$data_root/updater" "$data_root/updater/status"
# Secrets kept out of .env (ADR-0053), as tls/ is: the server only reads them.
mail_secrets_dir
echo "Data directories ready under ${data_root}."
[[ $mail_args -eq 0 ]] || mail_files
[[ "$install_updater" != true ]] || updater_install
if [[ "$with_authentik" == true ]]; then
  authentik_files
  if [[ "$upgrade" != true ]]; then
    authentik_next
    exit 0
  fi
fi
if [[ "$upgrade" == true ]]; then
  echo
  echo "Ready. Next: sudo docker compose pull && sudo docker compose up -d"
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
