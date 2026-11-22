#!/usr/bin/env bash
# Tests setup.sh's --smtp-* options (ADR-0053, slice 2) in copies of deploy/
# under a temporary directory, as a release unpacks it: .env's mail settings
# (paths in the container), the files under secrets/ (root:65532, 0750 and
# 0440), the secret in neither .env nor any command's arguments, the mail
# options alone on an existing .env, refusals that leave .env as it was,
# root required, --upgrade's owners and modes, and the secret asked for
# without echo on a terminal. The credentials are stand-ins made here.
#
#   sudo deploy/scripts/setup-mail_test.sh
set -euo pipefail

[[ $(id -u) -eq 0 ]] || { echo "run it as root (sudo): setup.sh gives the mail files to root:65532" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/var/tmp}/setup-mail-test.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
chmod 0755 "$work"

failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
expect() { [[ "$2" == "$3" ]] || fail "$1: got '$3', want '$2'"; }

TENANT=00000000-0000-4000-8000-00000000a001
CLIENT=00000000-0000-4000-8000-00000000c001
SECRET='STAND-IN~secret.0123456789abcdefghijklmn'

# The stand-in credentials.
creds="$work/creds"
mkdir "$creds"
printf '%s\n' "$SECRET" > "$creds/secret"
printf '\n' > "$creds/empty"
printf '%s\nmore\n' "$SECRET" > "$creds/two-lines"
printf 'not a certificate\n' > "$creds/garbage.crt"
(
  cd "$creds"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out app.key 2> /dev/null
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out other.key 2> /dev/null
  openssl req -x509 -key app.key -subj /CN=easyrmm-mail-test -days 365 -out app.crt 2> /dev/null
  openssl req -x509 -key app.key -subj /CN=easyrmm-mail-test -days 10 -out soon.crt 2> /dev/null
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec.key 2> /dev/null
  openssl req -x509 -key ec.key -subj /CN=easyrmm-mail-test -days 365 -out ec.crt 2> /dev/null
  # An expired certificate: openssl ca takes dates in the past.
  printf '[ca]\ndefault_ca = c\n[c]\ndatabase = index.txt\nnew_certs_dir = .\nserial = serial\ndefault_md = sha256\npolicy = p\n[p]\ncommonName = supplied\n' > ca.cnf
  : > index.txt
  echo 01 > serial
  openssl req -new -key app.key -subj /CN=easyrmm-mail-test -out expired.csr 2> /dev/null
  openssl ca -batch -config ca.cnf -selfsign -keyfile app.key -in expired.csr -out expired.crt \
    -startdate 20200101000000Z -enddate 20200102000000Z -notext > /dev/null 2>&1
)

# Every command setup.sh runs logs its arguments here, to show the secret is
# in none of them (the process list).
argv_log="$work/argv.log"
mkdir "$work/bin"
for c in sed grep install chown chmod mv mktemp cat rm openssl tail id paste comm sort tr cp date head awk; do
  real=$(command -v "$c")
  printf '#!/bin/sh\nprintf "%%s\\n" "%s $*" >> %s\nexec %s "$@"\n' "$c" "$argv_log" "$real" > "$work/bin/$c"
  chmod 0755 "$work/bin/$c"
done

# deployment NAME: a copy of deploy/, as a release unpacks it.
deployment() {
  local d="$work/$1"
  mkdir -p "$d/deploy/scripts"
  cp "$here/../.env.example" "$d/deploy/"
  cp "$here/setup.sh" "$here/setup-mail.sh" "$d/deploy/scripts/"
  chmod -R a+rX "$d"
  echo "$d"
}
# setup DIR ARGS...: setup.sh in DIR's deploy/, its output in DIR/out and DIR/err.
setup() {
  local d="$1"
  shift
  (cd "$d/deploy" && PATH="$work/bin:$PATH" ./scripts/setup.sh "$@") > "$d/out" 2> "$d/err" < /dev/null
}
env_of() { sed -n "s/^$2=//p" "$1/deploy/.env" | tail -n 1; }
owner_mode() { stat -c '%u:%g %a' "$1"; }
# refused DIR WANT ARGS...: setup.sh stops, saying WANT.
refused() {
  local d="$1" want="$2"
  shift 2
  if setup "$d" "$@"; then
    fail "taken: $*"
  elif ! grep -qF -- "$want" "$d/err"; then
    fail "refused without '$want': $*: $(cat "$d/err")"
  fi
}
install_args=(--hostname 127.0.0.1 --smtp-from rmm@m365.example.com --smtp-tenant-id "$TENANT" --smtp-client-id "$CLIENT")

# --- An install with a client secret ------------------------------------------
d=$(deployment install)
data="$d/data"
setup "$d" "${install_args[@]}" --data-root "$data" --smtp-client-secret-file "$creds/secret" || fail "install: $(cat "$d/err")"
for kv in EASYRMM_SMTP_AUTH=microsoft365 EASYRMM_SMTP_HOST=smtp.office365.com EASYRMM_SMTP_PORT=587 EASYRMM_SMTP_TLS=starttls \
  EASYRMM_SMTP_FROM=rmm@m365.example.com "EASYRMM_SMTP_TENANT_ID=$TENANT" "EASYRMM_SMTP_CLIENT_ID=$CLIENT" \
  EASYRMM_SMTP_CLIENT_SECRET_FILE=/run/secrets/easyrmm/smtp-client-secret EASYRMM_SMTP_CLIENT_CERT_FILE= EASYRMM_SMTP_CLIENT_KEY_FILE= \
  EASYRMM_SMTP_USERNAME= EASYRMM_SMTP_PASSWORD= "EASYRMM_DATA_ROOT=$data"; do
  expect "install: ${kv%%=*}" "${kv#*=}" "$(env_of "$d" "${kv%%=*}")"
done
grep -qF -- "$SECRET" "$d/deploy/.env" && fail "install: the secret is in .env"
grep -q '^mv -T -f .*/secrets/smtp-client-secret$' "$argv_log" || fail "install: the commands' arguments were not logged"
grep -qF -- "$SECRET" "$argv_log" && fail "install: the secret is in a command's arguments"
expect "install: secrets/" "0:65532 750" "$(owner_mode "$data/secrets")"
expect "install: the secret's file" "0:65532 440" "$(owner_mode "$data/secrets/smtp-client-secret")"
expect "install: the secret" "$SECRET" "$(cat "$data/secrets/smtp-client-secret")"
grep -qF "Warning: patching's email stops" "$d/err" || fail "install: no warning about patching's email: $(cat "$d/err")"
grep -qF "docker compose exec server easyrmm-server mail check" "$d/out" || fail "install: the next steps do not say to check the mail server"

# --- The mail options alone, on that .env: a certificate instead -------------
cp "$d/deploy/.env" "$work/env.before"
setup "$d" --smtp-from other@m365.example.com --smtp-client-cert-file "$creds/app.crt" --smtp-client-key-file "$creds/app.key" ||
  fail "certificate: $(cat "$d/err")"
diff <(grep -v '^EASYRMM_SMTP_' "$work/env.before") <(grep -v '^EASYRMM_SMTP_' "$d/deploy/.env") > /dev/null ||
  fail "certificate: settings other than the mail server's changed"
for kv in EASYRMM_SMTP_FROM=other@m365.example.com "EASYRMM_SMTP_TENANT_ID=$TENANT" "EASYRMM_SMTP_CLIENT_ID=$CLIENT" \
  EASYRMM_SMTP_CLIENT_SECRET_FILE= EASYRMM_SMTP_CLIENT_CERT_FILE=/run/secrets/easyrmm/smtp-client.crt \
  EASYRMM_SMTP_CLIENT_KEY_FILE=/run/secrets/easyrmm/smtp-client.key; do
  expect "certificate: ${kv%%=*}" "${kv#*=}" "$(env_of "$d" "${kv%%=*}")"
done
[[ ! -e "$data/secrets/smtp-client-secret" ]] || fail "certificate: the secret's file is left"
for f in smtp-client.crt smtp-client.key; do
  expect "certificate: $f" "0:65532 440" "$(owner_mode "$data/secrets/$f")"
done
cmp -s "$creds/app.crt" "$data/secrets/smtp-client.crt" || fail "certificate: not copied"
cmp -s "$creds/app.key" "$data/secrets/smtp-client.key" || fail "certificate: the key not copied"
grep -qF "Only the mail settings in .env changed" "$d/out" || fail "certificate: $(cat "$d/out")"

# The sender alone: the application and its certificate are kept.
setup "$d" --smtp-from third@m365.example.com || fail "the sender alone: $(cat "$d/err")"
expect "the sender alone" third@m365.example.com "$(env_of "$d" EASYRMM_SMTP_FROM)"
expect "the sender alone: the certificate" /run/secrets/easyrmm/smtp-client.crt "$(env_of "$d" EASYRMM_SMTP_CLIENT_CERT_FILE)"
cmp -s "$creds/app.key" "$data/secrets/smtp-client.key" || fail "the sender alone: the key changed"

# A certificate ending within 30 days: taken, with a warning.
setup "$d" --smtp-client-cert-file "$creds/soon.crt" --smtp-client-key-file "$creds/app.key" || fail "ending soon: $(cat "$d/err")"
grep -qF "ends within 30 days" "$d/err" || fail "ending soon: no warning: $(cat "$d/err")"

# --- Refused, leaving .env as it was ------------------------------------------
cp "$d/deploy/.env" "$work/env.before"
refused "$d" "--smtp-tenant-id must be" --smtp-tenant-id "not a tenant"
refused "$d" "--smtp-tenant-id must be" --smtp-tenant-id contoso
refused "$d" "--smtp-client-id must be" --smtp-client-id 1234
refused "$d" "is empty" --smtp-client-secret-file "$creds/empty"
refused "$d" "more than one line" --smtp-client-secret-file "$creds/two-lines"
refused "$d" "is not a file" --smtp-client-secret-file "$creds/missing"
refused "$d" "is not a certificate in PEM" --smtp-client-cert-file "$creds/garbage.crt" --smtp-client-key-file "$creds/app.key"
refused "$d" "is not the certificate's" --smtp-client-cert-file "$creds/app.crt" --smtp-client-key-file "$creds/other.key"
refused "$d" "the certificate expired" --smtp-client-cert-file "$creds/expired.crt" --smtp-client-key-file "$creds/app.key"
refused "$d" "is not RSA" --smtp-client-cert-file "$creds/ec.crt" --smtp-client-key-file "$creds/ec.key"
refused "$d" "not both" --smtp-client-secret-file "$creds/secret" --smtp-client-cert-file "$creds/app.crt" --smtp-client-key-file "$creds/app.key"
refused "$d" "go together" --smtp-client-cert-file "$creds/app.crt"
refused "$d" "must be an email address" --smtp-from "not an address"
refused "$d" "must be a port" --smtp-port 70000
refused "$d" "--smtp-host must be" --smtp-host "smtp example com"
cmp -s "$work/env.before" "$d/deploy/.env" || fail "refusals changed .env"
cmp -s "$creds/app.key" "$data/secrets/smtp-client.key" || fail "refusals changed the key"

# --- Root, and --upgrade's owners and modes -----------------------------------
chmod 0644 "$d/deploy/.env"
if (cd "$d/deploy" && setpriv --reuid=65534 --regid=65534 --clear-groups ./scripts/setup.sh --smtp-tenant-id "$TENANT") > /dev/null 2> "$d/err"; then
  fail "the application's options taken without root"
fi
grep -qF "need root (sudo)" "$d/err" || fail "without root: $(cat "$d/err")"
chmod 0600 "$d/deploy/.env"
if (cd "$d/deploy" && setpriv --reuid=65534 --regid=65534 --clear-groups ./scripts/setup.sh --smtp-from x@m365.example.com) > /dev/null 2> "$d/err"; then
  fail "root's .env changed without root"
fi
grep -qF "run setup.sh with sudo" "$d/err" || fail "root's .env without root: $(cat "$d/err")"
cmp -s "$work/env.before" "$d/deploy/.env" || fail "without root, .env changed"

chown 0:0 "$data/secrets" "$data/secrets/smtp-client.key"
chmod 0755 "$data/secrets"
chmod 0644 "$data/secrets/smtp-client.key"
setup "$d" --upgrade || fail "upgrade: $(cat "$d/err")"
expect "upgrade: secrets/" "0:65532 750" "$(owner_mode "$data/secrets")"
expect "upgrade: the key" "0:65532 440" "$(owner_mode "$data/secrets/smtp-client.key")"

# --- No credential, and no terminal to ask on; no .env ------------------------
d=$(deployment no-credential)
refused "$d" "is required when setup.sh cannot ask" "${install_args[@]}" --data-root "$d/data"
[[ ! -e "$d/deploy/.env" ]] || fail "no credential: .env written"
refused "$d" "need the deployment's .env here" --smtp-from rmm@m365.example.com

# A plain install creates secrets/ too, for the server's mount.
setup "$d" --hostname 127.0.0.1 --data-root "$d/data" || fail "plain install: $(cat "$d/err")"
expect "plain install: secrets/" "0:65532 750" "$(owner_mode "$d/data/secrets")"
[[ -z "$(env_of "$d" EASYRMM_SMTP_AUTH)" ]] || fail "plain install: a sign-in set"

# --- Asked on a terminal, without echo ----------------------------------------
d=$(deployment asked)
: > "$argv_log"
{
  sleep 3
  printf '%s\n' "$SECRET"
} | script -qefc "cd '$d/deploy' && PATH='$work/bin:$PATH' ./scripts/setup.sh --hostname 127.0.0.1 --data-root '$d/data' --smtp-from rmm@m365.example.com --smtp-tenant-id $TENANT --smtp-client-id $CLIENT" \
  "$d/typescript" > "$d/out" 2>&1 || fail "asked: $(cat "$d/out")"
grep -qF "client secret (its Value, not shown)" "$d/typescript" || fail "asked: no prompt: $(cat "$d/typescript")"
grep -qF -- "$SECRET" "$d/typescript" && fail "asked: the secret was echoed"
grep -q '^mv -T -f .*/secrets/smtp-client-secret$' "$argv_log" || fail "asked: the commands' arguments were not logged"
grep -qF -- "$SECRET" "$argv_log" && fail "asked: the secret is in a command's arguments"
expect "asked: the secret" "$SECRET" "$(cat "$d/data/secrets/smtp-client-secret" 2> /dev/null)"

if [[ $failures -gt 0 ]]; then
  echo "setup.sh's mail options: ${failures} failed" >&2
  exit 1
fi
echo "setup.sh's mail options: ok"
