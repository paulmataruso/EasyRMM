# shellcheck shell=bash
# Shared by the drills in this directory: a disposable EasyRMM deployment
# built from this checkout with deploy/scripts/setup.sh and Docker Compose,
# and a console API client that signs in like the browser.
#
# Settings: DRILL_ADDR (127.0.0.2), DRILL_PROJECT (easyrmm-drill), and
# DRILL_IMAGE to use an existing image instead of building one. Ports used
# on the host: DRILL_ADDR:80, :443 and :4443; 127.0.0.1:15432
# (PostgreSQL), :18080, :18081 and :14430.

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
addr=${DRILL_ADDR:-127.0.0.2}
export COMPOSE_PROJECT_NAME=${DRILL_PROJECT:-easyrmm-drill}
image=${DRILL_IMAGE:-easyrmm-server:drill}
build=${DRILL_IMAGE:+no}
url="https://$addr"
admin_email="operator@drill.invalid"
# Setup refuses a password containing the account's name or address.
password="verify $(openssl rand -hex 8) passphrase"
csrf=""

# drill_workdir DIR: checks the host, and sets work, data, state and report.
drill_workdir() {
  [[ $(id -u) -eq 0 ]] || { echo "run as root: setup.sh sets the data directories' owners" >&2; exit 1; }
  local tool
  for tool in docker curl jq openssl base32 od git patch; do
    command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
  done
  mkdir -p "$1"
  work=$(cd "$1" && pwd)
  [[ ! -e "$work/srv" && ! -e "$work/state" ]] || { echo "$work holds an earlier run; use an empty directory" >&2; exit 1; }
  data="$work/srv"
  state="$work/state"
  report="$work/report.txt"
  mkdir -p "$state"
  chmod 700 "$state"
  : >"$report"
  trap 'printf "   FAIL  line %s: %s (see %s)\n" "$LINENO" "$BASH_COMMAND" "$work/compose.log" | tee -a "$report" >&2' ERR
}

step() { printf '\n== %s\n' "$*" | tee -a "$report"; }
ok() { printf '   ok    %s\n' "$*" | tee -a "$report"; }
# To stderr: inside $(...) stdout is captured.
fail() {
  printf '   FAIL  %s\n' "$*" | tee -a "$report" >&2
  exit 1
}

# totp SECRET [STEPS]: RFC 6238 code (SHA-1, 6 digits, 30 s), STEPS ahead.
totp() {
  local s=${1^^} key msg bytes="" mac off i
  while ((${#s} % 8)); do s+='='; done
  key=$(printf %s "$s" | base32 -d | od -An -v -tx1 | tr -d ' \n')
  msg=$(printf '%016x' $(($(date +%s) / 30 + ${2:-0})))
  for ((i = 0; i < 16; i += 2)); do bytes+="\\x${msg:i:2}"; done
  # shellcheck disable=SC2059 # the format is the message's bytes
  mac=$(printf "$bytes" | openssl dgst -sha1 -mac HMAC -macopt "hexkey:$key" -r | cut -d' ' -f1)
  off=$((16#${mac:39:1} * 2))
  printf '%06d' $(((16#${mac:off:8} & 0x7fffffff) % 1000000))
}

# call STATUS METHOD PATH [JSON]: a console API request as the signed-in
# browser; prints the body, fails on another status.
call() {
  local want=$1 method=$2 path=$3 body=${4-} out code
  local args=(-sS --cacert "$state/ca.pem" -b "$state/cookies" -c "$state/cookies" -X "$method" -H "Origin: $url" -w '\n%{http_code}')
  [[ -z "$csrf" ]] || args+=(-H "X-CSRF-Token: $csrf")
  [[ -z "$body" ]] || args+=(-H 'Content-Type: application/json' --data-binary "$body")
  out=$(curl "${args[@]}" "$url$path")
  code=${out##*$'\n'}
  out=${out%$'\n'*}
  [[ "$code" == "$want" ]] || fail "$method $path: HTTP $code, wanted $want: $out"
  printf '%s' "$out"
}

compose() { docker compose "$@"; }

wait_ready() {
  local _
  for _ in $(seq 1 120); do
    curl -sf -o /dev/null http://127.0.0.1:18081/readyz && return 0
    sleep 2
  done
  fail "the server did not become ready (docker compose logs server)"
}

# checkout DIR: the repository at this commit, as a clone has it, with any
# uncommitted changes to deploy/ and docker/.
checkout() {
  mkdir -p "$1"
  git -C "$repo" archive HEAD | tar -x -C "$1"
  if ! git -C "$repo" diff --quiet HEAD -- deploy docker; then
    git -C "$repo" diff HEAD -- deploy docker | (cd "$1" && patch -p1 -s --no-backup-if-mismatch)
  fi
}

# stack_up DIR: a checkout in DIR, setup.sh for DRILL_ADDR, the image, the
# stack, and the server's certificate authority in $state/ca.pem, fetched
# the way the install commands fetch it: over a connection pinned to the
# server's key. Leaves the shell in DIR/deploy and sets pin.
stack_up() {
  checkout "$1"
  cd "$1/deploy" || fail "no $1/deploy"
  ./scripts/setup.sh --hostname "$addr" --data-root "$data" >/dev/null
  sed -i -e "s|^EASYRMM_LISTEN_HTTP=.*|EASYRMM_LISTEN_HTTP=$addr:80|" \
    -e "s|^EASYRMM_LISTEN_HTTPS=.*|EASYRMM_LISTEN_HTTPS=$addr:443|" \
    -e "s|^EASYRMM_IMAGE=.*|EASYRMM_IMAGE=${image%%:*}|" \
    -e "s|^EASYRMM_VERSION=.*|EASYRMM_VERSION=${image##*:}|" .env
  if [[ "$build" != no ]]; then
    compose build server >"$work/build.log" 2>&1 || fail "image build failed: $work/build.log"
    ok "server image built from the checkout"
  fi
  compose up -d >>"$work/compose.log" 2>&1
  wait_ready
  ok "server ready on $url"
  pin=$(openssl s_client -connect "$addr:443" </dev/null 2>/dev/null | openssl x509 -pubkey -noout |
    openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)
  curl -fsS --insecure --pinnedpubkey "sha256//$pin" -o "$state/ca.pem" "$url/api/agent/v1/ca.pem"
}

# first_admin: first-run setup and the administrator's authenticator; the
# secret is kept in $state/totp-secret.
first_admin() {
  local s secret setup_token
  setup_token=$(tr -d '[:space:]' <"$data/server/setup-token")
  call 204 POST /api/v1/setup "$(jq -nc --arg t "$setup_token" --arg e "$admin_email" --arg p "$password" \
    '{token:$t, email:$e, displayName:"Operator", password:$p, organizationName:"Drill Org"}')" >/dev/null
  s=$(call 200 POST /api/v1/auth/login "$(jq -nc --arg e "$admin_email" --arg p "$password" '{email:$e, password:$p}')")
  csrf=$(jq -r .csrfToken <<<"$s")
  [[ $(jq -r .state <<<"$s") == mfa_enrollment ]] || fail "expected authenticator enrollment, got $(jq -r .state <<<"$s")"
  secret=$(call 200 POST /api/v1/auth/mfa/totp/begin '{}' | jq -r .secret)
  printf '%s' "$secret" >"$state/totp-secret"
  s=$(call 200 POST /api/v1/auth/mfa/totp/confirm "$(jq -nc --arg c "$(totp "$secret")" '{code:$c}')")
  csrf=$(jq -r .session.csrfToken <<<"$s")
}

# sign_in: password and authenticator, as after a restore.
sign_in() {
  local s
  rm -f "$state/cookies"
  csrf=""
  s=$(call 200 POST /api/v1/auth/login "$(jq -nc --arg e "$admin_email" --arg p "$password" '{email:$e, password:$p}')")
  csrf=$(jq -r .csrfToken <<<"$s")
  [[ $(jq -r .state <<<"$s") == mfa_required ]] || fail "expected the second factor, got $(jq -r .state <<<"$s")"
  s=$(call 200 POST /api/v1/auth/mfa/verify "$(jq -nc --arg c "$(totp "$(cat "$state/totp-secret")")" '{code:$c}')")
  [[ $(jq -r .state <<<"$s") == active ]] || fail "sign-in did not complete: $s"
  csrf=$(jq -r .csrfToken <<<"$s")
}
