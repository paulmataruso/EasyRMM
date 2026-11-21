# shellcheck shell=bash
# Shared by the drills in this directory: a disposable EasyRMM deployment
# built from this checkout with deploy/scripts/setup.sh and Docker Compose,
# a console API client that signs in like the browser, and, for a
# deployment with Authentik, sign-in through Authentik as the browser goes
# through it.
#
# Settings: DRILL_ADDR (127.0.0.2), DRILL_PROJECT (easyrmm-drill), and
# DRILL_IMAGE and DRILL_ENGINE_IMAGE to use existing images of EasyRMM's
# server and the patching engine instead of building them. Ports used on
# the host: DRILL_ADDR:80, :443 and :4443; 127.0.0.1:15432 (PostgreSQL),
# :18080, :18081, :14430, :18180 and :18181 (the engine), and with
# Authentik :18280, :18243 and :18281.

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
addr=${DRILL_ADDR:-127.0.0.2}
export COMPOSE_PROJECT_NAME=${DRILL_PROJECT:-easyrmm-drill}
image=${DRILL_IMAGE:-easyrmm-server:drill}
build=${DRILL_IMAGE:+no}
engine_image=${DRILL_ENGINE_IMAGE:-easyrmm-drill/easypatch-server:drill}
engine_build=${DRILL_ENGINE_IMAGE:+no}
url="https://$addr"
admin_email="operator@drill.invalid"
# Setup refuses a password containing the account's name or address.
password="verify $(openssl rand -hex 8) passphrase"
csrf=""
# setup.sh's options besides the host name and the data root.
setup_args=()
# Authentik's sign-in name, served by the drill's edge on DRILL_ADDR.
signin_host="auth.drill.invalid"
signin="https://$signin_host"

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
# server's key. Leaves the shell in DIR/deploy and sets pin. setup.sh's
# output, which can hold an invitation link, is kept in $state/setup.out.
stack_up() {
  checkout "$1"
  cd "$1/deploy" || fail "no $1/deploy"
  ./scripts/setup.sh --hostname "$addr" --data-root "$data" "${setup_args[@]}" >"$state/setup.out" </dev/null
  sed -i -e "s|^EASYRMM_LISTEN_HTTP=.*|EASYRMM_LISTEN_HTTP=$addr:80|" \
    -e "s|^EASYRMM_LISTEN_HTTPS=.*|EASYRMM_LISTEN_HTTPS=$addr:443|" \
    -e "s|^EASYRMM_IMAGE=.*|EASYRMM_IMAGE=${image%%:*}|" \
    -e "s|^EASYRMM_VERSION=.*|EASYRMM_VERSION=${image##*:}|" \
    -e "s|^EASYPATCH_IMAGE=.*|EASYPATCH_IMAGE=${engine_image%:*}|" \
    -e "s|^EASYPATCH_VERSION=.*|EASYPATCH_VERSION=${engine_image##*:}|" .env
  if [[ "$build" != no ]]; then
    compose build server >"$work/build.log" 2>&1 || fail "image build failed: $work/build.log"
    ok "server image built from the checkout"
  fi
  if [[ "$engine_build" != no ]]; then
    # One image serves the engine's three services.
    compose build easypatch-migrate >"$work/engine-build.log" 2>&1 || fail "engine image build failed: $work/engine-build.log"
    ok "patching engine image built from the checkout"
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

# ------------------------------------------------------------------ Authentik
# For a deployment set up with setup.sh --with-authentik (setup_args). The
# browser reaches Authentik's sign-in name through EasyRMM's edge, and so do
# these functions, verifying TLS against the saved authority. Authentik's
# pages are its web interface answering the stages of its flow executor API
# one at a time; these answer the same stages through the same API.

# totp_fresh SECRET: a code for a time step not used before. Authentik takes
# each step's code once.
totp_fresh() {
  local now last
  last=$(cat "$state/totp-step" 2>/dev/null || echo 0)
  while now=$(($(date +%s) / 30)) && ((now <= last)); do sleep 2; done
  echo "$now" >"$state/totp-step"
  totp "$1"
}

# browse METHOD URL [JSON]: one request as the browser, to EasyRMM or to
# Authentik, with the cookies call uses. Sets web_code and web_location, and
# leaves the body in $state/body.
browse() {
  local method=$1 u=$2 body=${3-} token=""
  local args=(-sS --cacert "$state/ca.pem" --resolve "$signin_host:443:$addr" -b "$state/cookies" -c "$state/cookies"
    -X "$method" -D "$state/headers" -o "$state/body" -w '%{http_code}')
  if [[ $u == "$signin"/* ]]; then
    # Authentik's API wants its CSRF cookie's value back in a header, as
    # its web interface sends it.
    [[ ! -f "$state/cookies" ]] || token=$(awk '$6 == "authentik_csrf" { print $7 }' "$state/cookies" | tail -n 1)
    args+=(-H "Origin: $signin" -H "Referer: $signin/")
    [[ -z "$token" ]] || args+=(-H "X-authentik-CSRF: $token")
  fi
  [[ -z "$body" ]] || args+=(-H 'Content-Type: application/json' --data-binary "$body")
  web_code=$(curl "${args[@]}" "$u") || fail "$method $u: no answer"
  web_location=$(sed -n 's/^[Ll]ocation: *//p' "$state/headers" | tr -d '\r' | tail -n 1)
}

# authentik_flow SLUG QUERY: answers Authentik's flow SLUG, opened with
# QUERY, as the administrator: password $password, the authenticator app in
# $state/authentik-totp, set up at the first stage that offers one. Prints
# where the flow sends the browser, and appends each stage to
# $state/stages.
authentik_flow() {
  local slug=$1 query=$2 api challenge stage reply pk _
  api="$signin/api/v3/flows/executor/$slug/?query=$(jq -rn --arg q "$query" '$q | @uri')"
  browse GET "$api"
  for _ in $(seq 1 20); do
    while [[ $web_code == 30? ]]; do
      [[ $web_location == /* ]] && web_location="$signin$web_location"
      browse GET "$web_location"
    done
    [[ $web_code == 200 ]] || fail "Authentik's flow $slug: HTTP $web_code: $(head -c 500 "$state/body")"
    challenge=$(cat "$state/body")
    stage=$(jq -r .component <<<"$challenge")
    jq -e '.response_errors // {} | length == 0' <<<"$challenge" >/dev/null ||
      fail "Authentik refused the answer at $stage: $(jq -c .response_errors <<<"$challenge")"
    [[ $stage == xak-flow-redirect ]] || echo "$stage" >>"$state/stages"
    case $stage in
      xak-flow-redirect)
        jq -r .to <<<"$challenge"
        return 0
        ;;
      ak-stage-prompt)
        # The invitation's fields keep the values it gives them: the email.
        reply=$(jq -c --arg c "$stage" --arg p "$password" '
          reduce .fields[] as $f ({component: $c};
            .[$f.field_key] = (if $f.field_key == "name" then "Drill Operator"
              elif ($f.field_key | startswith("password")) then $p
              else ($f.initial_value // "") end))' <<<"$challenge")
        ;;
      ak-stage-identification) reply=$(jq -nc --arg c "$stage" --arg e "$admin_email" '{component: $c, uid_field: $e}') ;;
      ak-stage-password) reply=$(jq -nc --arg c "$stage" --arg p "$password" '{component: $c, password: $p}') ;;
      ak-stage-authenticator-validate)
        if jq -e '[.device_challenges[]? | select(.device_class == "totp")] | length > 0' <<<"$challenge" >/dev/null; then
          reply=$(jq -nc --arg c "$stage" --arg k "$(totp_fresh "$(cat "$state/authentik-totp")")" '{component: $c, code: $k}')
        else
          # No second factor yet: set one up, an authenticator app.
          pk=$(jq -r '[.configuration_stages[]? | select(.meta_model_name | test("totp"))][0].pk // empty' <<<"$challenge")
          [[ -n "$pk" ]] || fail "Authentik offers no authenticator app to set up: $challenge"
          reply=$(jq -nc --arg c "$stage" --arg s "$pk" '{component: $c, selected_stage: $s}')
        fi
        ;;
      ak-stage-authenticator-totp)
        # The secret under the QR code.
        jq -r .config_url <<<"$challenge" | sed -n 's/.*[?&]secret=\([A-Z2-7]*\).*/\1/p' >"$state/authentik-totp"
        [[ -s "$state/authentik-totp" ]] || fail "no authenticator secret in Authentik's setup stage"
        reply=$(jq -nc --arg c "$stage" --arg k "$(totp_fresh "$(cat "$state/authentik-totp")")" '{component: $c, code: $k}')
        ;;
      *) fail "Authentik's flow $slug stopped at $stage: $(head -c 500 <<<"$challenge")" ;;
    esac
    browse POST "$api" "$reply"
  done
  fail "Authentik's flow $slug did not end"
}

# sign_in_authentik URL: the browser's way from URL (an invitation, or
# EasyRMM's start of sign-in with Authentik) through Authentik's flows and
# back to EasyRMM, where it must be signed in as the super administrator.
# Sets csrf for call, and stages to the stages Authentik asked for.
sign_in_authentik() {
  local u=$1 slug query origin s _
  : >"$state/stages"
  for _ in $(seq 1 30); do
    case $u in
      "$signin"/if/flow/*)
        slug=${u#"$signin"/if/flow/}
        slug=${slug%%/*}
        query=""
        [[ $u != *\?* ]] || query=${u#*\?}
        u=$(authentik_flow "$slug" "$query")
        [[ $u != /* ]] || u="$signin$u"
        ;;
      "$signin"/* | "$url"/api/*)
        browse GET "$u"
        [[ $web_code == 30? ]] || fail "GET $u: HTTP $web_code, wanted a redirect: $(head -c 500 "$state/body")"
        origin=$url
        [[ $u != "$signin"/* ]] || origin=$signin
        u=$web_location
        [[ $u != /* ]] || u="$origin$u"
        ;;
      "$url"/*) break ;;
      *) fail "sign-in went to $u" ;;
    esac
  done
  [[ $u == "$url"/* && $u != "$url"/api/* ]] || fail "sign-in through Authentik did not end at EasyRMM: $u"
  [[ $u != *sso_error=* ]] || fail "EasyRMM refused the sign-in: $u"
  # shellcheck disable=SC2034 # the drills check it
  stages=$(paste -sd ' ' "$state/stages")
  csrf=""
  s=$(call 200 GET /api/v1/auth/session)
  [[ $(jq -r .state <<<"$s") == active && $(jq -r .isSuperAdmin <<<"$s") == true && $(jq -r .user.email <<<"$s") == "$admin_email" ]] ||
    fail "not signed in as the super administrator after Authentik: $s"
  csrf=$(jq -r .csrfToken <<<"$s")
}
