#!/bin/sh
# Starts the disposable Mailpit SMTP servers integration tests send mail to
# (ADR-0053), on host networking, loopback only:
#
#   plain     plain SMTP, as to a relay on the same machine
#   starttls  STARTTLS required
#   tls       TLS from the first byte
#
# Each asks for a user name and password, refuses recipients at .invalid
# (so that a test sees one refused), and is read through its API.
#
#   scripts/test-mail.sh            # start (replacing any previous ones)
#   scripts/test-mail.sh stop
#
# Tests find them through EASYRMM_TEST_MAIL_DIR (env.json). The password
# and the certificate in it are generated for each run and are test-only.
set -eu

image="${MAILPIT_IMAGE:?set MAILPIT_IMAGE (see Makefile)}"
dir="${EASYRMM_TEST_MAIL_DIR:-${TMPDIR:-/tmp}/easyrmm-testmail}"
modes="plain starttls tls"

for mode in $modes; do
  docker rm -f "easyrmm-testmail-$mode" >/dev/null 2>&1 || true
done
if [ "${1:-}" = stop ]; then exit 0; fi

rm -rf "$dir"
mkdir -p "$dir"
chmod 755 "$dir"

# A certificate for 127.0.0.1 that only the tests trust (SSL_CERT_FILE).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=EasyRMM test mail" -keyout "$dir/key.pem" -out "$dir/cert.pem" \
  -addext "subjectAltName=IP:127.0.0.1" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign" -addext "extendedKeyUsage=serverAuth" 2>/dev/null
password="$(head -c 18 /dev/urandom | base64 | tr -d '/+=')"
printf 'easyrmm:%s\n' "$password" >"$dir/auth"
chmod 644 "$dir/key.pem" "$dir/cert.pem" "$dir/auth"

port() {
  case "$1" in
    plain) echo 25025 ;;
    starttls) echo 25026 ;;
    tls) echo 25027 ;;
  esac
}

for mode in $modes; do
  smtp="127.0.0.1:$(port "$mode")"
  api="127.0.0.1:$(($(port "$mode") + 55))"
  case "$mode" in
    plain) extra="--smtp-auth-allow-insecure" ;;
    starttls) extra="--smtp-tls-cert /easyrmm/cert.pem --smtp-tls-key /easyrmm/key.pem --smtp-require-starttls" ;;
    tls) extra="--smtp-tls-cert /easyrmm/cert.pem --smtp-tls-key /easyrmm/key.pem --smtp-require-tls" ;;
  esac
  # The API's address goes in the environment, where the image's health
  # check finds it too. The allowed recipients are those not ending in
  # ".invalid" (Go's regular expressions have no lookahead).
  # shellcheck disable=SC2086 # extra is a list of flags
  docker run -d --name "easyrmm-testmail-$mode" --network host \
    --read-only --tmpfs /tmp:size=64m --cap-drop ALL --security-opt no-new-privileges \
    -e MP_UI_BIND_ADDR="$api" -v "$dir:/easyrmm:ro" "$image" \
    --smtp "$smtp" --smtp-auth-file /easyrmm/auth $extra \
    --smtp-allowed-recipients '(?:[^d]|[^i]d|[^l]id|[^a]lid|[^v]alid|[^n]valid|[^i]nvalid|[^.]invalid)$' \
    --smtp-disable-rdns --max 5000 --disable-version-check >/dev/null
done

for mode in $modes; do
  api="http://127.0.0.1:$(($(port "$mode") + 55))"
  ok=
  for _ in $(seq 1 60); do
    if curl -fsS -o /dev/null "$api/api/v1/messages?limit=1" 2>/dev/null; then
      ok=1
      break
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "easyrmm-testmail-$mode" 2>/dev/null)" != true ]; then
      break
    fi
    sleep 1
  done
  if [ -z "$ok" ]; then
    echo "Mailpit ($mode) did not start:" >&2
    docker logs "easyrmm-testmail-$mode" 2>&1 | tail -60 >&2
    exit 1
  fi
done

cat >"$dir/env.json" <<EOF
{
  "username": "easyrmm",
  "password": "$password",
  "ca": "$dir/cert.pem",
  "plain": {"smtp": "127.0.0.1:$(port plain)", "api": "http://127.0.0.1:$(($(port plain) + 55))"},
  "starttls": {"smtp": "127.0.0.1:$(port starttls)", "api": "http://127.0.0.1:$(($(port starttls) + 55))"},
  "tls": {"smtp": "127.0.0.1:$(port tls)", "api": "http://127.0.0.1:$(($(port tls) + 55))"}
}
EOF
echo "export EASYRMM_TEST_MAIL_DIR='$dir'"
