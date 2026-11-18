#!/bin/sh
# Starts a disposable Dex, the OpenID Connect provider single sign-on tests
# sign in through (host networking, loopback only).
#
#   scripts/test-oidc.sh            # start (replacing any previous one)
#   scripts/test-oidc.sh stop
#
# Tests find it through EASYRMM_TEST_OIDC_DIR (env.json). The client secret
# and password in it are generated for each run and are test-only.
set -eu

name=easyrmm-testoidc
image="${DEX_IMAGE:?set DEX_IMAGE (see Makefile)}"
dir="${EASYRMM_TEST_OIDC_DIR:-${TMPDIR:-/tmp}/easyrmm-testoidc}"
listen="${EASYRMM_TEST_OIDC_LISTEN:-127.0.0.1:25556}"
root="$(cd "$(dirname "$0")/.." && pwd)"

docker rm -f "$name" >/dev/null 2>&1 || true
if [ "${1:-}" = stop ]; then exit 0; fi

rm -rf "$dir"
mkdir -p "$dir"
chmod 755 "$dir"
go run "$root/server/internal/sso/ssotestenv" -dir "$dir" -listen "$listen"

docker run -d --name "$name" --network host \
  --read-only --tmpfs /tmp:size=16m --cap-drop ALL --security-opt no-new-privileges \
  -v "$dir/dex.yaml:/easyrmm/dex.yaml:ro" \
  --entrypoint dex "$image" serve /easyrmm/dex.yaml >/dev/null

for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null "http://$listen/dex/.well-known/openid-configuration" 2>/dev/null; then
    echo "export EASYRMM_TEST_OIDC_DIR='$dir'"
    exit 0
  fi
  if ! docker container inspect "$name" >/dev/null 2>&1 || [ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]; then
    break
  fi
  sleep 1
done
echo "Dex did not start:" >&2
docker logs "$name" 2>&1 | tail -60 >&2
exit 1
