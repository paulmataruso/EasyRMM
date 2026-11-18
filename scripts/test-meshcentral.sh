#!/bin/sh
# Starts a disposable MeshCentral for integration tests (host networking,
# loopback only), configured the way EasyRMM configures production.
#
#   scripts/test-meshcentral.sh            # start (replacing any previous one)
#   scripts/test-meshcentral.sh stop
#
# Tests find it through EASYRMM_TEST_MESH_DIR (config.json and key.hex) and
# EASYRMM_TEST_MESH_URL. Everything it writes is test-only.
set -eu

name=easyrmm-testmesh
image="${MESHCENTRAL_IMAGE:?set MESHCENTRAL_IMAGE (see Makefile)}"
dir="${EASYRMM_TEST_MESH_DIR:-${TMPDIR:-/tmp}/easyrmm-testmesh}"
listen="${EASYRMM_TEST_MESH_LISTEN:-127.0.0.1:24430}"
root="$(cd "$(dirname "$0")/.." && pwd)"

docker rm -f "$name" >/dev/null 2>&1 || true
if [ "${1:-}" = stop ]; then exit 0; fi

# Data written by the previous container belongs to the container's user.
if [ -d "$dir" ]; then
  docker run --rm --entrypoint sh -v "$dir:/clean" "$image" -c 'rm -rf /clean/* /clean/.[!.]*' >/dev/null
fi
mkdir -p "$dir/config" "$dir/data"
go run "$root/server/internal/meshcentral/meshtestenv" -dir "$dir/config" -listen "$listen" \
  -public-port "${EASYRMM_TEST_MESH_PUBLIC_PORT:-24443}" \
  ${EASYRMM_TEST_MESH_CERT_URL:+-cert-url "$EASYRMM_TEST_MESH_CERT_URL"}

docker run -d --name "$name" --network host --user "$(id -u):$(id -g)" \
  --read-only --tmpfs /tmp:size=64m --cap-drop ALL --security-opt no-new-privileges \
  -e HOME=/tmp \
  -v "$root/docker/meshcentral/start.sh:/easyrmm/start.sh:ro" \
  -v "$dir/config:/easyrmm/config:ro" \
  -v "$dir/data:/opt/meshcentral/meshcentral-data" \
  --tmpfs /opt/meshcentral/meshcentral-files:size=64m \
  --tmpfs /opt/meshcentral/meshcentral-backups:size=16m \
  --entrypoint /bin/bash "$image" /easyrmm/start.sh >/dev/null

for _ in $(seq 1 90); do
  if curl -fsS -o /dev/null "http://$listen/health.ashx" 2>/dev/null; then
    echo "export EASYRMM_TEST_MESH_DIR='$dir/config'"
    echo "export EASYRMM_TEST_MESH_URL='http://$listen'"
    exit 0
  fi
  if ! docker container inspect "$name" >/dev/null 2>&1 || [ "$(docker inspect -f '{{.State.Running}}' "$name")" != true ]; then
    break
  fi
  sleep 1
done
echo "MeshCentral did not start:" >&2
docker logs "$name" 2>&1 | tail -60 >&2
exit 1
