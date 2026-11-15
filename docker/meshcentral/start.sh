#!/bin/bash
# Starts MeshCentral for EasyRMM (ADR-0004, ADR-0005).
#
# EasyRMM writes MeshCentral's config.json on every start (it holds the shared
# login-cookie key), so this script waits for it, makes sure the service
# account EasyRMM acts as exists, then runs MeshCentral, restarting it when
# the configuration changes.
#
# The service account has no usable password: EasyRMM authenticates as it
# with cookies sealed by the shared key, and MeshCentral's login page is not
# reachable through the EasyRMM edge.
set -euo pipefail

config="${EASYRMM_MESH_CONFIG:-/easyrmm/config/config.json}"
mesh=/opt/meshcentral/meshcentral/meshcentral
data=/opt/meshcentral/meshcentral-data
account=easyrmm-service

waited=0
until [ -s "$config" ]; do
  if [ "$waited" -eq 0 ]; then echo "Waiting for EasyRMM to write $config"; fi
  if [ "$waited" -ge 300 ]; then
    echo "No MeshCentral configuration after 5 minutes. Is the EasyRMM server running?" >&2
    exit 1
  fi
  sleep 2
  waited=$((waited + 2))
done

run_tool() {
  # MeshCentral's maintenance commands open the database directly, so they
  # only work while the server is stopped, which it is at this point.
  node "$mesh" --configfile "$config" "$@"
}

marker="$data/.easyrmm-service-account"
if [ ! -f "$marker" ]; then
  echo "Creating the EasyRMM service account"
  # The stored hash "!" can never match a password hash.
  run_tool --createaccount "$account" --hashpass "x,!" --name "EasyRMM"
  run_tool --adminaccount "$account"
  touch "$marker"
fi

# Run MeshCentral, and restart it when EasyRMM rewrites the configuration
# (for example after the MeshCentral hostname changes).
pid=
current=
stopping=0
start_mesh() {
  current=$(cksum < "$config")
  node "$mesh" --configfile "$config" &
  pid=$!
}
stop_mesh() {
  # MeshCentral shuts down cleanly on SIGINT.
  kill -INT "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
# Docker sends SIGTERM to stop the container.
trap 'stopping=1; kill -INT "$pid" 2>/dev/null || true' TERM INT

start_mesh
while :; do
  sleep 5 &
  wait $! || true
  if [ "$stopping" -eq 1 ]; then
    status=0
    wait "$pid" || status=$?
    exit "$status"
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    status=0
    wait "$pid" || status=$?
    echo "MeshCentral exited with status $status" >&2
    exit "$status"
  fi
  if [ -s "$config" ] && [ "$(cksum < "$config")" != "$current" ]; then
    echo "EasyRMM changed the MeshCentral configuration; restarting MeshCentral"
    stop_mesh
    start_mesh
  fi
done
