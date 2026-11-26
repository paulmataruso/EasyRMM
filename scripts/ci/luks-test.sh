#!/usr/bin/env bash
# Runs the agent's LUKS escrow tests (agent/escrow/cryptsetup, ADR-0081) against real LUKS volumes: file-backed loop devices,
# inside a privileged throwaway container with host networking, removed afterwards. Needs Docker, root-capable
# Docker, a kernel with loop devices and dm-crypt, and network for the image's packages.
#
#   scripts/ci/luks-test.sh [image]        (default alpine:3.22; debian and ubuntu images work too)
set -euo pipefail

image="${1:-alpine:3.22}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d /var/tmp/luks-test.XXXXXX)"
trap 'rm -rf "$work"' EXIT

# A static binary runs in any image.
(cd "$root" && CGO_ENABLED=0 go test -c -o "$work/cryptsetup.test" ./agent/escrow/cryptsetup)

docker run --rm --privileged --network host -v "$work:/t:ro" -e EASYRMM_LUKS_TEST=1 "$image" sh -c '
  set -e
  if command -v apk >/dev/null; then
    apk add --no-cache cryptsetup util-linux >/dev/null
  else
    apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cryptsetup util-linux >/dev/null
  fi
  cryptsetup --version
  # A container'"'"'s /dev only has the loop nodes that existed when it started.
  for i in $(seq 0 63); do [ -e /dev/loop$i ] || mknod /dev/loop$i b 7 $i; done
  cd /tmp
  /t/cryptsetup.test -test.v -test.run "Real" -test.count=1
'
