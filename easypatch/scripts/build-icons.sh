#!/usr/bin/env bash
# Regenerates agent/EasyPatch.Agent/EasyPatch.ico (the agent executable's icon and the Installed apps / Programs and
# Features icon) from frontend/public/logo.svg. Run it after changing the logo. The .ico is committed, so neither the
# Windows nor the Linux build needs these tools.
#
#   scripts/build-icons.sh
#
# Rendering runs in a throwaway container (librsvg + icoutils); nothing is installed on the host.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
logo="$repo_root/frontend/public/logo.svg"
out_dir="$repo_root/agent/EasyPatch.Agent"

docker run --rm \
  -v "$logo:/in/logo.svg:ro" \
  -v "$out_dir:/out" \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  ubuntu:26.04@sha256:065aa8626841f16057b78b027b464cd59c4fac36c204c72dcbf48d66f5fa8a96 sh -c '
    set -e
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends librsvg2-bin icoutils >/dev/null
    cd /tmp
    sizes="16 20 24 32 40 48 64"
    for s in $sizes 256; do rsvg-convert -w "$s" -h "$s" /in/logo.svg -o "$s.png"; done
    # Small sizes as bitmaps, 256 px PNG-compressed (Windows Vista and later).
    icotool -c -o /out/EasyPatch.ico $(for s in $sizes; do printf "%s.png " "$s"; done) -r 256.png
    chown "$HOST_UID:$HOST_GID" /out/EasyPatch.ico
    icotool -l /out/EasyPatch.ico'

echo "Wrote agent/EasyPatch.Agent/EasyPatch.ico"
