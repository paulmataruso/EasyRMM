#!/bin/sh
# Installs oras, which pushes and pulls EasyRMM's edge builds (ADR-0052), into
# a directory, from its GitHub release, checked against the SHA-256 pinned
# here:
#
#   scripts/ci/install-oras.sh <dir>
#
# To move to another version, take its linux_amd64 line from the release's
# oras_<version>_checksums.txt.
set -eu

version=1.3.6
sha256=66fb0ad7206f3f6fa77ed5b552049d364ccf4b50b1684554f731f76302b52ca0
archive=oras_${version}_linux_amd64.tar.gz

[ $# -eq 1 ] || { echo "usage: install-oras.sh <dir>" >&2; exit 2; }
dir=$1
[ "$(uname -s)/$(uname -m)" = Linux/x86_64 ] || { echo "install-oras: only for Linux on x86-64" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 3 -o "$work/$archive" "https://github.com/oras-project/oras/releases/download/v$version/$archive"
echo "$sha256  $work/$archive" | sha256sum -c --quiet
mkdir -p "$dir"
tar --no-same-owner -xzf "$work/$archive" -C "$dir" oras
"$dir/oras" version | head -n 1
