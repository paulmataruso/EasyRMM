#!/usr/bin/env bash
# Extracts an OCI image layout, if it is the image whose index digest is
# given (ADR-0052):
#
#   scripts/ci/check-oci-layout.sh <layout.tar> sha256:<index> <new dir>
#
# The layout's index.json must name exactly that index, and its blob must
# hash to it; the index names everything else by digest, which the
# registry checks as oras pushes it. The jobs that push a layout another
# job built and checked use this before oras cp --from-oci-layout.
set -euo pipefail

die() {
  echo "check-oci-layout: $*" >&2
  exit 1
}

[ $# -eq 3 ] || { echo "usage: check-oci-layout.sh <layout.tar> sha256:<index> <new dir>" >&2; exit 2; }
tar=$1 digest=$2 dir=$3
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "check-oci-layout: \"$digest\" is not a digest" >&2; exit 2; }
mkdir "$dir"
tar -xf "$tar" -C "$dir"
jq -e --arg d "$digest" '[.manifests[].digest] == [$d]' "$dir/index.json" > /dev/null ||
  die "$tar's index.json does not name $digest alone"
index="$dir/blobs/sha256/${digest#sha256:}"
[ -f "$index" ] && [ ! -L "$index" ] || die "$tar has no blob $digest"
got="sha256:$(sha256sum < "$index" | cut -c1-64)"
[ "$got" = "$digest" ] || die "$tar's blob $digest hashes to $got"
echo "check-oci-layout: $tar is $digest"
