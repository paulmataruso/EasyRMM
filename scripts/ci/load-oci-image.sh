#!/bin/sh
# Loads one platform's image from an OCI image layout into Docker:
#
#   scripts/ci/load-oci-image.sh easyrmm-server.oci.tar linux/amd64 easyrmm-server:ci
#
# CI builds the server image once, for every platform, into an OCI layout
# (BuildKit's oci exporter, a tarball), runs its tests on this platform's
# image from that layout, and pushes the layout unchanged (ADR-0052). docker
# load reads Docker's archive: an OCI layout with a manifest.json naming the
# image's config and layers, which this adds. The loaded image must have the
# layout's layers, by their uncompressed digests.
set -eu

[ $# -eq 3 ] || { echo "usage: load-oci-image.sh <layout.tar> <os/arch> <name:tag>" >&2; exit 2; }
layout=$1 platform=$2 tag=$3
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xf "$layout" -C "$work"
blob() { printf '%s/blobs/%s' "$work" "$(printf '%s' "$1" | tr : /)"; }

index=$(jq -r '.manifests | if length == 1 then .[0].digest else error("the layout holds \(length) images, not one") end' \
  "$work/index.json")
manifest=$(jq -r --arg os "${platform%%/*}" --arg arch "${platform#*/}" '
  [.manifests[] | select(.platform.os == $os and .platform.architecture == $arch)]
  | if length == 1 then .[0].digest else error("the image has \(length) manifests for \($os)/\($arch), not one") end' \
  "$(blob "$index")")
jq --arg tag "$tag" '[{
  Config: ("blobs/" + (.config.digest | sub(":"; "/"))),
  RepoTags: [$tag],
  Layers: [.layers[].digest | "blobs/" + sub(":"; "/")]
}]' "$(blob "$manifest")" > "$work/manifest.json"
tar -C "$work" -cf - manifest.json blobs | docker load

config=$(jq -r .config.digest "$(blob "$manifest")")
want=$(jq -c .rootfs.diff_ids "$(blob "$config")")
got=$(docker image inspect -f '{{json .RootFS.Layers}}' "$tag")
if [ "$got" != "$want" ]; then
  echo "load-oci-image: $tag has the layers $got, not the layout's $want" >&2
  exit 1
fi
echo "Loaded $platform of $index as $tag"
