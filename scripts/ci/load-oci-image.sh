#!/bin/sh
# Loads one platform's image from an OCI image layout into Docker, if the
# layout is the image whose index digest is given:
#
#   scripts/ci/load-oci-image.sh easyrmm-server.oci.tar sha256:<index> linux/amd64 easyrmm-server:ci
#
# CI builds the server image once, for every platform, into an OCI layout
# (BuildKit's oci exporter, a tarball), runs its tests on images loaded from
# that layout, and pushes the layout unchanged (ADR-0052); the digest is the
# one the build recorded, which the push keeps. The layout must hold exactly
# that index; the index, the platform's manifest and its config must each
# hash to the digest that names them, and the loaded image must have the
# config's layers, by their uncompressed digests, so what runs is what is
# pushed. docker load reads Docker's archive: an OCI layout with a
# manifest.json naming the image's config and layers, which this adds.
set -eu

[ $# -eq 4 ] || { echo "usage: load-oci-image.sh <layout.tar> <index digest> <os/arch> <name:tag>" >&2; exit 2; }
layout=$1 digest=$2 platform=$3 tag=$4
printf '%s' "$digest" | grep -Eqx 'sha256:[0-9a-f]{64}' || { echo "load-oci-image: \"$digest\" is not a digest" >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xf "$layout" -C "$work"

# blob <digest>: the blob's path, once its content hashes to the digest.
blob() {
  path="$work/blobs/sha256/${1#sha256:}"
  if [ ! -f "$path" ] || [ "sha256:$(sha256sum < "$path" | cut -c1-64)" != "$1" ]; then
    echo "load-oci-image: the layout's blob $1 is missing or does not match its digest" >&2
    exit 1
  fi
  printf '%s' "$path"
}

index=$(jq -r '.manifests | if length == 1 then .[0].digest else error("the layout holds \(length) images, not one") end' \
  "$work/index.json")
if [ "$index" != "$digest" ]; then
  echo "load-oci-image: the layout holds $index, not $digest" >&2
  exit 1
fi
index_blob=$(blob "$index")
manifest=$(jq -r --arg os "${platform%%/*}" --arg arch "${platform#*/}" '
  [.manifests[] | select(.platform.os == $os and .platform.architecture == $arch)]
  | if length == 1 then .[0].digest else error("the image has \(length) manifests for \($os)/\($arch), not one") end' \
  "$index_blob")
manifest_blob=$(blob "$manifest")
config=$(jq -r .config.digest "$manifest_blob")
config_blob=$(blob "$config")
jq --arg tag "$tag" '[{
  Config: ("blobs/" + (.config.digest | sub(":"; "/"))),
  RepoTags: [$tag],
  Layers: [.layers[].digest | "blobs/" + sub(":"; "/")]
}]' "$manifest_blob" > "$work/manifest.json"
tar -C "$work" -cf - manifest.json blobs | docker load

want=$(jq -c .rootfs.diff_ids "$config_blob")
got=$(docker image inspect -f '{{json .RootFS.Layers}}' "$tag")
if [ "$got" != "$want" ]; then
  echo "load-oci-image: $tag has the layers $got, not the layout's $want" >&2
  exit 1
fi
echo "Loaded $platform of $index as $tag"
