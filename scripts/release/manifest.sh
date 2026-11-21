#!/bin/sh
# Writes the manifest of a release or an edge build to standard output, in
# the format of docs/architecture/edge-manifest.md (schemaVersion 2):
#
#   EASYRMM_IMAGE_PIN=ghcr.io/<owner>/easyrmm-server:<tag>@sha256:<digest> \
#   EASYPATCH_IMAGE_PIN=ghcr.io/<owner>/easypatch-server:<version>@sha256:<digest> \
#   [EASYPATCH_PACKAGES=<directory> | <release manifest>] \
#   scripts/release/manifest.sh <version> <commit> <bundle> <docker-compose.yml>
#
# bundle.sh runs it; the pins are the ones it checked. The images come from
# the bundle's docker-compose.yml, where every one but EasyRMM's server
# (named by .env, which the bundle's .env.example pins) must carry a tag and
# a digest. EASYPATCH_PACKAGES lists the engine's agent packages: a
# directory holding them (a release), or the manifest of the release whose
# engine this is (an edge build), whose engine must be the pinned one.
set -eu

die() {
  echo "manifest: $*" >&2
  exit 1
}

[ $# -eq 4 ] || die "usage: manifest.sh <version> <commit> <bundle> <docker-compose.yml>"
version=$1 commit=$2 bundle=$3 compose=$4
rmm_pin=${EASYRMM_IMAGE_PIN:?EASYRMM_IMAGE_PIN is required}
ep_pin=${EASYPATCH_IMAGE_PIN:?EASYPATCH_IMAGE_PIN is required}
printf '%s' "$commit" | grep -Eqx '[0-9a-f]{40}' || die "\"$commit\" is not a full commit"
[ -f "$bundle" ] || die "no bundle at $bundle"
[ -f "$compose" ] || die "no docker-compose.yml at $compose"
ep_version=${ep_pin##*/easypatch-server:}
ep_version=${ep_version%@*}

# "<service> <image>" for each service, in the order of the file. The
# server's line names its image through .env: the pin stands for it.
# shellcheck disable=SC2016 # the line as docker-compose.yml has it, unexpanded
server_line='${EASYRMM_IMAGE:-ghcr.io/paulmataruso/easyrmm-server}:${EASYRMM_VERSION:-latest}'
services=$(awk -v server="$server_line" -v pin="$rmm_pin" '
  /^services:/ { in_services = 1; next }
  /^[^ #]/ { in_services = 0 }
  in_services && /^  [A-Za-z0-9_.-]+:[ ]*$/ { service = $1; sub(/:$/, "", service); next }
  in_services && /^    image: / {
    image = substr($0, length("    image: ") + 1)
    if (image == server) image = pin
    print service, image
  }
' "$compose")
[ -n "$services" ] || die "$compose names no images"
pinned='[a-z0-9]+([._/-][a-z0-9]+)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}@sha256:[0-9a-f]{64}'
unpinned=$(printf '%s\n' "$services" | while read -r service image; do
  printf '%s' "$image" | grep -Eqx "$pinned" || echo "  $service: $image"
done)
[ -z "$unpinned" ] || die "$(printf 'every image must be named by tag and digest; these are not:\n%s' "$unpinned")"
image_of() { printf '%s\n' "$services" | awk -v s="$1" '$1 == s { print $2; exit }'; }
tag_of() { # image: its tag
  t=${1%@*}
  printf '%s' "${t##*:}"
}

[ "$(image_of server)" = "$rmm_pin" ] || die "the server's image line is not $server_line"
printf '%s\n' "$services" | awk '{ print $2 }' | grep -qxF "$ep_pin" || die "$compose does not run the engine $ep_pin"
postgres=$(image_of postgres)
[ -n "$postgres" ] || die "$compose has no postgres service"
major=$(tag_of "$postgres" | sed -n 's/^\([1-9][0-9]*\)\([.-].*\)\{0,1\}$/\1/p')
[ -n "$major" ] || die "no major version in PostgreSQL's tag: $postgres"
meshcentral=$(image_of meshcentral)
[ -n "$meshcentral" ] || die "$compose has no meshcentral service"
authentik=$(image_of authentik-server)
images=$(printf '%s\n' "$services" | awk '{ print $2 }' | LC_ALL=C sort -u | jq -R . | jq -s .)

# The engine's agent packages.
packages_from=${EASYPATCH_PACKAGES:-}
if [ -z "$packages_from" ]; then
  packages='[]'
elif [ -d "$packages_from" ]; then
  packages=$(cd "$packages_from" && find . -maxdepth 1 -type f -name 'EasyPatchAgent-*' ! -name '*.sig' -printf '%f\n' |
    LC_ALL=C sort | while IFS= read -r f; do
      jq -n --arg file "$f" --arg sha256 "$(sha256sum "$f" | cut -d' ' -f1)" '{file: $file, sha256: $sha256}'
    done | jq -s .)
  printf '%s' "$packages" | jq -e --arg v "EasyPatchAgent-$ep_version-" 'any(.[]; .file | startswith($v))' > /dev/null ||
    die "no EasyPatch $ep_version agent packages in $packages_from"
elif [ -f "$packages_from" ]; then
  from_image=$(jq -r '.easypatch.image // ""' "$packages_from")
  [ "$from_image" = "$ep_pin" ] || die "$packages_from names the engine \"$from_image\", not $ep_pin"
  packages=$(jq -e '.easypatch.agentPackages | arrays' "$packages_from") || die "$packages_from lists no agent packages"
else
  die "EASYPATCH_PACKAGES=$packages_from is neither a directory nor a manifest"
fi

if [ -n "$authentik" ]; then
  authentik=$(jq -n --arg image "$authentik" --arg version "$(tag_of "$authentik")" \
    '{included: true, version: $version, image: $image}')
else
  authentik='{"included": false}'
fi

jq -n \
  --arg version "$version" --arg commit "$commit" \
  --arg bundle_file "$(basename "$bundle")" --arg bundle_sha256 "$(sha256sum "$bundle" | cut -d' ' -f1)" \
  --arg rmm_pin "$rmm_pin" --arg ep_version "$ep_version" --arg ep_pin "$ep_pin" --argjson packages "$packages" \
  --argjson major "$major" --arg postgres "$postgres" --arg meshcentral "$meshcentral" \
  --argjson authentik "$authentik" --argjson images "$images" '
  {
    schemaVersion: 2,
    version: $version,
    commit: $commit,
    bundle: {file: $bundle_file, sha256: $bundle_sha256},
    easyrmm: {version: $version, image: $rmm_pin},
    easypatch: {version: $ep_version, image: $ep_pin, agentPackages: $packages},
    postgres: {major: $major, image: $postgres},
    meshcentral: {image: $meshcentral},
    authentik: $authentik,
    images: $images
  }'
