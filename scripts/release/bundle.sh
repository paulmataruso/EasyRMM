#!/bin/sh
# Builds the files attached to a GitHub release:
#
#   easyrmm-<version>-deploy.tar.gz    the Compose deployment, pinned to this release's images
#   easyrmm-<version>-manifest.json    the versions and image digests of this release
#   easyrmm-agent-<os>-<arch>[.exe]    the agents (the server image carries the same ones)
#   SHA256SUMS
#
#   EASYRMM_IMAGE_PIN=ghcr.io/<owner>/easyrmm-server:1.2.3@sha256:<digest> \
#   EASYPATCH_IMAGE_PIN=ghcr.io/<owner>/easypatch-server:1.10.1@sha256:<digest> \
#   [EASYPATCH_PACKAGES=<dir>] scripts/release/bundle.sh easyrmm-v1.2.3 [out-dir]
#
# Takes the release tag (easyrmm-v1.2.3) or the version alone (v1.2.3); the
# files carry the version (easyrmm-v1.2.3-deploy.tar.gz, agents reporting
# v1.2.3) either way.
#
# The patching engine is part of the release (ADR-0043): the bundle's
# docker-compose.yml names its image by digest, so a deployment runs the
# engine built from the same commit, and upgrading the bundle upgrades both.
# The manifest records both images, the engine's version and, with
# EASYPATCH_PACKAGES, the EasyPatch agent packages its image carries.
#
# The output depends only on the commit, the Go toolchain and the pins:
# archive entries are sorted, owned by root and dated at the commit, and gzip
# stores no name or time.
set -eu

tag=${1:?usage: bundle.sh easyrmm-vX.Y.Z [out-dir]}
version=${tag#easyrmm-}
if ! printf '%s' "$version" | grep -Eqx 'v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?'; then
  echo "bundle: \"$tag\" is not a release tag like easyrmm-v1.2.3 or easyrmm-v1.2.3-rc.1" >&2
  exit 1
fi
root=$(cd "$(dirname "$0")/../.." && pwd)
out=${2:-$root/dist/release}
go=${GO:-go}
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}
image_tag=${version#v}

owner_re='ghcr\.io/[a-z0-9][a-z0-9-]*'
digest_re='@sha256:[0-9a-f]{64}'
rmm_pin=${EASYRMM_IMAGE_PIN:-}
ep_pin=${EASYPATCH_IMAGE_PIN:-}
tag_re=$(printf '%s' "$image_tag" | sed 's/[.]/\\./g')
if ! printf '%s' "$rmm_pin" | grep -Eqx "$owner_re/easyrmm-server:$tag_re$digest_re"; then
  echo "bundle: EASYRMM_IMAGE_PIN must be ghcr.io/<owner>/easyrmm-server:$image_tag@sha256:<digest>, got \"$rmm_pin\"" >&2
  exit 1
fi
if ! printf '%s' "$ep_pin" | grep -Eqx "$owner_re/easypatch-server:[0-9]+\.[0-9]+\.[0-9]+$digest_re"; then
  echo "bundle: EASYPATCH_IMAGE_PIN must be ghcr.io/<owner>/easypatch-server:<version>@sha256:<digest>, got \"$ep_pin\"" >&2
  exit 1
fi
ep_version=${ep_pin##*/easypatch-server:}
ep_version=${ep_version%@*}
if [ -n "${EASYPATCH_PACKAGES:-}" ] && [ ! -d "$EASYPATCH_PACKAGES" ]; then
  echo "bundle: EASYPATCH_PACKAGES=$EASYPATCH_PACKAGES is not a directory" >&2
  exit 1
fi

rm -rf "$out"
mkdir -p "$out"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

# --- Deployment bundle --------------------------------------------------------
name=easyrmm-$version
dir=$stage/$name
"$root/scripts/release/deploy-tree.sh" "$dir"
sed -e "s|^EASYRMM_VERSION=.*|EASYRMM_VERSION=$image_tag|" "$root/deploy/.env.example" > "$dir/deploy/.env.example"
if ! grep -qx "EASYRMM_VERSION=$image_tag" "$dir/deploy/.env.example"; then
  echo "bundle: could not pin EASYRMM_VERSION in .env.example" >&2
  exit 1
fi
# The engine by digest: each of its three services names the image, and the
# build from ../easypatch (a clone's) goes, so a pinned engine is never built.
compose=$dir/deploy/docker-compose.yml
awk -v pin="$ep_pin" '
  function flush() { if (held != "") { print held; held = "" } }
  skip && /^      / { next }
  skip { skip = 0 }
  held != "" && /^      context: \.\.\/easypatch$/ { held = ""; skip = 1; built++; next }
  { flush() }
  /^    build:$/ { held = $0; next }
  /^    image: \$\{EASYPATCH_IMAGE:-[^}]*\}:\$\{EASYPATCH_VERSION:-[^}]*\}$/ { print "    image: " pin; pinned++; next }
  { print }
  END { flush(); if (pinned != 3 || built != 1) exit 3 }
' "$compose" > "$stage/compose.yml" || {
  echo "bundle: could not pin the patching engine in docker-compose.yml (three image lines and its build)" >&2
  exit 1
}
mv "$stage/compose.yml" "$compose"
chmod 0644 "$compose"
if grep -q 'EASYPATCH_IMAGE\|EASYPATCH_VERSION\|\.\./easypatch' "$compose" || [ "$(grep -c "image: $ep_pin\$" "$compose")" -ne 3 ]; then
  echo "bundle: docker-compose.yml still names the engine without its digest" >&2
  exit 1
fi
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner --format=gnu \
  -C "$stage" -cf - "$name" | gzip -n -9 > "$out/$name-deploy.tar.gz"

# --- Manifest -----------------------------------------------------------------
commit=$(git -C "$root" rev-parse HEAD)
packages=""
if [ -n "${EASYPATCH_PACKAGES:-}" ]; then
  packages=$(cd "$EASYPATCH_PACKAGES" && find . -maxdepth 1 -type f -name 'EasyPatchAgent-*' ! -name '*.sig' -printf '%f\n' |
    LC_ALL=C sort | while IFS= read -r f; do
      printf '      {"file": "%s", "sha256": "%s"},\n' "$f" "$(sha256sum "$f" | cut -d' ' -f1)"
    done | sed '$ s/,$//')
  if [ -z "$packages" ] || ! printf '%s\n' "$packages" | grep -q "EasyPatchAgent-$ep_version-"; then
    echo "bundle: no EasyPatch $ep_version agent packages in $EASYPATCH_PACKAGES" >&2
    exit 1
  fi
fi
{
  printf '{\n'
  printf '  "commit": "%s",\n' "$commit"
  printf '  "easyrmm": {\n    "version": "%s",\n    "image": "%s"\n  },\n' "$version" "$rmm_pin"
  printf '  "easypatch": {\n    "version": "%s",\n    "image": "%s",\n    "agentPackages": [' "$ep_version" "$ep_pin"
  if [ -n "$packages" ]; then printf '\n%s\n    ]\n' "$packages"; else printf ']\n'; fi
  printf '  }\n}\n'
} > "$out/$name-manifest.json"

# --- Agents -------------------------------------------------------------------
build() { # os arch suffix [GOARM]
  CGO_ENABLED=0 GOOS=$1 GOARCH=$2 GOARM=${4:-} "$go" -C "$root" build -trimpath \
    -ldflags "-s -w -X main.Version=$version" \
    -o "$out/easyrmm-agent-$1-$2$3" ./agent/cmd/easyrmm-agent
}
build windows amd64 .exe
build windows arm64 .exe
build linux amd64 ""
build linux arm64 ""
build linux arm "" 7
build linux 386 ""

# --- Checksums ----------------------------------------------------------------
sums=$(cd "$out" && find . -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort | xargs sha256sum)
printf '%s\n' "$sums" > "$out/SHA256SUMS"
ls -l "$out"
