#!/bin/sh
# Builds the files attached to a GitHub release, and those of an edge build
# of main (ADR-0052; docs/architecture/edge-manifest.md):
#
#   easyrmm-<version>-deploy.tar.gz    the Compose deployment, pinned to this version's images
#   easyrmm-<version>-manifest.json    its version, commit, bundle digest and images (manifest.sh)
#   easyrmm-agent-<os>-<arch>[.exe]    the agents (agents.sh; the server image carries the same ones)
#   SHA256SUMS
#
#   EASYRMM_IMAGE_PIN=ghcr.io/<owner>/easyrmm-server:1.2.3@sha256:<digest> \
#   EASYPATCH_IMAGE_PIN=ghcr.io/<owner>/easypatch-server:1.10.1@sha256:<digest> \
#   [EASYPATCH_PACKAGES=<dir> | <release manifest>] scripts/release/bundle.sh easyrmm-v1.2.3 [out-dir]
#
# Takes the release tag (easyrmm-v1.2.3), the version alone (v1.2.3), or an
# edge version (v1.0.1-edge.415.1, from version.sh); the files carry the
# version (easyrmm-v1.2.3-deploy.tar.gz, agents reporting v1.2.3) either
# way. The bundle's .env.example names the server image by tag and digest,
# which setup.sh --upgrade copies into .env.
#
# The patching engine is part of the release (ADR-0043): the bundle's
# docker-compose.yml names its image by digest, so a deployment runs the
# engine built from the same commit, and upgrading the bundle upgrades both.
# An edge build runs the engine of the last release. EASYPATCH_PACKAGES
# lists the agent packages the engine's image carries, in the manifest: the
# packages themselves (a release), or the manifest of the release whose
# engine it is (an edge build).
#
# The output depends only on the commit, the Go toolchain and the pins:
# archive entries are sorted, owned by root and dated at the commit, and gzip
# stores no name or time.
set -eu

tag=${1:?usage: bundle.sh easyrmm-vX.Y.Z [out-dir]}
version=${tag#easyrmm-}
n='(0|[1-9][0-9]*)'
p='[1-9][0-9]*'
if ! printf '%s' "$version" | grep -Eqx "v$n\\.$n\\.$n(-rc\\.$p(\\.edge\\.$p\\.$p)?|-edge\\.$p\\.$p)?"; then
  echo "bundle: \"$tag\" is not a release tag like easyrmm-v1.2.3 or easyrmm-v1.2.3-rc.1, nor an edge version" >&2
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
if [ -n "${EASYPATCH_PACKAGES:-}" ] && [ ! -e "$EASYPATCH_PACKAGES" ]; then
  echo "bundle: EASYPATCH_PACKAGES=$EASYPATCH_PACKAGES does not exist" >&2
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
# The server by tag and digest: the image line is
# ${EASYRMM_IMAGE}:${EASYRMM_VERSION}, so the two make the pin.
rmm_repo=${rmm_pin%:*@*}
rmm_version=${rmm_pin#"$rmm_repo":}
sed -e "s|^EASYRMM_IMAGE=.*|EASYRMM_IMAGE=$rmm_repo|" -e "s|^EASYRMM_VERSION=.*|EASYRMM_VERSION=$rmm_version|" \
  "$root/deploy/.env.example" > "$dir/deploy/.env.example"
if ! grep -qx "EASYRMM_IMAGE=$rmm_repo" "$dir/deploy/.env.example" ||
  ! grep -qx "EASYRMM_VERSION=$rmm_version" "$dir/deploy/.env.example"; then
  echo "bundle: could not pin EASYRMM_IMAGE and EASYRMM_VERSION in .env.example" >&2
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
"$root/scripts/release/manifest.sh" "$version" "$(git -C "$root" rev-parse HEAD)" "$out/$name-deploy.tar.gz" "$compose" \
  > "$out/$name-manifest.json"

# --- Agents -------------------------------------------------------------------
GO=$go "$root/scripts/release/agents.sh" "$version" "$out"

# --- Checksums ----------------------------------------------------------------
sums=$(cd "$out" && find . -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort | xargs sha256sum)
printf '%s\n' "$sums" > "$out/SHA256SUMS"
ls -l "$out"
