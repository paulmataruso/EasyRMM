#!/bin/sh
# Builds the files attached to a GitHub release:
#
#   easyrmm-<version>-deploy.tar.gz   the Compose deployment, pinned to this release's image
#   easyrmm-agent-<os>-<arch>[.exe]   the agents (the server image carries the same ones)
#   SHA256SUMS
#
#   scripts/release/bundle.sh easyrmm-v1.2.3 [out-dir]
#
# Takes the release tag (easyrmm-v1.2.3) or the version alone (v1.2.3); the
# files carry the version (easyrmm-v1.2.3-deploy.tar.gz, agents reporting
# v1.2.3) either way.
#
# The output depends only on the commit and the Go toolchain: archive entries
# are sorted, owned by root and dated at the commit, and gzip stores no name
# or time.
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

rm -rf "$out"
mkdir -p "$out"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

# --- Deployment bundle --------------------------------------------------------
# The repository's layout, so docker-compose.yml's relative mounts resolve
# and the install commands are the same as from a clone (cd deploy).
name=easyrmm-$version
dir=$stage/$name
mkdir -p "$dir/deploy/scripts" "$dir/deploy/easypatch" "$dir/docker/postgres/init" "$dir/docker/meshcentral" \
  "$dir/docs/deployment" "$dir/docs/operations"
cp "$root/LICENSE" "$root/CHANGELOG.md" "$dir/"
cp "$root/deploy/docker-compose.yml" "$dir/deploy/"
cp "$root/deploy/scripts/setup.sh" "$dir/deploy/scripts/"
# For EasyPatch on the same server (docs/deployment/easypatch-cohost.md).
cp "$root/deploy/easypatch/Caddyfile.easyrmm" "$root/deploy/easypatch/docker-compose.easyrmm.yml" "$dir/deploy/easypatch/"
cp "$root/docker/postgres/init/"*.sh "$dir/docker/postgres/init/"
cp "$root/docker/meshcentral/start.sh" "$dir/docker/meshcentral/"
cp "$root/docs/deployment/docker.md" "$root/docs/deployment/agents.md" "$root/docs/deployment/easypatch-cohost.md" "$dir/docs/deployment/"
cp "$root/docs/operations/backup-restore.md" "$root/docs/operations/upgrading.md" "$dir/docs/operations/"
sed -e "s|^EASYRMM_VERSION=.*|EASYRMM_VERSION=$image_tag|" "$root/deploy/.env.example" > "$dir/deploy/.env.example"
if ! grep -qx "EASYRMM_VERSION=$image_tag" "$dir/deploy/.env.example"; then
  echo "bundle: could not pin EASYRMM_VERSION in .env.example" >&2
  exit 1
fi
# Everything the Compose file mounts from beside it must be in the bundle.
missing=$(sed -n 's|^ *- \(\.\./[^:]*\):.*|\1|p' "$dir/deploy/docker-compose.yml" |
  while IFS= read -r src; do [ -e "$dir/deploy/$src" ] || echo "$src"; done)
if [ -n "$missing" ]; then
  printf "bundle: docker-compose.yml mounts files the bundle lacks:\n%s\n" "$missing" >&2
  exit 1
fi
find "$dir" -type d -exec chmod 0755 {} +
find "$dir" -type f -exec chmod 0644 {} +
chmod 0755 "$dir/deploy/scripts/setup.sh" "$dir/docker/postgres/init/"*.sh "$dir/docker/meshcentral/start.sh"
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner --format=gnu \
  -C "$stage" -cf - "$name" | gzip -n -9 > "$out/$name-deploy.tar.gz"

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
