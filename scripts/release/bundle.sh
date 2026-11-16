#!/bin/sh
# Builds the files attached to a GitHub release:
#
#   easyrmm-<version>-deploy.tar.gz   the Compose deployment, pinned to this release's image
#   easyrmm-agent-<os>-<arch>[.exe]   the agents (the server image carries the same ones)
#   SHA256SUMS
#
#   scripts/release/bundle.sh v1.2.3 [out-dir]
#
# The output depends only on the commit and the Go toolchain: archive entries
# are sorted, owned by root and dated at the commit, and gzip stores no name
# or time.
set -eu

version=${1:?usage: bundle.sh vX.Y.Z [out-dir]}
if ! printf '%s' "$version" | grep -Eqx 'v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?'; then
  echo "bundle: \"$version\" is not a version tag like v1.2.3 or v1.2.3-rc.1" >&2
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
name=easyrmm-$version
dir=$stage/$name
mkdir -p "$dir/scripts" "$dir/docs"
cp "$root/deploy/docker-compose.yml" "$root/LICENSE" "$root/CHANGELOG.md" "$dir/"
cp "$root/deploy/scripts/setup.sh" "$dir/scripts/"
cp "$root/docs/deployment/docker.md" "$root/docs/operations/backup-restore.md" "$dir/docs/"
sed -e "s|^EASYRMM_VERSION=.*|EASYRMM_VERSION=$image_tag|" "$root/deploy/.env.example" > "$dir/.env.example"
if ! grep -qx "EASYRMM_VERSION=$image_tag" "$dir/.env.example"; then
  echo "bundle: could not pin EASYRMM_VERSION in .env.example" >&2
  exit 1
fi
find "$dir" -type d -exec chmod 0755 {} +
find "$dir" -type f -exec chmod 0644 {} +
chmod 0755 "$dir/scripts/setup.sh"
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
