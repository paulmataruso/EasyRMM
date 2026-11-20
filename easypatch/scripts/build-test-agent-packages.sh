#!/usr/bin/env bash
# Builds the Linux agent packages signed with a throwaway test key, and stages them for the server image, for CI images
# and tests. The agents in them trust that test key only, and no released agent trusts it, so an image built this way
# carries packages that no real agent installs as an update. It must never be published.
#
#   scripts/build-test-agent-packages.sh [--version 1.11.0] [--arch x64|arm64|all]
#
# The key pair is made in a temporary directory, and the private key is deleted at the end. The public key is kept as
# artifacts/test-release-key.pub.pem for tests that check signatures. Needs the .NET SDK and Docker
# (scripts/build-linux-packages.sh).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="1.11.0"
arch="all"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="$2"; shift 2 ;;
    --arch) arch="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$arch" in
  all) arches="x64,arm64" ;;
  x64|arm64) arches="$arch" ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

cd "$repo_root"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "==> Making a test release key"
dotnet run --project tools/EasyPatch.ReleaseSigner -c Release -- generate-key --out "$work/test-release-key.pem"

EASYPATCH_RELEASE_KEY="$work/test-release-key.pem" EASYPATCH_RELEASE_PUBLIC_KEY="$work/test-release-key.pub.pem" \
  scripts/build-linux-packages.sh --version "$version" --arch "$arch" --no-test

mkdir -p artifacts
install -m 0644 "$work/test-release-key.pub.pem" artifacts/test-release-key.pub.pem
scripts/stage-agent-packages.sh --version "$version" --public-key artifacts/test-release-key.pub.pem \
  --formats deb,rpm --arches "$arches" artifacts/linux

# Not release-signed: the release key must refuse every one of them.
for package in deployment/server/agent-packages/EasyPatchAgent-*.deb deployment/server/agent-packages/EasyPatchAgent-*.rpm; do
  if dotnet run --project tools/EasyPatch.ReleaseSigner -c Release --no-build -- \
      verify --public-key keys/easypatch-release-key.pub.pem "$package" > /dev/null 2>&1; then
    echo "$package verifies with the release key; a test build must not" >&2
    exit 1
  fi
done
echo "==> Test packages staged; their agents trust artifacts/test-release-key.pub.pem only"
