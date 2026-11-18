#!/usr/bin/env bash
# Builds the experimental EasyPatch macOS agent installer: publishes easypatch-agent (self-contained, single file) and
# packages it as a .pkg per architecture (macOS 14 or later, x64 = Intel, arm64 = Apple silicon), in a pinned container
# (agent/Installer/macos/Dockerfile) with networking disabled.
#
#   scripts/build-macos-packages.sh [--version 1.10.0] [--arch x64|arm64|all] [--no-test]
#
# Output: artifacts/macos/EasyPatchAgent-<version>-<arch>.pkg, each with .sha256. The release public key
# (EASYPATCH_RELEASE_PUBLIC_KEY, default ~/.easypatch/easypatch-release-key.pub.pem) is built into the agent, and each
# package gets a release signature (<package>.sig) made with the private key (EASYPATCH_RELEASE_KEY, default
# ~/.easypatch/easypatch-release-key.pem). Copy the packages and their .sig files to the server's agent-packages directory.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="1.10.0"
arches=("x64")
run_tests=1
image="easypatch-macos-package-builder:xar1.8.0.498"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="$2"; shift 2 ;;
    --arch)
      if [[ "$2" == "all" ]]; then arches=("x64" "arm64"); else arches=("$2"); fi
      shift 2 ;;
    --no-test) run_tests=0; shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ ! "$version" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}$ ]]; then
  echo "version must be MAJOR.MINOR.BUILD, got '$version'" >&2
  exit 2
fi

for arch in "${arches[@]}"; do
  [[ "$arch" == "x64" || "$arch" == "arm64" ]] || { echo "unsupported architecture: $arch" >&2; exit 2; }
done

export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
cd "$repo_root"

public_key="${EASYPATCH_RELEASE_PUBLIC_KEY:-$HOME/.easypatch/easypatch-release-key.pub.pem}"
key_args=()
if [[ -f "$public_key" ]]; then
  public_key="$(cd "$(dirname "$public_key")" && pwd)/$(basename "$public_key")"
  grep -q "BEGIN PUBLIC KEY" "$public_key" || { echo "$public_key is not a PEM public key" >&2; exit 2; }
  key_args=("-p:EasyPatchReleasePublicKey=$public_key")
  echo "==> Release public key: $public_key (agents install only updates signed with its private key)"
else
  echo "WARNING: no release public key at $public_key: this agent will not be able to update itself." >&2
fi

echo "==> Building the macOS agent ($version, warnings are errors)"
for project in agent/EasyPatch.MacOS/EasyPatch.MacOS.csproj agent/EasyPatch.Agent.MacOS/EasyPatch.Agent.MacOS.csproj agent/EasyPatch.Agent.Tests/EasyPatch.Agent.Tests.csproj; do
  dotnet build "$project" -c Release "-p:Version=$version" "${key_args[@]}"
done

if [[ $run_tests -eq 1 ]]; then
  echo "==> Running agent tests"
  dotnet test agent/EasyPatch.Agent.Tests/EasyPatch.Agent.Tests.csproj -c Release --no-build
fi

echo "==> Building the package builder image ($image)"
docker build -q -t "$image" agent/Installer/macos >/dev/null

# File times in the package: the commit's time, so a rebuild of the same commit has the same payload.
epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}"

mkdir -p artifacts/macos
built=()
for arch in "${arches[@]}"; do
  publish="artifacts/agent/osx-$arch"
  echo "==> Publishing osx-$arch to $publish"
  rm -rf "$publish"
  dotnet publish agent/EasyPatch.Agent.MacOS/EasyPatch.Agent.MacOS.csproj -c Release -r "osx-$arch" -o "$publish" \
    "-p:Version=$version" -p:ContinuousIntegrationBuild=true -p:DebugType=none "${key_args[@]}"
  extra="$(find "$publish" -type f ! -name easypatch-agent | head -5)"
  [[ -z "$extra" ]] || { echo "unexpected files next to the single-file agent: $extra" >&2; exit 1; }

  pkg="EasyPatchAgent-$version-$arch.pkg"
  rm -f "artifacts/macos/$pkg"*
  echo "==> Building $pkg"
  # build-pkg.sh also checks the package: xar listing, payload byte-identical to the published agent, the Bom
  # against the payload, and check-pkg.py (owners, modes, Distribution, PackageInfo, Mach-O CPU and signature).
  docker run --rm --network none \
    -v "$repo_root/agent/Installer/macos:/pkg:ro" \
    -v "$repo_root/$publish:/publish:ro" \
    -v "$repo_root/artifacts/macos:/out" \
    "$image" sh /pkg/build-pkg.sh "$version" "$arch" "$epoch"

  hash="$(sha256sum "artifacts/macos/$pkg" | cut -d' ' -f1)"
  printf '%s  %s' "$hash" "$pkg" > "artifacts/macos/$pkg.sha256"
  echo "    artifacts/macos/$pkg"
  echo "    SHA-256 $hash"
  built+=("artifacts/macos/$pkg")
done

release_key="${EASYPATCH_RELEASE_KEY:-$HOME/.easypatch/easypatch-release-key.pem}"
if [[ -f "$release_key" ]]; then
  echo "==> Signing the release (agent self-update)"
  dotnet run --project tools/EasyPatch.ReleaseSigner -c Release -- sign --key "$release_key" "${built[@]}"
  if [[ -f "$public_key" ]]; then
    # The packages must verify against the public key built into the agent, or no agent will install them.
    dotnet run --project tools/EasyPatch.ReleaseSigner -c Release --no-build -- verify --public-key "$public_key" "${built[@]}"
  fi
else
  rm -f "${built[@]/%/.sig}"
  echo "WARNING: no release key at $release_key: the packages are not signed, so agents will not update themselves to them." >&2
fi
