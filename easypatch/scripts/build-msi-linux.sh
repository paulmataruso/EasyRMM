#!/usr/bin/env bash
# Builds the EasyPatch agent MSIs on Linux with Docker: publishes the agent (scripts/build-agent.sh), then runs
# WiX Toolset 5.0.2 under Wine in a pinned container (agent/Installer/linux/Dockerfile) with networking disabled.
# Output matches scripts/build-agent.ps1: artifacts/installer/EasyPatchAgent-<version>-<arch>.msi plus .sha256.
#
#   scripts/build-msi-linux.sh [--version 1.2.3] [--arch x64|arm64|all] [--no-test]
#
# Not available on Linux: ICE validation (Wine cannot run it) and Authenticode signing. Build release packages that
# must be Authenticode-signed or ICE-validated on Windows (scripts/build-agent.ps1 or the agent CI workflow).
#
# Release signatures for agent self-update are made here: each MSI gets <msi>.sig, signed with the release private key
# (EASYPATCH_RELEASE_KEY, default ~/.easypatch/easypatch-release-key.pem; EASYPATCH_RELEASE_KEY_PASSWORD if it is
# encrypted). Copy the MSI and its .sig to the server's agent-packages directory.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="1.10.0"
arches=("x64")
test_flag=()
image="easypatch-msi-builder:wix5.0.2"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="$2"; shift 2 ;;
    --arch)
      if [[ "$2" == "all" ]]; then arches=("x64" "arm64"); else arches=("$2"); fi
      shift 2 ;;
    --no-test) test_flag=(--no-test); shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

for arch in "${arches[@]}"; do
  [[ "$arch" == "x64" || "$arch" == "arm64" ]] || { echo "unsupported architecture: $arch" >&2; exit 2; }
done

cd "$repo_root"
rids=()
for arch in "${arches[@]}"; do rids+=("win-$arch"); done
rid_arg="${rids[0]}"
[[ ${#rids[@]} -gt 1 ]] && rid_arg="all"
scripts/build-agent.sh --version "$version" --rid "$rid_arg" "${test_flag[@]}"

echo "==> Building the MSI builder image ($image)"
docker build -q -t "$image" agent/Installer/linux >/dev/null

mkdir -p artifacts/installer
built=()
for arch in "${arches[@]}"; do
  name="EasyPatchAgent-$version-$arch.msi"
  echo "==> Building $name"
  rm -f "artifacts/installer/$name" "artifacts/installer/$name.sha256"
  docker run --rm --network none \
    -v "$repo_root/agent:/src:ro" \
    -v "$repo_root/artifacts/agent/win-$arch:/publish:ro" \
    -v "$repo_root/artifacts/installer:/out" \
    "$image" sh -c '
      set -e
      wine /opt/dotnet/dotnet.exe /opt/wix/tools/net6.0/any/wix.dll build "Z:\\src\\Installer\\Package.wxs" \
        -ext "Z:\\opt\\wix-util\\wixext5\\WixToolset.Util.wixext.dll" \
        -arch "$1" -d "ProductVersion=$2" -d "PublishDir=Z:\\publish\\" \
        -intermediatefolder "Z:\\tmp\\wixobj" -o "Z:\\tmp\\$3" 2>&1 | grep -v "^error: XDG_RUNTIME_DIR" || true
      test -s "/tmp/$3"
      # Guard against regressions that would expose the enrollment token in MSI logs.
      msiinfo export "/tmp/$3" Property | tr -d "\r" | grep -q "^MsiHiddenProperties.*ENROLLMENTTOKEN"
      msiinfo export "/tmp/$3" ActionText | tr -d "\r" | grep -q "^WriteRegistryValues.*Key: \[1\], Name: \[2\]$"
      # Installed apps icon.
      msiinfo export "/tmp/$3" Property | tr -d "\r" | grep -q "^ARPPRODUCTICON	EasyPatch.ico$"
      cp "/tmp/$3" "/out/$3"' sh "$arch" "$version" "$name"

  hash="$(sha256sum "artifacts/installer/$name" | cut -d' ' -f1)"
  printf '%s  %s' "$hash" "$name" > "artifacts/installer/$name.sha256"
  echo "    artifacts/installer/$name"
  echo "    SHA-256 $hash"
  built+=("artifacts/installer/$name")
done

release_key="${EASYPATCH_RELEASE_KEY:-$HOME/.easypatch/easypatch-release-key.pem}"
public_key="${EASYPATCH_RELEASE_PUBLIC_KEY:-$HOME/.easypatch/easypatch-release-key.pub.pem}"
if [[ -f "$release_key" ]]; then
  echo "==> Signing the release (agent self-update)"
  dotnet run --project tools/EasyPatch.ReleaseSigner -c Release -- sign --key "$release_key" "${built[@]}"
  if [[ -f "$public_key" ]]; then
    # The packages must verify against the public key built into the agent, or no agent will install them.
    dotnet run --project tools/EasyPatch.ReleaseSigner -c Release --no-build -- verify --public-key "$public_key" "${built[@]}"
  fi
else
  rm -f "${built[@]/%/.sig}"
  echo "WARNING: no release key at $release_key: the MSIs are not signed, so agents will not update themselves to them." >&2
fi
