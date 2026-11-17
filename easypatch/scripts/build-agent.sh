#!/usr/bin/env bash
# Builds, tests and publishes the EasyPatch agent from Linux or macOS.
# Build the MSI with scripts/build-msi-linux.sh (Docker, WiX under Wine) or on Windows with scripts/build-agent.ps1.
#
#   scripts/build-agent.sh [--version 1.2.3] [--no-test] [--rid win-x64|win-arm64|all]
#
# The release public key (EASYPATCH_RELEASE_PUBLIC_KEY, default ~/.easypatch/easypatch-release-key.pub.pem) is built
# into the agent: it installs only agent updates signed with the matching private key. Without it the agent cannot
# update itself. Create the key pair once with: dotnet run --project tools/EasyPatch.ReleaseSigner -- generate-key
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="1.10.0"
run_tests=1
rids=("win-x64")

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="$2"; shift 2 ;;
    --no-test) run_tests=0; shift ;;
    --rid)
      if [[ "$2" == "all" ]]; then rids=("win-x64" "win-arm64"); else rids=("$2"); fi
      shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ ! "$version" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}$ ]]; then
  echo "version must be MAJOR.MINOR.BUILD (MSI-compatible), got '$version'" >&2
  exit 2
fi

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
  echo "WARNING: no release public key at $public_key." >&2
  echo "         This agent will not be able to update itself; it must be upgraded by installing a newer MSI." >&2
  echo "         Create one with: dotnet run --project tools/EasyPatch.ReleaseSigner -- generate-key" >&2
fi

projects=(
  agent/EasyPatch.Communication/EasyPatch.Communication.csproj
  agent/EasyPatch.Agent.Core/EasyPatch.Agent.Core.csproj
  agent/EasyPatch.WindowsUpdate/EasyPatch.WindowsUpdate.csproj
  agent/EasyPatch.Inventory/EasyPatch.Inventory.csproj
  agent/EasyPatch.Agent/EasyPatch.Agent.csproj
  agent/EasyPatch.Agent.Tests/EasyPatch.Agent.Tests.csproj
)

echo "==> Building agent projects ($version, warnings are errors)"
for project in "${projects[@]}"; do
  dotnet build "$project" -c Release "-p:Version=$version" "${key_args[@]}"
done

if [[ $run_tests -eq 1 ]]; then
  echo "==> Running agent tests"
  dotnet test agent/EasyPatch.Agent.Tests/EasyPatch.Agent.Tests.csproj -c Release --no-build
fi

for rid in "${rids[@]}"; do
  out="artifacts/agent/$rid"
  echo "==> Publishing $rid to $out"
  rm -rf "$out"
  dotnet publish agent/EasyPatch.Agent/EasyPatch.Agent.csproj -c Release -r "$rid" -o "$out" "-p:Version=$version" -p:ContinuousIntegrationBuild=true \
    "${key_args[@]}"
  sha256sum "$out/EasyPatch.Agent.exe"
done

echo "Done. Build the MSI with scripts/build-msi-linux.sh (Docker) or, on Windows, scripts/build-agent.ps1."
