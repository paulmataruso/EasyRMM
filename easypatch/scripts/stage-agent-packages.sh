#!/usr/bin/env bash
# Puts the agent packages of one version, each with its release signature, where the server image's build takes them
# from (deployment/server/agent-packages/), after checking every signature against the given public key.
#
#   scripts/stage-agent-packages.sh --version 1.10.0 --public-key <public.pem> [--formats msi,deb,rpm]
#                                   [--arches x64,arm64] <dir>...
#
# Each format must be there for each architecture, with its .sig, in exactly one of the directories. Packages staged
# before are removed first. Needs the .NET SDK: the release signer checks the signatures. There is no default key: the
# release workflow passes the release public key, scripts/build-test-agent-packages.sh a test key.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version=""
public_key=""
formats="msi,deb,rpm"
arches="x64,arm64"
dirs=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="$2"; shift 2 ;;
    --public-key) public_key="$2"; shift 2 ;;
    --formats) formats="$2"; shift 2 ;;
    --arches) arches="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    -*) echo "unknown argument: $1" >&2; exit 2 ;;
    *) dirs+=("$1"); shift ;;
  esac
done

if [[ ! "$version" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,5}$ ]]; then
  echo "--version must be MAJOR.MINOR.BUILD, got '$version'" >&2
  exit 2
fi
[[ -n "$public_key" && -f "$public_key" ]] || { echo "--public-key must name a PEM public key file" >&2; exit 2; }
grep -q "BEGIN PUBLIC KEY" "$public_key" || { echo "$public_key is not a PEM public key" >&2; exit 2; }
[[ ${#dirs[@]} -gt 0 ]] || { echo "name at least one directory to take packages from" >&2; exit 2; }
public_key="$(cd "$(dirname "$public_key")" && pwd)/$(basename "$public_key")"
for i in "${!dirs[@]}"; do
  [[ -d "${dirs[$i]}" ]] || { echo "${dirs[$i]} is not a directory" >&2; exit 2; }
  dirs[i]="$(cd "${dirs[$i]}" && pwd)"
done

IFS=, read -ra format_list <<< "$formats"
IFS=, read -ra arch_list <<< "$arches"
for format in "${format_list[@]}"; do
  case "$format" in msi|deb|rpm|pkg) ;; *) echo "unknown package format: $format" >&2; exit 2 ;; esac
done
for arch in "${arch_list[@]}"; do
  case "$arch" in x64|arm64) ;; *) echo "unknown architecture: $arch" >&2; exit 2 ;; esac
done

cd "$repo_root"
stage="deployment/server/agent-packages"
clear_stage() { find "$stage" -maxdepth 1 -type f -name 'EasyPatchAgent-*' -delete; }
clear_stage
# Nothing stays staged unless every package is there and verifies, so a later image build cannot take it.
on_exit() {
  local status=$?
  if [[ $status -ne 0 ]]; then clear_stage; fi
  exit "$status"
}
trap on_exit EXIT

staged=()
for format in "${format_list[@]}"; do
  for arch in "${arch_list[@]}"; do
    name="EasyPatchAgent-$version-$arch.$format"
    found=""
    for dir in "${dirs[@]}"; do
      if [[ -f "$dir/$name" ]]; then
        [[ -z "$found" ]] || { echo "$name is in both $found and $dir" >&2; exit 1; }
        found="$dir"
      fi
    done
    [[ -n "$found" ]] || { echo "no $name in ${dirs[*]}" >&2; exit 1; }
    [[ -s "$found/$name.sig" ]] || { echo "$found/$name has no release signature ($name.sig)" >&2; exit 1; }
    install -m 0644 "$found/$name" "$found/$name.sig" "$stage/"
    staged+=("$stage/$name")
  done
done

echo "==> Checking the release signatures against $public_key"
dotnet run --project tools/EasyPatch.ReleaseSigner -c Release -- verify --public-key "$public_key" "${staged[@]}"
echo "==> Staged for the server image:"
for package in "${staged[@]}"; do echo "    $package"; done
