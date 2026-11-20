#!/usr/bin/env bash
# Checks that a server image carries exactly the agent packages staged in deployment/server/agent-packages/, byte for
# byte, owned by root and not writable by the server's user, and that at least one was staged.
#
#   scripts/check-image-agent-packages.sh <image>
set -euo pipefail

image="${1:?usage: scripts/check-image-agent-packages.sh <image>}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stage="$repo_root/deployment/server/agent-packages"

# Run by sh here and in the image, with the directory as $1.
# shellcheck disable=SC2016
list='cd "$1" && find . -maxdepth 1 -type f -name "EasyPatchAgent-*" | sort | while read -r f; do sha256sum "$f"; done'
want="$(sh -c "$list" sh "$stage")"
[[ -n "$want" ]] || { echo "no agent packages are staged in $stage" >&2; exit 1; }
got="$(docker run --rm --network none --entrypoint sh "$image" -c "$list" sh /app/agent-packages)"
if [[ "$got" != "$want" ]]; then
  echo "$image does not carry the staged agent packages" >&2
  diff <(echo "$want") <(echo "$got") >&2 || true
  exit 1
fi
owners="$(docker run --rm --network none --entrypoint sh "$image" -c \
  'find /app/agent-packages -mindepth 1 \( ! -user root -o -perm -0002 -o -perm -0020 \) -print')"
[[ -z "$owners" ]] || { echo "the server could change these packages: $owners" >&2; exit 1; }
if docker run --rm --network none --entrypoint sh "$image" -c 'touch /app/agent-packages/x' 2> /dev/null; then
  echo "the server's user can write to /app/agent-packages" >&2
  exit 1
fi
echo "$image carries $(echo "$want" | wc -l) agent package files:"
while read -r line; do echo "    $line"; done <<< "$want"
