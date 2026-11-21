#!/bin/sh
# Checks that the agents bundle.sh built are the server image's, byte for
# byte (ADR-0049: the server accepts an operator-signed release agent only
# if it matches its own build):
#
#   scripts/release/check-agents.sh <image> <dir holding easyrmm-agent-*>
#
# The image's agents are in /usr/share/easyrmm/agents/. Both must hold the
# same agents, by name, with the same SHA-256. Needs Docker; the image is
# pulled if it is not here.
set -eu

[ $# -eq 2 ] || { echo "usage: check-agents.sh <image> <dir>" >&2; exit 2; }
image=$1 dir=$2
work=$(mktemp -d)
container=
cleanup() {
  [ -z "$container" ] || docker rm -f "$container" > /dev/null
  rm -rf "$work"
}
trap cleanup EXIT

container=$(docker create "$image")
docker cp -q "$container:/usr/share/easyrmm/agents/." "$work/image"
sums() { (cd "$1" && find . -maxdepth 1 -type f -name 'easyrmm-agent-*' -printf '%f\n' | LC_ALL=C sort | xargs -r sha256sum); }
sums "$work/image" > "$work/image.sums"
sums "$dir" > "$work/bundle.sums"
if [ ! -s "$work/image.sums" ]; then
  echo "check-agents: $image has no agents in /usr/share/easyrmm/agents" >&2
  exit 1
fi
if ! cmp -s "$work/image.sums" "$work/bundle.sums"; then
  echo "check-agents: the agents in $dir are not $image's (< image, > $dir):" >&2
  diff "$work/image.sums" "$work/bundle.sums" >&2 || true
  exit 1
fi
echo "check-agents: the $(wc -l < "$work/image.sums") agents in $dir are $image's"
