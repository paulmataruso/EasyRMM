#!/usr/bin/env bash
# Checks that a downloaded artifact's directory holds exactly the files
# named, and that each one given a SHA-256 has it (ADR-0052):
#
#   scripts/ci/check-download.sh <dir> <file>[=<sha256>]...
#
# A job that may write packages or mint an identity downloads artifacts
# other jobs made, outside its workspace, by the IDs they recorded; this
# refuses anything else in the directory (another file, a directory, a
# link) and any file whose content is not the one recorded.
set -euo pipefail

die() {
  echo "check-download: $*" >&2
  exit 1
}

[ $# -ge 2 ] || { echo "usage: check-download.sh <dir> <file>[=<sha256>]..." >&2; exit 2; }
dir=$1
shift
[ -d "$dir" ] || die "$dir is not a directory"

want=()
for spec in "$@"; do
  name=${spec%%=*}
  [[ $name =~ ^[A-Za-z0-9._-]+$ ]] || { echo "check-download: \"$name\" is not a file name" >&2; exit 2; }
  want+=("$name")
done
got=$(cd "$dir" && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort)
expected=$(printf '%s\n' "${want[@]}" | LC_ALL=C sort)
[ "$got" = "$expected" ] || die "$dir holds \"$(tr '\n' ' ' <<< "$got")\", not \"$(tr '\n' ' ' <<< "$expected")\""

for spec in "$@"; do
  name=${spec%%=*}
  [ -f "$dir/$name" ] && [ ! -L "$dir/$name" ] || die "$dir/$name is not a regular file"
  [ "$spec" != "$name" ] || continue
  sha=${spec#*=}
  [[ $sha =~ ^[0-9a-f]{64}$ ]] || die "the SHA-256 recorded for $name is \"$sha\", not one"
  got=$(sha256sum < "$dir/$name" | cut -c1-64)
  [ "$got" = "$sha" ] || die "$dir/$name has the SHA-256 $got, not the recorded $sha"
done
echo "check-download: $dir holds $* as recorded"
