#!/usr/bin/env bash
# The server image's tags for a release, given the releases published
# already (ADR-0052; docs/development/releasing.md):
#
#   scripts/release/release-tags.sh <version> < published
#
# published holds one final release per line (v1.2.0; blank lines ignored),
# as GitHub lists them. Prints, one per line: the version without its v
# (1.2.3); for a final release also 1.2 when no published 1.2.x ranks above
# it, and latest when no published release does. A release candidate gets
# its own tag only. So a release published out of order (1.1.5 after
# 1.2.0) moves 1.1 but not latest. Errors exit 2.
set -euo pipefail

die() {
  echo "release-tags: $*" >&2
  exit 2
}

[ $# -eq 1 ] || die "usage: release-tags.sh <version> < published"
version=$1
final_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
rc_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-rc\.[1-9][0-9]*$'
newer=$(dirname "$0")/version.sh

if [[ $version =~ $rc_re ]]; then
  echo "${version#v}"
  exit 0
fi
[[ $version =~ $final_re ]] || die "\"$version\" is not a release like v1.2.3 or v1.2.3-rc.1"
echo "${version#v}"
core=${version#v}
series=${core%.*}

minor=true latest=true
while IFS= read -r published || [ -n "$published" ]; do
  [ -n "$published" ] || continue
  [[ $published =~ $final_re ]] || die "\"$published\" is not a published release like v1.2.3"
  status=0
  "$newer" newer "$published" "$version" || status=$?
  case $status in
    0)
      latest=false
      p=${published#v}
      if [ "${p%.*}" = "$series" ]; then minor=false; fi
      ;;
    1) ;;
    *) exit 2 ;;
  esac
done
if [ "$minor" = true ]; then echo "$series"; fi
if [ "$latest" = true ]; then echo latest; fi
