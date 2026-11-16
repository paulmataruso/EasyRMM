#!/bin/sh
# Prints the CHANGELOG.md section for a release, without its heading.
#
#   scripts/release/notes.sh v1.2.3
#
# Fails when the changelog has no "## [1.2.3]" section, or it is empty, so a
# release cannot go out without notes.
set -eu

version=${1:?usage: notes.sh vX.Y.Z}
version=${version#v}
root=$(cd "$(dirname "$0")/../.." && pwd)

notes=$(awk -v heading="## [$version]" '
  index($0, heading) == 1 { on = 1; next }
  on && /^## \[/ { exit }
  on { print }
' "$root/CHANGELOG.md")

# Trim leading and trailing blank lines.
notes=$(printf '%s\n' "$notes" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')
if [ -z "$notes" ]; then
  echo "notes: CHANGELOG.md has no section for $version (expected a heading \"## [$version] - YYYY-MM-DD\")" >&2
  exit 1
fi
printf '%s\n' "$notes"
