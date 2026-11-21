#!/bin/sh
# Tests for release-tags.sh:
#
#   scripts/release/release-tags_test.sh
set -eu

script=$(cd "$(dirname "$0")" && pwd)/release-tags.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# expect "<tags>" <version> [published...]: the tags, space-separated.
expect() {
  want=$1 version=$2
  shift 2
  status=0
  printf '%s\n' "$@" | "$script" "$version" > "$work/out" 2> "$work/err" || status=$?
  got=$(tr '\n' ' ' < "$work/out" | sed 's/ $//')
  if [ "$status" -ne 0 ] || [ "$got" != "$want" ]; then
    fail "$version after [$*]: got \"$got\" (exit $status: $(cat "$work/err")), want \"$want\""
  fi
}
# refuse <message part> <version> [published...]: exits 2, saying so.
refuse() {
  part=$1 version=$2
  shift 2
  status=0
  printf '%s\n' "$@" | "$script" "$version" > /dev/null 2> "$work/err" || status=$?
  if [ "$status" -ne 2 ] || ! grep -qF -- "$part" "$work/err"; then
    fail "$version after [$*]: exit $status, \"$(cat "$work/err")\"; want 2 and \"$part\""
  fi
}

# The first release, and one above every other.
expect "1.0.0 1.0 latest" v1.0.0
expect "1.2.1 1.2 latest" v1.2.1 v1.2.0 v1.1.5 v1.0.0
expect "1.10.0 1.10 latest" v1.10.0 v1.9.0 v1.2.0
# Out of order: 1.1.5 after 1.2.0 moves 1.1, not latest; after 1.1.6 too, neither.
expect "1.1.5 1.1" v1.1.5 v1.2.0 v1.1.4
expect "1.1.5" v1.1.5 v1.2.0 v1.1.6
expect "1.9.1 1.9" v1.9.1 v1.10.0
expect "0.9.9 0.9" v0.9.9 v1.0.0
# Its own release, published already (a run again), does not rank above it.
expect "1.2.3 1.2 latest" v1.2.3 v1.2.3 v1.2.2
# A release candidate: its own tag only, whatever is published.
expect "1.3.0-rc.1" v1.3.0-rc.1
expect "1.3.0-rc.1" v1.3.0-rc.1 v1.2.0
# Blank lines are ignored; no list at all is no release.
expect "1.2.0 1.2 latest" v1.2.0 "" v1.1.0 ""
printf '' | "$script" v2.0.0 > "$work/out" || fail "v2.0.0 with nothing on stdin failed"
[ "$(tr '\n' ' ' < "$work/out")" = "2.0.0 2.0 latest " ] || fail "v2.0.0 with nothing published: $(cat "$work/out")"
# The last line without its line break counts too.
printf 'v1.0.0\nv2.1.0' | "$script" v2.0.5 > "$work/out" || fail "v2.0.5 after an unterminated line failed"
[ "$(tr '\n' ' ' < "$work/out")" = "2.0.5 2.0 " ] || fail "v2.0.5 after v2.1.0, unterminated: $(cat "$work/out")"

nl='
'
for bad in 1.2.3 v1.2 v1.2.3-beta.1 v01.2.3 v1.2.3-rc.0 v1.2.3-rc.01 "v1.2.3${nl}x" ""; do
  refuse "is not a release" "$bad"
done
for bad in v1.2.3-rc.1 v1.2 1.2.0 "v9.0.0 x"; do
  refuse "is not a published release" v1.2.3 "$bad"
done
status=0
"$script" > /dev/null 2>&1 < /dev/null || status=$?
[ "$status" -eq 2 ] || fail "no arguments: exit $status, want 2"
# version.sh failing is an error, not a lower version.
mkdir "$work/broken"
cp "$script" "$work/broken/release-tags.sh"
printf '#!/bin/sh\nexit 3\n' > "$work/broken/version.sh"
chmod +x "$work/broken/version.sh"
status=0
echo v1.0.0 | "$work/broken/release-tags.sh" v1.2.3 > /dev/null 2>&1 || status=$?
[ "$status" -eq 2 ] || fail "version.sh failing: exit $status, want 2"

if [ "$failures" -ne 0 ]; then
  echo "release-tags.sh: $failures failure(s)" >&2
  exit 1
fi
echo "release-tags.sh: all tests passed"
