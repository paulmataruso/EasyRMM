#!/bin/sh
# Tests for version.sh, in a repository made for the run:
#
#   scripts/release/version_test.sh
#
# History (main, oldest first), with the tags on each commit:
#
#   c0                                    no release reachable
#   c1  easyrmm-v1.0.0-rc.1
#   c2  easyrmm-v1.0.0-rc.2 (annotated), easypatch-v1.10.0, easyrmm-v1.0.0-beta.1,
#       easyrmm-v01.0.0, easyrmm-v1.0.0-rc.0, easyrmm-v1.0.0-rc.02, v9.0.0   (only rc.2 is a release)
#   c3  easyrmm-v1.0.0-rc.9, easyrmm-v1.0.0-rc.10, easyrmm-v1.0.0-rc.012 (not a release; it would rank above)
#   c4  easyrmm-v1.0.0-rc.11, easyrmm-v1.0.0
#   c5                                    after a release
#   c6  easyrmm-v1.9.0, easyrmm-v1.10.0
#
# and a branch from c3 with easyrmm-v9.9.9, never merged.
set -eu

script=$(cd "$(dirname "$0")" && pwd)/version.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

# expect <want> <args...>: version.sh prints want and succeeds.
expect() {
  want=$1
  shift
  if ! got=$("$script" "$@" 2> "$work/err"); then
    fail "version.sh $* failed: $(cat "$work/err")"
  elif [ "$got" != "$want" ]; then
    fail "version.sh $*: got \"$got\", want \"$want\""
  fi
}

# refuse <status> <message part> <args...>: version.sh fails with status, saying message.
refuse() {
  want=$1 message=$2
  shift 2
  status=0
  "$script" "$@" > "$work/out" 2> "$work/err" || status=$?
  if [ "$status" -ne "$want" ]; then
    fail "version.sh $*: exit $status, want $want (stdout: $(cat "$work/out"))"
  elif [ -n "$message" ] && ! grep -qF -- "$message" "$work/err"; then
    fail "version.sh $*: error \"$(cat "$work/err")\" does not say \"$message\""
  fi
}

# --- The repository -------------------------------------------------------------
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
cd "$work"
git init -q -b main repo
cd repo
commit() {
  git commit -q --allow-empty -m "$1"
  git rev-parse HEAD
}
c0=$(commit c0)
c1=$(commit c1)
git tag easyrmm-v1.0.0-rc.1
c2=$(commit c2)
git tag -a -m "EasyRMM 1.0.0-rc.2" easyrmm-v1.0.0-rc.2
for t in easypatch-v1.10.0 easyrmm-v1.0.0-beta.1 easyrmm-v01.0.0 easyrmm-v1.0.0-rc.0 easyrmm-v1.0.0-rc.02 v9.0.0; do
  git tag "$t"
done
c3=$(commit c3)
git tag easyrmm-v1.0.0-rc.9
git tag easyrmm-v1.0.0-rc.10
git tag easyrmm-v1.0.0-rc.012
git checkout -q -b side
commit side > /dev/null
git tag easyrmm-v9.9.9
git checkout -q main
c4=$(commit c4)
git tag easyrmm-v1.0.0-rc.11
git tag easyrmm-v1.0.0
c5=$(commit c5)
c6=$(commit c6)
git tag easyrmm-v1.9.0
git tag easyrmm-v1.10.0

# --- release ----------------------------------------------------------------------
refuse 2 "no release tag" release "$c0"
expect easyrmm-v1.0.0-rc.1 release "$c1"
expect easyrmm-v1.0.0-rc.2 release "$c2"           # annotated; other forms ignored
expect easyrmm-v1.0.0-rc.10 release "$c3"          # rc.10 above rc.9, on one commit; rc.012 ignored
expect easyrmm-v1.0.0 release "$c4"                # the release above its rc.11, on one commit
expect easyrmm-v1.0.0 release "$c5"
expect easyrmm-v1.10.0 release "$c6"               # 1.10 above 1.9
expect easyrmm-v1.10.0 release                     # HEAD
expect easyrmm-v9.9.9 release side                 # reachable from the branch only
refuse 2 "not a commit" release no-such-commit

# --- edge -------------------------------------------------------------------------
refuse 2 "no release tag" edge 7 1 "$c0"
expect v1.0.0-rc.1.edge.7.1 edge 7 1 "$c1"
expect v1.0.0-rc.10.edge.412.1 edge 412 1 "$c3"
expect v1.0.0-rc.10.edge.412.2 edge 412 2 "$c3"    # a re-run: the attempt goes up
expect v1.0.1-edge.415.1 edge 415 1 "$c4"          # several tags on one commit, the release wins
expect v1.0.1-edge.416.3 edge 416 3 "$c5"
expect v1.10.1-edge.9.1 edge 9 1
for bad in "0 1" "1 0" "01 1" "1 x" "-1 1" "1 1.5"; do
  # shellcheck disable=SC2086 # two words, run and attempt
  refuse 2 "run and attempt" edge $bad "$c5"
done
nl='
'
refuse 2 "run and attempt" edge "1${nl}x" 1 "$c5"
refuse 2 "usage" edge 1
refuse 2 "usage" bogus

# --- newer --------------------------------------------------------------------------
# newer <a> <b>: a ranks above b; older <a> <b>: it does not.
newer() { "$script" newer "$1" "$2" 2> "$work/err" || fail "$1 should rank above $2 $(cat "$work/err")"; }
older() {
  status=0
  "$script" newer "$1" "$2" 2> "$work/err" || status=$?
  [ "$status" -eq 1 ] || fail "$1 should not rank above $2 (exit $status) $(cat "$work/err")"
}
pair() { newer "$2" "$1" && older "$1" "$2"; } # pair <lower> <higher>

# The ADR's examples.
pair v1.0.0-rc.4 v1.0.0-rc.4.edge.412.1
pair v1.0.0-rc.4.edge.412.1 v1.0.0-rc.5
pair v1.0.0 v1.0.1-edge.415.1
pair v1.0.1-edge.415.1 v1.0.1-rc.1
pair v1.0.1-edge.415.1 v1.0.1
# Why not the plan's form: semantic versioning ranks 1.0.0-rc.5-edge.412 above 1.0.0-rc.5.
pair v1.0.0-rc.5 v1.0.0-rc.5-edge.412
# Runs and attempts, by number.
pair v1.0.0-rc.4.edge.412.1 v1.0.0-rc.4.edge.412.2
pair v1.0.0-rc.4.edge.412.9 v1.0.0-rc.4.edge.412.10
pair v1.0.0-rc.4.edge.999.1 v1.0.0-rc.4.edge.1000.1
pair v1.0.1-edge.99999999999999999998.1 v1.0.1-edge.99999999999999999999.1
# Edge builds after an rc and after the release that follows it.
pair v1.0.0-rc.4.edge.500.1 v1.0.1-edge.415.1
# The rest of the order.
pair v1.0.0-rc.9 v1.0.0-rc.10
pair v1.9.0 v1.10.0
pair v1.2.3 v2.0.0
pair v0.9.9 v1.0.0-rc.1
pair v1.0.0-alpha v1.0.0-alpha.1
pair v1.0.0-alpha.1 v1.0.0-alpha.beta
pair v1.0.0-1 v1.0.0-a
older v1.0.0 v1.0.0
older v1.0.1-edge.415.1 v1.0.1-edge.415.1
for bad in 1.0.0 v1.0 v1.0.0- v1.0.0+build v1.0.0-rc..1 "v1.0.0 x" ""; do
  refuse 2 "is not a version" newer "$bad" v1.0.0
  refuse 2 "is not a version" newer v1.0.0 "$bad"
done
# A line break: each line alone would be a version.
refuse 2 "is not a version" newer "v9.0.0${nl}x" v1.0.0
refuse 2 "is not a version" newer v1.0.0 "v9.0.0${nl}x"
refuse 2 "is not a version" newer "x${nl}v9.0.0" v1.0.0
refuse 2 "usage" newer v1.0.0

if [ "$failures" -ne 0 ]; then
  echo "version.sh: $failures failure(s)" >&2
  exit 1
fi
echo "version.sh: all tests passed"
