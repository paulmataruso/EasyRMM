#!/bin/sh
# Tests for edge-retention.sh, with gh and docker stubbed by fixtures:
#
#   scripts/release/edge-retention_test.sh
#
# easyrmm-deploy                         easyrmm-server
#   d1 old edge version       deleted      s1 old edge version + sha-  deleted, with A1..A3
#   d2 old, edge              kept            (A4 is named but gone already)
#   d3 new edge version       kept         ra s1's attestations, new  deleted, with RA1
#   d4 old, untagged          kept         s2 old, edge               kept, with B1
#   d5 old release            kept         s3 old release              kept; names X
#   d6 old edge after a       deleted      s4 old edge version         deleted, with Y; X kept
#      release                             s5 new edge version         kept
#                                          s6 old attestations of F    deleted, with RF1 (F gone)
#                                          s7 new attestations of G    kept (G gone, but new)
#                                          s8 attestations of s3       kept
#                                          s9 old, untagged            kept
#                                          s10 old edge version        deleted, with H1; Y once
#                                          s11 old, short sha- tag     kept
set -eu

script=$(cd "$(dirname "$0")" && pwd)/edge-retention.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

old=$(date -u -d '40 days ago' +%Y-%m-%dT%H:%M:%SZ)
new=$(date -u -d '5 days ago' +%Y-%m-%dT%H:%M:%SZ)
d() { printf 'sha256:%s' "$(printf %s "$1" | sha256sum | cut -c1-64)"; }
hex() { d "$1" | cut -c8-; }
commit=0123456789abcdef0123456789abcdef01234567

# --- Stubs --------------------------------------------------------------------------
mkdir -p "$work/bin" "$work/fixtures/raw"
cat > "$work/bin/gh" <<'EOF'
#!/bin/sh
f=$FIXTURES
case "$1 $2 $3" in
  "api --paginate /users/o/packages/container/"*)
    [ -z "${GH_FAIL:-}" ] || { echo "gh: Server Error (HTTP 500)" >&2; exit 1; }
    pkg=${3#/users/o/packages/container/}
    pkg=${pkg%%/*}
    if [ -f "$f/$pkg.json" ]; then cat "$f/$pkg.json"; else echo "gh: Package not found. (HTTP 404)" >&2; exit 1; fi ;;
  "api -X DELETE") echo "$4" >> "$f/deleted.log" ;;
  *) echo "gh stub: unexpected $*" >&2; exit 3 ;;
esac
EOF
cat > "$work/bin/docker" <<'EOF'
#!/bin/sh
f=$FIXTURES
[ "$1 $2 $3 $4" = "buildx imagetools inspect --raw" ] || { echo "docker stub: unexpected $*" >&2; exit 3; }
hex=${5#ghcr.io/o/easyrmm-server@sha256:}
[ ! -e "$f/fail-$hex" ] || { echo "ERROR: unexpected status: 502 Bad Gateway" >&2; exit 1; }
if [ -f "$f/raw/$hex.json" ]; then cat "$f/raw/$hex.json"; else echo '{"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}'; fi
EOF
chmod +x "$work/bin/gh" "$work/bin/docker"

# v <id> <name> <created> [tag...]: one package version.
v() {
  id=$1 name=$2 created=$3
  shift 3
  jq -c -n --argjson id "$id" --arg name "$name" --arg created "$created" --args \
    '{id: $id, name: $name, created_at: $created, metadata: {container: {tags: $ARGS.positional}}}' "$@"
}
# index <parent> <child...>: the parent names the children.
index() {
  parent=$1
  shift
  for c in "$@"; do d "$c"; echo; done | jq -R . | jq -s '{mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [.[] | {mediaType: "application/vnd.oci.image.manifest.v1+json", digest: .}]}' \
    > "$work/fixtures/raw/$(hex "$parent").json"
}

{
  v 1 "$(d d1)" "$old" v1.0.0-rc.4.edge.100.1
  v 2 "$(d d2)" "$old" v1.0.0-rc.4.edge.101.1 edge
  v 3 "$(d d3)" "$new" v1.0.0-rc.4.edge.140.1
  v 4 "$(d d4)" "$old"
  v 5 "$(d d5)" "$old" v1.0.0-rc.4
  v 6 "$(d d6)" "$old" v1.0.1-edge.5.2
} | jq -s . > "$work/fixtures/easyrmm-deploy.json"

# Two pages, as gh api --paginate prints them.
{
  {
    v 101 "$(d s1)" "$old" 1.0.0-rc.4.edge.100.1 "sha-$commit"
    v 102 "$(d A1)" "$old"
    v 103 "$(d A2)" "$old"
    v 104 "$(d A3)" "$old"
    v 105 "$(d ra)" "$new" "sha256-$(hex s1)"
    v 106 "$(d RA1)" "$new"
    v 107 "$(d s2)" "$old" 1.0.0-rc.4.edge.101.1 "sha-$commit" edge
    v 108 "$(d B1)" "$old"
    v 109 "$(d s3)" "$old" 1.0.0-rc.4
    v 110 "$(d X)" "$old"
    v 111 "$(d s4)" "$old" 1.0.0-rc.4.edge.99.1
  } | jq -s .
  {
    v 112 "$(d Y)" "$old"
    v 113 "$(d s5)" "$new" 1.0.1-edge.200.1
    v 114 "$(d s6)" "$old" "sha256-$(hex F)"
    v 115 "$(d RF1)" "$old"
    v 116 "$(d s7)" "$new" "sha256-$(hex G)"
    v 117 "$(d s8)" "$old" "sha256-$(hex s3)"
    v 118 "$(d s9)" "$old"
    v 119 "$(d s10)" "$old" 1.0.0-rc.4.edge.98.1
    v 120 "$(d H1)" "$old"
    v 121 "$(d s11)" "$old" sha-0123456
  } | jq -s .
} > "$work/fixtures/easyrmm-server.json"

index s1 A1 A2 A3 A4
index ra RA1
index s2 B1
index s3 X
index s4 X Y
index s6 RF1
index s10 Y H1

# run <expected status> [args...]: runs the script on the fixtures, logging deletions.
run() {
  want=$1
  shift
  rm -f "$work/fixtures/deleted.log"
  status=0
  FIXTURES=$work/fixtures PATH=$work/bin:$PATH "$script" "$@" > "$work/out" 2> "$work/err" || status=$?
  if [ "$status" -ne "$want" ]; then
    fail "edge-retention.sh $*: exit $status, want $want: $(cat "$work/err")"
  fi
}
deleted() { if [ -f "$work/fixtures/deleted.log" ]; then sed 's:.*/versions/::' "$work/fixtures/deleted.log" | tr '\n' ' '; fi; }

# --- Deletes, children before what names them, each once ---------------------------
run 0 o
want="1 6 106 105 115 114 102 103 104 101 112 111 120 119 "
[ "$(deleted)" = "$want" ] || fail "deleted: got \"$(deleted)\", want \"$want\""
grep -qF "Keeping easyrmm-server@$(d X): a kept image names it" "$work/out" || fail "X not reported kept: $(cat "$work/out")"
grep -qF "Deleted easyrmm-deploy@$(d d1) (v1.0.0-rc.4.edge.100.1, $old)" "$work/out" || fail "d1 not reported: $(cat "$work/out")"
grep -qF "Deleted easyrmm-server@$(d A1) (untagged, $old)" "$work/out" || fail "A1 not reported: $(cat "$work/out")"

# --- Dry run --------------------------------------------------------------------------
run 0 o --dry-run
[ -z "$(deleted)" ] || fail "--dry-run deleted $(deleted)"
[ "$(grep -c '^Would delete ' "$work/out")" -eq 14 ] || fail "--dry-run: $(cat "$work/out")"

# --- Failures stop it -------------------------------------------------------------------
touch "$work/fixtures/fail-$(hex s10)"
run 1 o
case " $(deleted)" in *" 119 "* | *" 120 "*) fail "deleted s10 or H1 without reading s10: $(deleted)" ;; esac
rm "$work/fixtures/fail-$(hex s10)"
touch "$work/fixtures/fail-$(hex s3)"
run 1 o
[ -z "$(deleted | sed 's/^1 6 //')" ] || fail "deleted server versions without knowing what s3 names: $(deleted)"
rm "$work/fixtures/fail-$(hex s3)"
export GH_FAIL=1
run 1 o
unset GH_FAIL
[ -z "$(deleted)" ] || fail "deleted $(deleted) after gh failed"

# --- No packages yet, and arguments -----------------------------------------------------
mv "$work/fixtures/easyrmm-deploy.json" "$work/fixtures/easyrmm-server.json" "$work"
run 0 o
[ -z "$(deleted)" ] || fail "deleted $(deleted) with no packages"
run 2
run 2 o --force
run 2 o --dry-run extra

if [ "$failures" -ne 0 ]; then
  echo "edge-retention.sh: $failures failure(s)" >&2
  exit 1
fi
echo "edge-retention.sh: all tests passed"
