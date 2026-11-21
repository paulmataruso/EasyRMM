#!/bin/sh
# Tests for edge-retention.sh, with gh and oras stubbed by fixtures:
#
#   scripts/release/edge-retention_test.sh
#
# easyrmm-deploy (each names a server image)
#   d1 old edge version, names s1       deleted
#   d2 old, edge, names s12             kept
#   d3 new edge version, names s14      kept; among its images also s16, and s10
#                                      in another repository
#   d4 old, untagged, names s15         kept
#   d5 old release, names s3            kept
#   d6 old edge version, names s4       deleted
#
# easyrmm-server
#   s1  old edge version + sha-        deleted, with A1..A3 (A4 is named but gone already)
#   ra  s1's attestations, new         deleted, with RA1
#   s2  old, edge                      kept, with B1
#   s3  old release                    kept; names X
#   s4  old edge version               deleted, with Y; X and C15 kept
#   s5  new edge version               kept
#   s6  old attestations of F          deleted, with RF1 (F gone)
#   s7  new attestations of G          deleted, with RG1 (G gone)
#   s8  attestations of s3             kept
#   s9  old, untagged                  kept
#   s10 old edge version               deleted, with H1; Y once; K kept (tagged)
#   s11 old, short sha- tag            kept
#   s12 old edge version + sha-        kept: easyrmm-deploy:edge names it, though
#                                      easyrmm-server:edge is s2; with C12, and
#   s13 s12's attestations, old        kept, with RC13
#   s14 old edge version               kept: d3, kept, names it; with C14
#   s15 old, untagged                  kept: d4 names it; so is C15, which s4 names too
#   s16 old edge version               kept: among d3's images; with C16
#   K   old, tagged, named by s10      kept
#
# Then: a 404 for easyrmm-deploy stops it while easyrmm-server has an edge
# version, and not with only a release.
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
f=$work/fixtures

# --- Stubs --------------------------------------------------------------------------
mkdir -p "$work/bin" "$f/raw" "$f/blob"
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
cat > "$work/bin/oras" <<'EOF'
#!/bin/sh
f=$FIXTURES
case "$1 $2" in
  "manifest fetch") ref=$3 dir=raw ;;
  "blob fetch") [ "$3 $4" = "--output -" ] || { echo "oras stub: unexpected $*" >&2; exit 3; }; ref=$5 dir=blob ;;
  *) echo "oras stub: unexpected $*" >&2; exit 3 ;;
esac
case $ref in
  ghcr.io/o/easyrmm-server@sha256:* | ghcr.io/o/easyrmm-deploy@sha256:*) hex=${ref##*@sha256:} ;;
  *) echo "oras stub: unexpected reference $ref" >&2; exit 3 ;;
esac
[ ! -e "$f/fail-$hex" ] || { echo "Error: failed to fetch: 502 Bad Gateway" >&2; exit 1; }
if [ -f "$f/$dir/$hex.json" ]; then cat "$f/$dir/$hex.json"
elif [ "$dir" = raw ]; then echo '{"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}'
else echo "Error: $ref: not found" >&2; exit 1
fi
EOF
chmod +x "$work/bin/gh" "$work/bin/oras"

# v <id> <name> <created> [tag...]: one package version.
v() {
  id=$1 name=$2 created=$3
  shift 3
  jq -c -n --argjson id "$id" --arg name "$name" --arg created "$created" --args \
    '{id: $id, name: $name, created_at: $created, metadata: {container: {tags: $ARGS.positional}}}' "$@"
}
# index <parent> <child...>: the server image parent names the children.
index() {
  parent=$1
  shift
  for c in "$@"; do d "$c"; echo; done | jq -R . | jq -s '{mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [.[] | {mediaType: "application/vnd.oci.image.manifest.v1+json", digest: .}]}' \
    > "$f/raw/$(hex "$parent").json"
}
# names <deploy version> <server image> [image...]: the deploy version's
# manifest names the server image, as easyrmm.image and among its images,
# with PostgreSQL's and any others given.
names() {
  deploy=$1 image="ghcr.io/o/easyrmm-server:x@$(d "$2")"
  shift 2
  jq -n --arg b "$(d "bundle-$deploy")" --arg m "$(d "manifest-$deploy")" --arg s "$(d "sigstore-$deploy")" '{
    artifactType: "application/vnd.easyrmm.deploy.v1",
    layers: [{mediaType: "application/vnd.easyrmm.deploy.bundle.v1.tar+gzip", digest: $b},
      {mediaType: "application/vnd.easyrmm.deploy.manifest.v1+json", digest: $m},
      {mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json", digest: $s}]}' > "$f/raw/$(hex "$deploy").json"
  jq -n --arg image "$image" --arg postgres "docker.io/library/postgres:17@$(d postgres)" --args \
    '{schemaVersion: 2, easyrmm: {image: $image}, images: ([$image, $postgres] + $ARGS.positional)}' "$@" \
    > "$f/blob/$(hex "manifest-$deploy").json"
}

{
  v 1 "$(d d1)" "$old" v1.0.0-rc.4.edge.100.1
  v 2 "$(d d2)" "$old" v1.0.0-rc.4.edge.103.1 edge
  v 3 "$(d d3)" "$new" v1.0.0-rc.4.edge.140.1
  v 4 "$(d d4)" "$old"
  v 5 "$(d d5)" "$old" v1.0.0-rc.4
  v 6 "$(d d6)" "$old" v1.0.1-edge.5.2
} | jq -s . > "$f/easyrmm-deploy.json"
names d1 s1
names d2 s12
names d3 s14 "ghcr.io/o/easyrmm-server@$(d s16)" "ghcr.io/o/easypatch-server:1@$(d s10)"
names d4 s15
names d5 s3
names d6 s4

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
    v 112 "$(d Y)" "$old"
    v 113 "$(d s5)" "$new" 1.0.1-edge.200.1
    v 114 "$(d s6)" "$old" "sha256-$(hex F)"
    v 115 "$(d RF1)" "$old"
  } | jq -s .
  {
    v 116 "$(d s7)" "$new" "sha256-$(hex G)"
    v 117 "$(d s8)" "$old" "sha256-$(hex s3)"
    v 118 "$(d s9)" "$old"
    v 119 "$(d s10)" "$old" 1.0.0-rc.4.edge.98.1
    v 120 "$(d H1)" "$old"
    v 121 "$(d s11)" "$old" sha-0123456
    v 122 "$(d RG1)" "$new"
    v 123 "$(d s12)" "$old" 1.0.0-rc.4.edge.103.1 "sha-$commit"
    v 124 "$(d C12)" "$old"
    v 125 "$(d s13)" "$old" "sha256-$(hex s12)"
    v 126 "$(d RC13)" "$old"
    v 127 "$(d s14)" "$old" 1.0.0-rc.4.edge.140.1
    v 128 "$(d C14)" "$old"
    v 129 "$(d K)" "$old" keepme
    v 130 "$(d s15)" "$old"
    v 131 "$(d C15)" "$old"
    v 132 "$(d s16)" "$old" 1.0.0-rc.4.edge.141.1
    v 133 "$(d C16)" "$old"
  } | jq -s .
} > "$f/easyrmm-server.json"

index s1 A1 A2 A3 A4
index ra RA1
index s2 B1
index s3 X
index s4 X Y C15
index s6 RF1
index s7 RG1
index s10 Y H1 K
index s12 C12
index s13 RC13
index s14 C14
index s15 C15
index s16 C16

# run <expected status> [args...]: runs the script on the fixtures, logging deletions.
run() {
  want=$1
  shift
  rm -f "$f/deleted.log"
  status=0
  FIXTURES=$f PATH=$work/bin:$PATH "$script" "$@" > "$work/out" 2> "$work/err" || status=$?
  if [ "$status" -ne "$want" ]; then
    fail "edge-retention.sh $*: exit $status, want $want: $(cat "$work/err")"
  fi
}
deleted() { if [ -f "$f/deleted.log" ]; then sed 's:.*/versions/::' "$f/deleted.log" | tr '\n' ' '; fi; }

# --- Deletes, children before what names them, each once ---------------------------
run 0 o
want="1 6 106 105 115 114 122 116 102 103 104 101 112 111 120 119 "
[ "$(deleted)" = "$want" ] || fail "deleted: got \"$(deleted)\", want \"$want\""
for kept in X C15; do
  grep -qF "Keeping easyrmm-server@$(d $kept): a kept image names it" "$work/out" || fail "$kept not reported kept: $(cat "$work/out")"
done
for kept in s12 s14 s15 s16; do
  grep -qF "Keeping easyrmm-server@$(d $kept): a kept easyrmm-deploy version names it" "$work/out" ||
    fail "$kept not reported kept: $(cat "$work/out")"
done
grep -qF "Deleted easyrmm-deploy@$(d d1) (v1.0.0-rc.4.edge.100.1, $old)" "$work/out" || fail "d1 not reported: $(cat "$work/out")"
grep -qF "Deleted easyrmm-server@$(d A1) (untagged, $old)" "$work/out" || fail "A1 not reported: $(cat "$work/out")"
grep -qx "Deleted 16 version(s)." "$work/out" || fail "no count: $(cat "$work/out")"
grep '^Deleted easyrmm-' "$work/out" > "$work/deleted.lines"

# --- Dry run: exactly what the run deleted -----------------------------------------------
run 0 o --dry-run
[ -z "$(deleted)" ] || fail "--dry-run deleted $(deleted)"
grep '^Would delete easyrmm-' "$work/out" | sed 's/^Would delete /Deleted /' > "$work/would.lines"
cmp -s "$work/deleted.lines" "$work/would.lines" ||
  fail "--dry-run listed another set than the run deleted: $(diff "$work/deleted.lines" "$work/would.lines")"
grep -qx "Would delete 16 version(s); deleted none (dry run)." "$work/out" || fail "--dry-run: no count: $(cat "$work/out")"

# --- Failures stop it, before anything that depends on what failed ----------------------
touch "$f/fail-$(hex s10)"
run 1 o
case " $(deleted)" in *" 119 "* | *" 120 "*) fail "deleted s10 or H1 without reading s10: $(deleted)" ;; esac
rm "$f/fail-$(hex s10)"
for what in s3 d2 manifest-d3; do
  touch "$f/fail-$(hex $what)"
  run 1 o
  [ -z "$(deleted)" ] || fail "deleted $(deleted) without reading $what"
  rm "$f/fail-$(hex $what)"
done
cp "$f/blob/$(hex manifest-d2).json" "$work/manifest-d2.json"
jq '.easyrmm.image = "ghcr.io/o/easyrmm-server:edge"' "$work/manifest-d2.json" > "$f/blob/$(hex manifest-d2).json"
run 1 o
[ -z "$(deleted)" ] || fail "deleted $(deleted) when a kept deploy version names its image by tag only"
grep -qF 'not one by digest' "$work/err" || fail "no reason given: $(cat "$work/err")"
cp "$work/manifest-d2.json" "$f/blob/$(hex manifest-d2).json"
cp "$f/blob/$(hex manifest-d3).json" "$work/manifest-d3.json"
jq '.images += ["ghcr.io/o/easyrmm-server:1.0.0-rc.4.edge.141.1"]' "$work/manifest-d3.json" > "$f/blob/$(hex manifest-d3).json"
run 1 o
[ -z "$(deleted)" ] || fail "deleted $(deleted) when a kept deploy version names a server image by tag only"
grep -qF 'not one by digest' "$work/err" || fail "no reason given: $(cat "$work/err")"
cp "$work/manifest-d3.json" "$f/blob/$(hex manifest-d3).json"
export GH_FAIL=1
run 1 o
unset GH_FAIL
[ -z "$(deleted)" ] || fail "deleted $(deleted) after gh failed"

# --- easyrmm-deploy answers 404 -------------------------------------------------------------
# Stopped by one edge version alone (s4 has no sha- tag); a release alone goes on.
mv "$f/easyrmm-deploy.json" "$f/easyrmm-server.json" "$work"
{ v 109 "$(d s3)" "$old" 1.0.0-rc.4; v 111 "$(d s4)" "$old" 1.0.0-rc.4.edge.99.1; } | jq -s . > "$f/easyrmm-server.json"
run 1 o
[ -z "$(deleted)" ] || fail "deleted $(deleted) with easyrmm-deploy answering 404"
grep -qF 'easyrmm-deploy answers 404' "$work/err" || fail "no reason given: $(cat "$work/err")"
v 109 "$(d s3)" "$old" 1.0.0-rc.4 | jq -s . > "$f/easyrmm-server.json"
run 0 o
[ -z "$(deleted)" ] || fail "deleted $(deleted) with easyrmm-deploy answering 404 and only a release"

# --- No packages yet, and arguments -----------------------------------------------------
rm "$f/easyrmm-server.json"
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
