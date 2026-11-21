#!/bin/sh
# Tests for check-download.sh and check-oci-layout.sh:
#
#   scripts/ci/check-download_test.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0
fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}
sha() { sha256sum < "$1" | cut -c1-64; }

# run <want status> <message part> <script> <args...>
run() {
  want=$1 part=$2 script=$3
  shift 3
  status=0
  "$here/$script" "$@" > "$work/out" 2> "$work/err" || status=$?
  if [ "$status" -ne "$want" ] || ! grep -qF -- "$part" "$work/out" "$work/err"; then
    fail "$script $*: exit $status, \"$(cat "$work/out" "$work/err")\"; want $want and \"$part\""
  fi
}

# --- check-download.sh --------------------------------------------------------------------
d=$work/d
mkdir "$d"
echo bundle > "$d/b.tar.gz"
echo manifest > "$d/m.json"
b=$(sha "$d/b.tar.gz")
m=$(sha "$d/m.json")
run 0 "as recorded" check-download.sh "$d" "b.tar.gz=$b" "m.json=$m"
run 0 "as recorded" check-download.sh "$d" "m.json=$m" b.tar.gz
run 1 "not the recorded" check-download.sh "$d" "b.tar.gz=$m" "m.json=$m"
run 1 "not one" check-download.sh "$d" "b.tar.gz=$(echo "$b" | tr a-f A-F)" "m.json=$m"
run 1 "not one" check-download.sh "$d" "b.tar.gz=" "m.json=$m"
run 1 "holds" check-download.sh "$d" "b.tar.gz=$b"
run 1 "holds" check-download.sh "$d" "b.tar.gz=$b" "m.json=$m" other.txt
echo extra > "$d/extra"
run 1 "holds" check-download.sh "$d" "b.tar.gz=$b" "m.json=$m"
rm "$d/extra"
mkdir "$d/scripts"
run 1 "holds" check-download.sh "$d" "b.tar.gz=$b" "m.json=$m"
rmdir "$d/scripts"
mv "$d/m.json" "$work/m.json"
ln -s "$work/m.json" "$d/m.json"
run 1 "not a regular file" check-download.sh "$d" "b.tar.gz=$b" "m.json=$m"
rm "$d/m.json"
mkdir "$d/m.json"
run 1 "not a regular file" check-download.sh "$d" "b.tar.gz=$b" m.json
rmdir "$d/m.json"
mv "$work/m.json" "$d/m.json"
run 1 "not a directory" check-download.sh "$work/nothing" m.json
run 2 "not a file name" check-download.sh "$d" "../m.json=$m"
run 2 "usage" check-download.sh "$d"

# --- check-oci-layout.sh -------------------------------------------------------------------
# A layout: index.json naming one index, whose blob is there.
l=$work/l
mkdir -p "$l/blobs/sha256"
printf '{"schemaVersion":2,"manifests":[]}' > "$work/index-blob"
i=sha256:$(sha "$work/index-blob")
cp "$work/index-blob" "$l/blobs/sha256/${i#sha256:}"
printf '{"imageLayoutVersion":"1.0.0"}' > "$l/oci-layout"
jq -n --arg d "$i" '{schemaVersion: 2, manifests: [{mediaType: "application/vnd.oci.image.index.v1+json", digest: $d, size: 35}]}' > "$l/index.json"
tar -C "$l" -cf "$work/good.tar" .
run 0 "is $i" check-oci-layout.sh "$work/good.tar" "$i" "$work/x1"
[ -f "$work/x1/blobs/sha256/${i#sha256:}" ] || fail "check-oci-layout.sh did not extract the layout"
other=sha256:$(printf other | sha256sum | cut -c1-64)
run 1 "does not name" check-oci-layout.sh "$work/good.tar" "$other" "$work/x2"
run 2 "not a digest" check-oci-layout.sh "$work/good.tar" latest "$work/x3"
run 2 "not a digest" check-oci-layout.sh "$work/good.tar" "$i
x" "$work/x4"
# Two images named, the blob changed, the blob missing.
jq --arg d "$other" '.manifests += [{mediaType: "application/vnd.oci.image.index.v1+json", digest: $d, size: 1}]' \
  "$l/index.json" > "$work/two.json"
cp "$l/index.json" "$work/one.json"
cp "$work/two.json" "$l/index.json"
tar -C "$l" -cf "$work/two.tar" .
cp "$work/one.json" "$l/index.json"
run 1 "does not name" check-oci-layout.sh "$work/two.tar" "$i" "$work/x5"
# A link beside a good index: a layout is files and folders only.
ln -s /etc/passwd "$l/link"
tar -C "$l" -cf "$work/link.tar" .
rm "$l/link"
run 1 "neither a file nor a folder" check-oci-layout.sh "$work/link.tar" "$i" "$work/x9"
printf ' ' >> "$l/blobs/sha256/${i#sha256:}"
tar -C "$l" -cf "$work/changed.tar" .
run 1 "hashes to" check-oci-layout.sh "$work/changed.tar" "$i" "$work/x6"
rm "$l/blobs/sha256/${i#sha256:}"
tar -C "$l" -cf "$work/missing.tar" .
run 1 "no blob" check-oci-layout.sh "$work/missing.tar" "$i" "$work/x7"
# The directory must be new.
mkdir "$work/x8"
status=0
"$here/check-oci-layout.sh" "$work/good.tar" "$i" "$work/x8" > /dev/null 2>&1 || status=$?
[ "$status" -ne 0 ] || fail "check-oci-layout.sh extracted into a directory that existed"

if [ "$failures" -ne 0 ]; then
  echo "check-download.sh, check-oci-layout.sh: $failures failure(s)" >&2
  exit 1
fi
echo "check-download.sh, check-oci-layout.sh: all tests passed"
