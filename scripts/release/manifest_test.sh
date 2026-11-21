#!/bin/sh
# Tests for manifest.sh, with deploy/docker-compose.yml pinned as bundle.sh
# pins it, and variants of it:
#
#   scripts/release/manifest_test.sh
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
script=$root/scripts/release/manifest.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
out=$work/out
mkdir "$out"
failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

d1=sha256:1111111111111111111111111111111111111111111111111111111111111111
d2=sha256:2222222222222222222222222222222222222222222222222222222222222222
commit=0123456789abcdef0123456789abcdef01234567
version=v1.0.1-edge.415.1
rmm=ghcr.io/paulmataruso/easyrmm-server:1.0.1-edge.415.1@$d1
ep=ghcr.io/paulmataruso/easypatch-server:1.12.1@$d2
export EASYRMM_IMAGE_PIN="$rmm" EASYPATCH_IMAGE_PIN="$ep"

# The repository's docker-compose.yml with the engine named by its pin, as in a bundle.
compose=$work/docker-compose.yml
sed -e "s|^    image: \${EASYPATCH_IMAGE:-[^}]*}:\${EASYPATCH_VERSION:-[^}]*}\$|    image: $ep|" \
  "$root/deploy/docker-compose.yml" > "$compose"
[ "$(grep -c "image: $ep\$" "$compose")" -eq 3 ] || { echo "could not pin the engine in the test's compose file" >&2; exit 1; }
printf 'a bundle' > "$work/easyrmm-$version-deploy.tar.gz"
bundle=$work/easyrmm-$version-deploy.tar.gz

# run <name> [env...]: manifest.sh on $compose, its output in $out/<name>.json.
run() {
  name=$1
  shift
  env "$@" "$script" "$version" "$commit" "$bundle" "$compose" > "$out/$name.json" 2> "$out/$name.err"
}
# refuse <message part> <name> [env...]: manifest.sh fails, saying message.
refuse() {
  message=$1
  shift
  if run "$@"; then
    fail "$1: manifest.sh succeeded: $(cat "$out/$1.json")"
  elif ! grep -qF -- "$message" "$out/$1.err"; then
    fail "$1: error \"$(cat "$out/$1.err")\" does not say \"$message\""
  fi
}
# check <name> <jq filter>: the filter holds for $out/<name>.json.
check() {
  jq -e "$2" "$out/$1.json" > /dev/null || fail "$1: $2 does not hold for $(cat "$out/$1.json")"
}

# --- The deployment as it is ------------------------------------------------------
pg=$(sed -n 's/^    image: \(postgres:.*\)$/\1/p' "$root/deploy/docker-compose.yml" | head -n 1)
mesh=$(sed -n 's/^    image: \(ghcr.io\/ylianst\/meshcentral:.*\)$/\1/p' "$root/deploy/docker-compose.yml" | head -n 1)
ak=$(sed -n 's/^    image: \(ghcr.io\/goauthentik\/server:.*\)$/\1/p' "$root/deploy/docker-compose.yml" | head -n 1)
if run full; then
  check full '.schemaVersion == 2'
  check full ".version == \"$version\" and .commit == \"$commit\""
  check full ".bundle == {file: \"easyrmm-$version-deploy.tar.gz\", sha256: \"$(sha256sum "$bundle" | cut -d' ' -f1)\"}"
  check full ".easyrmm == {version: \"$version\", image: \"$rmm\"}"
  check full ".easypatch == {version: \"1.12.1\", image: \"$ep\", agentPackages: []}"
  check full ".postgres == {major: $(printf '%s' "${pg#postgres:}" | cut -d. -f1), image: \"$pg\"}"
  check full ".meshcentral == {image: \"$mesh\"}"
  ak_version=${ak%@*}
  check full ".authentik == {included: true, version: \"${ak_version##*:}\", image: \"$ak\"}"
  # Every image once, sorted, the server's being its pin.
  want=$(printf '%s\n' "$rmm" "$ep" "$pg" "$mesh" "$ak" | LC_ALL=C sort -u | jq -R . | jq -sc .)
  check full ".images == $want"
  # Nothing but the fields of the format.
  check full 'keys == ["authentik","bundle","commit","easypatch","easyrmm","images","meshcentral","postgres","schemaVersion","version"]'
else
  fail "full: $(cat "$out/full.err")"
fi

# --- The engine's agent packages ----------------------------------------------------
mkdir "$work/packages"
for f in EasyPatchAgent-1.12.1-x64.msi EasyPatchAgent-1.12.1-x64.deb EasyPatchAgent-1.12.1-x64.deb.sig other.txt; do
  printf '%s' "$f" > "$work/packages/$f"
done
if run from-dir EASYPATCH_PACKAGES="$work/packages"; then
  check from-dir "[.easypatch.agentPackages[].file] == [\"EasyPatchAgent-1.12.1-x64.deb\", \"EasyPatchAgent-1.12.1-x64.msi\"]"
  check from-dir ".easypatch.agentPackages[0].sha256 == \"$(sha256sum "$work/packages/EasyPatchAgent-1.12.1-x64.deb" | cut -d' ' -f1)\""
else
  fail "from-dir: $(cat "$out/from-dir.err")"
fi
mkdir "$work/old-packages"
printf x > "$work/old-packages/EasyPatchAgent-1.12.0-x64.deb"
refuse "no EasyPatch 1.12.1 agent packages" old-packages EASYPATCH_PACKAGES="$work/old-packages"
refuse "neither a directory nor a manifest" missing-packages EASYPATCH_PACKAGES="$work/nothing-here"

# An edge build: the packages of the release whose engine it runs.
jq -n --arg ep "$ep" '{easypatch: {version: "1.12.1", image: $ep, agentPackages: [{file: "EasyPatchAgent-1.12.1-x64.deb", sha256: "ab"}]}}' \
  > "$work/release-manifest.json"
if run from-release EASYPATCH_PACKAGES="$work/release-manifest.json"; then
  check from-release '.easypatch.agentPackages == [{file: "EasyPatchAgent-1.12.1-x64.deb", sha256: "ab"}]'
else
  fail "from-release: $(cat "$out/from-release.err")"
fi
jq '.easypatch.image = "ghcr.io/paulmataruso/easypatch-server:1.12.0@sha256:3333333333333333333333333333333333333333333333333333333333333333"' \
  "$work/release-manifest.json" > "$work/other-engine.json"
refuse "names the engine" other-engine EASYPATCH_PACKAGES="$work/other-engine.json"
jq 'del(.easypatch.agentPackages)' "$work/release-manifest.json" > "$work/no-packages.json"
refuse "lists no agent packages" no-packages EASYPATCH_PACKAGES="$work/no-packages.json"

# --- Refusals -------------------------------------------------------------------------
cp "$compose" "$work/pinned.yml"
variant() { # <sed expression>: $compose from the pinned file, changed
  sed -e "$1" "$work/pinned.yml" > "$compose"
}

# Without Authentik's services: not part of it.
awk '/^  authentik-[a-z-]+:$/ { skip = 1; next } /^  [a-z]/ { skip = 0 } !skip' "$work/pinned.yml" > "$compose"
if run no-authentik; then
  check no-authentik '.authentik == {included: false}'
  check no-authentik '.images | all(contains("goauthentik") | not)'
else
  fail "no-authentik: $(cat "$out/no-authentik.err")"
fi

variant "s|^    image: ghcr.io/ylianst/meshcentral:\\([^@]*\\)@.*|    image: ghcr.io/ylianst/meshcentral:\\1|"
refuse "meshcentral: ghcr.io/ylianst/meshcentral:" mesh-by-tag
variant "s|^    image: ghcr.io/goauthentik/server:.*|    image: ghcr.io/goauthentik/server@$d1|"
refuse "authentik-server: ghcr.io/goauthentik/server@" authentik-by-digest-only
variant "s|^    image: \${EASYRMM_IMAGE.*|    image: ghcr.io/paulmataruso/easyrmm-server:latest|"
refuse "server: ghcr.io/paulmataruso/easyrmm-server:latest" server-unpinned
variant "s|^    image: postgres:[^@]*@|    image: postgres:latest@|"
refuse "no major version in PostgreSQL's tag" postgres-latest
variant "s|^  postgres:\$|  database:|"
refuse "no postgres service" no-postgres
variant "s|^  meshcentral:\$|  mesh:|"
refuse "no meshcentral service" no-meshcentral
variant "s|$ep|ghcr.io/paulmataruso/easypatch-server:1.12.0@$d1|"
refuse "does not run the engine" other-engine-in-compose
cp "$work/pinned.yml" "$compose"
if "$script" "$version" abc123 "$bundle" "$compose" > /dev/null 2> "$work/short.err" ||
  ! grep -qF "is not a full commit" "$work/short.err"; then
  fail "a short commit was accepted, or not named: $(cat "$work/short.err")"
fi
if "$script" "$version" "$commit" "$work/no-bundle" "$compose" > /dev/null 2> "$work/nob.err" ||
  ! grep -qF "no bundle" "$work/nob.err"; then
  fail "a missing bundle was accepted, or not named: $(cat "$work/nob.err")"
fi

if [ "$failures" -ne 0 ]; then
  echo "manifest.sh: $failures failure(s)" >&2
  exit 1
fi
echo "manifest.sh: all tests passed"
