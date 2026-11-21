#!/bin/sh
# Checks a bundle against its manifest as the updater will (ADR-0052;
# docs/architecture/edge-manifest.md), short of the attestation:
#
#   scripts/release/check-bundle.sh <dir holding the bundle and its manifest> <version>
#
# - the manifest is the version's, in the format of schemaVersion 2;
# - the bundle is the file the manifest names, with its SHA-256;
# - unpacked, with .env made from its .env.example (and placeholders for
#   the secrets setup.sh adds), docker compose names exactly the manifest's
#   images: every profile with --profile '*', and all but Authentik's
#   without;
# - .env.example names the manifest's server image.
#
# Needs docker compose and jq.
set -eu

die() {
  echo "check-bundle: $*" >&2
  exit 1
}

[ $# -eq 2 ] || die "usage: check-bundle.sh <dir> <version>"
dir=$1 version=$2
manifest=$dir/easyrmm-$version-manifest.json
[ -f "$manifest" ] || die "no manifest $manifest"
jq -e --arg v "$version" '.schemaVersion == 2 and .version == $v and .easyrmm.version == $v' "$manifest" > /dev/null ||
  die "$manifest is not version $version's, or not of schemaVersion 2"
file=$(jq -r .bundle.file "$manifest")
[ "$file" = "easyrmm-$version-deploy.tar.gz" ] || die "the manifest names the bundle \"$file\""
[ -f "$dir/$file" ] || die "no bundle $dir/$file"
sum=$(sha256sum "$dir/$file" | cut -d' ' -f1)
[ "$sum" = "$(jq -r .bundle.sha256 "$manifest")" ] || die "$file's SHA-256 is $sum, not the manifest's"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xzf "$dir/$file" -C "$work"
deploy=$work/easyrmm-$version/deploy
[ -f "$deploy/docker-compose.yml" ] || die "$file has no easyrmm-$version/deploy/docker-compose.yml"
cp "$deploy/.env.example" "$deploy/.env"
grep -o '[$]{[A-Z0-9_]*:?' "$deploy/docker-compose.yml" | sed 's/^[$]{//; s/:?$//' | sort -u |
  while IFS= read -r name; do printf '%s=placeholder\n' "$name"; done >> "$deploy/.env"

image=$(sed -n 's/^EASYRMM_IMAGE=//p' "$deploy/.env.example"):$(sed -n 's/^EASYRMM_VERSION=//p' "$deploy/.env.example")
[ "$image" = "$(jq -r .easyrmm.image "$manifest")" ] || die ".env.example names the server $image, not the manifest's"

jq -r '.images[]' "$manifest" > "$work/want"
(cd "$deploy" && docker compose --profile '*' config --images) | LC_ALL=C sort -u > "$work/all"
if ! cmp -s "$work/want" "$work/all"; then
  diff "$work/want" "$work/all" >&2 || true
  die "docker compose names other images than the manifest (above: < manifest, > compose)"
fi
jq -r '(.authentik.image // "") as $authentik | .images[] | select(. != $authentik)' "$manifest" > "$work/want-default"
(cd "$deploy" && COMPOSE_PROFILES='' docker compose config --images) | LC_ALL=C sort -u > "$work/default"
if ! cmp -s "$work/want-default" "$work/default"; then
  diff "$work/want-default" "$work/default" >&2 || true
  die "without a profile, docker compose names other images than the manifest's less Authentik's"
fi
echo "check-bundle: $file matches its manifest; docker compose names exactly its $(wc -l < "$work/all") images"
