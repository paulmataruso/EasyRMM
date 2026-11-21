#!/usr/bin/env bash
# Deletes edge builds older than 30 days from ghcr.io (ADR-0052;
# docs/architecture/edge-manifest.md#retention), with the GitHub CLI and
# oras, both logged in to read and delete the owner's packages:
#
#   scripts/release/edge-retention.sh <owner> [--dry-run]
#
# - easyrmm-deploy: every version older than 30 days whose tags are all
#   edge versions (v1.0.1-edge.415.1). Whatever edge names, and untagged
#   versions, are kept.
# - easyrmm-server: every image older than 30 days whose tags are all edge
#   versions (1.0.1-edge.415.1) or sha-<commit>, with the untagged manifests
#   its index names (one per platform, and BuildKit's attestations); and the
#   GitHub attestations stored under the tag sha256-<digest> of those
#   images, or of images no longer there, with theirs.
#
# Kept whatever their age: the server image that any kept easyrmm-deploy
# version's manifest names (easyrmm-deploy:edge's among them, even when
# easyrmm-server:edge names another), with its manifests and attestations;
# every manifest that a kept tagged version names; release images, edge,
# and every other untagged version.
#
# Children go before the index that names them, so a run that stops part
# way leaves the index to name them for the next. With --dry-run it prints
# exactly what a run would delete, and deletes nothing.
set -euo pipefail
shopt -s inherit_errexit

usage="usage: edge-retention.sh <owner> [--dry-run]"
[ $# -ge 1 ] && [ $# -le 2 ] || { echo "$usage" >&2; exit 2; }
owner=$1
dry_run=false
case ${2:-} in
  '') ;;
  --dry-run) dry_run=true ;;
  *) echo "$usage" >&2; exit 2 ;;
esac
cutoff=$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)
api=/users/$owner/packages/container
registry=ghcr.io/$owner
edge='[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+\.edge|-edge)\.[0-9]+\.[0-9]+'
digest_re='^sha256:[0-9a-f]{64}$'
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# versions <package>: every version, as one JSON array; an empty one while
# the package does not exist.
versions() {
  if gh api --paginate "$api/$1/versions?per_page=100" 2> "$work/err" > "$work/pages"; then
    jq -s 'add // []' "$work/pages"
  elif grep -q 'HTTP 404' "$work/err"; then
    echo '[]'
  else
    cat "$work/err" >&2
    return 1
  fi
}

declare -A deleted=()
count=0

# remove <package> <version JSON>
remove() {
  local name what
  name=$(jq -r .name <<< "$2")
  [ -z "${deleted[$1@$name]:-}" ] || return 0
  what="$1@$name ($(jq -r '(.metadata.container.tags | if length == 0 then "untagged" else join(", ") end) + ", " + .created_at' <<< "$2"))"
  if [ "$dry_run" = true ]; then
    echo "Would delete $what"
  else
    gh api -X DELETE "$api/$1/versions/$(jq -r .id <<< "$2")" > /dev/null
    echo "Deleted $what"
  fi
  deleted[$1@$name]=1
  count=$((count + 1))
}

# children <digest>: the manifests that easyrmm-server@digest names, if an index.
children() {
  oras manifest fetch "$registry/easyrmm-server@$1" | jq -r '.manifests[]?.digest'
}

# deploy_image <digest>: the server image's digest that the manifest in
# easyrmm-deploy@digest names.
deploy_image() {
  local layer image
  layer=$(oras manifest fetch "$registry/easyrmm-deploy@$1" | jq -r '[.layers[]
    | select(.mediaType == "application/vnd.easyrmm.deploy.manifest.v1+json")]
    | if length == 1 then .[0].digest else error("\(length) manifest layers") end')
  image=$(oras blob fetch --output - "$registry/easyrmm-deploy@$layer" | jq -r .easyrmm.image)
  if ! grep -Eq "$digest_re" <<< "${image##*@}"; then
    echo "edge-retention: easyrmm-deploy@$1 names the server image \"$image\", not one by digest" >&2
    return 1
  fi
  echo "${image##*@}"
}

# --- easyrmm-deploy ---------------------------------------------------------------
deploy=$(versions easyrmm-deploy)
old_deploy=$(jq -c --arg cutoff "$cutoff" --arg edge "^v$edge\$" '[.[] | select(.created_at < $cutoff and
  (.metadata.container.tags | length > 0 and all(test($edge))))]' <<< "$deploy")

# The server images that the kept versions' manifests name, tagged or not,
# read before anything is deleted.
declare -A named=()
while IFS= read -r digest; do
  image=$(deploy_image "$digest")
  named[$image]=1
done < <(jq -r --argjson old "$old_deploy" '.[] | .name as $name | select(all($old[]; .name != $name)) | $name' <<< "$deploy")

# --- easyrmm-server ---------------------------------------------------------------
server=$(versions easyrmm-server)
keep=$(printf '%s\n' "${!named[@]}" | jq -R 'select(length > 0)' | jq -s -c .)
roots=$(jq -c --arg cutoff "$cutoff" --arg edge "^($edge|sha-[0-9a-f]{40})\$" --argjson keep "$keep" '[.[]
  | .name as $name | select(.created_at < $cutoff and all($keep[]; . != $name) and
    (.metadata.container.tags | length > 0 and all(test($edge))))]' <<< "$server")
attestations=$(jq -c --argjson roots "$roots" '
  [.[].name] as $names | [$roots[].name] as $old |
  [.[] | .metadata.container.tags as $tags
    | select($tags | length == 1 and (.[0] | test("^sha256-[0-9a-f]{64}$")))
    | ("sha256:" + ($tags[0] | ltrimstr("sha256-"))) as $subject
    | select(any($old[]; . == $subject) or all($names[]; . != $subject))]' <<< "$server")
doomed=$(jq -c -n --argjson a "$roots" --argjson b "$attestations" '[$a[].name, $b[].name]')

# Every manifest that a kept tagged version, or a server image a kept deploy
# version names, names stays.
declare -A protected=()
while IFS= read -r digest; do
  [ -n "$digest" ] || continue
  list=$(children "$digest")
  for child in $list; do protected[$child]=1; done
done < <(jq -r --argjson doomed "$doomed" '.[] | .name as $name
  | select((.metadata.container.tags | length > 0) and all($doomed[]; . != $name)) | $name' <<< "$server"
  printf '%s\n' "${!named[@]}")

# delete_with_children <version JSON>
delete_with_children() {
  local list child version
  list=$(children "$(jq -r .name <<< "$1")")
  for child in $list; do
    if [ -n "${protected[$child]:-}" ]; then
      echo "Keeping easyrmm-server@$child: a kept image names it"
      continue
    fi
    while IFS= read -r version; do
      remove easyrmm-server "$version"
    done < <(jq -c --arg d "$child" '.[] | select(.name == $d and (.metadata.container.tags | length == 0))' <<< "$server")
  done
  remove easyrmm-server "$1"
}

while IFS= read -r version; do remove easyrmm-deploy "$version"; done < <(jq -c '.[]' <<< "$old_deploy")
while IFS= read -r version; do delete_with_children "$version"; done < <(jq -c '.[]' <<< "$attestations")
while IFS= read -r version; do delete_with_children "$version"; done < <(jq -c '.[]' <<< "$roots")
for image in "${!named[@]}"; do
  echo "Keeping easyrmm-server@$image: a kept easyrmm-deploy version names it"
done
if [ "$dry_run" = true ]; then
  echo "Would delete $count version(s); deleted none (dry run)."
else
  echo "Deleted $count version(s)."
fi
