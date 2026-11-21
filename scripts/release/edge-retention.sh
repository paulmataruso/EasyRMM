#!/usr/bin/env bash
# Deletes edge builds older than 30 days from ghcr.io (ADR-0052;
# docs/architecture/edge-manifest.md#retention), with the GitHub CLI and
# Docker, both logged in to delete and read the owner's packages:
#
#   scripts/release/edge-retention.sh <owner> [--dry-run]
#
# - easyrmm-deploy: every version older than 30 days whose tags are all
#   edge versions (v1.0.1-edge.415.1). Whatever edge names is kept.
# - easyrmm-server: every image older than 30 days whose tags are all edge
#   versions (1.0.1-edge.415.1) or sha-<commit>, with the manifests its
#   index names (one per platform, and BuildKit's attestations); and the
#   attestations stored under sha256-<digest> of those images, or of images
#   no longer there, with theirs. A manifest that a kept tagged version
#   names is kept. Release images, edge, and every other untagged version
#   are kept.
#
# Children go before the index that names them, so a run that stops part
# way leaves the index to name them for the next. With --dry-run it lists
# what it would delete and deletes nothing.
set -euo pipefail

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
edge='[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+\.edge|-edge)\.[0-9]+\.[0-9]+'
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
}

# children <digest>: the manifests that easyrmm-server@digest names, if an index.
children() {
  docker buildx imagetools inspect --raw "ghcr.io/$owner/easyrmm-server@$1" | jq -r '.manifests[]?.digest'
}

# --- easyrmm-deploy ---------------------------------------------------------------
deploy=$(versions easyrmm-deploy)
while IFS= read -r version; do
  remove easyrmm-deploy "$version"
done < <(jq -c --arg cutoff "$cutoff" --arg edge "^v$edge\$" '.[] | select(.created_at < $cutoff and
  (.metadata.container.tags | length > 0 and all(test($edge))))' <<< "$deploy")

# --- easyrmm-server ---------------------------------------------------------------
server=$(versions easyrmm-server)
roots=$(jq -c --arg cutoff "$cutoff" --arg edge "^($edge|sha-[0-9a-f]{40})\$" '[.[] | select(.created_at < $cutoff and
  (.metadata.container.tags | length > 0 and all(test($edge))))]' <<< "$server")
attestations=$(jq -c --arg cutoff "$cutoff" --argjson roots "$roots" '
  [.[].name] as $names | [$roots[].name] as $old |
  [.[] | .metadata.container.tags as $tags
    | select($tags | length == 1 and (.[0] | test("^sha256-[0-9a-f]{64}$")))
    | ("sha256:" + ($tags[0] | ltrimstr("sha256-"))) as $subject
    | select(any($old[]; . == $subject) or (.created_at < $cutoff and all($names[]; . != $subject)))]' <<< "$server")

# Every manifest a kept tagged version names stays.
declare -A protected=()
doomed=$(jq -c -n --argjson a "$roots" --argjson b "$attestations" '[$a[].name, $b[].name]')
while IFS= read -r digest; do
  named=$(children "$digest")
  for child in $named; do protected[$child]=1; done
done < <(jq -r --argjson doomed "$doomed" \
  '.[] | .name as $name | select((.metadata.container.tags | length > 0) and all($doomed[]; . != $name)) | $name' <<< "$server")

# delete_with_children <version JSON>
delete_with_children() {
  local named child version
  named=$(children "$(jq -r .name <<< "$1")")
  for child in $named; do
    if [ -n "${protected[$child]:-}" ]; then
      echo "Keeping easyrmm-server@$child: a kept image names it"
      continue
    fi
    while IFS= read -r version; do
      remove easyrmm-server "$version"
    done < <(jq -c --arg d "$child" '.[] | select(.name == $d)' <<< "$server")
  done
  remove easyrmm-server "$1"
}

while IFS= read -r version; do delete_with_children "$version"; done < <(jq -c '.[]' <<< "$attestations")
while IFS= read -r version; do delete_with_children "$version"; done < <(jq -c '.[]' <<< "$roots")
