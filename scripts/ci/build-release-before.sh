#!/bin/sh
# Builds the Linux agent of an earlier release from its tag, for the test
# that shows an agent of the release before still runs every job it ran
# (ADR-0009, ADR-0064; server/internal/httpapi/agentapi).
#
#   build-release-before.sh <tag> <output>
#
# A shallow clone without tags fetches the one tag it needs.
set -eu

tag=$1
out=$2
go=${GO:-go}

if ! git rev-parse --verify --quiet "refs/tags/$tag^{commit}" >/dev/null; then
	git fetch --no-tags --depth=1 origin "refs/tags/$tag:refs/tags/$tag"
fi
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
git archive "$tag" | tar -x -C "$dir"
mkdir -p "$(dirname "$out")"
case $out in
/*) ;;
*) out=$(pwd)/$out ;;
esac
(cd "$dir" && CGO_ENABLED=0 GOOS=linux "$go" build -trimpath -ldflags "-X main.Version=${tag#easyrmm-v}" -o "$out" ./agent/cmd/easyrmm-agent)
echo "built the agent of $tag: $out"
