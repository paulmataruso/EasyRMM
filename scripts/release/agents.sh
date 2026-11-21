#!/bin/sh
# Builds the EasyRMM agents exactly as docker/server/Dockerfile builds the
# ones the server hands out (-trimpath, -buildvcs=false: no commit stamped
# in), so that a release's files are the same bytes: an operator signs the
# release's Windows agent and the server accepts it only if it matches its
# own build (ADR-0049). check-agents.sh compares them with an image's.
#
#   scripts/release/agents.sh <version> <out-dir>
#
# writes easyrmm-agent-windows-{amd64,arm64}.exe and
# easyrmm-agent-linux-{amd64,arm64,arm,386}, reporting <version> (v1.2.3).
# GO names the go command (default: go).
set -eu

[ $# -eq 2 ] || { echo "usage: agents.sh <version> <out-dir>" >&2; exit 2; }
version=$1 out=$2
root=$(cd "$(dirname "$0")/../.." && pwd)
go=${GO:-go}
mkdir -p "$out"
out=$(cd "$out" && pwd)

build() { # os arch suffix [GOARM]
  CGO_ENABLED=0 GOOS=$1 GOARCH=$2 GOARM=${4:-} "$go" -C "$root" build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.Version=$version" \
    -o "$out/easyrmm-agent-$1-$2$3" ./agent/cmd/easyrmm-agent
}
build windows amd64 .exe
build windows arm64 .exe
build linux amd64 ""
build linux arm64 ""
build linux arm "" 7
build linux 386 ""
