#!/usr/bin/env bash
# Builds the history of EasyPatch's old repository (github.com/paulmataruso/
# EasyPatch) from this one, and prints its head commit.
#
# The import (commit 819ae8f) merged EasyPatch's history in under easypatch/.
# This adds, on top of the imported head, one commit for each first-parent
# commit since then that changed easypatch/, with easypatch/ as its tree and
# the same author, committer, dates and message, plus an "EasyRMM-Commit:"
# trailer naming the commit here. The same input always gives the same
# commits, so the mirror only ever fast-forwards.
#
# Usage: scripts/easypatch/mirror.sh [<commit>]   (default HEAD)
#
# git subtree split cannot do this: its --onto fails when the imported
# history is reachable from the commit being split, as it is here.
set -euo pipefail

import=${EASYPATCH_IMPORT_COMMIT:-819ae8f6cb6326ea336370b3094c80cf306aa6d4}
head=$(git rev-parse --verify "${1:-HEAD}^{commit}")
git merge-base --is-ancestor "$import" "$head" || { echo "$head does not contain the import $import" >&2; exit 1; }

mirror=$(git rev-parse "$import^2")
mirror_tree=$(git rev-parse "$mirror^{tree}")
if [ "$(git rev-parse "$import:easypatch")" != "$mirror_tree" ]; then
  echo "the import's easypatch/ is not EasyPatch's imported head" >&2
  exit 1
fi

for commit in $(git rev-list --reverse --first-parent "$import..$head"); do
  tree=$(git rev-parse "$commit:easypatch" 2>/dev/null) || { echo "$commit has no easypatch/" >&2; exit 1; }
  [ "$tree" = "$mirror_tree" ] && continue
  IFS=$'\x1f' read -r an ae ad cn ce cd < <(git log -1 --format='%an%x1f%ae%x1f%ad%x1f%cn%x1f%ce%x1f%cd' --date=raw "$commit")
  message=$(git log -1 --format=%B "$commit" | git interpret-trailers --trailer "EasyRMM-Commit: $commit")
  mirror=$(printf '%s\n' "$message" | GIT_AUTHOR_NAME=$an GIT_AUTHOR_EMAIL=$ae GIT_AUTHOR_DATE=$ad \
    GIT_COMMITTER_NAME=$cn GIT_COMMITTER_EMAIL=$ce GIT_COMMITTER_DATE=$cd git commit-tree "$tree" -p "$mirror")
  mirror_tree=$tree
done
echo "$mirror"
