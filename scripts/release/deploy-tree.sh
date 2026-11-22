#!/bin/sh
# Writes the Compose deployment into an empty directory, in the repository's
# layout so docker-compose.yml's relative mounts resolve and the install
# commands are the same as from a clone (cd deploy):
#
#   deploy/                 docker-compose.yml, .env.example, scripts/setup.sh (with
#                           scripts/setup-mail.sh, which it reads) and
#                           scripts/import-easypatch.sh
#   docker/                 the PostgreSQL, MeshCentral and Authentik files it mounts
#   docs/                   the deployment, agent, backup and upgrade guides
#   LICENSE.md, LICENSING.md, CHANGELOG.md
#
#   scripts/release/deploy-tree.sh <dir>
#
# The release bundle (bundle.sh) is this tree, pinned to the release's
# images; the bundle test (scripts/e2e/bundle.sh) brings it up as it is.
# Refuses a tree that lacks a file the Compose file mounts.
set -eu

dir=${1:?usage: deploy-tree.sh <dir>}
root=$(cd "$(dirname "$0")/../.." && pwd)
if [ -e "$dir" ] && [ -n "$(ls -A "$dir")" ]; then
  echo "deploy-tree: $dir is not empty" >&2
  exit 1
fi

mkdir -p "$dir/deploy/scripts" "$dir/docker/postgres/init" "$dir/docker/meshcentral" \
  "$dir/docker/authentik/blueprints" "$dir/docs/deployment" "$dir/docs/operations"
cp "$root/LICENSE.md" "$root/LICENSING.md" "$root/CHANGELOG.md" "$dir/"
cp "$root/deploy/docker-compose.yml" "$root/deploy/.env.example" "$dir/deploy/"
cp "$root/deploy/scripts/setup.sh" "$root/deploy/scripts/setup-mail.sh" "$root/deploy/scripts/import-easypatch.sh" "$dir/deploy/scripts/"
cp "$root/docker/postgres/init/"*.sh "$dir/docker/postgres/init/"
cp "$root/docker/postgres/easypatch-db-init.sh" "$dir/docker/postgres/"
cp "$root/docker/meshcentral/start.sh" "$dir/docker/meshcentral/"
# Authentik, with setup.sh --with-authentik (ADR-0044).
cp "$root/docker/postgres/authentik-db-init.sh" "$dir/docker/postgres/"
cp "$root/docker/authentik/start.sh" "$root/docker/authentik/setup.py" "$dir/docker/authentik/"
cp "$root/docker/authentik/blueprints/easyrmm.yaml" "$dir/docker/authentik/blueprints/"
cp "$root/docs/deployment/docker.md" "$root/docs/deployment/agents.md" "$dir/docs/deployment/"
cp "$root/docs/operations/backup-restore.md" "$root/docs/operations/upgrading.md" "$root/docs/operations/import-easypatch.md" \
  "$dir/docs/operations/"

# Everything the Compose file mounts from beside it must be in the tree.
missing=$(sed -n 's|^ *- \(\.\./[^:]*\):.*|\1|p' "$dir/deploy/docker-compose.yml" |
  while IFS= read -r src; do [ -e "$dir/deploy/$src" ] || echo "$src"; done)
if [ -n "$missing" ]; then
  printf "deploy-tree: docker-compose.yml mounts files the tree lacks:\n%s\n" "$missing" >&2
  exit 1
fi
find "$dir" -type d -exec chmod 0755 {} +
find "$dir" -type f -exec chmod 0644 {} +
chmod 0755 "$dir/deploy/scripts/setup.sh" "$dir/deploy/scripts/import-easypatch.sh" "$dir/docker/postgres/init/"*.sh \
  "$dir/docker/postgres/easypatch-db-init.sh" "$dir/docker/meshcentral/start.sh" "$dir/docker/postgres/authentik-db-init.sh" \
  "$dir/docker/authentik/start.sh"
