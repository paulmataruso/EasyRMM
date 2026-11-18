#!/usr/bin/env bash
# Restores a backup made by scripts/backup.sh into this deployment, replacing the current database, key ring and
# agent packages. The stack must have been started at least once (so the volumes exist).
# Usage: scripts/restore.sh <backup-directory> --yes
set -euo pipefail
cd "$(dirname "$0")/.."

src="${1:-}"
if [[ -z "$src" || ! -d "$src" ]]; then
  echo "Usage: $0 <backup-directory> --yes" >&2
  exit 2
fi
if [[ "${2:-}" != "--yes" ]]; then
  echo "This replaces the current EasyPatch database, Data Protection keys and agent packages." >&2
  echo "Re-run with --yes to continue." >&2
  exit 2
fi

(cd "$src" && sha256sum --check --quiet SHA256SUMS)

echo "Stopping the application (the database stays up)..."
docker compose stop caddy api worker
docker compose up -d postgres
until docker compose exec -T postgres pg_isready -U easypatch -d easypatch >/dev/null 2>&1; do sleep 2; done

echo "Restoring the database..."
docker compose exec -T postgres pg_restore -U easypatch -d easypatch --clean --if-exists --no-owner --exit-on-error < "$src/easypatch.dump"

echo "Restoring the Data Protection key ring..."
docker compose run --rm --no-deps -T --entrypoint sh api -c 'find /app/keys -mindepth 1 -delete && tar -C /app/keys -xf -' < "$src/dpkeys.tar"

echo "Restoring agent packages..."
rm -rf data/agent-packages
tar -C data -xf "$src/agent-packages.tar"

echo "Starting EasyPatch..."
docker compose up -d
echo "Restore complete."
