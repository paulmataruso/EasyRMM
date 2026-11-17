#!/usr/bin/env bash
# Backs up everything needed to restore EasyPatch:
#   easypatch.dump      PostgreSQL (pg_dump custom format)
#   dpkeys.tar          ASP.NET Data Protection key ring. REQUIRED: it decrypts administrators' MFA secrets.
#   agent-packages.tar  Agent MSIs offered for download
# The output directory is created with mode 700. Store backups encrypted and off the host.
# Usage: scripts/backup.sh [output-directory]
set -euo pipefail
cd "$(dirname "$0")/.."

dest="${1:-backups/$(date -u +%Y%m%dT%H%M%SZ)}"
umask 077
mkdir -p "$dest"

echo "Dumping the database..."
docker compose exec -T postgres pg_dump -U easypatch -d easypatch --format=custom --no-owner > "$dest/easypatch.dump"

echo "Saving the Data Protection key ring..."
docker compose exec -T api tar -C /app/keys -cf - . > "$dest/dpkeys.tar"

echo "Saving agent packages..."
tar -C data -cf "$dest/agent-packages.tar" agent-packages

(cd "$dest" && sha256sum easypatch.dump dpkeys.tar agent-packages.tar > SHA256SUMS)
echo "Backup written to $dest"
