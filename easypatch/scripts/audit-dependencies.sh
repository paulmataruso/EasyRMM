#!/usr/bin/env bash
# Reports known-vulnerable NuGet and npm dependencies (direct and transitive). Exit code is non-zero if any are found.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
echo "== NuGet (backend, agent, shared) =="
report="$(dotnet list EasyPatch.slnx package --vulnerable --include-transitive 2>&1)"
echo "$report"
if grep -q "has the following vulnerable packages" <<<"$report"; then
  status=1
fi

echo
echo "== npm (frontend) =="
(cd frontend && npm audit --audit-level=low) || status=1

exit "$status"
