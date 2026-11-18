#!/usr/bin/env bash
# One-time preparation of a Docker host for EasyPatch:
#   * generates the PostgreSQL password as a Compose secret file (never in .env, images or source control)
#   * creates the agent package directory
#   * creates .env from .env.example if it does not exist
# Safe to re-run: existing files are never overwritten.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p secrets data/agent-packages
chmod 700 secrets            # only the host administrator can traverse to the secret files
chmod 755 data data/agent-packages

if [[ -s secrets/db_password ]]; then
  echo "secrets/db_password already exists; leaving it unchanged."
else
  umask 077
  # 32 random bytes as hex: no shell or URL metacharacters.
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > secrets/db_password
  # Readable inside the containers (postgres and the non-root app user); the 700 directory keeps other host users out.
  chmod 644 secrets/db_password
  echo "Generated secrets/db_password."
fi

if [[ -f .env ]]; then
  echo ".env already exists; leaving it unchanged."
else
  cp .env.example .env
  chmod 600 .env
  echo "Created .env from .env.example. Edit EASYPATCH_DOMAIN and ACME_EMAIL before starting."
fi

cat <<'MSG'

Next steps:
  1. Edit .env (EASYPATCH_DOMAIN, ACME_EMAIL) and point DNS for that name at this host.
  2. Copy a signed EasyPatch agent MSI into data/agent-packages/ (see docs/agent-installation.md).
  3. docker compose build && docker compose up -d
  4. docker compose run --rm api create-admin --email you@example.com   (you sign in with this address)
MSG
