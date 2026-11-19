#!/bin/sh
# Starts an Authentik service of deploy/docker-compose.yml (one-product plan,
# phase A) with akadmin's first password, which setup.sh generated into a
# file of its own (mode 0600, readable by Authentik's user only). Authentik
# reads that password only from its environment, and only to create akadmin
# at the first start: before that, anyone reaching Authentik could set it.
#
#   start.sh server | worker | shell -c "..."
set -eu

secret=/easyrmm/secrets/akadmin-password
if [ ! -s "$secret" ]; then
  echo "authentik: $secret is missing or empty: run deploy/scripts/setup.sh --with-authentik" >&2
  exit 1
fi
for setting in AUTHENTIK_SECRET_KEY AUTHENTIK_POSTGRESQL__PASSWORD EASYRMM_AUTHENTIK_CLIENT_SECRET; do
  eval "value=\${$setting:-}"
  if [ -z "$value" ]; then
    echo "authentik: $setting is empty: run deploy/scripts/setup.sh --with-authentik" >&2
    exit 1
  fi
done
AUTHENTIK_BOOTSTRAP_PASSWORD=$(cat "$secret")
export AUTHENTIK_BOOTSTRAP_PASSWORD
exec dumb-init -- ak "$@"
