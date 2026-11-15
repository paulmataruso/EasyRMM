#!/bin/sh
set -e

echo "EasyRMM Server starting..."

# Wait for PostgreSQL to be ready
echo "Waiting for database..."
until wget -q --spider "http://127.0.0.1:5432" 2>/dev/null || pg_isready -h 127.0.0.1 -p 5432 -q 2>/dev/null; do
  sleep 1
done
echo "Database is ready."

# Run database migrations
echo "Running database migrations..."
easyrmmserver migrate

# Create default admin if needed
if [ -n "$EASYRM_ADMIN_EMAIL" ] && [ -n "$EASYRM_ADMIN_PASSWORD" ]; then
  echo "Ensuring default admin user exists..."
  easyrmmserver create-admin \
    --email "$EASYRM_ADMIN_EMAIL" \
    --password "$EASYRM_ADMIN_PASSWORD" \
    --if-none-exists
fi

# Start the server
echo "Starting EasyRMM server on ${EASYRM_HOST:-0.0.0.0}:${EASYRM_PORT:-8443}..."
exec easyrmmserver serve
