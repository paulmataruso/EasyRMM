# Backup and restore

A complete backup has three parts. All three are needed to restore.

| Part | Where | Why |
|---|---|---|
| Database | PostgreSQL in the `postgres` container | Everything: tenants, devices, users, audit log |
| `deploy/.env` | Next to `docker-compose.yml` | **The encryption key** (`EASYRMM_SECRET_KEY`) and database passwords. Without the key, stored second factors and integration credentials cannot be decrypted |
| `/srv/easyrmm/server` | Data directory | ACME account and certificates; later, agent signing keys and release files |

MeshCentral data (`/srv/easyrmm/meshcentral`) joins this list in phase 5.

Store backups encrypted and off the host. The `.env` file and the database
dump together give full control of every managed device: protect them
accordingly.

## Back up

```bash
cd /path/to/easyrmm/deploy
ts=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p /var/backups/easyrmm && chmod 700 /var/backups/easyrmm

# Database: consistent online dump in PostgreSQL's custom format, keeping
# object ownership (easyrmm_owner) and grants (easyrmm_app).
docker compose exec -T postgres pg_dump -U postgres -h 127.0.0.1 -p 15432 \
    --format=custom easyrmm > /var/backups/easyrmm/db-$ts.dump

# Configuration and data directory.
tar -C /path/to/easyrmm/deploy -czf /var/backups/easyrmm/env-$ts.tgz .env
tar -C /srv/easyrmm -czf /var/backups/easyrmm/server-$ts.tgz server
```

Run it from cron or a systemd timer, and copy the files off the host. Test a
restore regularly; an untested backup is a hope, not a backup.

## Restore onto a new host

1. Install Docker, clone the repository at the same release, and restore
   `deploy/.env` and `/srv/easyrmm/server` (owner `65532:65532`, mode 700).
2. Create the data directories: `sudo ./scripts/setup.sh ...` with the same
   host name (it keeps the restored `.env`).
3. Start only PostgreSQL. Its first start creates empty roles and database
   from `.env`:

   ```bash
   docker compose up -d postgres
   ```

4. Load the dump as the PostgreSQL superuser. Row-level security is forced
   even for the table owner, so only a superuser can load the data; the dump
   restores ownership to `easyrmm_owner` and the grants to `easyrmm_app`:

   ```bash
   docker compose exec -T postgres pg_restore -U postgres -h 127.0.0.1 -p 15432 \
       --dbname=easyrmm --exit-on-error \
       < /var/backups/easyrmm/db-<timestamp>.dump
   ```

5. Start the server: `docker compose up -d`. It applies any newer migrations
   and serves the restored data.

6. Verify the audit chain as a super administrator:
   `GET /api/v1/audit/verify` returns `checked` and, if the chain is broken,
   `firstBadId`.
