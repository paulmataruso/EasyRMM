# Backup and restore

A complete backup has four parts, five with `manual` TLS. All are needed to
restore.

| Part | Where | Why |
|---|---|---|
| Database | PostgreSQL in the `postgres` container | Everything: tenants, devices, users, audit log |
| `deploy/.env` | Next to `docker-compose.yml` | **The encryption key** (`EASYRMM_SECRET_KEY`) and database passwords. The database's secrets are sealed with the key: authenticator-app secrets, MeshCentral's service account, the EasyPatch and audit-forwarding credentials, the internal certificate authority agents trust and the job-signing key they pinned. Without it, authenticator apps stop working (recovery codes and security keys still do) and every agent has to be reinstalled |
| `/srv/easyrmm/server` | Data directory | The ACME account and certificates (`acme` mode); empty in the other modes |
| `/srv/easyrmm/tls` (`EASYRMM_TLS_DIR`) | `manual` TLS only | Your certificate and key. Back them up wherever you manage certificates, or include the directory here |
| `/srv/easyrmm/meshcentral` | MeshCentral's data | **MeshCentral's server identity** (the keys its agents trust), its device records and the downloaded agent binaries. Without it, every remote-access agent has to be reinstalled |

`/srv/easyrmm/meshcentral-config` needs no backup: the server rewrites it on
every start from `.env` and the database.

Store backups encrypted and off the host. The `.env` file and the database
dump together give full control of every managed device: protect them
accordingly.

## Back up

```bash
cd /path/to/easyrmm/deploy
ts=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p /var/backups/easyrmm && chmod 700 /var/backups/easyrmm

# Database: consistent online dump in PostgreSQL's custom format, keeping
# object ownership (easyrmm_owner) and grants (easyrmm_app). As the
# container's postgres user over its local socket, which needs no password.
docker compose exec -T -u postgres postgres pg_dump -p 15432 \
    --format=custom easyrmm > /var/backups/easyrmm/db-$ts.dump

# Configuration and data directory.
tar -C /path/to/easyrmm/deploy -czf /var/backups/easyrmm/env-$ts.tgz .env
tar -C /srv/easyrmm -czf /var/backups/easyrmm/server-$ts.tgz server
# With manual TLS, unless your certificates are backed up elsewhere:
# tar -C /srv/easyrmm -czf /var/backups/easyrmm/tls-$ts.tgz tls

# MeshCentral keeps its database in files; stop it for a consistent copy.
# Open remote sessions drop and agents reconnect on their own when it is back.
docker compose stop meshcentral
tar -C /srv/easyrmm -czf /var/backups/easyrmm/meshcentral-$ts.tgz meshcentral
docker compose start meshcentral
```

Run it from cron or a systemd timer, and copy the files off the host. Test a
restore regularly; an untested backup is a hope, not a backup.

This procedure is rehearsed by `scripts/drill/backup-restore.sh` on a
disposable deployment (see [Drills](../development/drills.md)). The drill
backs up a server with a real agent, deletes the host, restores onto a new
checkout with the steps below, and checks:
* TLS against the saved certificate authority;
* the same password and authenticator;
* the audit chain;
* that the same agent reconnects without reinstalling and runs a job.

Its first run, on 16 November 2026, found that the guide's database
commands failed and that a fresh deployment did not start; both are fixed.

## Restore onto a new host

1. Install Docker, then clone the repository at the same release or unpack
   that release's deployment bundle ([Upgrading](upgrading.md) describes
   both). Restore `deploy/.env`, `/srv/easyrmm/server`,
   `/srv/easyrmm/meshcentral` and, with `manual` TLS, your certificate
   files.
   Keep the ownership `setup.sh` gives them: `65532:65532`, mode 700, for
   `server` and for the `data`, `files` and `backups` directories inside
   `meshcentral`.
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
   docker compose exec -T -u postgres postgres pg_restore -p 15432 \
       --dbname=easyrmm --exit-on-error \
       < /var/backups/easyrmm/db-<timestamp>.dump
   ```

5. Start the server: `docker compose up -d`. It serves the restored data.
   To move to a newer release as well, restore onto the same release first,
   check it, then upgrade as in [Upgrading](upgrading.md).

6. Verify the audit chain as a super administrator:
   `GET /api/v1/audit/verify` returns `checked` and, if the chain is broken,
   `firstBadId`.
