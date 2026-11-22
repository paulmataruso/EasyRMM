# Backup and restore

A complete backup has six parts, seven with `manual` TLS, and two more with
Authentik (`setup.sh --with-authentik`). All are needed to restore.

| Part | Where | Why |
|---|---|---|
| Database | PostgreSQL in the `postgres` container | Everything: tenants and their [customer record](customer-record.md) (contacts, addresses, hours, places), devices, users, audit log |
| The patching engine's database | `easypatch`, in the same PostgreSQL | Patching: each device's update state and history, policies, holds, jobs, alerts, reports, and the EasyPatch agents' credentials. Without it, every EasyPatch agent has to be reinstalled and patch history is lost |
| `/srv/easyrmm/easypatch/keys` | The engine's data-protection keys | They decrypt the engine's stored mail and webhook credentials. Without them, notification channels have to be set up again |
| `deploy/.env` | Next to `docker-compose.yml` | **The encryption key** (`EASYRMM_SECRET_KEY`) and database passwords. The database's secrets are sealed with the key, among them authenticator-app secrets, MeshCentral's service account, the single sign-on and audit-forwarding credentials, the console's mail server password, the internal certificate authority agents trust and the job-signing key they pinned. Without it, authenticator apps stop working (recovery codes and security keys still do) and every agent has to be reinstalled. With Authentik, it also holds Authentik's settings and secrets: `COMPOSE_PROFILES=authentik`, `EASYRMM_AUTHENTIK_HOSTNAME`, `EASYRMM_AUTHENTIK_ADMIN_EMAIL`, `EASYRMM_AUTHENTIK_CLIENT_SECRET`, `AUTHENTIK_SECRET_KEY` and `AUTHENTIK_DB_PASSWORD` |
| `/srv/easyrmm/server` | Data directory | The ACME account and certificates (`acme` mode); empty in the other modes |
| `/srv/easyrmm/tls` (`EASYRMM_TLS_DIR`) | `manual` TLS only | Your certificate and key. Back them up wherever you manage certificates, or include the directory here |
| `/srv/easyrmm/secrets` | With a Microsoft 365 application in `.env` only | **The application's client secret, or its certificate and private key** (`setup.sh --smtp-*`, [Mail](mail.md#microsoft-365)), which `.env` names by path and never holds. Without them the server does not start until they are given again (a new secret or certificate from Entra). Owned `root:65532`: the directory mode 750, the files 440. Protect the backup as you protect `.env` |
| `/srv/easyrmm/meshcentral` | MeshCentral's data | **MeshCentral's server identity** (the keys its agents trust), its device records and the downloaded agent binaries. Without it, every remote-access agent has to be reinstalled |
| Authentik's database | `authentik`, in the same PostgreSQL, with Authentik only | **Everyone's sign-in**: Authentik's users with their passwords and second factors, its flows, the provider EasyRMM signs in through, and the key pair that signs EasyRMM's ID tokens |
| `/srv/easyrmm/authentik` | With Authentik only | The password of Authentik's own administrator, `akadmin` (`secrets/`), the files uploaded to Authentik, such as icons (`data/`), and `setup.sh`'s record that it issued the first invitation (`invitation-issued`) |

**With Authentik, a backup without its database and directory loses
single sign-on.** Restored without them, the deployment starts a new, empty
Authentik: no users, no second factors, and a new key signing EasyRMM's ID
tokens. Making the users again does not let them back in. EasyRMM links each
account to its identity at Authentik, Authentik gives a re-made user a new
identity, and EasyRMM refuses an identity other than the linked one
(`linked_other` in [Single sign-on](../security/single-sign-on.md)). Without
the directory alone, `akadmin`'s password is lost.

`/srv/easyrmm/meshcentral-config` needs no backup: the server rewrites it on
every start from `.env` and the database. Nor does
`/srv/easyrmm/easypatch/winget`, the engine's copy of winget, which it
downloads again, or `/srv/easyrmm/updater`, the updater's status.
Authentik's blueprint and start-up scripts come with the release
(`docker/authentik/`), and it keeps its certificates in its database, so it
has no other files to back up.

Store backups encrypted and off the host. The `.env` file and the database
dump together give full control of every managed device: protect them
accordingly.

The database dump grows with what the database keeps. At the defaults, the
largest shares are the measurements kept for charts, about 1 GiB for 1,000
devices ([Inventory and health](inventory.md#retention-and-size)), and disk
health history, about 0.6 GiB for 1,000 devices with two disks each
([Disk health](disk-health.md#history-and-retention)). The dump is
compressed, so it is usually smaller than the database.

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
# The patching engine's database, the same way.
docker compose exec -T -u postgres postgres pg_dump -p 15432 \
    --format=custom easypatch > /var/backups/easyrmm/easypatch-db-$ts.dump

# Configuration, data directory and the engine's keys.
tar -C /path/to/easyrmm/deploy -czf /var/backups/easyrmm/env-$ts.tgz .env
tar -C /srv/easyrmm -czf /var/backups/easyrmm/server-$ts.tgz server
tar -C /srv/easyrmm -czf /var/backups/easyrmm/easypatch-keys-$ts.tgz easypatch/keys
# With manual TLS, unless your certificates are backed up elsewhere:
# tar -C /srv/easyrmm -czf /var/backups/easyrmm/tls-$ts.tgz tls
# The mail server's Microsoft 365 secret or key, from .env's setup.sh --smtp-*:
tar -C /srv/easyrmm -czf /var/backups/easyrmm/secrets-$ts.tgz secrets

# With Authentik (setup.sh --with-authentik made its directory): its
# database, the same way, and its directory. Skipped without Authentik.
if [ -d /srv/easyrmm/authentik ]; then
    docker compose exec -T -u postgres postgres pg_dump -p 15432 \
        --format=custom authentik > /var/backups/easyrmm/authentik-db-$ts.dump
    tar -C /srv/easyrmm -czf /var/backups/easyrmm/authentik-$ts.tgz authentik
fi

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
* that the same agent reconnects without reinstalling and runs a job;
* that the patching engine has the same organizations and the same keys.

With `--authentik` it installs with Authentik, makes the administrator in
Authentik from `setup.sh`'s invitation, and also checks that they sign in
through Authentik again as the same user, to the same account, and that the
key signing EasyRMM's ID tokens is unchanged. With `--in-place` it restores
over the running deployment instead, as in
[Restore in place](#restore-in-place), checks that the set-aside data root
is unchanged, then puts it back and checks that what changed after the
backup returns.

Its first run, on 16 November 2026, found that the guide's database
commands failed and that a fresh deployment did not start; both are fixed. A run on 19 November 2026, after the patching engine joined every
deployment, backed up and restored the engine's database and keys with the
steps above and passed. A run with Authentik on 21 November 2026 backed up
and restored Authentik's database and directory with the steps above and
passed. Runs in place the same day, with and without Authentik, set the
running deployment aside, restored over it, then put it back, with the
steps below, and passed ([Drills](../development/drills.md#runs)).

## Restore onto a new host

These steps expect an empty data root and an empty PostgreSQL. On a host
that still has the deployment, set it aside first, as in
[Restore in place](#restore-in-place).

1. Install Docker, then clone the repository at the same release or unpack
   that release's deployment bundle ([Upgrading](upgrading.md) describes
   both). Restore `deploy/.env`, `/srv/easyrmm/server`,
   `/srv/easyrmm/meshcentral`, `/srv/easyrmm/easypatch/keys`,
   `/srv/easyrmm/secrets`, with Authentik `/srv/easyrmm/authentik`, and
   with `manual` TLS your certificate files.
   Keep the ownership `setup.sh` gives them: `65532:65532`, mode 700, for
   `server` and for the `data`, `files` and `backups` directories inside
   `meshcentral`; `1654:1654`, mode 700, for `easypatch/keys`;
   `1000:1000` (Authentik's user), mode 700, for the `data`, `secrets` and
   `invitations` directories inside `authentik` and the files in them;
   `root:65532`, mode 750, for `secrets` and mode 440 for the files in it
   (`setup.sh` gives them these again).
   Extracting as root with `tar --numeric-owner` keeps them by number;
   without it, tar goes by name, and another host can give a name, such as
   uid 1000's, another number:

   ```bash
   sudo tar -C /path/to/easyrmm/deploy -xzf /var/backups/easyrmm/env-<timestamp>.tgz
   sudo mkdir -p /srv/easyrmm
   # Without Authentik, leave out authentik.
   for part in server meshcentral easypatch-keys secrets authentik; do
       sudo tar --numeric-owner -C /srv/easyrmm \
           -xzf /var/backups/easyrmm/$part-<timestamp>.tgz
   done
   ```

2. Create the data directories: `sudo ./scripts/setup.sh ...` with the same
   options as at install (it keeps the restored `.env`). With Authentik,
   that includes `--with-authentik` and the same `--authentik-hostname` and
   `--admin-email`; with the restored `authentik` directory it keeps
   `akadmin`'s password and issues no invitation.
3. Start only PostgreSQL. Its first start creates empty roles and database
   from `.env`:

   ```bash
   docker compose up -d postgres
   ```

   Not Authentik, before its database is restored: its first start on an
   empty database makes a new Authentik, and the dump no longer loads.

4. Load the dump as the PostgreSQL superuser. Row-level security is forced
   even for the table owner, so only a superuser can load the data; the dump
   restores ownership to `easyrmm_owner` and the grants to `easyrmm_app`:

   ```bash
   docker compose exec -T -u postgres postgres pg_restore -p 15432 \
       --dbname=easyrmm --exit-on-error \
       < /var/backups/easyrmm/db-<timestamp>.dump
   ```

   Then the patching engine's: `easypatch-db-init` creates its empty
   database and roles from `.env`, and the dump goes in the same way:

   ```bash
   docker compose run --rm easypatch-db-init
   docker compose exec -T -u postgres postgres pg_restore -p 15432 \
       --dbname=easypatch --exit-on-error \
       < /var/backups/easyrmm/easypatch-db-<timestamp>.dump
   ```

   With Authentik, its database last, the same way: `authentik-db-init`
   creates the empty `authentik` database and the `authentik` role that
   owns it, with the password from `.env`, and the dump gives every object
   back to that role:

   ```bash
   docker compose run --rm authentik-db-init
   docker compose exec -T -u postgres postgres pg_restore -p 15432 \
       --dbname=authentik --exit-on-error \
       < /var/backups/easyrmm/authentik-db-<timestamp>.dump
   ```

5. Start the server: `docker compose up -d`. It serves the restored data.
   With Authentik, this starts Authentik too, on its restored database, and
   waits until Authentik's worker is healthy.
   To move to a newer release as well, restore onto the same release first,
   check it, then upgrade as in [Upgrading](upgrading.md).

6. Verify the audit chain as a super administrator:
   `GET /api/v1/audit/verify` returns `checked` and, if the chain is broken,
   `firstBadId`. With Authentik, sign in through it: the same people sign
   in with the same passwords and second factors.

## Restore in place

To restore over a deployment still on the host, to go back after an
upgrade ([Upgrading](upgrading.md#going-back)) or to undo a mistake, set
the deployment aside first, then restore as onto a new host. The restore
steps expect an empty data root and an empty PostgreSQL. PostgreSQL keeps
its data in the data root, in `/srv/easyrmm/postgres`, so setting the data
root aside empties both. Nothing is deleted: the set-aside deployment is
the way back if the restore fails.

The steps run in the `deploy/` directory you restore in: the deployment's
own or, to go back from a bundle, the previous release's beside it.
Setting aside is a rename and takes no space, but the restore needs room
for the restored data next to the set-aside data (`sudo du -sh
/srv/easyrmm` shows how much).

1. Stop the deployment, in the `deploy/` directory it runs from:

   ```bash
   sudo docker compose down
   sudo docker compose ps -a    # lists nothing
   ```

   Never `down -v`, which removes volumes too: the restore needs only the
   containers gone. `down` lets PostgreSQL shut down cleanly, so the
   set-aside database starts again as it stopped.

2. Set aside the data root, and `.env` in the directory you restore in,
   under one timestamp:

   ```bash
   cd /path/to/easyrmm/deploy    # the directory you restore in
   aside=$(date -u +%Y%m%dT%H%M%SZ)
   sudo mv /srv/easyrmm /srv/easyrmm.before-restore-$aside
   sudo mv .env .env.before-restore-$aside
   echo $aside                   # the way back needs it
   ```

   A rename keeps every file with its owner and mode. Never delete the
   set-aside data root or `.env` during the restore. Together they are the
   whole deployment, encryption key included: protect them as you protect
   backups.

   If `/srv/easyrmm` is a mount point of its own (`mountpoint
   /srv/easyrmm` says so), it cannot be renamed. Set aside what it holds
   instead, into a directory on the same file system:

   ```bash
   sudo mkdir /srv/easyrmm/before-restore-$aside
   sudo find /srv/easyrmm -mindepth 1 -maxdepth 1 ! -name '*-restore-*' \
       -exec mv -t /srv/easyrmm/before-restore-$aside {} +
   ```

3. Restore as in [Restore onto a new host](#restore-onto-a-new-host),
   from restoring the files in step 1, in the same directory, with the
   release files the backup was made with. With `manual` TLS and the
   certificate files in the data root (`/srv/easyrmm/tls`), they went
   aside with it; copy them back if they are still current. Everything
   done after the backup is lost.

4. If the restore fails, put the set-aside deployment back, in the
   directory you restored in:

   ```bash
   sudo docker compose down
   sudo mv /srv/easyrmm /srv/easyrmm.failed-restore-$aside
   sudo mv .env .env.failed-restore-$aside
   sudo mv /srv/easyrmm.before-restore-$aside /srv/easyrmm
   sudo mv .env.before-restore-$aside .env
   ```

   With a mount point, in place of the two `mv` of `/srv/easyrmm`:

   ```bash
   sudo mkdir /srv/easyrmm/failed-restore-$aside
   sudo find /srv/easyrmm -mindepth 1 -maxdepth 1 ! -name '*-restore-*' \
       -exec mv -t /srv/easyrmm/failed-restore-$aside {} +
   sudo find /srv/easyrmm/before-restore-$aside -mindepth 1 -maxdepth 1 \
       -exec mv -t /srv/easyrmm {} +
   sudo rmdir /srv/easyrmm/before-restore-$aside
   ```

   Then start it with the release files it ran with. If you restored with
   an earlier release's, first `git checkout` the tag it ran (from a
   clone), or change to its own `deploy/` directory (from a bundle):

   ```bash
   sudo docker compose up -d
   ```

   It starts as it stopped in step 1, with the same database and `.env`.
   Keep the failed restore to find out what went wrong.

5. Once the restored deployment works and you will not go back, delete
   the set-aside data root and `.env`:

   ```bash
   sudo rm -rf /srv/easyrmm.before-restore-<timestamp>
   # With a mount point: sudo rm -rf /srv/easyrmm/before-restore-<timestamp>
   sudo rm .env.before-restore-<timestamp>
   ```
