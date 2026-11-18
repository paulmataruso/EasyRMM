# Upgrading EasyRMM

Each release is a version tag (`v1.2.3`), a server image
(`ghcr.io/paulmataruso/easyrmm-server:1.2.3`) and a deployment bundle
(`easyrmm-v1.2.3-deploy.tar.gz`) on the GitHub release page. The bundle
holds the Compose file, `setup.sh` and the files they use, in the
repository's layout. An installation from a clone and one from a bundle
upgrade the same way.

## Before you start

1. **Read the release notes**, the release's section of `CHANGELOG.md`.
   Look for *Security*, *Removed*, and new settings for `.env`.
2. **Back up**, as in [Backup and restore](backup-restore.md). The server
   applies database migrations when it starts, and only forward. To go back
   to the previous release you restore this backup.
3. **Decide how agents follow.** The new server image carries new agent
   builds, and by default every agent updates itself, a few at a time. To
   try the release on a few devices first, set **Settings → Agent updates**
   to **When asked** before upgrading. See
   [Updating agents](../deployment/agents.md#updating-agents).

## Upgrade

From a clone:

```bash
cd /path/to/easyrmm
git fetch --tags
git checkout v1.2.3
cd deploy
```

From a bundle, unpack it beside the old one and bring the old `.env`
across:

```bash
tar -xzf easyrmm-v1.2.3-deploy.tar.gz
cp easyrmm-v1.2.2/deploy/.env easyrmm-v1.2.3/deploy/.env
cd easyrmm-v1.2.3/deploy
```

Then, in `deploy/`:

```bash
# Settings this release adds; copy any you need into .env.
comm -13 <(grep -o '^[A-Z0-9_]*=' .env | sort) <(grep -o '^[A-Z0-9_]*=' .env.example | sort)

# Run this release's image.
sudo sed -i 's/^EASYRMM_VERSION=.*/EASYRMM_VERSION=1.2.3/' .env

# setup.sh with the options you installed with. It keeps .env, and gives
# the data directories the owners this release expects.
sudo ./scripts/setup.sh --hostname rmm.example.com ...

sudo docker compose pull
sudo docker compose up -d
```

The Compose project is named `easyrmm` whatever the directory, so
`up -d` replaces the running containers. When the server starts, it:
1. applies the release's database migrations, under a lock, before it
   serves anything;
2. rewrites MeshCentral's configuration;
3. starts serving the new agent builds.

## Check

```bash
sudo docker compose ps                                   # every container healthy
sudo docker compose exec server easyrmm-server version   # 1.2.3
sudo docker compose logs --since 10m server | grep -i error
```

Then sign in. Check that every device's last-seen time has moved on within
a couple of minutes (agents report every minute), and that the audit chain
verifies (`GET /api/v1/audit/verify` as a Super
Administrator). If you held agents back, update a few from their device
pages, watch them on **Settings → Agent updates**, then switch back to
**Automatically**.

## Going back

Migrations do not run backwards, so the previous release cannot run on the
upgraded database:
1. Stop the stack: `sudo docker compose down`.
2. Restore the backup from before the upgrade with the previous release's
   files, as in [Backup and restore](backup-restore.md#restore-onto-a-new-host).
   Everything done after the backup is lost.

Agents that already updated keep the new build until the server tells them
otherwise. With **Automatically**, the restored server puts its own build
back on them.
