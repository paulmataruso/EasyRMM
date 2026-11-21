# Upgrading EasyRMM

Each release is a version tag (`easyrmm-v1.2.3`), a server image
(`ghcr.io/paulmataruso/easyrmm-server:1.2.3`) and a deployment bundle
(`easyrmm-v1.2.3-deploy.tar.gz`) on the GitHub release page. The bundle
holds the Compose file, `setup.sh` and the files they use, in the
repository's layout. An installation from a clone and one from a bundle
upgrade the same way.

## With the updater

On a host where `setup.sh` installed the [updater](updater.md):

```bash
sudo easyrmm-updater check             # what the channel offers, verified
sudo easyrmm-updater upgrade           # the newest; or: upgrade v1.2.3
sudo easyrmm-updater status
```

It verifies the release, backs up, upgrades and checks as this page does
by hand, and when the new version does not start it brings the previous
one back by itself. `sudo easyrmm-updater rollback` undoes a confirmed
upgrade within 24 hours. Read the release notes and decide how agents
follow first, as [below](#before-you-start); the updater takes its own
backup.

The rest of this page is the manual upgrade. Run as root, its `setup.sh`
installs the updater on a host that lacks it.

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
git checkout easyrmm-v1.2.3
make updater    # optional, needs Go: setup.sh then installs the updater
cd deploy
```

From a bundle, unpack it as root into a directory only root can write,
such as `/opt/easyrmm`, where the [host updater](updater.md) unpacks its
own, and bring the old `.env` across. Everything in a bundle is root's;
`setup.sh` and Compose run from it as root, so no one else may change it:

```bash
sudo install -d -m 0755 /opt/easyrmm
sudo tar -xzf easyrmm-v1.2.3-deploy.tar.gz -C /opt/easyrmm
sudo cp -p /path/to/easyrmm-v1.2.2/deploy/.env /opt/easyrmm/easyrmm-v1.2.3/deploy/.env
cd /opt/easyrmm/easyrmm-v1.2.3/deploy
```

Then, in `deploy/`:

```bash
sudo ./scripts/setup.sh --upgrade
sudo docker compose pull
sudo docker compose up -d
```

`setup.sh --upgrade` takes every setting from `.env`, so the options you
installed with are not given again and nothing is asked. It keeps `.env`'s
values and secrets, adds secrets the release needs, gives the data
directories, under `.env`'s data root, the owners the release expects, and
issues no Authentik invitation. From a bundle it sets `EASYRMM_VERSION` to
the release's server image; from a clone it leaves it, so set it to the
release you checked out:

```bash
sudo sed -i 's/^EASYRMM_VERSION=.*/EASYRMM_VERSION=1.2.3/' .env
```

It lists settings `.env.example` has that `.env` lacks; copy any you need.

The Compose project is named `easyrmm` whatever the directory, so
`up -d` replaces the running containers. A bundle's `docker-compose.yml`
names the patching engine built for that release, by digest, so the same
`pull` and `up -d` upgrade it too; its database migrations run before it starts
(`easypatch-migrate`). From a clone, `docker compose up -d --build` builds the
engine from the checked-out `easypatch/`. When the server starts, it:
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
about 5 minutes (agents report every minute, but one that could not reach
the server waits up to 5 minutes before it tries again), and that the
audit chain verifies (`GET /api/v1/audit/verify` as a Super
Administrator). The upgrade's downtime raises no offline alert: offline
policies count every device as seen until 5 minutes after the server
starts ([Alerts](alerts.md#restarts-and-upgrades)). If you held agents back, update a few from their device
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
