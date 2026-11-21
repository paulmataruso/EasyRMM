# The host updater

`easyrmm-updater` upgrades a Docker deployment of EasyRMM to a verified
build and rolls it back, on the host, as root
([ADR-0052](../architecture/adr/0052-the-host-updater.md)). It does what
the [manual upgrade](upgrading.md) does: back up, set up the new bundle
with `setup.sh --upgrade`, and start it with Compose. It does that only
after Sigstore has verified that this repository's release workflow, or CI
on `main`, built what it installs.

Nothing runs between attempts. An attempt is `easyrmm-updater upgrade` run
by hand, or the hourly timer when automatic upgrades are on.

## Installing it

`setup.sh`, run as root, installs it, at install and at each manual
upgrade:

* `/usr/local/sbin/easyrmm-updater`, from `deploy/updater/`. A release's
  bundle carries it for x86-64 and ARM64; a Git clone builds it first with
  `make updater` (Go needed);
* `easyrmm-updater.service` and `easyrmm-updater.timer` in
  `/etc/systemd/system`, the timer enabled;
* `/etc/easyrmm/updater.conf`, naming this deployment. An existing one
  keeps every other setting.

`--no-updater` installs none of it. `--auto-upgrade` turns automatic
upgrades on. Without root, or on a host without systemd, `setup.sh` says so
and installs nothing. Existing installs get the updater with their next
manual upgrade.

The updater refuses Docker's user namespace remapping and rootless Docker.

## Configuration

`/etc/easyrmm/updater.conf`, root's, mode 600. The server never writes it.
The updater rewrites only its `deployment` line, when an upgrade or a
rollback moves the deployment to another directory.

```ini
# The deploy/ directory of the running version.
deployment = /opt/easyrmm/easyrmm-v1.2.3/deploy
# stable (full releases), pre-release (also release candidates) or edge
# (also builds of main, for test instances).
channel = stable
# The hourly timer upgrades to the newest version of the channel, in the
# hours given (the host's time zone, from-to: 2-5 is 02:00 to 05:00).
auto_upgrade = no
auto_upgrade_hours = 2-5
backup_dir = /var/backups/easyrmm-updater
```

A version outside the channel is refused, whoever asks. Automatic upgrades
are meant for test instances on the edge channel. Production installs
upgrade when someone chooses to.

## Commands

Run as root:

| Command | What it does |
|---|---|
| `easyrmm-updater status` | The running version, the last attempt and its result, the rollback on offer and what it would lose, the backups |
| `easyrmm-updater check` | What the channel offers, and its newest version verified. Changes nothing |
| `easyrmm-updater upgrade` | Upgrades to the newest version of the channel |
| `easyrmm-updater upgrade v1.2.4` | Upgrades to that version. Never to a lower one |
| `easyrmm-updater rollback` | Rolls the last confirmed upgrade back, within 24 hours, after you confirm what it loses (`--yes` confirms without a terminal) |
| `easyrmm-updater version` | The updater's version |

`--config FILE` reads another configuration. Each attempt is logged to the
journal: `journalctl -t easyrmm-updater` for attempts run by hand,
`journalctl -u easyrmm-updater` for the timer's.

Automatic upgrades skip a version that failed or was rolled back until a
newer one appears. Asked for by name, it is tried again.

## An upgrade

1. **Check.** The new version's manifest is verified against its
   attestation ([below](#verification)), then the bundle against the
   manifest's SHA-256. The host needs room for a copy of the data root and
   2 GiB for the new images, and PostgreSQL's major version must be the
   one the data root holds. A release that changes it says so, and is
   upgraded by hand.
2. **Pull** the new images by digest while the running version serves.
3. **Stop** every service. The downtime starts.
4. **Back up** the data root, the deployment directory (with `.env`) and
   `updater.conf` ([below](#backups)).
5. **Set up.** The bundle is unpacked beside the running one, `.env` is
   carried across with the server named by the manifest's tag and digest,
   and the new `setup.sh --upgrade --no-updater` runs. `docker compose
   config --images` must list exactly the manifest's images.
6. **Start held.** The updater writes the `hold` file, so the server
   answers its health check and nothing else
   ([ADR-0052](../architecture/adr/0052-the-host-updater.md#what-the-server-sees-and-can-ask)).
   Every service but the patching engine's worker starts and turns
   healthy, within 20 minutes. The server must be ready on its loopback
   health port and report the new version.
7. **Confirm.** The engine's automatic agent updates are held for 24
   hours, its worker starts, and `hold` is removed. The downtime ends.
   The updater replaces itself with the bundle's, and removes bundle
   directories other than the running and the previous, with their
   `.env`.

The downtime is a backup and a start: minutes on a typical install. Offline
alerts do not fire for it
([ADR-0052](../architecture/adr/0052-the-host-updater.md#downtime-and-alerts)).

A failure before step 3 changes nothing that runs. A failure to reach the
network, the registry or room on a disk is tried again at the next attempt;
any other failure marks the version failed.

A failure from step 3 on brings the previous version back. Before the
backup, the previous version starts again as it was. After it, the updater
restores the backup:
1. every service stops;
2. PostgreSQL starts alone, and the failed database's highest audit ID and
   chain head are read (if it does not start, they are recorded as
   unknown, and the audit IDs skip a million);
3. the failed data root is moved aside, as `.failed-<time>-<version>` in
   the data root, root's, mode 700, until the next successful upgrade, and
   the backup is copied in;
4. the previous deployment directory comes back;
5. PostgreSQL starts alone again. The audit ID sequence moves past every
   ID the failed version wrote, and a `updater.rolled_back` audit record
   names the discarded version and its chain head;
6. everything starts.

Nothing agents, the console or the engine's worker would write was written
by the failed version: it was held, and its worker had not started. The
restore contacts no agent.

## Rolling back after an upgrade

For 24 hours after a confirmed upgrade, `easyrmm-updater rollback` restores
that upgrade's backup the same way. Everything written since is lost:
`status` and `rollback` say what (devices enrolled since, which must enroll
again; jobs; audit records), and `rollback` asks you to type `yes`. The
engine's agents are not ahead of the restored engine, since its automatic
agent updates were held for those 24 hours (unless someone updated one by
hand). EasyRMM's agents move to the restored server's build as to any
build. The updater keeps its own, newer, version.

Audit collectors may receive records again, with the same IDs and contents:
forwarding resumes from the backup's position. Records of the discarded
version keep IDs that no later record reuses.

## Backups

Each upgrade takes one in `backup_dir` (root's, mode 700), and the last two
are kept. Each is a directory named by its time and version, for example
`20261121T030512Z-v1.2.3/`:

| Entry | What |
|---|---|
| `data/` | The whole data root, with owners and modes (reflinks where the filesystem has them), less the updater's own `updater/` and failed data roots |
| `tree/deploy/`, `tree/docker/` | The deployment directory, `.env` with it, and the files Compose mounts |
| `updater.conf` | The updater's configuration |
| `backup.json` | The version, the deployment directory, the data root and the time. Written last: a backup without it is incomplete |

A backup holds `.env`, and with it the key that encrypts the database's
secrets. Keep `backup_dir` on the host's own disks, root's alone.

To put one back by hand, for example when the updater cannot:

```bash
cd /path/to/deploy && sudo docker compose stop     # every service
sudo mv /srv/easyrmm /srv/easyrmm.broken           # the data root
sudo cp -a /var/backups/easyrmm-updater/<backup>/data /srv/easyrmm
sudo cp -a /var/backups/easyrmm-updater/<backup>/tree/. /path/to/easyrmm-<version>/
cd /path/to/easyrmm-<version>/deploy && sudo docker compose up -d
```

`backup.json` names the version, the deployment directory and the data
root. Set `deployment` in `updater.conf` back to that directory.

## Status

The updater writes `<data root>/updater/status/`, root's, mode 755, which
the server and the engine's worker mount read-only at `/run/easyrmm-updater`:

| File | What |
|---|---|
| `status.json` | `running`, `previous`, `channel`, the last `attempt` (`action`, `by`, `from`, `to`, `step`, `result`: `running`, `succeeded`, `failed`, `rolled-back` or `rollback-failed`, and `reason`), the `rollback` on offer (`to`, `since`, `until`) and `updated` |
| `hold` | While it exists the server is held |
| `agent-updates-held-until` | One RFC 3339 time: until then the engine starts no automatic agent update |

Its own state is in `/var/lib/easyrmm-updater` (root's, mode 700).

## Verification

Before anything changes, with Sigstore's public-good instance (its root
fetched through TUF and cached in `/var/lib/easyrmm-updater/tuf`), the
manifest's attestation must have been signed for the manifest's SHA-256
with a certificate that:
* GitHub Actions' issuer obtained, for this repository by its numeric ID,
  on a GitHub-hosted runner, for a push;
* names `release.yml` at the tag of the manifest's version, for a
  release; `ci.yml` on `main`, for an edge build (on the edge channel
  only);
* was issued for the manifest's commit.

Then the bundle must match the manifest's SHA-256, and the images the
deployment runs must be exactly the manifest's, by digest.
[Edge builds and the release manifest](../architecture/edge-manifest.md)
has the details. Releases come from their GitHub release, edge builds from
`ghcr.io/paulmataruso/easyrmm-deploy`.

## Removing it

```bash
sudo systemctl disable --now easyrmm-updater.timer
sudo rm /etc/systemd/system/easyrmm-updater.service /etc/systemd/system/easyrmm-updater.timer \
  /usr/local/sbin/easyrmm-updater /etc/easyrmm/updater.conf
sudo systemctl daemon-reload
```

The deployment keeps running. Remove `/var/lib/easyrmm-updater` and the
backups when you no longer need them.

## Test builds

The updater's tests build it with the Go build tag `updatertest`. Such a
build trusts `/etc/easyrmm/updater-test/trusted-root.json` instead of
Sigstore's, and reads versions from `/var/lib/easyrmm-updater-test/releases`,
and its `version` says so. `bundle.sh` refuses to put one in a bundle.
