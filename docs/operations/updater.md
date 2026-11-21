# The host updater

`easyrmm-updater` upgrades a Docker deployment of EasyRMM to a verified
build and rolls it back, on the host, as root
([ADR-0052](../architecture/adr/0052-the-host-updater.md)). It does what
the [manual upgrade](upgrading.md) does: back up, set up the new bundle
with `setup.sh --upgrade`, and start it with Compose. It does that only
after Sigstore has verified that this repository's release workflow, or CI
on `main`, built what it installs.

Nothing runs between attempts. An attempt is `easyrmm-updater upgrade` run
by hand, or the timer's run, every hour and five minutes after the host
starts, which upgrades only when automatic upgrades are on. Every run
first finishes what an earlier one left
([below](#interrupted-attempts)).

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
manual upgrade. While an attempt runs, `setup.sh` installs none of it
either, and says so: it takes the updater's lock
(`/var/lib/easyrmm-updater/lock`) first. Run it again once the attempt has
ended.

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
| `easyrmm-updater upgrade --deployment-repaired`, `rollback --deployment-repaired` | After an attempt whose rollback failed, once you have repaired the deployment by hand ([below](#when-a-rollback-fails)): the updater acts again |

`--config FILE` reads another configuration. Each attempt is logged to the
journal: `journalctl -t easyrmm-updater` for attempts run by hand,
`journalctl -u easyrmm-updater` for the timer's.

Ctrl-C, or `systemctl stop` for the timer's run, ends an attempt that has
not yet stopped the deployment (step 3 below), with nothing changed. Once
it has, the attempt runs on to its end, or brings the previous version
back; systemd allows it 45 minutes.

An upgrade without a version, automatic or by hand, skips a version that
failed or was rolled back until a newer one appears. Asked for by name, it
is tried again.

## An upgrade

1. **Check.** The new version's manifest is verified against its
   attestation ([below](#verification)), then the bundle against the
   manifest's SHA-256. PostgreSQL's major version must be the one the data
   root holds. A release that changes it says so, and is upgraded by hand.
   The deployment must run the version's required upgrade stop, if it has
   one ([below](#required-upgrade-stops)). The host must be as the updater
   needs it:
   * the data root Compose mounts is the one `.env` names, and it holds
     no links or mount points ([below](#the-data-root));
   * `/opt/easyrmm`, where the updater unpacks bundles, and every
     directory above it, can be written only by root;
   * each disk has room for all that goes on it: the backup (a copy of the
     data root and the deployment directory), a restore's copy of the data
     root, 2 GiB for the new images, and 256 MiB for the bundle's download
     and its unpacking. Where they share a disk, it needs the sum.
2. **Pull** the new images by digest while the running version serves.
3. **Stop** every service. The downtime starts.
4. **Back up** the data root, the deployment directory (with `.env`) and
   `updater.conf` ([below](#backups)). A backup that fails is removed.
5. **Set up.** The bundle is unpacked into `/opt/easyrmm` (root's, mode
   755), `.env` is carried across with the server named by the manifest's
   tag and digest, and the new `setup.sh --upgrade --no-updater` runs.
   `docker compose config --images` must list exactly the manifest's
   images.
6. **Start held.** The updater writes the `hold` file, so the server
   answers its health check and nothing else
   ([ADR-0052](../architecture/adr/0052-the-host-updater.md#what-the-server-sees-and-can-ask)).
   Every service but the patching engine's worker starts and turns
   healthy, within 20 minutes. The server must be ready on its loopback
   health port and report the new version.
7. **Confirm.** The engine's automatic agent updates are held for 24
   hours and its worker starts. The updater records the new deployment in
   `updater.conf` and its own state, and only then removes `hold`. The
   downtime ends. The updater replaces itself with the bundle's; if it
   cannot, `status` says so, and the next run installs it from the running
   version's bundle. Then it tidies:
   * a bundle directory it unpacked itself, other than the running and the
     previous, goes whole;
   * of any other directory a deployment ran from (one you unpacked, or a
     Git clone), only `deploy/.env` goes, since it holds the key. The rest
     is yours to remove;
   * nothing that holds the data root, `backup_dir`, the updater's state
     or its configuration is removed.

The downtime is a backup and a start: minutes on a typical install. Offline
alerts do not fire for it
([ADR-0052](../architecture/adr/0052-the-host-updater.md#downtime-and-alerts)).

A failure before step 3 changes nothing that runs. These are tried again
at the next attempt: failing to reach the network or the registry, a disk
without room (also one that fills during the backup), the host not as step
1 needs it, and a stop asked for before step 3. Any other failure marks the
version failed.

The version that runs is the highest of three: the one the server reports,
the one the deployment's `.env` names, and the one the updater last
brought up. The server cannot change `.env`. When the server's version and
`.env`'s disagree, the updater does nothing until they agree again. When
both differ from the updater's record, the deployment was changed by hand,
and the updater takes their word.

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

### Interrupted attempts

The updater records each attempt's step, deployment, data root, new
deployment directory and backup in `/var/lib/easyrmm-updater/state.json`
as soon as each exists. When its process ends before the attempt does
(killed by the out-of-memory killer or systemd's stop timeout, a power
cut, a reboot), the next run finishes the attempt from that record, and
does nothing else. Run by hand, it says so; run the command again. The
timer's run five minutes after the host starts does it unattended:
* before step 3, the attempt ends failed, and nothing that runs changed;
* during steps 3 and 4, an incomplete backup is removed and the previous
  version starts again;
* after the backup, the backup is restored as above, and the new version
  is marked failed. A restore cut short is done again. The failed
  database's audit chain head is read only once: if the first restore did
  not get to read it, it is recorded as unknown.

An attempt cut short before step 5 does not count against the version.
Until the next run,
`status` says that no updater runs and the attempt did not end. A
confirmed upgrade cut short before `hold` was removed is restored, since
the updater did not record it; one cut short after that keeps running, and
the next run removes `hold` if it is still there.

### When a rollback fails

An attempt ends `rollback-failed` when the previous version could not be
brought back. The deployment may then be stopped, half restored, or
running the failed version. From then on the updater does nothing, by the
timer or by hand. It keeps every backup, until someone repairs the
deployment by hand and says so:
1. `easyrmm-updater status` names the attempt, its reason and its backup
   (in `state.json`, `attempt.backup`);
2. put the backup back by hand ([below](#backups)), or otherwise bring a
   version up that serves;
3. run `easyrmm-updater upgrade --deployment-repaired`, or `rollback
   --deployment-repaired`. The flag records who said the deployment is
   repaired, and when. The automatic run never takes it.

### Required upgrade stops

A version's manifest may name, in `upgradeFrom`, the lowest version a
deployment must already run before it installs this one: always a release
or a release candidate, never an edge build. The updater compares it with
the lowest of the versions it knows run: the server's, `.env`'s, its own
record of what it brought up, and its own version, which came with the
bundle the deployment was last set up from (a server image changed by hand
can be ahead of that). Below it, the version is refused at step 1, before
anything stops, and the refusal names the version to install first:

```text
v1.4.0 installs only over v1.2.0 or later, and v1.1.0 runs: install v1.2.0 first (easyrmm-updater upgrade v1.2.0)
```

A refusal for a stop does not mark the version failed: once the stop is
installed, it is taken. The version to install first is the lowest one
your channel offers at or above `upgradeFrom` and below the version that
needs it; on the stable channel, a full release rather than the release
candidate named, when there is one. Only when your channel offers none is
it another channel's, such as a release candidate on the stable channel,
which `easyrmm-updater upgrade` then takes by name. A stop's own stop is
followed the same way.

Automatic upgrades install the stop first, as a version of its own; the
next run, by the stop's own updater, goes on. They never go down to a stop
below the running server: when the server's image was changed by hand
past a stop its bundle never installed, the updater says so and the
deployment is upgraded by hand ([Upgrading](upgrading.md)). `check` names
the stop the newest version needs.

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
| `data/` | The whole data root, with owners and modes (reflinks where the filesystem has them), less the updater's own `updater/` and failed data roots. PostgreSQL's whole cluster is in it, copied stopped: EasyRMM's database, the engine's and, with `--with-authentik`, Authentik's |
| `tree/deploy/`, `tree/docker/` | The deployment directory, `.env` with it, and the files Compose mounts |
| `updater.conf` | The updater's configuration |
| `backup.json` | The version, the deployment directory, the data root and the time. Written last: a backup without it is incomplete |

Every copy, into a backup and back out of one, is then checked against
what it copied, entry by entry: type, mode, owner, a file's size and a
link's target. A copy that differs fails the upgrade or the restore.

That covers every volume in `deploy/docker-compose.yml` that holds state.
With Authentik that is its database, with its users, their second factors
and the key pair that signs EasyRMM's ID tokens, and its `authentik/data`,
`authentik/secrets` and `authentik/invitations` directories; a rollback
restores all of them with the rest. `setup.sh` puts `EASYRMM_TLS_DIR`
(`manual` TLS mode's certificate and key) in the data root, as `tls/`, so
a backup holds it too. Outside a backup are the updater's own status
directory, which it writes as it goes, and `EASYRMM_TLS_DIR` if you have
pointed it elsewhere: your own certificate and key, mounted read-only,
which an upgrade never changes. Back those up where you manage
certificates ([Backup and restore](backup-restore.md)).

These backups are for rolling an upgrade back on the same host, not a
replacement for [Backup and restore](backup-restore.md): they stay on the
host, and only the last two are kept.

A backup holds `.env`, and with it the key that encrypts the database's
secrets. Keep `backup_dir` on the host's own disks, root's alone.

To put one back by hand, for example when the updater cannot:

```bash
cd /path/to/deploy && sudo docker compose stop     # every service
sudo mv /srv/easyrmm /srv/easyrmm.broken           # the data root
sudo cp -a /var/backups/easyrmm-updater/<backup>/data /srv/easyrmm
sudo mv /srv/easyrmm.broken/updater /srv/easyrmm/  # the updater's status
sudo rm -f /srv/easyrmm/updater/status/hold        # or the server stays held
sudo cp -a /var/backups/easyrmm-updater/<backup>/tree/. /path/to/easyrmm-<version>/
cd /path/to/easyrmm-<version>/deploy && sudo docker compose up -d
```

`backup.json` names the version, the deployment directory and the data
root. Set `deployment` in `updater.conf` back to that directory. After an
attempt whose rollback failed, tell the updater with the next `upgrade` or
`rollback`, with `--deployment-repaired` ([above](#when-a-rollback-fails)).

## The data root

The updater backs up and restores the data root (`EASYRMM_DATA_ROOT`,
`/srv/easyrmm` by default) as one tree on one host. It refuses to upgrade,
before anything stops, when:
* an entry at its top (`postgres`, `server`, `meshcentral` and the others)
  is a link: a backup would copy the link, not what it leads to, and a
  restore would put the link back over the failed version's data;
* anything in it, at any depth, is a mount point (a disk, a network share,
  a bind mount): a restore cannot move it aside, and its copy would land
  on the disk below;
* the data root Compose mounts for the server is not the one `.env` names.

The data root itself may be a mount point, and links deeper in the tree,
which the services make themselves, are copied as links. To keep data on
another disk, mount that disk at the data root, or set
`EASYRMM_DATA_ROOT` to a directory on it, before installing.

## Status

The updater writes `<data root>/updater/status/`, root's, mode 755, which
the server and the engine's worker mount read-only at `/run/easyrmm-updater`:

| File | What |
|---|---|
| `status.json` | `running`, `previous`, `channel`, the last `attempt` (`action`, `by`, `from`, `to`, `step`, `result`: `running`, `succeeded`, `failed`, `rolled-back` or `rollback-failed`, a rollback asked for ending `rolled-back`, and `reason`; `warning`, when the updater could not replace itself; `repaired`, who said with `--deployment-repaired` that they repaired the deployment, and when; and what the attempt works on: `deployment`, `dataRoot`, `newDeploy`, `backup`), the `rollback` on offer (`to`, `since`, `until`) and `updated` |
| `hold` | While it exists the server is held |
| `agent-updates-held-until` | One RFC 3339 time: until then the engine starts no automatic agent update |

Its own state is in `/var/lib/easyrmm-updater` (root's, mode 700): the
same attempt record, in `state.json`, which the next run finishes an
interrupted attempt from, the bundle directories it unpacked, and `lock`,
which one attempt, or `setup.sh` installing the updater, holds at a time.

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
