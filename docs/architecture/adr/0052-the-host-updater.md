# ADR-0052: Upgrading EasyRMM with an updater on the host

* Status: Accepted (2026-11-21). Not implemented yet.
* Builds on: [releasing](../../development/releasing.md) (releases, their
  attestations and manifest), [ADR-0027](0027-agent-updates.md) (agent
  updates) and the Docker deployment
  ([docs/deployment/docker.md](../../deployment/docker.md)).
* Part of [the feature plan](../feature-plan.md): F3 and feature 4.

## Context
An upgrade is run by hand on the server
([upgrading.md](../../operations/upgrading.md)): back up, download the
release's bundle and check it against `SHA256SUMS`, carry `.env` across,
run the new `setup.sh` with the install's options, `docker compose pull`
and `up -d`. Going back means restoring the backup by hand. Operators want
the console to do this, and test instances should follow `main` without
anyone logging in.

What exists:

* **The server cannot do it.** It runs in a read-only container without
  the Docker socket; giving it the socket would give whoever controls the
  server root on the host. Something on the host has to run Compose.
* **Releases are attested.** `release.yml` attaches the deployment
  bundle, the manifest (the commit, and the server's and the engine's
  images by digest), the agents and `SHA256SUMS` to a GitHub release, each
  with a build provenance attestation signed through Sigstore for the
  release workflow at the release's tag.
* **`main` builds are published but not installable.** `docker-build.yml`
  pushes `easyrmm-server:edge` and `:sha-<commit>` with an attestation,
  versioned `edge-<commit>`, which does not sort against releases; there
  is no bundle or manifest for them. The engine is built only by a
  release (its agent packages are signed with the release key).
* **No maintenance mode**: during an upgrade agents keep calling and the
  console keeps writing until the server stops.
* **Two agent rollouts.** EasyRMM's server hands its agent build to
  agents (ADR-0027); the engine updates its agents by itself where a
  policy has `AgentAutoUpdateEnabled`. An upgrade that is then rolled
  back would leave agents on a version the server no longer serves.

## Decision

### The updater
* **`easyrmm-updater`**, a static Go program in the bundle, installed by
  `setup.sh` as `/usr/local/sbin/easyrmm-updater` with three systemd
  units: `easyrmm-updater.path` (watches the request directory),
  `easyrmm-updater.service` (one attempt, `Type=oneshot`) and
  `easyrmm-updater.timer` (hourly; acts only when automatic upgrades are
  on). Nothing runs between attempts. It runs as root, as the manual
  upgrade does.
* **Its configuration**, `/etc/easyrmm/updater.conf` (root, 0600), is
  written by `setup.sh`: the deployment directory, the data root, the
  channel, whether to upgrade automatically and in which hours, and the
  `setup.sh` options the install was made with (one-time options, such as
  `--admin-email` and `--new-invitation`, are not kept). The server never
  writes it, and a request cannot change it.
* **Existing installs** get the updater with their next manual upgrade,
  which runs the new `setup.sh`. Installs from a Git clone install it with
  `setup.sh` as well; the guide says how.
* **Commands**: `easyrmm-updater status`, `check` (what the channel
  offers, verified, changing nothing), `upgrade [version]`, `rollback`.

### Channels and versions
* **stable** takes full releases; **pre-release** also release
  candidates; **edge** also builds of `main`. A version outside the
  configured channel is refused, whoever asks.
* **Edge versions sort.** An edge build is named after the last release
  `R` and the CI run: `R.edge.<run>` when `R` is a pre-release
  (`1.0.0-rc.4.edge.412`, above `1.0.0-rc.4` and below `1.0.0-rc.5`), and
  `<R with its patch raised>-edge.<run>` when `R` is a full release
  (`1.0.1-edge.415` after `1.0.0`). The feature plan's example,
  `1.0.0-rc.5-edge.412`, would sort above `1.0.0-rc.5`: semantic
  versioning ranks the identifier `5-edge` above `5`.
* **Never down**, except a rollback to the version the updater itself
  recorded as the previous one.

### Where builds come from
* **Every bundle is an OCI artifact** in the registry,
  `ghcr.io/paulmataruso/easyrmm-deploy:<version>`: the deployment bundle
  and the manifest. Releases push it beside their GitHub release; `main`
  pushes it for every build that passed the whole CI (publishing waits
  for every job, not only the image build). The updater has one path to
  fetch and verify, for both. The GitHub release stays for people.
* **The manifest** names, by digest, the server image and the engine
  image (for edge builds, the last release's engine, which only a release
  can build: engine changes reach test instances with a release), the
  databases the release uses (`easyrmm`, `easypatch`, `authentik` when it
  runs; later the logs database), the release it can roll back to, and
  whether that release runs on this release's schema (below).
* **Verification**, before anything changes: the artifact's attestation
  with sigstore-go (Sigstore's public-good instance through TUF: the
  embedded root only to start, the rest fetched, checked and cached), for
  the issuer `https://token.actions.githubusercontent.com`, this
  repository by its numeric ID (built into the updater), and the exact
  workflow: `release.yml` at `refs/tags/easyrmm-v<version>`, or, on the
  edge channel only, `docker-build.yml` at `refs/heads/main` run by a
  push. Then the bundle and manifest by their digests, and the images
  pulled by the digests in the verified manifest. An artifact that fails
  any check is not used, and the attempt ends with the reason.

### What the server can do
The server can ask; the updater decides.

* **Requests** (feature 4b): the server writes one file into
  `/srv/easyrmm/updater/requests/`, the only updater directory it can
  write: `{"id", "action": "upgrade"|"rollback", "version", "by"}`. The
  updater opens it without following links, accepts only a regular file
  owned by the server's user, under 1 KiB, with a version of the strict
  form above, and removes it whatever happens. One attempt at a time, at
  most one an hour; requests while one runs are refused.
* **What the updater says**: `/srv/easyrmm/updater/status/` belongs to
  root and is mounted read-only into the server: the attempt (its step,
  its result, the reason it failed), the running and the previous
  version, whether **Roll back** is possible and until when, and two
  switches the server obeys:
  * `maintenance`: agents are answered `503` with `Retry-After` (they
    back off as after any failure), the console is read-only (writes get
    `503 maintenance` and a banner says why), and the server's background
    work pauses;
  * `hold-agent-updates`: the server hands out no agent build, and asks
    the engine to stop its automatic agent updates until the switch is
    gone (the engine gains that setting, in a release).
* **The server's own user.** The server runs as a user of its own, apart
  from MeshCentral's, so that MeshCentral cannot write requests.

### An upgrade
1. Verify (above). Check the host: free disk space for a backup and the
   new images, Docker and Compose answering.
2. **Maintenance and hold**: write `maintenance` and
   `hold-agent-updates`; wait until the server says it is idle (no
   request in flight, background work paused), at most two minutes. A
   server from before this ADR has no maintenance mode and is stopped
   for the backup instead.
3. **Back up** every store into `/var/backups/easyrmm/<time>/` (root,
   0700): each database the running release's manifest lists, `.env`,
   the ACME cache, the engine's keys, `tls/`, and MeshCentral's data with
   MeshCentral stopped. Each dump must list with `pg_restore --list`
   before anything changes. The last three backups are kept.
4. Record the audit log's highest ID and its chain's head.
5. **Upgrade**: unpack the verified bundle beside the current one, carry
   `.env` across, run the new `setup.sh` with the recorded options, pull
   by digest, `docker compose up -d`.
6. **Check** within 10 minutes: the server reports the new version and is
   healthy, migrations ran, the engine answers.
7. **Confirm**: remove `maintenance`, then `hold-agent-updates`; agents
   update to the new builds. If the bundle carries a newer updater, it
   replaces this one, from the verified bundle only.

### Rollback
* **During an upgrade** (any failure before step 7): the previous bundle
  and images, every store restored from the backup taken in step 3.
  Nothing written since is lost: the server was in maintenance. Audit
  collectors tell records apart by ID, and the new server may have
  written some before it failed, so after the restore the ID sequence is
  moved past the highest ID recorded or written, and the rollback is the
  next record, naming the head it replaces. Refused across a job key
  rotation's cut-over (ADR to come, plan F0).
* **After a confirmed upgrade**, **Roll back** restores no data: it runs
  the previous release's code on the current databases. That works only
  if the previous server accepts the newer schema, so migrations follow
  expand then contract: a release only adds; a later release removes what
  an earlier one stopped using. Each manifest says whether the release
  before it runs on its schema. **Roll back** is offered for 24 hours, and
  only when it does.

### Seeing it
`easyrmm-updater status` on the host; journald for each attempt. The
console polls through the restart and shows the step (4b); until then it
shows a banner when an upgrade failed or was rolled back, from the status
directory. The guide has the manual recovery: the backup's location and
the restore steps of [backup-restore.md](../../operations/backup-restore.md).

### Automatic upgrades
Off unless `setup.sh --auto-upgrade` (or the configuration) turns them on,
for the hours configured. Meant for test instances on the edge channel:
each passed build of `main` arrives within the hour. Production installs
upgrade when someone chooses to.

## Testing
* **Verification** against real published artifacts: the latest release
  and an edge build accepted; a tampered bundle, a manifest from another
  build, another workflow's identity, an edge build on the pre-release
  channel, and a lower version refused.
* **The whole upgrade on CI's runner**, a throwaway machine with systemd
  and root where the bundle test already runs Compose: install the latest
  release, install the pull request's updater, upgrade to the newest edge
  build with verification on, and check it; then again with a migration
  made to fail, and check the rollback: the stores, the audit IDs and the
  chain. A job of its own, with a 60-minute limit; run locally, the test
  removes its units and files when it ends.
* **The request directory**: links, other owners, oversized files, bad
  versions, downgrades and versions outside the channel refused.
* The updater installed onto an existing deployment by a manual upgrade;
  from the second release with an updater, the updater updating itself.
* Then the owner's test instance on the edge channel.

## Consequences
* An operator upgrades and rolls back from the console (4b), or with one
  command on the host (4a); a test instance follows `main` within an hour.
* What runs as root on the host is what an operator ran by hand before:
  the release's own `setup.sh` and Compose, now only after Sigstore
  verification for this repository's release workflow.
* The server gains a maintenance mode, a hold on agent updates and a user
  of its own; the engine gains a hold on its automatic agent updates, in
  a release.
* Migrations must be expand then contract from the first release with the
  updater, and must never be edited once merged, since edge instances have
  run them.
* Edge instances run the last release's engine until the next release.
