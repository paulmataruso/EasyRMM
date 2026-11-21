# ADR-0052: Upgrading EasyRMM with an updater on the host

* Status: Accepted (2026-11-21, revised after review). Not implemented yet.
* Builds on: [releasing](../../development/releasing.md) (releases, their
  attestations and manifest), [ADR-0027](0027-agent-updates.md) (agent
  updates), [ADR-0044](0044-authentik-when-chosen.md) (Authentik's files)
  and the Docker deployment ([docker.md](../../deployment/docker.md)).
* Part of [the feature plan](../feature-plan.md): F3 and feature 4.

## Context
An upgrade is run by hand on the server
([upgrading.md](../../operations/upgrading.md)): back up, download the
release's bundle and check it against `SHA256SUMS`, carry `.env` across,
run the new `setup.sh` with the install's options again, set the new
version in `.env`, `docker compose pull` and `up -d`. Going back means
restoring the backup by hand. Operators want the console to do this, and
test instances should follow `main` without anyone logging in.

What exists, and what it means here:

* **The server cannot do it.** It runs in a read-only container without
  the Docker socket; giving it the socket would give whoever controls the
  server root on the host. Something on the host has to run Compose, as
  root, as the operator does now.
* **Releases are attested by file.** `release.yml` attests every file it
  attaches to a GitHub release (bundle, manifest, agents, `SHA256SUMS`) by
  its digest, for the release workflow at the release's tag. The manifest
  holds the commit and the server's and engine's images by digest, not
  the other images, the databases, or the bundle's digest. The release
  tag pattern accepts any pre-release suffix.
* **`main`'s builds are published early and are not installable.**
  `docker-build.yml`, called by `ci.yml`, pushes `easyrmm-server:edge` and
  `:sha-<commit>` once its own build and Compose smoke test pass, before
  the bundle, Authentik and contract tests; it builds the image again
  after the scan, so the pushed digest is not the scanned one. Their
  version, `edge-<commit>`, does not sort against releases, and there is
  no bundle or manifest for them. The engine is built only by a release
  (its agent packages are signed with the release key).
* **`main` is not protected** and no rule limits who can push a release
  tag: anyone who can push to `main` or push a tag can make a build the
  release workflow attests.
* **`setup.sh` takes the install's options again** at every upgrade; with
  Authentik and no terminal it needs `--admin-email`. Run as root, it
  wrote in a directory Authentik's setup container can write, through any
  link planted there (fixed before this ADR: it now writes Authentik's
  files where only root can and renames them into place).
* **Two agent rollouts.** EasyRMM's server moves every agent whose build
  differs to its own build, older ones included (ADR-0027). The engine's
  worker, every two minutes, moves agents only to newer packages, where a
  policy has `AgentAutoUpdateEnabled`.
* **Restarts raise offline alerts.** Offline policies can be as short as
  3 minutes, and agents back off for up to 5 minutes after failures; the
  engine marks endpoints offline after its threshold (10 minutes by
  default). Any stop of a few minutes, a manual upgrade included, raises
  offline alerts.

## Decision

### The updater
* **`easyrmm-updater`**, a static Go program in the bundle, installed as
  `/usr/local/sbin/easyrmm-updater` by `setup.sh` run as root (which says
  so plainly when it runs without root and installs nothing), with
  `easyrmm-updater.service` (one attempt, `Type=oneshot`),
  `easyrmm-updater.timer` (hourly; acts only when automatic upgrades are
  on) and, with feature 4b, `easyrmm-updater.path` (requests). Nothing
  runs between attempts. It refuses to run under Docker's user namespace
  remapping or rootless Docker, where the deployment's ownership is wrong
  anyway.
* **Its configuration**, `/etc/easyrmm/updater.conf` (root, 0600): the
  deployment directory, the channel, whether to upgrade automatically and
  in which hours, and where backups go. The server never writes it, and a
  request cannot change it.
* **`setup.sh --upgrade`** reads every setting from the existing `.env`,
  never prompts and issues no invitation. The updater runs it, and the
  manual upgrade guide uses it too, so no list of install options is kept
  anywhere.
* **Existing installs** get the updater with their next manual upgrade.
  Installs from a Git clone install it with `setup.sh` as well; the guide
  says how.
* **Commands**: `easyrmm-updater status`, `check` (what the channel
  offers, verified, changing nothing), `upgrade [version]`, `rollback`.

### Channels and versions
* **stable** takes full releases; **pre-release** also release
  candidates; **edge** also builds of `main`. A version outside the
  configured channel is refused, whoever asks.
* **Release tags** are only `easyrmm-vX.Y.Z` and `easyrmm-vX.Y.Z-rc.N`,
  and only on commits on `main`; `release.yml` refuses the rest.
* **Edge versions sort** and name one build. `R` is the highest release
  among the tags reachable from the commit (the job fetches every tag):
  * `R.edge.<run>.<attempt>` when `R` is a release candidate:
    `v1.0.0-rc.4.edge.412.1` sorts above `v1.0.0-rc.4` and below
    `v1.0.0-rc.5`;
  * `<R with its patch raised>-edge.<run>.<attempt>` when `R` is a full
    release: `v1.0.1-edge.415.1` sorts above `v1.0.0`, and below
    `v1.0.1-rc.1` (`edge` sorts before `rc`) and `v1.0.1`.

  `<run>` and `<attempt>` are the workflow's run number and attempt, so a
  run again is another version. (The plan's `1.0.0-rc.5-edge.412` would
  sort above `1.0.0-rc.5`: semantic versioning ranks `5-edge` above `5`.)
  Versions are written as the server reports them, with the `v`.
* **Never down**, except a rollback to the version the updater itself
  recorded as the previous one.
* **No retrying failures**: a version that failed or was rolled back is
  skipped by automatic upgrades until a newer one appears or an operator
  asks for it by name.

### What is published
* **Only what passed every test.** A build of `main` is published by a
  job at the end of `ci.yml` that needs every other job; the server image
  is built once, and the image the tests ran is pushed unchanged. Edge
  builds pair `main`'s server with the last release's engine, by its
  digest, so before publishing, the contract and bundle tests also run
  against that engine image.
* **The manifest** names the version, the commit, the bundle's SHA-256,
  every image the bundle runs by digest (EasyRMM's server, the engine,
  PostgreSQL, MeshCentral, Authentik), PostgreSQL's major version, and
  whether Authentik is part of the release.
* **Its attestation travels with it**: the Sigstore bundle of the
  manifest's attestation is published beside it
  (`<manifest>.sigstore.json`), so verification needs that file and
  Sigstore's trusted root, not GitHub's API.
* **Where**: releases on their GitHub release, as now, with the Sigstore
  bundle added. Edge builds as an OCI artifact,
  `ghcr.io/paulmataruso/easyrmm-deploy:<version>` (bundle, manifest, its
  Sigstore bundle), and the `edge` tag pointing at the newest, moved only
  after the test on `main` below passes. A scheduled workflow deletes edge
  artifacts and images older than 30 days.
* **Who can publish**: `main` is protected (changes by pull request, with
  the CI result required) and a ruleset limits release tags to the
  repository's administrators, before any updater trusts either.

### Verification
Before anything changes, with sigstore-go (Sigstore's public-good
instance through TUF: the embedded root only to start, the rest fetched,
checked and cached), the manifest's attestation must match every one of:

* the issuer `https://token.actions.githubusercontent.com`, this
  repository's numeric ID (built into the updater), and a GitHub-hosted
  runner;
* for a release: the certificate's identity and its build configuration
  both `.github/workflows/release.yml@refs/tags/easyrmm-v<version>`, the
  source ref that tag, triggered by a push;
* for an edge build, on the edge channel only: identity and build
  configuration both `.github/workflows/ci.yml@refs/heads/main`, the
  source ref `refs/heads/main`, triggered by a push;
* the source commit in the certificate equal to the manifest's commit.

The version is the verified manifest's, never a tag's or a file name's;
for a release it must also be the one in the certificate's tag. Then the
bundle by its SHA-256 from the manifest, the images pulled by the
manifest's digests, and `docker compose config --images` must list
exactly the manifest's images. Anything that fails a check is not used,
and the attempt ends with the reason.

### What the server sees and can ask
* **Status**: `<data root>/updater/status/` belongs to root and is
  mounted read-only into the server: the attempt (its step, its result,
  the reason it failed), the running and previous versions, whether
  **Roll back** is possible and until when, and **`hold`**.
* **`hold`**: while it exists, the server answers its health check and
  nothing else: the console, agents, the engine's agents through the
  edge, and Authentik's and MeshCentral's names get `503` with
  `Retry-After`. The server reads it before it opens its listeners, and
  follows it while it runs. Without the updater nothing is held.
* **Requests** (feature 4b): `<data root>/updater/requests/`, mounted
  read-write into the server only. A request is one file,
  `{"id", "action": "upgrade"|"rollback", "version", "by"}`. The updater
  opens each entry without following links and without blocking, accepts
  only a regular file owned by the server's user, reads at most 1 KiB
  from the same descriptor, and removes the entry it read; anything else
  in the directory is removed, without following links, so the path unit
  is not triggered again (its trigger limit is set too). A version must
  have one of the forms above. One upgrade at a time and at most one an
  hour; rollbacks and refused requests are not limited.

### An upgrade
1. **Check**: verify (above). The host has Docker and Compose, room for a
   copy of the data root and the new images; PostgreSQL's major version
   is unchanged (a release that changes it says so, and is upgraded by
   hand, by its guide).
2. **Pull** the new images by digest while the running version serves.
3. **Stop** every service, PostgreSQL last, so that it shuts down
   cleanly. The downtime starts.
4. **Back up**: a copy of the whole data root, the deployment directory
   (`.env` with it) and `updater.conf` into the backup directory (root,
   0700), with reflinks where the filesystem has them. The last two
   backups are kept.
5. **Set up**: the verified bundle unpacked beside the current one; `.env`
   carried across with `EASYRMM_VERSION` set to the server's tag and
   digest from the manifest; `hold` written; the new `setup.sh --upgrade`
   run, told not to install the updater.
6. **Start held**: `docker compose up -d --remove-orphans --wait`, every
   service but the engine's worker, within 20 minutes (longer than any
   service's start period); every service healthy and the server
   reporting the new version.
7. **Confirm**: the engine's worker started and healthy, with its
   automatic agent updates held for 24 hours; `hold` removed. The downtime
   ends. The updater replaces itself with the verified bundle's, and
   bundle directories other than the current and the previous are
   removed, with their `.env`, which holds the encryption key.

### Rollback
* **During an upgrade** (any failure after step 3): every service
  stopped. If PostgreSQL starts, the failed database's highest audit ID
  and chain head are read; if not, the head is recorded as unknown and the
  IDs skip a fixed margin of a million. The failed data root is moved
  aside, kept for diagnosis until the next successful upgrade, and the
  backup is copied into an empty one, so root writes into no directory a
  container could have written. The previous deployment directory comes
  back, and the previous version starts by its digests. Then the audit ID
  sequence is moved past every ID the failed version wrote, and the
  updater appends, through the database's own audit function, a record of
  the rollback naming the discarded head. Nothing that agents, the
  console or the engine's worker would write was written: the new version
  was held, and its worker had not started.
* **After a confirmed upgrade**, for 24 hours, **Roll back** is the same
  restore from that upgrade's backup, so everything written since is
  lost: the console and `status` say what (since when, devices enrolled
  since, which must enroll again, jobs, audit records) and the operator
  confirms. The engine's agents cannot be ahead of the restored engine,
  since its automatic agent updates were held for those 24 hours;
  EasyRMM's agents move to the restored server's build as to any build
  (in Manual mode, once approved). The updater keeps its own newer
  version.
* **Collectors** may receive audit records again, with the same IDs and
  contents: forwarding resumes from the backup's position. Records of the
  discarded version keep IDs no later record reuses.
* Refused across a job key rotation's cut-over (ADR to come, plan F0).

### Downtime and alerts
From step 3 to step 7 nothing answers: a backup and a start, minutes on
a typical install. Agents come back within their 5-minute backoff. So
that this raises no alert, EasyRMM's offline policies count a device as
seen no earlier than the moment the server began serving agents (its
start, or the end of a hold) plus 5 minutes; this holds after any restart.
The engine's presence monitor gets the same rule from its worker's start,
in a release.

### Seeing it
`easyrmm-updater status` on the host, and journald for each attempt.
Until feature 4b, the console shows a banner, from the status directory,
when an upgrade failed or was rolled back; with 4b it shows the step and
polls through the downtime. The guide has the manual recovery: the
backup's location and how to put it back.

### Automatic upgrades
Off unless `setup.sh --auto-upgrade` (or the configuration) turns them on,
in the hours configured. Meant for test instances on the edge channel:
each build of `main` that passed everything arrives within the hour.
Production installs upgrade when someone chooses to.

## Testing
* **Verification** against real published artifacts: the latest release
  and an edge build accepted; refused are a tampered bundle, a manifest
  from another build, another workflow's identity, a branch's workflow
  calling `main`'s, a tag that names another version than its manifest,
  an edge build on the pre-release channel, and a lower version.
* **The upgrade, on every pull request that changes it**: a job of its
  own on CI's runner (a throwaway machine with systemd and root, where the
  bundle test already runs Compose), with a 60-minute limit; run locally,
  it removes its units and files when it ends. It installs the last
  release from its bundle, builds the pull request's bundle (its server,
  the last release's engine) and upgrades with the pull request's
  updater. A pull request's build has no attestation, so that updater,
  built with a test-only tag that release builds lack, trusts a Sigstore
  instance the test creates (sigstore-go's virtual Sigstore: a real
  certificate authority and real signatures, only the root differs) and
  applies the same identity checks to the certificates it issues. It
  checks the held start, the backup, the new version and the confirm;
  then a second upgrade made to fail by a real cause (a port the new
  server needs, held by another process), and the rollback: the data
  root, the previous version serving, the audit IDs and the chain; then a
  rollback after a confirmed upgrade; then links and named pipes planted
  in every directory a container can write, through `setup.sh --upgrade`,
  a backup and a restore: nothing written through them.
* **On `main`, after publishing**, with Sigstore's public-good instance:
  the previous edge build upgraded to this one, verification on; only
  then does the `edge` tag move.
* **Requests**: links, named pipes, directories, other owners, oversized
  files, malformed versions, lower versions and versions outside the
  channel, each refused.
* **The updater updating itself**, from the second release that has one.
* Then the owner's test instance on the edge channel.

## Consequences
* An operator upgrades and rolls back from the console (4b), or with one
  command on the host (4a); a test instance follows `main` within an hour
  of each build that passed everything.
* What runs as root on the host is what an operator ran by hand before:
  the release's own `setup.sh` and Compose, now only after Sigstore
  verification for this repository's workflows. `setup.sh` must never
  write as root through anything a container can write.
* An upgrade has minutes of downtime, as a manual one does; offline
  alerts no longer fire for it, or for any restart.
* A rollback after a confirmed upgrade loses what was written since; it
  is offered for 24 hours and says what it loses.
* The server gains `hold` and the offline rule; the engine gains a hold on
  its automatic agent updates and the presence rule, in a release;
  `main`'s publishing moves to the end of CI; release tags are limited to
  `-rc.N`; `main` and release tags are protected.
* Migrations are never edited once merged, since edge instances have run
  them.
* Edge instances run the last release's engine until the next release.
