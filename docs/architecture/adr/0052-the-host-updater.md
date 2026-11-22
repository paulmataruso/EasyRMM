# ADR-0052: Upgrading EasyRMM with an updater on the host

* Status: Accepted (2026-11-21, revised after review). Implemented:
  publishing, that is edge builds of `main`, manifest schema 2 and the
  manifests' Sigstore bundles ([details](../edge-manifest.md)); the
  server's side, `hold` and the offline rule (both amended 2026-11-21,
  below; the rule only delays openings); and the engine's, its hold on
  automatic agent updates and its presence rule, which ship in its next
  release. The updater is implemented (feature 4a): `easyrmm-updater`
  with its service and timer, installed by `setup.sh`; verification, the
  backup, the upgrade, the rollback and the status, as amended below
  (2026-11-21, with the implementation). Not built: requests from the
  console (feature 4b), the rollback guards ("Rollback guards", due
  before ADR-0057's slice 2 or ADR-0061's slice 4, whichever comes
  first), and the test on `main` that upgrades from the
  previous edge build with the updater ([Testing](#testing)); until it
  is, that test verifies each published build as the updater does before
  `edge` moves.
* Builds on: [releasing](../../development/releasing.md) (releases, their
  attestations and manifest), [ADR-0027](0027-agent-updates.md) (agent
  updates), [ADR-0044](0044-authentik-when-chosen.md) (Authentik's files)
  and the Docker deployment ([docker.md](../../deployment/docker.md)).
* Part of [the feature plan](../feature-plan.md): F3 and feature 4.
* Amended 2026-11-21: "Rollback guards", decided in review for
  [ADR-0057](0057-rotating-the-job-key.md) and
  [ADR-0061](0061-moving-to-a-new-name.md).
* Amended 2026-11-21: "Required upgrade stops", decided in review for
  [ADR-0061](0061-moving-to-a-new-name.md).

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
  link planted there (fixed before this ADR, in #44: it now writes
  Authentik's files where only root can and renames them into place).
* **Two agent rollouts.** EasyRMM's server moves every agent whose build
  differs to its own build, older ones included (ADR-0027). The engine's
  worker, every two minutes, moves agents only to newer packages, where a
  policy has `AgentAutoUpdateEnabled`.
* **Restarts raise offline alerts.** Offline policies can be as short as
  3 minutes, and EasyRMM's agents back off for up to 5 minutes after
  failures, the engine's for up to 15; the engine marks endpoints offline
  after its threshold (10 minutes by default). Any stop of a few minutes,
  a manual upgrade included, raises offline alerts.

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

*Amended 2026-11-21, with the implementation:* the updater rewrites one
line of its configuration, `deployment`, when an upgrade or a rollback
moves the deployment to another directory; nothing else writes it.
`setup.sh` installs the updater from `deploy/updater/` (a bundle carries
it for x86-64 and ARM64; a clone builds it with `make updater`), and
`--no-updater` is the one option `--upgrade` takes along. No path unit is
installed until feature 4b.

### Channels and versions
* **stable** takes full releases; **pre-release** also release
  candidates; **edge** also builds of `main`. A version outside the
  configured channel is refused, whoever asks, except a required upgrade
  stop ("Required upgrade stops", below).
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
* **No retrying failures** (*amended 2026-11-21, with the
  implementation:* a failure that a later attempt could get past, such as
  Sigstore, the network or the registry not answering, or too little room
  on a disk, ends the attempt before anything stops and is not counted;
  any other failure is): a version that failed or was rolled back is
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
  *Amended 2026-11-21, with the implementation:* ACME's HTTP-01
  challenges on port 80 are still answered, so that a certificate can be
  issued or renewed during a held start; they come from the certificate
  authority, not from agents or people, and change nothing in the
  database. The rest, as built: the server looks at the file every
  second (`EASYRMM_UPDATER_STATUS_DIR`, `/run/easyrmm-updater`), and is
  held when it cannot tell (any error but the file's absence). Its health
  check (`/readyz` on loopback) passes while it is held, as
  `docker compose up --wait` needs, and says that it is held. Requests in
  progress when a running server becomes held finish, and connections
  already upgraded (remote sessions) stay: the updater holds only a server
  it is about to start.
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

*Amended 2026-11-21, with the implementation:*
* **Set up** carries `.env` across with `EASYRMM_IMAGE` set as well as
  `EASYRMM_VERSION`: the manifest names the server by repository, tag and
  digest ([the manifest](../edge-manifest.md)), and the two make that
  reference. After `setup.sh --upgrade` the updater sets both again and
  checks `docker compose config --images` against the manifest.
* **Start held** starts the services Compose restarts with
  `up --wait`, and one-shot services nothing depends on with
  `up --no-deps` and `compose wait`, since `--wait` fails when such a
  service exits, even successfully. Then the server must pass its own
  readiness check (`easyrmm-server healthcheck`, `/readyz` on its loopback
  health port) and report the new version; nothing goes through its
  public edge.
* **The backup** is the data root without `updater/` (the status the
  updater is writing) and failed data roots kept for diagnosis
  (`.failed-*`), the deployment's `deploy/` and `docker/` directories, and
  `updater.conf`, with a `backup.json` written last; one without it is
  incomplete. A failure before the backup completes starts the previous
  version again from where it stopped. Every copy, into a backup and back
  out of one, is checked against its source entry by entry (type, mode,
  owner, a file's size, a link's target). The data root holds every
  volume of `deploy/docker-compose.yml` that holds state: PostgreSQL's
  whole cluster, copied stopped, so every database in it (EasyRMM's, the
  engine's and, with `--with-authentik`, Authentik's: its users, their
  second factors, the key pair that signs EasyRMM's ID tokens), and the
  server's, MeshCentral's, the engine's and Authentik's directories. No
  database is dumped: a stopped cluster's files are the whole of it,
  roles included, which a dump of each database is not. `setup.sh` puts
  `EASYRMM_TLS_DIR`, `manual` TLS mode's certificate, in the data root
  too. Outside are the updater's own status and `EASYRMM_TLS_DIR` if the
  operator points it elsewhere: mounted read-only, never changed by an
  upgrade. A unit test reads the Compose file's volumes and fails on any
  it does not account for.
* **The engine's hold** is `agent-updates-held-until` in the status
  directory: one RFC 3339 time in UTC, root's, mode 644, written atomically.

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
  confirms. The engine's agents are not ahead of the restored engine,
  since its automatic agent updates were held for those 24 hours, unless
  an operator updated one by hand (the hold leaves those alone);
  EasyRMM's agents move to the restored server's build as to any build
  (in Manual mode, once approved). The updater keeps its own newer
  version.
* **Collectors** may receive audit records again, with the same IDs and
  contents: forwarding resumes from the backup's position. Records of the
  discarded version keep IDs no later record reuses.
* Refused across a job key cut-over or a name move, by the rollback
  guards (next section).

*Amended 2026-11-21, with the implementation:* the restore starts
PostgreSQL alone twice: once from the failed data root, to read its
highest audit ID and chain head, and once from the restored one, to move
the sequence and append the record before anything else starts; only
then does every service start. The ADR's order (the previous version
started, then the sequence moved) would let a starting server write an
audit record with an ID the discarded version used. The restore touches
only the host: it stops, copies, writes the audit record and starts, and
contacts no agent, so it does not depend on agents being reachable.

*Amended 2026-11-21, after review of the implementation:*
* **Interrupted attempts.** An attempt records its deployment, data root,
  new deployment directory and backup as soon as each exists, and each
  stage of a restore before the next. Every run, under the lock, first
  finishes an attempt whose process ended before it did (the
  out-of-memory killer, systemd's stop timeout, a reboot), and does
  nothing else: before the stop, the attempt ends failed; stopped before
  the backup was complete, the incomplete backup is removed and the
  previous version starts; after it, the backup is restored and the
  version marked failed. A restore cut short is done again, without
  reading the discarded database's head a second time; one that had put
  everything back only starts the restored version. The timer also runs
  five minutes after the host starts. A stop asked for (SIGINT, SIGTERM)
  ends an attempt that has not stopped the deployment; after that the
  attempt runs on to its end.
* **After a failed rollback** the updater does nothing, by the timer or by
  hand, and removes no backup, until an operator runs it with
  `--deployment-repaired`, which the automatic run never takes (decided
  in review).
* **The confirm** records the new deployment, in `updater.conf` and then
  the state, before it removes `hold`: a confirm cut short leaves the
  server held, and the next run restores the previous version; a `hold`
  left after the record is removed.
* **The host, at step 1.** The data root Compose mounts must be the one
  `.env` names. No entry at its top may be a link, and nothing in it, at
  any depth, a mount point (read from `/proc/self/mountinfo`, which also
  shows bind mounts within one filesystem); the data root itself may be
  one. Bundles are unpacked into `/opt/easyrmm`, which, with every
  directory above it, only root may write (or is sticky), not beside the
  running deployment, which may be anyone's. Room is added up per
  filesystem: the backup, a restore's copy of the data root, the images
  and the bundle. A host not as needed, a disk that fills (`ENOSPC`,
  `EDQUOT`) and a stop asked for before the stop are tried again at the
  next attempt, not counted against the version. A backup that fails is
  removed.
* **Tidying** removes whole only the bundle directories the updater
  recorded unpacking; of any other deployment directory only
  `deploy/.env`; and nothing that holds the data root, the backup
  directory, the updater's state or its configuration.
* **The running version** (decided in review). An upgrade never goes below
  the highest of the server's report, the updater's record and `.env`'s
  `EASYRMM_VERSION`; `upgradeFrom` is compared with the lowest of those and
  the updater's own. When the server and `.env` disagree (or, when `.env`
  names no version, the server and the record), the updater refuses and
  says why. When the server and `.env` agree on another version than the
  record, the deployment was changed by hand and the record follows them:
  refusing then would stop the updater for good after any manual upgrade
  (proposed in implementation, beyond the review's wording, and accepted
  in review). A rollback
  needs all three to name the version the confirmed upgrade installed.
* **`.env`** is read as `setup.sh` writes it: `KEY=value` lines, comments
  and blank lines. `export`, quoted values, spaces around a key and
  Windows line ends are refused, and the settings the updater reads must
  be set once, to plain values (quoted values amended below, 2026-11-22).
* **The updater not replacing itself** at the confirm is recorded as the
  attempt's warning, in `status`; the next run re-installs it from the
  running version's bundle, when it is older than that version and the
  bundle is one it unpacked.
* **`setup.sh`**, run as root, holds the updater's lock for its whole run
  (amended below, 2026-11-22).

*Amended 2026-11-22, after a second review of the implementation (decided
in review):*
* **Stopping.** `easyrmm-updater.service` has `KillMode=mixed`: systemd's
  stop sends SIGTERM to the updater alone, never to the `cp`, `docker` or
  `setup.sh` it runs, which run in process groups of their own, so Ctrl-C
  does not reach them either. The updater records the stop at once
  (`stop-asked` in its state directory) and runs on as before.
  `TimeoutStopSec=30min`, what is left of a held start and the engine's
  worker's, bounds how long a reboot waits; systemd then kills everything,
  and the next run settles the attempt. A stop recorded during an attempt
  keeps the next run from counting it against the version. A stop asked
  for before step 3 ends the attempt, not counted against the version,
  also when it kills a command the check runs (which then fails with the
  signal, not with the context's cancellation).
* **A command killed by a signal** (one the updater's own context did not
  send: the out-of-memory killer, someone's `kill`) after the stop is not
  the version failing. The previous version comes back at once, as for a
  failure: before step 5 where it stopped, from step 5 on from the backup.
  The attempt is counted as cut short (`cutShort`, in `state.json` and
  `status.json`), as one cut short by a stop asked for, or by a record not
  written, is, and as one whose own process ended, unexplained, during
  steps 3 and 4 (a panic, the out-of-memory killer on a large tree) is,
  once the next run has started the previous version again and done
  nothing else. After two at one version, each of which took the server
  down, automatic runs wait with it until an operator asks for it, and
  `status` says why: no version takes the server down every night. The attempt stops where it is instead, the server
  held, its record saying why (`interrupted`), for the next run to finish,
  only when bringing the previous version back would not be sound or would
  not end: a step not recorded from step 5 on (below), a command killed
  once a stop was asked for (the host is going down), and bringing the
  previous version back itself cut short.
* **Records before changes.** The updater never changes the data root, by
  starting the new version or by restoring, unless the step that says so
  is recorded. Before step 5 a step it cannot record ends the attempt, and
  the previous version starts again on its own data; from step 5 on the
  attempt stops where it is, the server held, and `status` says why. The
  hold is written again then: the attempt may have lifted it to start a
  version, or not yet written it; it lies in the data root's `updater/`,
  which no backup holds and no restore replaces. The same holds for a
  restore's stages: the discarded head, and the restore's end. Every
  record of the attempt (its steps, the new version's directory, the
  backup's directory, the discarded head, the restore's end and the
  attempt's end) is made so: a stage is undone only when `state.json`
  still says the stage before; once `state.json` records it, it is begun,
  whether or not `status.json` could say so (at the confirm, the hold is
  lifted); and one `state.json` was renamed to record but whose directory
  could not be synced stops the attempt at it.
* **Durability.** Every file the updater writes is synced, renamed into
  place and its directory synced. The backup's filesystem is synced
  (`syncfs`) before `backup.json` marks it complete, and the filesystems a
  restore copied to before the restore is recorded as done.
* **Room.** A file counts as the larger of its length and its blocks. The
  data root's filesystem needs room for a restore's copy of it, and the
  deployment directory's for a copy of it. A disk
  that runs out once the deployment has stopped does not mark the version
  failed; automatic runs skip that version until an operator asks for it,
  and `status` and `status.json` (`needsRoom`) say how many bytes it was
  short, and where.
* **A restore done again** removes the copies the first left in the data
  root, worth nothing beside the synced backup, before it copies, so a
  restore needs room for one copy; and the deployment directory's
  replaced copies once each copy is made.
* **`--deployment-repaired`** removes the failed version's directory only
  when no container of the project runs from it; otherwise tidying does,
  once none does.
* **Compose reads only what a backup covers.** Refused at step 1, for the
  running deployment, and once unpacked for the new one: another file
  Compose reads (`docker-compose.override.yml`, `compose.yaml` and their
  variants); a Compose setting in `.env` other than `COMPOSE_PROFILES`;
  and any volume but a `tmpfs` or a bind mount from the data root (not its
  `updater/` or a failed data root), the deployment's `deploy/` and
  `docker/`, the status directory and the server's certificates
  read-only, or `/etc/localtime`, `/etc/timezone` and the Docker socket.
  Each source but those last is taken where Docker finds it, its links
  followed: one whose way leads, through a link, out of the data root or
  the deployment's directory is refused. The updater runs Compose with an
  environment of its own.
* **Links in the data root.** A link at any depth that leads out of the
  data root, where the host follows it, is refused at step 1; links are
  never followed to copy what they lead to. Links that lead into it are
  copied as links. The check runs while the services still run: a link a
  service plants after it and before the stop is backed up, and restored,
  as a link. Nothing the updater does with the data root after the check
  follows it (`cp` copies a link as a link; a restore moves entries aside
  and copies them as they are), and Docker follows a link only on the way
  to a directory it mounts, while no service mounts a directory on the way
  to another's (`deploy/docker-compose.yml`); so it reaches nothing a
  service could not already reach. Left as it is (decided in review).
* **Paths.** Only root may change the way to the bundle directory: each
  directory on it is root's and only root writes it (or it is sticky); a
  link on it is root's, and the way to where it leads is checked the same,
  element by element. Mount points are compared with the data root by
  name, and with where a link to it leads, without resolving the host's
  every mount point.
* **`.env` by Compose's rules.** The updater and `setup.sh` take a value
  unquoted (up to a `" #"` comment, blanks trimmed), or in single or double
  quotes that end on the line with only a comment after them; so a sender
  with a name may be quoted. Either refuses what Compose would read
  otherwise (`export`, blanks before the key or around `=`, a quoted value
  over more lines, text after the closing quote, control characters). What
  each reads of a value is narrower than Compose's rules: the updater reads
  only its own settings, which must be plain and set once; `setup.sh`
  refuses a backslash, `$` or quote in the settings it reads, and, where it
  reads another (a secret it fills), takes off a backslash
  before the quote, or before a backslash in double quotes, keeps any other
  backslash, and refuses the escapes Compose decodes in double quotes
  (`\n`, `\t` and the others) rather than misread them. Neither reads
  Compose's `$` substitution. A test runs the same lines through both and
  through `docker compose config` (compose-go v2.16.2, Compose v5.7.0).
* **`setup.sh`**, run as root, holds the updater's lock for its whole run,
  every `.env` edit and the data root's directories included, and changes
  nothing while an attempt runs. The updater hands its own lock, open, to
  the `setup.sh --upgrade --no-updater` it runs (`EASYRMM_UPDATER_LOCK_FD`);
  that `setup.sh` checks that it is the updater's lock and takes it again,
  which succeeds at once, so neither waits for the other.

### Rollback guards (amended 2026-11-21)
*Decided in review, so that ADR-0057 (rotating the job key) and ADR-0061
(moving to a new name) share one mechanism; both cite this section. It
ships before whichever comes first of ADR-0057's slice 2 and ADR-0061's
slice 4, the first slices that move agents.*

A rollback after a confirmed upgrade restores a database from before
everything done since. Two things done since leave agents unable to work
with the restored server: a job key cut-over, after which moved agents
trust no key the restored server holds, and step 1 or 2 of a name move,
after which moved agents use an address it may not answer. Each is counted
by a value in the database, and the updater refuses a rollback that would
go back across either.

* **The values.** For each, what a backup records, what is read live,
  and its **baseline**, the value of a database in which nothing of the
  kind has happened:
  * **The job key.** The backup records `jobKeyGeneration`, the newest
    generation whose seed the database holds. The live value is the
    floor, the generation of the newest key cut over to (ADR-0057): 1
    from the moment the ring exists, since ADR-0057 records generation 1
    as cut over to, and moved by a cut-over or by `replace-lost`. A
    restored server that holds the floor's key can sign for every device
    that moved, so only a floor above every key the backup holds is a
    problem: a backup taken during a rotation's overlap and restored after
    its cut-over works (ADR-0057's restore table), and recording the
    backup's floor instead would refuse it. Both are 1 for a database
    without `job_keys`, whose `settings` key becomes generation 1.
    Baseline 1.
  * **A move.** `moveGeneration`, recorded and read live: ADR-0061's move
    generation, kept with `name_moves` and defined there; 0 for a database
    without `name_moves`. Baseline 0.
* **They do not go backwards across a restore.** Each new value is the
  larger of the time in milliseconds and the last value plus one; for
  the job key also above any generation a device reports within
  `MaxSkew` (ADR-0057, "One ring"). A restored database holds an older
  last value, but the clock has moved on, so a value made after a restore
  is above the values the restore lost, with one exception: a lost job
  key's generation can sit up to `MaxSkew` (5 minutes) ahead of the
  clock, through the reported-key term, so a key made within those
  minutes can be below it until a device reports it. That does not
  affect the guards, which compare a backup's record with the live
  database. A server whose clock is more than 5 minutes off cannot talk
  to agents (ADR-0057).
* **What a backup records.** At step 3, once every other service has
  stopped and before PostgreSQL does, the updater runs one fixed `psql`
  query, as PostgreSQL's own user in the `postgres` container, with `-X`
  (no `psqlrc`) and `-At` (bare values) and a `lock_timeout`, which
  returns both values. It keeps `{jobKeyGeneration, moveGeneration}` with
  the backup. A value that is absent or does not parse as an integer is
  recorded as unknown. The upgrade that brings the first updater with the
  guards is backed up by the updater before it (step 4 is the running
  updater's; it replaces itself at step 7), so that backup has no record:
  both values unknown.
* **A rollback during an upgrade** (any failure after step 3) is never
  refused: the new version was held throughout and moved no agent, and
  PostgreSQL may not start.
* **A rollback after a confirmed upgrade**, in this order:
  1. `hold` is written. It holds a running server too: new requests get
     `503`, and requests in progress finish (PR #51).
  2. When the live database has `server_instances` (ADR-0057's first
     slice on), the updater waits, up to 30 seconds, until every server
     instance seen in the last 2 minutes reports that it is held (each
     server records it at once when it enters or leaves a hold). It
     refuses while one does not, which includes every server on another
     host, since `hold` is this host's file, and while a database
     connection named plain `easyrmm-server` is open (a server from
     before ADR-0057, which records nothing). A database without
     `server_instances` gets neither check, since there every server
     names its connections plain `easyrmm-server`
     (`server/internal/database/database.go`) and the checks would refuse
     every rollback; the updater waits instead until this host's server
     says on `/readyz` that it is held (PR #51). A guarded rollback is a
     single-host one, as every rollback here is: the updater stops and
     restores this host's deployment only, and with several hosts the
     operator stops the others first.
  3. In one transaction that takes, in this fixed order, the job key
     ring's advisory lock and then the name move's, it reads the floor
     and the move generation and, where step 2 applied, counts again the
     servers not held. Its statements run under the same `lock_timeout`;
     a lock not taken in time is a value that cannot be read.
     Every change to either value takes its lock first and then checks
     `hold` again inside it, by looking at the file, not at the flag the
     server refreshes every second: ADR-0057's changes to the ring, and
     ADR-0061's steps 1 and 2, **Move back** included. So a change
     admitted before the hold has either committed by the time of this
     read, or finds `hold` and is refused.
  4. It decides, below. On a refusal `hold` is removed, and nothing was
     stopped.
* **Refusals**, the same for both values, each with its reason:
  * the live value is above the backup's (for the job key, the floor
    above the newest key the backup holds);
  * the backup's value is unknown (no record, or unreadable at step 3)
    and the live value is above its baseline;
  * the live value cannot be read.

  The reasons: for the job key, "Agents moved to a signing key made after
  this backup, on <time>; restoring it would leave them unable to accept
  anything from the server"; for a move, "Agents moved to a new address
  after this backup, on <time>; restoring it would leave them unable to
  reach the server"; for an unknown or unreadable value, that the updater
  cannot tell whether restoring would do so; for another server, that it
  shares this database and would keep changing it during the rollback.
  Otherwise the rollback goes ahead.
* **One override.** `--strand-agents`, on the host only (never through a
  request), rolls back despite every refusal. It first lists each refusal
  it overrides and what each strands (below), and asks for confirmation.
  Its record in the status directory and its audit record list the same.
* **What a forced rollback strands, and what it costs:**
  * **Across a job key cut-over**: devices that moved trust only keys the
    restored server never held. A restored version with ADR-0057 shows
    them as *Needs re-pinning*; one from before it shows nothing, so the
    operator re-pins every device that runs ADR-0057's agent. Each is
    re-pinned with `easyrmm-agent trust-key --force <generation>:<key>`
    (ADR-0057), through MeshCentral's terminal, policy tools or at the
    computer. The device keeps its identity and history. The cost: a
    command per device, run outside EasyRMM.
  * **Across step 1 or 2 of a name move**: onto a version with ADR-0061,
    agents that moved fall back to their previous address after an hour
    of failures (ADR-0061); the cost is that hour. Onto a version from
    before ADR-0061 they are stranded: that server answers ADR-0061's
    check with `404`, so neither their fall-back nor `set-server` can pass
    it, and their MeshAgents, on the new MeshCentral name, cannot be
    reached for a terminal. The only way back is to uninstall the agent
    and enroll it again with the restored server's install command,
    through policy tools or at the computer. Each comes back as a new
    device (ADR-0024): a new identity, its history left with the old
    record, and its EasyPatch agent enrolled again. The cost: a reinstall
    per device, and every device's history split in two.
  * **Past another server**: the servers on other hosts keep running
    against the restored database, and can change the ring or move names
    during and after the restore. Stop them first.
* **The updater's status** carries the backup's record (both values, or
  unknown), so the console, which knows the live values, hides **Roll
  back**, with the reason, before anyone tries.
* **Why the updater reads the database.** The plan's rule is that the
  updater trusts nothing the server writes beyond a version number
  ([feature-plan.md](../feature-plan.md), "What the reviews changed"). The
  guards depart from it by one fixed query whose answers are parsed as
  integers and nothing else: the two values and the count of servers not
  held. They decide only between the rollback the operator asked for and
  a refusal, which the host can override; they never make the updater do
  anything else.

### Downtime and alerts
From step 3 to step 7 nothing answers: a backup and a start, minutes on
a typical install. EasyRMM's agents come back within their 5-minute
backoff, the engine's within 15 minutes. So that this raises no alert,
EasyRMM's offline policies count a device as seen no earlier than the
moment the server began serving agents (its start, or the end of a hold)
plus 5 minutes; this holds after any restart. The engine's presence
monitor gets the same rule from its worker's start, in a release, with
15 minutes for its agents' longest backoff (revised when the engine
implemented it: with 5, an engine agent that waited out its backoff could
still be marked offline).

*Amended 2026-11-21, with the implementation:* the rule only delays
openings. The serving start plus 5 minutes holds back opening a new
offline alert, and nothing else: an alert already open stays open until
its device checks in, and resolving uses the device's real last check-in,
so a restart or a hold neither resolves an open alert nor opens it again.
As built: the start is when the server opens its listeners, after its
migrations, not when its process starts, which can be minutes earlier;
while it is held it serves no agents, so no new offline alert opens.
Agents add up to a tenth to their 5-minute backoff as jitter, which the
shortest offline policy (3 minutes) covers.

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

### Required upgrade stops (amended 2026-11-21)
*Decided in review for ADR-0061, whose slice 4 acts on a record that its
slice 1 begins to keep; a deployment that jumped over slice 1 would have
none.*

* **`upgradeFrom`**: the manifest (above) gains the version a deployment
  must already run before it installs this one. It always names a
  release, a release candidate or a full release, never an edge build:
  the scheduled workflow deletes edge artifacts after 30 days and never
  deletes releases, so the stop stays installable. Edge manifests carry
  it too. It is one line in the repository that
  `scripts/release/bundle.sh` and edge publishing write into the manifest
  and the bundle's `setup.sh` reads; it only ever rises. ADR-0061's slice
  4 and every later version name the release that carries its slice 1,
  which is cut before slice 4 merges.
* **The updater has the check from its first release**: it is being built
  now, and no updater without it ships. At step 1 it compares
  `upgradeFrom`, in this ADR's order, with the lower of the running
  server's version, read from the running server, and its own: an image
  swapped by hand can put the server above the updater. Below it, the
  upgrade is refused before anything changes, naming the version to
  install first.
* **Which version is the stop**: the lowest version on the deployment's
  own channel that is at or above `upgradeFrom` and below the target.
  Only when the channel has none does the updater cross channels, to the
  lowest release at or above `upgradeFrom`; that is the one exception to
  the channel rule above. A stable deployment so goes to a full release
  that carries the stop's change when one exists, not to its release
  candidate. Automatic upgrades install the stop first, as a version of
  its own.
* **No refusal by the manifest's form.** The updater refuses no manifest
  for a schema version: an older updater must always be able to install
  the release that carries its successor. Fields it does not know are
  ignored. A field an updater must honour is introduced only together
  with an `upgradeFrom` naming the first release whose updater honours
  it, and that release does not use the field itself. That is why the
  updater compares `upgradeFrom` with the lower of the running server's
  version and its own (above).
* **`setup.sh --upgrade` refuses the same jump** with the same message:
  the backstop for upgrades by hand. It takes the installed version from
  the running server; from the updater, which passes the version it read
  at step 1, since step 5 runs it with the services stopped; or, by hand
  with the server stopped, from the old `.env`'s `EASYRMM_VERSION`, read
  before `setup.sh` rewrites it. When it can learn none of them, it
  refuses and says to start the installed version first. A fresh install
  is never refused.
* **Release order**: `release.yml` refuses a tag above a stop whose commit
  does not contain the stop's commit (`git merge-base --is-ancestor`).
  The check relies on a version above the stop carrying the stop's
  change, which version order alone does not guarantee, since a higher
  tag could be put on an older commit of `main`. Edge versions are made
  from the releases reachable from their commit, so they follow.
* **Tests**, one per refusal: the updater refusing a release and an edge
  build whose `upgradeFrom` is above the running version, and accepting
  them from the stop; a server swapped by hand above the updater's own
  version, compared by the updater's; the stop chosen on the
  deployment's own channel (a stable deployment taking the full release
  that carries the change, not its release candidate, when both exist),
  and from another channel only when its own has none; an updater older
  than a must-honour field's `upgradeFrom` installing that release
  first, then the release that uses the field; `setup.sh --upgrade` by
  hand refusing with the
  running server below the stop, with the server stopped and the old
  `.env`'s `EASYRMM_VERSION` below it, and with no version to be had;
  `release.yml` refusing a tag above the stop on a commit without it.

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
* **The rollback guards**, in the upgrade job, from the first slice that
  moves agents: each refusal for each value (above the backup's; unknown
  in the backup with the live value above its baseline, and at the
  baseline allowed; unreadable); a change to the ring or a move step
  racing the hold, either committed before the read or refused inside the
  lock; a recorded instance not held, and a connection named plain
  `easyrmm-server`, each refused; a database without `server_instances`
  (from before ADR-0057), with the server's plain connections open,
  rolled back; a lock not taken within `lock_timeout` refused as
  unreadable; `--strand-agents` listing every refusal
  it overrode, in its confirmation, its status record and its audit
  record. ADR-0057 and ADR-0061 test what their agents do after each.
* **The updater updating itself**, from the second release that has one.
* Then the owner's test instance on the edge channel.

*Amended 2026-11-21, with the implementation:* required upgrade stops,
as ["Required upgrade stops"](#required-upgrade-stops-amended-2026-11-21)
above has them. A manifest may name in
`upgradeFrom` the lowest version a deployment must already run before it
installs that one: a release or a release candidate below it, never an
edge build. At step 1 the updater compares it with the lowest of the
running server's version, `.env`'s, the updater's record and its own,
which came with the bundle the deployment was last set up from (decided
in review: an image changed by hand can put the server above it, and,
after review of the implementation, the server's word is not taken
alone; see the amendments to "Rollback"), in semantic versioning's precedence,
as `scripts/release/version.sh newer` does. Below it, the version is
refused before anything stops, naming the version to install first, and
the refusal does not count as the version failing. That version is the
lowest the deployment's own channel offers at or above `upgradeFrom` and
below the version that names it, another channel's (the pre-release
channel's, a release candidate on the stable channel) only when that
channel offers none (decided in review), and a stop's own stop is followed
the same way. Asked for by name, such a stop is taken on any channel.
Automatic upgrades install it first, as a version of its own; the next
run, by the stop's own updater, goes on. They never go down to a stop
below the running server: that deployment is upgraded by hand. A manifest
of a later `schemaVersion` is read as this one, and fields the updater
does not know are ignored, so that an updater can always install the
release that carries its successor. Not built: `setup.sh --upgrade`'s own
refusal of the same jump, and the version the updater would pass it.

*Amended 2026-11-21, with the implementation:* what is built so far.
Unit tests drive every step against a fake Docker, and verification
against sigstore-go's virtual Sigstore, each certificate field refused
in turn; integration tests run the rollback's SQL against the migrated
schema, and take a real PostgreSQL cluster holding EasyRMM's, the
engine's and Authentik's databases, with Authentik's directories, through
a backup, a change and a restore. Against real artifacts, an integration
test takes the first edge build main's CI published, kept byte for byte
with Sigstore's public-good trusted root, through an upgrade's check,
and refuses seven changes to it before anything stops;
`make test-updater-published` takes the build ghcr.io's `edge` tag names
now the same way, the trusted root fetched through TUF. The upgrade runs
as a machine test
(`make test-vm-updater`, internal/vmtest): a Debian 12 machine with
Docker, installed from a bundle with `setup.sh`, upgraded to a second
bundle, the confirmed upgrade rolled back; `setup.sh` run again while the
updater's lock is held, which refuses and changes nothing; the updater
killed (SIGKILL to its whole unit) while the second bundle's server starts
held, then the machine restarted, and the timer's run after the boot
restoring the first version; an upgrade to a third bundle that fails at
the held start and is rolled back; then a fifth bundle whose `upgradeFrom`
names the fourth, refused by hand with nothing restarted, and installed by
two automatic runs, the fourth first, its service stopped with
`systemctl stop` during its backup and running on to the attempt's end;
and what tidying left. The third bundle's server fails its health check,
not a held port: a server that cannot bind restarts until the 20-minute
limit. It has run on an emulated machine only (no KVM on the host). On the
code as reviewed a second time, it passed whole on 22 November 2026
without Authentik, in 3 hours 48 minutes (run 9), as it had on the code
reviewed the first time on 21 November (run 8, 3 hours 28 minutes). The
two runs before run 8 with Authentik failed at the test's own
install, before the updater ran: once the engine's migration crashed
(exit 139, a segmentation fault) on the emulated processor, once
Authentik's worker did not turn healthy within the hour the test's
bundles give every service there. Run 7, without Authentik, was stopped
at its first error, the test's own: it took a container Compose had not
needed to recreate for one not running the new version; the test now
compares configuration hashes. Authentik's data through a backup and a
restore is covered by the integration test above. Not
built yet: the CI job, verification against a real release,
links and named pipes planted through a backup and a restore, requests
(4b), and the updater updating itself across releases.

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
  is offered for 24 hours and says what it loses. It is refused across a
  job key cut-over or a name move, and while a server on another host
  shares the database; `--strand-agents` overrides that on the host, at
  the cost the rollback guards state.
* The server gains `hold` and the offline rule; the engine gains a hold on
  its automatic agent updates and the presence rule, in a release;
  `main`'s publishing moves to the end of CI; release tags are limited to
  `-rc.N`; `main` and release tags are protected.
* Migrations are never edited once merged, since edge instances have run
  them.
* Edge instances run the last release's engine until the next release.
