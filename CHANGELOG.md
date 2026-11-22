# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- **Read-Only users no longer see what scripts printed or the arguments
  they were given, and every read is recorded.** A run's output and a
  job's argument values can hold a recovery password, a token or a key.
  Until now everyone with `job.view`, Read-Only included, could read them
  on the run's and the job's pages, and nothing recorded who did
  ([ADR-0063](docs/architecture/adr/0063-who-sees-job-output-and-arguments.md)).
  Now:
  - a new permission, `job.view_sensitive`, held by Technicians and above
    where their role is, opens them. Read-Only still sees every job and
    run, its status, exit code, error and timings, the script as run and
    how many arguments it had; the console says *Hidden: needs permission
    to see job output* where the output would be;
  - output and argument values leave every job and run answer of the API,
    for everyone, and come only from `GET /api/v1/job-runs/{id}/output`
    and `GET /api/v1/jobs/{id}/arguments`. Each read is recorded in the
    audit log (*Viewed job output*, *Viewed job arguments*) in the same
    transaction, super administrators' included; a refused read is
    recorded as denied, at most once per user and run in 10 minutes and at
    most 20 times per user in 10 minutes. After 20, that user's further
    refusals are not recorded until the 10 minutes pass, so a gap in the
    denied records is not proof that nobody tried. The server's database
    role can no longer select them directly. Scripts
    that read `stdout`, `stderr` or `args` from the run and job answers
    move to the new endpoints; `/api/v1` has no written compatibility
    policy, and the console is its only client in this repository;
  - output is kept for `EASYRMM_JOB_OUTPUT_RETENTION`, 30 days by default
    (or `EASYRMM_JOB_RETENTION` when that is shorter), counted from when it
    arrived; the job and its runs stay for `EASYRMM_JOB_RETENTION`. **The
    first purge after the upgrade empties output that arrived more than 30
    days before.** Set `EASYRMM_JOB_OUTPUT_RETENTION=2160h` to keep 90 days
    as before;
  - **Remove output** on a run's page empties its output at once, for
    Technicians and above, recorded as *Removed job output*;
  - a refused hardening result no longer quotes a module name from the
    script's output in the run's error or the server's log.

  Reads before the upgrade left no record. Treat a secret that a job
  printed, or that was passed as an argument, within the job retention
  before the upgrade as seen by every Read-Only user of its site, and
  change it. For BitLocker, add a new recovery password, then remove the
  old one. A console tab left open across the upgrade can go blank on a
  job's page, and says "Nothing was written" on a run's page, until it is
  reloaded. From this release on, a console page that fails to render
  offers **Reload** instead of going blank.

  **The upgrade fills in the output sizes of every run that has output,**
  in one pass, while `job_runs` and `jobs` are locked: jobs and runs
  cannot be read or written until the migration ends. Measured on a test
  database: 3 seconds for 50,000 runs with 1 KB of output each, and under
  a second for 5,000 runs with 16 KB each. It needs free disk about the
  size of the runs with output as stored in the table, 69 MB for those
  50,000 runs; output large enough to be stored apart (TOAST) is not
  copied, 1 MB for the 5,000. `VACUUM`, which autovacuum runs, makes that
  space reusable.
- **Functions that run as the database owner no longer look in a
  session's temporary schema first.** EasyRMM's `SECURITY DEFINER`
  functions, which run as `easyrmm_owner`, did not name `pg_temp` in their
  `search_path`. PostgreSQL then searches a session's temporary objects
  before its own for tables and types, so a database session of the
  server's role, for example through a flaw in the server, could have had
  its own code run as the owner. This covered the audit log's functions
  (`easyrmm_audit_append`, `easyrmm_audit_verify`, `easyrmm_purge_audit`)
  as well as the new ones above. Now:
  - every such function names `pg_temp` last (migration 00029 for the
    older ones), and a test fails the build for one that does not;
  - the server's role and `PUBLIC` can no longer create temporary tables
    in EasyRMM's database. The server never used them.

  The revoke needs `easyrmm_owner` to own the database, as the Docker
  install and the documented external setup make it. Under another owner,
  or when the server's role keeps the right through another grant, the
  upgrade still pins the functions, leaves `TEMPORARY` in place, and logs
  a warning with the statements to run as a superuser
  ([database.md](docs/architecture/database.md)).
- **The Windows agent checks its state folder before reading it.** Any
  user may create folders under ProgramData, and the agent protected
  `%ProgramData%\EasyRMM\Agent` only when it saved an enrollment. A
  standard user could have prepared that folder before the agent was
  installed, or after it was removed, and had the install and the service,
  which runs as SYSTEM, use what they left there. Now, before any command
  reads or writes its state, and before the service opens its log, the
  agent checks:
  - that every folder from ProgramData down is a plain folder that the
    system or an administrator made;
  - that no one but the system, administrators and TrustedInstaller may
    change the state folder or what it holds;
  - that each file it reads or writes there is a plain file with a single
    link, owned by the system or an administrator, that no one else may
    change. This covers the enrollment, key, status, job journal, log,
    update marker and EasyPatch downloads.

  A folder that fails is moved aside, as `<name>.untrusted-<time>`, and made
  anew. A file that fails is moved aside, and the configuration and the key
  go together. A state folder whose access list differs from the agent's
  own, but lets no one else change anything, such as one with entries in
  another order, an extra entry for administrators, or one that lets users
  read, keeps its enrollment: the agent sets its own list back and logs a
  warning. The agent never reads what it moved aside: it carries on as
  not enrolled, and an install enrolls anew. The scripts' working folders,
  which the check leaves out, are emptied when the agent starts. On
  Windows, `easyrmm-agent status` now needs an administrator. Linux is
  unchanged: only root reaches its state folder there.
- **`setup.sh` writes nothing through a link Authentik's containers plant.**
  As root, it wrote the administrator's invitation in
  `authentik/invitations/`, which the `authentik-setup` container can write,
  by a name that container could have made a link: a compromised container
  could have had root overwrite any file on the host, and own it, at the next
  upgrade. `setup.sh` now writes Authentik's files where only root can and
  renames them into place, and keeps its record of the first invitation in
  `authentik/invitation-issued`, which no container can reach. The Authentik
  end-to-end test plants those links.
- **MeshAgent's binary and settings are signed.** The agent fetched them
  from the server over TLS only; since agents trust the system's
  certificate authorities, a TLS-terminating proxy or an inspecting
  firewall could have changed what then runs as SYSTEM or root. The server
  now signs both with the job key the agent pinned, over the device and
  the request's single-use nonce, and the agent installs neither unless
  the signature verifies (ADR-0015, amended).
- **The agent bounds the server's heartbeat interval** to between 10
  seconds and 10 minutes, so that an answer changed on the way cannot
  silence it.
- **Releases come only from `main`, in two forms.** The release workflow
  published any tag `easyrmm-vX.Y.Z-<anything>` on any commit. It now
  accepts only `easyrmm-vX.Y.Z` and `easyrmm-vX.Y.Z-rc.N` (no leading zeros),
  only on commits on `main`. `.github/rulesets/` holds the rulesets that
  protect `main` (pull requests with CI passed) and limit release tags to
  administrators, with how to apply them (ADR-0052).

### Added

- **Downloading a job's output and results** (ADR-0064, slice 1). A run's
  page offers **Download** beside **Copy** on each stream, and
  **Download run** (the run as JSON, both streams with it); a job's page
  offers **Download output (ZIP)**, a folder for each finished run the
  user may read and `runs.csv` saying for every run whether its output is
  in, and **Download results (CSV)**, every run's status, exit code, error
  and times without output. Each is shown only where it can work. Output
  downloads go through ADR-0063's reads: `job.view_sensitive` at the run's
  site, and each recorded as *Downloaded job output* with what was
  downloaded, in the same transaction. The archive records every run it
  holds and commits those records before the first byte is sent; if they
  cannot be written nothing is sent, and output removed in between is
  listed as removed. Each person may download six archives at once, then
  one every 10 seconds (up to 11 in the first minute, six a minute after,
  counted by each server process); another is answered 429 with
  `Retry-After`. The results need only
  `job.view`, are recorded as
  *Downloaded job results* (`job.results_export`), and neutralize formula
  cells as reports do. API: `GET /api/v1/job-runs/{id}/output?download=stdout|stderr|json`,
  `GET /api/v1/jobs/{id}/output.zip` and `GET /api/v1/jobs/{id}/runs.csv`
  ([guide](docs/operations/scripts-and-jobs.md#downloading-output-and-results)).
- **Disk health** (ADR-0065, slice 1). The EasyRMM agent reads each disk's
  own health record every 30 minutes, NVMe's health log and ATA's SMART
  with a fixed list of read-only commands, on Windows and Linux, and sends
  it in a report of its own (`POST /api/agent/v1/hardware`, one in 10
  minutes per device with bursts of 6). The server judges every reading
  with one set of rules: *Healthy*, *Warning*, *Failing*, *Unknown*,
  *Unavailable* or *Unsupported*, each with a reason; a disk is never
  shown healthy because something could not be read. A device's
  **Hardware** tab shows each disk's health and firmware, and a disk's
  panel its facts, ATA attributes, last 30 days and open alerts;
  **Devices** gains a *Disk health* column and filter. Disks behind a
  hardware RAID controller, SAS and USB disks show *Unavailable* until
  later slices read them. See [Disk health](docs/operations/disk-health.md).
  - **Disk health alerts**, one per disk: a `disk_health` policy watches
    one check, *failing*, *errors*, *pending*, *wear* or *temperature*,
    and resolves after two readings in a row clear it. Five shared
    policies come with it, only **Disk failing** turned on. A disk that
    disappears keeps its alerts; they resolve on their own (*Disk gone*,
    `subject_gone`) once it has been missing from the device's disk
    readings for 14 days. See [Disk health policies](docs/operations/alerts.md#disk-health-policies).
  - **History**: every reading for `EASYRMM_METRICS_RETENTION`, then one
    row per disk and day for `EASYRMM_HARDWARE_RETENTION` (new; `17520h`,
    730 days, by default, at least the metrics retention). About 0.3 MiB
    per disk in the database and its backups.
  - **Each disk's firmware revision** is in the inventory, and on Linux a
    SATA disk's whole model (40 characters, where the kernel's listing
    holds the first 16). Every device uploads its inventory once after
    its agent is updated.
- **`setup.sh --upgrade`** prepares an upgrade with the deployment's own
  settings, all read from `.env`: the options it was installed with are not
  given again and nothing is asked. It sets the release's server version
  from a bundle, lists settings the release adds, makes the data
  directories under `.env`'s data root (rerunning `setup.sh` without
  `--data-root` used the default one), and issues no Authentik invitation.
  The upgrade guide now uses it (ADR-0052).
- **The server can be held by the updater** (ADR-0052's server side; the
  updater itself is not built yet). `setup.sh` makes
  `${EASYRMM_DATA_ROOT}/updater/status`, root's with mode 755, which the
  server and the engine's worker mount read-only at
  `/run/easyrmm-updater`. While a file
  named `hold` exists there, the server answers its health check and
  nothing else: the console, the API, agents, the engine's agents and
  Authentik's and MeshCentral's names get `503` with `Retry-After`; ACME's
  challenges are still answered. The server reads it before it opens its
  listeners and looks again every second; its health check passes while
  held and says so.
- **Restarts and upgrades raise no offline alerts.** Offline policies
  count every device as seen no earlier than 5 minutes after the server
  began serving agents (its start, or the end of a hold), the longest
  agents wait between attempts. The rule only delays openings: an offline
  alert already open stays open, and resolves only when its device checks
  in.
- **Edge builds.** Every build of `main` that passes CI is published as a
  version: `v1.0.0-rc.4.edge.412.1` after a release candidate,
  `v1.0.1-edge.415.1` after a release. The server image the tests ran is
  pushed unchanged as `easyrmm-server:<version>`, and the bundle, its
  manifest and the manifest's Sigstore bundle as the OCI artifact
  `ghcr.io/paulmataruso/easyrmm-deploy:<version>`; `edge` moves to the
  newest once it verifies. An edge build runs the last release's patching
  engine, so CI also runs the contract and bundle tests against it. Edge
  builds older than 30 days are deleted (ADR-0052;
  `docs/architecture/edge-manifest.md`).
- **The release manifest names everything a deployment runs**: schema
  version 2 adds the bundle's SHA-256, every image by digest, PostgreSQL's
  major version and Authentik. A release also publishes the Sigstore
  bundle of its attestation beside the manifest, so that verifying needs
  no GitHub API.
- **Hardening checks for Linux computers** (ADR-0051, its first part). A
  technician can have the agent on a Linux device check 14 areas: SSH,
  the firewall, fail2ban, kernel settings, audit rules, file permissions,
  legacy services, kernel modules, sudo, time synchronisation, shared
  memory, USB storage, SELinux or AppArmor, and file integrity. It runs
  through the API (`POST /api/v1/jobs/hardening`, mode `check`). The check
  changes nothing on the computer. It reports, per area, whether the
  hardening is in place, partly, not at all, not applicable, managed by
  something else, or half applied, and what applying it would change.
  Each device's latest findings are kept (`GET
  /api/v1/devices/{id}/hardening`); the console lists hardening jobs and
  shows what each checked. Applying and undoing come next. The job table
  now takes job bodies up to 512 KiB, for the script; library scripts keep
  their 64 KiB limit.
- **A device's Hardening tab, and hardening across the fleet** (ADR-0051,
  H3). Linux devices with the agent have a **Hardening** tab: each
  module's latest state, what is missing, what applying it would change,
  and for the firewall the ports it would leave open; when the last check
  ran, by which job, on which distribution and release, and how far
  EasyRMM's hardening supports it, with *check only* explained. **Run
  check…** chooses the modules, the recommended ones preselected and the
  others with their risk beside them, and needs `script.run`; the
  findings need only `device.view`. **Devices** gains a **Hardening**
  column (*9 of 10 in place*) and a filter (needs attention, in place, not
  checked), also on the API (`GET /api/v1/devices?hardening=`), and devices
  in the API carry a summary of their hardening. Job runs can be listed by
  kind (`GET /api/v1/job-runs?kind=hardening`). The audit log names
  hardening jobs *Hardening job*. See
  [Hardening Linux computers](docs/operations/hardening.md).
- **The mail server in the console** (ADR-0053, slice 1). Super
  administrators set it under **Settings → Notifications → Mail server**:
  host, port, STARTTLS, TLS or none (only to a relay on the same machine),
  signing in with a password or not at all, and the sender's address and
  name. The password is sealed with `EASYRMM_SECRET_KEY`, write-only, and
  kept while the host, port, security and user name stay the same. It
  applies at once, without a restart: to invitations, password resets,
  whether password reset is offered, and the patching engine, which
  EasyRMM now gives the mail server on every change rather than once per
  start. `EASYRMM_SMTP_*` in `.env` still works and wins: the console then
  shows it read-only, and a mail server saved in the console before can
  still be removed. **Send test message** tries the form's settings, saved
  or not, one every 30 seconds, and shows the mail server's answer without
  repeating what a server that is not a mail server said. **Limits**, 30
  messages a minute and 9,000 a day by default, hold across servers:
  invitations and password resets go first, the last 10% of the day is
  kept for resets people ask for, and other mail stops at 80%. Every
  change and test is audited (`mail_server.*`), from and to. See
  [Mail](docs/operations/mail.md).

### Changed

- **Upgrading adds five shared alert policies** for disk health, only
  **Disk failing** turned on. **Where a shared policy already has one of
  their names** (case aside), the new one is added as *… (disk health)*,
  for example *Disk failing (disk health)*; where both names are taken, no
  policy for that check is added. Check the **Policies** tab after the
  upgrade if you named policies that way.
- **An alert can be about one part of a device.** Alerts gain `checkName`,
  `subject`, `subjectLabel` and `detail` in the API, and a device can have
  one active alert per policy and disk. Changing a policy's check resolves
  its alerts as a changed condition (`policy_changed`), as changing its
  kind, threshold or minutes does.
- **Invitations and password reset emails come in HTML and text**, from a
  new mailer that sends each recipient a message of their own, can carry
  attachments, checks the mail server's certificate against the system's
  authorities with TLS 1.2 or later, and dials through the same address
  checks as EasyRMM's other outbound connections. When an invitation's or
  password link's email does not go, the console now says why: no mail
  server, or the mail server did not take it.
- **Invitations and password emails are limited**, so that no one
  administrator, organization or attacker can use up the mail server's
  day: per administrator an hour, per organization a day, per account
  (3 at once, then one every 20 minutes, resets and administrators' links
  together), and password resets people ask for per organization and on
  the whole platform, by the hour only, so that no one can keep them
  refused for a day. Each limit is the smaller of a fixed number and a share of
  the day's limit, and all are counted in the database, across servers
  (see the [Mail](docs/operations/mail.md#limits-on-invitations-and-password-emails)
  guide for the numbers). Past the administrator's own limit, an
  invitation or link is refused with `429` and a message that says when
  to try again, and the refusal is audited; past the account's or the
  organization's, it comes back to the administrator unsent, with the
  reason. A super administrator's invitations and links count only
  against their own limit. Without a mail server, links come back as
  before, unlimited.
- **Every `429` carries `Retry-After`.**
- **The patching engine's mail server comes from EasyRMM alone**: a mail
  server set in the engine itself is overwritten within a minute, and
  when EasyRMM cannot give the engine its own three passes in a row, the
  engine's is removed and Patching → Notifications says why. With several
  servers, one at a time gives it; another whose mail server differs logs
  an error and says so, rather than giving the engine its own in turn.
  A server that stops gives the work up at once, and another takes over
  at its next pass; a server whose connection to PostgreSQL died without
  a word is noticed in about 30 seconds, and another takes over; a
  pooler in transaction mode (PgBouncer's) is not supported. Servers compare theirs with a
  keyed HMAC of the one given, from which the password cannot be
  guessed, and change the engine's mail settings one at a time. The
  webhook switch no longer fails when EasyRMM's mail server cannot be
  read, leaves the engine's as it is then, and an engine that hangs no
  longer holds it up.
- **`.env`'s SMTP password and sender's name are checked** against the
  lengths the patching engine takes. Longer, EasyRMM still starts and
  sends, logs an error and shows it on the Mail server page.
- **Password reset checks the address's limit before anything else**, and
  whether reset is offered is kept for five seconds, so requests anyone
  may send seldom reach the database. A reset takes its room under the
  limits before its link is made and never holds one database connection
  while it waits for another, so that many resets at once for one address
  cannot use up the server's connections; a reset refused under a limit
  makes no new link, so the last one sent still works.

- **CI and releases build the server image once.** Both platforms, amd64
  and arm64, are scanned and their agents checked against a release's
  build, byte for byte; the amd64 image runs the tests; and the build is
  pushed unchanged. CI no longer rebuilds and pushes it on every push to
  `main` before the other checks finish, and a release no longer pushes a
  build other than the one it scanned.
- **The server image's agents are cross-compiled on the build machine**,
  so the arm64 image hands out the same files as the amd64 one and as a
  release: an operator-signed release agent matches either (ADR-0049).
- **Releases check their files before attesting**: the bundle against its
  manifest, and the attached agents against the pushed image.
- **A release published out of order leaves `latest` where it is.**
  `easyrmm-v1.1.5` after `easyrmm-v1.2.0` tags the server image `1.1.5`
  and `1.1`, not `latest`, and is not GitHub's Latest release. A version's
  server image is pushed once; a release run again pushes nothing more.

### Fixed

- **Remote sessions work from every address the server answers on.**
  MeshCentral accepted a session's control connection only from a page on
  its own name, so it closed every session started from a console reached
  at another address (`invalidorigin`): the IP addresses of a DNS install,
  and an IP-only install's addresses other than its public one, such as a
  private address behind NAT. EasyRMM now writes the host of every
  MeshCentral origin it serves into MeshCentral's `allowedOrigin`; when
  they change, the next start rewrites the list and MeshCentral restarts
  with it (ADR-0016, amended).
- **Changing `EASYRMM_PUBLIC_URL` moves the bundled Authentik with it.**
  After the URL was changed in `.env` and `docker compose up -d` run,
  Authentik's worker did not apply EasyRMM's blueprint again, since it does
  so only when the file changes, and the URL comes from `.env`. The
  provider kept the old redirect URI, so signing in at the new URL failed
  at Authentik, and an invitation's sign-up and the application's link
  still went to the old one. At every start, `authentik-setup` now compares
  what the blueprint takes from `.env` (the URL and the client secret) with
  what Authentik holds, applies the blueprint again when they differ, and
  stops with an error unless they then match. When nothing changed, nothing
  is applied. The Authentik end-to-end test changes the URL and signs in at
  the new one.
- **Backups keep Authentik.** With `setup.sh --with-authentik`, Authentik
  keeps everyone's sign-in in its own database, `authentik`, in the same
  PostgreSQL, and `akadmin`'s password and its files in
  `/srv/easyrmm/authentik`. The backup guide dumped only EasyRMM's and the
  patching engine's databases. A restore from it therefore started a new,
  empty Authentik: every user, password and second factor gone, a new key
  signing EasyRMM's ID tokens, and users made again refused by EasyRMM,
  whose accounts stay linked to their old identities. The guide now backs
  both up when Authentik is installed, and restores them in order: the
  `authentik` role and database from `authentik-db-init`, then the dump,
  and only then Authentik's first start. It also extracts the data
  directories with `tar --numeric-owner`, so that their owners survive a
  host where the same user names have other numbers. The upgrade guide
  says the same. The restore drill has an Authentik variant
  (`backup-restore.sh --authentik`): the administrator made from
  `setup.sh`'s invitation signs in through Authentik before the backup and
  after the restore, as the same user, with the same signing key.
- **Restoring over a deployment on the same host has its own steps.** The
  restore steps expect an empty data root and an empty PostgreSQL, but
  nothing said how to get there on a host that still has the deployment,
  and *Going back* after an upgrade sent operators straight to them. Run
  over the existing deployment, they overwrite its `.env` and cannot load
  the dumps into the databases already there, and deleting the data root
  to start clean throws away the way back. *Restore in place*, in the
  backup guide, stops the deployment, sets its data root (PostgreSQL's
  data with it) and `.env` aside under a timestamp, restores, and puts the
  set-aside deployment back if the restore fails; it also covers a data
  root that is a mount point. *Going back* points to it. The restore drill
  has an in-place variant (`backup-restore.sh --in-place`, with or without
  `--authentik`), which also checks that the set-aside data root is
  unchanged, puts it back, and checks that what changed after the backup
  returns.
- **The release's agents are the same files the server hands out.** The
  release bundle built them with the commit stamped in and the server's image
  without, so their bytes differed, and a Windows agent an operator signed
  from the release's file would not have matched the server's own build
  (ADR-0049). Both now build with `-buildvcs=false`; built from a clone, the
  two are identical for Linux and Windows.
- **Agents keep working when a server is rolled back.** The server now ignores
  request fields it does not know, instead of refusing the request, and says
  in each heartbeat answer which protocol level it speaks (2). Agents will
  send fields added by later releases only to servers of level 2 or higher,
  so an agent that updated before a rollback is never cut off (ADR-0009,
  "Evolving the protocol"). Malformed requests are still refused.
- `deploy/.env.example` lists `EASYRMM_ACME_DIRECTORY`, which the Compose
  file already passed to the server.
- Taking the database down past migration 12 removed no software jobs:
  row-level security hid them from the migration. It now sees every row.
- Toasts and copy buttons clear their timers when they leave the page. A
  closed toast, or a copy button in a dialog closed straight after copying,
  left a timer that later updated a component already gone; at the end of a
  unit-test file, that update threw `window is not defined` and failed the run.

## [1.0.0-rc.4] - 2026-11-21

The fourth release candidate: devices can be removed from the console with
their agents, and operators can sign the Windows agent with their own
certificate. Patching engine 1.12.1.

### Added

- **Removing a device.** **Remove** on a device's page (Site
  Administrators and above) has its agents uninstall themselves: with its
  next heartbeat the EasyRMM agent gets a signed instruction, starts its
  uninstaller outside its service, removes its service, MeshAgent and
  itself, and confirms; EasyRMM then deletes the device, the patching
  engine has the EasyPatch agent uninstall itself, and MeshCentral forgets
  the device. Until the agent confirms, the device shows *Removing* and
  the removal can be cancelled. If the agent cannot remove itself, the
  device shows why, with **Ask again** and **Remove anyway**. A device
  removed by force that comes back within 90 days is still told to
  uninstall itself. Devices with no EasyRMM agent are removed at once.
  ([Removing a device](docs/deployment/agents.md#removing-a-device),
  ADR-0050.)
- **Removing an endpoint only the patching engine has.** Patching →
  Overview's list of endpoints with no EasyRMM device has **Remove**: the
  EasyPatch agent uninstalls itself and the engine stops patching the
  endpoint.
- **Signing the Windows agent with your own certificate.** **Settings →
  Agent updates** offers the server's Windows agent builds to download,
  sign with your own code signing certificate and tools, and upload. The
  server checks that each upload is its own build with only an
  Authenticode signature added, then hands it out in place of the
  unsigned build; agents update to it. The page shows the signer, the
  thumbprint and whether the signature has a timestamp. **Hand out signed
  Windows builds only** keeps Windows computers on signed builds after an
  upgrade, until the new builds are signed; devices show *Waiting for a
  signed build*. EasyRMM never holds your key.
  ([Signing the Windows agent](docs/deployment/agents.md#signing-the-windows-agent),
  ADR-0049.)

### Fixed

- **`easyrmm-agent uninstall` on Linux left an empty
  `/usr/local/lib/easyrmm-agent` folder.** It is removed with MeshAgent.
- **The patching overview's list of endpoints with no EasyRMM device** drew
  the line under its description only part of the way across.

## [1.0.0-rc.3] - 2026-11-21

The third release candidate: the patching engine keeps only what EasyRMM
reaches, the console loads faster, and fixes from the first real
deployment. Patching engine 1.12.0.

### Changed

- **The patch policy's delay hints say what the engine does.** A delay
  counts from when an update first appears on any device, not from its
  release; the delay for security updates covers security updates only
  (critical updates take the other delay), and definition updates are never
  delayed. A device's policy shows "7 days after first seen".
- **Messages call the engine the patching engine.** A failed EasyPatch agent
  install on a device's page, and the patching engine's alerts and events,
  no longer call the engine "EasyPatch"; the EasyPatch agent keeps its name.
- **The console fetches each page when it is first shown.** The script the
  browser loads first went from 618 kB to 75 kB (plus the libraries, which
  browsers keep across upgrades). If a page cannot be fetched because
  EasyRMM was upgraded while the console was open, the console reloads
  once to get the new version; if it still cannot, it says so and offers
  **Reload**.

### Removed

- **What only EasyPatch's own console reached**
  ([ADR-0048](docs/architecture/adr/0048-the-engine-keeps-what-is-reached.md)).
  The patching engine no longer keeps deployment codes, enrollment requests
  waiting for approval or their install scripts, and a migration drops
  their tables. The EasyPatch agent enrolls only with the single-use token
  EasyRMM gives it; an older agent installed with a code is refused with
  `deployment_codes_retired`. Engine routes EasyRMM never calls go too, as
  do the "Enrollment waiting for approval" patching alert and the restart
  dialog's fallback for engines before 1.10.0.
- **The check for the engine's scheduled-installs capability.** EasyRMM
  ships with its engine, so the install dialog always offers a later time,
  and `canSchedule` and the engine's `capabilities` leave the API.

### Fixed

- **The agent stops a package manager gently.** An `rpm` query, or an
  `apt-get` or `dnf` install of the EasyPatch agent, that ran past its
  deadline was killed outright, which can leave the package database locked
  or, with RHEL 8's Berkeley DB, needing recovery. It is now asked to stop
  (SIGTERM) and killed only if it has not stopped 10 seconds (a query) or 30
  seconds (an install) later.
- **A damaged RPM database is named.** When `dnf` cannot install the
  EasyPatch agent because the machine's RPM database cannot be opened
  (`DB_RUNRECOVERY`, `rpmdb open failed`), the device's install status says
  to run `rpm --rebuilddb` as root and install again. Found on the first real
  deployment, on a RHEL 8.10 machine whose database was already damaged when
  it enrolled.
- **Sign-in says when no passkey answered.** When the browser's passkey or
  security key prompt ended without a key, sign-in and the second factor
  showed nothing, so a password manager that did not open (locked, or
  updated since the page loaded) looked like a page that ignored the click.
  They now say no passkey or security key answered and suggest reloading the
  page. Browsers report a closed prompt the same way, so it is a note, not an
  error.
- **The patching engine sorts agent versions as versions.** Its endpoint
  list, sorted by agent version, put 1.10.0 before 1.9.0. It now compares the
  numbers, in the database so that paging stays right.
- **The patching engine refuses a null list from an agent.** An agent
  request that sent `null` for a list, such as `"activeJobIds": null`, got a
  server error; it now gets `400 validation_failed` naming the list.
  EasyPatch agents never send one.
- **Software on Windows treats a missing package as Linux does.**
  *Uninstall* of a package that is not installed now succeeds with winget
  and Chocolatey, as the guide says, instead of failing; *Update* of one
  fails with exit code 3 and says it is not installed; a winget *Install* of
  an ID the `winget` source does not have says so. Chocolatey's check uses
  its own list of installed packages, so `choco` does not run.
  The guide also said winget's *Install* leaves an installed package as it
  is; winget updates it when a newer version exists, and the guide now says
  so.

## [1.0.0-rc.2] - 2026-11-20

The second release candidate, with what the first real deployment of
rc.1 found. Patching engine 1.11.1.

### Added

- **Show a token's install commands again.** Under Devices → Add devices,
  an active deployment or approval token has **Show install commands**,
  which opens the same install steps as when it was created. The server
  keeps each new token sealed with its encryption key, bound to the token;
  only people who manage the token can show it, only while it can still add
  devices, and each time is in the audit log (`enrollment_token.reveal`,
  `approval_token.reveal`). Tokens created before this release keep only
  their hash and say so (ADR-0047; migration 00024).

### Fixed

- A device approved in the console no longer shows twice for a few seconds.
  Its agent installs MeshAgent, and MeshCentral reported the new node before
  the agent's next heartbeat claimed it, so the node was listed as a
  discovered device of its own until the two were merged. A node no device
  claims now waits two minutes (two heartbeats) before it is recorded as
  discovered; a MeshAgent installed by hand shows up after that wait.

## [1.0.0-rc.1] - 2026-11-20

EasyRMM's first release candidate, for testing on a real server before
1.0.0: self-hosted remote monitoring, management and patching for MSPs, in
one Docker Compose deployment on host networking. Its patching engine,
EasyPatch's server, is built from the same commit and released with it as
version 1.11.0. Source-available under [FSL-1.1-ALv2](LICENSE.md).

### Added

- **Endpoints and the agent**
  - The EasyRMM agent for Windows (x64, ARM64) and Linux (x86-64, ARM64,
    ARMv7, x86), installed with one PowerShell or shell command from
    **Devices → Add devices**; it installs MeshAgent too.
  - Deployment tokens per site, or one approval token for every customer,
    with each computer approved into a site in the console.
  - Outbound HTTPS only: a signed heartbeat every minute, jobs by long poll.
  - Agent updates a few devices at a time (**Settings → Agent updates**),
    rolled back when a new build crashes or cannot reach the server.
- **Remote access**
  - Remote desktop, terminal and files, and RDP to Windows devices, through
    MeshCentral 1.3.1 behind EasyRMM's gateway; each session authorized and
    audited, RDP credentials never stored.
- **Inventory, monitoring and alerts**
  - Hardware, operating system, network and installed software; processor,
    memory, load and disk use charted on each device's page.
  - Alert policies for offline devices and processor, memory or disk use;
    alerts acknowledged and resolved in the console.
- **Scripts, jobs and software**
  - A script library (PowerShell, cmd, Bash, sh, Python 3) at shared,
    organization and site level; jobs on up to 500 devices, with output.
  - Software installed, updated and uninstalled through winget, Chocolatey,
    apt-get, dnf, yum or zypper, on one device or many.
  - A warning on scripts that install updates themselves and so bypass
    patch policies and maintenance windows.
- **Reports**
  - Device inventory, installed software, device health and alert history,
    in the console or as CSV.
  - Patch compliance with its trend, patch installations, and monthly patch
    reports: PDFs made by hand or on a schedule, downloaded or emailed.
- **Patching**
  - The patching engine in every deployment, on loopback with its own
    database; EasyRMM keeps its organizations and sites in step.
  - The EasyPatch agent for Windows (Windows Update, winget application
    updates) and Linux (apt, dnf), installed by the EasyRMM agent on chosen
    devices or across an organization (**Settings → Patching engine**).
  - **Patching**: what needs attention, worst first; devices; every update
    with its CVEs and known exploitation (CISA KEV); jobs and alerts; scans,
    installs, holds, restarts and retries across devices.
  - A device's **Patches** tab: install preview, exclusions, removing a
    Windows update, restarts, messages to users, the agent's version, the
    policy in effect with each value's layer, and stopping patching.
  - Patch policies for the default, organizations, sites, tags and devices:
    maintenance windows, delays, categories, restarts, Windows Update.
  - **Settings → Patching**: tags, report schedules, engine settings, OS
    lifecycle dates, agent packages, alert rules, notification channels
    (email, Slack, Microsoft Teams, webhooks) and the engine's audit log.
- **Organizations, users and sign-in**
  - Organizations (each with a time zone), sites and device groups; five
    built-in roles, Super Admin for the whole server and the others per
    organization or site.
  - Sign-in with a password and a required second factor (authenticator
    app with recovery codes, security key or passkey), or a passkey alone.
  - Single sign-on with OpenID Connect (**Settings → Single sign-on**);
    Authentik as an install option (`setup.sh --with-authentik`); a
    one-time recovery link from `easyrmm-server recover`.
  - A hash-chained audit log, forwarded to syslog or a SIEM if wanted
    (**Settings → Audit forwarding**).
- **Deployment**
  - One Docker Compose deployment on host networking: only EasyRMM's server
    listens publicly; MeshCentral, the patching engine and PostgreSQL on
    loopback ([guide](docs/deployment/docker.md)).
  - TLS by Let's Encrypt, your own certificate, the server's own CA, or
    NGINX in front ([guide](docs/deployment/nginx.md)).
  - Access by IP address beside the DNS name, or by IP alone; install
    commands by IP pin the server's key.
  - Backup and restore ([guide](docs/operations/backup-restore.md)) and
    upgrades ([guide](docs/operations/upgrading.md)).
  - Importing a standalone EasyPatch server (1.4 to 1.10) from its backup;
    its agents keep working ([guide](docs/operations/import-easypatch.md)).
- **Releases**
  - One release from one commit: server and engine images for amd64 and
    arm64, and a deployment bundle pinning both by digest, with the EasyRMM
    agents and `SHA256SUMS`.

### Security

- Tenant isolation in PostgreSQL by forced row-level security.
- Passwords hashed with Argon2id; secrets sealed with AES-256-GCM.
- Agent requests signed with each device's Ed25519 key; jobs and agent
  updates signed with the server's job key, pinned at enrollment.
- Remote sessions only with a grant for one device and session type; no
  TCP or UDP tunnels through agents.
- The patching engine accepts only EasyRMM's signed statements (30 seconds,
  one request) and its agents' signed requests.
- EasyPatch agent packages are signed with the release key, and the agent
  installs nothing else; it cannot run commands.
- Images and release files attested (Sigstore) with SBOMs and provenance,
  and scanned with Trivy ([CODE_SIGNING.md](CODE_SIGNING.md)).
- A security review of sign-in, the agent channel, remote access and tenant
  isolation ([findings](docs/security/security-review.md)).

### Known limitations

- No MSI, DEB or RPM packages of the EasyRMM agent: install commands only.
- No Authenticode signature on `easyrmm-agent.exe` or EasyPatch agent MSIs.
- Email and webhook notifications for patching alerts only, not device
  alerts; not yet tested against a real mail server or webhook receiver.
- No agent WebSocket channel: jobs arrive by long polling. Script output is
  not streamed, and scripts cannot be scheduled.
- Devices cannot be moved, renamed or removed in the console yet. No
  inventory history, scheduled device reports or software catalog.
- Not yet run end to end on a real Windows machine: RDP, the winget and
  Chocolatey scripts, undoing a crashing agent update, the ARM64 agent.
- No Windows update has yet been installed through EasyRMM on a real
  machine (the test machines had none missing); nor removing an update,
  messages to users, restart modes other than the countdown, or policy
  changes applied on Windows.
- The macOS EasyPatch agent is experimental and not released.
- Single sign-on has no group-to-role mapping, SAML or just-in-time
  accounts, and has not been tried with Entra ID, Google, Okta or Keycloak.
  The Authentik option has run only on an install addressed by IP.
- Security keys and passkeys need a DNS name and have not been tried with a
  physical key.
- One patching engine API instance per deployment; it cannot reach webhooks
  on the server's own subnet. The Linux EasyPatch agent needs systemd.
- EasyPatch's standalone console is not part of EasyRMM. The import needs
  an engine with no agents yet, and is tested only from EasyPatch 1.10.0
  with a Linux agent.
- The `internal` certificate authority has no name constraints: install it
  only on technicians' computers.
- Inviting an address that has an account on the server says that it
  exists ([roles](docs/security/rbac.md)).
- No outside penetration test yet.
