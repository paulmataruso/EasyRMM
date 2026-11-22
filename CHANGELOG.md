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

- **Hardening checks for Windows computers and servers, through the API**
  ([ADR-0054](docs/architecture/adr/0054-hardening-windows-computers-and-servers.md),
  W1; [guide](docs/operations/hardening.md#windows-computers-and-servers)).
  `POST /api/v1/jobs/hardening` takes `"platform": "windows"` and checks 23
  modules, from accounts and the firewall to BitLocker and LAPS, with
  Windows PowerShell 5.1 as LocalSystem. A check changes nothing it
  reports on. For each setting it reports the value, what EasyRMM wants,
  and who else owns it: Group Policy (read from Windows' own record of what
  it applied), registry preference items, an MDM, Defender for Endpoint, a
  Configuration Manager client, DSC, Azure machine configuration, OSConfig,
  Tamper Protection, or another antivirus or firewall (on servers, another
  vendor's filtering platform provider). A value a Group Policy object
  deletes is Group Policy's. Where EasyRMM cannot tell, the setting is
  *check only*, with the reason, a record that could not be read
  included. What the check could not read is never taken for an answer:
  such a setting is *unknown* with the error, a module none of whose
  settings could be read (or whose Defender or BitLocker state could not
  be) *failed*, and a role or join Windows did not report *unknown*, which
  makes the computer check only and what turns on whether it is a domain
  controller *unknown* too. On a computer enrolled in an MDM every value
  no other owner holds is *check only*, until the MDM reader is proven on
  an Intune-enrolled computer. The accounts module reports whether the
  computer is exposed: failed sign-ins from public addresses, or 10 or
  more for one account within 15 minutes. The platform says which
  Windows it is, its role, how it is joined, and whether apply will be
  supported there. Each module lists
  the NIST SP 800-53, SP 800-171 and ISO/IEC 27001 controls that DISA's and
  NIST's published mappings relate it to, with their sources. Every run
  first checks `%ProgramData%\EasyRMM\Hardening`, where apply will keep its
  record. It refuses a folder that someone other than SYSTEM or
  Administrators could write to, or that is reached through a link. The
  console's **Hardening** tab and its check dialog stay Linux's until W3;
  a checked Windows device's summary shows in **Devices**. Applying and
  undoing come with W2.
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
- **PowerShell 7 scripts** (ADR-0064, slice 1). A script's shell can be
  **PowerShell 7** (`pwsh`); `powershell` scripts still run in Windows
  PowerShell 5.1, unchanged, and the console now names that shell
  *Windows PowerShell 5.1*. Run as LocalSystem, the agent uses only a
  PowerShell 7 no standard user can change: it looks in Program Files and
  Program Files (x86) only, never the `PATH` or a user's folders, takes the
  newest stable 7 or later built for the processor, and before each run
  checks that the install, the folders above it, the module folders and
  configuration files the run reads can be changed only by Administrators,
  SYSTEM and TrustedInstaller and hold no links or junctions (except the
  hard links Windows keeps in Windows PowerShell's own module folders). A
  module an installer left open to users fails the run, naming it. Previews,
  32-bit builds, PowerShell 6 and Microsoft Store installs (winget's
  default since PowerShell 7.6) are listed and never run. Runs get the
  system's module folders only, and PowerShell 7's telemetry and update
  check off. Where no usable PowerShell 7 is found the run fails without
  running the script, unless its author set **Where PowerShell 7 is
  missing** to Windows PowerShell 5.1 (`pwshFallback`, copied into each
  job). The check also refuses a folder above the install or a module
  folder that someone else could replace, a module folder the
  configuration names that does not exist, and a file open in another
  program that may write it; files Windows compressed or deduplicated are
  plain files. A run holds `pwsh.exe` and the install's libraries open,
  unwritable, until its process is created. After fixing an install's
  permissions, restart the computer. An install whose module folders or
  configuration fail, with a file open in another program or with more
  than one hard link, whose version is not a version, or that could
  not be read or checked (a `Program Files\PowerShell` that cannot be
  listed included, shown as *could not be checked*, not as PowerShell 7
  missing) is *found, not usable*: runs use another install that passes
  every check, or fail, naming the blocked install the Hardware tab lists
  first, without falling back to Windows PowerShell 5.1,
  which loads from the same module folders and to which anyone who may
  read a file could otherwise send scripts. A script that falls back runs
  Windows PowerShell with a module path of checked folders only, never the
  computer's, written so that Windows PowerShell adds no folder of its own
  (with Windows' default `PSModulePath`, CI's runners showed it adding a
  relative one); a `PSModulePath` in the registry that names a variable
  the agent cannot expand as Windows PowerShell would stops PowerShell 7
  runs and the fallback. Migration 00033 adds the shell and the new
  columns, its checks unvalidated; migration 00034 validates them and
  fills each device's PowerShell 7 flag and blocked reason from its stored
  inventory
  ([guide](docs/operations/scripts-and-jobs.md#powershell-7)).
- **Every run records the program it used**: edition, version,
  architecture and path, read from the file just before it starts, and
  whether a PowerShell 7 script fell back to 5.1. Shown on the run's page
  ("PowerShell 7.6.10, 64-bit"), as the **Program** column of a job's runs,
  and in the results CSV and downloads, to everyone with `job.view`. Runs
  from agents of earlier releases say *Not reported by this agent's
  version*.
- **A Windows device's PowerShell installs**: the inventory lists Windows
  PowerShell and each PowerShell 7 found, and the **Hardware** tab shows
  which one PowerShell 7 scripts run in and why each other is not used,
  or *Found, not usable* with the reason. The run dialog warns how many
  chosen devices reported no usable PowerShell 7 and what the script does
  there.
- **Agents say which jobs they take.** The agent's poll lists the job
  capabilities its build takes (`accepts`; `job.pwsh` from Windows agents),
  kept on the device for that build. A PowerShell 7 job is sent only to an
  agent that listed it; starting one on a device whose agent cannot, or has
  not said, is refused with the reason, the device picker leaves such
  devices out, and a run left waiting says why and expires with that
  reason, as does a run the agent took before changing versions. The agent
  sends the list, its PowerShell installs and a run's program only to a
  server of protocol level 2 or higher (ADR-0009); a result waits at most
  until 30 seconds after the agent started to learn the level.
  **Agents of 1.0.0-rc.4 and earlier never list it: update them to run
  PowerShell 7 scripts.** Every other job runs on them as before: the
  integration tests run the rc.4 agent, built from its tag, on Linux
  through Bash, sh and Python scripts with arguments and exit codes, a
  timeout and a cancel.

- **The customer record** (ADR-0066, slice 1, the first of its three pull
  requests). An organization's **Overview** shows its main phone, email,
  website, business hours with *Open now* or *Closed now*, and
  after-hours instructions, its primary and emergency contacts, and each
  site with its address and whether it is open now; a **Contacts** tab
  lists the people to call at the customer, the organization's own and
  each site's, with one primary for the organization and one per site,
  secondary, and an emergency flag.
  A site's page shows its address as fields (two lines, city, region,
  postal code, country) beside the free text, its own hours or the
  organization's in the site's time zone, its contacts, and **Places**:
  buildings, floors, rooms, racks and others, up to four deep. Two new
  permissions: `doc.view`, held by every built-in role, and `doc.manage`,
  held by Technicians and above, at the organization or site where the
  role is; site-scoped people see their sites' contacts and places, not
  the organization's own contacts, which row-level security enforces in
  PostgreSQL. Every change is audited without the text typed in: the
  records name the fields that changed, and keep a contact's priority and
  emergency flag and a place's kind and the ID of the place it is inside
  (`parentId`), never a contact's name, job title, email address, phone
  numbers or note, or a place's name. A new primary contact and the one it
  replaces each get a record, naming the other by ID. Email addresses are
  plain ones only: characters such as `?` and `&`, which would add headers
  to a `mailto:` link, are refused; letters beyond ASCII, as in
  `zoë@example.com`, are taken, the server and not the browser judging
  them. A **Contacts** report exports them as CSV.
  Contacts are personal data of the customer's staff:
  [PRIVACY.md](PRIVACY.md) says what is kept and why. See
  [The customer record](docs/operations/customer-record.md).

- **Patch all, Schedule restart all and Update all now** (ADR-0030,
  amended 2026-11-22). With an organization chosen, and a new **site**
  filter beside it, the Patching overview offers **Patch all…** and
  **Schedule restart all…**; with a site, also **Update all now…**, which
  installs every available update now and restarts devices if the updates
  need it, Windows devices first (Linux when ticked). The organization's
  page has Patch all, a site's Update all now. The server reads "every
  device" when the request runs: those with a linked EasyPatch agent, not
  stopped, that you may patch; the dialog says how many, by platform, and
  how many are left out and why. Installs go to the engine 200 devices at
  a time with no limit on the organization's size, and each batch is
  reported, even if the page is closed meanwhile; every available update
  reaches at most 1,000 devices, splits a device's updates into jobs of at
  most 500 (the engine's limit), and leaves out updates excluded on a
  device, held, application updates the policy does not approve, feature
  upgrades unless ticked, and updates in the rollout delay if unticked. One audit
  record per request (`patch.install_all`, `patch.restart_all`) names the
  organization or site, the counts, what was left out, the batches and the
  presets. New: `GET /api/v1/patching/scope`,
  `POST /api/v1/patching/install/plan`, and `all`, `organizationId`,
  `siteId`, `platforms`, `updates`, `features`, `restart` and
  `confirmServers` on installs and restarts. See
  [Patch all](docs/operations/patching.md#patch-all-schedule-restart-all-update-all-now).
- **Restart after the install.** The install dialog, wherever it opens,
  offers *Don't restart* (the default), *Restart if the updates need it*
  and *Restart when done* (at most 100 devices), with the restart's modes;
  servers restart only when ticked by name. The patching engine cannot
  restart when an install ends, so EasyRMM does: it keeps the choice in its
  database (migration 00038), watches each install every minute, and asks
  the engine for one restart once the install has completed, never after
  one that failed, was cancelled or expired; it waits for an install the
  engine timed out; an install that waits for a restart gets one then, up
  to three, and the last when it ends; a restart already scheduled for
  later is left as it is. A restart of EasyRMM's
  server neither loses nor repeats it. The install's job shows the choice
  and what became of it. See
  [Restart after the install](docs/operations/patching.md#restart-after-the-install).
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
- **The server can be held by the updater** (ADR-0052's server side).
  `setup.sh` makes `${EASYRMM_DATA_ROOT}/updater/status`, root's with mode 755, which the
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
- **Applying and undoing hardening on Linux computers** (ADR-0051, its
  second part). A Site Administrator or above (the new `device.harden`
  permission) can apply each of the 14 areas through the API
  (`POST /api/v1/jobs/hardening`, modes `apply` and `undo`); Technicians
  keep checking. Apply changes only what the check found missing, and only
  to make it stricter, then checks again: a second apply changes nothing.
  Before changing anything, each area records on the computer (in
  `/var/lib/easyrmm-hardening/`) the files, modes, kernel values,
  services, packages and rules it changes; undo puts back what is still as
  apply left it, says what it left and why, and removes the record. Undo
  removes auditd, where apply installed it, only when no other rules file
  needs it; `/var/lib/easyrmm/auditd-installed` remembers that EasyRMM
  installed it, for log collection to share. An area that fails part way
  is put back as it was, but for packages it installed that cannot be
  removed, which it names; a job that is killed leaves the area half
  applied, which a later apply finishes and undo reverses. A package step
  cut short no longer fails every later one: before each, apply and undo
  finish an interrupted dpkg (`dpkg --configure -a`) or, on RHEL 8, an rpm
  database a killed rpm left needing recovery, once no other package
  manager is using it; the area's result and the audit log record it, and
  an area whose recovery fails, or that waited five minutes for another
  package manager, fails and says why, naming the packages the recovery
  finished. Apply and undo run for up to an hour (a check, 30 minutes),
  and the script works to that limit: it stops a step that would run past
  it, fails an area whose package step lacks the time it needs, and does
  not run the areas after it (*Not run*). Canceling a run stops the step it
  is in, and records the packages an installation it stopped had added, so
  that undo removes them. Undo removes only packages still at the version
  apply installed, and never purges them: their configuration files, logs
  (the audit trail among them) and data stay, and on Debian and Ubuntu the
  result names the packages `apt-get purge` would clear. It gives a
  directory an installation changed its mode and owner back, and removes
  the files the installation made that its packages leave, once those
  packages are gone, removes
  generated files only as they were made, keeps symbolic links and SELinux
  labels, and refuses the firewall alone while fail2ban bans with it; an
  installation never removes a package; fail2ban's bans stop growing at a
  day; USB storage is refused where `/etc/fstab` needs a USB disk to boot.
  Password sign-in goes off only where root or an administrator who may
  sign in has a key that parses as one, and root's password sign-ins are
  read from what sshd itself wrote to the journal.
  Apply and undo run on the releases CI's machine tests cover (Debian 12
  and 13, Ubuntu 22.04, 24.04 and 26.04, Rocky Linux 8, 9 and 10, AlmaLinux
  9 and 10, Fedora 45); other supported releases are checked only. Undo also runs
  on the computer without the agent:
  `sh /var/lib/easyrmm-hardening/easyrmm-hardening.sh undo all`. Each
  device's latest result now carries, per area, what apply or undo did and
  whether a record is kept. The console's job page names the mode, and the
  device's **Hardening** tab shows the state each leaves; starting them
  from the console comes next. See
  [Hardening Linux computers](docs/operations/hardening.md).
- **The host updater, `easyrmm-updater`** (ADR-0052, feature 4a). Run as
  root, `setup.sh` installs it with a systemd service and a timer (hourly,
  and five minutes after the host starts),
  configured in `/etc/easyrmm/updater.conf` (`--no-updater` installs
  none; `--auto-upgrade` turns automatic upgrades on, which are off
  otherwise). `easyrmm-updater upgrade [version]` verifies the release or
  edge build against its Sigstore attestation for this repository's
  workflow, checks the bundle and every image against its manifest, pulls
  while the server runs, stops it, backs up the data root (PostgreSQL's
  whole cluster with it, so Authentik's database too where it is
  installed) and the deployment, checking each copy against its source,
  sets the new bundle up with its `setup.sh --upgrade`,
  starts it held and confirms it; when the new version does not start, it
  restores the backup and records the rollback in the audit log.
  `easyrmm-updater rollback` undoes a confirmed upgrade within 24 hours,
  after saying what it loses; `status` and `check` change nothing. A
  version whose manifest names a required upgrade stop (`upgradeFrom`)
  above the lowest of the running server's version, `.env`'s, the
  updater's record and the updater's own is refused before anything
  stops, naming the version to install first; automatic upgrades install
  that stop first, and never go below the highest of the first three. An
  attempt cut short (killed, or the host restarted) is finished by the
  next run from what it recorded, which is on the disk before each step
  begins. A command of its killed by a signal brings the previous version
  back at once without counting against the version, and the updater's
  own process ending during the stop or the backup is finished so by the
  next run; after two attempts at one version cut short so, automatic
  upgrades wait for an operator, and `status` says why, so that no version
  takes the server down every night. A step it cannot record from step 5 on, a command
  killed once a stop was asked for, or bringing the previous version back
  cut short, stops it where it is, the server held, for the next run.
  systemd's stop (`KillMode=mixed`) and Ctrl-C reach the updater alone,
  which runs on to the attempt's end for up to 30 minutes. After a
  rollback that failed the updater does nothing until it is run with
  `--deployment-repaired`. It refuses, before anything stops, a data root
  holding links at its top, links anywhere that lead out of it (a mount's
  way included) or mount points, a host without room on each disk for
  everything that goes on it, a `.env` it could read otherwise than
  Compose does or that sets a Compose setting but `COMPOSE_PROFILES`,
  another Compose file beside `docker-compose.yml`, and a volume a backup
  would not hold. `.env` is read by Compose's rules, by the updater and
  `setup.sh` alike, so a quoted value, such as a sender with a name
  (`EASYRMM_SMTP_FROM="EasyRMM <rmm@example.com>"`), is read as Compose
  reads it. A version that ran out of room once the deployment stopped
  waits for an operator, and `status` says how many bytes it was short.
  Run as root, `setup.sh` holds the updater's lock for its whole run, and
  changes nothing while an attempt runs. The updater unpacks bundles into
  `/opt/easyrmm`, root's, through links only root can change, and removes
  only those. Each
  bundle carries it; a clone builds it with `make updater`. Guide:
  [the host updater](docs/operations/updater.md). The console's requests
  (feature 4b) come later.
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
- **Signing in to Microsoft 365 with an application** (ADR-0053, slice 2),
  ahead of Microsoft turning password sign-in to Exchange Online's SMTP
  off by default at the end of December 2026. The mail server signs in
  with an Entra application's token (`AUTH XOAUTH2`, only over STARTTLS or
  TLS) to the sender's mailbox, from the application's tenant ID, client
  ID and client secret, or its certificate and RSA private key. Set it in
  the console (Settings → Notifications → Mail server, which fills in
  `smtp.office365.com`), in `.env` (`EASYRMM_SMTP_AUTH=microsoft365`, the
  IDs, and the secret or key only in files named by
  `EASYRMM_SMTP_CLIENT_*_FILE`), or with `setup.sh --smtp-tenant-id` and
  the other `--smtp-*` options, which copy the secret or key into
  `${EASYRMM_DATA_ROOT}/secrets` (`root:65532`, 0750 and 0440) and may be
  given alone on an existing `.env`. The secret and the key are sealed and
  never returned; tokens are kept in memory until 5 minutes before they
  expire and never logged. Microsoft's and Exchange's refusals are
  explained: SMTP AUTH off for the tenant or the mailbox, security
  defaults, a missing permission or service principal, a wrong secret, and
  sending over the rate: a password reset someone asked for is tried again
  a minute later, and an invitation or password link comes back to the
  administrator at once (the replies' texts come from Microsoft's
  documentation, not yet checked against a real tenant). The certificate
  must be PEM certificates alone, and only they are stored. `setup.sh`
  leaves the settings it keeps as `.env` has them, writes `.env` whole and
  renames it into place, and refuses a data root others can change, a
  linked `secrets` directory, hard-linked files in it, and a `$` in a mail
  setting (Compose reads it as a variable). **While an
  application signs in, the patching engine is given no mail server, so
  patching sends no email or monthly reports** until a later release; the
  mail server page, Settings → Patching (Notifications and Reports),
  Reports → Monthly patch reports, a report's failed email and the log say
  so. For patching's email meanwhile, use a relay or a password. See
  [Mail](docs/operations/mail.md#microsoft-365).
- **`easyrmm-server mail check`** connects to the mail server in force
  and signs in, getting a token first with an application, and quits
  without sending; it prints the answer and exits 1 on failure. The server
  runs the same check at start, after every change and daily, logs it, and
  the mail server page shows the last one, with the application's
  certificate and its end date, warned of from 30 days before.
- **Active alerts pulse in red in the console.** On a device's page,
  every active alert in the **Alerts** card pulses slowly in red (a
  resolved one never does), and the card's title shows how many are
  active. On the **Alerts** page and in the menu's **Alerts** tree, the
  name of a device with an active critical alert pulses too, with the
  critical icon beside it. One cycle takes 1.8 seconds, only text colour
  and a soft tint change, every state keeps 4.5:1 contrast in both themes,
  and with reduce motion turned on the red holds still. **Stop flashing**,
  on the Alerts page and a device's Alerts card, holds it still in this
  browser too. A disk's panel on the Hardware tab pulses and counts its
  open alerts the same way. Severity badges, icons and counts keep saying
  the same in words. See
  [What pulses in red](docs/operations/alerts.md#what-pulses-in-red).
- **A detailed card for every alert.** Select an alert's name wherever
  alerts are listed (the **Alerts** page, a device's **Alerts** card, the
  dashboard and a disk's panel) for everything recorded about it: its
  device, site and organization; the condition, policy and values that
  opened it; a chart of the measurement around it with the threshold and
  the time it was open; for disk health, the disk's facts; its times and
  acknowledgement; what it means and what to do next; the policy's other
  alerts on the device; and the raw JSON to copy. The card has its own
  address; **Close**, Escape and **Back** close it. An alert older than
  the measurements kept charts what is kept, and says so. Patching alerts
  get a card too: select a title under **Patching → Alerts** for its
  device or organization, times, what it means, what to do next and its
  JSON ([Patching alerts](docs/operations/patching.md#alerts)). The API adds
  `GET /api/v1/alerts/{id}/metrics`, and `policyId` and `subject` filters
  on `GET /api/v1/alerts`. See
  [An alert's card](docs/operations/alerts.md#an-alerts-card).

### Changed

- **A site's address moves to its details.** The free-text address is
  edited under **Address and hours** on the site's page, with
  `doc.manage`, instead of in the site's **Edit**: `PUT /api/v1/sites/{id}`
  and `POST /api/v1/organizations/{id}/sites` no longer take `address`
  (they answer `422` with the field named) and
  `PUT /api/v1/sites/{id}/details` does. Existing addresses are kept as
  they are; nothing is read from them into the new fields. Without
  `doc.view`, a site's and an organization's answers carry empty
  details.
- **Deleting a site or an organization that holds contacts or places**
  needs them confirmed: the first try answers `409 documentation_exists`
  with their counts, and the console then offers **Delete site and its
  documentation** on a site's page, or **Delete organization and
  contacts** on an organization's. Through the API, send the counts back as
  query parameters (`?contacts=2&places=1`). Sites and organizations
  without any are deleted as before. The deletion's audit record keeps the
  counts; the contacts and places deleted with it get no records of their
  own.
- **Time zones must be names from the time zone database, as it writes
  them.** An organization's or site's time zone is one of the IANA names
  in the copy of the database the server is built with, such as
  `Europe/London` or `US/Eastern`, every one the console offers among
  them. Other spellings the system opens as the same zone, such as
  `Europe//London` or `./Europe/London`, were accepted and are now refused
  with the field named; upgrading rewrites any stored one as the name it
  stood for. Names held only by the server image's own zone files, such
  as `right/Europe/London` or `posixrules`, are left as stored and must be
  changed the next time that organization or site is edited: the console
  shows the error under the time zone field.
- **A downloaded report's audit record no longer quotes a search that can
  name a person.** For **Device inventory**, whose names are often their
  users', the two patch reports and **Contacts**, the record says
  `"searched": true` instead of the search text (`q`); **Installed
  software** still records it.
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
- **A key rotation no longer makes servers say their mail server differs
  from the patching engine's.** The record of the mail server given to the
  engine is kept under each secret key, and servers compare under a key
  they have in common. A server that waits for another's change of the
  engine's mail settings tries again at its next pass, counting no failure
  and never removing the engine's mail server for it. One account's
  password emails are now limited exactly as the guide says, however old
  its earlier emails: before, emails over a day old were left out, which let
  an account get about two more a day.
- **`docker-compose.yml` mounts `${EASYRMM_DATA_ROOT}/secrets`** read-only
  in the server, and `setup.sh` (`--upgrade` included) creates it,
  `root:65532` with mode 0750. Back it up with `.env`
  ([Backup and restore](docs/operations/backup-restore.md)).
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
