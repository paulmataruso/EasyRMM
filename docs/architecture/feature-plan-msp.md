# Plan: twelve MSP features and a keystore

* **Status: planned; nothing built.** Draft 2 (2026-11-21), revised
  after an independent review. No ADR for any of the twelve or the
  keystore exists yet: each gets its own, reviewed before it is built.
  ADR-0063 (F0, below) is accepted and built (PR #N). This page was
  written from four surveys of `main` at `6f9fe99` (read only; nothing
  was run), the owner's requirements and the decisions below.
* **Scope**: the owner's requirements of 2026-11-21,
  [committed verbatim](requirements/2026-11-21-msp-features.md) and
  numbered as there:
  1. Hardware warranty and lifecycle management.
  2. Endpoint security posture monitoring.
  3. Visual automation engine.
  4. Customer documentation and asset records.
  5. Software catalog and deployment policies.
  6. Remote PowerShell management.
  7. Remote Windows registry editor.
  8. BitLocker management.
  9. Remote Windows event viewer and event log management.
  10. Hardware diagnostics and health monitoring.
  11. Scheduled maintenance tasks.
  12. Active Directory health monitoring.

  And a keystore for recovery keys, which the owner added afterwards.
* **Who decided what.** The owner decided, in their words: the keystore
  ("I think we should also create a highly secure keystore, to backup
  bitlocker keys for client devices as well"); that it holds LUKS keys
  too ("yah it can hold LUKS to thats fine"); and, on the twelve, "Add
  this to the plan, and start doing them one by one". Later the same day
  the owner decided that the keystore keeps its keys on the EasyRMM
  server and that interactive PowerShell uses MeshCentral's terminal ("So
  we just need to find a super secure way to store the keys on the
  EasyRMM server, and for powershell yes the Mesh one is fine"). The owner
  also asked whether warranty data can come from the vendors' own tools
  on the computer (feature 1 quotes it). Everything else
  below that is written as decided was **decided in review**, and the
  owner can overturn it; the [owner questions](#owner-questions) list
  what is still open.
* **Names.** Features keep the owner's numbers. F0 to F5 on this page
  are this plan's shared foundations. The [earlier plan](feature-plan.md)
  (ADRs 0052 to 0061) has its own F0 to F3 and features 1 to 9; this page
  names those by their ADRs (ADR-0057 for the job key ring, ADR-0058 for
  signed settings, ADR-0053 for notifications, ADR-0052 for the updater)
  and its steps as *earlier step N*.

This page says what exists for each feature, what is new, how it relates
to what exists and is planned, its slices, Windows and Linux, what it
waits for, its risks and what the owner has to provide. It ends with the
test harnesses, the [order](#order) of both plans together, and the owner
questions.

## How every feature is done

As in the earlier plan's
[How every feature is done](feature-plan.md#how-every-feature-is-done):
an ADR and an independent review first; slices that each merge and are
verified on their own, at every level they touch; the gates; CI green,
merge, and the owner's test instance upgraded; the docs. In addition:

* **Each ADR cites the requirements** by number and heading, says which
  bullets it covers, and lists the ones it leaves for later.
* **Every state is explicit.** The requirements ask, in several places,
  that healthy, unhealthy, unknown, unsupported and unavailable are kept
  apart, and that nothing reads as healthy because it could not be read.
  Every new reading carries its state and a reason.
* **No stand-ins for what can be run for real.** A test on an emulated
  disk, a virtual TPM or a VM's domain is named as such until the same
  test has run on real hardware or a real domain.
* **Windows paths say "unverified"** until the earlier plan's Windows
  harnesses exist, as that plan already requires.

## Shared foundations

Each is built by the first feature that needs it, inside that feature's
ADR, and reused by the others. None of them exists today.

### F0. Job output and arguments hidden from roles that should not see them
[ADR-0063](adr/0063-who-sees-job-output-and-arguments.md) is accepted
and built (PR #N). It fixes shipped code, so it comes before every
feature here. The hole below is what it closed.

* **The hole.** `job_runs` keeps the first and last 128 KiB of each
  run's standard output and error, in plain text, for 90 days
  (`EASYRMM_JOB_RETENTION`). Anyone with `job.view` at the device's site
  reads them, and the Read-Only role holds `job.view`
  (`server/internal/rbac/rbac.go:122-125`;
  `server/internal/jobs/jobs.go:636-664`). Reads are not audited. Job
  arguments are "shown to everyone who can see" the job
  ([scripts and jobs](../operations/scripts-and-jobs.md)). The agent's
  journal holds each run's full result on the device until it is
  reported (`agent/jobs/journal.go:25-31`).
* **Why it matters here.** A script that prints a secret, a BitLocker
  recovery password from `manage-bde -protectors -get` for example, hands
  it to every Read-Only user of the site today. Features 6, 7, 8, 9 and
  12 would each add more of that output.
* **What ADR-0063 decides**, not this plan: who reads output and
  arguments, whether reads are audited, and what the guide tells
  operators now. This plan needs one thing from it: a rule that F2's job
  kinds extend per kind, not a second mechanism beside it.
* Feature 6 has no slice of its own for "sensitive output must not be
  exposed": F0 is that slice.

### F1. One collector for platform facts
Used by features 1, 2, 8, 10 and 12. **Built in parts, each with the
first feature that needs it** (decided in review), so that no feature
carries facts it does not use:

| Part | Facts | Built with |
|---|---|---|
| The rules, and disks | Each fact's state (below); each disk's firmware revision | Feature 10's slice 1 (disk health) |
| SMBIOS identifiers | The type 1 SKU (HP's product number), family and version (where Lenovo puts the machine type and model) and UUID; the type 3 chassis type and asset tag | Feature 4's slice 2 and feature 1's slices 1 and 2 (the asset record, warranty, age by kind of device) |
| TPM and Secure Boot | TPM present, version and state; Secure Boot on, off, or not a UEFI boot | Feature 8's slice 1, the first of feature 8 and posture's P2 in the [order](#order); posture reads them |
| The domain-controller role | The role, with the domain's DNS name, its forest and the AD site | Feature 12's slice 1 |

* **What exists**: manufacturer, model, serial and BIOS from SMBIOS
  types 0 and 1 on Windows (`agent/inventory/windows_parse.go:39-46`)
  and `/sys/class/dmi/id` on Linux (`agent/inventory/inventory.go:64-71`);
  disks' model and serial. Nothing else in the table.
* **How**, for each part's ADR to settle: on Windows the existing
  `parseSMBIOS` gains the identifiers; on Linux the same parser can read
  `/sys/firmware/dmi/tables/DMI` (the agent runs as root). The agent's
  inventory uses no WMI and no PowerShell on Windows
  (`agent/inventory/windows.go:30-31`); feature 8's ADR says how TPM and
  Secure Boot are read within that rule or why it changes.
* **Slow facts only**, so they belong in the hashed inventory
  ([ADR-0018](adr/0018-inventory-and-telemetry.md)); readings that
  change by the minute (temperatures, counters) never do (feature 10).
  Every new field needs the server's `cleanInventory` to keep it in the
  same release (`server/internal/inventory/service.go:166-239`), and is
  sent only to servers at protocol level 2 or higher (ADR-0009, amended
  by pull request #52).
* **Each fact has a state**: read, absent, or could not be read with a
  reason. Today's rule, "what cannot be read is left empty"
  (`agent/inventory/collector.go:6-7`), would make an unreadable TPM look
  like no TPM.
* **One set of device facts, not three.** ADR-0053 plans the kind of
  device (`role`, from `InstallationType`), ADR-0060 a domain-controller
  flag (§The rest) and ADR-0054 a role in its results. The first two are
  fields of one set of device facts: ADR-0053, earlier in the order,
  adds the set, and F1's domain-controller part adds its field to it.
  ADR-0060 is amended to take the domain-controller flag from F1;
  ADR-0054's results keep the role its script sees on the computer.

### F2. Fixed-script job kinds whose results are hidden by kind
Used by features 7, 9, 12 and 8's actions. Built by feature 7.

* **The pattern exists**: the `software` and `hardening` kinds run a
  script of EasyRMM's own compiled into the server, with arguments the
  server checks against fixed lists and a structured last line
  (`EASYRMM-HARDENING-RESULT-V1`, `server/internal/jobs/hardening.go:41-50`).
  The agent does not change.
* **New per kind**:
  * **who reads the result**, a permission per kind on F0's rule
    (registry values and Security events must not reach Read-Only);
  * **how long it is kept**: minutes or hours for browsing, not 90 days,
    since results also go into backups;
  * **a compact audit**: one row per query (the path or filter and the
    count) and one per change (path, name, type, and the old and new
    data's size and SHA-256), within the audit log's 16 KiB of details,
    never one `device.script_run` per click;
  * **kept out of the Jobs list** by default.
* **On ADR-0054's amendments.** ADR-0054 amends ADR-0017 with its W2:
  a batch ID, retention per kind, one audit row per organization per
  batch, and runs the server can cancel. ADR-0054 is proposed and not
  started: no W1 code is on `main`. W2 comes before feature 7 in the
  [order](#order), so F2 extends those per kind and does not add a
  second set; if the order changes, whichever is built first builds
  them and the other extends them.
* **Limits that make browsing page**: each output stream keeps 128 KiB
  from each end, a structured result 64 KiB, arguments 32 of 1 KiB each,
  and EasyRMM's own scripts 512 KiB.
* **A lane on the agent.** The agent runs four jobs at once
  (`agent/jobs/worker.go:40`), shared with 30-minute hardening runs and
  installs, so a query can wait behind them. A reserved slot is an agent
  change listed as a feature under ADR-0009's protocol levels; feature
  7's ADR decides whether slice 1 needs it.
* **Not ADR-0059.** The WebSocket channel is wake-only and carries no
  work. On one server a job reaches a waiting agent in about 231 ms at the
  median ([drills](../development/drills.md)); PowerShell's start adds
  about a second, to be measured.

### F3. One scheduler
Used by feature 11, feature 3, feature 12's scheduled checks and feature
1's vendor lookups. Built by feature 11.

EasyRMM's server has no scheduler: only fixed tickers for sweeps and
evaluation. **F3 is the one scheduler for EasyRMM's new features**
(decided in review). What schedules today stays as it is: the patching
engine's schedules (patch windows, restarts, `scheduledAt`), in C# and in
its own database, and ADR-0054's planned daily check. Moving any of them
onto F3 would be a change to their own ADRs, not part of this plan.

* **Time zone**: the site's, else the organization's. Both columns exist
  (`server/migrations/00001_core.sql:63` for sites,
  `server/migrations/00020_one_set_of_organizations.sql:8` for
  organizations) and are validated as IANA names
  (`server/internal/tenancy/tenancy.go:166-172`); only patching uses them
  today. Never the device's clock.
* **Daylight saving**: ADR-0053's rules: lengths are elapsed time, a start
  in a skipped hour begins when the gap ends, a start in a repeated hour
  begins at its first occurrence.
* **Missed because the server was down**: an explicit policy per
  schedule, for example "run within a grace, else skip"; never a storm of
  catch-up runs after the server was down. ADR-0054's daily check does not
  catch up either.
* **Missed because a device was offline**: each occurrence's job waits for
  offline devices with ADR-0017's existing wait per job (1 hour to 7
  days), and never past the schedule's next occurrence, so occurrences do
  not pile up on a device. A device still offline then is recorded as
  *missed: offline* for that occurrence, never run late. A task set to
  *only if online* skips offline devices at once and records them as
  skipped.
* **No duplicates**: a unique key per occurrence and an advisory lock, as
  `monitoring.Evaluate` takes, so a restart or a second server never runs
  one occurrence twice.
* **Run as its owner.** Unattended work runs with its owner's permissions,
  checked again at every run under the target's tenant scope, and never
  as `access.System`, which holds every permission and sees every tenant
  (`server/internal/access/access.go:30-34`). The audit actor is the
  system, with the owner and the schedule. In detail (decided in review):
  * **At every run** the owner's EasyRMM account must be active and still
    hold the permission at the target's scope; otherwise the schedule
    pauses, with a notice, until it is handed to someone else or the
    owner is restored. **The limit**: an account that signs in through an
    identity provider and is disabled only there is not noticed until its
    EasyRMM account is deactivated too, since a schedule never signs in.
    The guide says so.
  * **The script is pinned**: the library script's SHA-256 is recorded
    when the task is saved. If the script changes, the schedule pauses
    until its owner confirms the new version, and runs never pick up an
    edit nobody confirmed for that schedule.
  * **Step-up and approval happen when the schedule is saved** (F5), and
    again when its owner confirms a changed script or a sensitive change
    to its targets or actions, since nobody is there when it runs.
* **Targets resolved when it runs**: organization, site, device group,
  device, with a platform filter; in batches of at most 500 devices,
  ADR-0017's bound on a job.

### F4. One set of maintenance windows per site
Used by feature 11 (and features 3 and 5 through it). Built by feature
11 on what ADR-0053 builds.

* **Three would exist otherwise**: the patching engine's windows in patch
  policy, ADR-0053's per-site windows (which only hold notifications,
  §Device alert rules, table `site_maintenance_windows`) and feature
  11's.
* **One instead, for EasyRMM's new features**: ADR-0053's windows, with
  their daylight-saving rules, gaining a purpose (hold notifications,
  allow tasks, or both). **ADR-0053's text is amended now**, in the same
  change as this plan ([ADR-0053](adr/0053-one-notification-sender.md),
  *Maintenance windows, per site*). Its slice 4 builds the table as
  written, where every window holds notifications; **feature 11's slice 2
  adds the column** when tasks first use windows, so it never sits unused.
* **Patch windows stay in patch policy**, as they are, and the console
  shows them beside the site's windows. Merging them is a change to the
  engine's contract, for later.

### F5. Approvals and step-up authentication
Who uses which part:

| Part | Used by |
|---|---|
| Step-up | The keystore's reads and export; feature 7's protected paths (slice 3); feature 8's actions (slice 3); feature 5's shared-level entries (only super administrators edit them, with step-up); features 11 and 3 when a schedule or an automation with sensitive actions is saved (F3) |
| Approvals | The keystore's optional two-person rule for reads; feature 11's sensitive tasks (slice 4); feature 3's sensitive steps (slice 3) |

* **Step-up is designed in
  [ADR-0055](adr/0055-lets-encrypt-in-one-step.md#step-up-authentication)**,
  §Step-up authentication, which calls itself the one definition (ADR-0057
  and ADR-0061 cite it). In short: a second factor confirmed within the
  last 5 minutes, recorded on the session as `stepped_up_at`; never a
  recovery code or a password alone; for an account that signs in through
  a provider trusted to enforce MFA, a fresh sign-in there. ADR-0055's
  slice 5b2 builds it. It is not on `main`: today there is only
  `reauthenticate`, a password check before an account's own security
  changes (`server/internal/auth/service.go:891-925`).
* **Approvals do not exist** in EasyRMM or its ADRs as a general
  mechanism: only enrolment approval (ADR-0024) and ADR-0053's approval of
  private destinations, each for its own purpose. **One general mechanism
  (a second authorized person approves within N minutes, never the
  requester) is designed in the keystore's ADR and always built in its
  reads slice** (decided in review), whatever the owner decides about the
  two-person rule, which is only one of its users. That slice comes before
  feature 11's slice 4 and feature 3's slice 3 in the [order](#order),
  which reuse it.
* **If step-up is late**: the keystore's reads wait for it. Building
  step-up alone ahead of 5b2 would change ADR-0055's slices and would be
  said so there.

### Notifications for every new alert kind
* **Through ADR-0053**, which is proposed and not built. Its rules' filter
  of conditions (offline, processor, memory, disk, *agent removed without
  a request*) gains each new kind, as ADR-0060 adds `log`. Until its slice
  4, new alerts show in the console only. In the [order](#order),
  ADR-0053 comes before the first new alert kind.
* **New kinds this plan adds** (each named in its feature's ADR): disk
  health, battery and hardware errors (10); warranty and hardware age
  (1); a device that no longer meets its security policy (2, which
  carries BitLocker's and LUKS's); AD health (12); an automation's own
  alert (3's *generate an alert*). Failed scheduled tasks and paused
  schedules (11), key reads and escrow problems (the keystore) are
  ADR-0053 *notices*, new kinds of those.
* **One alert per subject.** `alerts_active_key` allows one open alert per
  policy and device (`server/migrations/00006_monitoring.sql:118`), so two
  failing disks give one alert. Feature 10's ADR decides for all of them:
  the alert names every subject in its details, or the key gains a
  subject, which touches ADR-0053's incident key.

## The features

In the order they are built (see [Order](#order)).

### 6. Remote PowerShell management

**What exists.** About two thirds of the requirement is scripts and jobs
([ADR-0017](adr/0017-scripts-and-jobs.md)):

* multi-line PowerShell from the script library (up to 64 KiB), standard
  output and error kept apart, the exit code, timeouts from 1 second to 4
  hours with a job object ending what the script started, history for 90
  days, who ran it and when, an audit record per run with the script's
  SHA-256, signed delivery, and waiting for offline devices (1 hour to 7
  days) with a journal so an agent restart never runs a job twice
  (`server/internal/jobs/jobs.go:137-195`; `agent/jobs/exec_windows.go`;
  `web/src/pages/jobs/RunDetailPage.tsx`);
* interactive PowerShell through MeshCentral's terminal: the gateway
  allows its PowerShell protocols (`server/internal/remote/relayguard.go:36-42`),
  and each session's start is authorized (`device.terminal`) and audited,
  but what is typed is not recorded.

The gaps: only Windows PowerShell 5.1
(`System32\WindowsPowerShell\v1.0\powershell.exe`,
`agent/jobs/exec_windows.go:39`); output only when the script ends;
**Copy** but no download; library scripts only (ADR-0017: "Only library
scripts run; there are no ad hoc scripts in this phase"); devices picked
by hand, at most 500, no group as a target; and F0.

**What is new.**
* **PowerShell 7** found on the computer (machine-wide installs; a Store
  install is invisible to SYSTEM), reported with the agent's facts, a
  `pwsh` shell, and on each run the interpreter and its version
  (`$PSVersionTable.PSVersion`) recorded and shown. The shells' `CHECK`
  constraint is widened (`server/migrations/00007_windows.sql:7-9`).
* **Download** of output, per stream and per job.
* **Live output over the agent's existing HTTPS**: signed chunks posted
  during a run, a tail kept on the run, the console polling it; a cap on
  chunk size and rate. Not ADR-0059, which is wake-only and says "Full
  delivery: not now".
* **Interactive sessions reuse MeshCentral's terminal**, with a
  PowerShell entry point. No second interactive channel. Whether
  MeshAgent can start `pwsh` is unverified.
* **What is audited, honestly.** Requirement 6 asks that "All remote
  command execution must be auditable". That is met for jobs and for
  one-off commands: each is recorded with its body's SHA-256, who ran it
  and when. It is **not** met, command by command, for interactive
  sessions: MeshCentral's terminal records nothing that is typed, and
  EasyRMM audits only each session's start and who opened it. **The
  owner's decision** (2026-11-21): "for powershell yes the Mesh one is
  fine". Interactive PowerShell uses MeshCentral's terminal with
  session-level audit, and typed input is not recorded; the console and
  the guide say so.
* **One-off commands behind a new permission.** This reverses ADR-0017's
  library-only rule, and feature 6's ADR decides it: the permission and
  who holds it, whether an organization can turn it off, the body kept
  and hashed like a script's, and *Save to library*. A technician with
  `device.terminal` can already run anything as SYSTEM, so the gain is
  the audit record of what ran.
* **Elevation.** Jobs run as LocalSystem or root today, and the
  permission to run them is the authorization. Running as the signed-in
  user is new and risky, and left out of these slices.

**How it relates.**
* F0 covers "sensitive output must not be exposed": downloads and live
  output follow its rule.
* ADR-0060's slice 0 changes how Windows jobs start (inside their job
  object first), and its *Configure logging* turns on script block
  logging; feature 6's slice 1 touches the same code, so the two are
  coordinated.
* Group and site targets come from F3 (feature 11).
* ADR-0054 notes that Group Policy's `AllSigned` and Constrained Language
  Mode stop PowerShell jobs; the same is expected of `pwsh`, to be
  tested.

**Slices.**
1. **PowerShell 7 and the version used, and downloading output.** The
   smallest worth shipping alone: technicians can run their scripts in
   the PowerShell they write for and see which one ran.
2. Live output.
3. One-off commands behind the permission feature 6's ADR settles.
4. A PowerShell entry point into MeshCentral's terminal, audited per
   session as the owner decided; group, site and organization targets
   once F3 exists.

**Windows and Linux.**
* Windows: `pwsh` installed machine-wide only; the BOM and encoding as
  today; `AllSigned` and Constrained Language Mode stop jobs; EDRs and
  AMSI may block. A job for `pwsh` on a computer without it fails with
  that reason and never runs under 5.1 instead.
* Linux: `pwsh` optional as a shell; `sh`, `bash` and `python3` exist.
  Live output and download apply to every shell.

**Depends on**: F0. Nothing in the earlier plan.

**Risks**:
* live output from 500 devices multiplies database writes: caps on chunk
  size and rate, and the tail bounded;
* one-off commands let a permission holder write code: a permission of its
  own, the body kept and hashed, and the ADR's decision on ADR-0017;
* a script that prints secrets: F0;
* interactive sessions audited only at their start, as the owner
  accepted: said plainly in the console and the guide.

**Owner inputs**: none needed to start.

### 10. Hardware diagnostics and health monitoring

**What exists.**
* Processor model, sockets, cores and threads; BIOS vendor, version and
  date; manufacturer and model; total memory; each disk's name, model,
  serial, size and kind (`internal/agentproto/inventory.go:26-101`),
  shown on the device's Hardware tab. On Linux, SATA and SAS serials may
  be empty (the kernel exposes them as `vpd_pg80`): unverified, to check
  on a real SATA machine.
* **Nothing about health**: no SMART, NVMe, sensor, battery, thermal or
  hardware-error data in either agent or the server (the survey searched
  for each).
* Alert kinds are fixed at four, `offline`, `cpu`, `memory` and `disk`
  (space) (`server/migrations/00006_monitoring.sql:19`). Measurements are
  kept 7 days by default; inventory has no history
  (`IMPLEMENTATION_STATUS.md`, Not built).
* The agent runs as root on Linux and LocalSystem on Windows, so raw
  SMART, NVMe and DMI reads need nothing new.

**What is new** (decided in review):
* **Every value has an explicit state**: ok, warning, failing,
  unsupported or unreadable, with a reason. **Unreadable is never
  healthy**: a disk whose SMART could not be read says so.
* **No kernel driver.** On Windows, processor temperatures mostly need one
  (tools that show them load a ring-0 driver), so they show as "not
  exposed by this hardware".
* **smartmontools (GPL-2.0) is not bundled.** A Go SMART library is used
  only after the CI licence check passes it (ADR-0037).
* **Sensor values stay out of the hashed inventory**, so the inventory is
  not uploaded again every hour (up to 20,000 packages and 4 MiB): a
  health report of its own, the latest values kept and daily samples for
  history.

**How it relates.**
* F1: slice 1 builds only F1's first part, the rule that every fact has
  a state and each disk's firmware revision. The SMBIOS identifiers, TPM
  and Secure Boot come with features 1, 4 and 8; the device's hardware
  view shows them as they arrive, and feature 2 scores TPM and Secure
  Boot.
* Feature 9: WHEA, disk and Ntfs events are the same events. Feature 10
  keeps counts and the latest event per kind and links into feature 9.
* ADR-0060 would collect only Error-level events by default; corrected
  WHEA errors are warnings and fall outside it, and it has no hardware
  detection. Feature 10 does not wait for it.
* Feature 11: SMART self-tests, `chkdsk /scan` and the memory test are
  maintenance tasks; feature 10 schedules nothing itself.
* Feature 5: vendor firmware tools (Dell Command | Update and the like)
  are catalog entries; feature 10's firmware versions show where they are
  needed.
* Feature 12: a domain controller's hardware is feature 10's data.

**Slices.**
1. **Disk health, read-only, with F1's first part.** NVMe health logs
   and ATA SMART attributes on Windows and Linux, and temperature from
   Linux's `hwmon`.
   Per disk: a verdict, temperature, percentage used or wear, media
   errors, reallocated and pending sectors, power-on hours and firmware,
   each with its state. The health report apart from inventory; a column
   on the Disks card; one alert kind, `disk_health`, for failing or
   warning drives with thresholds for wear and temperature. First because
   it is the failure most worth predicting, works on both platforms and
   needs no driver.
2. SMBIOS details: memory modules (type 17), ECC (type 16), baseboard
   (type 2) and processor (type 4), through F1's parser.
3. Battery: design and full-charge capacity, wear, cycles and charging,
   and a `battery` alert kind.
4. Hardware errors as numbers: Linux EDAC counters and Windows WHEA event
   counts per kind, and a `hardware_errors` alert kind.
5. Thermal: Linux `hwmon`, thermal zones, fans and throttle counters;
   on Windows only what is exposed without a driver. **GPU temperature**
   (requirement 10) where the GPU's own driver already exposes it, with
   nothing of EasyRMM's installed: on Linux through `hwmon` where the
   kernel's driver publishes it; on Windows only if the display driver's
   interface gives it to a service (Task Manager shows it for some GPUs;
   whether the agent can read it that way is to verify). Everywhere else
   *unavailable*, never zero.
6. Trends: charts, degradation alerts (sectors reallocated, wear rising,
   capacity falling) and health columns in reports.

Later: hardware RAID controllers; servers' management controllers
(Redfish or IPMI), which hold a server's real sensor and disk data;
`smartctl --json` where an operator has installed smartmontools.

**Windows and Linux.**
* Windows: NVMe through `IOCTL_STORAGE_QUERY_PROPERTY` with Microsoft's
  inbox driver (some vendor drivers refuse); ATA through the SMART or ATA
  pass-through IOCTLs; batteries through `IOCTL_BATTERY_QUERY_INFORMATION`.
  No WMI needed.
* Linux: the NVMe admin ioctl, `SG_IO` with ATA pass-through for SATA,
  `hwmon`, `/sys/class/power_supply`, EDAC.
* Both: hardware RAID, USB bridges and VMs hide SMART; VMs and containers
  report *unsupported*, never failed.

**Depends on**: nothing in the earlier plan to build. Its alert reaches
email and webhooks through ADR-0053, which comes first in the order.
Turning readings off per organization would be ADR-0058 keys; slice 1
uses fixed defaults.

**Risks**:
* **false healthy**: every reading's state, tested with disks that cannot
  be read;
* **invisible disks** behind RAID and USB: expect many *unreadable* on
  servers until controller support exists, and say so in the console and
  the guide;
* **odd hardware**: read-only SMART commands only, never self-tests or
  writes, tested on real SATA, NVMe, USB and RAID hardware;
* **storage growth**: daily samples for slow counters and a retention
  setting like `EASYRMM_METRICS_RETENTION`;
* **licences**: smartmontools never bundled; any SMART library checked
  first.

**Owner inputs**: the test hardware (see [harnesses](#test-harnesses));
to confirm that processor temperatures are mostly unavailable on Windows
without a driver (decided in review).

### 4. Customer documentation and asset records

**What exists.**
* Organizations have a name, a time zone and plain-text notes (up to
  10,000 characters); sites a time zone, one free-text address and notes;
  device groups a name and a description
  (`server/migrations/00001_core.sql:48-83`).
* Devices have no notes, tags, custom fields or owner. Custom fields
  appear only in a comment on `device.edit`
  (`server/internal/rbac/rbac.go:30`).
* No contacts, business hours, assets, pages, attachments, rich text or
  full-text search. Editing notes needs `org.manage` or `site.manage`, so
  Technicians cannot. The audit log records that notes changed, not what
  they were, so they have no history.
* Row-level security already isolates organizations and sites.

**What is new** (decided in review):
* **Feature 4 owns the asset record.** Feature 1 adds the warranty fields,
  each with a source label, and the replacement history.
* **Assets outlive devices.** A device's removal cascades to its rows
  today ([ADR-0050](adr/0050-removing-a-device.md)); the asset's link to
  it is cleared instead, and the asset keeps the hostname and serial.
* **A device links to at most one asset, matched by serial.** Serials
  repeat between makers (and HP reportedly reuses its own), so the match is
  proposed with the manufacturer shown, and feature 4's ADR decides
  whether the manufacturer is part of the key.
* **Documentation tables** carry `organization_id` and an optional
  `site_id` with a composite foreign key to sites, as `devices` does, and
  the same row-level security; links never cross organizations, enforced
  by the database.
* **Revisions are append-only**, with author, time and an optional note;
  the audit log records each with the body's SHA-256, never the body.

**How it relates.**
* Feature 1 (the asset record's warranty part) and its history.
* Business hours sit next to ADR-0053's maintenance windows (F4), in the
  same time zone handling.
* Credentials: the requirements ask that they are not stored casually and
  that password managers are referenced. A page holds a reference
  (manager, vault, item), never the secret. The keystore is for recovery
  keys; the surveys recommend that it does not become a password vault,
  and feature 4's ADR decides.
* Calls to a password manager from the server, later, are destinations
  an organization owns, under ADR-0053's address policy.

**Slices.**
1. **Contacts, locations, hours, pages, revisions, search.** Contacts per
   organization and site (name, role, email, phones; primary, secondary
   and emergency); **structured locations** (requirement 4's "Customer
   locations and physical addresses"): each site's address as fields
   (street, city, region, postal code, country) beside today's free-text
   one, and places within a site (building, floor, room) that slice 2's
   asset record uses for its physical location; business hours per site,
   in its time zone; pages at
   organization or site level in sanitized Markdown or plain text, with
   every revision and its author; search within the caller's
   organizations; new permissions so that Technicians can edit; a warning
   when text looks like a secret (`password:`, a private key, an `ert_`
   token). No attachments, assets or secrets. Worth shipping alone: MSPs
   keep this today in a second product.
2. **The asset record**, built with feature 1's slice 1: assets with an
   agent and without one (switches, printers, UPSs), manufacturer, model,
   serial, location, status, assigned user, the device link and each
   field's source; history, replacement included; **pages linked to
   devices and assets** (requirement 4's "Associate documentation with
   customers, sites, devices, and assets"), within one organization, and
   shown on the device's and the asset's page.
3. Attachments and diagrams, with a size cap, served only as downloads
   (`Content-Disposition: attachment`, `nosniff`, a sandboxing content
   security policy), never inline on the console's origin.
4. Network documentation: subnets, VLANs, addresses (shown read-only from
   the inventory for managed devices), DHCP and DNS notes, ISPs and
   circuits.
5. Custom fields, as templates per type.
6. Restricted pages, with a permission of their own, and password manager
   references; integrations after.

**Windows and Linux.** Not platform-specific: everything is on the
server, so it stays available when a device is offline.

**Depends on**: nothing. Slice 2 is shared with feature 1.

**Risks**:
* stored cross-site scripting through rich text or attachments: sanitized
  Markdown, attachments never served inline;
* secrets pasted into pages: the warning, and references instead;
* database and backup growth, and longer upgrades, since the updater
  copies the data root before each one (ADR-0052): caps, and the storage
  decision in slice 3's ADR;
* search under row-level security: ADR-0060 found that an index drives a
  query only through leakproof operators, so whether a full-text index is
  used must be measured with `EXPLAIN` as the application's role;
* contacts are personal data of customers' staff: `PRIVACY.md` changes
  with slice 1;
* scope: this is a product category of its own; the slices stay tight.

**Owner inputs**: `PRIVACY.md`'s wording for contacts.

### 1. Hardware warranty and lifecycle management

**What exists.**
* Manufacturer, model and serial on both platforms; a Dell service tag is
  the serial. Not collected: the SKU (HP's product number), family and
  version (Lenovo's machine type), the UUID and the chassis (F1 adds
  them).
* **OS end of support exists in the patching engine**: an editable
  lifecycle table seeded for Windows, Debian, Ubuntu, the RHEL family and
  Fedora (`easypatch/backend/Core/Domain/LifecycleEvaluator.cs`), each
  endpoint's status with ESU, Settings → Patching → OS lifecycle with
  every change audited, an `OsUnsupported` alert rule (0 to 365 days
  before the end), and an OS support column in the Patch compliance
  report. Only for devices with the EasyPatch agent.
* No warranty fields, no editable device attributes, no outbound warranty
  integration. `PRIVACY.md` says the server's own connections send
  nothing about managed computers.
* The reports framework, with audited CSV
  ([ADR-0029](adr/0029-reports.md)).

**What is new** (decided in review):
* **The engine's OS lifecycle table is reused; there is no second one.**
  **EasyRMM shows OS support for every device**, not only those with the
  EasyPatch agent: its server evaluates its own inventory against the
  engine's one table, which it already reads
  (`server/internal/easypatch/client_settings.go:107`), by the engine's
  rules (`LifecycleEvaluator.cs`), with a contract test so that the two
  evaluations cannot drift. A device that also has the EasyPatch agent
  shows the engine's own result. Distributions the engine does not patch
  (Alpine, Arch, SUSE) are added to that table if they are needed.
* **What EasyRMM's agent must report for it.** Today it reports the OS's
  name, `10.0.<build>` and the build on Windows
  (`agent/host/system_windows.go:47-77`), and os-release's `ID` and
  `VERSION_ID` on Linux, which is what the engine's Linux rule takes. The
  Windows rule also needs `EditionID` (Home and Pro, Enterprise and
  Education, LTSC and IoT have different dates) and the product type
  (workstation or server): both are in the `CurrentVersion` registry key
  the agent already reads, where it uses `InstallationType` today only to
  tell servers apart. No WMI.
  Whether an ESU licence is present, which only the engine's agent
  detects, shows as *not known* on the others, and the end date says
  whether it assumes ESU.
* **The warranty fields live on feature 4's asset record**, each with a
  **source label** of four values:
  * **vendor API**: from the vendor's own service, verified;
  * **vendor tool on the device**: what a vendor's own program on the
    computer holds;
  * **firmware estimate**: a date the firmware records, as an estimate of
    the purchase;
  * **entered by hand**.

  A technician's correction is kept and labelled, never overwritten by a
  lookup. Whether a vendor tool's copy on the computer also counts as
  verified is decided in feature 1's ADR, once the research below is in.
* **On-device vendor data: researched from the vendors' documentation
  (2026-11-21), not yet tried on a real computer.** The owner asked: "Ok
  but dosent each vender have like a tool you can install on the computer
  that shows all the warrnety stuff? Can't we pull it from there?" For
  business PCs on Windows
  10 and 11, each of the three has a free tool that fetches the warranty
  from the vendor and writes it to WMI, where the agent can read it:
  * **Dell Command | Monitor** (10.2.1 and later):
    `root\dcim\sysman`, `DCIM_AssetWarrantyInformation`, with the start
    and end dates and when it last refreshed (every 15 days). Dell's own
    documents disagree on whether every version fills it, and Dell lists
    a bug in 10.13.2 and earlier for some systems.
  * **Lenovo Commercial Vantage** (10.2104 and later), with its policy
    *Write Warranty Information to WMI*: `ROOT\Lenovo`,
    `Lenovo_WarrantyInformation`. How often it refreshes is not
    documented.
  * **HP Client Management Script Library** (1.8.5 and later), whose
    `Get-HPWarrantyInfo` fills `root/HP/InstrumentedServices/v1`
    `HP_Warranty` only when it is run, with a 30-day cache and a limit
    per IP address. HP's licence forbids "commercial timesharing or
    bureau use", which could be read to cover an MSP: **EasyRMM does not
    run it until that clause has had a legal review** (an owner question).

  Firmware dates estimate the purchase where there is no warranty: HP's
  BIOS setting *Born On Date* (readable through HP's BIOS WMI with no
  tool) and Dell's ownership or first-power-on date (through Dell's
  tools). Lenovo, Surface, Acer, ASUS, Windows Server and Linux have no
  equivalent found: they need a vendor API or entry by hand. The agent
  only reads: it installs nothing by default and needs no vendor
  credentials. Installing Dell's tool or setting Lenovo's policy is the
  MSP's choice, offered as a script. Each value keeps the tool's
  last-refreshed time, so stale data shows as stale. A firmware date is
  only ever a start-date estimate, never an end date. The sources and
  their evidence are in feature 1's ADR. The first slice that uses them
  starts by checking each one on a real Dell, ThinkPad and HP. With this
  source, EasyRMM sends no serials anywhere itself.
* **Vendor APIs are opt-in and off by default**, starting with Dell,
  with each MSP's own key (Dell's terms forbid passing credentials on;
  EasyRMM never ships a key). **`PRIVACY.md` is updated before any serial
  is sent anywhere.** No scraping (Dell's and Lenovo's terms prohibit it)
  and no AGPL tools ([ADR-0037](adr/0037-one-licence.md)), which rules
  out the community lookup tools.
* **Status**: active, nearing expiration, expired or unknown; unknown when
  no source has a date.
* **Lifecycle**: age from the purchase, ship or warranty-start date (not
  the BIOS date, which changes with every update, nor the date EasyRMM
  first saw the device); replacement after N years by kind of device
  (chassis from F1, ADR-0053's `role`). No vendor publishes a
  machine-readable end-of-life feed for PCs, so end of life is the MSP's
  own policy.
* **Virtual machines** are skipped.

**How it relates.** Feature 4 (the record and its history), F1
(identifiers), F3 (scheduled lookups), the patching engine (OS
lifecycle), ADR-0053 (alerts; `role`), feature 5 (vendor update tools).

**Slices.** Slices 1 and 2 are built together with feature 4's slice 2.
1. **Entered by hand.** Purchase date, warranty start and end, type and
   notes on the asset record, each with its source; the status with a
   platform-wide "nearing" threshold; shown on the device; a **Warranty
   and lifecycle** report with CSV, by organization and site. Edits
   audited. Worth shipping alone: MSPs track warranties by hand today,
   and the four source labels are in the data from the first day.
2. **OS support and age**: the agent reports `EditionID` and the product
   type; OS support and its end date for every device, on the device page
   and in the report, from the engine's one table; age; replacement
   policies by kind of device.
3. **On-device vendor data and firmware estimates**: Dell's and Lenovo's
   WMI and HP's *Born On Date*, each first checked on a real computer;
   HP's warranty command only after its licence review. Before Dell's
   API, since it needs no key and sends nothing out.
4. **Dell's API**: per organization, off by default; the MSP's client ID
   and secret sealed; scheduled with F3, rate-limited and cached, plus
   *Look up now*; the vendor's raw answer kept; `PRIVACY.md` first.
   Lenovo and HP only if the owner decides they are worth it.
5. **Alerts**: `warranty` (days before the end) and `hardware_age`, through
   ADR-0053; 30, 60 and 90 days as three policies or one with reminders.
6. **History**: hardware changes recorded, assets linked across
   replacements, and kept when a device is removed (with feature 4).

Later: emailed and scheduled reports (an extension of ADR-0029 on
ADR-0053's mailer); an aggregator as a provider; lifecycle entries for
more distributions, possibly suggested from endoflife.date (MIT) or
Debian's `distro-info-data` (ISC).

**Windows and Linux.**
* Identifiers through F1 on both.
* OS support: the engine's table covers Windows, Debian, Ubuntu, the RHEL
  family and Fedora; Alpine, Arch and SUSE have no status yet and show
  *unknown*. On Windows, EasyRMM's agent gains `EditionID` and the product
  type in slice 2 (above).
* The vendor tools named above are Windows programs. Dell's Linux build
  of Command | Monitor lacks the warranty class; whether the kernel's
  `/sys/class/firmware-attributes` exposes Dell's and HP's firmware dates
  is unconfirmed.

**Depends on**: feature 4's slice 2, and F1's SMBIOS identifiers built
with it, for slices 1 and 2; F3 for slice 4's schedule; ADR-0053 for
slice 5.

**Risks**:
* **vendor access and terms**: Dell is self-service but had outages
  reported in 2026; HP approves each customer and has reportedly refused
  IT service firms; Lenovo gives a ClientID only through a representative.
  Hand entry always works, one provider per vendor behind one interface,
  every lookup cached and bounded, and a failing provider shows its error
  instead of blanking dates;
* **privacy**: serials leave only after an operator turns lookups on and
  `PRIVACY.md` says so;
* **identity across replacement**: a new motherboard changes the serial
  and UUID, a reinstall makes a new device; the asset record decides what
  counts as the same hardware;
* **on-device data** may be missing, stale or written differently by each
  vendor's version: it is labelled with its source and date.

**Owner inputs**: the Dell TechDirect key and real Dell machines; whether
HP and Lenovo providers are worth building; consent to send serials to
vendors and `PRIVACY.md`'s wording; default lifecycle years and
thresholds; whether endoflife.date may feed the engine's table; whether
Microsoft's lifecycle dates, kept by hand from Microsoft's pages as the
engine does today, are acceptable.

### 7. Remote Windows registry editor

**What exists.**
* No registry feature. MeshCentral has a registry view, and EasyRMM
  switches it off on purpose (`RightNoRegistry` in the restricted set,
  `server/internal/meshcentral/rights.go:16-19`).
* Today a technician reaches the registry through a SYSTEM terminal,
  remote desktop or a library script; only the session's start or the
  script run is audited.
* The agent's Go code already reads both registry views and lists the
  loaded user hives under `HKEY_USERS` (`agent/inventory/windows.go:283-307`).

**What is new** (decided in review):
* **The first slice is read-only.**
* **Refused paths.** `SAM` and `SECURITY` under the local machine are
  refused, and so is the `HKLM\SECURITY\SAM` link into them. Paths are
  matched without regard to case and in every spelling that reaches them:
  `HKLM\`, `HKEY_LOCAL_MACHINE\` and the native `\Registry\Machine\`.
* **EasyRMM's and MeshAgent's own keys are refused for reading too**,
  not only for writing, since they hold what the agents use to trust and
  reach the server; the ADR lists them.
* **`REG_LINK` is refused** on write and on import, so no one can create
  a link that leads past the refusals.
* **Enforced twice**: by the server's check of the request, and inside
  the fixed script on the computer, for browsing, search, export and
  import alike, so a path that slips past one is stopped by the other.
* **Writes always export the key first.**
* **MeshCentral's registry view stays switched off**, because EasyRMM's
  is audited.

**How it relates.**
* Feature 6 can already change anything the editor can; the editor adds
  structure, safeguards and a record per change. Its permissions are apart
  from `device.terminal`, so an MSP can grant reading without writing.
* ADR-0054 writes registry values where Group Policy would. An edit to one
  of them defeats hardening's undo for that value, and Group Policy
  reverts edits under `Policies` at its next refresh: the editor warns,
  using ADR-0054's ownership reader (`internal/winpolicy`, W1), and never
  writes beside a hardening apply or undo.
* F2 (built here) and F0.

**Slices.**
1. **Read-only browsing, with F2.** `HKLM`, `HKU` (SIDs named from the
   profile list), `HKCR` and `HKCC`; `HKCU` shown as each signed-in user's
   `HKU\<SID>`, since jobs run as SYSTEM; the 64-bit and 32-bit views,
   each labelled; keys, values, types (`REG_SZ`, `REG_DWORD`, `REG_QWORD`,
   `REG_BINARY`, `REG_MULTI_SZ`, `REG_EXPAND_SZ`) and data shown by type;
   access denied shown as such; the refusals above, on the server and in
   the script; the device named on every view; a `registry` job kind, a
   view permission and one audit row per query.
2. Export a key as a `.reg` download, size-capped, with the refusals.
3. **Writes**: create, change and delete values and keys, each after an
   automatic export; a typed confirmation; `REG_LINK` refused; other
   protected paths behind step-up (F5); the warnings above; a write
   permission; an audit row per change with the old and new data's
   hashes.
4. Bounded search; import with a preview of the differences; both with
   the refusals, `REG_LINK` refused in imported data.
5. Native agent queries instead of PowerShell, only if measured latency
   calls for them, still through the signed poll.

**Windows and Linux.** Windows only; Linux devices have no registry tab.

**Depends on**: F0, F2. Slice 3 on ADR-0054's W1 (its ownership reader)
and F5.

**Risks**:
* **SYSTEM sees past Windows' permissions**: as LocalSystem the agent can
  read `SAM`, `SECURITY` (LSA secrets) and secrets such as an autologon
  password. EasyRMM's own refusals sit on top of Windows' access lists;
  slice 1's ADR lists the values to refuse or mask;
* **leaks through job output**: F2's per-kind visibility and retention
  from slice 1;
* large keys exceed the job limits: paging and caps;
* EDRs may flag the script: its hash is published, as ADR-0054 does.

**Owner inputs**: none needed to start.

### 9. Remote Windows event viewer and event log management

**What exists.** Nothing on `main`.
[ADR-0060](adr/0060-collecting-logs.md) (proposed) plans collection of
filtered sources into a store of its own, fleet search, export,
forwarding and detections, a **Logs** page and a device's **Logs** tab,
with `log.view` (Site Administrators and above) and `log.view_sensitive`
(command lines and scripts; Organization Administrators from
organization-wide grants). By default it does not collect Setup,
Forwarded Events, other operational logs, or warnings and information
events; it keeps no raw XML, and drops the rendered message for the
Security log and sensitive events.

**What is new** (decided in review):
* **The "On the computer" mode of ADR-0060's Logs tab**, beside its
  *Collected* mode. It adds every channel the computer has, its whole
  local history (from before the agent, after retention, or with
  collection off), the original message and raw XML, and costs no
  storage: results are fetched, shown and dropped.
* **Who may query.** Technicians and above may query one computer's logs
  on demand, at their sites, **without the Security log and without
  sensitive fields**. The Security log and sensitive fields need
  `log.view_sensitive`, exactly as ADR-0060 defines it (Organization
  Administrators and above, from organization-wide grants). The reasons: a
  Technician can already read a computer's event logs through its
  terminal (`device.terminal`), as ADR-0060 itself notes; and this mode
  shows the original message and raw XML, which ADR-0060 drops for the
  Security log and for events with a sensitive field. ADR-0060 gives
  `log.view` (which also opens fleet search and history) only to Site
  Administrators and above, so on-demand queries get a permission of their
  own rather than lowering `log.view`. The owner is asked to confirm
  ([owner questions](#owner-questions)).
* **Sensitive fields: feature 9 builds the classification it needs**,
  ADR-0060's list by field name, now, rather than waiting for log
  collection (step 26 in the [order](#order)), which then reuses it. The
  server asks the computer for those fields only on behalf of a caller
  with `log.view_sensitive`; otherwise the fixed script leaves them out
  on the computer, and the server removes them again before it keeps the
  result.
* **Keywords are filtered after the query.** The XPath that Windows'
  event log accepts has no `contains()`, so IDs, levels, providers, task
  categories and time go into the XPath, and the fixed script then
  matches keywords against the rendered message and the event's data,
  within the query's maximum count of events read and its time limit,
  saying when it stopped at either.

**How it relates.**
* ADR-0060 keeps fleet search, detections, forwarding and history after a
  computer is gone. Feature 9 shares its classification of sensitive
  fields (built here first), `log.view_sensitive`, its summaries per event
  code and its audit of searches.
* Feature 3's "a Windows event is generated" uses ADR-0060's detections,
  not on-demand queries.
* Features 10 and 2 read the same events (WHEA, disk, Defender); the
  diagnostic presets are shared definitions.

**Slices.**
1. **On demand, one device, with F2.** The channels (records, size,
   enabled, access denied); a query over one or more by IDs, levels,
   providers, **task category** (requirement 9's "Filter by event
   category": the event's `Task`, named from its provider), and time,
   turned into XPath, and keywords filtered after it (above); newest
   first, in pages of about 100 with a continuation; details with the
   message and raw XML; *not found*, *access denied*, *offline* and *timed
   out* kept apart; an `eventlog` job kind; the on-demand permission,
   `log.view_sensitive` and the classification of sensitive fields; every
   query audited.
2. Diagnostic presets (unexpected shutdowns, bug checks, disk and storage,
   Windows Update, service and application crashes, authentication,
   drivers, WHEA, network); saved searches; export of selected or
   filtered events.
3. With ADR-0060: one tab with both modes; recurring IDs and trends from
   ADR-0060's counts per code.

**Windows and Linux.** Windows only. Linux's journal is ADR-0060's.

**Depends on**: F0, F2. It is built before ADR-0060 in the order, so it is
the first to add `log.view_sensitive` to the roles, exactly as ADR-0060
defines it, and ADR-0060's classification of sensitive fields; if
ADR-0060's review changes them, feature 9 follows. The raw XML of an event
with a sensitive field needs `log.view_sensitive` too.

**Risks**:
* **two permission models for the same events**: one classification and
  one `log.view_sensitive`, otherwise a Technician would read command
  lines ADR-0060 keeps for Organization Administrators. The on-demand
  permission is stricter than `log.view` about the Security log, since it
  shows what ADR-0060 drops;
* **large logs**: every query bounded by XPath, time and a maximum count,
  keywords included; the Event Log service's own CPU is outside any job's
  cap;
* result limits: pages.

**Owner inputs**: to confirm that Technicians may query a computer's logs
on demand without the Security log and sensitive fields (decided in
review).

### 8. BitLocker management

**What exists.**
* Nothing reads BitLocker. ADR-0054 (proposed, not started) plans a
  report-only `bitlocker` module for the **system volume only**: whether it
  is protected, by which protectors, the PIN policy, and whether a recovery
  password exists. No percentage, method, other volumes or suspension.
* Actions only through generic scripts with `script.run`, audited as a
  script run. Reading a recovery key by script is a leak today (F0).
* Linux: no LUKS code in `linux.sh`.

**What is new** (decided in review):
* **One per-volume BitLocker reader**, shared with feature 2 and with
  ADR-0054's `bitlocker` module. Per volume: BitLocker available (Server
  needs the feature and a restart; Home has only device encryption),
  encrypted against protected (Microsoft: device encryption with only
  local accounts is encrypted but unprotected), conversion status and
  percentage, method, protection status, suspended, protector kinds and
  IDs (not secret), volume type and a stable volume ID, and *needs
  attention*.
* **Read in the agent's Go code** (decided in review), through WMI's
  `Win32_EncryptableVolume` class called in the agent's own process, not
  through `manage-bde`, whose text is for people and changes with the
  language, and not through a script. The same code reads the recovery
  password for the keystore's escrow, which must never pass through a
  script (see [the keystore](#the-keystore-for-bitlocker-and-luks-recovery-keys)),
  so BitLocker has one reader. That is an exception to the rule that the
  agent's inventory uses no WMI, made for this one class: the inventory
  itself keeps the rule, and feature 8's ADR records the exception and
  checks the Go library it needs against the licence rules (ADR-0037).
* **LUKS detection alongside**: open `crypt` mappings, `/etc/crypttab`,
  which of root, `/home`, swap and data filesystems are not encrypted,
  and keyslots and tokens from `cryptsetup luksDump` (JSON on LUKS2).
  Volumes Clevis or a distribution's TPM scheme manages are *managed
  elsewhere*, never rewritten.
* **Alerts** for encryption turned off or protection suspended come from
  feature 2's single "noncompliant" event, not a second source.

**How it relates.**
* ADR-0054 is amended so that its `bitlocker` module takes its values
  from this reader's report on the server rather than reading BitLocker
  in `windows.ps1` (it keeps its STIG-cited checks, such as the PIN
  policy). W1 comes first in the [order](#order), so its check of
  `bitlocker` will exist; feature 8 moves it onto the shared reader, and
  BitLocker is never read twice.
* Feature 2's disk encryption control; F1's TPM and Secure Boot (built
  with slice 1); the keystore; F2 for the actions (fixed-script kinds).

**Slices.**
1. **BitLocker and LUKS status, read-only, with F1's TPM and Secure
   Boot.** Every volume, as above, on the device's page and ready for
   feature 2. No keys, no actions. Worth shipping alone: it shows which
   computers are not protected.
2. The keystore with escrow ([below](#the-keystore-for-bitlocker-and-luks-recovery-keys)).
3. Actions as F2 kinds: suspend, resume, encrypt and decrypt, with a
   permission of their own, step-up (F5) and guards; **encrypt is refused
   until a recovery key is escrowed and verified**, a TPM is present and
   the edition allows it; the recovery password rotated after a read.
4. The encryption report and history, through feature 2's history.
5. **Also backed up to AD DS or Entra ID** (requirement 8's "Identify
   missing or improperly backed-up recovery information"): whether a
   volume's recovery password is also backed up there, where the
   computer's own records show it (BitLocker writes events when it backs
   one up; which ones, and how far back they go, is for the ADR to
   confirm), shown as *backed up*, *not found* or *cannot tell*. EasyRMM
   reads no key from the directory or from Entra. Later, after slice 4.

**Windows and Linux.**
* Windows: Pro, Enterprise and Education; Server once the feature is
  installed; Home only device encryption. The class needs administrator
  rights, which LocalSystem has.
* Linux: LUKS1 and LUKS2; reading headers needs root, which the agent
  has.

**Depends on**: F0; F1's TPM and Secure Boot, built with slice 1; F2 for
the actions. Its keystore slice on F5 and ADR-0053.

**Risks**:
* **encrypting without a verified escrow locks data away**: refused;
* **encrypted is not protected**: both shown, never merged;
* editions and hardware without full support: *unsupported*, never
  *failed*;
* verifying it needs TPM VMs and real laptops (harnesses).

**Owner inputs**: test hardware (TPM laptops and LUKS VMs).

### The keystore for BitLocker and LUKS recovery keys

The owner's decisions: "I think we should also create a highly secure
keystore, to backup bitlocker keys for client devices as well"; "yah it
can hold LUKS to thats fine"; and that the keys stay on the EasyRMM
server: "So we just need to find a super secure way to store the keys on
the EasyRMM server". The rest of this section was decided in review.

**What exists.**
* `secrets.Sealer`: AES-256-GCM under **one master key**,
  `EASYRMM_SECRET_KEY` from `.env`, with a key ring for rotation and each
  value bound to its row (`server/internal/secrets/seal.go`). No keys per
  organization and no envelope.
* A reveal pattern: a sealed secret opened only in the transaction that
  writes its audit record (`server/internal/agents/tokens.go:164-212`;
  ADR-0047), and a rate limiter per key
  (`server/internal/auth/ratelimit.go`).
* **Backups put the master key beside the data.** The
  [backup guide](../operations/backup-restore.md#back-up) writes `.env`
  into the same folder as the database dumps, and says the two together
  "give full control of every managed device". ADR-0052's updater copies
  the data root and the deployment directory (`.env` with it) into one
  backup directory. A stolen backup set opens every sealed secret.

**What is new.**
* **Built into EasyRMM, with the keys on the EasyRMM server**, as the
  owner decided. **Every key provider is on the host**: no cloud KMS and
  no outside service. OpenBao stays a possible on-host option only if the
  ADR finds it adds something; it would not be bundled, since it starts
  sealed after every restart, which an unattended appliance and the
  updater's restarts cannot wait for.
* **The on-host protection is the ADR's choice.** The keystore's ADR
  chooses the most secure protection of the key-encryption key that works
  on the host. A research agent is comparing the candidates now (2026-11-21)
  and its findings go into that ADR; this plan names no winner. The
  candidates, which can combine:
  * a key-encryption key sealed to a TPM 2.0, physical or virtual;
  * a privilege-separated keystore process or container with no network,
    which holds the key-encryption key and does every unwrap, so the main
    server never holds it;
  * locked memory and no core dumps, so neither the key-encryption key
    nor an opened key reaches swap or a crash dump;
  * a passphrase or a split unseal (several people each holding a share)
    after a restart;
  * a USB HSM through PKCS#11.

  A plain file on the host, readable by the server, is not the end state;
  if any slice ships with it, it is named as a stand-in until the ADR's
  choice is built.
* **Encryption**: an HPKE (RFC 9180) key pair per organization. Each
  private key is wrapped by a key-encryption key kept **outside
  PostgreSQL and outside `.env`**. **Key-encryption keys are versioned**:
  each wrapped key records the version that wrapped it. Each record is
  bound to its organization, device, volume, protector and key version. A
  database dump, with or without `.env`, opens no key.
* **Escrow**: the agent reads the recovery password and seals it in
  memory to its organization's public key, and uploads it on **a signed
  agent route of its own, never as job output**, and never into its
  journal or logs.
  * **How the agent reads it** (decided in review): on Windows, feature
    8's reader in the agent's Go code calls `Win32_EncryptableVolume`'s
    `GetKeyProtectorNumericalPassword` through WMI in the agent's own
    process. Never a script: a PowerShell script's output would pass
    through a pipe, and Group Policy's PowerShell transcription, where an
    organization turns it on, writes every PowerShell session's output to
    files. The agent's inventory keeps its rule of no WMI; this one class
    is the exception, recorded in feature 8's ADR.
  * **How the agent gets its organization's public key** (decided in
    review): as a signed instruction in the heartbeat's answer, in the
    pattern the agent already verifies for an update, an EasyPatch
    install and an uninstall (`internal/agentproto/easypatch.go:150`):
    signed with the job key under a context of its own, bound to the
    device, the organization, the key's version and an expiry. The agent
    keeps the newest version it has verified and never goes back to an
    older one. It needs nothing from ADR-0058; once signed settings exist,
    the keystore's ADR may move the key there. It is a feature under
    ADR-0009's protocol levels, sent only to agents that announce it.
  * **Verified at upload** (decided in review): the server opens the
    sealed password in memory, never writing the plaintext anywhere,
    computes its fingerprint, and checks it against the protector ID and
    fingerprint the agent reported for the volume's current protector
    (feature 8's reader). A match is *verified*; a mismatch marks the
    escrow *stale* and the agent escrows again. **The server therefore
    handles plaintext in memory twice**: at this check, and at an
    authorized read. The ADR defines the fingerprint.
* **LUKS**: there is no recovery key to read. The agent generates one and
  enrols it in a new keyslot, which needs an existing unlock (a TPM2
  token or a key file the agent can use), tests it
  (`cryptsetup open --test-passphrase`), seals and uploads it, and wipes
  its copy once the server confirms. Nothing is removed before that.
  Afterwards escrow is checked by metadata only (the slot and its token
  still there, the slot's key-derivation parameters unchanged), since the
  key cannot be read back.
* **Reads**: a permission of its own; step-up (F5); a stated reason, kept
  in the audit record; rate limits per user and per organization,
  enforced inside the keystore too; the audit record written in the same
  transaction that opens the key; a notice to every super administrator
  (who and which device, never the key); and a two-person rule on F5's
  general approvals, which this slice always builds (whether the rule is
  required for every read or optional per organization is an owner
  question). Shown once, with `Cache-Control: no-store`.
* **Never** in logs, the audit log's details (forwarded as written),
  notifications, errors or job output. A test feeds a known key through
  every path and searches the outputs for it, as ADR-0053 does for webhook
  URLs.
* **Rotation of the key-encryption key**: a new version is made and
  backed up (below) before it wraps anything; then the organizations'
  keys are re-wrapped under it. **An older version is kept**, apart from
  the data, **as long as any retained backup holds keys wrapped by it**:
  its life is tied to the retention of the updater's backups and the
  backup guide's, and the console lists each version with the backups
  that still need it. The keystore's ADR says how a version is marked no
  longer needed and destroyed.
* **Rotation of a recovery password** shown to someone: it is replaced (a
  new protector added, escrowed and verified, then the old one removed: a
  volume is never without an escrowed protector).
* **Offboarding**: an organization's keys exported encrypted to a
  passphrase or a key the customer gives, behind step-up and audit, never
  through the reports' CSV. Deleting an organization destroys its wrapped
  key; that is final once every backup that holds it has expired and the
  key-encryption key versions only those backups needed are destroyed.

**The honest threat model.**
* **Super administrators and the host operator are trusted.** They can
  run anything on every managed computer already
  ([threat model](../security/threat-model.md)).
* **Anyone who can run scripts can read the keys of online devices**:
  `script.run` or `device.terminal` at a site reaches
  `manage-bde` on its computers. The keystore's permission does not change
  that. The owner is asked to accept it
  ([owner questions](#owner-questions)).
* **What the keystore protects**: the keys of **offline or stolen
  devices** (at the recovery screen, or gone), against **database dumps,
  backups and lower roles**; and it makes **every read visible**. The
  server handles a key's plaintext in memory at escrow's check and at a
  read (above).
* **What the on-host candidates change**, for the ADR to weigh:
  * **sealed to a TPM**: a copy of the disk or of a backup opens nothing
    without the host's TPM; root on the running host can still ask the
    TPM to unseal; the key-encryption key dies with the TPM unless a
    recovery copy exists;
  * **a separate keystore process**: a compromise of the main server
    process can ask for unwraps, which the keystore process counts,
    limits and records, but cannot take the key-encryption key; root on
    the host still can;
  * **locked memory, no core dumps**: nothing reaches swap or a crash
    dump; no help against a live attacker with root;
  * **a passphrase or split unseal**: a stolen or rebooted host opens
    nothing until people unseal it; restarts, the updater's included,
    leave reads and escrow checks waiting until then;
  * **a USB HSM**: the key-encryption key never leaves the device; whoever
    controls the host can still ask it to unwrap while it is attached.

**Backups.** The keystore's ADR separates the master key from the data in
every backup path: the backup guide and the updater (ADR-0052). Today the
guide's commands write `.env` into the same folder as the dumps, and the
updater's backup holds both. **Each key-encryption key version is backed
up when it is made**, offline as a recovery copy, never in the same set
as the database, and kept as long as the rotation rule above says. A
restore without the version its data needs starts with key reads turned
off and says so. After any restore, escrow is checked again on every
device, since the restored escrow may be older than the devices'
protectors. Reads recorded after the backup are lost unless the audit log
was forwarded (ADR-0023); ADR-0062, merged in pull request #77 (proposed,
not implemented), keeps audit IDs from repeating after a restore.

**How it relates.** Feature 8 (the reader, then actions), feature 2 (an
*escrow missing or stale* control), F0 (scripts leak keys today), F5,
ADR-0053 (notices), ADR-0057 (the job key signs what agents receive; a
compromised server could hand agents a substitute public key, but it could
already run code on them, so nothing changes), ADR-0052 and the backup
guide. Today's sealed secrets and ADR-0057's job keys could later move
under the same key-encryption key; that is a note for the ADR, not this
plan's scope.

**Slices.**
1. **The keystore and BitLocker escrow**: the on-host protection the ADR
   chooses, keys per organization, versioned key-encryption keys outside
   PostgreSQL and `.env`, the backup guide and the updater changed with
   them, the organization's public key as a signed instruction, escrow
   from the agent, verification at upload, and *escrow missing or stale*
   per volume.
2. **Reads**, once step-up exists: the permission, reason, rate limits,
   audit, notices; **F5's general approvals, always built here**, and the
   two-person rule for reads on them.
3. **LUKS escrow** where the agent can unlock by itself (a TPM2 token or a
   key file).
4. Rotation after a read (BitLocker, with feature 8's actions; LUKS, with
   guards that never remove the last slot or a customer's slot); the
   passphrase-only route once decided.
5. Offboarding export, and any further on-host protection the ADR keeps
   for later.

**Windows and Linux.**
* Windows: numerical passwords on Pro, Enterprise, Education and Server
  with the feature; device encryption on Home.
* Linux: LUKS2 with `systemd-cryptenroll` for tokens; LUKS1 gets a slot
  with no token, the slot number the only binding. The new key never
  appears on a command line, where other processes could read it. Volumes
  with only a passphrase cannot be escrowed by the agent alone (owner
  question). Every change to a LUKS header is tested on VMs first.
* **`systemd-cryptenroll` and its TPM2 tokens came with systemd 248**
  (to verify against each distribution's build, including whether it has
  TPM2 support). Of ADR-0051's distributions, Rocky Linux and AlmaLinux 8
  ship systemd 239, so on RHEL 8 the agent adds a slot with `cryptsetup
  luksAddKey` and no systemd token, and TPM unlock there is Clevis's,
  *managed elsewhere*. Debian 12 and 13, Ubuntu 22.04, 24.04 and 26.04,
  RHEL 9 and 10 and current Fedora ship later versions (Ubuntu 22.04's
  249 the oldest); each is verified on its VM before it is listed as
  supported.

**Depends on**: feature 8's reader, F5 (step-up, ADR-0055's 5b2), ADR-0053
(notices), F0.

**Risks**:
* **losing the key-encryption key** makes escrow useless, and a key
  sealed to a TPM or held in a USB HSM dies with it: a recovery copy of
  every version, and the backup guide's separate step;
* **a LUKS header written wrongly** makes data unreadable: no slot removed
  before the new one is stored and tested, never the last slot or one
  EasyRMM did not add;
* **the permission is undermined by device control**: said plainly in the
  console and the guide, as the threat model above;
* a restore older than the devices' protectors: escrow checked again;
* **the plaintext in the server's memory** at escrow's check and at a
  read: the on-host protection the ADR chooses (a separate process,
  locked memory) bounds where it can be.

**Owner inputs**: what to do with LUKS volumes protected only by a
passphrase; whether the two-person rule is required for every read; who
may read keys (a grant per user, or a role add-on); to accept that script
and terminal rights reach the keys of online devices.

### 2. Endpoint security posture monitoring

**What exists.**
* **Linux hardening, check only** ([ADR-0051](adr/0051-hardening-linux-computers.md)):
  14 modules with states (`in_place`, `partly`, `not_in_place`,
  `not_applicable`, `managed_elsewhere`, `not_supported`, `half_applied`,
  `failed`) and findings with a reason, what is missing and what apply
  would change; the last state only; a fleet column and filter; "N of M in
  place" in the console, unweighted
  (`web/src/pages/devices/hardeningText.ts:141-153`); results need
  `device.view`.
* **Patching compliance** from the engine, and the Patch compliance
  report.
* **Planned**: ADR-0054's Windows modules (firewall, Defender, attack
  surface reduction, UAC, RDP, SMB and others; report-only `audit`,
  `device-guard`, `bitlocker` and `laps`) and its daily check; ADR-0060's
  Defender detections.
* **Missing**: Secure Boot, TPM, BitLocker per volume, LUKS, local
  administrators and inactive accounts, Defender's signature age and last
  scan, an `unknown` or stale state, policies, history, a security report
  and a posture alert.

**What is new** (decided in review):
* **A view over three sources**: hardening's results (ADR-0051, ADR-0054),
  new report-only modules for state, and patching. No second reader of the
  same values and no second scorer.
* **One server-side weighted score**: weighted controls in place over
  weighted required controls. **Unknown or stale counts as not passing.**
  Today's "N of M" is the case where every weight is equal. The
  explanation is the list of failing and unknown controls with their
  reasons.
* **The states**: hardening's, plus `unknown` (no data, or older than the
  policy's freshness window); unsupported, not applicable, not in place
  and failed stay apart, as the requirement asks. A setting another owner
  manages passes or fails on that owner's value, as ADR-0054 defines.
* **Wording: "meets its security policy"**, never "compliant": ADR-0054
  forbids "compliant" about benchmarks (§Basis).
* **One "noncompliant" event**, emitted when a required control's state
  changes, which alerts, notifications and automation all use. BitLocker's
  and LUKS's controls go through it.

**How it relates.** ADR-0051 and ADR-0054 (the controls), feature 8 (disk
encryption), F1 (TPM, Secure Boot), feature 12 (feature 2 covers local
accounts, feature 12 directory accounts; a domain controller has no local
accounts but DSRM, so feature 2 treats them as not applicable), feature 3
(the event), ADR-0060 (its Defender detections are events; posture is
state), ADR-0058 (policies).

**Slices.**
1. **P1, from what exists**: hardening's results and patching under one
   vocabulary with `unknown` and stale; the score with its reasons; a
   fleet column and filter; a **Security** report with CSV. No new
   collection, and nothing from feature 8 yet. It reads hardening's
   results for every platform that has them: Linux's (ADR-0051), and
   Windows' once ADR-0054's W1 has merged, which in the [order](#order)
   comes first.
2. **P2**, report-only modules for Linux state: LUKS from feature 8,
   UID-0 accounts other than root, `sudo` and `wheel` members, and
   **accounts with insecure settings** (requirement 2's "Report on
   accounts with potentially insecure configurations": an empty password
   field, a password that never expires on an account that can sign in);
   TPM and Secure Boot from F1.
3. **P3**, Windows state: Defender's status (signature age, last scan),
   Security Center's products (workstations only), BitLocker from feature
   8, local administrators and inactive accounts, and **accounts with
   insecure settings** (a password not required or never expiring, the
   built-in Guest or Administrator enabled).
4. **P4**: policies at organization, site, group and device; history
   (state changes, append-only); the noncompliant event, its alert and
   notifications; **each policy's list of allowed administrators**, so
   that an administrator not on it is reported as unexpected (requirement
   2's "Identify unexpected or unauthorized administrator accounts").
5. **P5, recent threat detections** (requirement 2's "Recent threat
   detections"), from ADR-0060's Defender detections (*Malware found*,
   *Protection turned off*), shown in posture once log collection is
   built (step 26 in the [order](#order)), so this is a later slice.
   Posture stays state; the detections stay events.

**Windows and Linux.** Linux's checks exist. Windows waits for ADR-0054's
W1; Security Center exists on workstations only; domain controllers defer
accounts to feature 12.

**Depends on**: hardening's results; ADR-0054 W1 for Windows; feature 8's
reader and F1 from P2; ADR-0053 for notifications; for P4's group scope,
ADR-0058 gaining a group scope or a table of its own (its ADR decides);
ADR-0060 for P5.

**Risks**:
* **a second scoring system**, and BitLocker read three times: one
  vocabulary, one reader, one score;
* **a false sense of safety**: stale counts as not passing; encrypted but
  unprotected is shown as such;
* local account lists are personal data: a permission above `device.view`
  for them, as ADR-0060's `log.view_sensitive` is for command lines.

**Owner inputs**: to confirm the wording "meets its security policy"
(decided in review).

### 12. Active Directory health monitoring

**What exists.**
* Nothing knows a device is a domain controller: the inventory has no
  domain membership or role. Three proposed ADRs each plan the fact; F1
  builds it once.
* The generic `offline`, `cpu`, `memory` and `disk` policies, uptime and
  the OS version apply to domain controllers as to any device. No service
  monitoring.
* ADR-0060 plans lockouts (4740, off by default), failed sign-ins (4625
  per device) and privileged group changes; it collects 4771 and 4776
  failures but has no detection for them.

**What is new** (decided in review):
* **Feature 12 covers current state.** Events stay with ADR-0060's
  detections, and feature 12 adds **a detection for 4771 and 4776**
  (failures on domain controllers, per account across them) to ADR-0060's
  table, not a second mechanism.
* **What that detection changes in ADR-0060** (slice 4, by an amendment):
  ADR-0060's counted detections count per device, and
  `alerts_active_key` allows one open alert per policy and device. This
  one counts per domain and account, across every controller F1 names
  for that domain. So:
  * **the count** is keyed by the domain and the account, not the device;
  * **the alert's subject is the domain**, at organization scope, not one
    controller. Feature 10's ADR chooses, for disks, between naming every
    subject in one alert and giving `alerts_active_key` a subject; a
    domain belongs to no device, so this alert needs the subject either
    way, and alerts gain one that row-level security reads with the
    organization rather than a device's site;
  * **the alert names the domain, the count and the times, never the
    account**, since ADR-0060 keeps event fields out of alerts, which
    everyone who sees the subject sees; the account is in the linked
    events, behind `log.view`.
* **Checks run as SYSTEM on enrolled domain controllers.** There, SYSTEM
  acts as the controller's computer account, which can read the directory
  and its replication data, so no domain credentials are stored. Which
  checks pass as that account is measured in slice 1.
* **Never healthy by default.** A controller that cannot be reached, or
  whose clock is more than 5 minutes off so that its agent can no longer
  sign requests (`internal/agentproto/agentproto.go:44-45`), shows as
  **unknown**, never healthy.
* **Read-only, always.** A fixed, signed EasyRMM script, never a library
  script; nothing changes the directory.

**How it relates.** F1 (the role), F2 (the job kind), F3 (scheduled
checks), ADR-0060 (events, the new detection; it configures a
controller's audit policy only when chosen), feature 2 (local against
directory accounts), feature 10 (the controllers' hardware), feature 3
(service monitoring, built once for both), ADR-0054 (controllers are
opt-in for changes; feature 12 changes nothing).

**Slices.**
1. **Which device is a domain controller, and one health check on
   demand.** F1's domain-controller part, built here; an `adhealth` job
   kind run from the controller's page; replication partners with their
   last success and failures, FSMO holders, SYSVOL and NETLOGON with
   DFSR's state, the time source and offset, and critical services;
   **DNS**: SRV registration, the domain's name and each controller's
   records resolving through every DNS server the controller uses, the
   AD-integrated zones loaded and their replication scope, and the
   controller's own DNS settings (requirement 12's "Identify DNS
   configuration problems affecting domain operations": for example a
   controller that uses no other controller, or a public resolver, for
   DNS); **Group Policy processing** on the controller (requirement 12's
   "Identify Group Policy processing problems"): the GroupPolicy
   Operational log's errors since the last successful processing, and
   `gpresult`'s XML report, not its text, which changes with the
   language. Each finding `ok`, `warning`, `critical`, `unknown`,
   `not_applicable` or *could not run*, with its reason and the
   controller it concerns; a domain view per organization joining its
   controllers, results kept per run.
2. Scheduled checks (F3, in ADR-0054's daily-check pattern), an AD health
   alert kind, service monitoring shared with feature 3, notifications
   through ADR-0053.
3. Directory accounts: locked out, expired, passwords expiring, disabled,
   stale, and privileged group snapshots with their differences, behind a
   permission for directory data; counts and the first N, or pages.
4. Events through ADR-0060: lockouts, privileged changes and the new 4771
   and 4776 detection with ADR-0060's amendment above; the consolidated
   domain health report through the reports framework.
5. Several domains and forests, and controllers without an agent listed
   from the directory as *not managed*.

**Windows and Linux.** Windows Server domain controllers only. Samba's
domain controllers are not in these slices.

**Depends on**: F1's domain-controller part (built with slice 1), F2;
ADR-0054's W1 for the Windows machines under KVM where the pair of
controllers is built ([harnesses](#test-harnesses)); F3 for slice 2;
ADR-0053; ADR-0060 for slice 4.

**Risks**:
* **SYSTEM on a controller is domain-wide power**: the script is fixed,
  signed and read-only;
* **localized text** from `dcdiag`, `repadmin /replsummary`, `w32tm` and
  `netdom` breaks parsing on non-English Windows: cmdlets, CSV, WMI and
  the registry first;
* the ActiveDirectory module may be missing on Server Core: to verify;
* `lastLogonTimestamp` lags 9 to 14 days: "stale" says so;
* directory account lists are personal data: a permission of their own;
* a controller with a bad clock falls silent rather than reporting it:
  unknown, as above.

**Owner inputs**: the test domain (harnesses).

### 11. Scheduled maintenance tasks

**What exists.**
* **No scheduler** in EasyRMM's server. The engine's patch windows,
  restart schedules and `scheduledAt` (up to 31 days) are for patching
  only.
* Jobs on up to 500 devices picked by hand, waiting for offline devices,
  cancelled by hand. `job.manage` mentions "reschedule", which does not
  exist.
* Restarts only through the engine, for devices with the EasyPatch agent.
* Time zones on organizations and sites, used only by patching.
* Patterns: ADR-0054's daily check; ADR-0053's windows (planned, for
  notifications).

**What is new** (decided in review): **features 11 and 3 are one
engine.** A scheduled task is an automation with a schedule trigger and
one step; the **Scheduled tasks** page is a filtered view of the same
objects, with the same history, targets, windows, staggering and
approvals. Feature 11 builds F3 and F4, and comes first because it uses
every foundation without event triggers or branches. The engine's
schedules and patch windows, and ADR-0054's daily check, stay as they are
(F3).

**How it relates.** Feature 3 (the same engine), the patching engine
(patch windows; restarts go through it where its agent is linked, and
never twice for one device), ADR-0053 (windows, notices for failures),
ADR-0054 (the daily check; one change at a time on a device), features
10, 12, 1 and 5 (their scheduled work).

**Slices.**
1. **Scheduled script jobs**: once, daily, weekly, monthly or an interval,
   for a library script, pinned by its SHA-256; targets resolved at each
   run; the site's or organization's zone with ADR-0053's daylight-saving
   rules; both missed-run rules (the server down, a device offline, with
   ADR-0017's wait per job) and the occurrence key; run as the owner with
   the re-checks at each run; step-up when saved; pause, resume, edit and
   cancel; the upcoming list; history linked to the jobs it made; audit.
   Worth shipping alone: recurring scripts are what MSPs ask for first.
2. **Windows and pacing**: F4's windows, with **ADR-0053's purpose column
   added here**; *only in a window*, *only if online*, and staggering per
   site, so that an organization's devices never restart at once.
3. **More actions** as fixed-script job kinds on both platforms: software
   (ADR-0028), restart (through the engine where linked, else a new
   agent action), shutdown, and starting, stopping and restarting a
   service; exclusivity classes per device, ADR-0054's rule made general;
   **a restart's offline and online are expected** (as in feature 3's
   loop guards, with ADR-0053's planned restarts).
4. **Failure notices** (ADR-0053), retrying only what failed, and approval
   (F5's general approvals, built with the keystore before this) for
   sensitive tasks, given when the task is saved, with servers confirmed
   by name as the engine's restarts are and a dry run listing the
   targets.
5. A calendar and an execution report.

**Windows and Linux.**
* Windows: restarts through the engine (its prompts) or the agent; services
  through the service control manager; Windows Update's own restarts can
  collide with tasks.
* Linux: `systemctl` and `shutdown -r`; the time is always the site's or
  the organization's, never the device's clock.

**Depends on**: F3 and F4 (built here); ADR-0053's slice 4 (the windows'
table), its notices and its slice 7 (planned restarts); step-up (F5) from
slice 1; F5's approvals for slice 4.

**Risks**:
* **time**: daylight saving, a catch-up storm after downtime, two servers
  firing one occurrence, a device offline across occurrences: the rules
  in F3;
* **privilege**: never `access.System`; the owner's account and the
  script's hash checked at every run; an account disabled only at an
  identity provider runs on until EasyRMM's own account is deactivated
  (F3's stated limit);
* **fleet-wide restarts**: staggering, servers by name, approval and
  step-up, a dry run;
* **collisions with patching** (msiexec 1618, restarts in patch windows):
  exclusivity classes;
* **agent capacity**: four runs at a time, so a 4-hour task blocks
  others;
* more unattended work rests on a job key that cannot be rotated until
  ADR-0057 is built.

**Owner inputs**: none needed to start.

### 5. Software catalog and deployment policies

**What exists.**
* The `software` job kind ([ADR-0028](adr/0028-software-deployment.md)):
  install, update and uninstall by package ID through winget, Chocolatey,
  apt-get, dnf, yum or zypper. **The Windows scripts run on CI's Windows
  runner against stand-ins** (`server/internal/jobs/software_windows_test.go`);
  **no run has used a real winget or Chocolatey** (`IMPLEMENTATION_STATUS.md`).
* Installed software in the inventory, and its report.
* The engine's *Approved applications*: up to 100 winget IDs, updated in
  the patch window, never installed or removed.
* Building blocks: the agent's verified download for the EasyPatch agent
  (a signed instruction, size and SHA-256 checked, msiexec's codes
  mapped), the server's Authenticode reader, binaries stored in
  PostgreSQL up to 64 MiB, and *Install automatically* per organization
  as a precedent for enrolment.

**What is new** (decided in review):
* **The catalog is built in EasyRMM, on the existing `software` job
  type.** Not in the patching engine, which ADR-0046 and ADR-0048 are
  shrinking.
* **Hosted installers are pinned by SHA-256 and size, and by publisher
  where they are signed**, and checked again on the agent before they
  run. **"Publisher"** is the Authenticode signer of a signed MSI, EXE or
  MSIX. An unsigned EXE, a ZIP or any file without a signature is pinned
  by its hash and size only and **labelled *unsigned*** wherever it is
  shown or chosen.
* **Installers are never fetched as "latest" at install time.**
* **Each winget app has one updater**: the catalog or the engine's
  approved list, never both.
* **Who edits shared-level entries**: only super administrators, with
  step-up (F5), since a shared entry reaches every organization's
  computers. An organization's or a site's entries need the catalog's
  permission there.
* **Who may download a hosted installer**: only devices of the entry's
  organization, checked by the server on every download (any device for
  a shared entry), through a signed instruction that names the device, as
  the EasyPatch agent's download does.
* **Silent install and uninstall switches.** The `software` kind checks
  every argument against fixed lists and patterns
  (`server/internal/jobs/software.go:67-76` and `121-124`), and free-text
  switches fit neither. So switches belong to the catalog entry, never to
  a job: written only by someone who may edit that entry, kept as a list
  of separate arguments, and checked when saved against a set of allowed
  characters that leaves out what `cmd.exe`, a shell or PowerShell would
  act on (`&`, `|`, `<`, `>`, `^`, `%`, `` ` ``, `$`, `;`, line breaks).
  The fixed script receives them as one encoded argument and starts the
  installer directly, never through `cmd.exe` and never by building
  PowerShell code from them, so a switch can change only what that
  installer does, which whoever uploaded it controls already. How each
  installer type's command line is built from them (msiexec parses its
  own) is the ADR's to settle and test. Each job's audit record carries
  the entry's version, the installer's SHA-256 and the switches' SHA-256.

**How it relates.** ADR-0028, the patching engine (one updater), F3 and
feature 11 (scheduled installs), feature 3 (install and uninstall steps),
features 10 and 1 (vendor tools as entries), ADR-0057 (every delivery is
signed with the job key).

**Slices.**
1. **A catalog of package-manager entries** at shared, organization and
   site levels (shared ones by super administrators with step-up): name,
   vendor, description, platforms, source and ID, an optional pinned
   version; detection by a match in the inventory; deploying from the
   catalog as a `software` job; *installed* and *missing* per device.
   Worth shipping alone: a standard list instead of IDs typed by hand.
2. Bundles assigned to organizations, sites, groups or devices, kept by a
   reconciler on the server: missing software installed on enrolment and
   after inventory, with backoff; retrying only what failed; scheduling
   through F3.
3. Hosted installers, MSI first: upload with SHA-256, size and the
   Authenticode publisher pinned; signed delivery carrying the hash, to
   the entry's organization's devices only; **silent install and
   uninstall switches** as above; each uploaded version kept, so the
   entry lists the versions it holds; msiexec's codes, with **3010** shown
   as *installed, restart needed*, never as failed, the device marked
   *restart pending* and the restart left to a scheduled task or the
   engine's restart schedule, and **1641** as *installed, the installer
   restarted the computer*, its offline expected as a planned restart
   (ADR-0053); detection by ProductCode; then EXE, MSIX and ZIP (unsigned
   ones labelled), and DEB and RPM files.
4. Prohibited software and its reports; removal only when chosen.
5. Dependencies, enforced versions, **the newest version a package manager
   offers** for each package-manager entry (requirement 5's "Track
   available software versions"), read by a fixed query on a device of
   each platform, rollback where the installer allows it, and the
   one-updater rule with the engine.

**Windows and Linux.**
* Windows: msiexec's codes (0, 1641, 3010, 1603, 1618), each EXE's own
  switches, MSIX for all users, detection from the Uninstall keys in both
  views, per-user installs that SYSTEM cannot see, winget absent on Server
  2019 and 2022 for EasyRMM's script.
* Linux: local DEB and RPM through apt and dnf, repository packages,
  detection through dpkg and rpm, OpenPGP signatures.

**Depends on**: step-up (F5) for shared entries; F3 for slice 2; an
enrolment hook; the storage decision for slice 3; ADR-0053's planned
restarts for 1641.

**Risks**:
* **hosted installers run as SYSTEM**, so whoever uploads one, or edits
  its switches, has a script's power: audited with their hashes, a
  permission of its own, and shared entries for super administrators
  with step-up only;
* **switches that smuggle commands**: kept on the entry, checked against
  allowed characters, never passed through a shell (above);
* **supply chain**: community winget and Chocolatey sources; versions
  pinned where chosen;
* **storage**: today's limit is 64 MiB in PostgreSQL, and Office or Adobe
  installers are larger; slice 3's ADR decides where installers live and
  what that does to backups and the updater's copy;
* **unverified Windows**: the winget and Chocolatey scripts have run only
  against stand-ins on CI's Windows runner, never with a real winget or
  Chocolatey; the catalog inherits that until they have.

**Owner inputs**: none needed to start.

### 3. Visual automation engine

**What exists.** No workflow, trigger or event concept anywhere. Alerts
are the only signals; the job pipeline runs the actions that exist;
ADR-0053's journal of alert changes (planned) is the reliable source for
alert triggers. Devices cannot be moved yet, and there is no service
monitoring.

**What is new** (decided in review):
* **The engine of feature 11.** Feature 3 adds event triggers, several
  steps, conditions and branches to it.
* **Loop guards**: a causation ID carried on jobs, alerts and notices, so
  an automation never triggers itself; a depth limit, which *execute
  another workflow* counts; cooldowns per automation and device; and a
  check for cycles between automations when one is saved.
* **A restart's offline is expected.** A restart or shutdown step marks
  its device as restarting for that run, so the offline and online that
  follow carry the run's causation ID and fire no *offline* or *online*
  trigger. With ADR-0053's slice 7 (planned restarts: the agent's
  `stopping` notice and the restart grace), the offline alert does not
  open at all, so no alert trigger fires either. The same holds for a
  software step whose installer restarts the computer (1641, feature 5)
  and for feature 11's restart tasks, since the two are one engine.
* **Runaway guards**: bounds on steps, time and devices; quotas per
  organization; a kill switch per automation and one for all.
* **No *Device checks in* trigger** (requirement 3 lists it): refused.
  Every device checks in every 60 seconds
  (`server/internal/agents/service.go:27`), so at 2,000 devices it would
  start some 33 runs a second, unbounded by anything an MSP would set. What
  it is usually wanted for is covered by *comes online*, a schedule, and
  an alert opened.
* **Thresholds through alerts.** Requirement 3's "CPU utilization exceeds
  a configured threshold", the memory one and "Disk space falls below a
  configured threshold" are the alert trigger on ADR-0019's `cpu`,
  `memory` and `disk` policies, whose thresholds and durations already
  exist: the workflow names the policy, and the threshold is set there,
  in one place.

**How it relates.** Feature 11, ADR-0053 (journal, notices, webhooks for
tickets), ADR-0058 (settings as an action), ADR-0060 (Windows events as
triggers), feature 2 (the noncompliant event), feature 10 (*collect
diagnostics* runs its collection), feature 12 (service monitoring), F5.

**Slices.**
1. **Workflows on feature 11's engine**: manual and schedule triggers;
   steps in a line (script, software action, restart, service action,
   delay); stop or continue on failure; each step's result; history;
   enable, disable, duplicate; a restart's offline expected (above).
2. **Event triggers from what exists**: an alert opened or resolved
   (through ADR-0053's journal), the `cpu`, `memory` and `disk`
   thresholds among them, a device enrolled, offline and online, each
   with the loop guards.
3. Conditions and branches on step results and device facts; retries;
   templates at the shared level; approval (F5's general approvals, built
   with the keystore before this) for sensitive steps, given when the
   workflow is saved; three more actions: **execute another workflow**,
   within the depth limit; **generate an alert**, of an `automation` kind
   whose alert carries the run's causation ID, so it cannot start the run
   that raised it; and **collect diagnostic information**, which runs
   feature 10's health report and a chosen library script and keeps both
   with the run (feature 9's presets join in slice 4); the visual editor
   over the same model.
4. **Triggers and actions on later work**: notify and open a ticket
   (ADR-0053), change a setting (ADR-0058), a Windows event (ADR-0060), a
   patch failure (ADR-0053's slice 6), a device that no longer meets its
   security policy (feature 2's P4), a service stopping, a device moved
   (not built), and feature 9's diagnostic presets in *collect diagnostic
   information*.

**Windows and Linux.** Each step declares its platforms; event-log
triggers are Windows', the journal's and auditd's come with ADR-0060.

**Depends on**: feature 11; ADR-0053's journal and its slice 7 (planned
restarts); F5 (step-up when saved, approvals from slice 3); feature 10's
health report for *collect diagnostic information*; slice 4 on ADR-0058,
ADR-0060, feature 2's P4, feature 9's presets and moving devices.

**Risks**:
* **loops**: a restart raises offline and online; *generate an alert*
  fires an alert trigger; a workflow runs another; an install changes the
  inventory: the loop guards, and a restart's offline expected;
* **runaway work**: the runaway guards;
* **fleet-wide destruction**: staggering, servers by name, approval and
  step-up, a dry run;
* **privilege**: F3's run-as rule, with its limit for accounts disabled
  only at an identity provider.

**Owner inputs**: to confirm that *Device checks in* is not offered as a
trigger (decided in review).

## What this plan asks of the earlier ADRs

Most of these are proposed, and each is amended before the slice that
would otherwise build the other way. ADR-0017, ADR-0018, ADR-0019 and
ADR-0052 are accepted, so they gain amendments, as ADR-0054 and ADR-0060
already amend ADR-0017.

* **ADR-0053**: its maintenance windows gain a purpose (F4): **its text
  is amended in this change**, and the column is built by feature 11's
  slice 2, not by ADR-0053's slice 4; its conditions gain each new alert
  kind; new notices (failed tasks, paused schedules, key reads, escrow
  problems).
* **ADR-0054**: its `bitlocker` module takes its values from feature 8's
  reader; its job amendments (retention per kind, compact audit) are
  extended by F2, not repeated.
* **ADR-0060**: the domain-controller fact comes from F1; feature 9 adds
  `log.view_sensitive` and the classification of sensitive fields first,
  as written, and on-demand queries get a permission of their own;
  feature 12 adds a 4771 and 4776 detection counted per domain and
  account, with a subject on `alerts_active_key` and no account in the
  alert; its Logs tab gains *On the computer*.
* **ADR-0058**: a group scope, if feature 2's ADR puts its policies in
  signed settings. The keystore's public keys do not wait for it.
* **ADR-0052 and the backup guide**: every version of the keystore's
  key-encryption key kept apart from the data in every backup, and kept
  as long as a backup needs it.
* **ADR-0017**: output and arguments (F0, ADR-0063); kinds hidden by kind
  (F2); one-off commands (feature 6).
* **ADR-0018 and ADR-0019**: a health report apart from the hashed
  inventory (feature 10), and the new alert kinds.
* **ADR-0055**: none, unless step-up is built ahead of its slice 5b2.

## Test harnesses

As the earlier plan's [harnesses](feature-plan.md#test-harnesses-to-build),
with these for the twelve:

* **Windows Server and client VMs on KVM**: the earlier plan's *Windows
  machines under KVM*, which ADR-0054's W1 (not started) decides can run
  on CI or needs a self-hosted runner or recorded hand tests. Used by
  features 6 (with and without PowerShell 7), 7, 8, 9, 10's Windows paths,
  11, 12 and 2. A virtual TPM (swtpm) for BitLocker, as ADR-0054 plans.
* **A pair of domain controllers** for feature 12: one domain with two
  controllers replicating, built in the same harness from evaluation
  media; scenarios for a partner that is down, a clock more than 5
  minutes off, a stopped Netlogon or DFSR, a missing SRV record, and a
  Server Core controller; later a second domain. Then a real domain.
* **Dell hardware** for feature 1: real Dell computers with service tags
  and the owner's TechDirect key; and, for on-device vendor data, the
  vendors' computers with their tools, whichever the research confirms.
* **Hardware with SMART, NVMe and a battery** for feature 10: a laptop
  with a battery; SATA hard disk and SSD; NVMe on Microsoft's driver and
  on a vendor's; a USB disk; a server behind hardware RAID; an ECC machine
  with EDAC. Emulated disks in VMs test parsing and *unsupported* only and
  are named as stand-ins.
* **LUKS VMs** for features 8 and 2 and the keystore: LUKS1 and LUKS2,
  passphrase only, a key file in `/etc/crypttab`, a TPM2 token (swtpm),
  and Clevis, on ADR-0051's distributions, each one's systemd checked for
  `systemd-cryptenroll` and TPM2 support; every header change tested here
  before any real computer.
* **The keystore's host protection**: whichever on-host protection the
  keystore's ADR chooses is tested on the host it would run on (a virtual
  TPM stands in for a physical one, named as such; a USB HSM on real
  hardware), including a restart, the updater's upgrade and rollback, and
  a restore.
* **Real laptops with TPMs** for BitLocker, after the VMs.

## Order

Both plans together. The earlier plan's steps keep their order; no
dependency forces one to move, and none does. The twelve start now, one
at a time, in the order decided in review, as the owner asked to start
them. An earlier step that one of the twelve needs comes before that
feature, as late as it can while the earlier steps keep their order; an
earlier step none of them needs stays right after the earlier step it
followed (the updater's console behind notifications, packages behind
Let's Encrypt, the name move behind log collection).

**Where the earlier plan stands** (2026-11-21): step 3's Linux hardening
has H1 (#49) and H3 (#55) merged, and **H2, ADR-0051's apply and undo, is
being built now** on `feat/linux-hardening-h2`; step 4's updater 4a is
open as pull request #70; **step 5, Windows hardening (ADR-0054), is not
started**: the ADR is proposed and no W1 code is on `main`. Its W1, W2
and W3 are placed below by their dependencies.

**ADR-0053's slices 1 and 2 are built now, beside steps 3 to 9**
(decided in review, 2026-11-21): Microsoft turns password sign-in to
Exchange Online off by default at the end of December 2026, and an MSP
whose mail is Microsoft 365 then needs slice 2's sign-in with an
application, a relay, or basic authentication turned back on. Slice 1,
the mailer, is being built on `feat/notifications-mailer`; slice 2
follows it. Slices 3 to 7 stay at step 10.

The placement of W1, W2 and W3:

* **W1 needs** step 3's job kind, permission and console (H1 and H3,
  merged), CI's Windows runners, the decision on Windows machines under
  KVM with their domain, and a real Intune-enrolled Windows 11. **Needed
  by**, among the twelve: posture's Windows results (P1), feature 7's
  writes (the ownership reader), and the Windows machines under KVM that
  features 7, 8, 9 and 12 are verified on (feature 12's pair of domain
  controllers is built in that harness); and log collection (the
  ownership reader).
* **W2 needs** W1. None of the twelve needs it; its job amendments to
  ADR-0017 are what F2 extends (step 15).
* **W3 needs** W2 and H3's console. None of the twelve needs it.

So step 5 keeps its place in the earlier plan's order, before
notifications, as late as that allows: F0 and feature 6's slice 1, which
need nothing, go ahead of it.

| Step | Work | Plan | Why here |
|---|---|---|---|
| 1–2 | The earlier plan's steps 1 and 2 | Earlier | Unchanged |
| 3 | Linux hardening (earlier step 3): H2, apply and undo, being built now | Earlier | Unchanged; H1 and H3 are merged |
| 4 | Updater 4a with the edge channel (earlier step 4), open as PR #70 | Earlier | Unchanged |
| 5 | F0: ADR-0063, job output and arguments | This | A hole in shipped code, so before new features, as the earlier plan's fixes (its step 2) were; needs nothing |
| 6 | 6 Remote PowerShell, slice 1 | This | Small and independent; improves the job pipeline the rest use |
| 7 | Windows hardening W1: check, the ownership reader, the runner matrix and the decision on Windows machines under KVM (earlier step 5) | Earlier | **Not started.** Kept before notifications, as the earlier plan has it; needs and needed by: above |
| 8 | Windows hardening W2: apply and undo (earlier step 5) | Earlier | **Not started.** After W1; stays with it, as the earlier plan has it |
| 9 | Windows hardening W3: the console (earlier step 5) | Earlier | **Not started.** After W2 |
| 10 | Notifications: ADR-0053 with device alert rules, its slices 1 to 7 (earlier step 6) | Earlier | Before the first new alert kind (step 12), so each kind is built into its rules rather than added later; its windows are built without the purpose column, which feature 11 adds (step 22); its slice 7's planned restarts are what features 11, 3 and 5 rely on |
| 11 | Updater 4b: the console (earlier step 7) | Earlier | Needs only ADR-0053; stays right behind it; none of the twelve needs it |
| 12 | 10 Hardware health: disk health, with F1's first part (each fact's state; disks' firmware) | This | Needs nothing else; its alert reaches email through step 10 |
| 13 | 4 Documentation, slice 1: contacts, locations, hours, pages, revisions, search | This | Needs nothing |
| 14 | 4 and 1 together: the asset record (feature 4's slice 2) and warranty (feature 1's slice 1, entered by hand, and slice 2, OS support for every device and the age policy), with F1's SMBIOS identifiers and the agent's `EditionID` and product type | This | On F1's rules (step 12) and feature 4's pages and locations (step 13) |
| 15 | 7 Registry, read-only, with F2 | This | F2's first user, extending W2's job amendments (step 8); W1's ownership reader (step 7) is there for its later writes |
| 16 | 9 Event viewer on demand | This | Reuses F2; builds ADR-0060's classification of sensitive fields and `log.view_sensitive`, and its own on-demand permission |
| 17 | Let's Encrypt 5a, 5b1 to 5b4 (earlier step 8) | Earlier | 5b2 builds step-up (F5), which the keystore's reads need at step 19 |
| 18 | Packages (earlier step 9) | Earlier | Stays right behind step 17; none of the twelve needs it |
| 19 | 8 BitLocker and LUKS status, with F1's TPM and Secure Boot; then the keystore with escrow, reads and F5's general approvals | This | Reads need step-up (step 17) and ADR-0053's notices (step 10); approvals come before features 11 and 3 need them (steps 22 and 24) |
| 20 | 2 Posture, P1 | This | Reads hardening's results (Linux's from step 3, Windows' from W1 at step 7) and patching; no new collection, and nothing from feature 8 until P2 and P3 |
| 21 | 12 AD health, slice 1, with F1's domain-controller part | This | On F2 (step 15) and W1's Windows machines under KVM with their domain (step 7) |
| 22 | 11 Scheduled tasks, with F3 and F4 | This | Needs ADR-0053's windows, notices and planned restarts (step 10), step-up (step 17), and for its slice 4 the approvals (step 19) |
| 23 | 5 Software catalog | This | Its bundles use feature 11's scheduler and targets; shared entries need step-up (step 17) |
| 24 | 3 Automation, slices 1 to 3 | This | On feature 11's engine, ADR-0053's journal and planned restarts, feature 10's health report (step 12), and for its slice 3 the approvals (step 19) |
| 25 | ADR-0057, ADR-0058, ADR-0059 (earlier step 10) | Earlier | Before automation's settings action (feature 3, slice 4); in the earlier plan's own order |
| 26 | Log collection (earlier step 11) | Earlier | Needs W1's ownership reader (step 7); before the slices that read collected events (below) |
| 27 | Moving to a new name (earlier step 12) | Earlier | Stays right behind step 26; needs ADR-0057 (step 25) |
| 28 | The later slices of the twelve | This | In the order above, each when its ADR is accepted and its inputs exist (a Dell key, the research, hardware). Those that wait for steps 25 and 26: feature 3's slice 4, feature 9's slice 3, feature 12's slice 4, feature 2's P5 |

The interleaving is a decision made in review, not the owner's: it puts
F0 and feature 6's slice 1 ahead of the earlier plan's step 5, and the
earlier plan's steps 7 to 12 behind parts of the twelve. If the owner
wants the earlier plan finished first, the twelve follow its step 12 in
the same order, and only the dependencies above still hold.

## Owner questions

1. **Dell TechDirect**: a TechDirect API key on a Dell business account,
   and real Dell computers, to test feature 1's lookups.
2. **HP and Lenovo**: whether their providers are worth building, given
   that HP approves each customer and Lenovo gives keys only through a
   representative.
3. **Serials to vendors**: consent to send serial numbers to vendors when
   an MSP turns lookups on, and `PRIVACY.md`'s wording.
4. **Lifecycle defaults**: the replacement age for laptops, desktops and
   servers, and the warning thresholds (days before a warranty ends).
5. **OS lifecycle data**: whether endoflife.date may feed the engine's
   table (as suggestions, or by itself), and whether Microsoft's dates,
   kept by hand from its pages as today, are acceptable.
6. **LUKS volumes with only a passphrase**: the agent cannot add a slot
   without an existing unlock. Options: a technician types the current
   passphrase into a prompt through EasyRMM's terminal; the passphrase is
   sent to the agent encrypted to a key the agent holds (it has only a
   signing key today); or such volumes stay check only, shown as *escrow
   needs the current passphrase*.
7. **The two-person rule**: whether a second person must approve every
   recovery key read, or it stays optional per organization. The general
   approvals it uses are built either way (F5).
8. **Who may read recovery keys**: a grant to named users, or an add-on to
   a role.
9. **Test hardware**: the Dell computers above; for feature 10, the
   laptop, disks, RAID server and ECC machine listed under
   [harnesses](#test-harnesses); laptops with TPMs for BitLocker; and a
   real domain to check feature 12 on after the VMs.
10. **Decided in review, to confirm or overturn**: no kernel driver, so
    processor temperatures are mostly unavailable on Windows; the wording
    "meets its security policy"; no *Device checks in* trigger in feature
    3 (a device checks in every 60 seconds); the interleaving in
    [Order](#order).
11. **Contacts**: `PRIVACY.md`'s wording for customers' contacts (feature
    4).
12. **HP's script library licence**: whether its clause against
    "commercial timesharing or bureau use" allows an MSP's EasyRMM to run
    `Get-HPWarrantyInfo` on customers' computers. Until a legal review
    says yes, feature 1 reads only HP's *Born On Date* and what an MSP
    has already put in WMI itself.
13. **A ThinkPad and an HP business PC**, alongside the Dell above, to
    check the vendor tools' WMI on real computers before slice 3 is
    built.
14. **The keystore's limit**: to accept that anyone with `script.run` or
    `device.terminal` at a site can read the recovery keys of that site's
    online devices, through `manage-bde` or a script, whatever the
    keystore's own permission says. The keystore protects the keys of
    offline and stolen devices, against database dumps, backups and lower
    roles, and makes every read through EasyRMM visible; it cannot take
    that power back from those roles.
15. **On-demand event logs for Technicians** (feature 9): decided in
    review that Technicians may query a computer's logs on demand,
    without the Security log and sensitive fields, which need
    `log.view_sensitive`. ADR-0060 gives `log.view` only to Site
    Administrators and above; to confirm that on-demand queries may go
    lower, with a permission of their own.

## Risks across the twelve

* **Secrets in job output**: F0 first, then every new kind hidden by kind
  (F2), and recovery keys never through jobs at all.
* **False "healthy"**: explicit states everywhere; unreadable, stale and
  unreachable are never passing (features 10, 2 and 12).
* **Two of the same thing**: one lifecycle table (the engine's), one
  BitLocker reader, one set of device facts, one score, one engine for
  tasks and automation, one classification of sensitive event fields;
  one scheduler and one set of windows for EasyRMM's new features, while
  the engine's schedules and patch windows and ADR-0054's daily check
  stay as they are.
* **Unattended power**: schedules and automations run as their owner,
  never as the system caller, with the owner's account and the script's
  hash checked at every run; sensitive actions need step-up and approval
  when they are saved. An account disabled only at an identity provider
  is not noticed until EasyRMM's own account is deactivated.
* **Recovery keys on the server**: kept on the EasyRMM server as the owner
  decided, with the on-host protection the keystore's ADR chooses; the
  server sees a key's plaintext in memory at escrow's check and at a
  read; script and terminal rights still reach online devices' keys.
* **Proposed ADRs this plan builds on** (0053, 0054, 0055, 0058, 0060)
  may change in review; each feature's ADR follows them, and the
  amendments above are made in those ADRs, not around them.
* **Windows unverified** until the Windows harnesses exist: every Windows
  path says so.
