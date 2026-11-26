# ADR-0077: Managing Windows backup from the console

* Status: Proposed (2026-11-26). Design only; no code is changed by this ADR.
* Asked for by the owner (2026-11-26): "A module to control windows backup, we
  should have full managment over windows backup for both desktops and
  servers via our GUI". Those words are the only owner decisions here.
  Everything marked *decided in review* is the writer's call and the owner
  can overturn it.
* Builds on: [ADR-0073](0073-windows-management-modules.md) (the framework:
  the `winmod` job kind, `params` on standard input, the pinned script
  catalogue and its AST check, toggles, permissions, role detection, alert
  kinds and per-organization default policies, `devscope`), which this ADR
  follows except where *Amendments to ADR-0073* says otherwise;
  [ADR-0074](0074-defender-management.md) (the model for structure, risk
  tiers, the agent-side event reader and default policies);
  [ADR-0072](0072-what-each-page-shows.md) (where the tab appears);
  [ADR-0055](0055-lets-encrypt-in-one-step.md), section *Step-up
  authentication* (the one definition: a second factor within the last 5
  minutes).
* Amends: ADR-0073 (four points, below).

## Context

Windows has no single backup product. What a computer can be managed through
depends on its edition, and the owner's wish for "full management" for both
desktops and servers can only be met for one of the two. This ADR says which,
and builds that.

### What Microsoft documents (read on 2026-11-26; see References)

**Servers: Windows Server Backup (WSB).** A server feature with two
scriptable interfaces:

* `wbadmin.exe`: `enable backup`, `disable backup`, `start backup`, `stop
  job`, `get status`, `get versions`, `get items`, `get disks`, `start
  recovery`, `start sysrecovery`, `start systemstatebackup`, `delete
  systemstatebackup`, `delete catalog` and others. It must run elevated; a
  scheduled backup is configured by an Administrator, other tasks by a Backup
  Operator or Administrator.
* The `WindowsServerBackup` PowerShell module, for Windows Server 2016, 2019,
  2022 and 2025 (Microsoft publishes the reference for all four): policy
  (`Get-WBPolicy`, `New-WBPolicy`, `Set-WBPolicy`, `Remove-WBPolicy`,
  `Add-`/`Remove-WBVolume`, `-WBFileSpec`, `-WBSystemState`,
  `-WBBareMetalRecovery`, `-WBBackupTarget`, `Set-WBSchedule`,
  `Set-WBVssBackupOption`), state (`Get-WBSummary`, `Get-WBJob` including
  `-Previous N`, `Get-WBBackupSet`, `Get-WBBackupTarget`, `Get-WBDisk`,
  `Get-WBVolume`), actions (`Start-WBBackup` with `-Async`, `Stop-WBJob`,
  `Remove-WBBackupSet` with `-KeepVersions` and `-DeleteOldest`) and recovery
  (`Start-WBFileRecovery`, `Start-WBVolumeRecovery`,
  `Start-WBSystemStateRecovery`, `Start-WBApplicationRecovery`,
  `Start-WBHyperVRecovery`).
* `Get-WBSummary` returns the next scheduled backup, the last backup and the
  last successful backup; it, `Get-WBJob` and `New-WBBackupTarget` need
  Administrators or Backup Operators.
* The feature is **not installed by default**. The command is
  `Install-WindowsFeature Windows-Server-Backup`. Microsoft's pages found for
  that command describe Windows Server 2008 R2 to 2016, so that it still works
  on 2019 to 2025, and on Server Core, is **to confirm on a real server**.
* Network targets take a `PSCredential` (`New-WBBackupTarget -NetworkPath
  -Credential`); `wbadmin` takes `-user` and `-password` as command-line
  arguments. Microsoft warns that **a backup saved to a remote shared folder
  is overwritten by the next backup of the same computer to the same folder**,
  and that a failed run can leave no usable backup; its advice is sub-folders
  (which need twice the space). Adding a *disk* as a target **formats it and
  permanently erases what is on it**. `-vssFull` can break the incremental
  chain of another backup product; the default is a copy backup.
* `wbadmin start sysrecovery` "is only available if you are using the Windows
  Recovery Environment". A bare-metal or system recovery cannot be run from a
  running Windows.

**Desktops: three things, none a management interface.**

* The Windows 11 **Windows Backup** app (settings and folders to OneDrive) has
  no scriptable interface that Microsoft documents. For Intune-managed devices
  Microsoft documents an `EnableWindowsBackup` policy and a tenant-level
  restore setting; EasyRMM is not an MDM and does not touch these.
* **File History.** Its configuration object (`IFhConfigMgr`) "represents the
  File History configuration of the user under which the object is created":
  it is per user and needs that user's session, while the agent runs as the
  system. Group Policy has a "Turn off File History" setting. `fhmanagew.exe
  -cleanup <days>` removes old versions (a third-party report of an "Element
  not found" failure means this is not to be relied on). File History is
  **not** on Microsoft's list of deprecated features (checked 2026-11-26).
* **System Image Backup, "Backup and Restore (Windows 7)"**, is on that list,
  announced with Windows 10 version 1709 ("no longer being actively
  developed, and might be removed in a future update"). Microsoft's `wbadmin`
  pages describe servers and do not say whether `wbadmin` backs up a client;
  whether it does on Windows 10 and 11 is **to confirm on a real desktop**.

**Events.** The Windows Server Backup log is *Applications and Services Logs,
Microsoft, Windows, Backup, Operational* (channel `Microsoft-Windows-Backup`).
Microsoft's pages, written for Windows Server 2008 and 2008 R2, give: **4**
`BACKUP_SUCCESS_EVENT` ("Backup finished successfully"), **5**
`GENERIC_BACKUP_FAILED_EVENT` ("Backup started at '%6' failed with following
error code '%2'", with `HResult` and `DetailedHResult` in the XML node
`VolumesInfo`), **19** `BACKUP_FAILED_DID_NOT_START_EVENT` ("Backup attempted
at '%4' failed to start, error code '%5'"). **49** ("Backup failed as no
target could be found") comes from a search summary of Microsoft's page, not
a page this ADR read. Those pages predate Server 2016: whether the same IDs,
and a "completed with warnings" ID, are used on 2016 to 2025 is **to confirm
by a real run** (slice B1, step R1). File History writes to
`Microsoft-Windows-FileHistory-Engine` (log `BackupLog`) and
`Microsoft-Windows-FileHistory-Core`; the only ID found with a Microsoft
statement is **201** (Core provider, error, "unable to scan user libraries
for changes and perform a backup of modified files"). Meanings of other File
History IDs come from forum posts, not Microsoft, so no alert is built on a
File History ID other than by *level* and 201 (below).

### What exists today

ADR-0073 reserves the module, the `backup.view` and `backup.manage`
permissions, the `windows_backup` role and toggle (on by default), the
`backup_failed` and `backup_overdue` kind names, and the "Backup" tab.
ADR-0072 places it. Nothing else is built.

### What "full management" can and cannot mean

This is the ADR's central statement, and the console says it in the tab.

| | Server with WSB | Server without WSB | Desktop (Windows 10, 11) |
|---|---|---|---|
| See state, history, targets, space | yes | "not installed" | partly: events only (see below) |
| Configure schedule, items, targets | **yes** (cmdlets) | after installing the feature | **no**: nothing supported to drive |
| Run now, stop | **yes** | - | no |
| Restore files to a chosen place | **yes** | - | no |
| Delete old versions | **yes** | - | no |
| Install the feature | - | **yes** | - |
| Restore a volume, system state or bare metal | **no**, from the console (see Actions) | - | no |
| Alerts | **yes** | optional ("not configured") | failures and stale, quiet by default |
| The Windows Backup app (OneDrive) | - | - | **cannot be managed or read** |

So on **servers** the console manages the whole supported lifecycle except
whole-system recovery. On **desktops** it **watches and alerts but does not
manage**, because Windows offers nothing documented to manage: File History is
per user and the Windows Backup app has no interface. Where the console
cannot do something it shows the reason and, for what the owner may want to
change, the owner decisions below say how.

## Decision

### In short

1. One module, `windows_backup`, on ADR-0073's framework, with four
   permissions: `backup.view`, `backup.manage`, and two added by this ADR
   (`backup.view_sensitive`, `backup.destroy`).
2. State comes from the agent's event reader (last success and failure, no
   job) and an hourly `backup.status` read (next run, targets, space,
   versions); everything else is on demand.
3. Every action is a fixed script with typed parameters on standard input, in
   four risk tiers. Anything that erases, formats, overwrites, or stops
   protecting is tier 3 and needs a step-up.
4. Network-target credentials travel as a sealed secret in `params`, are
   never in a command line, never logged, and are never stored by EasyRMM.
5. Failures, a missing target and no recent backup become seven alert kinds
   and eight default policies that are quiet on laptops because they are
   scoped by device class and configured-ness.
6. Servers are managed; desktops are watched.

### 1. Identity, permissions and where it is offered

* **Module** `windows_backup`; toggle default **on** (ADR-0073 section 2).
* **Offered** on a device when the `windows_backup` role is reported (below)
  and the toggle and permission agree; otherwise 404.
* **Role states** (*amends ADR-0073 section 1*): the agent reports
  `windows_backup` as `{state, kind}` for every Windows computer.
  * Server (`ProductType` `ServerNT` or `LanmanNT`): `kind: "wsb"`, state
    `not_installed` (no `wbengine` service entry), `installed` (service
    present, no policy), `configured` (a policy exists; set from the hourly
    read, so a fresh install reads `installed` for up to an hour, which the
    UI never presents as a failure). ADR-0073 says a server reports the role
    only when `wbengine` exists, which would hide the install action on the
    servers that need it; that sentence is amended.
  * Desktop (`WinNT`): `kind: "client"`, state `events_seen` when either of
    the two logs holds a backup event in its retained history, otherwise
    `none`. A desktop with `none` offers only a short explanation card.
* **Permissions.**

| Permission | Holds | Gives |
|---|---|---|
| `backup.view` | Technician and above (ADR-0073) | state, last and next run, versions (times, sizes), job progress, alert history, target kind and free space, the schedule |
| `backup.manage` | Technician and above (ADR-0073) | tier 1 and tier 2 actions |
| `backup.view_sensitive` (new) | Site Administrator and above | target paths and share names, the account used for a share, included and excluded paths, restore source paths (these name customers and users) |
| `backup.destroy` (new) | Site Administrator and above | tier 3 actions |

  *Decided in review.* ADR-0073's table gives Technicians only `view` and
  `manage` ("reversible, low-blast-radius"). Running a backup, stopping one
  and restoring a file as a copy are; formatting a disk, deleting backups or
  switching protection off are not, so they need their own permission, as
  `defender.weaken` does. Read-Only has none. Each is checked at the device's
  site through `access`; the unions in `rbac.go` get a small additive edit.

### 2. State shown

Two sources (ADR-0073 section 5).

* **Facts, from the agent's event reader, no job.** On the role:
  `detail = {lastSuccess, lastFailure{time, hresult}, lastResult,
  running}`. The reader (section 7) updates these within a minute of a
  backup finishing. Cost: nothing while no event matches.
* **`backup.status`, hourly, a scheduled read** (ADR-0073 section 5 allows
  scheduled reads only for a value Facts lacks; these three are such):
  `nextRun`, `schedule` (times of day), `targets` (kind, label, free and
  total bytes where Windows reports them, online or not), `versions`
  (count, oldest, newest), and the policy's `items` and VSS option. It runs
  only while the module is on, the device is online, the role state is
  `installed` or `configured` and `modules.Allowed`. Windows returns this
  through `Get-WBPolicy`, `Get-WBSummary`, `Get-WBBackupTarget` and
  `Get-WBBackupSet`; the names of the properties of their results are not on
  Microsoft's reference pages, so the script maps by name at runtime and
  slice B1 pins the mapping from a real server.
* **On demand:** `backup.versions` (the backup sets), `backup.disks`
  (candidate target disks), `backup.job` (progress of the running or last N
  jobs, `Get-WBJob -Previous`), `backup.items_in_version` is **not** offered
  (browsing a backup mounts it; see Actions).
* **Freshness.** Status: 5 minutes shown, 1 hour refreshed; job progress: 5
  seconds while the tab shows a running job, only then.
* **A desktop** shows what the events say (last success, last failure, "no
  File History or system-image event seen"), an honest "not manageable"
  card for the Windows Backup app, and nothing else.

### 3. Actions

#### Risk tiers

| Tier | Meaning | Permission | Confirmation | Step-up | Audit |
|---|---|---|---|---|---|
| 0 Read | no change | `backup.view` (`view_sensitive` for paths, shares, accounts) | none | none | compact (ADR-0073) |
| 1 Routine | starts or ends work, no data lost | `backup.manage` | none | none | `winmod.windows_backup.<action>` with parameters |
| 2 Change | changes configuration or writes recovered data as a copy | `backup.manage` | `confirm: "<action>:<device name>"` | none | as tier 1 plus old and new value |
| 3 Destroy | erases, formats, overwrites, deletes backups, or stops protecting | `backup.manage` **and** `backup.destroy` | confirm naming the effect | **required** (ADR-0055: a second factor within 5 minutes) | as tier 2; the destroyed set listed |

Every tier-3 action refuses unless a step-up is recorded on the session
within 5 minutes, and is `Destructive` for ADR-0073's confirmation rule.

#### Catalogue

Every action is `{Module: windows_backup, Name, Version, Script, Params
schema, Result schema, Tier, Sensitive, Destructive, Timeout}` (ADR-0073
section 4). Scripts import `WindowsServerBackup` by name and report
`module_missing` if it is absent. Every action except `feature_install` and
`status` first checks `Get-WBJob` for a running job and returns `busy`
(WSB runs one operation at a time).

| Action | Does | Parameters (typed) | Tier | Timeout |
|---|---|---|---|---|
| `status` | state of section 2 | none | 0 | 60 s |
| `versions` | backup sets: time, volumes, items, recoverable kinds | optional target | 0 | 60 s |
| `disks` | candidate disks and volumes (`Get-WBDisk`, `Get-WBVolume -AllVolumes`) | none | 0 | 60 s |
| `job` | the running job's progress, or the last N | `previous` 0 to 20 | 0 | 30 s |
| `run_now` | `Start-WBBackup -Policy (Get-WBPolicy) -Async` using the **configured** policy and the copy-backup default; returns at once, progress by `job` | none | 1 | 60 s |
| `stop` | `Stop-WBJob` for a backup | none | 1 | 60 s |
| `stop_recovery` | `Stop-WBJob` for a recovery (may leave partly restored files) | none | 2 | 60 s |
| `policy_set` | build a policy and `Set-WBPolicy`: schedule, volumes, file specs, system state, bare-metal items, exclusions; **replaces** the current one | schedule times, items, flags (below) | 2 | 120 s |
| `target_network_set` | network share target with an account; to an existing policy or a new one | UNC path, account, password (secret), `subfolder` (required) | 2 | 120 s |
| `target_volume_set` | an already-formatted local volume (drive letter or volume GUID) | volume | 2 | 120 s |
| `target_disk_set` | a whole disk as a target: **Windows formats it** | disk number and a serial or id, label | **3** | 300 s |
| `vss_full_set` | `-vssFull` instead of the copy default | on or off | **3** | 60 s |
| `policy_remove` | `Remove-WBPolicy`: protection stops | none | **3** | 60 s |
| `restore_files` | `Start-WBFileRecovery -Async` of paths from a backup set to a **different** folder, `CreateCopyIfExists` | version id, source paths, target folder, recursive | 2 | 60 s, then by `job` |
| `restore_files_overwrite` | the same to the original place, `OverwriteIfExists` | as above | **3** | 60 s |
| `versions_prune` | `Remove-WBBackupSet -KeepVersions N` or `-DeleteOldest -Force`, after a preview that lists the sets | `keep` (1 to 365) or `oldest` | **3** | 300 s |
| `feature_install` | `Install-WindowsFeature Windows-Server-Backup` (and a rescan of roles) | none | **3** (a server change) | 600 s |

*Plain limits, decided in review:*

* **No volume, system-state, application or bare-metal recovery from the
  console.** Microsoft says a system recovery runs only from the recovery
  environment; a volume recovery of a volume in use, a domain controller's
  system state (which needs Directory Services Restore Mode) and Hyper-V
  recovery stop or replace running systems and cannot be made safe by a
  remote button. The console shows the backup, its recoverable kinds and
  the command to run at the recovery console. No action is added to the
  catalogue for them; a later ADR may add one with its own risk analysis.
* **No browsing inside a backup.** `Get-WBBackupVolumeBrowsePath` mounts a
  volume of the backup as a share. v1 restores by a path the operator types
  and reports "not found in this version" from the recovery's result. A
  browse tree is a follow-up.
* **`target_disk_set` is the only way a disk is chosen**, and the request
  must repeat the disk's identity read by `disks` within the last 5 minutes;
  a mismatch is refused (no formatting the wrong disk after a disk
  renumbering).
* **A backup is a copy backup unless `vss_full_set` is on.** The dialog says
  Microsoft's caution: a full backup can break another product's incremental
  chain.
* **A share target must name a sub-folder** (`subfolder` is required, the
  UI proposes `<computer name>`), and the dialog states that without one the
  next backup overwrites the last and that a failed run can leave none
  (Microsoft's wording). *Decided in review.*
* **`versions_prune` never deletes the last version**: `keep` is at least 1,
  and the script refuses when it would leave none. It lists the sets it
  would remove in a typed result *before* a second, confirmed call removes
  them (no `-WhatIf` is assumed to exist for it).
* **`restore_files` cannot target a system folder or the source folder.**
  The target is checked for absolute path, no `..`, no device path, and not
  under `%SystemRoot%`; the default target is
  `<volume>:\EasyRMM-Restore\<timestamp>`.

Parameter validation is the framework's (ADR-0073 section 4): paths absolute,
no `..`, no device or `\\?\` paths except `\\?\Volume{GUID}\` for volumes,
UNC paths `\\server\share[\sub]` with allowed characters and at most 260
characters, schedule times `HH:MM`, at most 6 per day, versions by their
`MM/DD/YYYY-HH:MM` identifier or GUID read from `versions`. User values reach
cmdlets only as argument values.

#### Credentials for network targets

* The account name is an ordinary parameter. The **password is a sealed
  secret** (ADR-0073 section 4, *Secrets*): sealed with the server key, held
  at most 10 minutes, delivered once inside the signed `params`, deleted on
  delivery.
* The script builds the credential in memory
  (`ConvertTo-SecureString -AsPlainText -Force`, which the AST check allows
  for this one named secret parameter and nothing else) and passes it to
  `New-WBBackupTarget -Credential`. **`wbadmin -password` is not used**: a
  command-line argument is visible to every process listing and to
  command-line audit logs.
* The server and the agent never keep it: `jobs.args`, `jobs.body`, audit,
  logs, results and `winmod_job_secrets` after delivery hold no password
  (ADR-0073's grep test is extended with this action). The script's result
  carries `credentialSet: true`, never a value.
* Windows Server Backup stores the credential inside its own policy; it is
  not readable back, so the tab shows the account (sensitive) and "password
  set", and a password change is a new `target_network_set` call.
* The share's own permissions (who can read the backups) are Windows'
  business; `-NonInheritAcl` applies only to one-time backups (Microsoft)
  and is not set for the scheduled policy.

### 4. Where it sits (ADR-0072, ADR-0073 section 7)

* **Device, "Backup" tab** (`backup.view`): panels *Status* (last, next, the
  job running with progress), *Schedule and items*, *Targets and space*,
  *Versions*, *Restore*, *Events*, and for a desktop a single *What Windows
  allows* card. Each panel is a component and one row in the tab registry.
  Buttons carry their tier and show the reason when disabled (offline, busy,
  feature not installed, no permission).
* **Group:** a "last backup" column and filter from Facts.
* **Site:** a Backup card on Overview (counts from Facts: backed up in 24
  hours, failed, overdue, not configured) and the "Windows modules" toggle.
* **Organization:** the same card and a fleet table (device, kind, last
  success, last failure, open Backup alerts). Cards never send a job.

### 5. Server Core, servers and desktops

* **Servers (2016 and later).** Full set. A domain controller gets the same
  module; the system-state item is offered only as a *backup* item. Nothing
  promotes or demotes a server.
* **Server Core.** WSB cmdlets and `wbadmin` are the only interface there
  (Microsoft's guidance for 2012 Core), and the module needs no desktop
  session, so it should work; `feature_install` on Core is
  `Install-WindowsFeature`. **Not verified on Server Core**; slice B11 says
  so until R10 is run.
* **Desktops.** Visibility and alerts only, plus the explanation card. No
  action in the catalogue targets a `WinNT` computer, and the server refuses
  any with `not_offered`. If the owner wants more (decisions 1 and 2), they
  are separate follow-ups, each needing its own real-device confirmation.

### 6. Alerts

#### How events reach the server

*Reuses ADR-0074 section 7*: the agent-side reader (`agent/winevents`,
whichever of the two lands first creates it) with a bookmark, deduplication
by `(device_id, record_id, log_created)`, acknowledgement in the heartbeat
answer, first-run backfill (events under 60 minutes old open alerts, older
ones are stored only), `gap` on a wrapped log, aggregation of storms,
and "off means off". Differences:

* **Channels and IDs.** `Microsoft-Windows-Backup` with IDs 4, 5, 19 and 49
  (the set of section *Context*; others only if a real run on 2016 to 2025
  shows more, R1), and for File History, the Engine
  `BackupLog` and the Core provider with a **level filter** (Error and
  Critical) plus ID 201. **Every 5 minutes** (not every minute),
  because backups are slow and a failure is not urgent to the minute.
* **Fields** kept (1 KiB per event): ID, record ID, time, `HResult` and
  `DetailedHResult` from `VolumesInfo` (error codes only), the start time in
  event 5 and 19. Volume names and paths go in a separate `sensitive` object
  shown only to `backup.view_sensitive`.
* **Policy answer.** The heartbeat answer's per-module policy block gains a
  `backup` entry (`enabled`, `events`, the day it was last answered), exactly
  as `DefenderPolicy` gains `events` in ADR-0074; the reader stops when it
  says off or the organization is not allowed.
* **Storage.** Migration `server/migrations/9xxxx_backup.sql` (number from
  the integrator; goose up and down, down working): `backup_events`,
  retention 90 days. No backup content, share credentials or file names
  are stored.

#### Alert kinds

Registered per ADR-0073 section 6 (name, label, module `windows_backup`,
parameters, value source). Seven kinds:

| Kind | Source | `threshold` means | `minutes` means | Opens on | Resolves on |
|---|---|---|---|---|---|
| `backup_failed` | events 5 and 19; File History errors | unused | unused | a failure; subject = the product (`wsb` or `filehistory`) | event 4 after it (WSB), or a later success the status read shows; for File History when no error has been logged for 7 days (*decided in review*) |
| `backup_overdue` | Facts `lastSuccess` | days without a success | unused | `now` minus the later of `lastSuccess` and **the time the device last came online** is at least the threshold | a success |
| `backup_target_missing` | event 49; status `targets[].online` | unused | grace in minutes | the target is not found or offline for the grace | the target comes back |
| `backup_target_low_space` | status `targets[].free` | percent free | unused | free space below the threshold | above it |
| `backup_not_configured` | role state | unused | unused | a server has WSB installed with no policy for the grace | a policy exists |
| `backup_not_installed` | role state | unused | unused | a server without the WSB feature | the feature appears |
| `backup_stuck` | status/`job` | unused | minutes | a backup job running longer than `minutes` | it ends |

* **The "online" rule is the answer to laptops.** `backup_overdue` counts
  from the time the device last came online (the monitoring engine already
  tracks that for `offline`), so a laptop that was closed for a week is not
  "overdue" the moment it opens; it has until the threshold after it wakes.
* **Applicability (amends ADR-0073 section 6).** A kind declares `AppliesTo`
  (`any`, `server`, `workstation`), and a policy may carry an optional
  `deviceClass`; the evaluator skips a device of the other class and
  resolves with `not applicable`. A device where the module is off, the
  role state is `none`, or backup is not `configured` raises nothing
  (except `backup_not_configured` and `backup_not_installed`, which exist to
  say exactly that).
* **Subject and dedup.** One alert per policy, device and subject, as in
  ADR-0074.
* **Our own actions are not alerts.** A failure within the window of a
  `winmod` `run_now`, `stop`, `policy_*` or `restore_*` job on that device
  (5 seconds before its start to 60 seconds after its end) is tagged `ours`
  and shown in Events with the cause; a backup the operator stopped is not
  a failed backup.
* **Evaluation** is one more pass in the monitoring loop's `Evaluate`, over
  `backup_events` and Facts, through `modules.Allowed(ctx, org)`
  (`devscope.Allowed`). Notifications use the existing paths.

#### Default policies

Created per organization, idempotently, when the module is first enabled
there (ADR-0073 section 6); organization-level, owned by the module, marked
`default`. They apply to servers unless the name says otherwise.

| Name | Kind | Threshold | Minutes | Class | Severity | Default |
|---|---|---|---|---|---|---|
| Backup: last backup failed | `backup_failed` | - | - | any | critical | on |
| Backup: target not found | `backup_target_missing` | - | 60 | server | critical | on |
| Backup: no successful backup in 2 days | `backup_overdue` | 2 | - | server | warning | on |
| Backup: target nearly full (under 10% free) | `backup_target_low_space` | 10 | - | server | warning | on |
| Backup: running too long | `backup_stuck` | - | 720 | server | warning | on |
| Backup: no successful backup in 14 days (workstations) | `backup_overdue` | 14 | - | workstation | warning | **off** |
| Backup: not configured on a server | `backup_not_configured` | - | 1440 | server | warning | **off** |
| Backup: feature not installed on a server | `backup_not_installed` | - | - | server | warning | **off** |

*Decided in review.* The owner asked for alerts on failure, none for N days
and a full or missing target. A server's failure, a missing target, two days
without a backup, a nearly full target and a stuck job mean something is
wrong now and are on. On laptops a missing target (the external drive left at
home) and a week without a backup are normal: the failure rule is on for
every class but the other four are server-only or off, the 14-day rule is
off and online-relative, and File History's own errors resolve after 7 quiet
days. "Not configured" and "not installed" are off because many customers
back up servers with another product, and a default that fires on every such
server teaches people to ignore alerts; an organization that uses WSB turns
them on. Creation calls `modules.Allowed`.

### 7. Organization scope

Every scheduled `backup.status` read, every event-reader instruction, every
alert evaluation and every default-policy creation calls
`modules.Allowed(ctx, org)`, which wraps the toggle and
`devscope.Allowed(orgID)` (ADR-0073, *Organization scope*). Actions by an
operator are explicit requests and are gated by permission, toggle and the
same function for the organization.

### 8. Tests

* **Unit (Go, no Windows).** Per action: the validator (accepts and rejects,
  fuzzing paths, UNC paths, volume GUIDs, version identifiers, schedule
  times; the system-folder and `..` rules; `keep` below 1), the stdin
  builder (hostile values arrive unchanged), the result decoder (good,
  truncated, wrong version, unknown fields), the catalogue lint (a tier-3
  action requires `backup.destroy`, a confirmation and a step-up; every
  script's SHA-256 matches), the role-state mapping from a table of
  `ProductType` and service states, the `ours` windows, the
  last-online rule, the policy `deviceClass` skip, and the secret handling
  for `target_network_set` (a test password is absent from the stored job
  row, the audit row, the logs and the result).
* **Integration (server, real PostgreSQL).** The permission matrix across
  the five roles including the two new permissions; 404 for a desktop on a
  server-only action; step-up refused after 5 minutes; confirmation
  mismatch refused; the contract-test fake runs `run_now`, `versions_prune`
  with its preview, and `target_network_set` and the secret row is gone
  after delivery; events deduplicated by acknowledgement; each alert kind
  opens and resolves (including `not applicable` by class, `module off`,
  and the laptop that wakes after a week); default policies are created and
  refreshed once.
* **PowerShell AST check (Windows runner CI).** ADR-0073's check over every
  `windows_backup` script, with one allowed exception: `ConvertTo-SecureString
  -AsPlainText -Force` whose input is the single declared secret parameter.
* **Windows runner CI.** On a `windows-latest` runner: parse all scripts;
  the hostile-value stdin pattern; the `module_missing` result where the
  module is absent; and, **if** the runner can install the feature
  (`Install-WindowsFeature Windows-Server-Backup`; not known to work on that
  image, to confirm), `status`, `policy_set` to a local volume and
  `versions` with typed results. CI says which steps were skipped.
* **Real-device steps, on the owner's test Windows servers** (installing the
  WSB feature and running backups are allowed; promoting a domain controller
  is not; roll back the snapshot after, and use a scratch disk or share,
  never production storage; no real addresses or names are written down):
  * R1 `Get-WinEvent -ListLog *Backup*,*FileHistory*` and list each
    provider's event IDs and messages (`wevtutil gp`) and record them in
    this ADR; confirm 4, 5, 19, 49 on the server's version and find the
    "completed with warnings" ID, if any.
  * R2 On a server without WSB: role `not_installed`, the tab shows the
    install action, `feature_install` with step-up, the role becomes
    `installed` after the rescan; note whether a reboot was needed.
  * R3 `policy_set` to a local volume with a schedule; `status` shows
    `configured`, next run and targets; fill the property-name mapping.
  * R4 `run_now`; watch `job` progress; event 4 arrives; Facts `lastSuccess`
    updates within the reader's interval.
  * R5 Force a failure (remove the target volume's access) and confirm event
    5 or 19 or 49, the alert, and that it resolves after a good run.
  * R6 `target_network_set` to a share with an account; confirm the password
    appears nowhere (server audit, job rows, logs, the agent's job journal,
    the process list while it runs).
  * R7 `restore_files` to a new folder from a version, and the overwrite
    variant with step-up; confirm CreateCopy semantics.
  * R8 `versions_prune` preview then delete, with `keep` 1; confirm the last
    version is never removed.
  * R9 `target_disk_set` on a **scratch** disk only: confirm the identity
    check, the format, and the dialog text.
  * R10 Server Core, if a test Core server exists: install, configure and
    run; otherwise the ADR says "not verified on Server Core".
  * R11 On a Windows 11 desktop: confirm what the logs and events show with
    File History on and off, whether `wbadmin` exists and works, and that
    the tab shows the explanation card; settle owner decisions 1 and 2 (this is R11).
  Until they are run the ADR says "not verified on a real server".

## Slices

Files named exist today unless marked *new*. Hotspot files get small
additive edits.

1. **B1 Role states, events, and the facts.** Role detection of
   `windows_backup` states (Go, table tests), `agent/winevents` use for the
   Backup and File History channels, Facts `detail`, heartbeat answer
   `backup` block, the migration, the event store. Needs ADR-0073 slice 1
   and ADR-0074's D7 (or builds `agent/winevents` first). Files:
   `internal/agentproto/agentproto.go`, `agent/runner/runner.go`,
   `server/internal/agents/heartbeat.go`; the real-device event confirmation
   (R1 above) lands here.
2. **B2 Permissions and catalogue skeleton.** `backup.view_sensitive`,
   `backup.destroy`, role unions, tier field and lint, validators, the
   secret parameter rule in the AST check. Files:
   `server/internal/rbac/rbac.go`, new `server/internal/winmod/backup/`.
   Needs ADR-0073 slice 2.
3. **B3 Reads.** `status`, `versions`, `disks`, `job`, the hourly scheduled
   read and snapshots. Needs B1, B2, ADR-0073 slices 5 and 6.
4. **B4 Run and stop.** `run_now`, `stop`, `stop_recovery`, the `busy`
   rule. Needs B3.
5. **B5 Configure.** `policy_set`, the three `target_*`, `vss_full_set`,
   `policy_remove`, credentials. Needs B3 and ADR-0073 slices 3 and 4
   (`params`, step-up).
6. **B6 Restore.** `restore_files`, `restore_files_overwrite`. Needs B3, B4.
7. **B7 Prune.** `versions_prune` with its preview. Needs B3 and slice 4.
8. **B8 Install.** `feature_install` and the role rescan. Needs B1, B2 and
   ADR-0073 slice 4.
9. **B9 Alerts and defaults.** Seven kinds, `AppliesTo` and `deviceClass`,
   the last-online rule, `ours` windows, eight default policies, the
   `Evaluate` pass. Files: `server/internal/monitoring/policies.go`,
   `evaluate.go`, `service.go`. Needs B1 and ADR-0073 slice 7.
10. **B10 UI.** The Backup tab's panels, group column, site and organization
    cards, the desktop explanation card. Files:
    `web/src/pages/devices/DeviceDetailPage.tsx`,
    `web/src/pages/organizations/levelTabs.tsx`, new
    `web/src/pages/devices/backup/`. Needs ADR-0073 slice 8; each panel
    needs its action's slice.
11. **B11 CI and the real-device run.** The module's AST rules and Windows
    job (grows with each slice; needs ADR-0073 slice 9) and the R1 to R11
    runbook with results written back here.

B1 and B2 start together; B3 to B8 after them, in parallel where marked; B9
after B1; B10 as its slices land. ADR-0073's order puts this module second,
after Defender.

## Consequences

* Servers get complete management of the supported Windows Server Backup
  lifecycle; desktops get honest visibility and alerts, not management, and
  the console says why.
* Whole-system recovery stays at the recovery console, a deliberate limit.
* Four new pieces of cross-module machinery are small and additive: a role
  state on every server, two permissions, a class on alert kinds and
  policies, and the "last came online" rule for age alerts.
* The agent gains one more reader on a 5-minute timer and a few bytes in the
  heartbeat; both stop when the module is off.
* Many facts here come from Microsoft pages written for older Server
  versions, or from search summaries; the unconfirmed ones are marked and
  settled in R1 to R11.
* The password of a share account passes through the server and the agent
  once, sealed; it is stored only by Windows inside the backup policy.

## Owner decisions

The owner's request is the only owner decision recorded. Two things are worth
the owner's eye, with defaults chosen in review:

1. **Desktops are read-only.** Windows has no supported way to manage File
   History from the system account, and System Image Backup is deprecated.
   If the owner wants the console to turn File History on or off by policy,
   or to drive the deprecated system image through `wbadmin` once R11 shows
   it works on Windows 11, those are follow-ups. Default: not built.
2. **A helper in the user's session** (to manage per-user File History or
   the Windows Backup app) would be a new kind of agent component. Default:
   not built, and not planned.

## Amendments to ADR-0073 (decided in review)

All are additive.

* **Section 1:** the `windows_backup` role is reported for every Windows
  computer with a state (servers: `not_installed`, `installed`, `configured`;
  desktops: `events_seen` or `none`), replacing "server: `wbengine`" as the
  only marker, so that the install action is reachable.
* **Section 3:** the Windows Backup row gains `backup.view_sensitive` and
  `backup.destroy`.
* **Section 4, step-up:** ADR-0073 says "within the last 10 minutes". The one
  definition is ADR-0055's, **5 minutes**; this ADR and every module use
  that, and ADR-0073's number is read as ADR-0055's.
* **Section 6:** kinds may declare `AppliesTo`, and a policy may carry an
  optional `deviceClass`, so one kind can have a server rule and a
  workstation rule; the evaluator skips the other class and resolves with
  `not applicable`.

## References

Read on 2026-11-26 unless marked otherwise:

* `wbadmin` (the command list and permissions):
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin
* `wbadmin enable backup` (targets, formatting of a disk target, overwriting a
  share, `-user` and `-password`, `-vssFull`, `-allowDeleteOldBackups`):
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-enable-backup
* `wbadmin start backup`, `start recovery`, `get versions`, `delete
  systemstatebackup` (`-keepVersions:0` deletes all; the cmdlet equivalents are
  below), and `start sysrecovery` (only in the Windows Recovery Environment, in
  the `wbadmin` page above):
  https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-start-backup ,
  .../wbadmin-start-recovery , .../wbadmin-get-versions ,
  .../wbadmin-delete-systemstatebackup . A page for `wbadmin delete backup`
  was not found (404).
* The `WindowsServerBackup` module for Windows Server 2025 (and the 2016,
  2019, 2022 views): https://learn.microsoft.com/en-us/powershell/module/windowsserverbackup/
  ; `Get-WBSummary`, `Get-WBJob`, `New-WBBackupTarget`, `Remove-WBBackupSet`,
  `Start-WBFileRecovery` under the same path. The property names of the
  objects they return are not on these pages.
* Event IDs 4, 5 and 19 of `Microsoft-Windows-Backup` (Windows Server 2008 and
  2008 R2 pages, archived):
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd364969(v=ws.10)
  (4), .../dd364941(v=ws.10) (5), .../cc734218(v=ws.10) (19). **Event 49** is
  from a search summary of Microsoft's page for it, *not re-read*. File History
  event 201 and the channel names are from search results and
  `winevt-kb.readthedocs.io`, *not Microsoft documentation read in full*.
* Deprecated features (System Image Backup, "Backup and Restore (Windows 7)",
  announced with 1709; File History not listed):
  https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features
* File History configuration object `IFhConfigMgr` (per user):
  https://learn.microsoft.com/en-us/windows/desktop/api/Fhcfg/nn-fhcfg-ifhconfigmgr
  (from a search result, *not re-read*).
* Windows Backup (settings and OneDrive) for organizations and Intune
  (`EnableWindowsBackup`): https://learn.microsoft.com/en-us/windows/configuration/windows-backup/
  and https://learn.microsoft.com/en-us/intune/intune-service/enrollment/windows-backup-restore
  (from a search result, *not re-read*).
* Installing the feature, Server Core guidance (2008 R2 to 2016 era):
  https://learn.microsoft.com/en-us/previous-versions/technet-magazine/dd673659(v=msdn.10)
  (from a search result, *not re-read*).
* Repository: `agent/winevents` (proposed by ADR-0074),
  `server/internal/monitoring/policies.go`, `server/internal/rbac/rbac.go`,
  `internal/agentproto/agentproto.go`.
