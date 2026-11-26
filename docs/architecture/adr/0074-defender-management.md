# ADR-0074: Managing Microsoft Defender from the console

* Status: Accepted (2026-11-26, after an independent review). Design only; no code is changed by this ADR.
* Asked for by the owner (2026-11-26): "I want a module to manage Windows
  Defender from our GUI. Full Management, or as much as we can from the UI.
  I also want alerts from defender to be able to be used as alert rules in
  our GUI. We should have default rules as well for defender." Those words
  are the only owner decisions here. Everything marked *decided in review*
  is the writer's call and the owner can overturn it.
* Builds on: [ADR-0073](0073-windows-management-modules.md) (the framework:
  the `winmod` job kind, `params` on standard input, the pinned script
  catalogue, `roles` in Facts, toggles, permissions, alert kinds and default
  policies per organization, step-up, `devscope`), which this ADR follows
  exactly except where *Amendments to ADR-0073* says otherwise;
  [ADR-0070](0070-defender-exclusions-at-install.md) (our own exclusions,
  already built); [ADR-0072](0072-what-each-page-shows.md) (where the tabs
  appear); [ADR-0054](0054-hardening-windows-computers-and-servers.md)
  (the reader of who owns a setting: Group Policy, MDM, Defender for
  Endpoint); [ADR-0060](0060-collecting-logs.md) (proposed: the same
  Defender event IDs, collected for storage) and
  [ADR-0068](0068-remote-event-viewer.md) (proposed: the cursor rules).
* Amends: ADR-0073 (three points, below).

## Context

Defender is on every Windows computer the console manages, so it is the
first module on the ADR-0073 framework and the one that proves it.

What exists today:

* **Our exclusions.** ADR-0070 is built. The agents add Defender path,
  process, Attack Surface Reduction (ASR) and Controlled Folder Access (CFA)
  exclusions at install, keep a record of exactly what they added
  (`defender-exclusions.json` in the EasyRMM agent's protected state folder,
  and `state\defender-exclusions.json` under the EasyPatch data folder),
  reconcile at each start, and report their state in the heartbeat
  (`agentproto.DefenderReport`). The server answers every heartbeat with
  `defender.enabled`, the development-scope result
  (`agentproto.DefenderPolicy`). `agent/defender` already treats Defender's
  "N/A" text as *unavailable*, never as an empty list.
* **A reader of who owns a setting.** `internal/winpolicy` (ADR-0054) names
  Group Policy, MDM, Defender for Endpoint, Configuration Manager and DSC as
  owners (`ReasonGroupPolicyPreferences`, `ReasonMDM`,
  `ReasonDefenderForEndpoint`, ...).
* **Nothing that reads Defender's health or events, and nothing that changes
  a preference.** ADR-0073 reports a `defender` role from `MSFT_MpComputerStatus`
  and fixes the permission names, the alert kinds `defender_threat`,
  `defender_protection_off`, `defender_signatures_old`, and the placement.

### What Microsoft documents (read on 2026-11-26; see References)

* **No cmdlet changes Tamper Protection.** `Set-MpPreference` has no
  parameter for it. Microsoft's overview says tamper protection is managed
  in Intune, in the Defender portal, or, where no security team manages the
  device, in the Windows Security app by an administrator; with it on,
  attempts to change protected settings, including through the registry and
  Group Policy, are blocked and event 5013 is written; exclusions "can't be
  modified or added" while it protects them. **This corrects the request's
  "it can't be changed locally":** it can be changed by an administrator
  at the computer in the Windows Security app when no one manages it, but
  never by a script, so the module shows it read-only and says where it is
  changed.
* **There is no per-item quarantine delete.** `MpCmdRun.exe -Restore
  -ListAll` lists quarantined items and `-Restore -Name`/`-FilePath`
  restores one; `Remove-MpThreat` "removes all active threats", not
  quarantined items; quarantine is emptied by the preference
  `QuarantinePurgeItemsAfterDelay` (days; zero means never). So the
  request's "quarantine remove" is offered as **removing active threats**
  and **setting how long quarantine keeps items**, not as deleting one
  quarantined file. If a documented per-item delete exists later, it is a
  new catalogue action.
* **Passive mode.** On Windows 10/11 another antivirus switches Defender to
  disabled (or passive with Smart App Control); on Windows Server 2016 and
  later Defender "doesn't enter passive mode automatically" and an
  administrator sets `ForceDefenderPassiveMode` (and passive mode needs
  Defender for Endpoint onboarding). `Get-MpComputerStatus` reports
  `AMRunningMode` as `Normal`, `Passive` or `EDR Block Mode`. In passive
  mode, real-time protection, cloud protection, network protection, ASR
  and CFA do not work, so the module treats them as *not applicable*.
* **Other owners.** Group Policy, Intune (Defender CSP) and Defender for
  Endpoint's security settings management all write Defender settings and
  win over a local `Set-MpPreference` (ADR-0054, *Someone else often owns
  the settings*).

## Decision

### In short

1. One module, `defender`, on ADR-0073's framework: permissions
   `defender.view`, `defender.manage`, and two added by this ADR
   (`defender.view_sensitive`, `defender.weaken`).
2. State comes from Facts (cheap, hourly) and from a fixed read action per
   panel (on demand, cached).
3. Every action is a fixed script with typed parameters on standard input,
   in four risk tiers; the tier decides the permission, the confirmation
   and the step-up.
4. Our own exclusions are protected twice (on the computer and on the
   server), shown as protected, and never removable from the module.
5. A setting owned by Group Policy, Intune, Defender for Endpoint or Tamper
   Protection is shown as "managed by policy" and the module does not write
   it.
6. Defender events are read by a small agent-side reader with a bookmark,
   deduplicated on the server, and become twelve alert kinds with thirteen
   default policies per organization.

### 1. Identity, permissions and where it is offered

* **Module name** `defender`; role `defender` (ADR-0073 section 1); toggle
  default **on** (ADR-0073 section 2). Offered on a device only when the role
  is `present` and the state is not `not_installed`.
* **Permissions.**

| Permission | Holds | Gives |
|---|---|---|
| `defender.view` | Technician and above (ADR-0073) | state, preferences, ASR, exclusions (our own marked), scan times, threat and event history without file paths or user names |
| `defender.manage` | Technician and above (ADR-0073) | tier 1 and tier 2 actions (below) |
| `defender.view_sensitive` (new) | Site Administrator and above | file paths of detections and quarantined items, user names and process names in events, and the exclusion values an administrator added (paths can name customers or users) |
| `defender.weaken` (new) | Site Administrator and above | tier 3 actions: anything that lowers protection or restores a threat |

  *Decided in review.* ADR-0073's table lists only `view` and `manage` but
  its section 4 already makes Defender's quarantine paths sensitive, which
  needs `view_sensitive` by its own rule (section 3), and it gives
  Technicians `defender.manage` because Defender changes are "reversible,
  low-blast-radius". That is true of scans and updates and false of "turn
  real-time protection off" or "restore this malware", so those need
  `defender.weaken`. Both permissions are added to `AllPermissions` and the
  role unions in `rbac.go` by the same small additive edit as the others.
  Read-Only has none of them. Each is checked at the device's site through
  `access`, as ADR-0073 requires.
* **A device is offered the module** when role, toggle and permission agree;
  otherwise 404 (ADR-0073 section 2).

### 2. State shown

Two sources, per ADR-0073 section 5. Facts carry what alerts need cheaply;
read actions carry the rest.

**Facts (no job).** The `defender` entry of `roles` gains an optional bounded
`detail` object, an additive field (*decided in review*), filled by the same
`MSFT_MpComputerStatus` read the detection already makes in a killed-after-10-seconds
child process: `runningMode` (`Normal`, `Passive`, `EDR Block Mode`, `Not
running`), `otherAntivirus` (name from Security Center on clients; unknown on
servers), `realtime`, `behaviorMonitor`, `ioav`, `engineVersion`,
`signatureVersion`, `signatureUpdated` (UTC), `signatureAgeDays`,
`platformVersion`, `quickScanAgeDays`, `fullScanAgeDays` (null when never run:
Defender reports 4294967295), `tamperProtected`, `tamperSource` (shown
verbatim; the property names `IsTamperProtected` and `TamperProtectionSource`
are named in Microsoft's tamper protection configuration article but not in
the `Get-MpComputerStatus` example, so they are **to confirm on R1**), `nisEnabled`. Roles scan every 6 hours (ADR-0073); the Defender
detail refreshes **every hour** from its own agent timer, only while the
server's heartbeat answer says `defender.enabled` and the module is on
(`DefenderPolicy` gains a `module` bool, additive), one child process at a
time. Signature age in days does not need finer.

**Read actions** (cached 5 minutes, ADR-0073 section 5):

| Panel | Action | Source | Sensitive |
|---|---|---|---|
| Status | `defender.status` (the framework's proof action) | `Get-MpComputerStatus` | no |
| Protection settings | `defender.preferences_read` | `Get-MpPreference`, each allowed field with value, supported flag and owner (section 4) | no |
| ASR rules | `defender.asr_read` | `Get-MpPreference` `AttackSurfaceReductionRules_Ids` and `_Actions`, joined to the catalogue's rule names | no |
| Controlled Folder Access | `defender.cfa_read` | `EnableControlledFolderAccess`, `ControlledFolderAccessProtectedFolders`, `ControlledFolderAccessAllowedApplications` | yes (paths) |
| Exclusions | `defender.exclusions_read` | `ExclusionPath`, `ExclusionProcess`, `ExclusionExtension`, `AttackSurfaceReductionOnlyExclusions`, plus our record (section 5) | yes (values) |
| Threats | `defender.threats_read` | `Get-MpThreat`, `Get-MpThreatDetection` (ID, name, severity, category, status, times; paths separate) | paths yes |
| Quarantine | `defender.quarantine_read` | `MpCmdRun.exe -Restore -ListAll` | yes |
| Events | from the server's event table (section 7) | | detail yes |

What each state item shows and where it comes from:

| Item | Shown as | From |
|---|---|---|
| Real-time protection | on / off / not applicable (passive, disabled) | Facts `realtime`; `DisableRealtimeMonitoring` |
| Signatures and engine | versions, last updated, age in days (amber at 3, red at 7: the default policy thresholds) | Facts |
| Last quick and full scan | age in days or "never" | Facts |
| Tamper Protection | on / off / not applicable, read-only, with its source and the sentence "Changed in the Windows Security app on the computer, in Intune or in the Defender portal, never from here" | Facts |
| Cloud protection | `MAPSReporting` (Disabled, Basic, Advanced), `SubmitSamplesConsent`, `CloudBlockLevel`, `CloudExtendedTimeout` | `Get-MpPreference` |
| PUA | Disabled, Enabled, AuditMode | `PUAProtection` |
| Network protection | Disabled, Enabled, AuditMode | `EnableNetworkProtection` |
| ASR rules | rule name, GUID, mode (Disabled, Enabled, AuditMode, Warn), "unrecognised rule" for a GUID not in the catalogue | `defender.asr_read` |
| Controlled Folder Access | mode, protected folders, allowed applications (ours marked) | `defender.cfa_read` |
| Exclusions | four lists plus extensions; ours first, locked, with the state ADR-0070 already reports (`effective`, `present_not_effective`, ...) | `defender.exclusions_read` and the existing `DefenderReport` |
| Threats and quarantine | active, last 30 days, counts by severity | `defender.threats_read`, events |
| Passive mode or another antivirus | a banner: "Defender is not the active antivirus on this computer"; the panels that need an active Defender show *not applicable* | Facts |

A value Defender will not show (its "N/A: Must be an administrator or have
Tamper Protection..." text) is *unavailable* with that reason, never `0`,
never an empty list (the rule `agent/defender` already follows).

### 3. Actions

#### Risk tiers

| Tier | Meaning | Permission | Confirmation | Step-up | Audit |
|---|---|---|---|---|---|
| 0 Read | no change | `defender.view` (`view_sensitive` for sensitive results) | none | none | compact, one row per query (ADR-0073) |
| 1 Routine | reversible, does not lower protection | `defender.manage` | none | none | `winmod.defender.<action>` with parameters |
| 2 Change | changes configuration without lowering protection, or removes something that only restores scanning (an admin's exclusion, active threats) | `defender.manage` | `confirm: "<action>:<device name>"` | none | as tier 1 plus old and new value |
| 3 Weaken | lowers protection, widens what is not scanned, or puts a threat back | `defender.manage` **and** `defender.weaken` | confirm, naming the effect in the dialog | **required** (step-up as [ADR-0055](0055-lets-encrypt-in-one-step.md) defines it, section *Step-up authentication*, the one definition) | as tier 2, and the alert `defender_config_changed` is suppressed as ours (section 7) |

Which tier a preference write takes is decided per field **and per value** in
the catalogue (`Direction`: strengthen, neutral, weaken). `DisableRealtimeMonitoring = $true`
is tier 3, `$false` is tier 1. Where a write mixes directions, the highest
tier applies. Destructive actions (ADR-0073's `Destructive` flag) are the
tier 2 and 3 removals below.

#### Catalogue

Every action is `{Module: defender, Name, Version, Script, Params schema,
Result schema, Tier, Sensitive, Destructive, Timeout}` per ADR-0073 section 4.
Parameters reach the script only as JSON on standard input; the scripts
use `Set-MpPreference`, `Add-MpPreference`, `Remove-MpPreference`,
`Start-MpScan`, `Update-MpSignature`, `Remove-MpThreat` and `MpCmdRun.exe`
with fixed argument lists and each user value as one argument.

| Action | Does | Parameters (typed) | Tier | Timeout |
|---|---|---|---|---|
| `scan_start` | `Start-MpScan -ScanType QuickScan` or `FullScan` | `type`: `quick` or `full` | 1 | see *Scans* |
| `scan_custom` | `Start-MpScan -ScanType CustomScan -ScanPath` | `path`: absolute local path, validated as below | 1 | see *Scans* |
| `scan_cancel` | `MpCmdRun.exe -Scan -Cancel` (cancels active quick and full scans) | none | 1 | 60 s |
| `signatures_update` | `Update-MpSignature` (uses the configured fallback order); after it, reads the new versions | none | 1 | 10 min |
| `threats_remove` | `Remove-MpThreat` (all active threats) | none | 2 | 10 min |
| `quarantine_restore` | `MpCmdRun.exe -Restore -Name <threat> [-All]` or `-FilePath <quarantined path>`; restores **to the original location**, which puts the file back where it was found. The dialog says so | `name` (threat name from the last quarantine read, not free text) or `filePath` (a path from that read) | 3 | 2 min |
| `preferences_set` | `Set-MpPreference` with the validated fields below, one call, nothing else | a map of field to typed value (the table below); at most 8 fields | by field | 2 min |
| `asr_set` | `Add-MpPreference -AttackSurfaceReductionRules_Ids ... -AttackSurfaceReductionRules_Actions ...` | list of `{id: GUID from the catalogue's rule list, mode: Disabled, Enabled, AuditMode, Warn}`, at most 20 | by mode: Enabled or Warn is 1; AuditMode or Disabled is 3 | 2 min |
| `cfa_set` | `Set-MpPreference -EnableControlledFolderAccess` | `mode`: Disabled, Enabled, AuditMode | Enabled 1; AuditMode, Disabled 3 | 2 min |
| `cfa_folder_add`, `cfa_folder_remove` | `Add-`/`Remove-MpPreference -ControlledFolderAccessProtectedFolders` | `path` | add 1; remove 3 | 2 min |
| `cfa_app_add`, `cfa_app_remove` | `Add-`/`Remove-MpPreference -ControlledFolderAccessAllowedApplications` | `path` (an `.exe`), never ours | 3 | 2 min |
| `exclusion_add` | `Add-MpPreference` with `-ExclusionPath`, `-ExclusionProcess`, `-ExclusionExtension` or `-AttackSurfaceReductionOnlyExclusions` | `kind`, `value`, `reason` (free text, 3 to 200 characters, audited) | 3 | 2 min |
| `exclusion_remove` | `Remove-MpPreference` with the same parameters | `kind`, `value` that **is in the last read's list** and is not ours | 2 | 2 min |

There is no "clear all exclusions", no "disable Defender", no action that
takes script text, and nothing for Tamper Protection.

**Scans (*decided in review*).** `Start-MpScan` runs the scan in the
foreground cmdlet, and a full scan can take hours; ADR-0073 gives the agent
four job slots and no reserved one. Two designs, chosen by the first
real-device step (R2):

* **A** (preferred): if the scan can be started and the script can return
  while Defender's service goes on scanning, the job ends when the scan has
  started (confirmed by event 1000 or a status change); progress is the
  events 1000, 1001 and 1002 the reader already collects; the console shows
  "scan running since ...".
* **B** (fallback): the job holds its slot until the scan ends, with caps
  (quick 2 hours, custom 6 hours, full 24 hours), at most one scan job per
  device, and `-CpuThrottling` never raised; the full scan is then offered
  only on devices whose agent advertises the reserved-slot level of
  ADR-0073's *The lane*, and otherwise as a scheduled-scan setting.
Either way a second scan request on a device that has one running is
refused with `scan_running`. Scans are tier 1: they add load, and Defender
throttles them. Where the module is in passive mode, scans still work
(Microsoft: file scanning works in passive mode) but scheduled scan settings
are ignored there, which the UI says.

**Custom scan path validation.** Absolute, a drive letter or a UNC path
`\\server\share\...`, at most 260 characters, no `..`, no device paths
(`\\.\`, `\\?\`), no wildcards, none of `" ' ; & | < > ^ % $` or a backtick,
no reparse trick checked by the script (`Test-Path -LiteralPath`). The value
is passed as `-ScanPath $p.path`, never joined.

#### Preferences the module may set

Typed, bounded; the catalogue holds each field's type, range and direction,
and a unit test compares the field list to the pinned
`Set-MpPreference` parameter list so a Windows change is noticed in review.
Types are those of the cmdlet page. Anything not in this table is not
settable from the module (`not_allowed`, 400).

| Group | Fields (type; allowed values) | Direction |
|---|---|---|
| Protection switches | `DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`, `DisableIOAVProtection`, `DisableScriptScanning`, `DisableBlockAtFirstSeen`, `DisableArchiveScanning`, `DisableEmailScanning`, `DisableRemovableDriveScanning`, `DisableScanningNetworkFiles`, `DisableScanningMappedNetworkDrivesForFullScan` (bool) | `$true` weakens |
| Cloud | `MAPSReporting` (0, 1, 2); `SubmitSamplesConsent` (0 to 3); `CloudBlockLevel` (the cmdlet's enumeration, pinned); `CloudExtendedTimeout` (0 to 50 seconds) | lowering `MAPSReporting` to 0 or `CloudBlockLevel` to default weakens; the rest neutral |
| Features | `PUAProtection`, `EnableNetworkProtection` (Disabled, Enabled, AuditMode) | Disabled, AuditMode weaken |
| Threat actions | `LowThreatDefaultAction`, `ModerateThreatDefaultAction`, `HighThreatDefaultAction`, `SevereThreatDefaultAction` (Clean, Quarantine, Remove, Allow, UserDefined, NoAction) | Allow, NoAction, UserDefined weaken (Microsoft: Allow, NoAction and None "don't remediate") |
| Retention | `QuarantinePurgeItemsAfterDelay`, `ScanPurgeItemsAfterDelay` (days, 0 to 365) | neutral (0 means keep forever) |
| Schedule | `ScanScheduleDay` (0 to 8), `ScanScheduleTime`, `ScanScheduleQuickScanTime` (minutes after midnight, 0 to 1439), `ScanParameters` (1 quick, 2 full), `RemediationScheduleDay`, `RemediationScheduleTime`, `DisableCatchupFullScan`, `DisableCatchupQuickScan`, `RandomizeScheduleTaskTimes`, `SignatureScheduleDay`, `SignatureScheduleTime`, `SignatureUpdateInterval` (1 to 24 hours), `SignatureUpdateCatchupInterval` (days, 1 to 30), `CheckForSignaturesBeforeRunningScan`, `MeteredConnectionUpdates` | neutral; `DisableCatchup*` `$true` weakens |
| Performance | `ScanAvgCPULoadFactor` (0, or 5 to 100), `ScanOnlyIfIdleEnabled`, `EnableLowCpuPriority`, `DisableCpuThrottleOnIdleScans`, `EnableFullScanOnBatteryPower`, `DisableRestorePoint` | neutral |
| Servers | `DisableAutoExclusions` (bool; Windows Server's automatic role exclusions) | `$true` weakens |

*Left out of the first version, each on purpose:* proxy settings and update
file shares (a URL or UNC from a user is where data leaves), the update
channels, the network-protection internals (`Disable*Parsing`,
`AllowDatagramProcessingOnWinServer`, ...), `DisableLocalAdminMerge`
(it changes whether *our* local exclusions count, see section 5),
`DisablePrivacyMode`, and every `-Force` and `-CimSession`.

**Exclusions an administrator may add** (`exclusion_add`): `ExclusionPath`
(absolute path or folder), `ExclusionProcess` (a full path to an `.exe`, never
a bare name), `ExclusionExtension` (letters and digits, 1 to 10), and
`AttackSurfaceReductionOnlyExclusions` (a path). Refused with `too_broad`
(400): a drive root, `*` or a path with a wildcard in a folder name, the
Windows folder, System32, `%ProgramFiles%` itself, a user profile root, a
whole share root, a process named `powershell.exe`, `pwsh.exe`, `cmd.exe`,
`wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `msiexec.exe` or
`regsvr32.exe`, and the extensions `exe dll ps1 psm1 bat cmd vbs vbe js jse
wsf wsh msi scr com hta lnk jar py`. These follow Microsoft's list of
common exclusion mistakes. A request that the catalogue refuses can be done
by an operator through the script runner, which audits it as a script
(ADR-0073). Adding takes tier 3 because it stops scanning; removing takes
tier 2 because it only restores scanning.

**Never `Set-MpPreference` for a list.** `Set-MpPreference -ExclusionPath`
replaces the whole list, which would delete our exclusions. Lists change only
with `Add-MpPreference` and `Remove-MpPreference`, one value at a time, and
the ASR rule table likewise (Microsoft's ASR configuration guidance uses
`Add-MpPreference`; `Set-MpPreference` overwrites existing rule settings,
which is *to confirm on a real device* at R5). The AST check (section 9)
fails a `Set-MpPreference` that names any list parameter.

### 4. What Group Policy, Intune and the rest own: "managed by policy"

* **Detecting the owner, per field.** `defender.preferences_read`,
  `asr_read`, `cfa_read` and `exclusions_read` report, for each value, `value`
  (what `Get-MpPreference` says, which is the effective one) and `managedBy`:
  `group_policy` when the field has a value under
  `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` (and its subkeys for
  real-time protection, scan, MAPS, signature updates, threats, exclusions and
  the Exploit Guard keys); `mdm` when it has one under
  `HKLM\SOFTWARE\Microsoft\Windows Defender\Policy Manager`, where the
  Defender CSP writes (*to confirm on a real Intune-enrolled computer*;
  ADR-0054's MDM reader is not proven on one either);
  `defender_for_endpoint` and `configmgr` from the existing `internal/winpolicy`
  reasons; `tamper_protection` for the protected settings when Facts say it is
  on; null when nothing owns it. The registry reads are Go in the agent
  (no process), read-only, and the result carries the owner and, for Group
  Policy, nothing more (no GPO name: the reader has none for Defender keys).
  *Decided in review.* Where the owner cannot be told (an unreadable key),
  the field reads `unknown_owner` and is **writable with a warning**, never
  silently locked. **Tamper Protection is one rule, not two:** when Facts
  say it is on, every field it protects (the protection switches, cloud
  protection, threat actions, signature updates, and exclusions, which
  Microsoft lists) has the owner `tamper_protection`, so a write to it is
  refused with `409 managed_by_policy` and the message "Tamper Protection is
  on and blocks this change; change it in the Windows Security app, Intune or
  the Defender portal". Nothing is attempted. A field Tamper Protection does
  not protect (the schedule, the performance fields) is not locked by it.
* **The console shows it.** A field with an owner is drawn with a lock and
  the text "Managed by Group Policy" (or Intune, Defender for Endpoint,
  Tamper Protection), its controls disabled, and a link "Change it where it
  is managed". It is not hidden. A default policy of section 8 still alerts
  on it.
* **The module does not fight it.** The server's validator refuses a write
  to a field whose last read (at most 5 minutes old, otherwise the request
  first reads) names an owner: `409 managed_by_policy`. The script checks again
  on the computer and refuses with `managed_by_policy` before calling the
  cmdlet (the same two-place guard ADR-0073 uses for protected targets). The
  module never writes under a `Policies` key, never sets
  `DisableLocalAdminMerge`, and never retries.
* **Read-back.** After a write the script reads the preference again. If it
  did not change, the result is `not_applied` with the likely reason: an
  owner appeared since the read, or Tamper Protection blocked it (event 5013
  after the job's start). The audit row records `not_applied`, not success.
  Nothing is reported as changed that is not.
* **Tamper Protection on** (read from Facts): the panels show the lock above
  and the sentence "Tamper Protection is on: it blocks changes to protected
  settings and exclusions". Facts can be an hour old, so when the server's
  snapshot is older than 5 minutes the request first runs
  `defender.status` and decides on that. If Tamper Protection was turned on
  after the check, the script's read-back reports `not_applied` with the
  reason (event 5013 after the job's start) and the audit row says so.
* **Exclusions are decided per entry, not per list.** Local exclusions merge
  with policy's unless `DisableLocalAdminMerge` is set; with merge on, a
  local add or remove works, and only the entries that **policy owns** (those
  under the Group Policy or Policy Manager exclusion keys) are read-only,
  each shown with its owner. If policy sets `DisableLocalAdminMerge`, local
  exclusions are ignored by Defender, so adds are refused with
  `managed_by_policy` for the whole kind and the panel says why. Tamper
  Protection on locks every exclusion change, as above.
* **Passive mode or another antivirus:** every action that needs an active
  Defender (preference writes for real-time protection, cloud, network
  protection, ASR, CFA) is disabled with the reason; scans, signature
  updates and reads stay.

### 5. Our own exclusions are protected

ADR-0070's exclusions must survive this module. Mechanism (*decided in
review*):

* **What is ours.** Each exclusion in a list is `ours` when it is in either
  agent's record (the two `defender-exclusions.json` files), **or** equals,
  case-insensitively and normalised, an entry of the fixed set in ADR-0070
  section 3 (the five folders, the three executables). The script reads both
  records as SYSTEM and does not trust their shape (a corrupt record means
  the fixed set decides). The server also marks ours from the last
  `DefenderReport`.
* **Shown.** Ours sort first, carry a lock and the words "EasyRMM needs this
  so Defender does not block its own files", show ADR-0070's per-kind state,
  and have no remove button. The CFA allowed-application list and the
  ASR-only list show ours the same way.
* **Never removed or weakened, in three places.** (1) The catalogue has
  no action that takes a value not in the last read's list, and
  `exclusion_remove`, `cfa_app_remove` and the ASR-only removal refuse an
  `ours` value on the server (`protected_exclusion`, 409). (2) The script
  refuses it on the computer before calling `Remove-MpPreference`, even if
  the request names a path differently (it **expands environment variables**, converts 8.3 short names with
  `GetLongPathName`, and normalises with `[System.IO.Path]::GetFullPath`,
  then compares ordinally ignoring case; the same expansion applies to
  the values read from the lists and from both record files, so
  `C:\PROGRA~1\EasyRMM\Agent` and `%ProgramFiles%\EasyRMM\Agent` both
  match ours; unit fixtures cover each of the two and a short name of a
  folder that no longer exists, which compares as written). (3)
  The AST check fails any script with a `Remove-MpPreference` that is not
  driven by one `$p.value` and the guard function. There is no "remove all"
  and no `Set-MpPreference` on a list (section 3). Removing a *parent* of one
  of ours is a different value and is allowed (the exclusion of the parent is
  not ours); the child stays listed.
* **Nothing the module sets can disable ours indirectly.** The settable
  fields exclude `DisableLocalAdminMerge`. `DisableAutoExclusions` is a
  different list. If an owner (policy) sets `DisableLocalAdminMerge` on a
  computer, ADR-0070's existing `not_effective` reporting applies and the
  panel shows it under ours.
* **Turning ASR or CFA on can block our own agents.** ASR rules and
  Controlled Folder Access can block `easyrmm-agent.exe`, `meshagent.exe` or
  `EasyPatch.Agent.exe` and their writes. ADR-0070 section 3 already adds
  ASR-only exclusions for the five working folders and CFA allowed
  applications for the three executables. The module therefore **checks
  before enabling**: `asr_set` (mode Enabled or Warn) and `cfa_set` (Enabled)
  read the lists in the same job and proceed only if every one of ours is
  present and, per ADR-0070's report, `effective` for that kind; otherwise
  the result is `ours_not_covered` and nothing is changed. A forced override
  is not offered. The check is a tier 1 action's precondition, so no tier
  is raised; R6 proves it with an ASR rule on.
* **Reconcile still wins.** The agents add what is missing at each start
  (ADR-0070); the module neither blocks nor races that.
* **Audit.** A refused attempt on ours writes `winmod.defender.exclusion_remove`
  with `ok: false` and `protected_exclusion`.

### 6. Where it sits (ADR-0072, ADR-0073 section 7)

* **Device, "Security" tab** (`defender.view`): panels *Status*, *Protection*
  (preferences, with the lock), *Attack Surface Reduction*, *Controlled
  Folder Access*, *Exclusions*, *Threats and quarantine*, *Scans and
  updates*, *Events*. Each panel is a component and one row in the tab
  registry, so builders do not edit one file. Frame, as-of time and Refresh
  come from `ModuleTab`.
* **Group:** a protection-state column and filter from Facts.
* **Site:** a Security card on Overview (counts from Facts: protected,
  not protected, signatures old, threats in 30 days), and the "Windows
  modules" toggle card (ADR-0073).
* **Organization:** the same card and toggle, and a Security tab if the
  organization has an organization switch (ADR-0072): the fleet table
  (device, state, signature age, last scan, open Defender alerts) read from
  Facts. The module's alert policies appear in the Alert policies tab with a
  "Defender" filter and a "default" badge.
* Cards and the fleet table never send a job to a device (ADR-0073).

### 7. Alerts

#### Events collected

From the channel `Microsoft-Windows-Windows Defender/Operational` only.

| ID | Meaning (Microsoft's wording) | Used for |
|---|---|---|
| 1006 | the antimalware engine found malware or other potentially unwanted software | `defender_threat` |
| 1116 | the platform detected malware or other potentially unwanted software (name, ID, severity, category, path, origin, source, user, process) | `defender_threat` |
| 1117 | the platform performed an action to protect the system (the action taken) | resolves `defender_threat`; history |
| 1007 | the platform performed an action (older form of 1117) | same as 1117 |
| 1008, 1118 | the action failed (1118: a noncritical error) | `defender_remediation_failed` |
| 1119 | the platform hit a critical error taking action | `defender_remediation_failed` |
| 1015 | the platform detected suspicious behavior | `defender_threat` (severity from the event) |
| 5001 | real-time protection is disabled | `defender_protection_off` |
| 5010 | scanning for malware and other potentially unwanted software is disabled | `defender_protection_off` |
| 5012 | scanning for viruses is disabled | `defender_protection_off` |
| 5000, 5009, 5011 | the matching protection is enabled | resolves `defender_protection_off` |
| 3002 | real-time protection encountered an error and failed | `defender_unhealthy` |
| 3007 | real-time protection recovered from a failure | resolves `defender_unhealthy` |
| 5008 | the antimalware engine encountered an error and failed | `defender_unhealthy` |
| 5100, 5101 | the antimalware platform expires soon, is expired | `defender_out_of_support` |
| 5004 | the real-time protection configuration changed | `defender_config_changed` |
| 5007 | the platform configuration changed (old and new value) | `defender_config_changed` or `defender_exclusion_changed` |
| 5013 | tamper protection blocked a change | `defender_tamper_blocked` |
| 2001 | the security intelligence (signature) update failed | `defender_update_failed` |
| 2003 | the engine update failed | `defender_update_failed` |
| 2006 | the platform update failed | `defender_update_failed` |
| 2000, 2002 | definitions / engine updated successfully | resolves `defender_update_failed` |
| 1000, 1001, 1002 | scan started, finished, stopped before it finished | scan state and history |

*Decided in review* (the owner named 1006, 1116, 1117, 5001, 5007, 2001 and
2003; the others are added because Microsoft's page documents them and
each answers a question an administrator asks: was it removed, is anything
off, is it healthy, is something tampering). **Not collected in the first
version:** 1005 (scan failed) and 1122, 1123, 1124 (ASR and CFA audit and
block), because the Microsoft troubleshooting page this was written from
documents 1121 and 1127 for ASR and CFA and not 1005; they join once their
documentation is read. 1121 (an ASR rule fired in block mode) is stored for
the Events panel and has no alert kind.

#### How the agent collects them (cheap, bounded, deduplicated)

*Amends ADR-0073 section 6* (which says ADR-0068's builtin reads the log on a
schedule): a job every minute would hold a worker slot and write an audit row
each time, so a small agent-side Go reader does it, in a package that
ADR-0060's collector will reuse (`agent/winevents`: whichever lands first
creates it).

* **Query.** One `EvtQuery` (wevtapi) on that one channel, forward
  direction, with an XPath that names the event IDs above and
  `EventRecordID > <bookmark>`, so Windows filters and the reader never
  renders an event it does not use. It runs **every 60 seconds**, only
  while the server's heartbeat answer says the module is on and
  `devscope.Allowed` (the `DefenderPolicy` answer gains `events`).
* **Bookmark.** The last record ID sent, per channel, kept with the log's
  creation time in a file in the agent's protected state folder, written
  atomically. If the log was cleared or wrapped past the bookmark (the
  oldest record ID is above the bookmark, or the creation time changed, the
  rule ADR-0068 uses for its cursor), the batch carries `gap: true`; the
  server shows "events may have been missed" and opens no alert from the
  gap itself.
* **First run.** No bookmark: read the last 24 hours, newest 100 matching
  events, marked `backfill`. The server stores them but opens alerts only for
  events less than 60 minutes old, so enabling the module does not raise a
  day of stale alerts.
* **Bounds.** Each event becomes a compact record (ID, record ID, time,
  and the fields Microsoft lists for that ID: threat name, ID, severity
  name, category, detection origin and source, action, process, signature
  and engine version, old and new value, error code; path and user in a
  separate `sensitive` object), 1 KiB at most, long text cut and marked.
  At most 25 events per query and 24 KiB per heartbeat. A storm (more than
  20 events with the same ID in one query) is **aggregated, never
  dropped**: the reader sends the first 5 and one counted summary record
  per event ID and device (`count`, first and last time, first and last
  record ID, and for detections the distinct threat IDs, at most 20), in
  the same batch and before the bookmark moves past those events. Every
  record the bookmark passes is therefore either sent whole or counted in
  a summary that was sent, so "the bookmark never passes what was not
  sent" holds. The server stores a summary as one row with `count`, and
  evaluates the alert kinds from it as from the events it stands for.
  Beyond the 25-event and 24 KiB caps the bookmark stops at the last event
  sent, so a backlog drains at 25 per minute.
* **Dedup and acknowledgement.** The server's table has a unique key
  `(device_id, record_id, log_created)`, inserts with `ON CONFLICT DO
  NOTHING`, and the heartbeat answer acknowledges the highest record ID it
  stored; the agent resends from its last acknowledged record, so a lost
  response duplicates nothing and loses nothing.
* **Cost.** Reading an event by ID costs nothing while none match; with
  protection quiet the query returns nothing. No process is started, no
  PowerShell, no job slot, no audit row per poll.
* **Off means off.** Module off, role absent or organization not allowed:
  the answer says so, the reader stops, the bookmark is kept.

#### Where they are stored

Migration `server/migrations/9xxxx_defender.sql` (number from the brief;
goose up and down, down working): `defender_events(id, organization_id,
device_id, record_id, log_created, event_id, occurred_at, received_at,
severity, threat_id, threat_name, category, action, summary jsonb,
sensitive jsonb, ours boolean, backfill boolean)` with row-level security by
organization as the other tables; `summary` holds only what `defender.view` may see (event ID,
severity, threat name and category, the action's name, counts, versions,
error code). **Exclusion paths, process names, the old and new values of
event 5007 and 5004 (which carry the exclusion or setting itself), and
every file path and user name go in `sensitive`, never in `summary`**; a
unit test feeds each fixture event through the normaliser and fails if a
path, a user or a 5007 value appears in `summary`. `sensitive` is returned
only to holders of `defender.view_sensitive`; a `defender.view` caller sees
for a 5007 only "a protection setting changed" or "an exclusion changed". Retention: `sensitive` cleared after 30 days, the
row deleted after 90, through the module-data retention job. Detections of
a device removed from the console go with it.

#### Alert kinds

Registered with the monitoring package as ADR-0073 section 6 describes
(name, label, module `defender`, policy parameters, value source). The
three of ADR-0073 are kept; nine are added (twelve kinds in all). `validKind` gains them through
the framework's registry.

| Kind | Source | `threshold` means | `minutes` means | Opens on | Resolves on |
|---|---|---|---|---|---|
| `defender_threat` | events 1006, 1116, 1015 | minimum threat severity: 1 Low, 2 Moderate, 4 High, 5 Severe (from the event's severity name) | unused | a detection at or above the threshold, subject the threat ID | event 1117 or 1007 for the same threat ID, or manually |
| `defender_remediation_failed` | events 1008, 1118, 1119 | unused | unused | a failed action, subject the threat ID | a 1117 for the same threat ID |
| `defender_protection_off` | events 5001, 5010, 5012; Facts `realtime` | unused | grace in minutes before opening (restarts write these) | the event, or Facts reporting real-time off for the grace | 5000, 5009, 5011, or Facts reporting on |
| `defender_signatures_old` | Facts `signatureAgeDays` | age in days | unused | age at or above the threshold | age below it |
| `defender_update_failed` | events 2001, 2003, 2006 | unused | minutes a failure stays unanswered by 2000 or 2002 | a failure with no later success inside the minutes | 2000 or 2002 |
| `defender_config_changed` | events 5004, 5007 | unused | unused | a change to a security-relevant key (below) not made by EasyRMM | manually, or after 7 days |
| `defender_exclusion_changed` | event 5007 on an exclusion key | unused | unused | an exclusion added or removed not by EasyRMM | manually, or after 7 days |
| `defender_tamper_blocked` | event 5013 | unused | unused | a blocked change not made by EasyRMM | manually, or after 7 days |
| `defender_unhealthy` | events 3002, 5008 | unused | unused | the event | 3007, or Facts `runningMode` normal and no 5008 since |
| `defender_out_of_support` | events 5100, 5101; Facts `platformVersion` | unused | unused | the platform expires soon (5100) or is expired (5101) | a platform update (Facts platform version changes) or 2006's absence for a day after a 2002 |
| `defender_tamper_off` | Facts `tamperProtected` | unused | unused | Tamper Protection reads off on an active Defender | it reads on, or Defender is not active |
| `defender_scan_overdue` | Facts `quickScanAgeDays` | age in days | unused | age at or above the threshold (never run counts as overdue) | age below it |

* **Subject and dedup.** An alert is per policy, device and subject, as
  `repair_failed` already is (`Subject`): the same threat found again
  updates the open alert (last seen, count) instead of opening another.
* **Best match.** For kinds with a threshold (`defender_threat`,
  `defender_signatures_old`), when more than one enabled policy matches an
  event or a reading, only the one with the **highest threshold** it
  satisfies opens an alert (so a 7-day policy hides the 3-day one on the same
  computer; a Severe threat is not alerted twice). *Decided in review.*
* **Which 5007 changes count.** The server classifies the event's old and new
  value by key: real-time protection, anti-spyware and antivirus switches,
  `Exclusions\`, ASR, CFA, network protection, MAPS, default threat actions.
  Others (Defender writes many on its own) are stored and shown in Events
  and open no alert. The classification list is data in the catalogue,
  *to confirm against real events* at R5.
* **EasyRMM's own changes are not alerts** (the principle of ADR-0060). The
  server tags an event `ours` and shows it in Events with the cause when it
  falls inside the window of (a) a `winmod` Defender change job on that
  device, from 5 seconds before its start to 60 seconds after its end, or
  (b) a reconcile or removal event ADR-0070's agent reported
  (`DefenderEvents`). A write the *module* attempted that Tamper Protection
  blocked is likewise `ours`. Changes outside those windows alert, including
  an administrator's change at the computer.
* **Not applicable.** Kinds that depend on an active Defender
  (`protection_off`, `tamper_off`, `unhealthy`, `scan_overdue`,
  `signatures_old`, `config_changed`, `exclusion_changed`) do not evaluate where `runningMode`
  is `Passive` or Defender is not the active antivirus, and resolve with
  the reason `not applicable`. A module that is off evaluates nothing and
  resolves with `module off` (ADR-0073).
* **Evaluation.** The monitoring engine already has the loop: `Service.Run`
  (`server/internal/monitoring/service.go`) calls `Evaluate` every
  `EvaluateInterval` (one minute) under an advisory lock. Defender's kinds
  are evaluated **in that loop**, as one more pass in `Evaluate` over
  `defender_events` and the Facts detail, so there is no second timer. The
  grace of `defender_protection_off` and the minutes of
  `defender_update_failed` are conditions that pass on a tick: an open
  "protection off" event with no later 5000, 5009 or 5011 and, for the
  grace, an event time older than `minutes`; a 2001, 2003 or 2006 with no
  later 2000 or 2002 older than `minutes`. Detection kinds could also open
  on arrival, but waiting at most one minute keeps one code path, so they
  do not. Every pass goes through `modules.Allowed(ctx, org)`.
* **Notifications** use the existing policy and notification paths; the
  module adds none.

#### Default policies

Created per organization, idempotently, keyed by module and name, when the
module is first enabled there, owned by the module and marked `default`
(ADR-0073 section 6: not editable or deletable by a normal user, only
turned off, refreshed on upgrade where the user has not changed them). All
are organization-level rows, enabled, except where stated.

| Name | Kind | Threshold | Minutes | Severity | Default |
|---|---|---|---|---|---|
| Defender: high or severe threat | `defender_threat` | 4 | - | critical | on |
| Defender: low or moderate threat | `defender_threat` | 1 | - | warning | on |
| Defender: threat not removed | `defender_remediation_failed` | - | - | critical | on |
| Defender: real-time protection off | `defender_protection_off` | - | 5 | critical | on |
| Defender: Tamper Protection off | `defender_tamper_off` | - | - | warning | on |
| Defender: signature update failing | `defender_update_failed` | - | 240 | warning | on |
| Defender: engine or platform out of support | `defender_out_of_support` | - | - | critical | on |
| Defender: not healthy | `defender_unhealthy` | - | - | critical | on |
| Defender: exclusions changed | `defender_exclusion_changed` | - | - | warning | on |
| Defender: Tamper Protection blocked a change | `defender_tamper_blocked` | - | - | warning | on |
| Defender: protection settings changed | `defender_config_changed` | - | - | warning | **off** |
| Defender: signatures out of date (7 days) | `defender_signatures_old` | 7 | - | warning | **off** |
| Defender: no recent scan | `defender_scan_overdue` | 7 | - | warning | **off** |

(Thirteen rows, twelve kinds.) *Decided in review.* The owner asked for
default rules, so the ones that mean something is wrong now are on:
detections at every severity, real-time protection off past its grace,
Tamper Protection off, a failing signature update, and an engine or platform
out of support. Three are created **off**: "protection settings changed"
(Defender writes many changes on its own and administrators change settings
on purpose), and the two that measure **age** (signatures, last scan). Age
rules fire on every laptop that is switched off for a week or on holiday and
on the servers of a closed office, which teaches people to ignore alerts; an
organization whose computers are always on turns them on, and the age
default is 7 days, not 3. An organization turns any default off or on.
Creation, like every automatic behaviour, calls `modules.Allowed` and so
`devscope.Allowed(org)`.

### 8. Desktops, servers and Server Core

* **Desktops (Windows 10 and 11).** Full set. `runningMode` and
  `otherAntivirus` show Defender going quiet when another product is
  installed (the compatibility table above); Smart App Control can put
  Defender in a passive-like state, which the banner names.
* **Servers (2016 and later).** Same set. Defender is a feature on servers
  and may be absent: the role is then `not present` and the module is not
  offered. A server with a non-Microsoft product keeps Defender active
  unless an administrator set passive mode or removed it, so the module
  shows `Normal` and a note when `otherAntivirus` is detected, since two
  scanners conflict (Microsoft's advice, not ours to change). Windows Server
  adds `DisableAutoExclusions` (automatic role exclusions). Windows Server
  2016 may lack ASR, network protection or CFA properties: a field the
  cmdlet does not return reads `supported: false` and its controls are
  hidden, decided by the property being absent, never by the OS version.
* **Server Core.** The module needs no desktop session and no Windows Security
  app: it uses the Defender PowerShell module, `MpCmdRun.exe` and the
  Operational log, all of which run in a service context, and the console is
  the only interface. Because the Windows Security app is absent there, a
  Tamper Protection change on Server Core is by Intune, the Defender portal
  or (with no management) not at all; the panel says so. That the module
  works on Server Core is **to confirm on a real Server Core device** (R9);
  until then the ADR says "not verified on Server Core".
* **A domain controller** gets the same module. No step promotes or demotes
  one.

### 9. Tests

* **Unit (Go, no Windows).** Per action: the validator (accepts and
  rejects, fuzz on paths and values: `..`, device paths, wildcards, quotes,
  `$()`, backticks, newlines, `;`, 260-character limit, the extension and
  process deny-lists); the field table against the pinned parameter list and
  each field's direction and tier; the stdin builder (hostile values arrive
  unchanged); the result decoder (good, truncated, wrong version, unknown
  fields); the `ours` function (the fixed set, both records, a corrupt
  record, case, trailing slashes, short names, a parent of an excluded
  folder); the owner reader's mapping from a table of registry states to
  `managedBy`; the event normaliser from stored XML of each ID (fixtures
  with fields from Microsoft's pages); the bookmark (first run, resend,
  gap, cleared log, storm coalescing, byte cap); the severity mapping; the
  5007 classifier; the best-match rule; the catalogue lint (permission,
  version, timeout, `Destructive` implies confirmation, tier 3 implies
  step-up and `defender.weaken`, script hashes match).
* **Server integration (real PostgreSQL).** Permission matrix for the five
  built-in roles on every action, including that a Technician cannot do a
  tier 3 action and Read-Only sees nothing; toggle off sends no job, no
  event query answer and evaluates no kind; the 404 rule; a job round trip
  with the contract-test fake for each tier, with the confirmation and
  step-up refused when missing; `409 managed_by_policy` from a snapshot
  naming an owner; `protected_exclusion` from the server guard and from a
  fake agent returning it; event ingest: duplicates (same batch twice),
  acknowledgement, backfill not alerting, gap, retention of `sensitive`;
  each alert kind opens and resolves from stored events or Facts; `ours`
  windows suppress the alert and keep the event; passive mode skips; the
  default policies are created once, not duplicated on a second enable or an
  upgrade, not editable, can be turned off; `devscope` disallowed
  organization gets no job, no events and no policies; sensitive fields
  absent for a caller without `defender.view_sensitive`; the audit row holds
  no exclusion value for a caller's audit export beyond length and hash.
* **Windows runner CI** (a job `windows-defender-module`, on
  `windows-latest`, following the framework's job): every script passes the
  AST check of ADR-0073 plus these Defender rules: no `Set-MpPreference`
  with a list parameter, no `Remove-MpPreference` outside the guard
  function, no `-ExclusionPath` etc. value built from a string, no write
  under `Policies` keys; the stdin pattern with hostile values; the read
  actions return typed results; `defender.status` returns the shapes
  Microsoft shows; a harmless preference (`ScanAvgCPULoadFactor`) is
  set, read back and put back, with the result recorded whichever way
  Tamper Protection answers; the event reader reads a seeded detection
  (an EICAR test string assembled at run time from two halves, never stored
  in the repository, scanned with a custom scan of a temporary folder) and
  proves the bookmark, resend and dedup; an exclusion add of a temporary
  folder and its removal, and that the guard refuses a value from a
  record file written by the test. What the runner cannot do (Defender
  may be configured by the image; Tamper Protection state is unknown) is
  **recorded in the job summary, not assumed**; scan design A or B is
  decided from R2, not from this job.
* **Real devices: the owner's Windows servers** (the test devices the owner
  names when the run happens). Allowed there: Defender setting changes,
  reinstalls and reboots. **Not allowed:** promoting a domain controller.
  Run by the owner or the orchestrator; until run, the ADR says "not
  verified on a real device". Steps:
  * **R1** Enrol; confirm `roles` lists `defender` with its detail, and the
    Security tab matches `Get-MpComputerStatus`, `Get-MpPreference` and the
    Windows Security app. Note each setting's owner and the Tamper state.
  * **R2** Run a quick scan from the console; find whether the job can end
    while the scan continues (design A) or holds the slot (design B);
    cancel a full scan; write the result here as an amendment.
  * **R3** Signature update; confirm versions change and 2000 appears.
  * **R4** Change a harmless preference, then a tier 3 one (turn behaviour
    monitoring off and on); confirm the confirmation, the step-up, the audit
    rows, the read-back, and that 5007 appears and **no** alert opens for
    the module's own change; then change the same setting at the computer
    and confirm an alert opens.
  * **R5** Seen real 5007 events: confirm the key classification, and
    confirm in a test that `Add-MpPreference` (not `Set-`) is the right call
    for ASR rules and leaves the other rules alone.
  * **R6** Add and remove an exclusion for a test folder; try to remove one
    of ours from the console (refused) and, by a direct request, the server
    and the script both refuse; reboot and confirm ours are still listed
    and `effective` (ADR-0070 states), and that reconcile restores one
    removed by hand.
  * **R7** A computer with Group Policy or Intune setting a Defender value:
    the field shows "managed by policy", the write is refused, and if the
    policy is later removed the field unlocks. Record the registry
    location that Intune used (the *Policy Manager* assumption).
  * **R8** An EICAR detection from a custom scan: the alert opens, history
    shows it, `quarantine_read` lists it (paths for a `view_sensitive`
    caller only), restore it with the step-up and see it return and be
    detected again; confirm the alert resolves on 1117.
  * **R9** Server Core (if the owner has one) and Windows Server 2016 (if
    any): which panels hide, and that nothing needs a desktop session.
  * **R10** Reinstall Defender on a server (`Uninstall-WindowsFeature` and
    `Install-WindowsFeature` of Windows-Defender, reboot): the role goes
    away and returns, module snapshots clear, open alerts resolve with
    `role removed`, default policies are not duplicated.
  * **R11** Clear the Defender Operational log: the reader reports a gap and
    nothing is lost afterward.
  * **R12** Turn the module off for the organization: no job, no event
    polling, alerts resolve with `module off`; on again.

### Organization scope

`devscope.Allowed(orgID)` is applied through `modules.Allowed` (ADR-0073's
framework gate) to: the hourly Defender detail refresh, the event reader's
answer, event-driven and Facts-driven alert evaluation, and default-policy
creation. Reads and actions a user starts are gated by the toggle and the
permission as ADR-0073 sets. The guard has not landed everywhere; until it
has, the function calls `devscope.Allowed` and the toggle only.

## Slices

Files named are ones that exist in the repository today (checked on
2026-11-26); a path marked *new* is proposed. Builders make small additive
edits to the hotspots, never reordering around them: `server/internal/rbac/rbac.go`,
`internal/agentproto/agentproto.go` and `defender.go`, `agent/runner/runner.go`
and `defender.go`, `web/src/pages/devices/DeviceDetailPage.tsx`,
`web/src/pages/organizations/levelTabs.tsx` (the tab registry),
`server/internal/agents/heartbeat.go` and `defender.go`, and the server's `app.go`. A slice is merged
only when the catalogue lint and its Windows-runner tests pass.

1. **D1 Facts detail, `defender.status`, and the owner reader.** The `detail`
   object on the `defender` role, the hourly refresh, `DefenderPolicy.module`,
   the registry owner reader (reusing `internal/winpolicy`), `defender.status`
   as ADR-0073's proof action, `preferences_read`. Files: `internal/agentproto/defender.go`,
   `agent/runner/defender.go`, `internal/winpolicy` (reused), `server/internal/agents/heartbeat.go`
   and `defender.go`; new `server/internal/winmod/defender/` (catalogue, scripts). Needs ADR-0073 slices 1,
   2, 5.
2. **D2 Permissions and catalogue skeleton.** `defender.view_sensitive`,
   `defender.weaken`, role unions, the tier field and its lint, the field
   table with its pinned-list test, the `ours` function, the validators.
   Files: `server/internal/rbac/rbac.go`, new `server/internal/winmod/defender/`. Independent of D1; needs ADR-0073 slice 2.
3. **D3 Scans, updates, threats.** `scan_start`, `scan_custom`, `scan_cancel`,
   `signatures_update`, `threats_remove`, `threats_read`; the scan design from
   R2 (until R2, design B with its caps). Needs D1, D2.
4. **D4 Preferences, ASR, CFA.** `preferences_set`, `asr_set`, `cfa_*`,
   the managed-by-policy refusal and read-back. Needs D1, D2; ADR-0073
   slice 4 (step-up).
5. **D5 Exclusions and protection of ours.** `exclusions_read`,
   `exclusion_add`, `exclusion_remove`, the three guards and their tests.
   Needs D1, D2; ADR-0073 slice 4.
6. **D6 Quarantine.** `quarantine_read`, `quarantine_restore`, sensitive
   handling. Needs D1, D2; ADR-0073 slice 4.
7. **D7 Event reader and store.** New `agent/winevents`, the bookmark, the
   heartbeat field and acknowledgement (`internal/agentproto/agentproto.go`,
   `server/internal/agents/heartbeat.go`), `DefenderPolicy.events`, the
   migration `server/migrations/9xxxx_defender.sql`, retention, the Events
   read. **Needs ADR-0073 slice 1** (`modules.Allowed`, the role and the
   gate) **and `DefenderPolicy.events`** (built here, additive); D2 for the
   permission; independent of D3 to D6.
8. **D8 Alerts and default policies.** Twelve kinds, best-match rule, `ours`
   windows, 5007 classifier, thirteen default policies, skip rules, the pass
   in `Evaluate`. Files: `server/internal/monitoring/policies.go`,
   `evaluate.go`, `service.go`. Needs D7, D1, and ADR-0073 slice 7.
9. **D9 UI.** The Security tab's panels (Status, Protection, ASR, CFA,
   Exclusions, Threats and quarantine, Scans, Events), the group column, the
   site and organization cards, the org tab, the "managed by policy" lock
   component. Files: `web/src/pages/devices/DeviceDetailPage.tsx`,
   `web/src/pages/organizations/levelTabs.tsx`, new
   `web/src/pages/devices/security/` (one file per panel). Needs ADR-0073 slice 8; each panel needs its action's slice
   (Status needs D1; Events needs D7); panels are independent of each other.
10. **D10 CI and the real-device run.** The Windows job (new, in
    `.github/workflows/`; **depends on ADR-0073 slice 9**, which builds the
    shared Windows-runner job and the AST check), the Defender AST
    rules (grows with each slice, started with D2), and the R1 to R12 runbook
    with its results written back here.

D1, D2 and D7 start together; D3 to D6 in parallel after D1 and D2; D8 after
D7; D9 panels as their slices land.

## Consequences

* The console gets full Defender management that stays inside what Windows
  allows: it never changes Tamper Protection, never writes policy, never
  deletes a quarantined item, and says so.
* Two new permissions exist beyond ADR-0073's list; Technicians keep
  scans, updates and strengthening, and lose the dangerous half.
* An administrator who needs one of the blocked exclusions (a wildcard, a
  whole drive) must use the script runner, audited as a script.
* The agent gains a periodic event reader and one more field in the
  heartbeat; both stop when the module is off.
* The default policies create thirteen policy rows per organization on first
  enable; an organization sees them in Alert policies with a "default" badge.
* Scan behaviour (design A or B) is not known until R2; until then full
  scans hold a slot.
* Many Microsoft facts here come from documentation, not from a computer:
  the `Policy Manager` key, `TamperProtectionSource` values, `Add-MpPreference`
  for ASR, the 5007 key list, and Server Core are each marked *to confirm*.

## Owner decisions

The owner's request is the only owner decision recorded (a module for
"Full Management, or as much as we can from the UI", Defender alerts usable as
alert rules, default rules for Defender). Worth the owner's eye, with defaults
chosen in review:

1. Technicians cannot lower protection or restore a quarantined file
   (`defender.weaken` is Site Administrator and above).
2. Quarantine "remove" is offered as removing active threats and setting
   quarantine retention, because Windows documents no per-item delete.
3. Ten of the thirteen default policies are on; the three that measure age or settings changed are off.

## Amendments to ADR-0073 (decided in review)

All are additive. Where one touches the protocol, an older agent or server
keeps working: a field an older agent does not know is ignored, a server
that does not answer the field reads as "module off", and the server sends
no Defender work to an agent below the protocol level that reports it
(ADR-0009, *Evolving the protocol*).

* **Section 3:** the Defender row gains `defender.view_sensitive` and
  `defender.weaken` (above).
* **Section 1:** the `defender` role entry gains the optional `detail`
  object, refreshed hourly, not at the 6-hour role scan.
* **Section 6, the monitoring engine:** the **best-match rule** (for kinds
  with a threshold, of several enabled policies that match one event or
  reading, only the one with the highest threshold opens an alert) is a change
  to `monitoring.Evaluate`, not Defender-only; it applies to any registered
  kind that declares a threshold, so a later module gets it. Event-driven kinds
  are evaluated in the existing one-minute loop, not a new timer.
* **Heartbeat and storage:** the `DefenderPolicy` answer gains `module` and
  `events`, the heartbeat gains the events batch and the answer gains its
  acknowledgement, and the `defender_events` table is added. All are
  additive protocol-level features (an agent that does not report the level
  sends no events; the server shows "update the agent").
* **Step-up:** nothing is restated here; ADR-0073's step-up duration is
  whatever ADR-0055 defines.
* **Section 6:** the Defender event log is read by an agent-side reader with a
  bookmark, not by ADR-0068's job-based builtin, to avoid a job per minute.

## Amendments made while building (decided in review)

Amended 2026-11-26 (decided in review), while building the module. Each is what the code proved or what a slice left for later, not an owner decision.

* **Parameters are single values.** ADR-0073's parameter types have no list or map, so `preferences_set` takes one `field` and one `value` (not up to 8 fields), `asr_set` one rule (not up to 20). The direction decides the action: `preferences_set` (tier 1) refuses a value that lowers protection, `preferences_weaken` (tier 3) refuses one that does not; likewise `asr_set` (Enabled, Warn) and `asr_weaken` (AuditMode, Disabled), `cfa_set` (Enabled) and `cfa_weaken` (Disabled, AuditMode). The refusal is a `422` that names the other action, so a weakening value can never ride a tier 1 request.
* **Tier 3 is one permission.** A tier 3 action carries `defender.weaken` alone; everyone who holds it also holds `defender.manage` (a test checks it), so "manage and weaken" holds. A tier 2 action uses the framework's `Confirm` flag (the typed confirmation without a step-up); the framework also gained `Check`, a module's own check of the validated parameters.
* **The confirmation subject** is the value, such as the exclusion or the field; for `threats_remove`, which has no value, it is the computer's name (`device`, `SubjectIsDeviceName`, which the server compares with the real name). One mechanism: `Confirm` or `Destructive` with a `Subject`.
* **Scans** are three actions, `scan_quick` (2 hours), `scan_full` (24 hours) and `scan_custom` (6 hours), design B until R2. The `scan_running` refusal beyond Defender's own refusal of a second scan is not built.
* **`quarantine_restore` takes the threat `name` only**; the script checks the name is in the quarantine list on the computer. There is no `filePath` variant.
* **Sensitive reads are served whole**: `exclusions_read`, `cfa_read` and `quarantine_read` are sensitive actions, so a holder of `defender.view` without `defender.view_sensitive` gets none of them (the console hides the panels), not a version with our own entries marked.
* **Managed by policy** is decided by the script on the computer (the registry owner reader, Tamper Protection, `unknown_owner` writable); the server's earlier `409 managed_by_policy` from a stored snapshot is not built. The script's refusal comes back as the run's failure `managed_by_policy`.
* **State** comes from the hourly `defender.status` snapshot, not from a `detail` object in Facts: the Facts `detail`, its hourly agent timer and `DefenderPolicy.module` are not built. The fleet table and the cards read that snapshot.
* **Events** ride the heartbeat (about every 60 seconds) instead of a separate timer. A log incarnation is an `epoch` the agent names (a cleared log starts a new one) instead of `log_created`; a gap is told by the channel's oldest and newest record IDs. The `defender_events` table has `epoch` for that and `severity` as a rank.
* **Event alert kinds** are judged from a derived snapshot, `defender.events`, which the server rebuilds from `defender_events` when a batch arrives and at least every 30 minutes while the module is on, so the monitoring engine's existing snapshot path evaluates them (no new pass in `Evaluate`). An alert is therefore one per policy and device, not per threat; its detail names up to three threats. The best-match rule was already in the engine. The grace of `defender_update_failed` counts from the server's first reading of the failure. `defender_protection_off` stays status-based (event 5001 adds no input). `defender_unhealthy` and `defender_out_of_support` end after 24 hours and 3 days without a repeat, not by Facts. The ours window of ADR-0070's own reconcile events is not built; the window of a Defender change job is.
* **Not built:** the protection-state column and filter on the device group page, and the e2e spec. Not verified: everything marked *to confirm* above (the `Policy Manager` key, `TamperProtectionSource` values, `Add-MpPreference` for ASR, the 5007 key list, event field names, MpCmdRun's quarantine listing format), and Server Core.

## References

Read on 2026-11-26 unless marked *not re-read* (cited from the knowledge the
design relies on; confirm before building):

* Set-MpPreference parameters and their types and values (`MAPSReporting`
  0 to 2, `SubmitSamplesConsent` 0 to 3, `PUAProtection`, `EnableNetworkProtection`,
  `EnableControlledFolderAccess`, threat default actions, `ScanAvgCPULoadFactor`
  0 or 5 to 100, `SignatureUpdateInterval` 1 to 24, `QuarantinePurgeItemsAfterDelay`,
  `CloudExtendedTimeout`, `ScanScheduleDay`, `ScanParameters`):
  https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference
* Event IDs, symbolic names, messages and the fields of 1116 and 5007:
  https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
  (IDs 1000, 1001, 1002, 1006, 1007, 1008, 1015, 1116 to 1119, 1121, 2000 to
  2003, 2006, 3002, 3007, 5000, 5001, 5004, 5007 to 5013, 5100, 5101 are on
  this page; 1005 and 1122 to 1124 were not found on it).
* `MpCmdRun.exe` (`-Scan -ScanType 0 to 3`, `-Cancel`, `-File`,
  `-SignatureUpdate`, `-Restore -ListAll`, `-Restore -Name`, `-FilePath`,
  `-Path`, scan timeouts, locations):
  https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus
* `Remove-MpThreat`, `Get-MpThreat`, `Start-MpScan`, `Update-MpSignature`,
  `Get-MpComputerStatus` (properties `AMRunningMode`, `QuickScanAge`,
  `FullScanAge`, signature fields):
  https://learn.microsoft.com/en-us/powershell/module/defender/remove-mpthreat ,
  .../get-mpthreat , .../start-mpscan , .../update-mpsignature ,
  .../get-mpcomputerstatus
* Tamper Protection, what it blocks, who manages it, Server support:
  https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-overview
  (`IsTamperProtected` and `TamperProtectionSource` are named in its
  configuration article, *not re-read*:
  https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-windows-configure )
* Active, passive and disabled modes, `ForceDefenderPassiveMode`, Server
  behaviour, `AMRunningMode`:
  https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility
* *Not re-read:* common exclusion mistakes:
  https://learn.microsoft.com/en-us/defender-endpoint/common-exclusion-mistakes-microsoft-defender-antivirus ;
  ASR rules and their GUIDs:
  https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference ;
  Defender CSP (Intune):
  https://learn.microsoft.com/en-us/windows/client-management/mdm/defender-csp ;
  Defender Group Policy settings (ADMX `WindowsDefender.admx`):
  https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender
* Repository: `agent/defender`, `internal/agentproto/defender.go`,
  `internal/winpolicy`, `server/internal/monitoring/policies.go`,
  `server/internal/rbac/rbac.go`.
