# ADR-0073: The framework every Windows management module builds on

* Status: Proposed (2026-11-26). Design only; no code is changed by this ADR.
* Asked for by the owner (2026-11-23 and 2026-11-26), for the four modules
  that build on it: Windows Defender (ADR-0074),
  Active Directory (ADR-0075), the server roles
  (ADR-0076) and Windows Backup
  (ADR-0077). Everything marked *decided in review*
  is the writer's call and the owner can overturn it.
* Builds on: [ADR-0017](0017-scripts-and-jobs.md) and the fixed-script kinds
  of `docs/architecture/feature-plan-msp.md` (F2),
  [ADR-0064](0064-remote-powershell-management.md) (PowerShell on the
  computer), [ADR-0065](0065-hardware-health.md) (a reading with a state, a
  deadline and alerts), [ADR-0067](0067-remote-registry-editor.md) and
  [ADR-0068](0068-remote-event-viewer.md) (sensitive results hidden by kind),
  [ADR-0072](0072-what-each-page-shows.md) (where modules appear) and
  [ADR-0059](0059-the-agents-websocket-channel.md) (the channel: wake only).
* The dev-scope guard (`devscope.Allowed`) applies to everything here that
  acts on its own (detection, scheduled reads, alert evaluation); see
  *Organization scope*.

## Context

The owner wants four sets of Windows management from the console, each with
"full management, or as much as we can from the UI": Defender, Active
Directory, six server roles (certificate authority, DNS, DHCP, file sharing,
print) that "can be toggled off", and Windows Backup on desktops and
servers. Built one by one they would each invent a way to find the role, a
switch, permissions, a way to run PowerShell safely, a cache, alerts and a
tab. The ADR writes that once.

What exists today:

* **Jobs.** The agent runs up to four jobs at once (`agent/jobs/worker.go`);
  the server signs each job with its Ed25519 key (`server/internal/jobs/key.go`).
  The `software` and `hardening` kinds already run a script of EasyRMM's own
  compiled into the server, with arguments the server checks against fixed
  lists and a structured last line (`hardening.go`). F2 generalises that: a
  permission per kind, retention per kind, compact audit, kept out of the Jobs
  list.
* **Prior patterns.** ADR-0067 and ADR-0068 read the registry and event logs
  through F2 builtins, hide sensitive fields by kind (`log.view_sensitive`)
  and keep results an hour; ADR-0065 reads disks on a schedule with a fixed
  deadline and raises alerts from the server's rules.
* **Facts.** `agentproto.Facts` is sent at enrollment and with every
  heartbeat; it holds names and versions, no roles.
* **RBAC.** `rbac.Permission` strings, `AllPermissions`, and five built-in
  roles whose sets are unions (`viewPerms`, `technicianPerms`,
  `siteAdminPerms`, `orgAdminPerms`).
* **Alerts.** Policies at shared, organization and site level
  (`monitoring/policies.go`) with kinds such as `disk_health`; some kinds
  belong to no policy and are opened by a service (`repair_failed`).

## Decision

### In short

1. The agent reports which roles and features are installed, cheaply, as a
   `roles` fact. The server stores it; a module is offered only where its
   role is present.
2. A module is a row in a table of toggles per organization with an optional
   site override. Off means no agent call, no scheduled read, no alert
   evaluation, no tab.
3. Each module has `<module>.view` and `<module>.manage` permissions, plus a
   `<module>.view_sensitive` where results hold secrets or personal data.
4. Actions are fixed PowerShell scripts compiled into the server (F2 kinds),
   one kind per module, with a named action and typed arguments. Parameters
   are checked on the server and reach PowerShell as a JSON document read
   from standard input, never joined into script text. Results are one typed
   JSON line.
5. Reads are on demand with a cached, timestamped snapshot, or come from
   Facts.
6. Modules register alert kinds and default policies.
7. One tab per module per level, from ADR-0072's table.

### 1. Role detection

* **Where.** One new Facts field, `roles`: a list of
  `{name, state, version?}` with names from a fixed set (`ad_ds`, `ad_cs`,
  `dns`, `dhcp`, `file_server`, `print_server`, `windows_backup`,
  `defender`). Unknown names are dropped by the server. Adding the field is
  additive to the heartbeat; an older server ignores it and an older agent
  sends none, which the server reads as *unknown*, not *absent* (modules then
  show "not detected yet", not "not installed").
* **How, without PowerShell.** The agent does not start PowerShell to detect.
  Detection is Go code in the agent that is cheap and has no process to hang:
  * **Servers.** The installed state of the Windows features comes from the
    Component-Based Servicing registry keys and the service control manager,
    both direct reads: service present (`NTDS`, `CertSvc`, `DNS`, `DHCPServer`,
    `LanmanServer` with at least one non-administrative share found through
    `NetShareEnum`, `Spooler` with the role's print-server feature key,
    `wbengine`). A running service is not enough on its own (the print spooler
    runs on every desktop), so each role pairs its service with the feature's
    key under `HKLM\SYSTEM\CurrentControlSet\Services` or its servicing state.
  * **Domain controller.** `NTDS` present and the `ProductType` value equal to 2
    (a domain controller), from the registry. This is also F1's domain
    controller flag, so there is one source.
  * **Defender.** The `WinDefend` service, and `MSFT_MpComputerStatus` through
    WMI (`root\Microsoft\Windows\Defender`) for the engine and signature
    versions, in a child process with a deadline (below). Defender in passive
    mode, or replaced by another product, is reported with its state.
  * **Windows Backup.** Server: the `wbengine` service and the
    `Windows-Server-Backup` feature key. Desktop: the File History and
    Backup and Restore settings are always present, so `windows_backup` is
    reported on every Windows computer, with its state (*not configured* or
    *configured*) from the registry.
  * **Client or server.** `ProductType` 1 or not decides which of the
    server-only roles can be reported at all; a desktop never reports `dns`
    and the like.
* **When.** At enrollment, at agent start, and then at most once every 6
  hours, or at once when the server asks (the Repair path, an "Rescan roles"
  action that requires `device.edit`). Not every heartbeat; the heartbeat
  carries the last result unchanged. A changed result is sent with the next
  heartbeat.
* **Timeout.** Every part has a deadline. The registry and service reads are
  local and bounded (2 seconds for the lot). The one WMI call (Defender)
  runs in a child process killed after 10 seconds; if it fails the role is
  reported with `state: "unknown"` and the failure is not an error that
  breaks the heartbeat. A computer where detection cannot run reports no
  `roles`, and the server keeps the last known list for 7 days before
  marking it *unknown*.
* **Safe.** Read-only; no cmdlet loads a module (`Get-WindowsFeature` loads
  ServerManager and takes seconds, and is not used); nothing is written. The
  list is data the server stores per device and never executes.
* **Not a gate on security.** Detection decides what is *offered*. The
  server still checks the permission and the toggle on every call; a forged
  `roles` list can only make a tab appear, and the tab's calls then fail on
  the computer.

### 2. Module toggles

* **Table.** `windows_module_settings(organization_id, site_id NULL, module,
  enabled)`, a row per override, with one `site_id` null row per
  organization. Modules: `defender`, `active_directory`, `certificate_authority`,
  `dns`, `dhcp`, `file_shares`, `print`, `windows_backup`.
* **Resolution.** A site row wins over its organization's row; no row means
  the module's default, which is **on** for `defender` and `windows_backup`
  (they are on every Windows computer) and **on** for the server roles *where
  the role is detected* (*decided in review*: the owner said they "can be
  toggled off", which means on by default). A module needing a setup step
  (a connector credential) does not exist here.
* **Offered when** the role is detected on the device *and* the module is
  enabled for its site *and* the caller has the view permission. The tab
  hides, and the API answers 404 for a module that is not offered, not 403,
  so the endpoint does not confirm a role.
* **Off means silent.** A module that is off: the server sends no job of its
  kind, schedules no snapshot refresh, evaluates none of its alert kinds, and
  shows no tab. Role detection itself still runs (it is part of the
  heartbeat and sends nothing extra); turning a module off does not delete
  its stored snapshots, which stop being read and age out under the
  retention below. Turning it on again is immediate.
* **Who changes it.** `org.manage` at the organization (a site override
  needs `site.manage`). The change is audited (`windows_module.set`, with
  module, scope and old and new value). The settings sit on the
  organization's and site's own pages (ADR-0072), in a "Windows modules"
  card, not in Settings.
* **Dev scope.** The toggles are data and need no guard; every scheduled
  read and alert evaluation the modules start checks `devscope.Allowed(org)`.

### 3. Permissions

For each module `m`: `m.view` (read the module's state and lists) and
`m.manage` (change things). A module whose results include secrets or
personal data adds `m.view_sensitive`, in the manner of `job.view_sensitive`
and `log.view_sensitive`.

| Module | Permissions |
|---|---|
| Defender (0074) | `defender.view`, `defender.manage` (settings, exclusions, scans, signature updates, quarantine release) |
| Active Directory (0075) | `ad.view`, `ad.manage` (create, change, disable users and groups, unlock), `ad.reset_password`, `ad.view_sensitive` (group membership of privileged groups, last logons, security descriptors) |
| Server roles (0076) | `ca.view`, `ca.manage`; `dns.view`, `dns.manage`; `dhcp.view`, `dhcp.manage`; `shares.view`, `shares.manage`; `print.view`, `print.manage` |
| Windows Backup (0077) | `backup.view`, `backup.manage` |

Built-in roles (*decided in review*):

* **Read-Only** gets none of them. Module state (users, shares, printers,
  certificates, backup paths) is more than a status light; this follows
  `log.view`, which Read-Only also lacks. The Overview cards from ADR-0072
  show counts and health only, through the existing view permissions.
* **Technician**: every `*.view` except `ad.view_sensitive`, plus the
  reversible, low-blast-radius `defender.manage`, `backup.manage` and
  `print.manage`. No Active Directory management.
* **Site Administrator**: everything a Technician has, plus `dns.manage`,
  `dhcp.manage`, `shares.manage`, `ad.manage`, `ad.view_sensitive`.
* **Organization Administrator**: Site Administrator plus `ca.manage` and
  `ad.reset_password`.
* **Super Administrator**: all, as today.

Row-by-row, the same rules the other permissions use apply: each is checked
at the device's site through `access`, so a site administrator acts only on
their site's computers, and a global-only rule is not used here. The
destructive and credential actions (below) need `manage` plus a confirmation,
so the permission is never the only gate. The new permissions are added to
`AllPermissions` and to the unions in `rbac.go` by a small additive edit.
Custom roles, if they exist by then, see them in the same list.

### 4. Execution: fixed, versioned actions

* **One job kind per module** (`kind = "winmod"`, with `module` and `action`
  in the arguments, so one handler, one retention rule and one audit shape,
  not eight). It is an F2 kind: not shown in the Jobs list, retention per
  action (minutes for reads, the usual 90 days for nothing: results are not
  kept for backups), permission per module and action.
* **An action is a Go value on the server**, in a catalogue per module:
  `{Module, Name, Version, Script (embedded .ps1), Params schema, Result
  schema, Permission, Sensitive, Destructive, Timeout, Audit fields}`.
  The `.ps1` files are embedded in the server and sent in the job; the job
  is signed with the server's key as every job is, so the agent rejects an
  altered script. The agent does not change: it runs a script and reads the
  last line, as for hardening. Each script carries its action's `Version`
  and prints it in the result; the server rejects a result whose version is
  not the one it sent.
* **No free scripts.** There is no endpoint that takes PowerShell text for a
  module. An operator who wants more uses ADR-0064's script runner under
  `script.run`, which is audited as a script.
* **Parameters** are declared in the catalogue with a type, bounds and a
  pattern (names of users, groups, shares: length-bounded and from an
  allowed character class; paths: absolute, no `..`, no device paths; IDs:
  GUID or SID parsed; enumerations from a fixed list). The server rejects a
  value that does not match with 400 and the reason. Then:
  * the validated parameters are encoded as **one JSON document passed on
    standard input**, and the script's first line reads it with
    `$p = [Console]::In.ReadToEnd() | ConvertFrom-Json`; each value is used
    only as an argument *value* to a cmdlet (`-Identity $p.name`), never
    interpolated into a string, a `-Filter` expression, an LDAP filter or
    `Invoke-Expression`. Where a cmdlet takes a filter language (AD's
    `-Filter`, `Get-WinEvent -FilterXPath`), the script uses the form that
    takes the value as a parameter (`-Identity`, `-LDAPFilter` built by
    the script from an escaped value with RFC 4515 escaping in a tested
    helper) and the unit tests fuzz it.
  * Secrets (a new password) travel in the same stdin document, **never in
    the command line, an environment variable, the job's stored arguments
    or the audit row**. The server seals such a parameter in the job row
    (`secrets` package), deletes it when the job is delivered, and the
    script clears the variable. The password is generated by the console and
    shown once, or typed by the operator; the audit row records that a
    password was reset, not what.
  * Scripts start with `Set-StrictMode -Version Latest`,
    `$ErrorActionPreference = 'Stop'`, and run in the PowerShell ADR-0064
    chose for the computer, with the module they need imported by name from
    the system path (`-ErrorAction Stop` on the import; a missing module is a
    typed error, `module_missing`, not a stack trace).
* **Results are typed JSON.** The last line is
  `EASYRMM-WINMOD-RESULT-V1 {json}`; the JSON is `{ok, version, data, error}`
  where `data` follows the action's schema. The server decodes it into a Go
  struct for the module, rejects an unknown shape (as a failed job, with the
  raw output kept only for users with `job.view_sensitive`), and stores
  the typed value, not the text. Limits are F2's: 64 KiB structured result,
  and an action that can be long (a user list) pages by an opaque cursor the
  script returns.
* **Sensitive by kind.** Each action says whether its result is sensitive.
  Sensitive results are served only to callers with the module's
  `view_sensitive` (or `job.view_sensitive` for the job's raw output), are
  kept for minutes and not in backups of the job output, and are redacted in
  the audit row. The AD privileged-group membership and password reset
  results are sensitive; Defender's quarantine file paths are sensitive
  (they can name user files).
* **Audit.** Every action writes one audit row: `winmod.<module>.<action>`,
  the device, the actor, the validated parameters **except secrets and
  anything marked sensitive** (replaced by their length and SHA-256), the
  result's `ok` and a count. Reads write a row too, compact, one per query
  and not per click, within the audit log's 16 KiB limit.
* **Destructive actions are confirmed.** An action marked `Destructive`
  (delete a user, delete a group, remove an exclusion list, delete a share,
  clear a print queue, delete a backup set, disable a CA template, remove a
  DHCP scope) needs a confirmation in the request: the console shows the
  subject's name and the effect and the request carries
  `confirm: "<action>:<subject>"` that the server compares, so a stray
  request or script cannot do it by omission. Password resets, account
  disabling on a privileged account and anything on a domain controller's
  own computer account need the existing step-up (the second factor
  re-check) as well. The confirmation is part of the action's catalogue
  entry, not of each handler, so no action forgets it.
* **Dry run.** Where a cmdlet supports `-WhatIf`, a destructive action's
  confirmation dialog can ask for a preview first; the result of that is a
  typed list of what would change. Not required of every action.
* **The lane.** A module read can wait behind a 30-minute hardening job
  because the worker has four slots. This ADR does not add a reserved slot;
  the F2 feature that does (feature 7's ADR) covers it, and the framework
  reads the wait as "queued" in the console. If it proves slow in the real
  test below, a reserved slot is a separate protocol-level feature.

### 5. Reading state

* **Server-reported state** (role list, Defender engine and signature
  versions, whether Backup is configured) comes from Facts, with no job.
* **Everything else is on demand.** A tab loads by sending the module's read
  action; the server stores the typed result in `windows_module_snapshots
  (device_id, module, action, params_hash, taken_at, data jsonb)`, one row
  per action and parameters, replaced on the next read. The API returns the
  snapshot with `taken_at` and `stale` (older than the action's freshness,
  5 minutes by default, 1 minute for a list the operator just changed) and
  the tab shows "as of 14:02" with a Refresh button. Opening a tab returns
  the cached snapshot at once and starts a refresh if it is stale; a
  successful change action invalidates its module's snapshots and starts a
  refresh.
* **Offline computers.** A snapshot is shown, marked with its age, and the
  actions are disabled with the reason. No job is queued for a computer that
  is offline unless the action is one a scheduled alert needs.
* **Retention.** Snapshots are kept 7 days (sensitive ones 15 minutes),
  deleted by the retention job already in place for module data; a module
  that is turned off stops refreshing and its rows age out.
* **Scheduled reads.** Only where an alert needs a value that Facts does not
  carry (Windows Backup's last result, a certificate's expiry). They run at
  most hourly per device, only while the module is enabled and
  `devscope.Allowed(org)`, and never when the computer is offline.

### 6. Alerts

* **Kinds.** A module registers kinds with the monitoring package the way
  `disk_health` is registered: `defender_threat`, `defender_protection_off`,
  `defender_signatures_old`, `ad_replication_failed`, `ad_account_locked_out`
  (a count over a window), `ca_certificate_expiring`, `dns_service_stopped`,
  `dhcp_scope_exhausted`, `print_queue_stuck`, `backup_failed`,
  `backup_overdue`. The kinds are listed in each module's ADR; the framework
  fixes how they work: a kind has a name, a human label, the module it
  belongs to, the parameters of its policy (a threshold, minutes) and the
  source of its value, which is Facts, a snapshot, or an event the agent
  forwarded. The Windows Event Log channel for a kind (Defender's operational
  log, the Backup log) is read by ADR-0068's builtin on a schedule and the
  server's rules turn the events into alert state; the agent sends events,
  the server decides.
* **A module that is off evaluates nothing.** The evaluator skips a kind
  whose module is not enabled for the device's site or whose role is not
  detected, and resolves the open alert when a module is turned off, with
  the reason `module off`.
* **Default policies.** A module ships default policies as data: a list of
  `{kind, params, severity, name}` it asks the server to create at the
  *shared* level when the module's first device is detected, owned by the
  module and marked `default`. They respect everything a policy does:
  an administrator can disable one or override it at organization or site
  level, but the shared defaults cannot be edited or deleted by a normal
  user, only turned off (*decided in review*, so an upgrade can refresh the
  defaults and an organization can still opt out). A new version of a module's
  defaults adds policies and changes ones the user has not edited.
* **Organization scope.** The evaluator and every default-policy creation
  check `devscope.Allowed(orgID)`.

### 7. UI

Each module is one tab or card per ADR-0072's "How later modules slot in"
table; this ADR adds the contract:

* **Device**: a tab named for the module (or one "Roles" tab holding a
  view per role, for ADR-0076's five roles), shown only when offered
  (section 2). It shows the snapshot's time, a Refresh, and the module's
  forms.
* **Site and group**: a group has no tab of its own (ADR-0072 gives group
  pages no module tab); the group's device list gets a column or filter
  where it makes sense (Defender protection state, backup state), from
  Facts. A site gets a card on its Overview with counts and health, from
  Facts and snapshots only: **a site or organization page never sends a job
  to a device to draw a card**.
* **Organization**: the same cards, plus the "Windows modules" toggles
  card (section 2) and the module's policies in the organization's alert
  policies.
* **Settings**: only server-wide parts, as ADR-0072 says (Defender's hash
  list).
* **One component.** A shared `ModuleTab` frame draws the header (name,
  as-of time, refresh, why-unavailable), so a module only supplies its
  panels. A module that is not offered is absent from the tab strip, and its
  URL shows "this module is off for this site" with a link to the toggle for
  someone who may change it.

### 8. Tests

* **Unit tests (Go, no Windows).** Per action: the argument validator
  (accepts and rejects, with fuzzing on names and paths), the stdin
  document builder (JSON round trip, a value containing quotes, `$()`,
  backticks, newlines and `;` arrives unchanged and unevaluated), the
  result decoder (good, truncated, wrong version, unknown fields), the
  catalogue lint (every action has a permission, a version, a timeout, and
  every `Destructive` action requires confirmation; a test fails if a
  script contains `Invoke-Expression`, `iex`, `-Command` built from a
  parameter, or string-interpolates `$p.`), and the role-detection
  mapping from a table of registry and service states.
* **Integration (server, real PostgreSQL).** The toggle resolution (site
  over organization over default), the 404 for a module not offered, the
  permission matrix for the five roles, a job round trip with a fake agent
  speaking the real protocol (the contract-test fake), the audit row with
  secrets absent (grep the stored row), snapshot cache and stale logic,
  sensitive results hidden from a caller without the permission, alert kinds
  skipped while a module is off, default policies created and refreshed.
  No mocks of our own code.
* **Windows runner CI.** Each module's scripts run on a `windows-latest`
  runner for what that runner has: Defender (present), Windows Backup
  cmdlets that load, the registry and service detection, the stdin
  parameter pattern with hostile values, the typed result of every action
  that can run without the role (the script reports `module_missing` when
  the role is not there, and that is also tested). Roles the runner does not
  have (AD DS, CA, DNS, DHCP) are covered by the real-server steps below,
  and the CI says which were skipped.
* **Real-server steps, on a Proxmox VM (owner's test host).** A Windows
  Server VM promoted to a domain controller, with DNS and DHCP roles added,
  on an **isolated virtual network that has no route to a real subnet**:
  DHCP on it must never serve a real network, so the VM's bridge has no
  uplink and the DHCP scope is a private range created for the test. Steps:
  enrol the agent; confirm `roles` lists `ad_ds`, `dns`, `dhcp`, and not
  `ad_cs`; toggle each module off and confirm no job is sent (server log
  and the agent's job journal); on again; create, disable, reset the
  password of and delete a test user (with the confirmation and step-up);
  create a DHCP scope, lease from a second test VM, remove it; add and
  remove a DNS record; run a Defender scan and read the engine state; set
  up a Windows Backup of a test volume and read the last result; confirm the
  audit rows hold no passwords. Roll the VM back to its snapshot after.
  These steps are run by the owner or the orchestrator; until they are,
  the ADRs say "not verified on a real server".

### Organization scope

The detection and toggles act on a device only when asked. Everything the
framework starts by itself (scheduled snapshot reads, alert evaluation,
default-policy creation, rescans) checks `devscope.Allowed(orgID)` once
the guard has landed; this ADR predates its use in these paths, so each
slice's PR adds the check with a test that a disallowed organization gets no
job.

## Slices

1. **Roles in Facts.** The `roles` field, the agent's detection (Go, tests
   on a table), the server's storage and a read API, the 6-hour rescan.
2. **Toggles and permissions.** The table, resolution, the "Windows
   modules" card, the permissions in `rbac.go` and the role unions, the 404
   rule.
3. **Actions.** The `winmod` kind, the catalogue type, the stdin parameter
   pattern, the typed result, confirmation and step-up, audit, F2 retention
   and sensitivity; one real action (`defender.status`) as proof. Depends on
   the F2 work being in (ADR-0054 W2 / feature 7) or builds the part it
   needs and says so.
4. **Snapshots.** The table, freshness, refresh, retention.
5. **Alerts.** The kind registry for modules, default policies, skipping
   while off.
6. **UI frame.** `ModuleTab`, the tab-strip rule, site and organization
   cards, "this module is off" page.
7. **CI.** The lint, the Windows runner job, the hostile-value fixtures.

Slices 1 and 2 are independent; 3 needs 2; 4 and 5 need 3; 6 needs 1 and 2
and can start on mock-free fixtures once 1 lands; 7 grows with each.

### How ADR-0074 to 0077 plug in

Each ADR supplies, and only supplies: its role names for detection (slice 1
already knows them; Defender and Backup are always offered on Windows), its
permissions (section 3), its action catalogue (names, schemas, scripts,
which are sensitive or destructive), its alert kinds and default policies,
and its tab's panels. None adds a job kind, an endpoint style, a toggle
mechanism or a cache. Order: Defender first (it needs the alert and
default-policy parts, so it proves slices 3 to 5 on a role every Windows
computer has); then Windows Backup (same, with scheduled reads); then Active
Directory (the sensitive and destructive paths, secrets in stdin); then the
server roles (many catalogues, no new framework). A module is merged only
when its catalogue passes the lint and its own Windows-runner tests.

## Consequences

* Every module shares one safe path, so a mistake in quoting or audit is
  fixed once.
* The server grows a large catalogue of scripts that must be maintained as
  Windows changes; the version and the Windows-runner CI are the defence.
* Detection by registry and services can disagree with `Get-WindowsFeature`
  on odd configurations; the role's tab shows the state it found, and a
  *Rescan* exists.
* A Read-Only user sees no module detail, a deliberate cost.
* Four slots on the agent remain the limit; module reads can queue.

## Owner decisions

None are required to start. Two are worth the owner's eye, with defaults
chosen in review:

1. Server-role modules are **on by default where the role is found**.
2. Read-Only gets no module permissions, and Technicians do not get
   Active Directory management.

## Amendments

None yet.

## References

* `agent/jobs/worker.go`, `server/internal/jobs/hardening.go` and `key.go`.
* `docs/architecture/feature-plan-msp.md`, F2.
* `server/internal/rbac/rbac.go`, `server/internal/monitoring/policies.go`,
  `internal/agentproto/agentproto.go`, `server/internal/devscope/devscope.go`.
