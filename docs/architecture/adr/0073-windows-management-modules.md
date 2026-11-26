# ADR-0073: The framework every Windows management module builds on

* Status: Accepted (2026-11-26, after independent review). Design only; no code is changed by this ADR.
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
* **How, without PowerShell.** Detection is Go code in the agent: direct
  registry and service-control reads, no process to hang. A role is
  reported `present` only when **its service is running or installed and a
  role-specific marker exists**; a service alone is not enough (the print
  spooler runs on every desktop). `ProductType` below is the string value
  at `HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType`:
  `WinNT` (client), `ServerNT` (server or member) or `LanmanNT` (domain
  controller), as ADR-0060 and `agent/host/system_windows.go` use it.

  | Role | Service | Marker |
  |---|---|---|
  | `ad_ds` | `NTDS` running | `ProductType` = `LanmanNT`. A former domain controller (NTDS present, `ProductType` not `LanmanNT`) is **not** detected |
  | `ad_cs` | `CertSvc` running | the key `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA name>` exists (a configured CA, not just the installed role) |
  | `dns` | `DNS` running | `ProductType` is `ServerNT` or `LanmanNT` |
  | `dhcp` | `DHCPServer` running | the same server check; a server whose DHCP role is installed but unconfigured still reports it, with `state: "unconfigured"` when the `DHCPServer\Parameters` key is absent |
  | `file_server` | `LanmanServer` running | at least one non-administrative, non-IPC share from `NetShareEnum` (*decided in review*: a share is the configured role) |
  | `print_server` | `Spooler` running | server `ProductType` **and** at least one shared printer (`Print$` share present or a printer with the shared flag in `HKLM\SYSTEM\CurrentControlSet\Control\Print\Printers\<name>\Attributes`) (*decided in review*: the installed-feature test is not read, a shared printer is) |
  | `windows_backup` | server: `wbengine` | server: `ProductType` is a server type. Desktop (`WinNT`): reported always, with the state from File History and Backup and Restore settings. `wbengine` exists on desktops too, so the two are told apart by `ProductType`, not by the service |
  | `defender` | `WinDefend` | `MSFT_MpComputerStatus` through WMI in a child process, with deadline; passive mode or another product is the state |

  Server-only roles are never reported on `WinNT`.* **When.** At enrollment, at agent start, and then at most once every 6
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
* **A role that disappears** (uninstalled, a DC demoted) is dropped from
  `roles` on the next report. The server then clears that module's
  snapshots for the device and **resolves its open alerts** with the reason
  `role removed`, the same path as a module turned off (section 6).
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
* **Technician**: every `*.view` **except** `ad.view_sensitive`, `ca.view`,
  `dns.view` and `shares.view` (those four go to Site Administrator and
  above; *decided in review*), plus the reversible, low-blast-radius
  `defender.manage`, `backup.manage` and `print.manage`. No Active
  Directory management.
* **Site Administrator**: everything a Technician has, plus `dns.manage`,
  `dhcp.manage`, `shares.manage`, `ca.view`, `dns.view`, `shares.view`, `ad.view`, `ad.view_sensitive`.
  Site Administrators hold **no** `ad.manage`, `ad.reset_password` or
  `ca.manage`.
* **Organization Administrator**: Site Administrator plus `ca.manage`,
  `ad.manage` and `ad.reset_password`. **Every `ad.manage` write requires
  Organization Administrator** (*decided in review*).
* **Super Administrator**: all, as today.

**Plainly: Active Directory permission is power over the whole domain.**
RBAC scope is the domain controller's site or organization, but a
domain controller's directory is not scoped to that site: `ad.manage` on one
DC changes users and groups of the entire domain and forest-wide
replication carries it. That is why writes need Organization Administrator
and why the protected-target guard (section 4) exists. The same holds for
`ca.manage` (a CA issues for the whole forest) and, less, `dhcp.manage` and
`dns.manage`.

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
  * the validated parameters travel in a new **`params` field of the job**
    (the agent change below), which the agent writes to the script's
    standard input; the script's first line reads it with
    `$p = [Console]::In.ReadToEnd() | ConvertFrom-Json`. Each value is used
    only as a cmdlet argument *value* (`-Identity $p.name`), never joined
    into a string, a `-Filter`, `Invoke-Expression` or a command line.
  * **No LDAP or other filter is built from a user value.** Scripts use
    `-Identity` and typed parameters only (a user is found by SID or GUID
    the server already holds, or by `-Identity` with the sAMAccountName as a
    value). `-Filter`, `-LDAPFilter`, `-FilterXPath` from user values are
    banned, not escaped.
  * Scripts start with `Set-StrictMode -Version Latest`,
    `$ErrorActionPreference = 'Stop'`, run in the PowerShell ADR-0064 chose,
    and import the module they need by name from the system path (a missing
    module is the typed error `module_missing`).
* **The agent protocol change (new).** Today the agent runs
  `-File script args` (`agent/jobs/exec_windows.go:160`) with no stdin. This
  ADR adds, as a feature under ADR-0009's protocol levels:
  * a `params` field (a JSON object, at most 16 KiB) on the job the agent
    receives, and a `paramsSha256`; the job's Ed25519 signature now covers
    the **script hash and the params hash** (a canonical encoding of both,
    versioned so an older agent that does not know the field refuses the
    job instead of running it without its parameters);
  * the agent writes `params` to the child's standard input and closes it
    (a pipe, never a file, never the command line), caps it, and the
    output capture redacts nothing it does not know, so scripts must not
    echo it (the catalogue's redaction rules, below);
  * the agent advertises the level that supports it in its poll; the server
    sends a `winmod` job only to agents of that level, and the console shows
    "update the agent" otherwise.
* **Secrets** (a new password, a restore key). The server never puts them
  in `jobs.args`, `jobs.body`, audit, logs or output:
  * on accepting the request the server seals the secret with the server
    key (the `secrets` package, AAD `easyrmm:winmod:<jobID>:<name>`) into
    a short-lived row `winmod_job_secrets(job_id, name, sealed, expires_at)`,
    expiry 10 minutes or the job's own expiry if shorter;
  * the signed job payload built at **delivery** unseals it and places it in
    `params` for that one delivery; the signature covers the params with the
    secret inside, so the agent can verify them, and the job row keeps only
    the params *without* the secret and its hash for the audit;
  * the secret row is **deleted on delivery** or at expiry (a sweep), and a
    job never delivered fails with `expired`; a redelivery after a lost
    response is refused (the operator re-issues), so a password is never
    held waiting;
  * the transport is the agent's TLS channel; nothing logs `params`
    (a test greps server logs and the audit row for the test secret).
* **Embedded scripts are pinned.** Each action's catalogue entry carries the
  SHA-256 of its script, computed at build time and checked by a test; the
  job carries that hash and the **agent verifies the script body against
  the hash in the signed job** before running it (the signature already
  binds them; the check is a second, cheap guard against a mis-built
  payload). A script cannot change without the catalogue's hash changing in
  review.
* **Protected targets (Active Directory).** The catalogue marks AD actions
  `GuardsProtected`. A target is protected when it is a member (directly or
  by nesting) of Domain Admins, Enterprise Admins, Schema Admins or
  Administrators, has `adminCount=1`, or is `krbtgt` or the built-in
  Administrator (RID 500). The guard runs **twice**: on the computer inside
  the script, which resolves the target and refuses with `protected_target`
  before changing anything, and on the server, which refuses a request whose
  name is on a fixed denylist and which rejects a result of `protected_target`
  as a failure. **No action can add anyone to a protected group**, and the
  catalogue has none that does. Changing protected accounts from the console
  is **out of scope** (*decided in review*): an administrator uses the
  directory's own tools.
* **Results are typed JSON.** The last line is
  `EASYRMM-WINMOD-RESULT-V1 {json}`; the JSON is `{ok, version, data, error}`
  where `data` follows the action's schema. The server decodes it into a Go
  struct for the module, rejects an unknown shape (as a failed job, with the
  raw output kept only for users with `job.view_sensitive`), and stores
  the typed value, not the text. Limits are F2's: 64 KiB structured result,
  and an action that can be long (a user list) pages by an opaque cursor the
  script returns.
* **Redaction of raw output, per action.** The catalogue lists, for each
  action, which fields of the raw stdout and stderr are removed before
  storage, even for `job.view_sensitive` holders: **a password-reset
  result never contains the password** (the script returns only
  `{ok, mustChange}` and the server drops any line matching the secret's
  value before storing output; a test proves it), quarantine paths and
  privileged membership are redacted from raw output and kept only in the
  typed result, which is gated by the module's `view_sensitive`.
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
  disabling and every destructive action need a **step-up**: a sign-in
  re-check within the last 10 minutes. It is **not built**
  (`auth/service.go` only records the AMR and `AuthenticatedAt`), so it is
  its own slice below (or F5, if that lands first; whichever is first builds
  it and the other uses it). The confirmation is part of the action's catalogue
  entry, not of each handler, so no action forgets it.
* **The job kind in the server (new).** `jobs.go` allows only `script`,
  `software` and `hardening` (the insert at line 579 and the kind filter at
  735), and the `jobs` table has a column per kind (`software`,
  `hardening`). The migration `server/migrations/9xxxx_winmod.sql` (number
  from the integrator; goose up and down, down working):
  * adds `winmod jsonb` (module, action, version, validated params without
    secrets, params SHA-256, confirmation subject) and `hidden boolean NOT
    NULL DEFAULT false`, and widens the kind check to `winmod`;
  * creates `winmod_job_secrets` and `windows_module_settings` and
    `windows_module_snapshots` (sections 2 and 5);
  * indexes `jobs (kind, created_at)` for the retention sweep.
  `KindWinmod` is added to the allowed kinds in the create and list paths;
  the run list and the Jobs list **exclude `kind = 'winmod'` by default**
  (the list query at `jobs.go:601` gets `AND NOT j.hidden` unless a caller
  with `job.view_sensitive` passes `kind=winmod`, which shows only the
  compact row, never params); the module's own tab shows its runs.
  **Retention** per action: reads 1 hour, changes 7 days, sensitive
  results minutes, then job body, params and output are deleted and only
  the audit row and the compact run row remain; results are excluded from
  backups of job output. The agent's run list filters the same way. This
  uses F2's per-kind retention and visibility; **if ADR-0054 W2 (retention
  per kind, batches) has not landed, this slice builds the part it needs
  and says so**, and W2 extends it.
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
  `{kind, params, severity, name}` it asks the server to create **per organization, idempotently, when the
  module is first enabled there** (keyed by module and policy name, so
  re-enabling or an upgrade never duplicates), owned by the module and
  marked `default`. They are organization-level rows, so an organization
  that never enables a module has none. They respect everything a policy does:
  an administrator can disable one or override it at organization or site
  level, but a default cannot be edited or deleted by a normal
  user, only turned off (*decided in review*, so an upgrade can refresh the
  defaults and an organization can still opt out). A new version of a module's
  defaults adds policies and changes ones the user has not edited.
* **Organization scope.** The evaluator and every default-policy creation
  check `devscope.Allowed(orgID)`.

### 7. UI

Each module is one tab or card per ADR-0072, at every level. This ADR adds
the contract and fixes the placement:

| Module | Device | Group | Site | Organization |
|---|---|---|---|---|
| Defender (0074) | "Security" tab | column and filter: protection state, from Facts | Security card on Overview, counts from Facts | Security tab (organization switch) and its alert policies |
| Active Directory (0075) | "Roles" tab, a Directory view, on a domain controller | none | none | Directory health card on Overview (from snapshots, no job), toggle |
| CA, DNS, DHCP, shares, print (0076) | one "Roles" tab, a view per role found | none | none | one count card per role on Overview |
| Windows Backup (0077) | "Backup" tab | column and filter: last result, from Facts | Backup card on Overview | Backup status card; alert policy kinds in Alert policies |

* **Rule for cards.** A site or organization page never sends a job to a
  device to draw a card; cards come from Facts and stored snapshots.
* **Toggles** live in a "Windows modules" card on the organization and site
  pages (section 2), not in Settings. Settings holds server-wide parts
  only (Defender's hash list).
* **One component.** A shared `ModuleTab` frame draws the header (name,
  as-of time, refresh, why-unavailable); a module supplies its panels. A
  module that is not offered is absent from the tab strip, and its URL shows
  "this module is off for this site" with a link to the toggle for someone
  who may change it.

### 8. Tests

* **Unit tests (Go, no Windows).** Per action: the argument validator
  (accepts and rejects, with fuzzing on names and paths), the stdin
  document builder (JSON round trip, a value containing quotes, `$()`,
  backticks, newlines and `;` arrives unchanged and unevaluated), the
  result decoder (good, truncated, wrong version, unknown fields), the
  catalogue lint (every action has a permission, a version, a timeout, and
  every `Destructive` action requires confirmation; a script's SHA-256
  matches the catalogue's), and the role-detection
  mapping from a table of registry and service states.
* **Integration (server, real PostgreSQL).** The toggle resolution (site
  over organization over default), the 404 for a module not offered, the
  permission matrix for the five roles, a job round trip with a fake agent
  speaking the real protocol (the contract-test fake), the audit row with
  secrets absent (grep the stored row), snapshot cache and stale logic,
  sensitive results hidden from a caller without the permission, alert kinds
  skipped while a module is off, default policies created and refreshed.
  No mocks of our own code.
* **PowerShell AST check (Windows runner CI).** Every embedded script is
  parsed with `[System.Management.Automation.Language.Parser]::ParseFile`;
  the check fails on `Invoke-Expression`/`iex`, `-Command`, `Add-Type`
  with strings from parameters, `-Filter`, `-LDAPFilter` or `-FilterXPath`
  whose argument is not a literal, and any expandable string (`"...$p..."`)
  or `+` concatenation that includes `$p`. A grep is not used: the AST sees
  through spacing and aliases.
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

`devscope.Allowed(orgID)` is a **framework gate (slice 1), not left to each
module**: one function in the framework, `modules.Allowed(ctx, org)`, wraps
the toggle check and `devscope.Allowed`, and is the only way the framework
dispatches a scheduled read, rescan, alert evaluation or default-policy
creation. A test in the framework's catalogue lint fails any code path that
dispatches without it, and an integration test shows a disallowed
organization gets no job. The guard has not landed everywhere yet, so until
it has, the function calls `devscope.Allowed` and the toggle only.

## Slices

1. **Roles in Facts and the gate.** The `roles` field, the agent's
   detection (Go, tests on a table of registry and service states),
   storage, read API, 6-hour rescan, role-removal clearing, and
   `modules.Allowed` (the `devscope` gate).
2. **Toggles and permissions.** The table, resolution, the "Windows
   modules" card, the permissions and role unions in `rbac.go`, the 404 rule.
3. **Agent protocol: `params`.** The `params` field, signature over the
   script and params hashes, stdin delivery, the protocol level; the agent
   refuses a job whose hash it cannot verify.
4. **Step-up.** Re-authentication within 10 minutes for destructive and
   credential actions (or F5, by name, if it lands first).
5. **The `winmod` kind.** The migration, catalogue type, pinned script
   hashes, validation, typed results, secret rows, confirmation, audit,
   retention, Jobs-list exclusion; one real action (`defender.status`) as
   proof. Depends on 2, 3 and 4 (and ADR-0054 W2 if not landed).
6. **Snapshots.** Table, freshness, refresh, retention.
7. **Alerts.** The kind registry, per-organization default policies,
   skipping while off, resolving on role removal.
8. **UI frame.** `ModuleTab`, the tab-strip rule, cards, "module off" page.
9. **CI.** The PowerShell AST check, the hostile-value fixtures, the Windows
   runner job.

Slices 1, 2, 3 and 4 are independent; 5 needs 2, 3 and 4; 6 and 7 need 5; 8 needs
1 and 2; 9 grows with each.

### How ADR-0074 to 0077 plug in

Each ADR supplies, and only supplies: its role names for detection (slice 1
already knows them; Defender and Backup are always offered on Windows), its
permissions (section 3), its action catalogue (names, schemas, scripts,
which are sensitive or destructive), its alert kinds and default policies,
and its tab's panels. None adds a job kind, an endpoint style, a toggle
mechanism or a cache. Order: Defender first (it needs the alert and
default-policy parts, so it proves slices 3 to 5 on a role every Windows
computer has); then Windows Backup (same, with scheduled reads); then Active
Directory (the sensitive and destructive paths, secrets in `params`); then the
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
2. Read-Only gets no module permissions; Technicians get no Active
   Directory management and no `ca.view`, `dns.view` or `shares.view`
   (decided in review). Active Directory writes need Organization
   Administrator (decided in review), and protected accounts are
   console-out-of-scope (decided in review).

## Amendments

Amended 2026-11-26 (decided in review, after independent review): the `params`
protocol change and secret mechanism, step-up as its own slice, detection
markers per role, the `winmod` migration and list exclusion, the AD
protected-target guard, AST-based injection checks, per-organization default
policies and the framework `devscope` gate.

## References

* `agent/jobs/worker.go`, `server/internal/jobs/hardening.go` and `key.go`.
* `docs/architecture/feature-plan-msp.md`, F2.
* `server/internal/rbac/rbac.go`, `server/internal/monitoring/policies.go`,
  `internal/agentproto/agentproto.go`, `server/internal/devscope/devscope.go`.
