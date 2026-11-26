# ADR-0083: Group Policy management and editing

* Status: Proposed (2026-11-26). Design only; no code is changed by this ADR.
* Asked for by the owner (2026-11-26): "What are the chances of full Group
  Policy Editor as well? And I mean full, anything they can do in the
  windows UI they can do in the WebUI?" On writing the policy files
  directly: "idk how I feel about direct sysvol write, is there
  alternatives? is there not an API or something like that." Those words
  are the only owner decisions here. Everything marked *decided in review*
  is the writer's call and the owner can overturn it.
* Builds on: [ADR-0073](0073-windows-management-modules.md) (the framework:
  `winmod` actions, `params` on standard input, pinned scripts, roles,
  toggles, permissions, step-up, audit, `modules.Allowed`);
  [ADR-0075](0075-active-directory.md) (the AD module: one controller per
  domain chosen by a fixed rule, receiving every write; the SYSTEM-identity
  question and its per-request credential fallback; the protected-target
  guard; paged reads), which excluded Group Policy on purpose and which this
  ADR follows for everything about the controller;
  [ADR-0064](0064-remote-powershell-management.md) (jobs, the script runner,
  output limits); [ADR-0072](0072-what-each-page-shows.md) (where the view
  and the card go); [ADR-0055](0055-lets-encrypt-in-one-step.md) (step-up);
  [ADR-0070](0070-defender-exclusions-at-install.md) (the agent's protected
  work folders).
* Amends: ADR-0073 (one new role, `gpmc`, and the `gpo.*` permissions) and
  ADR-0075 (its "Group Policy excluded" line: Group Policy is now a module of
  its own, and the AD module is unchanged).

## Context

The owner wants the console to do what the Group Policy Management Console
(GPMC) and the Group Policy Management Editor do, "full", for the domains the
MSP looks after, and a local policy editor for computers outside a domain.

ADR-0075 left Group Policy out because a GPO is two stores that must stay in
step: an object in Active Directory (`CN=Policies,CN=System`) and a folder
under `SYSVOL` (`\\<domain>\SYSVOL\<domain>\Policies\{GUID}`), with version
numbers in both and a list of client-side extension GUIDs on the AD object
that tells clients which files to process. A tool that writes the folder
itself must also bump both version numbers and keep the extension lists
right, or clients silently skip the change. The owner does not want
EasyRMM writing SYSVOL itself, and neither does this ADR.

What ADR-0073 and 0075 already fix, and this ADR does not reopen: the agent
runs jobs as SYSTEM; a module is fixed PowerShell embedded in the server,
pinned by hash, run as a `winmod` job with parameters as JSON on standard
input; one controller per domain does the work; destructive actions need
step-up and a typed confirmation; every action is audited.

## Decision

### In short

1. EasyRMM **never writes SYSVOL, and never writes a GPO's Active Directory
   attributes**. It calls only Microsoft's own APIs, on a domain controller
   (or a member server with GPMC installed). Section 1 lists them.
2. There are **three write paths**, in order of preference: management
   cmdlets (section 2), the registry-policy API (section 3), and a GPO backup
   edited in a staging copy then imported with `Import-GPO` (section 4). A
   fourth, the NetSecurity cmdlets' GPO session, serves the firewall
   (section 4, *Windows Firewall*).
3. **What no supported API can write is read-only** in EasyRMM, and the
   console says so (section 5).
4. **Safety is the product**: an automatic backup before every change with
   one-click restore, a diff before saving, "computers and users affected",
   step-up, a reason, an audit row with the diff, two-person approval where
   it matters, `devscope.Allowed`, four permissions, and a guard on the two
   Default policies (section 7).
5. The **local policy editor** for computers outside a domain uses the same
   registry-policy API and `secedit` (section 6).
6. Seven slices, each verified on the test domain, in a test OU only
   (*Slices* and *Testing*).

### 1. The APIs, and what Microsoft documents

Sources, all Microsoft Learn: the
[GroupPolicy module](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/)
(part of RSAT or a controller's GPMC; Microsoft recommends Windows
PowerShell 5.1 for it, so the scripts run in `powershell.exe`, not the
`pwsh` of ADR-0064); [`Import-GPO`](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/import-gpo);
[`Set-GPRegistryValue`](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/set-gpregistryvalue);
[`IGroupPolicyObject`](https://learn.microsoft.com/en-us/windows/win32/api/gpedit/nn-gpedit-igrouppolicyobject);
[`IGroupPolicyObject::Save`](https://learn.microsoft.com/en-us/windows/win32/api/gpedit/nf-gpedit-igrouppolicyobject-save);
[Back up and restore Group Policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-backup-restore);
the [NetSecurity module](https://learn.microsoft.com/en-us/powershell/module/netsecurity/)
(`Open-NetGPO`, `Save-NetGPO`).

**The GroupPolicy module has these 25 cmdlets and no others**: `Backup-GPO`,
`Copy-GPO`, `Get-GPInheritance`, `Get-GPO`, `Get-GPOReport`,
`Get-GPPermission`, `Get-GPPrefRegistryValue`, `Get-GPRegistryValue`,
`Get-GPResultantSetOfPolicy`, `Get-GPStarterGPO`, `Import-GPO`,
`Invoke-GPUpdate`, `New-GPLink`, `New-GPO`, `New-GPStarterGPO`,
`Remove-GPLink`, `Remove-GPO`, `Remove-GPPrefRegistryValue`,
`Remove-GPRegistryValue`, `Rename-GPO`, `Restore-GPO`, `Set-GPInheritance`,
`Set-GPLink`, `Set-GPPermission`, `Set-GPPrefRegistryValue`,
`Set-GPRegistryValue`. The module has **no cmdlet for WMI filters**, for the
GPO's status flags, or for a GPO description. Those go through the GPMC COM
object model (`GPMgmt.GPM`, in `gpmgmt.dll`: `IGPMGPO` for `SetWMIFilter`,
`SetUserEnabled`, `SetComputerEnabled`, `Description`; `IGPMDomain` for
`CreateWMIFilter` and `SearchWMIFilters`; `IGPMRSOP` for modeling). The
writer did not re-read each COM page; the slice 1 first step lists each
member used on the test domain and records the result (section 9).

**Which controller.** The cmdlets take `-Server` and, when it is absent,
contact the domain's PDC emulator (documented on each cmdlet's page). Every
call passes `-Server` explicitly with the controller ADR-0075 chose, so all
writes for a domain reach one controller and the directory's multi-master
conflicts cannot arise between our own calls.

**Which identity.** Same open question as ADR-0075 section 3, with the same
answer: SYSTEM on a controller reaches the directory as the computer account,
which is not a Domain Admin and may not be allowed to create or change a GPO.
This is **go or no-go for every write, decided at the first real-controller
step of slice 1**. If SYSTEM cannot write, ADR-0075's designed fallback
applies unchanged: a per-request credential typed in the step-up dialog,
sealed as a `winmod_job_secrets` row, used for that one job through
`-Credential`, never stored or reused. In the directory's own audit the
subject is then the typed administrator; with SYSTEM it is the controller's
account. EasyRMM's audit row is the only record of who asked, and the console
says so.

### 2. Management: the GPMC API

Fixed actions, all through the cmdlets above, never through raw LDAP:

| Area | Actions | Through |
|---|---|---|
| GPOs | list, read, create (blank or from a Starter GPO), copy, rename, delete | `Get-GPO`, `New-GPO`, `Copy-GPO`, `Rename-GPO`, `Remove-GPO`, `Get-GPStarterGPO` |
| Links | add, remove, order, enabled, enforced, block inheritance, read inheritance of an OU, domain or site | `New-GPLink`, `Remove-GPLink`, `Set-GPLink`, `Set-GPInheritance`, `Get-GPInheritance` |
| Filtering and delegation | security filtering (apply group policy), delegation (read, edit, edit and delete, custom), WMI filters | `Get-GPPermission`, `Set-GPPermission`; GPMC COM for WMI filters |
| Status | user part and computer part enabled or disabled, description | GPMC COM (`IGPMGPO`) |
| Backup and restore | back up one or all, restore, import, copy between domains with a migration table | `Backup-GPO`, `Restore-GPO`, `Import-GPO`, `Copy-GPO` |
| Reports | every setting of a GPO, as XML, shown in the console; HTML for download | `Get-GPOReport` |
| Modeling and results | "what would apply" for a user and computer in an OU; "what applied" to a device | GPMC COM `IGPMRSOP` (planning mode); `Get-GPResultantSetOfPolicy` or `gpresult /x` run by the device's own agent |
| Refresh | ask devices to refresh policy now | `Invoke-GPUpdate` |

**Read-only "every setting" view (slice 1).** The XML from `Get-GPOReport` is
parsed on the server into a tree (Computer and User configuration, each
extension, each setting with its state, value and scope) and shown beside a
search box. This is also the diff's "before" for settings the editor cannot
edit yet, and it is how the read-only parts of section 5 are shown. The
report is the only source for reading, so what the console shows is what
Microsoft's own report engine says.

Link order, enforcement and the other link properties are changed one link at
a time, each its own audited action. Deleting a GPO, removing a link and
changing security filtering are destructive: typed confirmation as well as
step-up.

### 3. Registry-based settings: the editor's own API

All of Administrative Templates (computer and user) and registry
preferences go through the same layer the Group Policy Management Editor
uses.

* **Policy settings**: `Set-GPRegistryValue` (keys under `HKLM` for Computer
  Configuration, `HKCU` for User Configuration; types String, ExpandString,
  Binary, DWord, MultiString, QWord; list values are String or ExpandString
  only; `-Disable` writes the "delete this value on the client" marker;
  `-Additive` keeps existing list values), `Remove-GPRegistryValue` (returns a
  setting to Not Configured), `Get-GPRegistryValue` (read). **Preferences**:
  `Set-GPPrefRegistryValue`, `Remove-GPPrefRegistryValue`,
  `Get-GPPrefRegistryValue`. All of these are documented to be the supported
  way to change registry-based policy.
* **When a cmdlet cannot do it**: the COM interface `IGroupPolicyObject`
  (gpedit.h; `OpenDSGPO` to open the GPO, `GetRegistryKey` for the root of
  the Computer or User policy hive, `Save`). The editor's own `Save` takes
  `bMachine`, `bAdd`, the registry extension GUID and the snap-in GUID,
  writes the `.pol` file, and updates the GPO's version number. The interface
  is documented as not supporting multithreaded use and as needing
  `Gpedit.dll`; the script uses one thread and one open object at a time.
* **Versions and extension GUIDs.** With either route Microsoft's code, not
  ours, writes `Registry.pol`, raises the user or computer version number in
  AD and SYSVOL, and records the registry extension's GUID on the AD object.
  Our scripts never name a version or a GUID except `Save`'s documented
  registry-extension argument, and a test (section 9) proves that after each
  edit the AD version equals the SYSVOL version and clients pick the change up.
* **The ADMX engine.** The console renders each setting as the Group Policy
  Management Editor does, from the domain's **central store**
  (`\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions`: `.admx` and the
  language folders' `.adml`), falling back to the controller's own
  `%SystemRoot%\PolicyDefinitions` when no central store exists. EasyRMM
  reads these files and never writes them (adding a third party's template
  to the central store is a copy into SYSVOL that EasyRMM does not do;
  the console says "place the template in the central store", and the
  open question below asks whether to build a supported way). A Go engine,
  `server/internal/admx` (also compiled for Windows in CI), parses the
  categories, policies, `supportedOn`, `parentCategory`, `using` namespaces
  and the elements (`decimal`, `longDecimal`, `text`, `boolean`, `enum`,
  `list`, `multiText`) with their `enabledValue`, `disabledValue`,
  `enabledList` and `disabledList`, and the `.adml` strings and
  presentation. It turns a console choice (Enabled with these values,
  Disabled, Not Configured) into the exact list of `Set-` and `Remove-`
  calls. Third-party templates therefore appear by themselves, with no
  release of ours. The parsed catalogue is cached per domain, keyed by a hash
  of the files, and rebuilt when the hash changes.
* **`Registry.pol` is read, never written, by us.** A small reader of the
  `.pol` format (documented in Microsoft's open specification MS-GPREG) is
  used by the engine to compute the "current state" and the diff, from a
  backup copy (section 4) rather than from the live SYSVOL folder. The
  cmdlets are the only writers.
* **Search** across all settings (name, explanation, registry path), filter
  by "configured only", and a link from every setting to its explanation.
  Settings the ADMX cannot explain (a registry value set in a GPO that no
  template describes) are shown in an "extra registry settings" list with
  the raw key, name, type and value, editable through the same cmdlets.

### 4. Everything else: backup, edit the copy, import

For settings that are not registry-based, no cmdlet edits the content. The
supported route, the one Microsoft's Security Compliance Toolkit uses to
apply its baselines, is `Backup-GPO`, change the backup, `Import-GPO`.
GPMC itself, not EasyRMM, writes SYSVOL on import and updates the AD object,
the version numbers and the extension GUIDs.

**An edit is the following, in one `winmod` job on the chosen controller:**

1. Read the GPO with `Get-GPO` and record its `ComputerVersion` and
   `UserVersion` (each reports an AD version and a SYSVOL version).
2. `Backup-GPO -Guid <id> -Path <staging>`, where `<staging>` is a new,
   empty, per-job folder under the agent's protected work folder (ADR-0070),
   removed at the end whatever happens. This backup is also kept as the
   automatic backup of section 7.
3. Change the **copy** in the backup's `DomainSysvol\GPO\...` tree, by the
   typed editor for that area (below), never by free text.
4. Read the GPO again. **If either version differs from step 1, stop**
   (optimistic concurrency): someone changed the GPO meanwhile, and the
   console shows "changed by someone else, reload". Nothing has been written.
5. `Import-GPO -BackupId <id> -Path <staging> -TargetGuid <id>` into the
   same GPO.
6. Read the GPO again and compare with the "before" read: links,
   permissions, security filtering, WMI filter, status flags and
   description must be as before, and the report must show the intended
   change. A mismatch is reported, and the console offers the one-click
   restore of the automatic backup.

**What `Import-GPO` preserves and replaces** (from its page and the
GPMC documentation; the first check on the test domain confirms each line):

* **Replaced**: the GPO's settings, that is, everything in the backup's
  extension data: all Administrative Templates and preferences in the GPO,
  Security Settings, scripts, firewall, folder redirection, AppLocker, and so
  on. This is why step 2 backs up the whole GPO and the editor changes only
  its own area: the rest comes back as it was.
* **Not replaced**: the GPO's links and, per the GPMC documentation, its
  security filtering and delegation (the page says a migration table maps
  security principals; a plain import into the same domain needs none).
  Whether the WMI filter link and the status flags are kept is **not
  stated** on the pages read; step 6 checks and puts them back.
* **Not copied**: the DACL on Software Installation package objects (only
  with an explicit option on copy), and a script's file unless it lives in
  the GPO.
* **Version numbers**: `Import-GPO` returns the GPO with new version
  numbers (the page's examples show them rising). We rely on that and verify
  AD equals SYSVOL after.

**Typed editors in this path** (each its own slice, section *Slices*):

* **Security Settings**: `GptTmpl.inf` (account policies, local policies, user
  rights, restricted groups, services, registry and file system permissions)
  and `audit.csv` (advanced audit policy), parsed and written by a small
  INF and CSV engine of ours, round-trip tested (section 9).
* **Scripts**: startup, shutdown, logon, logoff (`scripts.ini`, `psscripts.ini`
  and the script files in the GPO's script folders), edited as an ordered
  list with parameters. A script body is stored in the copy and shown in the
  diff in full for review.
* **Windows Firewall with Advanced Security**: rules, profiles, connection
  security rules. *Decided in review:* the firewall is changed through
  Microsoft's documented NetSecurity GPO session, `Open-NetGPO`,
  `New-NetFirewallRule`/`Set-NetFirewallRule` with `-GPOSession`, then
  `Save-NetGPO` (the pages say a session loads the GPO once and saves it
  once, and name a GPO as `<domain>\<GPO name>`), because it is a documented
  editing API and needs no import. The backup-and-import route is the
  fallback if the session route fails the test-domain check. The same
  version check as step 4 applies, around the session.
* **Group Policy Preferences**: the preferences XML files (Drive Maps,
  Printers, Files, Folders, Ini Files, Environment, Shortcuts, Network Shares,
  Scheduled Tasks, Services, Local Users and Groups, Data Sources, Power,
  Regional, Start Menu, Internet, Folder Options, Devices), with **item-level
  targeting** (the filter tree), from Microsoft's open specification for the
  preferences extension (MS-GPPREF). Registry preference items with no
  targeting use `Set-GPPrefRegistryValue`; the rest use this path.
  **Credentials are never written**: the editor has no password field.
  Preferences once stored a `cpassword` that any domain user can decrypt
  (Microsoft security bulletin MS14-025); a GPO that holds one is flagged on
  the read-only view as a finding, and the editor refuses to save an item
  that carries one.
* **Folder redirection** (`fdeploy.ini`) and **AppLocker** (the policy XML),
  edited as typed forms with the product's own validation (AppLocker's
  rule collections; folder redirection's paths) and nothing free-form.

### 5. What no supported API can write: read-only in EasyRMM

The owner asked for "full". The honest answer is: **everything a supported
API can write, and nothing else**. The following have no supported write
API: the cmdlets above cover none of them, GPMC's COM model exposes them only
as opaque data, and the only way to change them is a hand edit of the AD
object or the files, which is what the owner ruled out. EasyRMM shows them
(from the report) and **does not edit them**:

* **Software Installation** (Computer and User). The package list lives as
  objects in the AD container of the GPO and as `.aas` advertise scripts in
  SYSVOL. No cmdlet or interface in the lists above creates or edits a
  package. The GPMC import carries the existing packages (and does not copy
  their DACL), so a GPO that has them is **safe to edit in other areas**:
  step 6 confirms the packages survive. Showing them is the report's job.
* **Wired Network (IEEE 802.3) and Wireless Network (IEEE 802.11) policies**,
  including 802.1X. Microsoft documents them as extensions edited in the
  Group Policy Management Editor; no cmdlet writes them. Shown read-only.
  (Where wireless profiles must be set, the console says "deploy with a
  device job", which is a different feature.)
* **IP Security policies** (the older IPsec policy, under Windows Settings,
  Security Settings). The GPO stores only a pointer to a policy object in
  AD's IP Security container, which is outside the GPO. Shown read-only, with
  the pointed-to policy's name; the newer connection security rules are in the
  firewall editor and are editable.

**Each is verified, not assumed.** Slice 6 first checks on the test domain, for
each item here and for the rest of the long tail (Public Key policies,
Network List Manager, QoS, Name Resolution Policy, Remote Installation,
Offline Files and other items the report lists), whether an import round-trip
keeps it and whether any supported API writes it. An item moves out of
read-only only if a **documented** API writes it. The console marks every
read-only area with the words "Read-only here: no supported API changes this.
Use the Group Policy Management Console." The writer found no Microsoft page
that lists every area a GPMC backup does not carry; the one known gap
reported in public sources (IP security policies and WMI filters live outside
the GPO) is handled as above and confirmed on the test domain.

### 6. The local policy editor (computers outside a domain)

A device-side `winmod` action set that runs on any Windows device the
organization has enabled, not only controllers, and is **offered by default
only on a device that is not joined to a domain** (a domain's GPO would
override it; the page on a joined device is a read-only view with the
precedence explained).

* **Registry-based settings** (Administrative Templates, user and computer
  parts): `IGroupPolicyObject.OpenLocalMachineGPO` ("opens the default GPO
  for the computer"), `GetRegistryKey`, `Save`, which refreshes policy when
  the part is enabled or disabled. The same ADMX engine renders them, from
  the device's own `%SystemRoot%\PolicyDefinitions` (the central store does
  not exist off-domain). The device's ADMX files are read by the agent and
  sent as a catalogue.
* **Security Settings**: Microsoft's `secedit`: `secedit /export /cfg` for the
  current state, and `secedit /configure /db <db> /cfg <inf> /areas <areas>`
  with an INF built by our INF engine. This changes the local security
  database, not a policy file, so the change shows in the local policy tools
  but not as a GPO; the console says so. Each configure is preceded by an
  export kept as the backup.
* **Not offered**: the local GPOs for Administrators, for non-Administrators
  and for one user (`OpenLocalMachineGPO` opens the computer-wide one only);
  the console says so.
* The same safety as section 7, less the approval step (a single computer is
  the blast radius): backup before, diff, step-up, reason, audit.

### 7. Safety

* **Automatic backup before every change, with one-click restore.** Before
  any write (and before a restore), `Backup-GPO` of the GPO is taken and the
  backup folder is compressed and **kept on the server** (the controller may
  be the thing that failed), in a `gpo_backups` table with the GPO's id and
  name at the time, the versions, the job and the actor. Size cap per backup
  20 MB (refused above, the change is not made). Retention follows
  ADR-0073's retention rules per kind: **default the newest 20 per GPO and
  anything younger than 90 days, whichever is more**, a number to confirm;
  the console never deletes the last backup of a GPO that still exists.
  **Restore** is `Restore-GPO` into the same GPO (or `Import-GPO` into a
  chosen one), is itself a change (backup first, step-up, reason, audit), and
  appears beside every change in the history.
* **A diff before saving.** The console shows the settings before and after as
  a readable diff (setting names and values from the ADMX engine; for
  non-registry areas, the parsed items, never raw files) and the full text of
  any script. Saving is a second click on the diff.
* **"Computers and users affected."** For a change, the console computes,
  read-only, the OUs the GPO is linked to (`Get-GPInheritance` and the
  GPO's link list), the computers and users in those OUs and below
  (through ADR-0075's bounded, paged reads), after security filtering, and
  shows a count and a sample, with the OUs. Modeling (`IGPMRSOP` planning
  mode) is run for a chosen sample user and computer to show whether the GPO
  would apply. The count is **an estimate**: WMI filters and item-level
  targeting are evaluated only on the client, and loopback processing
  changes user scope; the console says "up to" and lists what it could not
  evaluate.
* **Step-up, a reason, and an audit record.** Every `gpo.edit`, `gpo.link`
  and `gpo.manage` action needs step-up (ADR-0055: a second factor within 5
  minutes) and a typed reason (required, 10 to 500 characters). The audit
  row `winmod.group_policy.<action>` carries the actor, the domain, the GPO's
  id and name, the reason, the versions before and after, the backup's id and
  the **diff** (capped at 64 KiB, with a hash of the full diff and a marker
  when cut; script bodies are included in full up to the cap, and nothing
  the editor treats as a credential is ever in it).
* **Two-person approval.** Optional per organization, **required by default
  for** a GPO **linked at the domain root, linked to the Domain Controllers
  OU, or linked to a site**, and for the two Default policies. The first
  person prepares the change and its diff and submits it (a
  `gpo_change_requests` row: the staged change, the versions it was read at,
  the diff, the reason, the requester). A second person, who must hold
  `gpo.edit`, must be a different user and must pass step-up, reads the diff
  and approves or rejects, with a reason. A request expires after 24 hours
  (default). On approval the job runs the version check of section 4 and
  **refuses if the GPO changed since the request was read**. Turning the
  requirement off for an organization is audited and needs an Organization
  Administrator; a link to the domain root or the Domain Controllers OU
  stays two-person unless that setting is off. An organization with one
  administrator cannot approve its own change; the console says who can.
* **The Default policies.** The Default Domain Policy
  (`{31B2F340-016D-11D2-945F-00C04FB984F9}`) and Default Domain Controllers
  Policy (`{6AC1786C-016F-11D2-945F-00C04FB984F9}`), whose identifiers are
  fixed by Microsoft, need an **extra confirmation** (the policy's name typed
  in full, plus a warning about what each carries: password and lockout
  policy; controller rights and audit policy) and always the two-person
  rule. The scripts refuse to delete, unlink or disable them under any
  confirmation; renaming is refused too. Tests never touch them (section 9).
* **`devscope.Allowed(orgID)`** is checked by `modules.Allowed` (ADR-0073)
  before every automatic behaviour: the hourly read, the ADMX catalogue
  rebuild, the pending-request expiry, and the alert evaluation. A manual
  action by a permitted person on an organization that is not allowed still
  passes through the guard the same way every other module's does.
* **Not lock-out proof.** The guard that ADR-0075 runs by SID cannot see
  what a GPO does. The editor therefore also warns on the settings known to
  lock people out: the **deny log on** rights, **account lockout** and
  **password** policy, **Restricted Groups** that replace membership, the
  firewall's profile defaults to block with no allow rule for the agent's
  connection, and a security filtering change that removes Authenticated
  Users without leaving Read for the computers (the cause of the well-known
  "GPO stopped applying" since MS16-072). These are warnings, not refusals,
  except the last, which is refused when it would leave no principal that can
  read the GPO.

### 8. Permissions and where it lives

* **`gpo.view`**: read GPOs, the report, links, backups' metadata and
  history. **`gpo.edit`**: change the content of a GPO (settings, scripts,
  firewall, preferences) and request or approve a change. **`gpo.link`**:
  add, remove, reorder or change a link, and block inheritance (a link at
  the domain root affects every computer, so it is separate from editing).
  **`gpo.manage`**: create, copy, rename, delete, change delegation, security
  filtering, WMI filters and status, back up and restore.
* *Decided in review*: **Read-Only** none; **Technician** `gpo.view` only;
  **Site Administrator** `gpo.view`; **Organization Administrator** all four;
  **Super Administrator** all. A Group Policy change reaches the whole
  domain, as ADR-0073 says of AD, so every write needs Organization
  Administrator, and `gpo.edit` of the second person for approval means a
  second Organization Administrator. The permissions are added to
  `AllPermissions` and the unions in `rbac.go` by the same small additive
  edit as ADR-0073's.
* **A role**: ADR-0073's detection reports `ad_ds` for a controller. This
  ADR adds `gpmc` to `roles`: the GroupPolicy module is present and the
  device can reach a controller. The module is offered on a controller, or
  on a member server with `gpmc` that the organization has chosen as the
  management host (same toggle, same site override). A domain with no
  qualified host has no module. The controller for writes is chosen by
  ADR-0075 section 3's rule; a member server with GPMC runs the cmdlets with
  `-Server` set to that controller.
* **The page** (ADR-0072): a "Group Policy" view in the domain controller's
  "Roles" tab, with a card on the organization Overview (GPO count, unlinked
  GPOs, GPOs with no settings, pending approvals) and the pending approvals
  shown where the organization's other alerts are. It adds no top-level
  section and no tab. The editor opens as a full page from the view, with
  the tree of settings on the left (Computer, User; categories as in the
  Group Policy Management Editor) and the search and diff on the right.
* **Alerts**: no new alert kind in this ADR. *Decided in review*: GPO changes
  made outside EasyRMM are not detected by it (the directory's own audit is the
  source), and the card says so.

### 9. Testing, and the owner's permission

The owner allowed GPO writes on the test domain, **only in a test OU** that
EasyRMM's tests create and link to.

* **The test OU.** Every real-domain test creates its own OU under a fixed,
  disposable parent, creates its GPOs from scratch, links them to that OU
  **and nowhere else**, and removes the links, the GPOs and the OU at the
  end, including on failure. The scripts the tests call refuse any link whose
  target is outside the test OU (a guard in the test harness, separate from
  the product's). **The Default policies are never edited in a test**, nor
  linked, nor unlinked, nor modeled against, and no test touches the domain
  root, the Domain Controllers OU or any site.
* **Without a domain, in CI, on Windows runners**: the ADMX engine against the
  real Windows ADMX set (every policy parses; every element type renders and
  produces the right calls), and the **`Registry.pol` round-trip**: a
  `.pol` written by Microsoft's own cmdlets (a local GPO, via the
  `IGroupPolicyObject` route) read back by our reader, and a table of edits
  compared by value. Also the INF, CSV and preferences XML round-trips (our
  engine parses and writes a file that GPMC then accepts, using a local
  backup import where possible), the script AST check for the new catalogue,
  hostile-value fixtures, and the diff and approval logic against the real
  PostgreSQL.
* **On the test domain**, per slice: each action run once, its effect read
  back through the report, the AD and SYSVOL versions compared, a client
  (an enrolled device in the test OU) refreshed with `Invoke-GPUpdate` and
  `gpresult` checked, the automatic backup restored and the result compared,
  and a deliberate concurrent change from another session to prove the
  version check refuses. The first run answers the open facts above: SYSTEM
  versus a credential, what import keeps (WMI filter, status), whether a
  hand-edited backup imports, whether `Open-NetGPO` works as SYSTEM, and the
  exact members of the COM model.
* No test claims a result it did not run; a check not run is listed in the
  slice's report.

## Slices

1. **Management and the read-only "every setting" view.** The role, toggle and
   permissions; the first real-controller run (identity, COM members);
   list, create, copy, rename, delete; links and inheritance; security
   filtering, delegation, WMI filters, status; backup, restore and the
   automatic backup table and retention; reports parsed into the tree;
   step-up, reason, audit; the Default-policy guard; two-person approval; the
   page and the card.
2. **Administrative Templates editing.** The ADMX engine and its catalogue,
   the `Registry.pol` reader, the editor with search, the diff, "computers
   and users affected" and modeling, registry preferences; the CI round-trip.
3. **Security Settings and scripts.** `GptTmpl.inf`, `audit.csv`, scripts;
   the backup-edit-import path with the version check; the first proof that
   a hand-edited backup imports.
4. **Firewall.** Rules and profiles through the GPO session, import fallback.
5. **Preferences.** The preferences XML and item-level targeting; folder
   redirection and AppLocker may move here if slice 3 leaves them.
6. **The long tail.** The check of section 5 for every other area the report
   lists; each is made editable only when a documented API writes it, else
   it is recorded read-only.
7. **The local policy editor.** Section 6.

Slice 1 depends on ADR-0073's framework slices and ADR-0075's controller
choice. Slice 2 needs 1. Slices 3 to 6 need 1 and the diff of 2. Slice 7
needs the ADMX engine of 2 and nothing else.

## Consequences

* The console can do, through Microsoft's own APIs, most of what the Group
  Policy Management Console does, and shows the rest read-only. "Full" is
  stated as what a supported API can write, with the gaps named.
* A GPO change is a heavy action: backup, diff, approval for the sensitive
  ones, a version check. It is slower than the GPMC and the owner should
  expect that; each step is a protection.
* The server stores GPO backups; they can hold scripts and settings an
  organization treats as private. They are kept with the same access as
  `gpo.view` plus `gpo.manage` to download, and fall under the retention above.
* The ADMX engine, the INF and preferences engines and the `.pol` reader are
  new code with no Microsoft dependency at run time, and need the CI
  round-trips to stay honest as Microsoft's templates change.
* The version check is a check, not a lock: another administrator saving in
  the GPMC in the seconds between the second read and the import can still
  be overwritten for the non-registry areas. Registry-based edits do not have
  this window (each is a single Microsoft API call). The step-6 comparison and
  the automatic backup are the net.

## Risks

* **SYSTEM cannot write.** The fallback is the per-request credential; if an
  organization will not type one, the module is read-only for it.
* **A hand-edited backup is rejected or mis-imported.** Not verified. Slice 3
  proves it first; if it fails, the non-registry areas become read-only and
  slices 3 to 5 shrink to what other APIs allow (the firewall session stands
  alone).
* **Import changes what it should not** (the WMI filter, status flags, a
  Software Installation package). Step 6 checks and restores; a failure
  there blocks the slice.
* **Microsoft changes the format** of a file we edit. The CI round-trip on
  the newest Windows Server runner is the alarm; the editor for that area is
  turned off by a server flag until fixed.
* **A bad GPO change locks out a domain.** The warnings and approval reduce it;
  they cannot remove it. The one-click restore is the recovery, and it needs a
  working path to the controller, which a firewall change can cut. The
  firewall editor therefore refuses a profile change that would block the
  agent's own connection, and the tests include a deliberate failure.
* **Scale**: a domain with thousands of GPOs or a very large Registry.pol.
  Reads page; a GPO whose backup exceeds the cap is read-only.
* **The COM model** (`gpmgmt.dll`) is documented as legacy. It is the only
  route for WMI filters and status; if a later Windows drops it, those actions
  become read-only.

## Open questions, with defaults

1. **Retention** of automatic backups: default the newest 20 per GPO and 90
   days, whichever is more. (No separate retention ADR was found; ADR-0073's
   per-kind retention is the carrier.)
2. **Approval expiry**: default 24 hours.
3. **Approval for a single-administrator organization**: default none possible
   and the setting must be turned off, audited, by an Organization
   Administrator.
4. **Third-party ADMX upload**: default none (the console says to put the
   template in the central store). A supported way would be a Microsoft API
   that does not exist in the lists above; the question is whether to build
   a documented file copy anyway. The default keeps the owner's ruling.
5. **Who may download a backup**: default `gpo.manage`.
6. **Domain-joined local editing**: default read-only; a switch for a
   "break-glass" local edit is not built.
7. **Local GPOs for Administrators and users**: default not offered.
8. **Modeling** for a sample: default one user and one computer chosen by the
   operator; a bulk model is later.
9. **Whether a Group Policy alert** for changes made outside EasyRMM is wanted
   (from ADR-0060's event collection): default no.
