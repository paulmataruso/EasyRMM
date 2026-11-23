# ADR-0070: Microsoft Defender exclusions at install

* Status: Proposed (2026-11-23). Design only; nothing is implemented.
* Asked for by the owner (2026-11-23), who suspects antivirus is blocking
  the agents on client machines. Everything marked *decided in review* is
  mine and the owner can overturn it.
* Related, unchanged: [ADR-0049](0049-operators-sign-windows-agents.md)
  (operators sign the EasyRMM agent with their own certificate),
  [ADR-0054](0054-hardening-windows-computers-and-servers.md) (reads
  Defender's state; changes none of its exclusions),
  [ADR-0069](0069-recovery-agent-logs-and-one-device-tree.md) (the agents
  repair each other; the folders below are the ones it relies on).
* Amends, each gaining an *Amended by ADR-0070* line when this lands:
  [ADR-0015](0015-enrollment-and-meshagent-delivery.md) (install),
  [ADR-0031](0031-easypatch-agent-install.md) (EasyPatch agent install),
  [ADR-0050](0050-removing-a-device.md) (uninstall).

## Context

Neither agent carries an Authenticode signature (`CODE_SIGNING.md:56-62`),
and both do things antivirus dislikes in combination: a Go program running
as LocalSystem that downloads and runs scripts, replaces its own
executable, installs a remote-access program (MeshAgent) and drives
`msiexec`. Microsoft Defender can quarantine or block any of these. Nothing
in the code today touches Defender: there is no exclusion handling in
`agent/` or in the installers, and the only mention of Defender is ADR-0054's
read-only hardening checks.

### What is on a Windows device, and who can write it

| Folder | What is in it | Who can write it today |
|---|---|---|
| `%ProgramFiles%\EasyRMM\Agent` | the agent's executable, with `.new`, `.old`, `.failed` beside it during an update (`agent/host/host.go:70`, `agent/update/update.go:346`, `agent/host/files.go:27`) | Not set by the agent: it creates the folder with `MkdirAll` (`agent/host/files.go:24`) and inherits Program Files, which only SYSTEM, Administrators and TrustedInstaller may change. **Inherited, not enforced.** |
| `%ProgramFiles%\EasyRMM\MeshAgent` | MeshAgent, `meshagent.msh`, `meshagent.db`, `meshagent.log` (`host.go:62`, `host.go:92`, `agent/meshagent/meshagent.go:90-92`) | SYSTEM and Administrators only: `host.Protect` (`meshagent.go:191`) sets a protected access list, `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` (`agent/host/system_windows.go:100`) |
| `%ProgramFiles%\EasyRMM\Package` | named in the brief, but **no code creates a folder called `Package`**; see the contradictions below | n/a |
| `%ProgramData%\EasyRMM\Agent` | enrollment, key, `logs\`, `recovery\` (ADR-0069), `jobs\` with each run's `work\run-*` folder, `easypatch\` (the downloaded EasyPatch MSI) (`host.go:54`, `host.go:80`, `agent/state/state.go:354`, `agent/jobs/worker.go:96`, `agent/jobs/exec.go:58-61`, `agent/easypatch/easypatch.go:237`) | SYSTEM and Administrators only: `host.Protect` (`agent/state/state.go:109`, `:338`), which also refuses a folder under ProgramData owned by anyone but SYSTEM, Administrators, TrustedInstaller or the agent's account, and moves it aside (`system_windows.go:103-112`) |
| `%ProgramFiles%\EasyPatch Agent` | the EasyPatch agent, installed by the WiX package (`easypatch/agent/Installer/Package.wxs:74-76`, `:105-106`) | Not set by the package: inherited from Program Files, as for the EasyRMM folder. **Inherited, not enforced.** |
| `%ProgramData%\EasyPatch` | keys, `state\`, `outbox\`, `logs\`, `updates\` (the agent-update MSI and its install log), `winget\` (`easypatch/agent/EasyPatch.Agent.Core/AgentRuntimeOptions.cs:52-55`, `AgentStateStore.cs:22`, `ReportOutbox.cs:67`, `Jobs/AgentUpdateHandler.cs:148`, `:242`, `AgentRuntime.cs:134`) | SYSTEM and Administrators only, owner Administrators, inheritance off: the installer sets `O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` (`Package.wxs:136-140`) and the agent sets the same on every service start and CLI run (`Platform/SecureStorage.cs:20-40`, `Program.cs:53`, `Cli.cs:90`). Everything below inherits it, because the list has `OI` and `CI`. |

The EasyPatch side already has a checker that decides whether a folder
and every folder above it are writable by administrators only
(`EasyPatch.Agent.Core/Companion/FileTrust.cs:15-40`: it lists the write
rights, treats SYSTEM, Administrators and TrustedInstaller as the
administration, and ignores CREATOR OWNER entries and the add-a-folder
right that ProgramData gives every user). The EasyRMM agent's Go side has
`host.Protect`, which sets and tests a list but has no read-only check of
an existing folder's list ("is this still true?").

### Where the agents write scripts, downloads and updates

| What | Where | Inside a protected tree? |
|---|---|---|
| Job scripts (`script.ps1`, `script.cmd`) | `%ProgramData%\EasyRMM\Agent\jobs\work\run-*\`, then deleted (`agent/jobs/exec.go:58-61`, `exec_windows.go:129-139`, `worker.go:96`) | Yes. Their `TEMP`/`TMP` is the run folder (`exec_windows.go:125`). |
| EasyRMM agent update | `easyrmm-agent.exe.new` beside the installed executable (`update/update.go:346`) | Yes (Program Files) |
| Recovery copy | `%ProgramData%\EasyRMM\Agent\recovery\` | Yes |
| MeshAgent download | `.meshagent-*` in MeshAgent's folder (`meshagent.go:197`) | Yes |
| EasyPatch MSI, installed by the EasyRMM agent | `%ProgramData%\EasyRMM\Agent\easypatch\` (`easypatch.go:237`, `repair.go:136`), run with `msiexec` (`agent/easypatch/system_windows.go:32-63`) | Yes |
| EasyPatch agent update | `%ProgramData%\EasyPatch\updates\` (`AgentUpdateHandler.cs:148`) | Yes |
| The Windows install script's download of the agent | `%TEMP%\easyrmm-<guid>` of whoever runs it (`server/internal/httpapi/agentapi/install.ps1.tmpl:61`, `:75`) | **No.** An administrator's temp folder, outside any folder this ADR protects. |
| The EasyPatch agent's winget calls | working directory `Path.GetTempPath()` (`Platform/WingetProcessRunner.cs:38`) | **No.** |

### How each agent is installed and removed today

* **EasyRMM agent.** There is no EasyRMM MSI (`ROADMAP.md:91` lists it as
  future). `install.ps1` downloads the agent, checks it against the
  server's checksums, and runs `easyrmm-agent install` (`install.ps1.tmpl:99`),
  which is `enroll` with the service on (`agent/cmd/easyrmm-agent/main.go:163-166`,
  `:188`). `putService` copies the executable to the program folder and
  registers the service (`main.go:282`). The agent's `run` loop installs
  MeshAgent (`meshagent.Manager`, `meshagent.go:180-215`) and the EasyPatch
  agent (`easypatch.Installer`, ADR-0031).
* **EasyPatch agent.** The WiX package under `easypatch/agent/Installer`
  (`Package.wxs`), installed by `msiexec /i` from the EasyRMM agent
  (`agent/easypatch/system_windows.go:32-48`) or by an administrator.
* **Uninstall.** `easyrmm-agent uninstall` (`main.go:648`) removes the
  recovery copy, the service, MeshAgent (`meshagent.Remove`,
  `meshagent.go:407-416`) and then the files (`removeFiles`, `main.go:699`).
  The server can start the same removal (`removeOnRequest`, `removal.go:54`,
  ADR-0050). The EasyPatch agent is removed by `msiexec /x`
  (`Platform/WindowsAgentUninstaller.cs`), during which the package runs
  `unenroll` as a deferred custom action (`Package.wxs:89-99`).

### Contradictions with the request's description

* There is no EasyRMM MSI; the Windows install is `install.ps1` plus the
  `install` subcommand.
* There is no `%ProgramFiles%\EasyRMM\Package` folder.
* `%ProgramFiles%\EasyRMM\Agent` and `%ProgramFiles%\EasyPatch Agent` are
  protected by inheritance from Program Files, not by anything the agents
  or the package set. The agent therefore has to *check* them
  (decision 1), not assume it.

## The requirement (the owner's)

The agents add Microsoft Defender exclusions on Windows when they install,
and remove them when they uninstall.

## Decision

### Who may do what

| Action | Permission |
|---|---|
| Turn the setting on or off for an organization | `org.manage` (new field on the organization, edited with the rest of the organization, as `autoRepair` is: `server/internal/tenancy/tenancy.go:147`) |
| See whether the exclusions are present and effective, and why not | `device.view`, on the device page and the device API |
| See each agent build's SHA-256 and MD5 | whoever may open Settings; read-only |
| The agent adds or removes an exclusion on its own device | it acts as LocalSystem on the device; nobody else is given a way to name a path |

No user and no job can name a path to exclude. The paths are fixed in the
agent's code (below).

### 1. Only folders administrators alone can write

The exclusion set is the following folders, and no others:

| Managed by | Folder |
|---|---|
| EasyRMM agent | `%ProgramFiles%\EasyRMM\Agent` |
| EasyRMM agent | `%ProgramFiles%\EasyRMM\MeshAgent` |
| EasyRMM agent | `%ProgramData%\EasyRMM\Agent` (includes `jobs\work`, `recovery\`, `easypatch\`) |
| EasyPatch agent | `%ProgramFiles%\EasyPatch Agent` |
| EasyPatch agent | `%ProgramData%\EasyPatch` (includes `updates\`) |

Before adding each one, the agent reads the folder's access list and
the lists of every folder above it, and **adds the exclusion only if all of
these hold; otherwise it refuses that folder and says why**:

* the folder is a plain folder, not a link or reparse point, and exists;
* its owner is SYSTEM, Administrators or TrustedInstaller;
* the only principals allowed any write right (create files or folders,
  write data or attributes, delete, delete child, change the access list,
  take ownership, or the generic rights containing them) are SYSTEM,
  Administrators and TrustedInstaller. CREATOR OWNER and CREATOR GROUP
  entries are ignored, and so is the add-a-folder right that ProgramData
  and a drive root give every user, since it cannot replace the agent's
  folder (the rule `FileTrust.cs:15-40` already states for ADR-0064);
* the same holds for every folder from the drive root down to it.

The EasyPatch agent reuses `FileTrust`. The EasyRMM agent gets the same
check in `agent/host` (a read-only counterpart of `Protect`), written to
the same rule and tested against the same table of lists, so the two cannot
drift. The check runs again before **each** add, and again on every
reconcile (below): if a folder has since become writable by someone else,
the agent removes its own exclusion for it and reports `refused: folder is
writable by <principal>`.

Never excluded, whatever the settings say: `%TEMP%` and `%TMP%`, any
user's profile or temp folder, the folder `install.ps1` downloads to, a
winget working directory, a drive root, `%ProgramData%` or
`%ProgramFiles%` themselves, and any folder outside the five above. If a
future build adds a staging folder it must be inside a folder on the list
or it gets no exclusion.

### 2. No process exclusions

The agents add no `ExclusionProcess` and no `ExclusionExtension`. A
process exclusion would make Defender skip everything that process opens,
which includes the scripts the agent runs and the updates it downloads.
Path exclusions cover only files stored in the five folders.

### 3. AMSI still scans scripts

Path exclusions do not switch off AMSI (Antimalware Scan Interface). Script
content that PowerShell, Windows Script Host or other AMSI-aware hosts hand
to the antimalware provider is scanned whatever the exclusions say, and
behaviour-based detections still apply. The exclusions only stop the
files in the five folders from being scanned and quarantined *on disk*.
(*To confirm on the CI runner, with a harmless AMSI test string run from a
script stored inside an excluded folder.*)

### 4. Each agent manages its own folders; a record keeps it honest

* The EasyRMM agent adds and removes the first three folders (MeshAgent is
  its own child: ADR-0015, ADR-0069).
* The EasyPatch agent adds and removes the last two.
* Each keeps a **record** of exactly the exclusions it added: the
  EasyRMM agent in `defender-exclusions.json` in its protected state folder
  (`host.State()`, covered by the state checks), the EasyPatch agent in
  `state\defender-exclusions.json` in its data folder. It holds the
  normalized path, the time and the agent version.
* Before adding a path the agent reads `ExclusionPath`. A path that is
  **already listed** is not ours: the agent does not record it, does not
  add it again and never removes it. Comparison is case-insensitive on the
  normalized absolute path.
* Uninstall and "turned off" remove **exactly the recorded paths**, one
  `Remove-MpPreference -ExclusionPath` each, then delete the record. A path
  an administrator added, even for the same folder (it was present first),
  and any other exclusion are never touched. A record that cannot be
  read means the agent removes nothing and logs it.
* There is no wildcard and no "remove everything under EasyRMM".

**When it runs.** On the EasyRMM agent: in `easyrmm-agent install`,
after `putService` and before the service starts (`main.go:264`); in
`repair-install` (`main.go:313`) and on each start of `run`, as a
reconcile that adds what is missing and removes what no longer qualifies;
and in `uninstall` (`main.go:648`) after the service and MeshAgent are
stopped and **before** the files are removed, so a failure leaves the
folders still there for a retry. The server-started removal
(`removeOnRequest`) takes the same path. On the EasyPatch agent: on each
service start, next to `SecureDataDirectory` (`Program.cs:53`), as a
reconcile; and on uninstall by a new deferred custom action in
`Package.wxs`, run before `UnenrollAgent`
(`Package.wxs:89-99`), under the same `REMOVE="ALL" AND NOT
UPGRADINGPRODUCTCODE` condition, so an upgrade keeps the exclusions.

**How.** Through the documented Defender cmdlets, run from the fixed
`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` with a
fixed script, `-NoProfile -NonInteractive`, and the path given as an
environment variable, never joined into the script text. The EasyPatch
agent's .NET code does the same. Any Defender call that fails is logged and
reported; it never fails the install, the uninstall or the heartbeat.

### 5. Defender may ignore or refuse them: report whether they work

A local exclusion is not always honoured. The agent reports, in its facts,
`defender` with:

* `state`: `effective`, `present_not_effective`, `refused`, `unavailable`
  or `off` (the organization setting is off);
* `reason`: one short sentence, set whenever `state` is not `effective`;
* per folder: the path, `listed` (true when the exact path is in
  `ExclusionPath`), `ours` (it is in the record) and the refusal if the
  folder check failed.

The agent decides from these documented fields (to be confirmed against
real hosts on the CI runner):

| Source | Field | What it tells |
|---|---|---|
| `Get-MpPreference` | `ExclusionPath` | whether each path is listed |
| `Get-MpPreference` | `DisableLocalAdminMerge` | `True` means local exclusions are ignored in favour of the policy's (Intune, GPO, Configuration Manager): reason `local exclusions are ignored (DisableLocalAdminMerge)` |
| `Get-MpComputerStatus` | `AMRunningMode` | `Passive`, `SxS Passive Mode` or `EDR Block Mode` instead of `Normal`: Defender is not the active antivirus; passive is the sign of a third-party AV |
| `Get-MpComputerStatus` | `AntivirusEnabled`, `AMServiceEnabled`, `RealTimeProtectionEnabled` | Defender is off or its real-time scanner is, so exclusions are moot |
| `Get-MpComputerStatus` | `IsTamperProtected` | Tamper Protection is on: an add made by the agent may be refused or reverted; reported next to the result of the add, not alone |
| the add itself | the cmdlet's error, and a read-back of `ExclusionPath` | `refused` with Defender's own message when the add fails or the path is not listed afterwards |

`effective` needs: Defender's `AMRunningMode` is `Normal`, antivirus and
real-time protection are enabled, `DisableLocalAdminMerge` is not true, and
every folder is listed. The Defender module is missing on a Windows
Server installed without Defender: `unavailable`, with the reason. Naming
which third-party AV is active is not required; the agent may add the
product name from the Windows Security Center's `AntiVirusProduct` if
present, and does not depend on it.

The device page shows this beside the agent versions: a status, the
reason, and the five folders with a tick or a cross. The hardening page
(ADR-0054) is unchanged.

### 6. The organization setting

`organizations.defender_exclusions` (boolean, default **true**),
edited with `org.manage`. The server includes the setting in the
heartbeat response (`HeartbeatResponse`, `internal/agentproto/agentproto.go:163`) for the EasyRMM agent,
and in whatever the EasyPatch engine already gives its agent (carried by
the connector, ADR-0030; the channel is to be confirmed when built). *Turning it off*
makes each agent's next heartbeat reconcile remove the recorded exclusions
and report `off`. Turning it on adds them on the next heartbeat. A new
device enrolled into an organization with it off installs without adding
any. Linux and macOS agents ignore the field.

### 7. Every change is audited

The server writes an audit event for each of: the setting being changed
(`organization.defender_exclusions.update`, actor, old and new value), and
each change the agent reports (`device.defender_exclusion.add`,
`.remove`, `.refuse`, with the device, the path, the agent, the reason
and the agent version). The agent sends them with the next heartbeat
(a new agent-reported event; the server writes it into the audit chain
with `audit.Event`, as `tenancy.go:340` does for organizations). The agent also
writes each add, removal and refusal to its own log (the EasyRMM agent's
`logs\agent.log`, the EasyPatch agent's rolling log and Windows event log),
with the path and the reason, even when the server cannot be reached.

### 8. Third-party antivirus, and a list for allow lists

Excluding from a third-party product is out of scope: its settings differ
and are rarely local. Instead the documentation (`docs/operations`, new
page "Antivirus and EasyRMM") gives:

* the five folders, per agent;
* where to find the current SHA-256 of each build: the server already
  serves `SHA256SUMS` (`server/internal/httpapi/agentapi/agentapi.go:756`);
  the page says where, and how to check a device's build against
  `devices.agent_sha256` (ADR-0069);
* how to allow-list by hash in Microsoft Defender for Endpoint (file
  indicators) and by path in other products.

**Proposed addition.** The console's **Settings** shows each published
agent build (EasyRMM agent per platform and architecture, and the
EasyPatch agent's packages): file name, version, size, **SHA-256** and
**MD5**, each with a copy button, read-only. MD5 is shown only because
some antivirus allow lists still ask for it; it is never used to trust
anything. The server computes both when it loads a build (the same place
that builds `Checksums()`), and holds them in memory with it.

### 9. This does not replace code signing

Signing is the real fix for false positives, because the reputation and
trust Defender and SmartScreen give follow a publisher's certificate, not
a folder. Public-certificate signing is on hold (`CODE_SIGNING.md:56-62`);
ADR-0049 lets an operator sign the EasyRMM agent with their own
certificate. Exclusions are a stopgap for the folders above, they do
nothing for the *download* in `%TEMP%` (which is scanned before it is
ever installed), and they must not be read as a reason to leave signing
undone. When signing lands, this ADR stays: the exclusions still avoid
scans of files the agents rewrite constantly, but the setting's default
can be revisited.

## Data

* Migration (next free number when built): `organizations.defender_exclusions
  boolean NOT NULL DEFAULT true`; `devices.defender jsonb` for the last
  reported state (state, reason, per-folder rows, observed at).
* `Facts.Defender` (new optional field on `agentproto.Facts`,
  `internal/agentproto/agentproto.go:58`) and `HeartbeatResponse.DefenderExclusions`
  (`*bool`, absent for old servers, treated as on by an agent that
  has never heard).
* Two audit actions for the device and one for the organization (above).
* Agent-side files: the two records. Nothing else is stored; PRIVACY.md
  gains one line: paths of the agents' own folders and Defender's state are
  collected from Windows devices.

## Agent changes

* EasyRMM agent (Go): `agent/defender` (new): the folder check, the record,
  add, remove, reconcile and state report; called from `enroll`/`install`,
  `repair-install`, `run`, `uninstall` and `removeOnRequest`. A read-only
  folder-trust check in `agent/host`.
* EasyPatch agent (.NET): a `DefenderExclusions` class using `FileTrust`; a
  `defender` command (`add`, `remove`, `status`) so the installer can call
  it; the custom action in `Package.wxs`.
* Windows only. The agents ignore the whole feature elsewhere.

## Server changes

* Organization field and API (`tenancy`), heartbeat response, the facts and
  the device page, the audit events, the connector's policy field to the
  EasyPatch engine, the build hashes in Settings, and the documentation
  page.
* The server never connects out to Defender and never names a path.

## Testing

* Unit: the folder check against a table of access lists (administrators
  only; Users with write; Users with add-a-folder only on ProgramData;
  CREATOR OWNER; a link; a missing folder; a writable parent), the same
  table in Go and .NET; the record (adds only what was absent, removes
  only what is recorded, a pre-existing path survives); the state
  decision table (each field above).
* **A real Windows runner in CI** (a Windows Server 2022 or 2025 job with
  Defender running, not mocked), where the agent really runs:
  1. add: after `install`, the five (or the EasyRMM three) paths are in
     `Get-MpPreference`'s `ExclusionPath`;
  2. check: `Get-MpComputerStatus` reports `Normal`; the agent's facts say
     `effective`; with `DisableLocalAdminMerge` set the facts say so;
  3. remove: after `uninstall`, exactly those paths are gone, and a
     path the job added by hand beforehand is still listed;
  4. refusal: make a protected folder writable by Users (`icacls`), run
     the reconcile, and assert the exclusion for it is removed and the
     state is `refused` with the reason; and that `%TEMP%` is never added;
  5. the organization switch: off removes them on the next heartbeat;
  6. AMSI still fires: a harmless test string run from a script stored in
     an excluded folder is still blocked.
* What CI cannot reach, and is stated as untested until run on real
  devices: Tamper Protection on, Intune/GPO-managed exclusions, a
  third-party AV, Defender passive mode.

## Consequences

* Fewer quarantines of the agents' own files on a device where Defender
  honours local exclusions; no change on devices where it does not, and the
  console now says why.
* A real, if small, loss of protection: files in the five folders are not
  scanned at rest. Because only administrators can write them, an attacker
  who can already write there has administrator rights; AMSI, behaviour
  detection and the scan of the download still apply.
* The two Program Files folders depend on inheritance. If an administrator
  loosens them, the exclusion is removed and reported. The agents do not
  change those access lists (a change to do so is a separate decision).
* Exclusions can show on a client's own audit of Defender; the page for
  administrators says what they are and why.
* An agent that is uninstalled while Defender is unreachable leaves
  exclusions behind; the record is deleted only after a successful removal,
  so a re-install finds it and removes them.
* Code signing is still needed and still on hold; this is not a substitute.

## Slices (proposed)

1. Folder check (Go and .NET), the record, add/remove/reconcile, facts.
2. Organization field, heartbeat, audit, device page.
3. EasyPatch agent and its installer custom action; the connector field.
4. Build hashes in Settings; the documentation page; Windows CI job.
