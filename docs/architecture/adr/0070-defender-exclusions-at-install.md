# ADR-0070: Microsoft Defender exclusions at install

* Status: Accepted (2026-11-26, after independent review). Not implemented yet.
* Revised after an independent review (2026-11-23), every point *decided in
  review*: the subtree is verified, the install folder is made safely and
  deleted by the script, the .NET extraction folder and the TEMP of the
  tools the agents start are set per process, uninstall without a record
  removes only the fixed set, Defender's "N/A" answers and
  `DisableLocalAdminMerge` are handled, the AMSI probe comes first, the
  hash list gains MeshAgent's version and adds no new text list, and the
  work is split in two slices.
* Amended 2026-11-26 (decided in review), after a second independent
  review: the .NET extraction folder is per service and per command, a
  failed `install.ps1` removes what it made and added, Defender not being
  the active antivirus is `not_applicable` and never a failure, the AMSI
  probe asserts AMSI stays on, hashes refresh on a self-update, a rebuild
  and every heartbeat that reports a new version, every new agent-side
  action is gated by `devscope.Allowed(org)`, the CI jobs prove the
  order, and each slice lists its files and tests.
* Amended 2026-11-26 (decided in review), while building slice A: (1) a
  Defender refusal or an unreadable Defender during `install.ps1` step 4
  is a warning and the agent reports it (`refused`, `unavailable`); only a
  failure of the script's own steps stops it, so a machine with Tamper
  Protection can still be installed; (2) the hash list refreshes on its own
  thirty-minute timer, not on the connector poll, and the server reads the
  engine's packages directly from the engine, not through the agent edge,
  checking each package's SHA-256 against the engine's list; (3) the
  Windows CI steps are one new job, `windows-defender`, not additions to
  `windows-system` and `windows-hardening`, and it covers steps 0 to 4, 6,
  8a and 9; steps 5, 7 and 8 (moved winget and update work, MeshAgent's
  update, the .NET extraction folders) wait for slice B and real devices;
  (4) the server answers every heartbeat with `defender.enabled`, the
  development-scope result, and the agent reconciles and reports only after
  an answer that says yes; MeshAgent's version is read from
  `meshagent -info`'s compile line, which is to confirm on a real device;
  (5) **the AMSI probe has not run yet**: it is `TestAMSIStaysOnAsSystem`
  in the `windows-defender` job, and its result is to be written here as an
  amendment before the feature ships.
* Asked for by the owner (2026-11-23), who suspects antivirus is blocking
  the agents on client machines. **Revised the same day to the owner's
  changed design** (below, *Owner decisions*): whole working folders are
  excluded at install, always, with no organization switch, and the server
  keeps a hash list of everything it hands out or installs, shown in the
  console. Everything marked *decided in review* is mine and the owner can
  overturn it.
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

## Owner decisions (2026-11-23)

The owner's words: "you will exclude the entire folders we work out of upon
agent install, we will keep an updated hash list of all things installed,
that the admin can see at anytime in the GUI." From that:

1. **Exclusions at install, always.** On install each agent adds a
   Defender path exclusion for every folder it works out of, the whole
   folder. There is no organization on/off setting.
2. **Every working folder is covered**, and any work done outside a
   protected root moves into one, so the excluded set never includes a
   folder ordinary users can write.
3. **The agent locks a folder down, then excludes it.** It never excludes a
   folder it cannot lock down, and reports that.
4. **"I dont want defender scaning our stuff at all."** Exclude everything
   Defender lets us exclude: path exclusions, process exclusions for the
   three executables, Attack Surface Reduction exclusions and Controlled
   Folder Access allowed applications (section 3). This **reverses** the
   first draft's "no process exclusions". Never disable AMSI or real-time
   protection machine-wide. Uninstall removes exactly what the agent
   added; the device page shows whether each kind works and why not.
5. **A current hash list of everything installed**, in the console, and
   each Windows agent reports the hashes of what is installed on it,
   compared with the expected ones.

Everything below that is not one of these five is *decided in review*.

## Decision

### Who may do what

| Action | Permission |
|---|---|
| See the hash list (Settings, "Agent files") | `org.view` or higher (`server/internal/rbac/rbac.go:24`) |
| See a device's exclusion state and installed-file hashes | `device.view` on the device |
| The agent adds or removes an exclusion, or locks a folder, on its own device | it acts as LocalSystem; nobody else is given a way to name a path |
| Upload a signed build (changes the list) | unchanged from ADR-0049 |

No user and no job can name a path to exclude. The paths are fixed in the
agents' code.

### 1. Every working folder, and what moves

The excluded set is every folder an agent writes to or runs from, whole
folders (`ExclusionPath`; the other kinds are in section 3):

| Managed by | Folder | Holds |
|---|---|---|
| EasyRMM agent | `%ProgramFiles%\EasyRMM\Agent` | the executable, `.new`/`.old`/`.failed` (update staging) |
| EasyRMM agent | `%ProgramFiles%\EasyRMM\MeshAgent` | MeshAgent, its settings, database, log, the `.meshagent-*` download |
| EasyRMM agent | `%ProgramData%\EasyRMM\Agent` | state, `logs\`, `recovery\`, `jobs\work\run-*` (scripts), `easypatch\` (the EasyPatch MSI), and the new `install\` (below) |
| EasyPatch agent | `%ProgramFiles%\EasyPatch Agent` | the executable |
| EasyPatch agent | `%ProgramData%\EasyPatch` | state, outbox, logs, `updates\`, `winget\`, and the new `work\` and `bundle\` (below) |

Work found outside those roots (see the table under *Where the agents
write*) **moves**:

* the Windows install script's download (`install.ps1.tmpl:61`, `:75`,
  today in the administrator's `%TEMP%`) goes to
  `%ProgramData%\EasyRMM\Agent\install\`, and the script, which already
  runs elevated, does these in order **before it downloads anything**
  (*decided in review*: it creates `ProgramData\EasyRMM\Agent\install`
  only after the same trusted-ancestor check as `Protect`
  (`system_windows.go:103-112`: every folder from ProgramData down is a
  plain folder owned by SYSTEM, Administrators, TrustedInstaller or the
  account running), and creates it with its access list in one step, as
  `mkdirProtected` does (`system_windows.go:817`), so there is no moment
  it is open to users). **On failure the script cleans up** (*decided in
  review*): it removes the exclusions it added (using the record it wrote),
  then the folders it created that hold nothing from an earlier install, in
  a `finally` block, and leaves a folder that existed before it ran
  untouched:
  (1) creates the agent's folders (`%ProgramData%\EasyRMM\Agent` with
  `install\`, and `%ProgramFiles%\EasyRMM\Agent` and `\MeshAgent`);
  (2) locks them down with the administrators-only list
  (`protectedDACL`, `agent/host/system_windows.go:100`); (3) verifies them
  with the check in section 2; (4) adds the Defender exclusions; (5) only
  then downloads the agent into the excluded `install\` folder. If any of
  steps 1 to 4 fails, the script stops and says why, rather than
  downloading into an unprotected folder. `easyrmm-agent install` takes
  over the script's record of what it excluded (the script writes
  `defender-exclusions.json` in the state folder, in the agent's format),
  so uninstall still removes exactly what was added. The script's `finally` block deletes
  `install\` (`install.ps1.tmpl:61-100`), not the agent, so it goes
  whether or not the install succeeded. The only thing nothing can exclude is the
  text of `install.ps1` itself, which AMSI still checks when it runs
  (section 3);
* the temp folder of every process the agents start: `TEMP` and `TMP`
  are set to the agent's own work folder on the winget and `msiexec`
  `ProcessStartInfo`s in the EasyPatch agent (`WingetProcessRunner.cs:38`,
  `WindowsAgentUninstaller.cs:36`, the agent-update installer in
  `AgentUpdateHandler.cs`) and on the Go agent's `msiexec` runs
  (`agent/easypatch/system_windows.go:66`), as the job runner already does
  (`agent/jobs/exec_windows.go:125`) (*decided in review*);
* the EasyPatch agent's winget working directory
  (`WingetProcessRunner.cs:38`, `Path.GetTempPath()`) becomes
  `%ProgramData%\EasyPatch\work\`;
* .NET's single-file extraction of the EasyPatch agent
  (`EasyPatch.Agent.csproj:11-12`, which extracts native libraries to a
  temp folder at start) is pointed at `%ProgramData%\EasyPatch\bundle\`
  with `DOTNET_BUNDLE_EXTRACT_BASE_DIR` set (**per service, never shared**:
  each .NET service or command gets its own subfolder,
  `bundle\EasyPatchAgent\` for the service and `bundle\unenroll\` and
  `bundle\defender\` for the commands run under `msiexec`, so one process
  cannot plant a library another loads; each is under the verified subtree)
  in the EasyPatch service's own
  `Environment` REG_MULTI_SZ value (under `HKLM\SYSTEM\CurrentControlSet\Services\EasyPatchAgent`)
  **only**, never machine-wide (*decided in review*). The `unenroll` and
  `defender` commands that run under `msiexec` (`Package.wxs:89-99`) get
  the variable explicitly, in the custom action's environment, since
  they do not inherit the service's. *To confirm on the runner where it extracts today.*
  If it cannot be moved, that folder is not excluded and the page says so.

Not ours, so never excluded: the Windows Update cache and Installer folder
(`C:\Windows`), PowerShell 7's own folders and winget's own package
store (Microsoft's, installed by others), `%TEMP%`, `%TMP%`, any user's
profile, a drive root, `%ProgramData%` and `%ProgramFiles%` themselves. If
a future build adds a working folder it goes under one of the five or gets
no exclusion.

**The EasyPatch MSI** gets the same order when the EasyRMM agent installs
it: the exclusion for `%ProgramData%\EasyRMM\Agent\easypatch\` (inside the
state folder, already locked and excluded) is in place first, then the MSI
is downloaded into it (`agent/easypatch/easypatch.go:237`), then run.

### 2. The agent locks the folder down, then excludes it (replaces "refuse")

For each folder, in order:

1. **Lock it down.** The EasyRMM agent calls `host.Protect`
   (`agent/host/system_windows.go:111`) for the folders under ProgramData
   and for MeshAgent's; the EasyPatch agent calls `SecureDataDirectory`
   (`Platform/SecureStorage.cs:20`) for `%ProgramData%\EasyPatch`. The two
   Program Files folders, today protected only by inheritance
   (`Package.wxs:74-76` sets no list; `host/files.go:24` makes the folder
   with `MkdirAll`), gain the same protected list, applied by the agent
   with a new `host.Protect` call and, for EasyPatch, a new `PermissionEx`
   on `INSTALLFOLDER` in `Package.wxs` plus the same call in the agent at
   start. Locking down changes only the folders the agents own.
2. **Verify** by reading the list back, with the check that decides
   whether a folder and every folder above it are writable by SYSTEM,
   Administrators and TrustedInstaller alone: a plain folder (not a link),
   owner SYSTEM, Administrators or TrustedInstaller, no other principal
   with a write right (CREATOR OWNER and CREATOR GROUP entries, and the
   add-a-folder right that ProgramData and a drive root give every user,
   are ignored: the rule of `FileTrust.cs:15-40`, ADR-0064). The EasyPatch
   agent reuses `FileTrust`; the EasyRMM agent gets the same check in
   `agent/host`, tested against the same table of lists.
   **The verify step walks the whole subtree** (*decided in review*), not
   only the ancestors: every file and folder below must have an owner of
   SYSTEM, Administrators, TrustedInstaller or the agent's account,
   entries from those principals only, and no link or reparse point.
   Anything else is moved aside or fails the check, as `checkState` does
   (`agent/host/system_windows.go:139-270`).
3. **Only then** add the exclusion.

**The EasyPatch agent gets the same handling as `checkState`**
(*decided in review*): `SecureDataDirectory` (`SecureStorage.cs:20`), which
today creates or re-lists the folder and sets the owner, instead
(a) moves a pre-created folder that is not trustworthy aside (owner not
trusted, a link, a user-added entry) and makes it anew, with its list set
at creation; (b) checks the owner and that every entry is a trusted
principal; and (c) walks the subtree for owner, access list and
reparse points, with the same table of lists as the Go side. A folder it
cannot make safe stops the agent from starting (it already fails closed:
`Program.cs:49-58`).

If a folder cannot be locked down or verified (a policy blocks the change,
a parent is writable by users, a link), the agent **does not exclude it**,
logs why, and reports `not_locked: <reason>` for that folder. Each
reconcile (below) repeats the check, and if a folder has since become
writable by someone else the agent removes its own exclusion for it and
reports it.

### 3. Everything Defender lets us exclude (owner decision)

Four kinds, each added only after the folder (or executable's folder) is
locked down and verified (section 2), each from a fixed list in the code:

| Kind | Cmdlet parameter | What is added |
|---|---|---|
| Path | `ExclusionPath` | every working folder in section 1 |
| Process | `ExclusionProcess` | the **full path** of `easyrmm-agent.exe`, `meshagent.exe` (EasyRMM agent) and `EasyPatch.Agent.exe` (EasyPatch agent); never a bare name, never `powershell.exe`, `msiexec.exe` or any other program |
| Attack Surface Reduction | `AttackSurfaceReductionOnlyExclusions` | the same folders, so ASR rules (for example "block process creations from PSExec and WMI commands" or "block executable files unless they meet prevalence, age or trusted list criteria") do not act on our files |
| Controlled Folder Access | `ControlledFolderAccessAllowedApplications` | the full paths of the same three executables, so ransomware protection lets them write to protected folders |

The agent never adds `ExclusionExtension`, and never turns off real-time
protection, Controlled Folder Access, ASR rules or any Defender feature,
on the machine or for a user.

**The cost of the process exclusions, stated plainly.** Defender does not
scan what an excluded process opens or writes, **anywhere**, not only in
our folders, at that moment: file transfers the agent receives or sends,
scripts it writes and runs, updates it downloads, and files MeshAgent
moves during a remote session. Such a file is scanned when a *different*
process opens it. A process exclusion is also only as safe as the
executable: the executables sit in folders only administrators can write
(section 2), and each agent still verifies its updates (the server's
signed instructions, the release signature on the EasyPatch agent) before
using them. The owner chose this knowing the cost.

**Defender answers that are not data** (*decided in review*): where
`Get-MpPreference` returns text such as "N/A: Must be an administrator or
have Tamper Protection ... " instead of a list (Defender hides what it
will not show), the state is `unavailable` with that reason, never
`effective` and never a guess from an empty list.

**AMSI.** What the Microsoft documentation says: Defender's exclusion
lists (path, process, extension) apply to its file scanning; AMSI is a
separate interface that script hosts such as PowerShell call with the
script text, and I found no documented exclusion list for it. Not
documented, so it is **to confirm on the Windows CI runner**: whether a
script run by PowerShell from an excluded folder, or by an excluded process,
is still passed to AMSI and blocked. **The build's first step is a CI probe** (*decided in review*), before
any feature code: with the exclusions of this section in place on the runner,
run an EICAR-style AMSI test string from our script folder, and write the
result into this ADR as an amendment **before the feature ships**; the
status text on the device page follows that result and says nothing about
scripts the probe did not show. The test (the
Testing section) runs an EICAR-style AMSI test string from the
agents' script folder and **records the result**; this ADR assumes
scripts are still scanned until it shows otherwise. If the result is that
they are, the answer to "can scripts be excluded" is no, and nothing
here tries to disable AMSI or the provider. The text of `install.ps1`
itself is likewise checked by AMSI when it runs.

### 4. Each agent manages its own folders; a record keeps it honest

* The EasyRMM agent adds, reconciles and removes the first three folders,
  the EasyPatch agent the last two.
* Each keeps a **record** of exactly the exclusions it added, of all four
  kinds (the kind is stored with each entry):
  `defender-exclusions.json` in the EasyRMM agent's protected state folder,
  and `state\defender-exclusions.json` in the EasyPatch data folder: the
  normalized path, the time and the agent version.
* An entry already in the list for its kind (`ExclusionPath`,
  `ExclusionProcess`, `AttackSurfaceReductionOnlyExclusions`,
  `ControlledFolderAccessAllowedApplications`) before the agent adds
  anything is not ours: it is not recorded, not added again and never removed (comparison
  is case-insensitive on the normalized absolute path). An administrator's
  exclusion, even for the same folder, survives uninstall.
* Uninstall removes **exactly the recorded entries**, one
  `Remove-MpPreference` each with the parameter of its kind, then deletes
  the record. If
  the record is **missing or corrupt**, the agent removes only entries
  that exactly match the fixed set in section 3 and only for folders that
  still verify as administrators-only; it never removes anything else,
  and logs what it removed and what it left (*decided in review*). No
  wildcard, no "everything under EasyRMM".

**When it runs.** The EasyRMM agent: in `easyrmm-agent install`
(`agent/cmd/easyrmm-agent/main.go:264`, after `putService`, before the
service starts); in `repair-install` (`main.go:313`); at each start of `run`
as a reconcile that adds what is missing and removes what no longer
qualifies; and in `uninstall` (`main.go:648`) after the service and
MeshAgent are stopped and **before** the files are removed, so a failure
leaves the folders for a retry. The server-started removal
(`removeOnRequest`, `removal.go:54`) takes the same path. The EasyPatch
agent: at each service start beside `SecureDataDirectory` (`Program.cs:53`)
and in the MSI's install, and on uninstall by a deferred custom action in
`Package.wxs` before `UnenrollAgent` (`Package.wxs:89-99`), under the same
`REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE`, so an upgrade keeps the
exclusions.

**How.** The Defender PowerShell module (`Add-MpPreference`,
`Remove-MpPreference`, `Get-MpPreference`, `Get-MpComputerStatus`), run from the fixed
`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe` with a
fixed script, `-NoProfile -NonInteractive`, and the path passed as an
environment variable, never joined into the script text; the command text
is fixed and built only from our constant paths, with no user input.
**Why the module first**: the module matches how
the agent already drives Windows (`agent/powershell`) and adds no COM
dependency to the Go agent or the .NET one (*decided in review*). A failed Defender
call is logged and reported; it never fails an install, an uninstall or a
heartbeat.

### 5. Defender may ignore or refuse them: report whether they work

A local exclusion is not always honoured. The agent reports, in its facts,
`defender` with:

* `state`: `effective`, `present_not_effective`, `not_locked` (a folder
  could not be locked down, so it was not excluded), `refused` (Defender
  refused the add), `unavailable`, or `not_applicable` (Defender is not the
  active antivirus: a third-party product, passive mode or off, see below;
  *decided in review*);
* `reason`: one short sentence, set whenever `state` is not `effective`;
* per folder: the path, `listed` (true when the exact path is in
  `ExclusionPath`), `ours` (it is in the record) and the reason if the folder was not
  locked down; and per kind (path, process, ASR, Controlled Folder
  Access) the same state and reason, so the page shows each of the four
  working or not.

The agent decides from these documented fields (to be confirmed against
real hosts on the CI runner):

| Source | Field | What it tells |
|---|---|---|
| `Get-MpPreference` | `ExclusionPath`, `ExclusionProcess`, `AttackSurfaceReductionOnlyExclusions`, `ControlledFolderAccessAllowedApplications` | whether each entry is listed, per kind |
| `Get-MpPreference` | `EnableControlledFolderAccess`, `AttackSurfaceReductionRules_Ids` and `_Actions` | whether Controlled Folder Access and ASR are on at all (if off, those two kinds are `not_needed`, not a failure) |
| `Get-MpPreference` | `DisableLocalAdminMerge`, **read before the exclusions are read back** (a null counts as false) | `True` means local exclusions are ignored in favour of the policy's (Intune, GPO, Configuration Manager): reason `local exclusions are ignored (DisableLocalAdminMerge)` |
| `Get-MpComputerStatus` | `AMRunningMode` | `Passive`, `SxS Passive Mode` or `EDR Block Mode` instead of `Normal`: Defender is not the active antivirus; passive is the sign of a third-party AV |
| `Get-MpComputerStatus` | `AntivirusEnabled`, `AMServiceEnabled`, `RealTimeProtectionEnabled` | Defender is off or its real-time scanner is, so exclusions are moot |
| `Get-MpComputerStatus` | `IsTamperProtected` | Tamper Protection is on: an add made by the agent may be refused or reverted; reported next to the result of the add, not alone |
| the add itself | the cmdlet's error, and a read-back of the list of its kind | `refused` with Defender's own message when the add fails or the path is not listed afterwards |

**`not_applicable` is not a failure** (*decided in review*): when
`AMRunningMode` is not `Normal`, or antivirus or real-time protection is
off, the agent still locks the folders down but adds nothing, reports
`not_applicable` with the reason, raises no alert, and does not fail an
install or a heartbeat. The reconcile adds the exclusions if Defender later
becomes active. `DisableLocalAdminMerge` set by Group Policy is detected
before any add and reported as `present_not_effective` with the reason above;
the agent still records what it added.

`effective` needs: Defender's `AMRunningMode` is `Normal`, antivirus and
real-time protection are enabled, `DisableLocalAdminMerge` is not true, and
every folder is listed. The Defender module is missing on a Windows
Server installed without Defender: `not_applicable`, with the reason.
**PowerShell or WMI:** the Defender module is the one way; if the module
cannot be loaded or the cmdlet fails for a reason other than Defender's own
refusal, the agent falls back **once** to the `MSFT_MpPreference` class
(`root\Microsoft\Windows\Defender`, `Add`/`Remove` methods) for that call,
logs which was used, and reports `unavailable` if both fail. Never both for
the same entry, so the record stays one-to-one. Naming
which third-party AV is active is not required; the agent may add the
product name from the Windows Security Center's `AntiVirusProduct` if
present, and does not depend on it.

The device page shows this beside the agent versions: a status, the
reason, and the folders with a tick or a cross. The hardening page
(ADR-0054) is unchanged.

**Development scope** (*decided in review*, plan section 3). Every
agent-side action in this ADR (lock-down, exclusion add, remove and
reconcile, the hash report) runs only where `devscope.Allowed(org)` allows
while the development scope is set; the server sends the agent the result
with its configuration and the agent does nothing on a device the scope
excludes. Exclusions are **machine-wide** (Defender has no per-user or
per-process scope for a path), so the safeguard is the order: SYSTEM and
Administrators only on every folder, verified, before any add; if that
check fails the exclusion is not added.

### 6. No organization setting

Dropped at the owner's direction. Installing an agent on Windows adds the
exclusions; uninstalling removes them. An administrator who does not want
them removes them in Defender and the agent will add them back at its next
reconcile (it does not take a "do not add" decision from the console); the
way to stop that is to uninstall the agent. This is a consequence the
documentation page states. Linux and macOS agents ignore the whole
feature.

### 7. Every change is audited

Each add, removal, lock-down and refusal is written to the agent's own log
(the EasyRMM agent's `logs\agent.log`; the EasyPatch agent's rolling log
and Windows event log) with the path, the reason and the agent version,
even when the server cannot be reached. The agent also reports each as a
new agent-reported event with the next heartbeat, and the server writes it
into the audit chain with `audit.Event` (as `server/internal/tenancy/tenancy.go:340`
does for organizations) as `device.defender_exclusion.add`, `.remove`,
`.lock`, `.not_locked` and `.refuse`, with the device, path, agent and
reason.

### 8. The hash list of everything installed

**Part A, the console page.** Settings gains **Agent files**, read-only,
for anyone with `org.view` or higher. It lists every file the server hands
out or the agents install, each with name, platform and architecture,
version, size, **MD5** and **SHA-256** (with copy buttons), and the
source. MD5 is shown because some allow lists still ask for it and is
never used to trust anything. There is **no new unauthenticated list**
(*decided in review*): the existing public `SHA256SUMS`
(`agentapi.go:756`) stays as it is, and the new list is only in the
console, behind `org.view`.

| Entry | Where the server reads it from |
|---|---|
| EasyRMM agent, each platform and architecture | `agents.Builds`, read once from the build directory at startup (`server/internal/agents/builds.go:79-121`). `Build` has `SHA256` only (`builds.go:21-35`); `describe` (`builds.go:123-139`) gains an MD5 computed in the same pass |
| Signed Windows builds (ADR-0049) | the same list: a signed build is served in place of the release's (`builds.go:253-258`, `Build.Signed`); its hashes are computed from the uploaded bytes when it is accepted, and the entry shows the signer |
| MeshAgent builds served by MeshCentral | not on the server's disk. `meshcentral.Files.Agent(ctx, arch)` opens `/meshagents?id=<arch>` as the service account (`server/internal/meshcentral/files.go:62`, used by `remote.MeshAgents.Binary`, `remote/agentfiles.go:31`). The server downloads each architecture it offers through that call, hashes it (both sums, one pass), and keeps the result with the time. Which architectures: the Windows and Linux ones the agent's installers use today |
| EasyPatch agent packages (MSI, and the Linux packages) | the patching engine's package list: `Client.AgentPackages` (`server/internal/easypatch/client.go:~952`, `AgentPackage` with `SHA256`, `Version`, `Architecture`, `Format`) as already used by `Service.AgentPackageList` (`easypatch/settings.go:348`). The engine gives SHA-256 only, so the server fetches the package once through its own agent edge (`/downloads/agent/`, `easypatch/agentedge.go:28`), checks the SHA-256 equals the engine's, and computes the MD5 |
| EasyPatch agent's own executables inside the MSI | the MSI holds them; the server cannot read inside it. The EasyPatch build publishes a per-file list beside each package (file name, MD5, SHA-256 of what the installer lays down), which the server reads with the package. Until it does, the page shows the package's hashes and says the files inside are not listed |

**Refresh.** The list is rebuilt when the server starts (so after an
upgrade or a rebuild), when a signed build is accepted or removed, when the patching
engine's package list changes (checked on the existing connector poll), and
by a *Refresh* button that needs the permission that already guards
signed-build uploads, `settings.manage` (`server/internal/agents/signed_builds.go:152`,
platform-wide, `rbac.go:61`); the page shows when each entry
was last computed. An entry that cannot be read (MeshCentral down) keeps
its last value, marked stale, rather than disappearing.

**Part B, what is installed on each device.** The EasyRMM agent, which is
SYSTEM and already reads the EasyPatch agent's folder
(`agent/inventory/easypatch_windows.go:20`), hashes the program files of
the three program folders: `easyrmm-agent.exe`, MeshAgent's `meshagent.exe`
(`meshagent.go:87`), and the files in `%ProgramFiles%\EasyPatch Agent`
(from the per-file list above, or every file in the folder). It reports MD5 and
SHA-256 of each in its facts, with **MeshAgent's version** (new in `Facts`,
since the hash alone says nothing about which build it is), at most 64
files, names of at most 260 characters and a total `InstalledFiles` size
the server caps (a few tens of KiB), refusing the facts that exceed it
(*decided in review*), on enrollment, after each install, update or
self-update (the agent reports once it is running the new build), once a
day, and **in every heartbeat that reports a changed version** of any of
the three programs, so a device never shows hashes of a build it no longer
runs (the owner: never a stale hash). State, logs, scripts and settings files are not hashed.
The device page labels them **"reported by the device"**, as an agent
could report anything, and lists them **next to the expected values** from Part A
for the version the device reports, and flags a mismatch (a missing file,
an unexpected file, a different hash) without acting on it. **MeshAgent
is the exception**: MeshCentral updates its agents itself, so a MeshAgent
hash that differs from the currently served build shows as "not the
current build", not "mismatch". A mismatch on
a build the operator signed compares against the signed build's hashes.
A device whose version has no expected entry (an older build) shows the
installed hashes and "no expected value". When a device reports a version
the list lacks, the server recomputes the list entry for it (once per
version, rate limited) instead of waiting for the next refresh. Every hash
shows its source ("served by the server", "MeshCentral", "patching engine",
"reported by the device") and when it was computed or observed; a value
older than its last version change is never displayed as current. Who sees
what: the list (Settings, Agent files) needs `org.view`; a device's
reported hashes need `device.view` on that device; the Refresh button needs
`settings.manage`.

### 9. This does not replace code signing

Signing is the real fix for false positives, because the reputation and
trust Defender and SmartScreen give follow a publisher's certificate, not
a folder. Public-certificate signing is on hold (`CODE_SIGNING.md:56-62`);
ADR-0049 lets an operator sign the EasyRMM agent with their own
certificate. Exclusions are a stopgap for the folders above; they do
nothing for the text of `install.ps1` (checked by AMSI, section 3), and they must not be read as a reason to leave signing
undone. When signing lands, this ADR stays: the exclusions still avoid
scans of files the agents rewrite constantly, but the setting's default
can be revisited.

## Data

* Migration (next free number when built): `devices.defender jsonb` (last
  reported exclusion state: state, reason, per-folder rows, observed at)
  and `devices.installed_files jsonb` (file, version, MD5, SHA-256,
  observed at); a table `agent_file_hashes` for the console list (name,
  platform, arch, version, source, size, md5, sha256, computed at, stale).
  No organization column.
* `agentproto.Facts` (`internal/agentproto/agentproto.go:58`) gains
  `Defender` and `InstalledFiles`, both optional; `Build` gains `MD5`.
* Audit actions as in section 7.
* Agent-side files: the two records. PRIVACY.md gains a line: the paths
  of the agents' own folders, Defender's state, and hashes of the agents'
  own program files are collected from Windows devices.

## Agent changes

* EasyRMM agent (Go): `agent/defender` (new): lock down, verify, record,
  add, remove, reconcile, state; a read-only folder-trust check and a
  `Protect` of the two Program Files folders in `agent/host`; the installed
  file hashing; callers in `install`, `repair-install`, `run`, `uninstall`
  and `removeOnRequest`; `install.ps1` downloads into the protected
  `install\` folder.
* EasyPatch agent (.NET): a `DefenderExclusions` class using `FileTrust`;
  a `defender` command (`add`, `remove`, `status`); `Package.wxs` gains the
  list on `INSTALLFOLDER`, the custom action and the bundle-extract
  environment; the winget working directory moves; the build emits the
  per-file hash list.
* Windows only.

## Server changes

* Heartbeat and facts handling for the new fields; the device page (state,
  reason, folders, installed files against expected); the audit events;
  `describe` computes MD5; the hash list service (MeshCentral and
  EasyPatch fetches, refresh, stale marking); Settings "Agent files"
  with `org.view`; the text list; the documentation page "Antivirus and
  EasyRMM" (the folders, where the hashes are, how to allow-list by hash in
  Microsoft Defender for Endpoint and by path elsewhere).
* The server never names a path to an agent.

## Testing

* Unit: the folder check against a table of access lists (administrators
  only; Users with write; add-a-folder only on ProgramData; CREATOR
  OWNER; a link; a missing folder; a writable parent), the same table in
  Go and .NET; the record (adds only what was absent, removes only what is
  recorded, a pre-existing path survives); the state decision table; the
  hash list refresh and stale rules; the installed-file comparison.
* Integration (real PostgreSQL): the list endpoint and its `org.view`
  gate; the facts stored; the audit rows.
* **A real Windows runner in CI** (Windows Server 2022 or 2025 with
  Defender running, not mocked). It reuses the `windows-system` and
  `windows-hardening` jobs (`.github/workflows/backend-tests.yml:140`,
  `:329`), which run as LocalSystem, as the agents do. Real-time
  protection is turned on in the job where the image allows it;
  where it does not, the assertions that depend on it are skipped with a
  stated reason in the job log. The winget check is skipped on
  `windows-11-arm`. The steps:
  0. **order:** a CI run of `install.ps1` records timestamps and asserts
     create, lock down, verify, exclusion, then download, in that order,
     that nothing was written before the exclusion, and that a forced
     failure at each of the first four steps downloads nothing and leaves
     no folder or exclusion the script made;
  1. add: after `install`, every working folder is locked down and listed
     in `Get-MpPreference`'s `ExclusionPath` and `AttackSurfaceReductionOnlyExclusions`, the three executables in `ExclusionProcess` and `ControlledFolderAccessAllowedApplications`, and `%TEMP%` and `powershell.exe` are not;
  2. check: `Get-MpComputerStatus` reports `Normal`; the facts say
     `effective`; with `DisableLocalAdminMerge` set they say so;
  3. remove: after `uninstall`, exactly those paths are gone and a path
     added by hand beforehand is still listed;
  4. not locked: make a folder's parent writable by Users (`icacls`) so it
     cannot be verified; assert no exclusion is added, the state is
     `not_locked` with the reason, and an existing exclusion for a folder
     that became writable is removed;
  5. moved work: a script run, a winget call and an agent update leave
     nothing in `%TEMP%` or `C:\Windows\Temp`, and run from the
     protected folders;
  6. **AMSI:** an EICAR-style AMSI test string, run by PowerShell from the
     agents' script folder (with everything excluded) and again run by an
     excluded process, with the result **recorded** (blocked or not) in
     the job log and the ADR's amendment; the build fails if real-time
     protection or AMSI was disabled to get a result, and **the job asserts
     AMSI stays enabled** after install, after the exclusions and after
     uninstall (the AMSI provider is registered and the test string is
     still blocked when run from a non-excluded path); a change that makes
     the agent turn AMSI off, or a machine-wide change, fails it;
  7. MeshAgent: after a MeshAgent update, no file was written outside its
     folder (compare the folders' contents and `%TEMP%` before and after);
  8. DOTNET extraction: the EasyPatch service extracts into its own
     `bundle\EasyPatchAgent\` folder, each command into its own, and
     nothing machine-wide has the variable set;
  8a. `not_applicable`: with Defender passive or real-time off (where the
     image allows) the facts say `not_applicable` and install succeeds;
  9. hashes: the reported installed hashes equal the list's; replacing a
     byte of an installed file shows a mismatch on the device page; after
     a self-update the next heartbeat carries the new hashes and the page
     shows no stale one.
* Not reachable by CI, stated as untested until run on real devices:
  Tamper Protection on, Intune/GPO-managed exclusions, a third-party AV,
  Defender passive mode.

## Consequences

* Fewer quarantines of the agents' own files where Defender honours local
  exclusions; no change where it does not, and the console says why.
* Whole-folder and process exclusions remove Defender's scanning of
  everything in those folders and of what the three processes open
  anywhere, at that moment (section 3). The path exclusions are acceptable
  because the agent makes the folders administrators-only first and
  refuses to exclude any it cannot lock down. The process exclusions are
  a wider trade the owner accepted: a file moved by the agent or
  MeshAgent is scanned only when another process opens it. Whether AMSI
  still scans scripts is to be confirmed on the runner.
* Locking the two Program Files folders and moving the three pieces of
  work are real changes to how the agents run, and are the riskiest part
  of the build.
* No off switch: an organization that does not want exclusions cannot say
  so in the console. The owner chose this; the documentation says so.
* The console now holds the truth about every file the agents run, which
  also serves anyone allow-listing by hash. MeshCentral's and EasyPatch's
  files are fetched, so their rows can be briefly stale; they are marked.
* An agent uninstalled while Defender is unreachable leaves exclusions
  behind; the record is deleted only after a successful removal, so a
  re-install finds it and removes them.
* Code signing is still needed and still on hold; this is not a
  substitute.

## Build slices

Two slices, built separately (*decided in review*). The AMSI probe is the
first step of slice A, before any feature code.

**A. The EasyRMM side** (files: `agent/defender/` (new), `agent/host/`
`system_windows.go` and the folder-trust and subtree check, `agent/cmd/
easyrmm-agent/main.go`, `agent/easypatch/` (`TEMP`/`TMP`), the installed-file
hashing in `agent/inventory/`, `server/internal/agentproto/agentproto.go`,
`server/internal/agents/builds.go`, the hash list service and its handler,
the audit actions, a migration `server/migrations/9xxxx_*.sql`,
`install.ps1.tmpl`, `web/` Settings "Agent files" and the device page,
`.github/workflows/backend-tests.yml`, the documentation page; tests: the
unit and integration tests above and CI steps 0 to 9). The Go agent (`agent/defender`, the folder check
and subtree walk in `agent/host`, `Protect` of the Program Files folders,
installed-file hashing, `TEMP`/`TMP` on its `msiexec` runs, the MSI
order: exclusion, then download), `install.ps1` (create, lock down,
verify, exclude, then download; its `finally`), `Facts` and its caps, the
server (storage, audit, the hash list service and `describe`'s MD5), the
console (device page, Settings "Agent files"), the documentation page and
the Windows CI job.

**B. The EasyPatch side** (files: `easypatch/` `DefenderExclusions.cs` (new),
`Platform/SecureStorage.cs`, `FileTrust.cs`, `Program.cs`,
`WingetProcessRunner.cs`, `WindowsAgentUninstaller.cs`,
`AgentUpdateHandler.cs`, `Package.wxs`, `EasyPatch.Agent.csproj`, the build
script that emits the per-file hash list; tests: `dotnet test` for the
folder check table, the record and the state table, and CI steps 1 to 5 and
8). The .NET agent (`DefenderExclusions`, the
`defender` command, `SecureDataDirectory` brought to `checkState`'s
handling, the subtree walk), `TEMP`/`TMP` on the winget and `msiexec`
`ProcessStartInfo`s, `DOTNET_BUNDLE_EXTRACT_BASE_DIR` in the service
`Environment` and the custom actions, `Package.wxs` (the list on
`INSTALLFOLDER`, the custom action, the MSI order), the per-file hash
list the build emits, and the `FileTrust` table shared with A.
