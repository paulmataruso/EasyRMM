# ADR-0064: Remote PowerShell management

* Status: Proposed (2026-11-21). Not implemented.
* The owner decided one part (2026-11-21): interactive sessions use
  MeshCentral's terminal, audited at the session's start, without a
  record of what is typed ([Interactive sessions](#interactive-sessions)).
  Everything else marked as decided was decided in review.
* Amends: [ADR-0017](0017-scripts-and-jobs.md): a `pwsh` shell beside
  `powershell`; one-off commands beside the library; output while a run
  is open; targets chosen by organization, site or group; the program
  that ran recorded on each run. It gains an *Amended by ADR-0064* line
  when this is implemented.
* Builds on: [ADR-0009](0009-agent-protocol.md) (its section "Evolving
  the protocol"), [ADR-0014](0014-remote-access-gateway-and-device-discovery.md)
  and [ADR-0033](0033-relays-bound-to-grants.md) (the remote-access
  gateway), [ADR-0018](0018-inventory-and-telemetry.md) (the hashed
  inventory), [ADR-0020](0020-windows-agent.md) (the Windows agent),
  [ADR-0025](0025-remote-session-latency.md) (the session view's script),
  [ADR-0029](0029-reports.md) (audited CSV downloads),
  [ADR-0047](0047-tokens-shown-again.md) (a read and its audit record in
  one transaction), and these proposed ADRs:
  [ADR-0054](0054-hardening-windows-computers-and-servers.md)
  (`AllSigned` and Constrained Language Mode; the Windows test machines),
  [ADR-0055](0055-lets-encrypt-in-one-step.md#step-up-authentication)
  (step-up authentication), [ADR-0057](0057-rotating-the-job-key.md)
  (the job key ring), [ADR-0058](0058-signed-settings-that-reach-the-agent.md)
  (capabilities), [ADR-0059](0059-the-agents-websocket-channel.md)
  (wakes) and [ADR-0060](0060-collecting-logs.md) (its slice 0, and
  script block logging). ADR-0063 (who sees a job's output and
  arguments) is proposed on a branch of its own and not merged, so it is
  cited without a link; this ADR builds on its permission and endpoints.
* Requirements: feature 6, "Remote PowerShell Management", of the
  owner's requirements of 2026-11-21. Every bullet is placed in
  [The requirements](#the-requirements). The plan for the twelve MSP
  features (`feature-plan-msp.md`, on its own branch, not merged) lists
  this as feature 6; where this ADR differs from it, it says so.

## Context
Most of the requirement is already scripts and jobs (ADR-0017). Each
claim below was checked in the code at `main` `0596332` for this ADR.

**What exists.**

* **The library.** Scripts at three levels (shared, organization, site),
  shells `powershell`, `cmd`, `sh`, `bash` and `python3`, bodies up to
  64 KiB, a default timeout from 1 second to 4 hours. Writing needs
  `script.manage` at the script's level: Site Administrators and above
  (`server/internal/jobs/scripts.go`; migrations `00004_scripts_jobs.sql`
  and `00007_windows.sql`, whose `CHECK` constraints list the shells).
* **Jobs run library scripts only.** `CreateJob` refuses a job without a
  `scriptId` (`server/internal/jobs/jobs.go`). ADR-0017: "Only library
  scripts run; there are no ad hoc scripts in this phase, so
  `script.run` lets a technician run reviewed code without letting them
  write it. (Interactive terminals remain a separate permission.)"
* **Who runs what.** Technicians hold `script.run`, `job.manage` and
  `device.terminal`; Read-Only holds the view permissions only
  (`server/internal/rbac/rbac.go`). Roles are fixed in code; there are no
  custom roles. Every check is made at each device's site, and one device
  failing refuses the whole job.
* **Targets.** Up to 500 devices, chosen one by one in the console's
  device picker (a text filter and *select all*); the API takes device
  IDs only (`JobInput.DeviceIDs`). A device has at most one device group,
  inside its site.
* **Delivery.** A signed long poll (`PollRequest` is an empty object),
  redelivery after two minutes, a start check so that a late redelivery
  never runs, the first result wins, a sweeper every 30 seconds. A run
  waits 1 hour to 7 days for an offline device; a started run that does
  not report by its deadline (start + timeout + 5 minutes) becomes
  `lost`, and a late result replaces `lost`
  (`server/internal/jobs/delivery.go`, `service.go`).
* **The payload is strict on the agent.** `DecodeJob` refuses unknown
  fields, `VerifyJob` refuses a shell it does not know and any payload
  version but 1 (`internal/agentproto/jobs.go`). ADR-0009 requires that
  the server send a new instruction, or a new field in one, only to a
  build that reported understanding it. The server reads agent requests
  leniently (`decode` in `server/internal/httpapi/agentapi/agentapi.go`).
* **Signed requests are limited per device**: one a second with bursts
  of 120, at most four open polls, bodies of 1 MiB (4 MiB for results
  and inventories); inventories once in 10 minutes with bursts of 6.
* **On Windows, PowerShell is Windows PowerShell 5.1 only.**
  `interpreter` takes `System32\WindowsPowerShell\v1.0\powershell.exe`
  under the Windows folder, and runs it as LocalSystem with `-NoLogo
  -NoProfile -NonInteractive -ExecutionPolicy Bypass -File script.ps1`
  and the arguments, the script saved as UTF-8 with a byte order mark,
  without a window, with the system environment, in a job object
  assigned after the process starts (`agent/jobs/exec_windows.go`).
  ADR-0060's slice 0 (proposed) assigns the job object before the
  process runs. The agent is built for Windows on amd64 and arm64
  (`Makefile`, `build-agents`).
* **Output only at the end.** The agent keeps the first and last 128 KiB
  of each stream; writing never blocks the script (`agent/jobs/capture.go`).
  The result, with the exit code, goes to the server when the script
  ends (`agent/jobs/exec.go`). The run page says "The device sends the
  script's output when it ends" (`web/src/pages/jobs/RunDetailPage.tsx`).
* **The agent's journal** records each run as received, started and
  finished, with its result, until the server has it, so that a restart
  never runs a job twice and nothing that ran goes unreported. At most
  four scripts run at once (`agent/jobs/worker.go`, `journal.go`).
* **Nothing records which program ran or its version.** The run has a
  status, an exit code, both streams, an error and times; the job has
  the shell's name.
* **Copy, no download.** Each stream has a *Copy* button
  (`OutputView`, `web/src/pages/scripts/parts.tsx`).
* **The agent's facts.** The heartbeat's `Facts` (host name, system,
  platform, the agent's build) are written to the device's row every
  minute. The inventory is collected every hour and after each job,
  hashed, and uploaded only when its hash changes (ADR-0018;
  `agent/runner/runner.go`); the server keeps it as JSON after
  `cleanInventory` (`server/internal/inventory/service.go`).
  PowerShell 7 appears only as an installed program, if at all.
* **Audit.** Each run is recorded when the job is created, as
  `device.script_run`, with the script's name and SHA-256, never
  argument values (`jobs.go`). A record's details hold at most 16 KiB
  (`server/internal/audit/audit.go`).
* **Output and arguments are read by everyone with `job.view`**,
  Read-Only included, with no record. ADR-0063 (proposed) moves them
  behind `job.view_sensitive`, held by Technicians and above, through
  audited endpoints of their own: `GET /api/v1/job-runs/{id}/output` and
  `GET /api/v1/jobs/{id}/arguments`, a read and its record in one
  transaction. It says downloads, when built, use the output endpoint
  with `?download=stdout` or `?download=stderr`.

**The terminal today.**

* The console opens MeshCentral's terminal in a frame: `StartSession`
  checks `device.terminal` at the device's site, that the device is
  online and MeshCentral connected, gives the user's MeshCentral account
  the site's rights, and records `device.remote_session` with the kind
  `terminal` and the grant (`server/internal/remote/sessions.go`).
* The frame opens MeshCentral's terminal tab (`viewmode=12`), and
  EasyRMM's script for MeshCentral's page (ADR-0025,
  `server/internal/meshcentral/viewer.js`) presses *Connect*.
  In MeshCentral 1.3.1, the pinned image, *Connect* opens protocol 1,
  the *Admin Shell*; its menu also offers *Admin PowerShell* (6), *User
  Shell* (8) and *User PowerShell* (9), each with an *Ask* variant that
  asks the signed-in user first (`views/default.handlebars` in the
  image). The user variants run as the person signed in to the computer.
* The gateway lets a browser's relay through only for protocols 1, 6, 8
  and 9, only on a device the session was granted a terminal on
  (`relayKinds`, `server/internal/remote/relayguard.go`). It sees which
  of the four is opened, and records nothing about it.
* MeshAgent starts its PowerShell terminals through modules built into
  its binary (`win-virtual-terminal` or `win-terminal`,
  `StartPowerShell`, named in the image's `agents/meshcore.js`). Nothing
  in that file names `pwsh`; which PowerShell they start is not verified
  on a Windows computer.
* What is typed and shown is not recorded by EasyRMM. MeshCentral can
  record sessions itself (`sessionrecording` per domain and protocol, in
  the image's `meshrelay.js`); EasyRMM does not turn it on, and the
  gateway refuses MeshCentral's recordings pages (ADR-0014).
* MeshCentral's rights (`server/internal/meshcentral/rights.go`) turn the
  terminal on or off as a whole; there is no right per terminal type.

**What is missing for the requirement**: PowerShell 7; the version used;
real-time output; individual commands that are not in the library;
groups as targets; downloads; and who sees output, which is ADR-0063.

**Test harnesses.**

* CI's job *Agent tests on Windows* runs on `windows-latest`, as an
  administrator (`.github/workflows/backend-tests.yml`). On 2026-11-21
  that was Windows Server 2025 (10.0.26100), image `windows-2025-vs2026`
  version 20261116.315, whose list of included software names
  PowerShell 7.6.10; Windows PowerShell 5.1 is part of Windows.
* The machine harness (`internal/vmtest`) boots Linux distributions'
  cloud images under QEMU. It has no Windows image; ADR-0054's W1 decides
  how Windows machines are tested.
* The browser end-to-end test runs a real server with a simulated agent
  (`web/e2e/agent.ts`); `tools/agentsim` simulates many agents.

## Decision

### In short
* **PowerShell 7.** The agent finds machine-wide PowerShell 7
  installations in fixed folders only, checks who can change them,
  reports them with Windows PowerShell 5.1 in its inventory, and runs a
  new `pwsh` shell in the newest one. A script says what happens where
  PowerShell 7 is missing: the run fails (the default), or it runs in
  Windows PowerShell 5.1. Every run records the program, its edition,
  version and architecture, shown on the run and in every download.
* **Downloads.** One stream as text, one run as JSON, a whole job as a
  ZIP, through ADR-0063's audited output reads; and the job's results as
  CSV without output.
* **Live output** for runs someone is watching, posted by the agent over
  its existing HTTPS every 2 seconds, kept as a bounded tail in an
  unlogged table, read under `job.view_sensitive` with one audit record
  per watch.
* **One-off commands** under a new permission, `script.run_oneoff`, held
  by the roles that hold `device.terminal`, with step-up authentication
  for every job; the text kept with the job, read through an audited
  endpoint, and its SHA-256 in the audit record of every run.
* **SYSTEM stays the only way jobs run** (root on Linux). "Appropriate
  authorization" is the permission at each device's site, plus step-up
  for one-off commands. Running as the signed-in user is MeshCentral's
  user terminal, not jobs.
* **Interactive sessions stay MeshCentral's terminal**, as the owner
  decided, audited when each session starts; what is typed is not
  recorded, which the owner accepts. The console names its four
  terminals, shows where PowerShell 7 is, and records which terminal was
  opened.
* **Targets** can be chosen by organization, site or device group,
  resolved when the job is created; targets resolved each time a job
  runs wait for the plan's scheduler.

### PowerShell 7 on the computer
*Decided in review.*

* **Where the agent looks, on Windows**: in Program Files and Program
  Files (x86), taken from Windows' known folders, never from environment
  variables, for `PowerShell\<name>\pwsh.exe`, where `<name>` is a major
  version (`7`, and later ones such as `8`) or a major version followed
  by `-preview`. These are the folders Microsoft's MSI uses, which
  `winget install Microsoft.PowerShell` installs by default (to be
  confirmed in slice 1).
* **Where it does not look**: the `PATH`, the user's folders, a Store
  install (an MSIX package installed for a user, run through an alias in
  that user's profile), a .NET global tool (in a user's profile) and a
  ZIP unpacked anywhere else. Each is installed for one person, or found
  through a place a non-administrator may be able to write; run as
  SYSTEM, a program planted there would make that person SYSTEM. They
  are not reported either; the console's text says which installs are
  found.
* **Who can change it.** Before reporting or running a `pwsh.exe`, the
  agent checks the file and each folder from `PowerShell` down to it
  with the test its state check uses (`trustedEntry`,
  `agent/host/system_windows.go`, from PR #61): a plain file with one
  link, or a plain folder, owned by SYSTEM, Administrators or
  TrustedInstaller, that no one else may change. Program Files as Windows
  sets it up passes. An install whose folder an installer opened to users
  is reported as *found, not used*, with that reason, and never run.
  A folder no one else may change keeps others from adding a library
  beside `pwsh.exe`; the files already in it keep the access lists the
  MSI gave them, which slice 1 checks on the runner.
* **What is read**:
  * the version from the file's version resource (its product version,
    with a prerelease label for previews), not by starting it;
  * the architecture from the file's PE header (x64, ARM64 or x86);
  * *preview* from the folder's name or the prerelease label;
  * for Windows PowerShell 5.1, the version from
    `HKLM\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine`
    (`PowerShellVersion`).

  Slice 1 checks on the CI runner that both agree with
  `$PSVersionTable.PSVersion` as each PowerShell prints it. If either
  does not, another source is chosen there and this section amended.
* **Which one a `pwsh` run uses**: a usable, stable install of version 7
  or later in the computer's own architecture (x64 on x64; ARM64 on
  ARM64, then x64, which ARM64 Windows emulates), the newest version
  first. Never a preview, never version 6 (out of support), never an x86
  build: a 32-bit PowerShell on 64-bit Windows reads the 32-bit view of
  the registry and is sent to `SysWOW64` for `System32`, so a script
  would behave differently from the same script in Windows PowerShell
  5.1, which the agent runs 64-bit. Those installs are reported, marked
  as not used, with the reason.
* **When**: with the inventory (at the agent's start, every hour and
  after every job, as now), and again at the start of every `pwsh` run,
  so a run uses what is on the computer at that moment and never an
  hour-old list.
* **Reported in the inventory, not the heartbeat.** PowerShell installs
  change a few times a year; ADR-0018 keeps such facts in the hashed
  inventory, uploaded only when they change, while the heartbeat's facts
  are written to the device's row every minute. The plan's F1 says the
  same of the facts it adds. The inventory gains `powerShell`: at most 16
  entries, each with the edition (`Desktop` for Windows PowerShell,
  `Core` for PowerShell 7, as `$PSVersionTable.PSEdition` names them),
  version, architecture, path, *preview*, and *usable* or the reason it
  is not. The server's `cleanInventory` keeps it, bounded, in the same
  release. The field follows ADR-0009's rule for new request fields.
* **Every state is explicit** on the device's page: *installed* with
  version and path; *not found*; *found, not used* with the reason;
  *could not be read* with the error; and *not reported* for an agent too
  old to report.

### Choosing the PowerShell a script runs in
*Decided in review.*

* **Two shells.** `powershell` stays Windows PowerShell 5.1, unchanged,
  so no existing script changes. `pwsh` is new: "PowerShell 7", meaning
  the install chosen above. The console names them *Windows PowerShell
  5.1* and *PowerShell 7*. The shells' `CHECK` constraints on scripts and
  jobs gain `pwsh`. EasyRMM's own software and hardening scripts keep
  `powershell`.
* **Where PowerShell 7 is missing**, a `pwsh` script says what happens,
  a setting of the script, copied into each job:
  * **Fail the run** (the default): "PowerShell 7 is not installed on
    this device (looked in …). The script was not run." The run's status
    is `failed`, without an exit code.
  * **Use Windows PowerShell 5.1**: the agent runs the script in Windows
    PowerShell 5.1 and records that it did.

  This differs from the plan, which said a `pwsh` job never runs under
  5.1. Running a script written for 7 in 5.1 without being asked is
  wrong: syntax 5.1 lacks (`??`, `?.`, the ternary operator, `&&`)
  stops it before it starts, but cmdlets that behave differently (the
  default encoding of `Out-File` and `Set-Content`, `ConvertFrom-Json`,
  web requests) can change what it does without an error. So the default
  is the plan's, and the fallback is something the script's author turns
  on, for scripts written to run in both. The technician who runs a
  library script sees the setting and cannot change it; it is part of
  the reviewed script.
* **The server does not refuse a job because an inventory says
  PowerShell 7 is missing.** The inventory can be an hour old, and the
  agent decides at the run's start. The run dialog warns instead: "3 of
  40 devices reported no PowerShell 7 at their last inventory; this
  script fails there", or "runs in Windows PowerShell 5.1 there". The
  server does refuse devices whose agent cannot run `pwsh` jobs at all
  (*Older agents*, below), as it refuses a device of the wrong platform.
* **How it runs** is as today for `powershell`: `pwsh.exe -NoLogo
  -NoProfile -NonInteractive -ExecutionPolicy Bypass -File script.ps1`
  and the arguments, the script saved as UTF-8 with a byte order mark
  (which PowerShell 7 reads too), the same folder, job object and
  environment, the same rule for output in the console code page. Exit
  codes follow the same rules: `exit N` sets it, an uncaught error gives
  1. Two variables are added for `pwsh` runs:
  `POWERSHELL_TELEMETRY_OPTOUT=1`, since PowerShell 7 otherwise sends
  usage data to Microsoft when it starts, on the customer's computer;
  and `POWERSHELL_UPDATECHECK=Off`.
* **Group Policy can still stop it.** `-ExecutionPolicy Bypass` sets the
  process's policy, which a machine or user policy set by Group Policy
  overrides. PowerShell 7 has a policy setting of its own and may follow
  Windows PowerShell's, so a computer can block one edition and not the
  other. `AllSigned` and Constrained Language Mode stop jobs in either
  edition, as ADR-0054 notes for 5.1; the run fails with PowerShell's
  own error in standard error. An EDR or AMSI may block a script too.
  The guide says so.

### The version used, on every run
*Decided in review.*

* **The agent reports what it started.** The result gains `interpreter`:
  the edition, version, architecture and path of the program, and
  whether the script fell back to Windows PowerShell 5.1. The version is
  read from that file just before it is started (for Windows PowerShell,
  from the registry, as above). `cmd` and the Linux shells report the
  path only. The journal keeps it with the result, so a result reported
  after a restart still has it.
* **Not from inside the script.** Printing `$PSVersionTable` would need a
  wrapper around every script, and ADR-0060 already dropped one in
  review: it changes how `-File` binds arguments and sets exit codes, and
  Constrained Language Mode refuses it.
* **Kept on the run**, in columns of their own, checked for length like
  the others, written with the result.
* **Shown** on the run's page ("PowerShell 7.6.10, 64-bit", with the
  path; or "Windows PowerShell 5.1.26100: PowerShell 7 was not found, and
  this script allows Windows PowerShell"), as a column of the job's runs,
  in the results CSV and in every download. A run from an agent that
  reports nothing says "Not reported by this agent's version", never a
  guess.
* **Who sees it**: everyone with `job.view`, Read-Only included. It is
  EasyRMM's own fact about the computer, not output.

### Older agents and the poll
*Decided in review.*

* **The poll says what the agent takes.** `PollRequest` gains `accepts`,
  a list of job capabilities: `job.pwsh` (slice 1: the `pwsh` shell,
  `pwshFallback` in the payload, `interpreter` in the result) and
  `job.live` (slice 2: live output). The poll is signed by the process
  that will run what it receives, so the claim decides on what that
  build takes, at that moment, with nothing to go stale.
* **The claim** delivers a `pwsh` run only in answer to a poll whose
  `accepts` lists `job.pwsh`; otherwise the run stays queued, and the
  device's other runs are delivered as now. Under ADR-0009 a
  process sends no field added after level 2 before its first heartbeat
  answer, so its first poll may carry no list; its next poll, within 25
  seconds, does.
* **The device keeps the last list it reported** (on its row, written
  only when the list changes). Creating a `pwsh` job refuses a device
  whose list lacks `job.pwsh`: "PC-12's agent cannot run PowerShell 7
  scripts; update the agent." A run left queued because the device's
  polls stopped listing it (an agent rolled back after a crash,
  ADR-0027) says so on its page, and expires with that reason.
* **Not ADR-0058's `capabilities`.** ADR-0058 (proposed) puts the signed
  messages an agent takes in its heartbeat, for instructions the
  heartbeat answer carries, bound to the build that last reported. Jobs
  go out in the poll, so the poll says what the poll's sender takes.
  When ADR-0058 is built, its report may list the same names for the
  console; the claim keeps reading the poll's.
* **During a rolling upgrade** of several server instances sharing a
  database, an older instance knows nothing of `accepts` and may deliver
  a `pwsh` run to an agent that refuses it; the run fails with the
  agent's reason ("the job is malformed. It was not run.") and nothing
  runs.

### One-off commands
*Decided in review.*

* **Allowed, under a permission of their own: `script.run_oneoff`**,
  "run a command or script that is not in the library". It is checked at
  each device's site, as `script.run` is. A one-off is any text a person
  types in the console's *Run a command* dialog, one line or a whole
  script, up to 64 KiB of UTF-8 without NUL, in any shell the library
  offers. It takes no arguments: the person types the command whole.
* **Held by Technicians and above**: Technician, Site Administrator,
  Organization Administrator and Super Administrator; not Read-Only. The
  same roles hold `device.terminal`, which opens a SYSTEM shell on any
  online computer of their sites. Withholding one-off commands from
  Technicians would leave them the terminal, which records what was
  typed nowhere, for the same work.
* **Step-up for every one-off job**, as ADR-0055 defines it: a second
  factor confirmed within the last 5 minutes, on the session that asks.
  A technician working through a problem confirms once and runs several
  commands. An account without a second factor cannot run one-off
  commands. Library scripts do not need step-up.
* **Why step-up here and not on the terminal.** Someone holding a stolen
  session can already open a terminal, on one computer at a time. A
  one-off job runs unreviewed code on up to 500 computers with one
  request. Step-up closes that path; the terminal's is unchanged
  (*What this does not fix*).
* **The confirmation names the scale**: "Run this command as Local System
  on 312 devices in 3 sites? It is not from the library." The limits are
  a job's: 500 devices, 1 second to 4 hours (default 5 minutes). The wait
  for an offline device defaults to 1 hour, not 24: a command typed now
  that runs tomorrow surprises everyone. It can be set up to 7 days.
* **What is recorded.**
  * The job keeps the text, as it keeps a library script's snapshot, with
    its SHA-256 and size, for `EASYRMM_JOB_RETENTION`, as ADR-0063 keeps
    arguments. Its kind is `command` (the jobs' `kind` constraint gains
    it), its name *One-off command*.
  * Each run is recorded as `device.command_run`, under the device's
    organization and site, with the shell, the text's SHA-256 and size,
    the timeout, the PowerShell 7 fallback, the job and run, and when the
    session stepped up. Never the text: the audit log outlives jobs, is
    forwarded (ADR-0023), and a typed command can hold a password.
* **Who reads the text.** A person typed it, so it is treated as ADR-0063
  treats arguments: it leaves every job response and list; the job
  carries its size, SHA-256 and `canViewCommand`; it is read through
  `GET /api/v1/jobs/{id}/command`, which answers as ADR-0063's arguments
  endpoint does (`404`; `403` recorded as denied; `200` recorded as
  `job.command_view`, once per organization of the job's runs the caller
  holds `job.view_sensitive` for). Read-Only sees "One-off command,
  PowerShell 7, 412 bytes" and the SHA-256, never the text.
* **Signing does not change.** A one-off job is signed with the job key
  like any job, and the agent cannot tell it from a library script; it
  does not need to. More now depends on the job key, which ADR-0057
  (proposed) makes rotatable.
* **Reuse.** *Run again* on a one-off job reads the text through the
  audited endpoint and asks for step-up again if it has lapsed. *Save to
  library* is offered to holders of `script.manage` at a level that
  covers the job's devices; it opens the script form filled in, and saving
  is audited as any script is. Technicians do not hold `script.manage`,
  so the library stays reviewed (Owner questions).
* **No switch per organization now.** A switch that turned off one-off
  commands and left the terminal on would move the same work to the
  channel with no record. A switch for both needs settings per
  organization kept on the server, which ADR-0058's catalogue (proposed)
  would provide (Owner questions).

### What changes in ADR-0017
*Decided in review.*

ADR-0017 made the library the only source of code so that `script.run`
"lets a technician run reviewed code without letting them write it",
with terminals as a separate permission. Weighed here:

* **What stays**: `script.run` still runs only library scripts. Nothing a
  role held changes meaning, and the separation ADR-0017 drew stays in
  the permissions, ready for custom roles if they come.
* **What changes**: a second, stronger permission runs unreviewed code.
  In today's roles it adds no power: every role that would hold it holds
  `device.terminal`. What it adds is a record of exactly what ran, its
  output kept and downloadable, and running it on many devices at once.
* **What it costs**: unreviewed code on up to 500 devices in one request,
  which step-up, the confirmation and the audit record answer; and
  secrets typed into commands, which the text's treatment answers inside
  EasyRMM. On the computer, the text is in its PowerShell logs once
  script block logging is on (ADR-0060, or the customer's own policy).

ADR-0017's line becomes: "Library scripts run with `script.run`.
One-off commands run with `script.run_oneoff` and step-up, recorded with
their text and its SHA-256 (ADR-0064)." Its shells gain `pwsh`, and its
"Execution on the agent" gains live output and the program recorded.

### Elevation
*Decided in review.*

* **Jobs keep running as LocalSystem on Windows and root on Linux.**
  "Elevated execution with appropriate authorization" is met by what
  authorizes a run: `script.run` or `script.run_oneoff` at each device's
  site, step-up for one-off commands, signed jobs the agent checks, and a
  record of every run.
* **What SYSTEM can do**, said plainly in the guide and on the one-off
  dialog:
  * everything an administrator can, without UAC's prompt: install and
    remove software and drivers, change any setting, start and stop any
    service, turn off protections that are not tamper-protected;
  * read every user's files and every secret the computer holds for
    itself: the SAM and LSA secrets, the machine's DPAPI keys, BitLocker
    recovery passwords, saved Wi-Fi and service passwords; and, without
    Credential Guard or LSA protection, the credentials of people
    signed in;
  * act on the network as the computer's domain account;
  * on a domain controller, control the whole Active Directory domain.

  So `script.run` at a site with a domain controller is, in effect, a
  domain administrator's power. Root on Linux is the same.
* **Running as the signed-in user is not offered for jobs now.** It is a
  common request (per-user registry, mapped drives, a user's own
  programs), and Windows makes it possible (the agent can take the
  console session's token and start the process with it). It is left out
  because:
  * which user is guesswork: servers usually have nobody signed in,
    Remote Desktop hosts have many, a job queued for 24 hours runs as
    whoever is signed in when it is delivered, or fails;
  * its result is that user's: they can attach to, change or end a
    process running as themselves, so its output and exit code are only
    as trustworthy as they are;
  * the script, its arguments and its folder must be readable by that
    user, unlike today's folder, which only SYSTEM and Administrators can
    reach;
  * interactive work as the user already exists: MeshCentral's *User
    Shell* and *User PowerShell*, which the gateway allows under
    `device.terminal`.

  If wanted, it is an ADR of its own (Owner questions).
* **No lower-privileged account** (such as Local Service) for read-only
  scripts: what such a script could read is too little to be worth a
  second way to run.

### Live output
*Decided in review.*

* **Only for runs someone is watching.** Streaming every run would write
  to the database for runs nobody looks at: a job on 500 devices, each
  sending every 2 seconds, is 250 writes a second, of up to 64 KiB each,
  for its whole length. So output is sent while a run's page is open,
  and only then.
* **Starting a watch.** A run's page, opened by someone who holds
  `job.view_sensitive` at the run's site while the run is open, calls
  `POST /api/v1/job-runs/{id}/watch`. That is a read of output, so it is
  recorded as ADR-0063's `job_run.output_view`, with `live: true`, in the
  same transaction that starts the watch; if the record cannot be
  written, no watch starts. One record per watch, not per refresh. A
  session watches at most four runs at once.
* **Telling the agent.** A poll answers at once when one of the device's
  runs gains its first watcher, as it does for a new run or a
  cancellation, and every answer lists the watched runs (`watch`, with 60
  seconds to keep sending). Answers renew it while the page stays open
  (the poll is held 25 seconds at most). This is an answer, not a signed
  instruction: an older agent ignores it, and a forged one only makes the
  agent send output to its own server. On one server instance the agent
  hears within a second; across several, within one poll (25 seconds)
  until ADR-0059's wakes, which would carry it like any wake. Nothing
  goes over ADR-0059's channel itself, which is wake-only and carries no
  work.
* **Sending.** While a run is watched, the agent posts what is new every
  2 seconds to `POST /api/agent/v1/jobs/output`, a signed request like
  every other: for each watched run, each stream's new text from where
  it last sent, at most 32 KiB per stream per post; the first post sends
  the latest 32 KiB. All watched runs of the device go in one post, so
  at most four runs and 256 KiB of text per post, within the 1 MiB
  limit. Text is decoded as the final output is, whole characters only.
* **Never queued, never blocking.** If more than 32 KiB arrived since the
  last post, or a post failed or was refused, the next post sends the
  newest text and says how many bytes it skipped. The script never waits
  for the network: the capture keeps accepting output as it does now. A
  per-device limit of one post every 2 seconds (bursts of 3) is added
  beside the existing one; `429` makes the agent wait and skip ahead. An
  endpoint the server does not have (`404`) stops the sending for that
  server, as ADR-0009 says.
* **Kept on the server as a tail.** Posts go to an **unlogged** table of
  their own, one row per watched open run, with the organization and site
  for row-level security: the last 64 KiB of each stream, the total sent
  and skipped, and when it last changed. Unlogged means no transaction
  log for it, so live output costs no WAL and is not replicated; after a
  database crash the table is empty and pages start their watch again.
  The row goes when the result arrives (in the result's transaction) or
  5 minutes after its watch ends. A backup taken while a row exists holds
  it (`pg_dump` includes unlogged tables' rows); it holds the same text
  the run's result keeps.
* **Load.** One write per watched run every 2 seconds at most, in a small
  table without a transaction log: 20 people each watching a run are
  about 10 small updates a second. Measured with `tools/agentsim` before
  slice 2 merges, with the numbers in the slice's pull request.
* **Reading it.** The page asks `GET /api/v1/job-runs/{id}/live` every 2
  seconds (as it already asks for the run), with what it has seen. It
  needs an open watch of the same session; the permission is checked on
  every request; the request renews the watch and records nothing more.
  When the run ends, the page asks ADR-0063's output endpoint for the
  kept output (the first and last 128 KiB of each stream), which replaces
  the tail: another read, another record.
* **The console.** Standard output and error apart, as now, each showing
  the latest 64 KiB with "1.2 MB written so far; showing the latest
  64 KiB" when there is more, and "No output received for 30 seconds"
  when the posts stop. Without `job.view_sensitive`: "Hidden: needs
  permission to see job output". For an agent that does not list
  `job.live`: "This device's agent sends output when the script ends;
  update the agent to see it while it runs." Live output covers every
  shell, not only PowerShell.

### Interactive sessions
*Decided by the owner (2026-11-21)*: interactive PowerShell sessions use
MeshCentral's terminal, audited when a session starts; what is typed is
not recorded, and the owner accepts that. In the owner's words: "for
powershell yes the Mesh one is fine." There is no second interactive
channel.

What the record holds, and what it does not:

| | Recorded by EasyRMM | Where |
|---|---|---|
| Who opened a terminal, on which device, when, from which address; or was refused for lack of `device.terminal` | Yes | `device.remote_session` with the kind `terminal` and the grant, as now |
| Which of the four terminals was opened (Local System or the signed-in user; command prompt or PowerShell) | Yes, new in slice 5 | `device.terminal_open`, below |
| What was typed | No | |
| What the terminal showed | No | |
| Which PowerShell, and which version, ran inside it | No | The terminal shows it; the device's page lists what is installed |

*The rest of this section was decided in review.*

* **PowerShell 7 there.** A technician opens *PowerShell* (MeshCentral's
  *Admin PowerShell*) and types `pwsh`, or its path. The terminal panel
  shows the device's PowerShell 7 installs from its inventory, each path
  with a *Copy* button, and says that the terminal starts Windows
  PowerShell and that `pwsh` may not be on the `PATH` of a service
  started before PowerShell 7 was installed. EasyRMM does not type into
  the terminal for the person.
* **The console names MeshCentral's four terminals**: *Command prompt*
  and *PowerShell* as Local System, *Shell* and *PowerShell* as the
  signed-in user (the latter two only where someone is signed in). The
  choice goes to EasyRMM's script for MeshCentral's page as `ps=1` or
  `user=1`, as `rdp=1` is passed for RDP (ADR-0026), and the script
  connects with that protocol instead of pressing *Connect*. Slice 5
  checks this against the pinned MeshCentral, as every change there
  checks first that what it changes is there.
* **Recorded**: the start of every session (`device.remote_session`, as
  now), and new, at the gateway, each terminal connection it admits, as
  `device.terminal_open` with which of the four it is, the device and the
  grant. The gateway is where the protocol is known for certain, whatever
  the console asked for.
* **Not recorded**: what is typed and what is shown, as the owner
  accepted. Said plainly in the console's terminal panel, the guide and
  the threat model. MeshCentral's own session recording
  (`sessionrecording`) stays off: it would write every secret shown to
  MeshCentral's disk, outside EasyRMM's permissions, audit, retention
  and backups.
* **No change to MeshCentral's rights.** `device.terminal` still grants
  all four terminals; MeshCentral has no right per type.

### Targets
*Decided in review.*

* **Chosen by organization, site or device group**, or devices one by
  one as now, in the run dialog, for library scripts and one-off
  commands. The API takes the selection and resolves it in the job's
  transaction into devices: those the caller can see, on the shell's
  platforms, with the agent. Devices left out for platform or agent are
  counted and named in the dialog before running ("312 devices: 300 will
  run it; 8 are Linux devices and 4 have no agent"). A device in the
  selection the caller cannot run on refuses the whole job, as today:
  nobody gets a partial run they did not ask for.
* **Fixed when the job is created.** The job keeps its devices, and the
  selection it came from for display ("Site *Main office*, Windows
  devices"). *Run again* resolves the same selection again and shows the
  new count before running.
* **At most 500 devices**, ADR-0017's bound: "This selection has 812
  devices; a job runs on at most 500. Choose a site or a group."
* **What waits for the plan's F3** (the scheduler, with feature 11):
  targets resolved every time a job runs, batches past 500 devices, and
  running as the owner of a schedule. The plan put every group target
  after F3; choosing a group when the job is created needs none of F3,
  and the same selection is what F3 will resolve again at each run.

### Downloads and results
*Decided in review.*

On ADR-0063's rule: output is read only through its audited endpoint,
under `job.view_sensitive`, and every read is recorded.

* **One stream**: `GET /api/v1/job-runs/{id}/output?download=stdout` or
  `=stderr`, as ADR-0063 names them: the text as kept, UTF-8 without a
  byte order mark, at most about 257 KiB, as `text/plain` with a file
  name made of the device's name and the run's.
* **One run**: `?download=json`: the device, organization and site, the
  job, the script's name and SHA-256 (or *One-off command* and its
  SHA-256), the shell, the program recorded, the status, exit code,
  error, times, both streams and whether each was cut. At most about
  600 KiB.
* Each is recorded as ADR-0063's `job_run.output_view`, with what was
  downloaded.
* **A whole job**: `GET /api/v1/jobs/{id}/output.zip`. For each finished
  run the caller holds `job.view_sensitive` for, a folder with
  `stdout.txt`, `stderr.txt` and `result.json` (as above); and
  `runs.csv`, one row per run the caller sees, saying whether its output
  is included or why not (hidden, removed, still running).
  * At most 500 runs of about 514 KiB of text: about 257 MiB before
    compression, written as it is read, run by run, so the server holds
    one run at a time.
  * Recorded as `job.output_download`, one record per site of the runs
    included, under that organization and site, with the job, the number
    of runs and the bytes. The records are written, in their own
    transaction, before the first byte is sent; if they cannot be,
    nothing is sent. A download that then breaks off is still recorded:
    recording a read that may have happened is the safe side.
  * Names in the archive are made of letters, digits, `-`, `_` and `.`,
    never absolute and never `..`.
* **The job's results without output**: `GET /api/v1/jobs/{id}/runs.csv`,
  under `job.view`, Read-Only included: one row per run the caller sees,
  with the device, organization, site, status, exit code, error, program
  and version, and the times. It carries no output, so it follows the
  reports' rules (ADR-0029): recorded as `job.results_export`, cells that
  a spreadsheet would read as formulas neutralized as `reports/csv.go`
  does.
* **The console**: *Download* beside *Copy* on each stream, *Download
  run* on the run's page, *Download output (ZIP)* and *Download results
  (CSV)* on the job's page; each shown only where it can work.

### Disconnected devices and long runs
*Decided in review.*

What exists stays: a run waits 1 hour to 7 days for an offline device,
is delivered again if not started within two minutes, never runs twice
(the start check and the journal), reports a result whenever the device
is back (a late result replaces `lost`), and stops at its timeout (1
second to 4 hours) with everything it started. What this ADR changes:

* **A device that loses its network during a run** finishes the script;
  live output stops, the page says no output has arrived for a while,
  and the result arrives when the device is back.
* **The 4-hour limit stays.** A run holds one of the agent's four slots
  for its length, and its deadline decides when it counts as lost. Longer
  work belongs in a scheduled task (feature 11) or in steps.
* **One-off commands wait 1 hour by default** (above).
* **PowerShell 7 missing at the run's start** fails at once with the
  reason, or falls back, as the script says.
* **A run waiting behind four others** stays *Delivered, waiting to
  start*, as now. Whether quick work gets a reserved slot is decided for
  every kind by feature 7's ADR (the plan's F2), not here.

### Not chosen
*Decided in review.*

* **Falling back to Windows PowerShell 5.1 without being asked**: a
  script for 7 can do something else in 5.1 without an error.
* **Looking for `pwsh` on the `PATH` or in users' folders**: a
  non-administrator could put a program there that SYSTEM then runs.
* **Starting `pwsh` to read its version** every hour: a process per
  install per hour on every computer, in every EDR's log, for what the
  file's version resource says.
* **PowerShell remoting (WinRM) from the server**: an inbound connection
  to every computer and credentials for it, which the agent's design
  avoids.
* **One-off commands run with `-Command`** instead of a script file:
  `-Command` is not subject to the execution policy, so it would step
  around an `AllSigned` an administrator set on purpose, and it binds
  arguments and sets exit codes differently.
* **One-off commands under `device.terminal`**: one device at a time and
  500 at once are different powers, and custom roles may want them
  apart.
* **One-off commands without step-up**: a stolen session would run code
  on 500 computers with one request.
* **Streaming every run**, or keeping live output in `job_runs`: writes
  and transaction log for output nobody watches.
* **Live output over ADR-0059's WebSocket**: it is wake-only by decision,
  and carrying work over it would need an ADR of its own (ADR-0059,
  "Full delivery: not now").
* **Running jobs as the signed-in user now**: above.

A second interactive channel and a record of what is typed in the
terminal were not options here: the owner decided both (Interactive
sessions).

### What this does not fix
*Decided in review.*

* **SYSTEM is SYSTEM.** Whoever may run scripts or open a terminal at a
  site can do anything on its computers and read any secret on them.
  This ADR records what was run; it cannot limit what the code does.
* **The terminal** records who opened which terminal on which computer,
  not what was typed or shown, and asks for no step-up. Someone holding a
  stolen session can still open a terminal, one computer at a time.
* **Secrets typed into one-off commands** are kept with the job for the
  job retention and in backups, readable by holders of
  `job.view_sensitive` with a record, and on the computer in its
  PowerShell logs once script block logging is on.
* **The computer's own environment.** Jobs get the system's `PATH` and
  `PSModulePath`, as today. A folder in them that users can write lets
  them plant a command or module that any SYSTEM process may load: a
  hole on that computer, not one this ADR adds.
* **Group Policy, Constrained Language Mode, EDRs and AMSI** can stop a
  script in either edition.
* **Live output is a tail**, and what is between the head and tail of a
  long run's output is not kept anywhere, as now.

## The requirements
Feature 6 of the owner's requirements, bullet by bullet.

| Requirement | Where | Status after this ADR |
|---|---|---|
| Execute individual PowerShell commands remotely | One-off commands (slice 3); the terminal | New, behind a permission and step-up |
| Execute multi-line PowerShell scripts | ADR-0017's library; one-off commands may be many lines | Exists |
| Interactive PowerShell sessions where feasible | Interactive sessions (the owner's decision; slice 5) | MeshCentral's terminal, as now; slice 5 names the four terminals and records which was opened |
| Elevated execution with appropriate authorization | Elevation | SYSTEM, per-site permissions, step-up for one-offs |
| Output in real time where supported | Live output (slice 2) | Runs being watched, agents listing `job.live` |
| Standard output and error separately | ADR-0017; live output and downloads keep them apart | Exists |
| Process exit codes | ADR-0017; downloads and results CSV carry them | Exists |
| Execution timeouts | ADR-0017 (1 second to 4 hours); Disconnected devices and long runs | Exists |
| Save reusable scripts | ADR-0017's library; *Save to library* (slice 3) | Library writers are Site Administrators and above (Owner questions) |
| Command and script execution history | Jobs and runs (ADR-0017); one-offs in the same lists | Exists; one-offs added |
| Timestamps and the technician responsible | Jobs, runs and audit records | Exists; `device.command_run` added |
| Individual devices or selected groups | Targets (slice 4) | Organization, site or group when created; at each run waits for F3 |
| Results and status reporting | Results CSV, run columns (slice 1) | Per job; no report across jobs (ADR-0063's export rule applies to one later) |
| Download command output | Downloads and results (slice 1) | New |
| Windows PowerShell and PowerShell 7 where installed | PowerShell 7 on the computer; Choosing (slice 1) | New |
| Identify the PowerShell version being used | The version used, on every run (slice 1) | New |
| Appropriate execution privileges | Elevation | SYSTEM only; signed-in user deferred (Owner questions) |
| Prevent unauthorized execution | Permissions at each site, signed jobs, step-up | Exists; extended |
| All remote command execution auditable | `device.script_run`, `device.command_run`, `device.remote_session`, `device.terminal_open` | Every run, with its script's or command's SHA-256; terminals at the session's start, not what is typed (accepted by the owner) |
| Sensitive output not exposed | ADR-0063; downloads, live output and one-off text follow it | With ADR-0063 |
| Long-running commands and disconnected devices | Disconnected devices and long runs | Exists; one-off default wait 1 hour |

PowerShell on Linux is not asked for ("managed Windows devices") and is
slice 6, last, and can be dropped without changing the rest.

## Slices
Each merges and is verified on its own, at every level it touches. The
plan's order puts slice 1 right after ADR-0063 (F0).

1. **PowerShell 7, the version used, and downloads.** The smallest that
   is worth shipping alone: technicians run their scripts in the
   PowerShell they write for, see which one ran, and take the output
   away. Two pull requests: downloads and the results CSV first (server
   and console only, on ADR-0063's endpoint), then PowerShell 7 (agent,
   protocol, migration, console).

   *Verified*: integration tests; the Windows runner (discovery, both
   editions, versions against `$PSVersionTable`, exit codes, fallback, the
   x86 build reported and not used, an untrusted folder refused); the
   end-to-end test; an agent of the previous release still running every
   job it ran before.
2. **Live output.** Second, because it needs nothing that is not built,
   and it is the riskiest for load, so it is measured before anything
   else depends on it.

   *Verified*: integration tests with the agent's requests; the load
   measured with `tools/agentsim`; the Windows runner and Linux tests of
   the agent's sending and skipping; the end-to-end test.
3. **One-off commands.** Third, because they need step-up, which
   ADR-0055 builds in its slice 5b2, step 15 of the plan's order; this
   keeps the plan's order of live output, then one-off commands. Putting
   one-off commands second was weighed: they are the bullet the
   requirement lists first, but without step-up they would run unreviewed
   code on 500 computers from a stolen session. If the owner wants them
   sooner, step-up is built ahead of 5b2 as ADR-0055 defines it, ADR-0055
   says so, and slices 2 and 3 change places with nothing else changing
   (Owner questions).

   *Verified*: integration tests of the permission, step-up and the
   text's endpoint for every role; the end-to-end test.
4. **Targets by organization, site and group.** Independent of 2 and 3;
   may be built beside them.
5. **The terminal**: the four terminals named, the PowerShell 7 paths
   shown, `device.terminal_open` recorded.

   *Verified*: the gateway's integration test with a live terminal
   through the relay (as today) records the protocol; the script for
   MeshCentral's page against the pinned image; on a real Windows
   computer, *PowerShell* opening Admin PowerShell and `pwsh` started in
   it. Until that real computer, it is marked unverified.
6. **PowerShell 7 on Linux**, if still wanted: `pwsh` from Microsoft's
   packages in `/opt/microsoft/powershell/<major>/`, checked as root's
   (owned by root, changeable by no one else), the version from the
   package that installed it, which the inventory already reads; the
   fallback does not apply, so a Linux device without it fails the run
   with the reason; the shell's platforms gain Linux.

## Consequences
* Technicians can choose PowerShell 7 per script, see which PowerShell
  and version ran on every run, and download output.
* Scripts' and jobs' shell lists gain `pwsh`; the inventory gains
  `powerShell`; the poll gains `accepts`; the result gains
  `interpreter`; runs gain columns for it; devices keep the last
  `accepts`.
* An agent of the release before keeps running everything it ran; it
  gets no `pwsh` job and sends no live output; the console says to
  update it.
* ADR-0017's library-only rule gains an exception behind
  `script.run_oneoff` and step-up. One-off commands depend on step-up
  being built.
* The audit log gains `device.command_run`, `job.command_view`,
  `job.output_download`, `job.results_export` and
  `device.terminal_open`, and ADR-0063's `job_run.output_view` says when
  a read was a download or a live watch.
* The database gains one unlogged table, for watched runs only.
* Interactive work stays in MeshCentral's terminal, as the owner
  decided; its record says who opened which terminal where, never what
  was typed, and it asks for no step-up. The guide and the threat model
  say so.
* Windows paths that the CI runner cannot show stay marked unverified
  until the Windows machines of ADR-0054's W1, or real computers, show
  them: a computer without PowerShell 7, ARM64, `AllSigned` from Group
  Policy, Constrained Language Mode, Windows client editions.

## Testing
* **Integration tests** in Go against real PostgreSQL through `testdb`
  (`make test-db`), without mocks: the jobs service
  (`server/internal/jobs`), the agent API with signed requests
  (`server/internal/httpapi/agentapi`) and the console's API
  (`server/internal/app`, as `jobs_api_integration_test.go` is now).
  * **PowerShell 7**: scripts and jobs with `pwsh` and each fallback
    setting; the claim delivering a `pwsh` run only to a poll that
    accepts it, leaving it queued for one that does not, and the run's
    page saying why; creation refused for a device whose last list lacks
    `job.pwsh`; the device's list written only when it changes; a result
    with `interpreter` kept and shown to Read-Only; one without it
    shown as not reported; the inventory's `powerShell` cleaned and
    bounded.
  * **Downloads**, on ADR-0063's tests: every role on each download;
    a random marker in output appearing only in downloads to holders;
    one record per download, one per site for the ZIP, written before
    the first byte, and with appends made to fail, nothing sent; the ZIP
    opened and its names checked; the results CSV for Read-Only, its
    formula cells neutralized, its record.
  * **Live output**: a watch needing `job.view_sensitive` and an open
    run, its one record, at most four per session; a poll answering at
    once when a watch starts and listing it after; posts kept as a 64 KiB
    tail, skips counted, the per-device limit refusing a fifth post in a
    burst; the row removed with the result; `/live` refused without the
    session's watch; the table emptied (as after a crash) and the page's
    watch started again.
  * **One-off commands**: every role, with and without step-up, stale
    step-up, and an account with no second factor; one
    `device.command_run` per run with the SHA-256 and no text; the
    marker in the text appearing only in `/command` to holders; the job
    of kind `command` in lists without the text; *Run again* asking for
    step-up after it lapses.
  * **Targets**: an organization, a site and a group resolved under
    row-level security; devices left out by platform and agent counted;
    the whole job refused for a device the caller cannot run on; over 500
    refused.
  * **The terminal**: the existing live terminal test through the relay
    records `device.terminal_open` with the protocol, for each of 1, 6, 8
    and 9.
* **Agent tests** in Go on every platform: the payload's new shell and
  field refused by the strict decoder of the release before and accepted
  now; `accepts` sent only after a level-2 answer; the capture handing
  out new text with skips; whole characters at chunk ends; the journal
  keeping `interpreter` across a restart.
* **Agent tests on CI's Windows runner** (`windows-latest`, as an
  administrator, with Windows PowerShell 5.1 and PowerShell 7):
  * discovery finds the runner's PowerShell 7, and its version and
    architecture match what `pwsh` itself prints; Windows PowerShell's
    version matches `powershell.exe`'s `$PSVersionTable`;
  * Microsoft's x86 ZIP of the same version, pinned by SHA-256 and
    unpacked into Program Files (x86), is reported and never chosen;
  * a copy in a folder the test opens to Users is reported as not used
    and never run, and a `pwsh.exe` a standard user places on the `PATH`
    is never found;
  * with the folders the agent searches pointed at an empty test folder
    (a test hook, since the runner's own PowerShell 7 cannot be removed
    while the step runs in it), a `pwsh` run fails with the reason, or
    falls back and records Windows PowerShell;
  * `pwsh` jobs with arguments give the same exit codes as `powershell`
    jobs (`exit N`, a failing native command, a thrown error), non-ASCII
    output in both editions, the telemetry variable in the run's
    environment, and stopping a run stopping everything it started; with
    ADR-0060's slice 0, the job object from the start as well;
  * live output sent and skipped from a real script that prints faster
    than 32 KiB in 2 seconds.

  GitHub also offers a Windows 11 ARM64 runner; if the repository can
  use it, the discovery tests run there too, otherwise ARM64 stays
  unverified.
* **Machine tests** (`internal/vmtest`): slice 6 on the harness's
  distributions, with Microsoft's package pinned by SHA-256 and without
  it. Windows machines come with ADR-0054's W1: then a Windows client
  and server without PowerShell 7, with it from the MSI, under `AllSigned`
  from Group Policy and under Constrained Language Mode.
* **Page tests** (`web/src/pages/jobs/jobs.test.tsx`,
  `web/src/pages/scripts/scripts.test.tsx`): the shells and the fallback
  setting; the program on the run's page, and "not reported"; the
  warning counts; downloads offered only where they work; the live view,
  its "showing the latest" and silence messages and the hidden state;
  the one-off dialog asking for step-up and naming the device count;
  the text hidden without the permission; target selection and its
  counts; the four terminals named.
* **The browser end-to-end test** (`make e2e`, `web/e2e/console.spec.ts`)
  against a real server, with the simulated agent (`web/e2e/agent.ts`)
  taught `accepts`, `powerShell`, `interpreter` and output posts: a
  technician runs a `pwsh` script and sees "PowerShell 7.6.10"; downloads
  the run as JSON and the job as a ZIP and the files hold the marker;
  watches a run and sees the agent's posted output before the result;
  steps up with the test's authenticator code and runs a one-off
  command; a Read-Only user sees the program and status but no output and
  no command text; the audit log shows each record.
* **Real computers**: the terminal's PowerShell entry and `pwsh` in it,
  and a `pwsh` job, on a real Windows computer of the owner's test
  instance, before the guide calls them verified.
* The coverage floors in `scripts/ci/check-coverage.sh` hold for the
  packages touched.

## Owner questions
1. **One-off commands and step-up.** One-off commands wait for step-up,
   built in ADR-0055's slice 5b2. Is that wait acceptable, or should
   step-up be built earlier so that one-off commands come second?
2. **Turning them off per organization.** Should an organization be able
   to turn off one-off commands, and the terminal with them, once
   settings per organization exist on the server?
3. **Running as the signed-in user.** Is running jobs as the person
   signed in to the computer wanted, as an ADR of its own, with the
   limits under Elevation?
4. **Saved commands for Technicians.** The library stays reviewed: only
   Site Administrators and above write it. Should Technicians keep
   personal saved commands, which would run as one-off commands?
5. **PowerShell 7 on Linux.** Keep slice 6, or drop it?
