# ADR-0064: Remote PowerShell management

* Status: Accepted (2026-11-21, after an independent review). Slice 1
  implemented (PRs #88, #90).
* One part is the owner's (2026-11-21): the owner chose MeshCentral's
  terminal with session-level audit, so typed input is not recorded
  ([Interactive sessions](#interactive-sessions)). Everything else
  marked as decided was decided in review.
* Amends: [ADR-0017](0017-scripts-and-jobs.md): a `pwsh` shell beside
  `powershell`; one-off commands beside the library; output while a run
  is open; targets chosen by organization, site or group; the program
  that ran recorded on each run. It has an *Amended by ADR-0064* line
  since slice 1.
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
  (`AllSigned` and Constrained Language Mode; the Windows test machines
  and runners), [ADR-0055](0055-lets-encrypt-in-one-step.md#step-up-authentication)
  (step-up authentication), [ADR-0057](0057-rotating-the-job-key.md)
  (the job key ring), [ADR-0058](0058-signed-settings-that-reach-the-agent.md)
  (capabilities), [ADR-0059](0059-the-agents-websocket-channel.md)
  (wakes) and [ADR-0060](0060-collecting-logs.md) (its slice 0, and
  script block logging).
  [ADR-0063](0063-who-sees-job-output-and-arguments.md) (who sees a job's
  output and arguments) is accepted and built; this ADR builds on its
  permission, endpoints and output retention.
* Requirements: feature 6, "Remote PowerShell Management", of the
  owner's requirements of 2026-11-21. Every bullet is placed in
  [The requirements](#the-requirements). The
  [plan for the twelve MSP features](../feature-plan-msp.md) lists this
  as feature 6. This ADR differs from it in four places, each
  argued where it is decided: a `pwsh` script may fall back to Windows
  PowerShell 5.1 when its author allows it; Store installs are seen and
  reported, not invisible; the version is read from the program's file,
  not from `$PSVersionTable`; and a one-off command's SHA-256 is kept
  only beside its text, never in the audit record.

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
* **A job is written once.** Its row holds the script's snapshot
  (`body`) and its SHA-256; `easyrmm_app` may insert and delete jobs but
  not update them (migration `00004`). Every job response carries the
  SHA-256 (`Job.SHA256`, `jobColumns` in `jobs.go`); `GET
  /api/v1/jobs/{id}` (`GetJob`) adds the body, and `GET
  /api/v1/job-runs/{id}` (`GetRun`) nests the job with its body. The
  console shows them as *Script as run* and *SHA-256*
  (`web/src/pages/jobs/JobDetailPage.tsx`).
* **Who runs what.** Technicians hold `script.run`, `job.manage` and
  `device.terminal`; Read-Only holds the view permissions only
  (`server/internal/rbac/rbac.go`). Roles are fixed in code; there are no
  custom roles. A person may hold different roles at different sites.
* **Targets.** Up to 500 devices, chosen one by one in the console's
  device picker (a text filter and *select all*); the API takes device
  IDs only (`JobInput.DeviceIDs`). `targets` in `jobs.go` refuses the
  whole job, naming the devices, when one is at a site where the caller
  cannot run scripts, outside the script's level (an organization's
  script runs only in that organization, a site's only in that site),
  without an agent, or of another platform. A device has at most one
  device group, inside its site.
* **Delivery.** A signed long poll (`PollRequest` is an empty object; the
  agent's `Poll` sends `{}`, `agent/client/client.go`), redelivery after
  two minutes, a start check so that a late redelivery never runs, the
  first result wins, a sweeper every 30 seconds. A run waits 1 hour to 7
  days for an offline device; a started run that does not report by its
  deadline (start + timeout + 5 minutes) becomes `lost`, and a late
  result replaces `lost` (`server/internal/jobs/delivery.go`,
  `service.go`).
* **The payload is strict on the agent.** `DecodeJob` refuses unknown
  fields, `VerifyJob` refuses a shell it does not know and any payload
  version but 1 (`internal/agentproto/jobs.go`). ADR-0009 requires that
  the server send a new instruction, or a new field in one, only to a
  build that reported understanding it, and that an agent send a request
  field added after level 2 only while its last heartbeat answer came
  from a server of level 2 or higher. The heartbeat answer carries the
  level (`HeartbeatResponse.Protocol`); nothing in the agent reads it
  yet. The server reads agent requests leniently (`decode` in
  `server/internal/httpapi/agentapi/agentapi.go`).
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
  of each stream, and counts every byte written (`total`); writing never
  blocks the script (`agent/jobs/capture.go`). On Windows, output that is
  not valid UTF-8 is decoded from the OEM code page (`decodeOutput`,
  `exec_windows.go`). The result, with the exit code, goes to the server
  when the script ends (`agent/jobs/exec.go`), and `Result` stores it
  for a run that is `sent`, `running` or `lost` (`delivery.go`). The run
  page says "The device sends the script's output when it ends"
  (`web/src/pages/jobs/RunDetailPage.tsx`).
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
  argument values (`create` in `jobs.go`). A record's details hold at
  most 16 KiB (`server/internal/audit/audit.go`).
* **Output and arguments are read by everyone with `job.view`**,
  Read-Only included, with no record. ADR-0063 (proposed) moves them
  behind `job.view_sensitive`, held by Technicians and above, through
  audited endpoints of their own: `GET /api/v1/job-runs/{id}/output` and
  `GET /api/v1/jobs/{id}/arguments`, a read and its record in one
  transaction. It keeps output for `EASYRMM_JOB_OUTPUT_RETENTION` (30
  days by default) and lets it be removed sooner with `DELETE
  /api/v1/job-runs/{id}/output`. It says downloads, when built, use the
  output endpoint with `?download=stdout` or `?download=stderr`.

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
* MeshAgent takes the terminal to open from the first message inside the
  tunnel that is not a JSON object (`parseInt` of it, in the image's
  `agents/meshcore.js`), whatever the relay's address says. The gateway
  lets a browser's relay through only for protocols 1, 6, 8 and 9 in its
  address (`p`), only on a device the session was granted a terminal on
  (`relayKinds`, `server/internal/remote/relayguard.go`), and then reads
  that first message and refuses the relay unless it is exactly `p`
  (`relayProtocolCheck`, `server/internal/remote/tunnels.go`, from
  ADR-0033). It records nothing about which of the four was opened.
* MeshAgent starts its PowerShell terminals through modules built into
  its binary (`win-virtual-terminal` or `win-terminal`,
  `StartPowerShell`, named in the image's `agents/meshcore.js`), and
  refuses protocols 6 and 9 where `PowerShellCapable` says no. Nothing in
  that file names `pwsh`; which PowerShell they start is not verified on
  a Windows computer.
* What is typed and shown is not recorded by EasyRMM. MeshCentral can
  record sessions itself (`sessionrecording` per domain and protocol, in
  the image's `meshrelay.js`); EasyRMM does not turn it on, and the
  gateway refuses MeshCentral's recordings pages (ADR-0014).
* MeshCentral's rights (`server/internal/meshcentral/rights.go`) turn the
  terminal on or off as a whole; there is no right per terminal type.

**What is missing for the requirement**: PowerShell 7; the version used;
real-time output; individual commands that are not in the library;
groups as targets; downloads; and who sees output, which is ADR-0063.

**PowerShell 7's packages** (Microsoft's guide *Install PowerShell 7 on
Windows*, as of 2026-09-21): the MSI installs into `Program Files\PowerShell\7`
(`7-preview` for previews); the ZIP can be unpacked anywhere, the guide
suggesting `Program Files\PowerShell\7`; the MSIX (the Microsoft Store's
package) is "installed for a single user"; a .NET global tool lives in
the user's profile. Since PowerShell 7.6.0, `winget install --id
Microsoft.PowerShell` installs the MSIX unless `--installer-type wix`
asks for the MSI, and PowerShell 7.7, stable since 2026-11-10, has no MSI
(*Store installs*, under Decision).

**Test harnesses.**

* CI's job *Agent tests on Windows* runs on `windows-latest`, as an
  administrator (`.github/workflows/backend-tests.yml`). On 2026-11-21
  that was Windows Server 2025 (10.0.26100), image `windows-2025-vs2026`
  version 20261116.315, whose list of included software names
  PowerShell 7.6.10 (runner-images release
  [`win25-vs2026/20261116.315`](https://github.com/actions/runner-images/releases/tag/win25-vs2026/20261116.315));
  Windows PowerShell 5.1 is part of Windows.
* GitHub's `windows-11-arm` runner (Windows 11 Enterprise on ARM64,
  10.0.26200), which ADR-0054 found available to this public repository,
  names PowerShell 7.4.13 in its image's list (image version
  20260105.41.1,
  [`images/arm-windows-11-image.md`](https://github.com/actions/partner-runner-images/blob/eda504029d027e897b2116218beefe06da55a16f/images/arm-windows-11-image.md)
  in `actions/partner-runner-images`).
* Neither image's list names winget. Microsoft's guide says winget is
  part of Windows 11 and of Windows Server 2025 with Desktop Experience.
* ADR-0054 runs its Windows tests as LocalSystem, as the agent's service
  runs, through a scheduled task.
* The machine harness (`internal/vmtest`) boots Linux distributions'
  cloud images under QEMU. It has no Windows image; ADR-0054's W1 decides
  how Windows machines are tested.
* The browser end-to-end test runs a real server with a simulated agent
  (`web/e2e/agent.ts`); `tools/agentsim` simulates many agents.

## Decision

### In short
* **PowerShell 7.** The agent finds machine-wide PowerShell 7
  installations in fixed folders only, checks the whole install and its
  module folders for anything others may change, reports them with
  Windows PowerShell 5.1 and any Store install in its inventory, and runs
  a new `pwsh` shell in the newest usable one, with a module path of
  checked folders only. A script says what happens where PowerShell 7 is
  missing: the run fails (the default), or it runs in Windows PowerShell
  5.1; never where an install is found but what it would load fails the
  check. Every run records the program, its edition, version and
  architecture, shown on the run and in every download.
* **Downloads.** One stream as text, one run as JSON, a whole job as a
  ZIP, through ADR-0063's audited output reads, one record per run; and
  the job's results as CSV without output.
* **Live output** for runs someone is watching, posted by the agent over
  its existing HTTPS every 2 seconds by stream position, kept as a
  bounded tail in an unlogged table and written only while the run is
  running, read under `job.view_sensitive` with one audit record per
  watch.
* **One-off commands** under a new permission, `script.run_oneoff`, held
  by the roles that hold `device.terminal`, with step-up authentication
  for every job. The text and its SHA-256 are kept apart from the job,
  for the output retention, and read together through an audited
  endpoint; no other answer and no audit record carries the hash.
* **SYSTEM stays the only way jobs run** (root on Linux). "Appropriate
  authorization" is the permission at each device's site, plus step-up
  for one-off commands. Running as the signed-in user is MeshCentral's
  user terminal, not jobs.
* **Interactive sessions stay MeshCentral's terminal**: the owner chose
  MeshCentral's terminal with session-level audit, so typed input is not
  recorded. The console names its four terminals, shows where
  PowerShell 7 is, and records which terminal was opened.
* **Targets** can be chosen by organization, site or device group,
  resolved when the job is created, leaving out and counting devices
  that cannot run the job; targets resolved each time a job runs wait
  for the plan's scheduler.

### PowerShell 7 on the computer
*Decided in review.*

* **Where the agent looks, on Windows**: in Program Files and Program
  Files (x86), taken from Windows' known folders, never from environment
  variables, for `PowerShell\<name>\pwsh.exe`, where `<name>` is a major
  version (`7`, and later ones such as `8`) or a major version followed
  by `-preview`. These are the MSI's folders, and the one Microsoft's
  guide suggests for the ZIP (Context).
* **Store installs are reported, not used.** A PowerShell installed from
  the Microsoft Store, or from its MSIX package, is in
  `Program Files\WindowsApps`, in a folder named for the package
  (`Microsoft.PowerShell_<version>_<architecture>__8wekyb3d8bbwe`,
  `Microsoft.PowerShell-LTS_…` for a long-term release's package, or
  `Microsoft.PowerShellPreview_…` for previews; the LTS name added in
  slice 1, as winget's MSIX for 7.6 is that package), owned by TrustedInstaller
  and closed to users. The agent lists those folders, reports each as
  *found, not used (Store install)* with its version, and never runs it:
  * Microsoft installs it for one user ("There is no option to install it
    for all users"), so it is that user's to remove, and the Store's to
    update;
  * its `$PSHOME` cannot be changed, so what an administrator sets there
    for every user of that PowerShell cannot be set, the `LocalMachine`
    execution policy among them (Microsoft's guide lists
    `Set-ExecutionPolicy -Scope LocalMachine` as unsupported there);
  * starting a package's program as SYSTEM, outside the user it is
    installed for, is not something Microsoft's guide describes, and it
    has not been tried.

  This weighs more with each release. *Amended in slice 1 (checked
  2026-11-22):* PowerShell 7.7 was released as stable on 2026-11-10, and
  it has no MSI. Its GitHub release, `v7.7.0`, published
  2026-11-10T20:18Z, offers for Windows only ZIPs (x64, ARM64, x86 and
  two framework-dependent ones) and an MSIX bundle,
  `PowerShell-7.7.0.msixbundle`, as its asset list read through GitHub's
  API on 2026-11-22 shows
  ([release `v7.7.0`](https://github.com/PowerShell/PowerShell/releases/tag/v7.7.0)).
  Microsoft announced it on 2026-04-10: "MSI isn't planned for future
  releases, including PowerShell 7.7 GA and beyond", adding that MSIX
  does not yet support "execution by system-level services (like Task
  Scheduler)" (PowerShell Team blog,
  [*PowerShell MSI package deprecation and preview updates*](https://devblogs.microsoft.com/powershell/powershell-msi-deprecation/)).
  `winget install --id Microsoft.PowerShell` installs the MSIX by default
  since 7.6.0. A computer that took PowerShell 7 from winget's default, or
  7.7 from its installer, reports a Store install, and `pwsh` scripts fail
  there, or fall back, until an MSI (7.6) or a ZIP is in Program Files;
  the console and the guide say so and give `winget install --id
  Microsoft.PowerShell --installer-type wix` for 7.6.

  On CI's runners, on 2026-11-22, the test as LocalSystem started the
  Store package's `pwsh.exe` (`Microsoft.PowerShell-LTS` 7.6.10, x64 on
  `windows-latest` and ARM64 on `windows-11-arm`) and it ran: it printed
  `7.6.10`, the computer's account as its user name and its
  `WindowsApps` folder as `$PSHOME`. That is recorded, not relied on:
  Store installs are still not run. Whether they should be is being
  re-reviewed separately, with this result and Microsoft's statement
  above; an amendment of this ADR follows this pull request.
* **Where it does not look**: the `PATH`, the user's folders, a .NET
  global tool (in a user's profile) and a ZIP unpacked anywhere but the
  folders above. Each is a place a non-administrator may be able to
  write, or is found through one; run as SYSTEM, a program planted there
  would make that person SYSTEM. They are not reported either; the
  console's text says which installs are found.
* **Who can change it: the whole install.** Before reporting an install
  as usable, and again before each run, the agent checks `Program
  Files`, `Program Files\PowerShell`, the install's folder and every file
  and folder in it at any depth, and `Program Files\PowerShell\Modules`
  with everything in it, where it exists. Each entry must pass the test
  of the agent's state check (`trustedEntry`,
  `agent/host/system_windows.go`, from PR #61): not a reparse point (no
  symbolic link, junction or mount point), a file with a single link,
  owned by SYSTEM, Administrators, TrustedInstaller or the account the
  agent runs as, and changeable by no one else. The account the agent
  runs as is trusted too (`trusted`, same file); for the service that is
  SYSTEM, so in production the list is the first three. The first entry
  that fails makes the install *found, not used*, naming the entry and
  why ("`…\7\Modules\Foo\Foo.psm1` can be changed by Users"), and it is
  never run. Checking only the path down to `pwsh.exe` would miss what
  it loads: the libraries beside it, the modules in `$PSHOME\Modules` it
  imports by name, and its `powershell.config.json`, which can set the
  module path and the execution policy. Program Files as Windows sets it
  up and the MSI's files are expected to pass; slice 1 checks both on
  the runners and measures how long the check takes.

  *Amended after the review of PR #90 (decided in review):*
  * **The folders above.** For the install's folder, each module folder
    and the folder of each configuration file, every existing folder above
    it, up to the drive's root, is checked for the rights that would let
    someone put another folder in its place: deleting the folder itself,
    deleting what its parent holds (`DELETE_CHILD`), and changing the
    access list or the owner of either (`WRITE_DAC`, `WRITE_OWNER`).
    Where the folder does not exist yet, its first existing parent must
    also let no one else create folders in it. The drive's root is checked
    for the replacing rights only: every user may create folders in `C:\`
    as Windows sets it up, and each folder the agent checks by default is
    below `Program Files` or `System32`
    (`host.CheckAbove`, `agent/host/system_windows.go`).
  * **Files open to write.** An access list is checked when a file is
    opened, so a program that opened a file to write before the list was
    fixed can still write it. The check opens each file of the install and
    of the module folders to read while denying others writes; that open
    fails while another program holds the file open to write or delete,
    or without sharing it: "… is open in another program that may write
    to it". For a run, `pwsh.exe` and the install's libraries (`.dll`)
    stay open that way from their check until Windows has created the
    run's process (`CreateProcess` returned), so no one can write,
    replace or delete them in between; then the agent lets go. That is
    before the process has loaded its libraries, which it does after it
    starts: for a library, the hold covers the check and the start, not
    the load, and a file changed after the agent let go is what the
    files' access lists, checked, allow, that is the administrators.
    After fixing an install's permissions, restart the computer: a
    restart closes every handle opened before the fix. Not claimed, and
    covered by that restart only: a writable mapping of a file made
    before the fix, whose handle was then closed; and a handle opened
    with `WRITE_DAC` or `WRITE_OWNER` before the fix, which can change
    the file's access list or owner again without write access, so the
    sharing test does not see it. Neither is detected, and no test shows
    otherwise. The open has a cost: a user who may read a file may also
    open it denying everyone else, and while they hold it the check
    fails. *Amended after the second review of PR #90 (decided in
    review):* the install is then *blocked*, not *found, not used*, and
    its runs fail without falling back, whatever the script allows: a
    user who could make runs fall back could choose where SYSTEM's
    scripts run. While they hold the file, `pwsh` runs on that computer
    fail; it gives them no way to change what runs.
  * **Files Windows compresses or deduplicates** are reparse points whose
    tag says so: `IO_REPARSE_TAG_WOF` (`compact /exe`, Windows' own
    compression) and `IO_REPARSE_TAG_DEDUP` (Data Deduplication). A file
    with one of those two tags passes as a plain file; every other reparse
    point still fails, and a folder that is a reparse point always does.
    On CI's runners (2026-11-22), where Windows' overlay filter runs, a
    file `compact /exe` compressed shows no reparse point at all
    (attributes `0x20`, tag 0) and passes as any plain file does; the two
    tags are what such a file shows where the filter is not attached, so
    which tags pass is tested on the rule itself, not on a file that
    carries one, and no deduplicated file was tested.
* **The module path of a `pwsh` run.** PowerShell 7 imports a module by
  name from the folders in `PSModulePath`, and imports one on its own
  when a script uses a command that no loaded module has and a module
  there exports. The machine's `PSModulePath` holds whatever installers
  added to it, and a folder there that users can write would let them
  plant a module that a SYSTEM script then imports. So:
  * the agent sets the run's `PSModulePath` to Windows PowerShell's two
    machine folders, `Program Files\WindowsPowerShell\Modules` and
    `System32\WindowsPowerShell\v1.0\Modules`, and nothing else.
    PowerShell 7 puts its own three before them when it starts
    (Microsoft's *about_PSModulePath*): SYSTEM's
    `Documents\PowerShell\Modules` in the system profile,
    `Program Files\PowerShell\Modules` and `$PSHOME\Modules`. A
    `powershell.config.json` in `$PSHOME`, or in SYSTEM's
    `Documents\PowerShell`, can name another folder for the first two;
    both files are in folders only administrators can change, and the
    agent reads them and uses the folders they name in place of those
    defaults;
  * before each run, every one of the five that exists is checked as the
    install is, everything in it included. One that fails fails the run,
    naming the entry. In System32, Windows keeps many of its own files
    as hard links into its component store (`WinSxS`), so in Windows
    PowerShell's folder there a file may have more than one link; owner
    and access list are checked all the same. *Amended in slice 1:* so
    does Windows PowerShell's folder in Program Files,
    `Program Files\WindowsPowerShell\Modules`, whose in-box modules
    (`Microsoft.PowerShell.Operation.Validation` among them) are hard
    links too on both CI runners. *Narrowed after the review of PR #90:*
    those two folders only; SYSTEM's profile, which is in System32 too,
    has no such exception, nor do configuration files;
  * *amended after the review of PR #90 (decided in review):* a folder a
    `powershell.config.json` names must exist, or the run fails naming
    it, since whoever may create it later could fill it; and each module
    folder is checked with the folders above it, as the install is;
  * *amended after the review of PR #90 (decided in review):* an install
    whose own files pass while a module folder or configuration file of
    its run fails is *blocked*: the run fails without falling back to
    Windows PowerShell 5.1, whatever the script allows. Windows PowerShell
    loads from Windows PowerShell's two module folders too, so the
    fallback would load a folder that fails there as well, and one rule
    for every such failure keeps what a run does predictable. Discovery
    runs the same checks, so the inventory reports the install as blocked
    with the reason (`blocked`, below), the Hardware tab says *found, not
    usable*, and the run dialog warns that the script fails there;
  * *amended after the second review of PR #90 (decided in review):* a
    `powershell.config.json`'s module path is expanded as PowerShell 7
    expands it, with Windows' `ExpandEnvironmentStrings`, from the
    environment the run gets: the agent's, without what each run sets for
    itself, with the run's `PSModulePath` and PowerShell variables over
    it. A variable that environment does not set fails the check, naming
    it, where Windows would leave it as it is and read on from its closing
    `%`; so does one each run sets for itself (`TEMP`, `TMP`,
    `EASYRMM_*`), as the inventory checks without a run;
  * **Windows PowerShell's compatibility session.** A module that only
    Windows PowerShell can load (`ServerManager`, `AppLocker`, …) is
    loaded by PowerShell 7 in a `powershell.exe` 5.1 process of its own
    when a script imports it or uses its commands (implicit
    compatibility); it stays on, as scripts rely on it. *Checked after the
    review of PR #90:* on 2026-11-22, on both runners, a `pwsh` run as
    LocalSystem imported `ServerManager` (`windows-latest`) or `AppLocker`
    (`windows-11-arm`) and printed that process's `$env:PSModulePath`: it
    was exactly the run's two Windows PowerShell folders, which the run
    checks, and the machine-wide entries did not come back. So no other
    folder needs checking; `TestPwshCompatibilitySessionAsSystem` asserts
    it on every CI run, with a folder planted in the computer's and in
    SYSTEM's `PSModulePath`;
  * folders other products added to the machine's `PSModulePath` are
    left out. A script that needs a module from one imports it by its
    full path, in the script, where its reviewer sees it. The guide says
    so;
  * **the fallback's module path.** *Amended after the second review of
    PR #90 (decided in review):* a `pwsh` script that falls back runs
    Windows PowerShell 5.1 with `PSModulePath` set to Windows PowerShell's
    two folders, as the compatibility session has it, not with the
    agent's own, which names the machine's `PSModulePath` and SYSTEM's.
    Before it starts, those two and SYSTEM's own
    `Documents\WindowsPowerShell\Modules`, which Windows PowerShell may add
    to what it is given, are checked as a `pwsh` run's folders are, and
    the same folder is checked for a `pwsh` run's compatibility session;
    one that fails fails the script ("Windows PowerShell would load
    modules from …; the script was not run"). So no fallback sees a
    module path the check did not cover.

  Refusing every `pwsh` run while some folder in the machine's
  `PSModulePath` is open to users was weighed and not chosen: a run
  would fail for another product's folder that the script never uses,
  the technician could not fix that from the console, and what a run may
  load would still depend on whatever the next installer adds. A fixed
  list of checked folders is the same on every computer. Slice 1 checks
  from inside a run that it sees exactly these five, and measures the
  check on the runners' images, which come with many modules installed;
  the time goes in the pull request, and if it is over a second this
  section is revisited there.
* **What is read**:
  * the version from the file's version resource (its product version,
    with a prerelease label for previews), not by starting it;
  * the architecture from the file's PE header (x64, ARM64 or x86);
  * *preview* from the folder's name or the prerelease label;
  * for Windows PowerShell 5.1, the major and minor version from
    `HKLM\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine`
    (`PowerShellVersion`), with the build and revision of its engine's
    file version (`System.Management.Automation.dll` in the .NET
    Framework's assembly cache, `GAC_MSIL`).

  Slice 1 checks on the CI runners that both agree with
  `$PSVersionTable.PSVersion` as each PowerShell prints it. If either
  does not, another source is chosen there and this section amended.
  *Amended in slice 1:* the registry's value alone did not agree on
  2026-11-22: on `windows-11-arm` it was 5.1.26100.9818 while
  `$PSVersionTable.PSVersion` was 5.1.26100.9974 (on `windows-latest`
  both were 5.1.26100.33822). The engine's build and revision agree on
  both runners, as the test as LocalSystem asserts.
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
  the whole check included, so a run uses what is on the computer at
  that moment and never an hour-old list.
* **Reported in the inventory, not the heartbeat.** PowerShell installs
  change a few times a year; ADR-0018 keeps such facts in the hashed
  inventory, uploaded only when they change, while the heartbeat's facts
  are written to the device's row every minute. The plan's F1 says the
  same of the facts it adds. The inventory gains `powerShell`: at most 16
  entries, each with the edition (`Desktop` for Windows PowerShell,
  `Core` for PowerShell 7, as `$PSVersionTable.PSEdition` names them),
  version, architecture, path, *preview*, *Store install*, and *usable*
  or the reason it is not. The server's `cleanInventory` keeps it,
  bounded, in the same release. The field follows ADR-0009's rule for
  new request fields. *Amended after the review of PR #90 (decided in
  review):* each entry also says whether it is *blocked* (above), which a
  server of the release before ignores. The device's row keeps what the
  device list shows: `powershell7`, whether a usable install is listed
  (NULL without a list), and `powershell7_blocked`, why a run fails where
  none is usable and one is blocked, both written with the inventory.
  Reading them from the inventory for every row of the device list cost
  more than a few milliseconds: on a seeded list of 10,000 devices with
  inventories, on the development host's PostgreSQL, the list took 231 ms
  with that join and 119 ms without. Migration 00034 fills `powershell7`
  from the inventories already stored, since an agent sends its inventory
  only when it changes.
* **Every state is explicit** on the device's page: *installed* with
  version and path; *not found*; *found, not used* with the reason
  (*Store install*, an entry others may change, preview, x86, version 6);
  *found, not usable* with the reason for a blocked install;
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
    PowerShell 5.1, exactly as a `powershell` run, its environment
    included, and records that it did.

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
  40 devices reported no usable PowerShell 7 at their last inventory;
  this script fails there", or "runs in Windows PowerShell 5.1 there".
  The server does refuse, or leave out of a selection (*Targets*),
  devices whose agent cannot run `pwsh` jobs at all (*Older agents*,
  below), as it does devices of the wrong platform.
* **How it runs** is as today for `powershell`: `pwsh.exe -NoLogo
  -NoProfile -NonInteractive -ExecutionPolicy Bypass -File script.ps1`
  and the arguments, the script saved as UTF-8 with a byte order mark
  (which PowerShell 7 reads too), the same folder and job object, the
  same rule for output in the console code page. Exit codes follow the
  same rules: `exit N` sets it, an uncaught error gives 1. The
  environment is the system's, with three changes for `pwsh` runs:
  `PSModulePath` as above; `POWERSHELL_TELEMETRY_OPTOUT=1`, since
  PowerShell 7 otherwise sends usage data to Microsoft when it starts,
  on the customer's computer; and `POWERSHELL_UPDATECHECK=Off`.
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
* **The agent's side is built in slice 1.** Under ADR-0009 the agent may
  send `accepts` only while its last heartbeat answer came from a server
  of level 2 or higher. Today nothing in the agent reads the answer's
  level (`HeartbeatResponse.Protocol`) and `Poll` sends `{}`. Slice 1
  makes the agent keep, for the life of its process, the level of its
  last heartbeat answer, and put `accepts` in its polls only while that
  level is 2 or higher. A process's first poll may go out before its
  first heartbeat answer and so carry no list; its next poll, within 25
  seconds, does. *Amended after the review of PR #90 (decided in
  review):* a result with `interpreter` waits for that first answer, at
  most until 30 seconds after the agent started; with no answer by then it
  is sent as to a level-1 server, without `interpreter`, so a server that
  does not answer heartbeats cannot hold up the job loop.
* **The claim** delivers a `pwsh` run only in answer to a poll whose
  `accepts` lists `job.pwsh`; otherwise the run stays queued, and the
  device's other runs are delivered as now.
* **The device keeps the last list it reported**, on its row, written
  only when it changes, for the console and for creating jobs.
  * **A poll without `accepts` leaves it as it was**, as a heartbeat
    without its report leaves ADR-0058's last report ("A heartbeat
    without the report changes nothing"). So an agent's restart, whose
    first poll carries no list, never marks the device unable to run
    PowerShell 7, even briefly. A poll with a list, even an empty one,
    replaces it.
  * **The list holds for the build that sent it**, as ADR-0058's report
    does: it is stored with the device's build at that moment (the
    heartbeat's `agentSha256`, or `agentVersion` from an agent that
    sends no hash). When the heartbeat's facts name another build (an
    update, or a rollback after a crash, ADR-0027), the list counts as
    not reported until that build's poll brings one, within about half a
    minute of its start.
  * Creating a `pwsh` job refuses a device chosen one by one whose list
    lacks `job.pwsh` or is not reported: "PC-12's agent cannot run
    PowerShell 7 scripts; update the agent", or "PC-12's agent has not
    yet said whether it can run PowerShell 7 scripts; try again in a
    minute". A selection leaves such devices out and counts them
    (*Targets*).
  * A run left queued because the device's polls stopped listing
    `job.pwsh` says so on its page, and expires with that reason.
    *Amended after the review of PR #90:* so does a run delivered to an
    agent that then changes builds before starting it, as a rollback
    does. It is not delivered again until that build's poll lists
    `job.pwsh`; its page says so instead of *about to start*.
* **Not ADR-0058's `capabilities`.** ADR-0058 (proposed) puts the signed
  messages an agent takes in its heartbeat, for instructions the
  heartbeat answer carries. Jobs go out in the poll, so the poll says
  what the poll's sender takes. When ADR-0058 is built, its report may
  list the same names for the console; the claim keeps reading the
  poll's.
* **During a rolling upgrade** of several server instances sharing a
  database, an instance of the release before knows nothing of
  `accepts`, `requires` or `pwsh_fallback`: it delivers a `pwsh` run to
  whichever agent polls it, with no `pwshFallback` in the payload. An
  agent of the release before refuses it ("the job is malformed. It was
  not run.") and nothing runs. *Amended after the review of PR #90:* an
  agent of this release runs it as a script that does not fall back, so
  where no usable PowerShell 7 is found the run fails instead of running
  in Windows PowerShell 5.1. Upgrade every instance before running `pwsh`
  scripts.

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
* **Where the text is kept.** Not in the job's row, which is written once
  and returned by every job and run response (Context). A table of its
  own, `job_commands`, holds one row per one-off job: the text, its
  SHA-256, its size, and when the text was removed, under row-level
  security as the job is (visible through a visible run). The job's kind
  is `command` (the jobs' `kind` constraint gains it), its name *One-off
  command*; its `body` and `body_sha256` are empty, which a constraint
  ties to that kind. The claim reads the text from `job_commands` to
  sign the payload.
* **The SHA-256 goes only with the text.** A SHA-256 of a short command
  confirms a guess: whoever holds it can hash `net user admin
  Winter2026!` and its likely variants and compare, offline and without
  a record. So for a one-off job:
  * no answer under `job.view` carries the hash or the text. The job
    lists; `GET /api/v1/jobs/{id}` (`GetJob`, whose `body` and `sha256`
    become *Script as run* and *SHA-256* on the job's page); and `GET
    /api/v1/job-runs/{id}` (`GetRun`, which nests the job with its
    `body`) carry the job's ID, *One-off command*, the shell, the text's
    size, `commandRemovedAt` once removed, and `canViewCommand`. They
    carry it to no one, holders of `job.view_sensitive` included, since
    fetching a job is not reading it (ADR-0063's rule for output);
  * the text and its SHA-256 come together, and only, from `GET
    /api/v1/jobs/{id}/command`, under `job.view_sensitive`, recorded;
  * no audit record carries the hash (*What is recorded*, below).

  A keyed hash (an HMAC under a key only the server holds) was weighed
  and not chosen: it would add a key to keep, back up and rotate, for a
  value that lets someone without the text check nothing.
* **Who reads the text.** `GET /api/v1/jobs/{id}/command` answers as
  ADR-0063's arguments endpoint does: `404` when the caller cannot see
  the job, with no record; `403` when they hold `job.view_sensitive` for
  none of its runs they see, recorded as denied; `409 command_removed`
  once the text was removed, with no record; and `200` with `text`,
  `sha256` and `bytes`, recorded as `job.command_view` once per
  organization of the job's runs the caller holds `job.view_sensitive`
  for, in the transaction that reads it. Read-Only sees "One-off command,
  PowerShell 7, 412 bytes", never the text or its hash.
* **Kept as output is.** A command is typed in the moment, often with a
  password in it; it is closer to output than to a library script or
  its arguments, which ADR-0063 keeps with the job. So it follows
  ADR-0063's output rules:
  * kept for `EASYRMM_JOB_OUTPUT_RETENTION` (30 days by default), not
    the job's retention. The hourly purge empties the text and its
    SHA-256 of each one-off job created longer ago than that whose runs
    have all ended, and sets when; the job, its runs and the text's size
    stay until the job goes;
  * removed at once with `DELETE /api/v1/jobs/{id}/command`, as
    `DELETE /api/v1/job-runs/{id}/output` removes output, by a caller
    with `job.manage` and `job.view_sensitive` at the site of every run
    of the job, those they cannot see included, since the text is shared
    by all of them; refused with `409 job_open` while a run has not
    ended, since a queued run still needs it; recorded as
    `job.command_remove` once per organization of the job's runs;
  * after either, the job's page says "The command's text was removed
    on …", and *Run again* is not offered.

  Emptying a row removes the text from the table; old row versions go at
  PostgreSQL's next vacuum, and backups made before keep it as long as
  they are kept, as ADR-0063 says of output.
* **What is recorded.** Each run is recorded as `device.command_run`,
  under the device's organization and site, with the device, the job and
  run, the shell, the text's size, the timeout, the PowerShell 7
  fallback and when the session stepped up. Never the text, and never
  its SHA-256: the audit log outlives jobs, is forwarded (ADR-0023), and
  is read by more people than `job.view_sensitive` reaches. `create`
  adds the script's SHA-256 to every run's record today (`jobs.go`); for
  kind `command` it adds none.
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
  EasyRMM (kept as output is, read with a record, no hash anywhere else).
  On the computer, the text is in its PowerShell logs once script block
  logging is on (ADR-0060, or the customer's own policy).

ADR-0017's line becomes: "Library scripts run with `script.run`.
One-off commands run with `script.run_oneoff` and step-up; their text is
kept apart from the job for the output retention and read with a record
(ADR-0064)." Its shells gain `pwsh`, and its "Execution on the agent"
gains live output and the program recorded.

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
  sending every 2 seconds, is 250 updates a second, each rewriting up to
  128 KiB, for its whole length. So output is sent while a run's page is
  open, and only then.
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
* **Sending, by position.** While a run is watched, the agent posts
  every 2 seconds to `POST /api/agent/v1/jobs/output`, a signed request
  like every other. For each watched run and each stream it sends a
  piece of text and where that piece starts and ends in the stream,
  counted in the bytes the script wrote since it started (the capture
  already counts them: `total` in `agent/jobs/capture.go`), with the
  stream's total so far. A piece is at most 32 KiB: the text from where
  the last piece ended, or, when more than that has arrived since, a
  post failed or was refused, or this is the first post, the latest
  32 KiB. All watched runs of the device go in one post, so at most four
  runs and 256 KiB of text per post, within the 1 MiB limit.
* **Placed by position, never by a count.** The server places a piece
  by where it starts: one that starts where the kept text ends is
  appended; one that starts later is appended after a mark saying how
  many bytes are missing; one that ends at or before the kept end (a
  post repeated, or overtaken by a later one) is dropped; one that
  overlaps is trimmed. A post lost, repeated or arriving late cannot put
  text in the wrong place, which a count of bytes skipped since the last
  post could.
* **Whole characters, decoded as the final output is.** Each piece is
  decoded as `decodeOutput` (`agent/jobs/exec_windows.go`) decodes a
  stream when the run ends: UTF-8, or the OEM code page where the bytes
  are not valid UTF-8.
  * For live text the choice is made once per stream of each run, at its
    first piece holding a byte above 0x7F, and kept. The final output is
    still decoded whole, and replaces the live text when the run ends;
    where a later part of a stream is not valid UTF-8, the two can
    differ until then, the live text showing replacement characters.
  * A piece ends only after a whole character. An unfinished UTF-8
    sequence at its end, or, in a double-byte OEM code page (932, 936,
    949 and 950, on Japanese, Chinese and Korean Windows), a lead byte
    without its second byte, waits for the next post; the agent scans
    from the last position it sent, where a character starts, so it
    knows which bytes are lead bytes. Single-byte code pages end
    anywhere.
  * After a gap the agent no longer knows where characters start. The
    piece then starts at the first byte that begins a character in
    UTF-8, or, in a double-byte code page, just after the first line
    feed in it, a byte that is never the second half of a character in
    those code pages.
  * On Linux the text is UTF-8, as the final output is, with the same
    rule at both ends.
* **Never queued, never blocking.** The script never waits for the
  network: the capture keeps accepting output as it does now, and a
  post that fails is not sent again; the next one sends from its own
  position. A per-device limit of one post every 2 seconds (bursts of 3)
  is added beside the existing one; `429` makes the agent wait and send
  the newest text after. An endpoint the server does not have (`404`)
  stops the sending for that server, as ADR-0009 says.
* **Written only while the run is running.** The post's transaction
  locks the run's row (`FOR SHARE`), the row `Result` updates when it
  stores the result (`delivery.go`), and writes the live text only if
  the run is `running`. So a post that meets a result either goes first,
  and the result's transaction then removes the live row, or waits for
  the result and then finds the run ended and writes nothing. A late
  post cannot write the live row again after the result.
* **Kept on the server in unlogged tables.** Two tables, both unlogged:
  the watches (the run, the session, until when), and the live text, one
  row per watched running run, with the organization and site for
  row-level security, the last 64 KiB of each stream, where each kept
  stream ends, the totals, the gaps, and when it last changed. Unlogged
  means no transaction log for them, so live output costs no WAL and is
  not replicated; after a database crash both are empty, and pages
  start their watch again, recorded again. The live row goes when the
  result arrives (in the result's transaction), when the run ends
  otherwise (canceled, timed out or lost, by the sweeper), or 5 minutes
  after its last watch ends. A backup taken while a row exists holds it
  (`pg_dump` includes unlogged tables' rows); it holds the same text the
  run's result keeps.
* **What it writes.** PostgreSQL writes a whole new version of a row it
  updates, and rewrites a value kept out of line (TOAST, for anything
  over about 2 KiB) when it changes. So each post rewrites up to 128 KiB
  per run, both streams' 64 KiB tails: 20 people each watching a busy
  run are 10 updates a second, up to about 1.25 MiB a second written to
  the table's files, without transaction log, with the old versions left
  to vacuum. The second writer is the watches: each `/live` request
  renews its watch, which is a write too, so a renewal is written only
  when less than half of the watch's 60 seconds remain, once per page in
  30 seconds. Both writers are measured with `tools/agentsim` before
  slice 2 merges, the table's size and vacuum under that load included,
  and the numbers go in the slice's pull request.
* **Reading it.** The page asks `GET /api/v1/job-runs/{id}/live` every 2
  seconds (as it already asks for the run), with the position it has
  up to. It needs an open watch of the same session; the permission is
  checked on every request; the request renews the watch as above and
  records nothing more. When the run ends, the page asks ADR-0063's
  output endpoint for the kept output (the first and last 128 KiB of
  each stream), which replaces the tail: another read, another record.
* **The console.** Standard output and error apart, as now, each showing
  the latest 64 KiB with "1.2 MB written so far; showing the latest
  64 KiB" when there is more, a line where bytes are missing, and "No
  output received for 30 seconds" when the posts stop. Without
  `job.view_sensitive`: "Hidden: needs permission to see job output".
  For an agent that does not list `job.live`: "This device's agent sends
  output when the script ends; update the agent to see it while it
  runs." Live output covers every shell, not only PowerShell.

### Interactive sessions
*Decided by the owner (2026-11-21)*: the owner chose MeshCentral's
terminal with session-level audit, so typed input is not recorded. In
the owner's words: "for powershell yes the Mesh one is fine." There is
no second interactive channel.

What the record holds, and what it does not:

| | Recorded by EasyRMM | Where |
|---|---|---|
| Who opened a terminal, on which device, when, from which address; or was refused for lack of `device.terminal` | Yes | `device.remote_session` with the kind `terminal` and the grant, as now |
| Which of the four terminals was opened (Local System or the signed-in user; command prompt or PowerShell) | Yes, new in slice 5 | `device.terminal_open`, from the message MeshAgent reads (below) |
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
  now), and new, each terminal connection the gateway admits, as
  `device.terminal_open` with which of the four it is, the device and the
  grant.
  * The terminal is not taken from the relay's address, nor from what
    the console asked for. MeshAgent opens the terminal named by the
    first message inside the tunnel that is not a JSON object (Context).
    The gateway already reads that message and refuses the relay unless
    it is exactly the address's `p` (`relayProtocolCheck`). The record
    is written when that check passes, with the terminal that message
    names.
  * It says which terminal MeshAgent was asked to open and the gateway
    let through. MeshAgent can still fail to open it (it refuses
    PowerShell where `PowerShellCapable` says no); the record does not
    say that it opened.
* **Not recorded**: what is typed and what is shown. The owner chose
  MeshCentral's terminal with session-level audit, so typed input is not
  recorded (above). Said plainly in the console's terminal panel, the
  guide and the threat model. MeshCentral's own
  session recording (`sessionrecording`) stays off: it would write every
  secret shown to MeshCentral's disk, outside EasyRMM's permissions,
  audit, retention and backups.
* **No change to MeshCentral's rights.** `device.terminal` still grants
  all four terminals; MeshCentral has no right per type.

### Targets
*Decided in review.*

* **Chosen by organization, site or device group**, or devices one by
  one as now, in the run dialog, for library scripts and one-off
  commands. The API takes the selection and resolves it, in the job's
  transaction, into the devices the caller can see.
* **Devices chosen one by one keep today's rule.** A device the caller
  cannot run on, outside the script's level, without an agent, of
  another platform, or, for a `pwsh` job, whose agent cannot run
  PowerShell 7 (*Older agents*), refuses the whole job, naming it.
  Naming a device is asking for that device.
* **A selection leaves such devices out and counts them.** Choosing a
  site means the devices there that can run it. The dialog shows the
  counts before running: "312 devices: 290 will run it; 8 are Linux
  devices, 4 have no agent, 3 have an agent that cannot run PowerShell 7,
  and 7 are at *Warehouse*, where you cannot run scripts." A device
  outside the script's level is left out the same way: a site's script
  run on an organization runs on that site only. A selection with no
  device left is refused.
* **Mixed roles in one organization.** A person can be a Technician at
  one site and Read-Only at another of the same organization. Choosing
  the organization resolves to the devices they can see; those at sites
  where they lack `script.run` (or `script.run_oneoff`) are left out and
  counted by site, as above. Refusing the job instead, as for devices
  named one by one, would make choosing their own organization useless
  to them. Nothing runs where the permission is missing, and the count
  says where it did not run and why.
* **What was confirmed is what runs.** The request carries the number of
  devices the person confirmed. If the selection resolves to another
  number in the job's transaction (a device added, moved or enrolled
  meanwhile), the job is refused and the dialog shows the new counts.
* **Fixed when the job is created.** The job keeps its devices, and the
  selection it came from for display ("Site *Main office*, Windows
  devices"). *Run again* resolves the same selection again and shows the
  new counts before running.
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
under `job.view_sensitive`, and every read is recorded, one record per
run read.

* **One stream**: `GET /api/v1/job-runs/{id}/output?download=stdout` or
  `=stderr`, as ADR-0063 names them: the text as kept, UTF-8 without a
  byte order mark, at most about 257 KiB, as `text/plain` with a file
  name made of the device's name and the run's.
* **One run**: `?download=json`: the device, organization and site, the
  job, the script's name and SHA-256 (for a one-off command, *One-off
  command* and the text's size, never the text or its hash, which only
  `/command` gives), the shell, the program recorded, the status, exit
  code, error, times, both streams and whether each was cut. At most
  about 600 KiB.
* Each is recorded as ADR-0063's `job_run.output_view`, with what was
  downloaded.
* **A whole job**: `GET /api/v1/jobs/{id}/output.zip`. For each finished
  run the caller holds `job.view_sensitive` for, a folder with
  `stdout.txt`, `stderr.txt` and `result.json` (as above); and
  `runs.csv`, one row per run the caller sees, saying whether its output
  is included or why not (hidden, removed, still running).
  * **Its size about doubles** the output: each run's streams are in it
    twice, as files and inside `result.json`. At most 500 runs of about
    1 MiB of text each, about 514 MiB before compression.
  * **One record per run included**, ADR-0063's `job_run.output_view`
    with `download: "zip"`, under the run's organization, site and
    device, as any read of that run's output.
  * **The set of runs is fixed in the transaction that records them.**
    That transaction chooses the runs included (finished, output not
    removed, `job.view_sensitive` at their site) and writes their
    records, and commits before the first byte is sent; if it cannot,
    nothing is sent. A download that then breaks off is still recorded:
    recording a read that may have happened is the safe side.
  * **No transaction stays open while the archive is sent.** After that
    commit, each run's output is read in a short transaction of its own
    (at most about 514 KiB) that closes before the run's files are
    written to the client, so a slow client holds no database
    connection or snapshot. A run whose output is removed between its
    record and its read is listed in `runs.csv` as removed, without its
    files; its record stays. *Decided in review (slice 1):* so is a run
    purged, or moved where the caller may no longer read it, meanwhile.
  * **Each read is held to its record**, by the database: the record must
    be of that run, by that caller, with `download: "zip"`, and at most a
    day old by the database's clock (`clock_timestamp()`, and no more
    than 5 minutes ahead of it, should that clock be set back). *Decided
    in review (slice 1):* the server passes no time to that read, so it
    cannot stretch the day; and the database's clock dates the record
    too, so a server whose clock is ahead of the database's cannot date
    the records out of their day and have every run listed as removed.
  * **Locks**: the transaction that records the runs holds them `FOR
    SHARE` until it commits, taken in the order canceling a job takes
    them (device name, then run), so a download and a cancel of the same
    job wait for each other at most and never deadlock. *Decided in
    review (slice 1).*
  * **Load**: one archive appends up to 500 audit records, under the
    audit chain's lock. *Decided in review (slice 1):* each person may
    download six archives at once, then one every 10 seconds: up to 11
    in the first minute, six a minute after that. Another is answered
    `429` with `Retry-After: 10` before anything is read or recorded. The
    limit is kept by each server process, in memory: a restart starts it
    again, and with several servers each allows that much.
  * Names in the archive are made of letters, digits, `-`, `_` and `.`,
    never absolute and never `..`.
* **The job's results without output**: `GET /api/v1/jobs/{id}/runs.csv`,
  under `job.view`, Read-Only included: one row per run the caller sees,
  with the device, organization, site, status, exit code, error, program
  and version, and the times; no hash of a one-off command. It carries no
  output, so it follows the reports' rules (ADR-0029): recorded as
  `job.results_export`, cells that a spreadsheet would read as formulas
  neutralized as `reports/csv.go` does.
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
* **Running Store installs now**: installed for one user, with a
  `$PSHOME` no administrator can set, and not tried as SYSTEM; decided
  again with slice 1's result (*PowerShell 7 on the computer*).
* **Checking only the path down to `pwsh.exe`**: a library or module
  inside the install that users can change runs as SYSTEM all the same.
* **The machine's `PSModulePath` for `pwsh` runs**, or refusing runs
  while a folder in it is open to users: above.
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
* **A plain or keyed SHA-256 of a one-off command beside the job or in
  the audit log**: above.
* **Streaming every run**, or keeping live output in `job_runs`: writes
  and transaction log for output nobody watches.
* **Placing live text by a count of skipped bytes**: a lost or repeated
  post would put text in the wrong place.
* **Live output over ADR-0059's WebSocket**: it is wake-only by decision,
  and carrying work over it would need an ADR of its own (ADR-0059,
  "Full delivery: not now").
* **Running jobs as the signed-in user now**: above.

A second interactive channel and a record of what is typed in the
terminal were not weighed here: the owner chose MeshCentral's terminal
with session-level audit, so typed input is not recorded (*Interactive
sessions*).

### What this does not fix
*Decided in review.*

* **SYSTEM is SYSTEM.** Whoever may run scripts or open a terminal at a
  site can do anything on its computers and read any secret on them.
  This ADR records what was run; it cannot limit what the code does.
* **The terminal** records who opened which terminal on which computer,
  not what was typed or shown, and asks for no step-up. Someone holding a
  stolen session can still open a terminal, one computer at a time.
* **Secrets typed into one-off commands** are kept apart from the job
  for the output retention, unless removed sooner, and in backups made
  meanwhile; readable by holders of `job.view_sensitive` with a record;
  and on the computer in its PowerShell logs once script block logging
  is on.
* **The computer's own environment, for every run but `pwsh`.**
  `powershell`, `cmd` and the Linux shells get the system's `PATH`, and
  Windows PowerShell its `PSModulePath`, as today, so no existing script
  changes. `pwsh` runs, and *after the second review of PR #90* a `pwsh`
  script that falls back, get their own module path of checked folders,
  but the system's `PATH`,
  since scripts call installed programs (`winget`, `choco`, vendors'
  tools) by name from folders installers add. A folder on the `PATH`, or
  on Windows PowerShell's module path, that users can write lets them
  plant a program or module that a SYSTEM process may load: a hole on
  that computer, which this ADR does not add and does not close.
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
| Interactive PowerShell sessions where feasible | Interactive sessions (slice 5) | MeshCentral's terminal, as now: the owner chose MeshCentral's terminal with session-level audit, so typed input is not recorded; slice 5 names the four terminals and records which was opened |
| Elevated execution with appropriate authorization | Elevation | SYSTEM, per-site permissions, step-up for one-offs |
| Output in real time where supported | Live output (slice 2) | Runs being watched, agents listing `job.live` |
| Standard output and error separately | ADR-0017; live output and downloads keep them apart | Exists |
| Process exit codes | ADR-0017; downloads and results CSV carry them | Exists |
| Execution timeouts | ADR-0017 (1 second to 4 hours); Disconnected devices and long runs | Exists |
| Save reusable scripts | ADR-0017's library; *Save to library* (slice 3) | Library writers are Site Administrators and above (Owner questions) |
| Command and script execution history | Jobs and runs (ADR-0017); one-offs in the same lists | Exists; one-offs added, their text kept for the output retention |
| Timestamps and the technician responsible | Jobs, runs and audit records | Exists; `device.command_run` added |
| Individual devices or selected groups | Targets (slice 4) | Organization, site or group when created, devices that cannot run it left out and counted; at each run waits for F3 |
| Results and status reporting | Results CSV, run columns (slice 1) | Per job; no report across jobs (ADR-0063's export rule applies to one later) |
| Download command output | Downloads and results (slice 1) | New |
| Windows PowerShell and PowerShell 7 where installed | PowerShell 7 on the computer; Choosing (slice 1) | New for MSI and ZIP installs in Program Files; Store installs reported, not used |
| Identify the PowerShell version being used | The version used, on every run (slice 1) | New |
| Appropriate execution privileges | Elevation | SYSTEM only; signed-in user deferred (Owner questions) |
| Prevent unauthorized execution | Permissions at each site, signed jobs, step-up, checked installs and module folders | Exists; extended |
| All remote command execution auditable | `device.script_run`, `device.command_run`, `device.remote_session`, `device.terminal_open` | Every run: a library script with its SHA-256, a one-off command with its job and size; terminals at the session's start and which was opened; the owner chose MeshCentral's terminal with session-level audit, so typed input is not recorded |
| Sensitive output not exposed | ADR-0063; downloads, live output and one-off text follow it | With ADR-0063; a one-off command's hash only beside its text |
| Long-running commands and disconnected devices | Disconnected devices and long runs | Exists; one-off default wait 1 hour |

PowerShell on Linux is not asked for ("managed Windows devices") and is
slice 6, last, and can be dropped without changing the rest.

## Slices
Each merges and is verified on its own, at every level it touches. The
plan's order puts slice 1 right after ADR-0063 (F0), whose output
endpoint its downloads use.

1. **PowerShell 7, the version used, and downloads.** The smallest that
   is worth shipping alone: technicians run their scripts in the
   PowerShell they write for, see which one ran, and take the output
   away. Two pull requests: downloads and the results CSV first (server
   and console only, on ADR-0063's endpoint), then PowerShell 7 (agent,
   protocol, migration, console), which builds the poll's `accepts` and
   the agent's side of ADR-0009's rule.

   *Verified*: integration tests; the Windows runners, x64 and ARM64, as
   LocalSystem (discovery; the whole install's check, an entry deep in
   it that users can change refused, and the check's time; the run's
   module path seen from inside a run; both editions; versions against
   `$PSVersionTable`; exit codes; fallback; the x86 build reported and
   not used; a Store install reported and not used, and what happens
   when SYSTEM starts its `pwsh.exe`); the winget check (*Testing*); the
   end-to-end test; an agent of the previous release still running every
   job it ran before.
2. **Live output.** Second, because it needs nothing that is not built,
   and it is the riskiest for load, so it is measured before anything
   else depends on it.

   *Verified*: integration tests with the agent's requests, a post and a
   result racing included; the load of both writers measured with
   `tools/agentsim`; the Windows runners and Linux tests of the agent's
   pieces, gaps and character ends; the end-to-end test.
3. **One-off commands.** Third, because they need step-up, which
   ADR-0055 builds in its slice 5b2, step 15 of the plan's order; this
   keeps the plan's order of live output, then one-off commands. Putting
   one-off commands second was weighed: they are the bullet the
   requirement lists first, but without step-up they would run unreviewed
   code on 500 computers from a stolen session. If the owner wants them
   sooner, step-up is built ahead of 5b2 as ADR-0055 defines it, ADR-0055
   says so, and slices 2 and 3 change places with nothing else changing
   (Owner questions).

   *Verified*: integration tests of the permission, step-up, the text's
   table, endpoint, purge and removal for every role, and of no hash in
   any `job.view` answer or audit record; the end-to-end test.
4. **Targets by organization, site and group.** Independent of 2 and 3;
   may be built beside them.
5. **The terminal**: the four terminals named, the PowerShell 7 paths
   shown, `device.terminal_open` recorded.

   *Verified*: the gateway's integration test with a live terminal
   through the relay (as today) records the terminal from the tunnel's
   message for each of the four, and a message that differs from `p` is
   refused with no record; the script for MeshCentral's page against the
   pinned image; on a real Windows computer, *PowerShell* opening Admin
   PowerShell and `pwsh` started in it. Until that real computer, it is
   marked unverified.
6. **PowerShell 7 on Linux**, if still wanted: `pwsh` from Microsoft's
   packages in `/opt/microsoft/powershell/<major>/`, checked as root's
   (owned by root, changeable by no one else, the whole install), the
   version from the package that installed it, which the inventory
   already reads; the fallback does not apply, so a Linux device without
   it fails the run with the reason; the shell's platforms gain Linux.

## Consequences
* Technicians can choose PowerShell 7 per script, see which PowerShell
  and version ran on every run, and download output.
* A computer whose only PowerShell 7 is a Store install, which winget
  installs by default since 7.6.0, cannot run `pwsh` scripts until an
  MSI or ZIP install is added, unless slice 1's result changes that.
* `pwsh` scripts import modules from five checked folders only; a module
  elsewhere is imported by its path.
* Scripts' and jobs' shell lists gain `pwsh`; the inventory gains
  `powerShell`; the poll gains `accepts`; the result gains
  `interpreter`; runs gain columns for it; devices keep the last
  `accepts` with the build that sent it; one-off commands' text has a
  table of its own.
* An agent of the release before keeps running everything it ran; it
  gets no `pwsh` job and sends no live output; the console says to
  update it.
* ADR-0017's library-only rule gains an exception behind
  `script.run_oneoff` and step-up. One-off commands depend on step-up
  being built.
* The audit log gains `device.command_run`, `job.command_view`,
  `job.command_remove`, `job.results_export` and `device.terminal_open`,
  and ADR-0063's `job_run.output_view` says when a read was a download
  (and which) or a live watch.
* The database gains two unlogged tables, for watched runs only.
* Interactive work stays in MeshCentral's terminal: the owner chose
  MeshCentral's terminal with session-level audit, so typed input is not
  recorded. Its record says who opened which terminal where, and it asks
  for no step-up. The guide and the threat model say so.
* Windows paths that the CI runners cannot show stay marked unverified
  until the Windows machines of ADR-0054's W1, or real computers, show
  them: a computer without PowerShell 7, `AllSigned` from Group Policy,
  Constrained Language Mode, Windows Server on ARM64, a domain.

## Testing
* **Integration tests** in Go against real PostgreSQL through `testdb`
  (`make test-db`), without mocks: the jobs service
  (`server/internal/jobs`), the agent API with signed requests
  (`server/internal/httpapi/agentapi`) and the console's API
  (`server/internal/app`, as `jobs_api_integration_test.go` is now).
  * **PowerShell 7**: scripts and jobs with `pwsh` and each fallback
    setting; the claim delivering a `pwsh` run only to a poll that
    accepts it, leaving it queued for one that does not, and the run's
    page saying why; a poll without `accepts` leaving the device's list
    as it was, and one with an empty list replacing it; a heartbeat
    naming another build making the list not reported; creation refused
    for a device chosen one by one whose list lacks `job.pwsh`; a result
    with `interpreter` kept and shown to Read-Only; one without it shown
    as not reported; the inventory's `powerShell` cleaned and bounded.
  * **Downloads**, on ADR-0063's tests: every role on each download; a
    random marker in output appearing only in downloads to holders; one
    record per download, one per run included for the ZIP, written and
    committed before the first byte, and with appends made to fail,
    nothing sent; a run's output removed after the records and before
    its read, listed as removed; the ZIP opened and its names checked;
    the results CSV for Read-Only, its formula cells neutralized, its
    record.
  * **Live output**: a watch needing `job.view_sensitive` and an open
    run, its one record, at most four per session; a poll answering at
    once when a watch starts and listing it after; pieces placed by
    position (appended, a gap marked, a repeat dropped, an overlap
    trimmed); the per-device limit refusing a fourth post in a burst; a
    post and a result in both orders, the live row never there after the
    result; the row removed when the run ends any way; the watch renewed
    only when half its time is left; `/live` refused without the
    session's watch; both tables emptied (as after a crash) and the
    page's watch started again.
  * **One-off commands**: every role, with and without step-up, stale
    step-up, and an account with no second factor; one
    `device.command_run` per run with the size and neither text nor
    hash; a marker in the text, and its SHA-256, appearing only in
    `/command` to holders, never in job lists, `GetJob`, `GetRun` or the
    audit log; the purge emptying the text after the output retention
    and not while a run is open; `DELETE` refused while a run is open
    and for a caller missing the permission at one run's site; *Run
    again* asking for step-up after it lapses and not offered once the
    text is removed.
  * **Targets**: an organization, a site and a group resolved under
    row-level security; devices left out by platform, agent, `job.pwsh`,
    the script's level and the caller's permission, counted; a caller
    with different roles at two sites of one organization; the whole job
    refused for a device chosen one by one that cannot run it; a count
    that differs from the confirmed one refused; over 500 refused.
  * **The terminal**: the existing live terminal test through the relay
    records `device.terminal_open` with the terminal from the tunnel's
    message, for each of 1, 6, 8 and 9, and none for a refused relay.
* **Agent tests** in Go on every platform: the payload's new shell and
  field refused by the strict decoder of the release before and accepted
  now; `accepts` sent only while the last heartbeat answer was of level
  2 or higher, and not after one of level 1; the capture handing out
  pieces by position, with gaps; whole characters at piece ends in UTF-8
  and in code page 932, a lead byte at the end held back; after a gap,
  a piece starting at a character, after a line feed in 932; the
  encoding chosen once per stream; the journal keeping `interpreter`
  across a restart.
* **Agent tests on CI's Windows runners, as LocalSystem.** A job of its
  own, in a matrix over `windows-latest` (x64) and `windows-11-arm`
  (ARM64), whose images name PowerShell 7.6.10 and 7.4.13 (Context); the
  existing *Agent tests on Windows* job keeps its tests. The job builds
  the agent's Windows test binary and runs it as LocalSystem through a
  scheduled task, as ADR-0054's hardening tests run, and fails with the
  task's exit code and output. Run as the runner's administrator, the
  checks would test something else: `trusted` also trusts the account
  the agent runs as (`agent/host/system_windows.go`), so a file owned by
  the administrator's account would pass there and fail under the
  service. As SYSTEM, runs also get SYSTEM's profile, its module path
  and PowerShell's first start as SYSTEM (its telemetry and update
  check), as on a customer's computer. The versions the tests compare
  against are read on the runner, never written into the tests.
  * discovery finds the runner's PowerShell 7, and its version and
    architecture match what `pwsh` itself prints; Windows PowerShell's
    version matches `powershell.exe`'s `$PSVersionTable`;
  * the whole install and the module folders pass, and the check's time
    is printed; a file deep in a copy of the install that the test opens
    to Users makes that copy *found, not used*, naming the file, and it
    is never run; a junction inside it is refused the same way;
  * `$env:PSModulePath` inside a `pwsh` run is exactly the five folders;
    a module in a folder added to the `PSModulePath` the agent itself
    was started with is not found by name;
  * Microsoft's x86 ZIP of the same version, pinned by SHA-256 and
    unpacked into Program Files (x86), is reported and never chosen;
  * a `pwsh.exe` a standard user places on the `PATH` is never found;
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
    than 32 KiB in 2 seconds;
  * *added after the review of PR #90:* a library of the copy held open
    to write makes it *blocked* (*after the second review*; before, *found,
    not used*), and `pwsh.dll` held open with no sharing, by the test's
    own process standing in for a user's, makes a run that allows the
    fallback fail without starting anything; a run holds `pwsh.exe` and
    the libraries, writes refused, until it lets go; the copy compressed with `compact /c /exe:xpress4k` is still
    used; a configured module folder that does not exist, one whose
    parent Users may empty, and SYSTEM's own `powershell.config.json`
    opened to Users each make the copy *blocked*, and the run fails
    without falling back, while `$PSHOME`'s opened to Users makes it
    *found, not used*, as one of the install's own files; a
    folder opened to Users in Windows PowerShell's or PowerShell 7's
    shared module folder fails a run that allows the fallback; the
    compatibility session's module path; *after the second review*, the
    fallback's module path, and the compatibility session's, holding only
    folders the agent checked, both with the runner's `PSModulePath` and
    with Windows' default one, and a folder opened to Users in Windows
    PowerShell's folder in Program Files failing the fallback. The
    statements of
    `agent/powershell/powershell_windows.go` that the two test binaries
    run are measured from their coverage profiles, and the job fails below
    a floor of 82% (`backend-tests.yml`; both runners measured 83.2% of
    its 286 statements on 2026-11-22): `scripts/ci/check-coverage.sh`
    measures the Linux build only, which does not compile that file.
* **Agent tests on CI's *Agent tests on Windows* job** (as the runner's
  administrator), *added after the review of PR #90*: a file open to
  write fails the check and one open to read does not; held files cannot
  be written or renamed and a failed check holds nothing; a file
  compressed with `compact` passes and a junction does not, and the
  reparse tags a file may carry (`TestReparseTags`); the folders
  above, with a planted `DELETE_CHILD`, `WRITE_DAC`, `DELETE` and owner,
  `ProgramData`'s create right for a missing folder, and Windows' own
  module folders passing.
* **The winget check**, in the same job, before the tests: the step, as
  the runner's administrator, checks that winget is there (the images'
  lists do not name it) and fails if not; then `winget install --id
  Microsoft.PowerShell`, pinned to a version, installs the MSIX, which
  discovery, as SYSTEM, reports as *found, not used (Store install)*
  while runs keep the image's install. The test also starts that
  install's `pwsh.exe` as SYSTEM and records what happens, for the
  decision on Store installs.
* **Machine tests** (`internal/vmtest`): slice 6 on the harness's
  distributions, with Microsoft's package pinned by SHA-256 and without
  it. Windows machines come with ADR-0054's W1: then a Windows client
  and server without PowerShell 7, with it from the MSI, under `AllSigned`
  from Group Policy and under Constrained Language Mode.
* **Page tests** (`web/src/pages/jobs/jobs.test.tsx`,
  `web/src/pages/scripts/scripts.test.tsx`): the shells and the fallback
  setting; the program on the run's page, and "not reported"; the
  warning counts; downloads offered only where they work; the live view,
  its "showing the latest", missing-bytes and silence messages and the
  hidden state; the one-off dialog asking for step-up and naming the
  device count; the text and its hash hidden without the permission, and
  "removed"; target selection and its counts; the four terminals named.
* **The browser end-to-end test** (`make e2e`, `web/e2e/console.spec.ts`)
  against a real server, with the simulated agent (`web/e2e/agent.ts`)
  taught `accepts`, `powerShell`, `interpreter` and output posts: a
  technician runs a `pwsh` script and sees "PowerShell 7.6.10"; downloads
  the run as JSON and the job as a ZIP and the files hold the marker;
  watches a run and sees the agent's posted output before the result;
  steps up with the test's authenticator code and runs a one-off
  command; a Read-Only user sees the program and status but no output,
  no command text and no hash; the audit log shows each record.
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
