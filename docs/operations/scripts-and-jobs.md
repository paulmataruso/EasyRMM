# Scripts and jobs

EasyRMM keeps a library of scripts and runs them on devices that have the
EasyRMM agent. Running a script on one or more devices is a **job**; each
device's part of it is a **run**, with its own status, exit code and output.
The design is in [ADR-0017](../architecture/adr/0017-scripts-and-jobs.md).

| Shell | Runs on |
|---|---|
| Windows PowerShell 5.1 (`powershell`) | Windows |
| PowerShell 7 (`pwsh`), see [PowerShell 7](#powershell-7) | Windows, with an agent of this release or later |
| Command Prompt (`cmd`, a batch file) | Windows |
| Bash, POSIX `sh`, Python 3 | Linux |

A script runs only on devices of its shell's platform: the device picker
lists those, and a device's **Run script** lists only scripts for it.

Installing, updating and removing software has a form of its own, which
runs EasyRMM's scripts for each package manager: see
[Installing, updating and removing software](software.md).

## The library

Every script belongs to one level, chosen when it is added:

| Level | Runs on | Who can add and change it |
|---|---|---|
| Shared | Devices in every organization | Super Administrators |
| Organization | Devices in that organization and its sites | Organization Administrators of it (and Super Administrators) |
| Site | Devices in that site | Site Administrators of it and above |

Anyone with `script.view` sees the shared library and the scripts of the
organizations and sites their roles cover. Technicians and above
(`script.run`) can run them on the devices they support. See
[RBAC](../security/rbac.md) for the full role table.

A script has a name (unique within its level), an optional description, a
shell, a body of up to 64 KiB and a default timeout (1 second to 4 hours).
Windows line endings in the body are converted to Unix ones (the agent
writes `cmd` scripts with Windows ones again). Adding, changing
and deleting scripts is audited with the body's SHA-256.

### Scripts that install updates

Where the patching engine patches devices ([Patching](patching.md)),
updates should come from it. Updates a script installs skip the patch
policy, its maintenance window and exclusions, and the engine sees them only
at the next scan. People who can see patching get a warning naming each
line that does one of these:

| Shell | Lines that warn |
|---|---|
| Both PowerShells, cmd | Installing Windows updates: PSWindowsUpdate (`Install-WindowsUpdate`, `Get-WindowsUpdate -Install`, `Get-WUInstall`), the Windows Update Agent API (`CreateUpdateInstaller`), `usoclient StartInstall`/`ScanInstallWait`/`ResumeUpdate`, `wuauclt /updatenow` |
| Both PowerShells, cmd | Installing update packages: `wusa` with an `.msu`, `dism /add-package`, `Add-WindowsPackage` |
| Both PowerShells, cmd | Writing Windows Update policy (`Policies\Microsoft\Windows\WindowsUpdate`) with `Set-ItemProperty`, `New-Item`, `reg add` and the like |
| Bash, sh, Python 3 | Upgrading every package: `apt`/`apt-get`/`aptitude` `upgrade`, `dist-upgrade`, `full-upgrade`; `dnf`/`yum`/`microdnf` `upgrade`, `update`, `distro-sync`; `zypper update`, `patch`, `dup`; `pacman -Syu`; `apk upgrade`; `unattended-upgrade` |
| Bash, sh, Python 3 | Upgrading to a new release (`do-release-upgrade`); turning on automatic updates (`systemctl enable`/`start` of unattended-upgrades, dnf-automatic or yum-cron, `dpkg-reconfigure unattended-upgrades`, `dnf-automatic`, `yum-cron`) |

Python scripts are checked through their string literals, as in
`subprocess.run(["apt-get", "-y", "upgrade"])`. Comments are skipped. These
do not warn: updating one named package (`apt-get install --only-upgrade
nginx`, `dnf update nginx`), checking for updates without installing them,
and application updates with winget or Chocolatey.

The warning appears while the script is edited, on its page, and when it is
about to run. It is a check on the text, so a script can install updates in
ways it does not recognize. Nothing is refused.

## Running a script

From a script's page, **Run** asks for the devices; from a device's page,
**Run script** asks for the script. Both then take:

* **Arguments**, one per line, passed to the script exactly as typed, with
  no shell expansion: `$1`, `$2` and so on, or `sys.argv[1:]` in Python. At
  most 32, each up to 1 KiB. Arguments are stored with the job. People who
  hold `job.view_sensitive` can read them, and each read is recorded (see
  [Who sees output and arguments](#who-sees-output-and-arguments)). They
  are also on the device's command line and in its logs. **Never pass
  passwords or keys as arguments.**
* **Timeout**, the script's default unless changed for this job.
* **Wait for offline devices**, 1 hour to 7 days (24 hours by default). A
  device that does not come online in that time is marked *Expired*.

One job can target up to 500 devices. Every device must have the agent, be
covered by the script's level, and be one where the person running it holds
`script.run`; otherwise the job is refused and the reason names the device.

The job keeps its own copy of the script. Changing or deleting the script
afterwards does not change what a job runs, and a job's page shows the exact
script it ran. **Run again** on a job's page starts a new job with the
library's current version, after showing the devices and arguments again.
It is offered only to people who can read the job's arguments, since
running it without them would run something else.

Each device's run is recorded in the audit log as *Ran script*, with the
script's hash and the number of arguments but not their values.

## Who sees output and arguments

What a script prints, and the arguments it was given, can hold secrets: a
recovery password, a token, a key. They have a permission of their own,
`job.view_sensitive`, separate from `job.view`, which shows the jobs and
runs themselves ([ADR-0063](../architecture/adr/0063-who-sees-job-output-and-arguments.md)).

* **Technicians and above** hold it where their role is: Technician, Site
  Administrator, Organization Administrator and Super Administrator. A
  Technician sees other technicians' output in the same organization or
  site.
* **Read-Only does not.** A Read-Only user still sees every job and run in
  their scope: the status, the exit code, the error text the agent or the
  server wrote, when it ran and how long it took, who started it, the
  script as run, and how many arguments it had. Where the output and the
  argument values would be, the console says *Hidden: needs permission to
  see job output* (or *job arguments*).
* **Every read is recorded** in the audit log, super administrators'
  included: *Viewed job output* under the run's organization, site and
  device, and *Viewed job arguments* under each organization of the job's
  runs. A refused read is recorded as *Denied*, at most once per user,
  read and target in 10 minutes, and **at most 20 times per user in 10
  minutes**: after 20, that user's further refusals are not recorded until
  the 10 minutes pass. A gap in *Denied* records is therefore not proof
  that nobody tried. The records hold sizes and names, never the output or
  the values. The console reads a run's output once each time its page is
  opened, never in the background.
* **Remove output** on a run's page empties a finished run's output at once,
  for everyone. It needs `job.view_sensitive` and `job.manage` at the run's
  site, and is recorded as *Removed job output*. Backups made before keep
  the output.
* **Output is kept for less time than the job**: see [Retention](#retention).

### Downloading output and results

Output and results can be downloaded as files
([ADR-0064](../architecture/adr/0064-remote-powershell-management.md)).
Each output download is a read like opening the run's page: it needs
`job.view_sensitive` at the run's site and is recorded, each time, as
*Downloaded job output*, with what was downloaded.

| Where | Button | What you get | Needs |
| --- | --- | --- | --- |
| A run's page, beside **Copy** on a stream | **Download** | That stream as a text file | `job.view_sensitive` at the run's site |
| A run's page, on the Output card | **Download run** | The run as JSON: device, organization, site, script, SHA-256, shell, status, exit code, error, times, the program it used, and both streams | `job.view_sensitive` at the run's site |
| A job's page, on the Devices card | **Download output (ZIP)** | A folder for each finished run you may read (`stdout.txt`, `stderr.txt`, `result.json`), and `runs.csv` listing every run you see and whether its output is in the archive | `job.view_sensitive` at the site of at least one finished run |
| A job's page, on the Devices card | **Download results (CSV)** | One row per run you see: device, organization, site, status, exit code, error, times, the program the run used (name, version, architecture and path) and run ID. **No output** | `job.view` |

* **The archive records before it sends.** Opening the archive records one
  *Downloaded job output* for each run whose output goes in, and commits
  those records before the first byte is sent; if they cannot be written,
  nothing is sent. Runs at sites where you lack `job.view_sensitive` are
  listed in `runs.csv` as *Hidden: needs permission to see job output*,
  without their files. A run whose output is removed between the records
  and its turn in the archive, or that is purged or moved to a site where
  you may not read it meanwhile, is listed as *Removed*, without its
  files. A run that printed nothing has empty files and no record. The
  records let the archive read the output for a day; the database's clock
  dates them and decides.
* **Six archives at once, then one every 10 seconds.** Each person may
  download six jobs' archives at once, then one every 10 seconds: up to 11
  in the first minute, and six a minute after that. Another is answered
  *429 Too Many Requests* with `Retry-After: 10` before anything is read
  or recorded; the browser shows that download as failed, and it works
  again a few seconds later. Each archive writes up to 500 audit records,
  which is what the limit bounds. Each server process keeps the limit in
  memory: restarting the server starts it again, and with several servers
  each allows that much.
* **Refusals.** Someone without `job.view_sensitive` anywhere in the job is
  refused the archive, recorded as *Denied* on the job under each
  organization of the runs they see, within the bound above.
* **The results are an export**, recorded as *Downloaded job results* once
  for each organization whose runs they hold, under the site when those
  runs share one. Cells that a spreadsheet would read as a formula start
  with an apostrophe, as in [reports](reports.md).
* **File names** are made of the device name (letters, digits, `.`, `_`
  and `-`; anything else becomes `_`) and the run's ID, so two devices of
  the same name never collide.
* **A downloaded file is outside EasyRMM.** Removing a run's output or
  retention emptying it does not reach copies already downloaded; treat a
  secret in a download as you would one in the output.

**Never print secrets** (passwords, tokens, keys, recovery passwords) in a
script's output if you can avoid it. Everyone who holds `job.view_sensitive`
in the site can read them until the output is removed, backups keep them,
and they pass through the agent's journal on the device. If a script must
print one, remove the run's output once the secret is used, and change the
secret if others could have read it.

**BitLocker and LUKS recovery keys** will have a keystore of their own, with
its own permission and every read recorded. It is planned, not built. Until
then, a recovery key retrieved by a script is in that run's output: remove
it after use. For BitLocker, add a new recovery password and remove the old
one once it has been used.

**After upgrading from a version before this.** Reads before the upgrade
left no record, and every Read-Only user of a site could read its output
and arguments. Treat a secret that a job printed, or that was passed as an
argument, within the job retention before the upgrade as seen, and change
it.

What this does not cover: whoever can run scripts or open a terminal at a
site can print any secret on an online device again; super administrators
and the server's operator can read the database; and once output is shown,
the record says who opened it, not what they did with it.

## What happens on the device

The agent checks for work continuously (a long poll), so an online device
starts a script within a second or two.

Before running anything, the agent verifies the job's Ed25519 signature
against the job key it pinned when it enrolled, and checks that the job is
for this device and has not expired. A job that fails these checks is
reported as failed and never runs.

On **Windows** the script runs:

* as **LocalSystem**, the EasyRMM Agent service's account;
* Windows PowerShell scripts with `powershell.exe -NoLogo -NoProfile
  -NonInteractive -ExecutionPolicy Bypass -File script.ps1 <arguments>`,
  saved as UTF-8 with a byte order mark so non-English text survives.
  Arguments arrive in `$args` or a `param()` block; `exit <n>` sets the exit
  code, and an uncaught error ends the script with code 1. PowerShell 7
  scripts run the same way with `pwsh.exe` ([PowerShell 7](#powershell-7));
* `cmd` scripts as a batch file, `cmd.exe /D /E:ON /V:OFF /S /C
  "script.cmd" "<argument>" …`, saved with Windows line ends in the console
  code page. Arguments arrive as `%1`, `%2` (`%~1` without the quotes) and
  cannot contain `%`, double quotes or line breaks: cmd expands `%variables%`
  even inside quotes, so such an argument could end its quotes and run a
  command of its own. `exit /b <n>` sets the exit code;
* in a new, empty folder under `%ProgramData%\EasyRMM\Agent\jobs\work\`,
  which is also `TEMP` and is removed afterwards;
* with the service's environment (Windows' system environment) without
  the agent's own `EASYRMM_*` settings, plus `EASYRMM_JOB_ID` and
  `EASYRMM_RUN_ID`;
* without a window, inside a job object: at the timeout, or when the job is
  canceled, Windows ends the script and every process it started at once.

Output in the console code page is converted to UTF-8.

On **Linux** the script runs:

* as the agent's user, **root** on a standard install;
* with the chosen interpreter (`bash`, `sh` or `python3`), the first found
  in `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`
  and `/bin`; a `#!` line is ignored;
* in a new, empty working directory under
  `/var/lib/easyrmm-agent/jobs/work/`, which is also `$HOME` and is removed
  afterwards;
* with a minimal environment: `PATH`, `HOME`, `LANG=C.UTF-8`,
  `EASYRMM_JOB_ID` and `EASYRMM_RUN_ID`. Nothing else from the agent's
  environment is passed on;
* with nothing on standard input (`/dev/null`);
* at most four at a time per device; further runs wait their turn.

When the timeout passes, or the run is stopped, the agent sends `SIGTERM` to
the script's whole process group, then `SIGKILL` 10 seconds later, so child
processes are stopped too. Processes that leave the group on purpose (for
example with `setsid`) are not followed.

Output is kept up to **256 KiB per stream**: the first and last 128 KiB of
standard output and of standard error, with a note in the middle saying how
much was left out. Output is sent when the script ends; it is not streamed
while it runs.

The agent records each run, output included, in a journal under its state
folder until the server has its result, then deletes the file:
`/var/lib/easyrmm-agent/jobs/journal/` on Linux (root only), and
`%ProgramData%\EasyRMM\Agent\jobs\journal\` on Windows (SYSTEM and
Administrators only). Whoever can read it can read the device's own key
beside it. If the agent restarts while a script runs, the run is reported as
failed ("The agent restarted while the script ran.") rather than run a
second time. Results the server could not take yet are sent again later.

## PowerShell 7

`pwsh` scripts run in PowerShell 7
([ADR-0064](../architecture/adr/0064-remote-powershell-management.md));
`powershell` scripts still run in Windows PowerShell 5.1, unchanged.

### Which PowerShell 7 runs

A script runs as LocalSystem, so the agent runs only a PowerShell 7 that no
standard user can change:

* **Where it looks**: `Program Files\PowerShell\<version>` and `Program
  Files (x86)\PowerShell\<version>`, where Microsoft's MSI and ZIP put it.
  Never the `PATH`, a user's folders or a .NET global tool: a program
  planted there would run as SYSTEM.
* **Which one**: the newest stable PowerShell 7 or later built for the
  computer's processor; on ARM64, an x64 build when no ARM64 one is
  installed. Previews, PowerShell 6, 32-bit (x86) builds (which see the
  32-bit registry and `SysWOW64`) and Microsoft Store installs are listed
  on the device and never run.
* **Who can change it**: before each run, `Program Files`, `Program
  Files\PowerShell`, the install's folder, every file and folder in it and
  `Program Files\PowerShell\Modules` must be changeable only by
  Administrators, SYSTEM and TrustedInstaller, and none may be a link,
  junction or other reparse point. So must the module folders and
  configuration files the run reads (below), except that in Windows
  PowerShell's two module folders, and only there, a file may have more
  than one hard link, as Windows keeps its own modules there. Files
  Windows compressed (`compact /exe`) or deduplicated count as plain
  files.
* **The folders above them**, up to the drive's root, must not let anyone
  else replace them: delete them, delete what they hold, or change their
  permissions or owner. Where a module folder does not exist yet, no one
  else may create folders where it would be. The drive's root may let
  users create folders, as `C:\` does by default.
* **No one may be writing them**: a program that opened a file to write
  before its permissions were fixed could still change it, so a file open
  in another program that may write to it, or that it holds so that no one
  else may, fails the check. From the check until Windows has created the
  run's process, the agent holds `pwsh.exe` and the install's libraries
  open so that no one can change them; the process loads its libraries
  after that, from files only administrators may change.

An install that fails is not used, and the device says which file and why.
**After fixing permissions, restart the computer**: a program that opened a
file before the fix keeps what it opened until it closes it, including a
handle that may change the file's permissions or owner, which the check
cannot see, and a restart closes everything. A user who can read a file can
also hold it open, or lock it, so that the agent cannot check or read it;
the install is then *Found, not usable* (below), so PowerShell 7 runs on the
device use another install that passes every check, or fail while they hold
it, without falling back, and they gain no way to change what runs.

A device's **Hardware** tab lists Windows PowerShell and every PowerShell 7
the agent found: the one PowerShell 7 scripts run in, and why each other is
not used. An agent of an earlier release reports none and says so.

**Found, not usable**: an install is *blocked* when its own files pass
while a module folder or configuration file its runs would read does not,
when a file of it is open in another program, or when the agent could not
read or check it (*Could not be checked: …*); so is `Program Files\PowerShell`
itself where the agent cannot list it, which the Hardware tab lists as that
folder, not as PowerShell 7 missing. Runs use another install where one
passes every check. Otherwise PowerShell 7 scripts fail there, **and do not
fall back to Windows PowerShell 5.1 even where the script allows it**:
Windows PowerShell loads from Windows PowerShell's module folders too, so a
folder that fails would be loaded by the fallback as well, and anyone who
may read a file can keep the agent from reading it. A script falls back
only where there is no `Program Files\PowerShell`, or every install in it is
not used for a reason of its own (a Store install, a preview, x86,
PowerShell 6, a file others may change). The Hardware tab says *Found, not
usable* with the reason, and the run dialog warns that the script fails
there. Fix what the reason names, or close the program that holds the file,
restart the computer, and the next inventory (within the hour, or after the
next job) shows the result.

**Microsoft Store installs are not run.** Since PowerShell 7.6, `winget
install --id Microsoft.PowerShell` installs the Store (MSIX) package by
default. Install the MSI instead, from Microsoft's release page or with
`winget install --id Microsoft.PowerShell --installer-type wix` (for a
release that has an MSI: PowerShell 7.7, stable since 2026-11-10, has
none, only ZIPs and the MSIX; unpack its ZIP into
`Program Files\PowerShell\7` as an administrator). Whether Store installs
should be run is being reviewed again
([ADR-0064](../architecture/adr/0064-remote-powershell-management.md#powershell-7-on-the-computer)).

### Where PowerShell 7 is missing

Each `pwsh` script says what happens on a device with no usable PowerShell
7, under **Where PowerShell 7 is missing**:

* **Fails the run** (the default): the run fails without an exit code, with
  "PowerShell 7 is not installed on this device (looked in …). The script
  was not run.", or, where installs were found and none can be used, "No
  PowerShell 7 on this device can run scripts (looked in …; found …)" with
  each install's reason.
* **Runs in Windows PowerShell 5.1**: the script runs exactly as a
  `powershell` script would, and the run records that it fell back. Choose
  it only for scripts written to run in both: syntax 5.1 lacks (`??`, `?.`,
  `&&`, the ternary operator) stops a script before it starts, but commands
  that behave differently (the encodings of `Out-File` and `Set-Content`,
  `ConvertFrom-Json`, web requests) change what it does without an error.
  It does not apply where PowerShell 7 is found but blocked (above): the
  run fails with "PowerShell 7 would load modules from …; the script was
  not run.", "PowerShell 7 would read its configuration from …", "… is
  open in another program that may write to it; the script was not run."
  or "… could not be checked: …; the script was not run."
  Windows PowerShell gets the module path a PowerShell 7 run gives its
  Windows PowerShell session (below), not the computer's `PSModulePath`;
  its module folders, and the system account's own
  `Documents\WindowsPowerShell\Modules`, are checked first, and one that
  fails stops the script: "Windows PowerShell would load modules from …;
  the script was not run." Windows PowerShell adds a folder of its own to
  a module path equal to the computer's or the system account's
  `PSModulePath`, so where the computer has Windows' default the agent
  gives the same two folders with a trailing backslash on the first, and
  a script sees `C:\Program Files\WindowsPowerShell\Modules\`. A
  `PSModulePath` in the registry that names a variable the agent cannot
  expand as Windows PowerShell would (`%TEMP%`, `%TMP%`, an `EASYRMM_`
  variable, `%PSModulePath%`, PowerShell 7's two, or one the agent's
  environment does not set) stops PowerShell 7 runs and the fallback:
  "Windows PowerShell would be given a module path it may not keep as
  given: the computer's PSModulePath names %TEMP%, …".

The setting is part of the script, copied into each job; whoever runs the
script sees it and cannot change it. A job is not refused because a
device's last inventory listed no usable PowerShell 7, since that can be an
hour old and the agent decides when the run starts; the run dialog warns
instead ("3 of 40 devices reported no usable PowerShell 7 at their last
inventory; this script fails there", and for blocked installs "2 of 40
devices have PowerShell 7 found, not usable: …, so this script fails
there").

### Agents that cannot run it

An agent says, each time it asks for work, which kinds of job its build
takes; agents of this release on Windows take PowerShell 7 scripts. The
server keeps that for the build that said it:

* a PowerShell 7 job is never sent to an agent that has not said it takes
  one. Starting one on such a device is refused with the reason: "PC-12's
  agent cannot run PowerShell 7 scripts; update the agent." or "PC-12's
  agent has not yet said whether it can run PowerShell 7 scripts; try again
  in a minute, and update the agent if it still has not." The device
  picker leaves such devices out and counts them;
* **agents of 1.0.0-rc.4 and earlier never say**: update them to run
  PowerShell 7 scripts. Every other job runs on them as before;
* after an agent updates, it says again within a minute of starting. A run
  waiting for an agent that stopped taking PowerShell 7 jobs says why on its
  page, and expires with that reason. So does a run an agent took and had
  not started when it changed versions, as a rollback after a failed update
  does: it is not sent again until the version it runs says it takes
  PowerShell 7 scripts;
* **while upgrading several server instances that share a database**, one
  still on the release before sends PowerShell 7 jobs to any agent and
  without their **Where PowerShell 7 is missing** setting: an agent of the
  release before refuses them ("the job is malformed"), and an agent of
  this release runs them as scripts that do not fall back. Upgrade every
  instance before running PowerShell 7 scripts.

### How it runs

As a Windows PowerShell 5.1 script does (see
[What happens on the device](#what-happens-on-the-device)), with
`pwsh.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File
script.ps1 <arguments>` and three changes to the environment:

* **Modules** load from five checked folders only. PowerShell 7 builds its
  module path from the system account's own folder, `Program
  Files\PowerShell\Modules` (or what the install's `powershell.config.json`
  names, which must exist; `%variables%` there must be set in the run's
  environment, and not be `TEMP`, `TMP` or `EASYRMM_…`, which each run
  sets for itself), its own `Modules` and Windows PowerShell's two,
  in `Program Files` and `System32`; the agent checks each like the
  install, and sets `PSModulePath` to Windows PowerShell's two, so the
  system environment's `PSModulePath` and anything it names are not used.
  A module only Windows PowerShell can load (`ServerManager`, for
  example) still works: PowerShell 7 loads it in a Windows PowerShell 5.1
  process of its own, whose module path is those same two Windows
  PowerShell folders (seen on CI's runners).
* `POWERSHELL_TELEMETRY_OPTOUT=1`: otherwise PowerShell 7 sends usage data
  to Microsoft when it starts.
* `POWERSHELL_UPDATECHECK=Off`.

Exit codes follow the same rules: `exit <n>` sets it, an uncaught error
gives 1. **Group Policy can still stop a script**: `-ExecutionPolicy Bypass`
sets the process's policy, which a machine or user policy from Group Policy
overrides. PowerShell 7 has a policy setting of its own and may follow
Windows PowerShell's, so a computer can block one edition and not the
other. `AllSigned` and Constrained Language Mode stop scripts in either
edition, with PowerShell's error in standard error; so can an EDR product or
AMSI.

### The program each run used

Every run records the program the agent started: edition, version,
architecture and path, read from the file just before it starts, and
whether it fell back to Windows PowerShell 5.1. It is on the run's page
("PowerShell 7.6.10, 64-bit" and the path), in the **Program** column of
the job's runs, in the results CSV and in every download, for everyone with
`job.view`, Read-Only included. Windows PowerShell's version is its
registry's major and minor version with its engine's build and revision, as
`$PSVersionTable.PSVersion` shows it. `cmd` and the Linux shells record the
path only. A run from an agent of an earlier release says *Not reported by
this agent's version*.

## Statuses

| Status | Meaning |
|---|---|
| Queued | Waiting for the device to pick it up |
| Delivered | The device has it and is about to start it. Not started within 2 minutes, it is delivered again. A PowerShell 7 run whose agent changed versions meanwhile waits until that version says it takes PowerShell 7 scripts, and its page says so |
| Running | Running on the device |
| Succeeded | Exited with code 0 |
| Failed | Exited with another code, was killed by a signal, or could not start (for example, the interpreter is not installed) |
| Timed out | Ran past its timeout and was stopped |
| Canceled | Stopped from the console, before or while it ran |
| Expired | The device did not pick it up before the wait ran out |
| No result | It started, but the device reported nothing by the timeout plus 5 minutes. A result that arrives later still replaces it, without its output if the run's output was removed meanwhile |

**Stop job** cancels every run still open that you may cancel; **Stop run**
on a run's page cancels one. A run that has not started is canceled at once
and never runs. A running script is stopped the next time its device checks
in, within seconds when it is online. Whatever the script already changed
stays changed.

## Retention

* **Output** is emptied `EASYRMM_JOB_OUTPUT_RETENTION` after it arrived:
  by default `720h` (30 days), or the job retention when that is shorter.
  Set, it must be at least `24h` and at most `EASYRMM_JOB_RETENTION`, or
  the server does not start. The run, its status and exit code stay; its
  page says when the output was removed.
* **Finished jobs**, with their runs and arguments, are removed after
  `EASYRMM_JOB_RETENTION` (default `2160h`, 90 days; at least `24h`). Jobs
  with runs still open are kept.

Both are for the whole deployment. Emptied output leaves the database at
PostgreSQL's next vacuum; backups made before keep it as long as they are
kept. The audit log keeps its own record of every run for
`EASYRMM_AUDIT_RETENTION`.

## Troubleshooting

| What you see | What to check |
|---|---|
| Runs stay *Queued* | The device is offline, or its agent is older than this feature. On the device: `sudo easyrmm-agent status` and `journalctl -u easyrmm-agent` (Linux), or `& "$env:ProgramFiles\EasyRMM\Agent\easyrmm-agent.exe" status` and `%ProgramData%\EasyRMM\Agent\logs\agent.log` (Windows) |
| *Failed* with "The job's signature does not verify" | The device pinned another server's job key, for example after the server's database was replaced. Uninstall the agent and enroll it again |
| *Failed* with "… is not installed on this device." | Install the interpreter (`python3`, `bash`) or pick another shell |
| A PowerShell script ends with code 1 and its error in standard error | The script threw an error that nothing caught. Check standard error; `$ErrorActionPreference = 'Stop'` at the top makes every error stop the script |
| *Failed* with "PowerShell 7 is not installed on this device" or "No PowerShell 7 on this device can run scripts" | No usable PowerShell 7 was found. The device's **Hardware** tab lists what the agent found and why each is not used. Install the MSI (a Store install is not run), or let the script fall back to Windows PowerShell 5.1 if it was written for both |
| "… can be changed by …: not used" on the device or the run | A file or folder of the install lets someone other than administrators change it. Restore the install's permissions (reinstalling the MSI does), then restart the computer |
| "… is open in another program that may write to it: not used while it is" on the Hardware tab, or *Failed* with "… is open in another program that may write to it; the script was not run." | A program holds that file open to write it, or holds it so that no one else may. Close it, or restart the computer. Scripts that allow Windows PowerShell 5.1 do not run in it meanwhile |
| *Failed* with "Windows PowerShell would load modules from …; the script was not run." | A script that allows Windows PowerShell 5.1 fell back, and one of Windows PowerShell's module folders lets someone other than administrators change it. Fix what the reason names as below, then restart the computer |
| *Found, not usable* on the Hardware tab, or *Failed* with "PowerShell 7 would read its configuration from …" or "… names the module folder …, which does not exist" | What a PowerShell 7 run would load fails the check, so it fails there even for scripts that allow Windows PowerShell 5.1. Fix what the reason names (for a folder the configuration names, create it as an administrator or remove it from `powershell.config.json`), then restart the computer |
| "… can be replaced, or what it holds deleted, by …" or "… lets … create folders in it" | A folder above the install or a module folder lets someone else replace it. As an administrator, remove that account's right (`icacls "<the folder named>" /remove:g "<the account named>"`), or for an owner, make Administrators the owner (`icacls "<the folder named>" /setowner *S-1-5-32-544`), then restart the computer |
| *Failed* with "PowerShell 7 would load modules from …, and … can be changed by …; the script was not run" | A module some installer put in one of the module folders lets users change it, so any user could change what a SYSTEM script loads. Remove that module, or, as an administrator, give it the folder's permissions back: `icacls "<the folder named>" /reset /T` and `icacls "<the folder named>" /setowner *S-1-5-32-544 /T`. GitHub's Windows runner images ship `ImageHelpers` this way |
| "… agent cannot run PowerShell 7 scripts" or "… has not yet said whether it can" | The device's agent is from an earlier release, or has just started. Update the agent |
| A PowerShell 7 script fails under Group Policy's execution policy, `AllSigned` or Constrained Language Mode | The computer's policy stops scripts in that edition; PowerShell's error is in standard error. Sign the script or change the policy |
| "contains %, a double quote or a line break" when starting a job, or *Failed* with "A cmd script's arguments cannot contain %, double quotes or line breaks" | cmd cannot receive such an argument safely. Use a PowerShell script |
| *No result* | The device went offline or the agent stopped during the run. The script may or may not have finished; check the device |
