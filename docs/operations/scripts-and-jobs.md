# Scripts and jobs

EasyRMM keeps a library of scripts and runs them on devices that have the
EasyRMM agent. Running a script on one or more devices is a **job**; each
device's part of it is a **run**, with its own status, exit code and output.
The design is in [ADR-0017](../architecture/adr/0017-scripts-and-jobs.md).

| Shell | Runs on |
|---|---|
| PowerShell (Windows PowerShell 5.1) | Windows |
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
| PowerShell, cmd | Installing Windows updates: PSWindowsUpdate (`Install-WindowsUpdate`, `Get-WindowsUpdate -Install`, `Get-WUInstall`), the Windows Update Agent API (`CreateUpdateInstaller`), `usoclient StartInstall`/`ScanInstallWait`/`ResumeUpdate`, `wuauclt /updatenow` |
| PowerShell, cmd | Installing update packages: `wusa` with an `.msu`, `dism /add-package`, `Add-WindowsPackage` |
| PowerShell, cmd | Writing Windows Update policy (`Policies\Microsoft\Windows\WindowsUpdate`) with `Set-ItemProperty`, `New-Item`, `reg add` and the like |
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
  runs. A refused read is recorded as *Denied*. The records hold sizes and
  names, never the output or the values. The console reads a run's output
  once each time its page is opened, never in the background.
* **Remove output** on a run's page empties a finished run's output at once,
  for everyone. It needs `job.view_sensitive` and `job.manage` at the run's
  site, and is recorded as *Removed job output*. Backups made before keep
  the output.
* **Output is kept for less time than the job**: see [Retention](#retention).

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
* PowerShell scripts with `powershell.exe -NoLogo -NoProfile
  -NonInteractive -ExecutionPolicy Bypass -File script.ps1 <arguments>`,
  saved as UTF-8 with a byte order mark so non-English text survives.
  Arguments arrive in `$args` or a `param()` block; `exit <n>` sets the exit
  code, and an uncaught error ends the script with code 1;
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

## Statuses

| Status | Meaning |
|---|---|
| Queued | Waiting for the device to pick it up |
| Delivered | The device has it and is about to start it. Not started within 2 minutes, it is delivered again |
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
| "contains %, a double quote or a line break" when starting a job, or *Failed* with "A cmd script's arguments cannot contain %, double quotes or line breaks" | cmd cannot receive such an argument safely. Use a PowerShell script |
| *No result* | The device went offline or the agent stopped during the run. The script may or may not have finished; check the device |
