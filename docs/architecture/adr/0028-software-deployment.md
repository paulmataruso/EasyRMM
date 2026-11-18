# ADR-0028: Software deployment through package managers

* Status: Accepted (2026-11-16).
* Builds on: ADR-0017 (scripts and jobs), ADR-0018 (inventory),
  ADR-0020 (the Windows agent).

## Context
Installing, updating and removing software is most of what an MSP asks of
an RMM after remote access. Script jobs could already do it, but each
technician would write their own script per package manager, get the
non-interactive flags and exit codes wrong in different ways, and type
package names into script text, where a name is code. The `software.manage`
permission (technicians and above) existed in the role model with nothing
behind it.

Every platform EasyRMM supports has a package manager that installs
unattended: winget and Chocolatey on Windows, apt-get, dnf, yum or zypper
on Linux. EasyRMM does not need to host installers to be useful; it needs
to drive those tools correctly.

## Decision
* **A software action is a job.** It goes through the job pipeline of
  ADR-0017 unchanged: signed with the job key, delivered at the next poll,
  run once, reported, cancellable, kept for the same retention. Jobs gain a
  `kind` (`script` or `software`) and, for software, the action itself:
  `{action, manager, package, version}`.
* **The script is EasyRMM's, the package is an argument.** Each package
  manager has one fixed script compiled into the server
  (`server/internal/jobs/software/`): `linux.sh` (POSIX `sh`),
  `winget.ps1` and `chocolatey.ps1` (Windows PowerShell). The action,
  package and version reach the script as arguments; they never become
  script text. The server also accepts only conservative names, per
  manager: letters, digits and `. _ -` (winget and Linux also `+`, Linux
  also `:`), starting with a letter or digit so that a name cannot be read
  as an option, with no spaces or shell characters. A version, for
  installs only, is held to a similar rule (`. _ - + ~ :`).
* **Actions**: *install* (newest, or a given version), *update* (`upgrade`
  in the API; fails if the package is not installed), *uninstall*
  (succeeds if it is already absent).
* **Managers**:
  * **winget** (Windows). The agent runs as LocalSystem, which has no
    winget of its own, so the script runs the newest `winget.exe` in the
    App Installer package's folder. It works by exact package ID from the
    `winget` source, accepts the source and package agreements, never
    prompts, and installs for the whole computer (`--scope machine`).
    "No update available", "already installed" and "installed, restart
    needed" end successfully, the last with a message.
  * **Chocolatey** (Windows), which must already be installed. Exit codes
    1641 and 3010 (installed, restart needed) end successfully with a
    message.
  * **The system's package manager** (Linux): the first of apt-get, dnf,
    yum and zypper found. apt-get waits up to 10 minutes for the dpkg lock,
    keeps changed configuration files, and refreshes the package lists
    before an install or update; zypper's "installed, restart needed" codes
    end successfully.
* **Who and where.** Every device needs `software.manage` for the caller,
  an EasyRMM agent, and the manager's platform; as with script jobs, one
  device that fails a check stops the whole request and nothing runs. The
  default timeout is one hour (up to four), since installers are slow.
* **Audit**: `device.software_action` for each device, with the action,
  manager, package, version and job.
* **The inventory follows.** After any job ends, the agent collects its
  inventory at its next heartbeat instead of waiting for the hour, and
  uploads it if it changed (ADR-0018), so a device's Software tab shows
  the result within a minute or so.
* **API**: `POST /api/v1/jobs/software`; `GET /api/v1/jobs?kind=software`
  (or `script`). Devices report `canManageSoftware`.
* **Console**: a device's **Software** tab has **Install software**, and on
  Debian/Ubuntu and RPM-based devices, **Update** and **Uninstall** on each
  package. **Jobs** has **Install software** for many devices at once and a
  **Kind** filter. A software job's page shows the action and the script
  as run, and **Run again** asks for the same action on the same devices.

## Consequences
* EasyRMM installs only what the package managers can find. A private
  installer (an MSI on a share, a vendor download) still needs a script
  job; hosting installers and a package catalog are left for later, as is
  a policy that keeps software installed.
* EasyRMM does not install the package managers. winget comes with App
  Installer on Windows 10 1809 and later, Windows 11 and Windows Server
  2025, but not on Windows Server 2019 or 2022; Chocolatey is installed by
  its own script, which a script job can run. The scripts say so when the
  tool is missing.
* winget packages that only install per user cannot be installed this way,
  since `--scope machine` is required; Microsoft Store packages are not
  offered (`--source winget` only).
* Windows' installed-programs list names programs for people ("7-Zip 24.08
  (x64)"), not by package ID, so its rows have no Update or Uninstall: the
  dialog takes the winget or Chocolatey ID. dpkg and RPM names are the
  package manager's own, so those rows do. Alpine (apk) and Arch (pacman)
  are not managed.
* The scripts change with EasyRMM releases; each job keeps a copy of the
  script it ran and its hash, as script jobs do.
* The Linux script is tested against stand-ins for every package manager,
  including names that try to run commands. On the preview, through the
  console, a Debian 13 agent installed `jq` (7 seconds on the device; the
  Software tab listed it 26 seconds after the job ended), uninstalled it
  from its row (gone from the tab 57 seconds later), and an update of the
  now missing package failed with exit code 3 and "jq is not installed.";
  the audit log recorded all three. The Windows scripts have not yet been
  run on Windows, and their exit-code handling follows winget's and
  Chocolatey's documentation, not observation.
