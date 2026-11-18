# Installing, updating and removing software

EasyRMM installs, updates and removes software on devices with the EasyRMM
agent by driving each device's package manager. Each request is a job, like
running a script ([Scripts and jobs](scripts-and-jobs.md)): it waits for
offline devices, reports each device's status, exit code and output, and
can be stopped. The design is in
[ADR-0028](../architecture/adr/0028-software-deployment.md).

| Package manager | Runs on | The package is named by |
|---|---|---|
| winget | Windows 10 (1809 and later), Windows 11, Windows Server 2025 | Its ID, as `winget search` shows it: `Mozilla.Firefox`, `7zip.7zip`, `Git.Git` |
| Chocolatey | Windows, once Chocolatey is installed | Its ID in the [community repository](https://community.chocolatey.org/packages) or your own feed: `7zip`, `googlechrome` |
| Linux package manager | Linux with apt-get, dnf, yum or zypper | The distribution's package name: `jq`, `nginx`, `postgresql-client` |

You need the **software.manage** permission on every device: technicians,
site administrators and organization administrators hold it; read-only
users do not.

## Asking for an action

* **One device**: on the device's **Software** tab, **Install software**.
  On Debian, Ubuntu and RPM-based devices, each package also has **Update**
  and **Uninstall**.
* **Many devices**: **Jobs → Install software**. Choose the package
  manager first; the device list then shows the devices of its platform
  where you may manage software. Changing to a package manager for the
  other platform clears the devices chosen.

Then choose:

* **Action**: *Install*, *Update* or *Uninstall*.
  * *Install* takes an optional **version** (`1.7.1-3`, `128.0`); empty
    installs the newest. With winget and Chocolatey, installing something
    already installed succeeds without changing it; use *Update* to move it
    to the newest version.
  * *Update* fails on a device that does not have the package, and succeeds
    on one that is already current.
  * *Uninstall* succeeds on a device that does not have the package.
* **Package**: its name as the package manager writes it: letters, digits
  and `. _ -` (winget and Linux also `+`, Linux also `:`), with no spaces.
* **Timeout**: one hour unless changed, up to four.
* **Wait for offline devices**: 1 hour to 7 days (24 hours by default).

A job can target up to 500 devices. Every device must have the EasyRMM
agent, run the package manager's platform, and be one where you hold
software.manage; otherwise nothing runs and the reason names the device.

The job's page shows the action, the package, and the script that ran.
**Run again** asks for the same action on the same devices.

Each device's action is recorded in the audit log as *Software action*,
with the package manager, action, package and version.

## What runs on the device

EasyRMM sends one of its own scripts and passes the action, package and
version to it as arguments. Nothing you type becomes part of a script. The
agent runs it as LocalSystem on Windows and as root on Linux, as it runs
any script.

* **winget** runs from the App Installer package's folder (LocalSystem has
  no winget of its own), from the `winget` source only, never prompting,
  and installs for every user of the computer (`--scope machine`).
  Packages that only install per user cannot be installed this way.
  "Restart needed" counts as success, with a message in the output.
* **Chocolatey** runs `choco install|upgrade|uninstall <id> -y`. "Restart
  needed" (exit codes 1641 and 3010) counts as success, with a message.
* **Linux** uses the first of apt-get, dnf, yum and zypper it finds.
  apt-get refreshes its package lists first, waits up to 10 minutes for
  another apt or dpkg to finish, and keeps configuration files you
  changed. Restarting services or the computer is left to you.

After the job ends, the agent reports its installed software again at its
next check-in, so the device's Software tab shows the change within a
minute or so.

## Troubleshooting

| What you see | What to check |
|---|---|
| *Failed*, exit code 2, "winget is not installed on this computer" | Windows Server 2019 and 2022 do not include winget. Use Chocolatey, or install App Installer |
| *Failed*, exit code 2, "Chocolatey is not installed on this computer" | Install Chocolatey first, for example with its install script as a [script job](scripts-and-jobs.md) |
| *Failed*, exit code 2, "This computer has none of the package managers EasyRMM uses" | The Linux device has none of apt-get, dnf, yum or zypper (Alpine and Arch are not supported) |
| *Failed*, exit code 3, "*package* is not installed." | *Update* applies to installed packages. Use *Install* |
| *Failed* with winget's "No package found matching input criteria" | The ID is wrong, or the package is not in the `winget` source. Check `winget search --exact --id <ID>` on a computer with winget |
| *Failed* with winget's "No applicable installer found" | The package has no installer for the whole computer. Install it another way |
| *Failed* with apt's "Unable to locate package" | The name is wrong, or its repository is not configured on the device |
| *Timed out* | Large installers can take more than an hour; ask again with a longer timeout. The package manager may have been stopped part-way: check the device |
