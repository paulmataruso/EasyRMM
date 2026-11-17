# EasyPatch agent for macOS (experimental)

> **Experimental: the macOS agent is in development and not for production use.**
> It was added in 1.9.0. The project builds and unit-tests it (against sample `softwareupdate`
> output), but has not yet used it to patch a real Mac. Behaviour, packaging and the console
> pages for Macs can change in any release. Use it only on test Macs you can wipe, never on Macs
> people depend on, and expect bugs.

The macOS agent is a launchd daemon (`com.dhitechnical.easypatch.agent`) that reports the updates
Apple's software update service offers the Mac (`softwareupdate`) and installs the ones an
administrator approves. It uses the same server, enrollment, policies, jobs and console as the
Windows and Linux agents. The agent:

* **restarts the Mac only when an administrator asks for it**, once or through a restart
  schedule set in policy. Installing an update never restarts the Mac (`softwareupdate` is never
  run with `--restart`). It reports when an update it installed is waiting for a restart;
* **only installs updates Apple offers the Mac**, by the label `softwareupdate` listed. It does
  not install other software or change software update settings. A newer major macOS release is
  classified as an *Upgrade*, so it is installed only when a policy includes upgrades or an
  administrator selects it;
* cannot run commands. It executes the update scan, inventory refresh, install updates and
  restart jobs, plus agent updates and removing itself (see [Uninstalling](#uninstalling)).
  There is no menu bar icon, so preset messages to signed-in users are Windows only. Removing an
  installed update and downloading updates before the maintenance window are Windows only too.

## Known limitations

Read these before installing it anywhere.

| Limitation | What it means |
|---|---|
| **Apple silicon cannot install macOS updates** | On Macs with Apple silicon, Apple lets only a *volume owner* (an administrator typing their password in System Settings) or an MDM server install updates that need a restart, which includes every macOS update. The agent does not ask for or store passwords, so it fails those updates at once with `macos_owner_required` and installs only updates that need no restart (for example command line tools). Use System Settings or your MDM for macOS updates on Apple silicon; EasyPatch still reports them. Intel Macs install them |
| No on-screen warning before a restart | `shutdown -r` restarts the Mac at the end of the grace period without a dialog. Signed-in users can lose unsaved work. Restart only when nobody is using the Mac |
| Unsigned package | The `.pkg` and the agent are not signed with an Apple Developer ID or notarized (the agent binary is ad-hoc signed). Gatekeeper blocks opening the package from Finder; the install script installs it with `installer` instead |
| Pending restarts | Only updates the agent installed itself are reported as waiting for a restart. A restart started from System Settings or MDM is not detected |
| Security classification | `softwareupdate` does not say which updates fix vulnerabilities. EasyPatch classifies macOS updates within the installed major release and Background Security Improvements as *Security*, newer major releases as *Upgrade*, and everything else (Safari, command line tools) as *Other*. No CVEs are reported for Macs |
| Credential protection | The agent's private key is protected by file permissions only (root only, 0600); the keychain is not used |
| Server certificate | The Mac must trust the server's certificate (System keychain). Unlike the Windows agent, there is no option to pin a private certificate authority |
| Lifecycle | Apple publishes no end-of-support dates, so the console shows the support status of Macs as unknown |

## Requirements

* macOS 14 (Sonoma) or later, Intel (x64) or Apple silicon (arm64).
* An administrator account (`sudo`) to install it.
* HTTPS access to the EasyPatch server, and to Apple's software update servers (or your
  organisation's caching server).
* The server must offer a macOS package: copy `EasyPatchAgent-<version>-<arch>.pkg` and its `.sig`
  to `data/agent-packages` (see [installation.md](installation.md#6-offer-agent-packages)).

## Installing

### Deployment code: install script

*Deploy → Deployment codes → macOS (experimental)* shows the one-line installer for a code. Run it
in Terminal on the Mac:

```sh
curl -fsSL https://patch.example.com/downloads/install/macos/EPD-XXXXXXXXXXXXXXXX.sh | sudo sh
```

The script checks that it runs on macOS 14 or later, downloads the package for the Mac's
architecture, checks its SHA-256 against the value the server put in the script, writes
`/Library/EasyPatch/agent.conf` with the server address and deployment code, and installs the
package with `installer`. The Mac then appears under *Pending Approvals*. The script contains no
enrollment token.

### Enrollment token

Install the package, then enroll with a token (read from a file or standard input, never from
the command line). *Deploy → Enrollment tokens* shows the enroll command for a new token when the
server has a macOS package:

```sh
sudo installer -pkg EasyPatchAgent-1.10.0-arm64.pkg -target /
sudo easypatch-agent enroll --server https://patch.example.com --token-file /path/to/token
```

`easypatch-agent` is a symbolic link in `/usr/local/bin`; the program is
`/Library/EasyPatch/easypatch-agent`.

## What the package installs

| Path | Contents |
|---|---|
| `/Library/EasyPatch/easypatch-agent` | The agent (single self-contained executable, ad-hoc signed) |
| `/Library/EasyPatch/uninstall.sh` | Removes the agent (see [Uninstalling](#uninstalling)) |
| `/usr/local/bin/easypatch-agent` | Symbolic link to the agent |
| `/Library/LaunchDaemons/com.dhitechnical.easypatch.agent.plist` | The daemon. Loaded on installation and at every start of the Mac, restarted by launchd if it stops |
| `/Library/EasyPatch/agent.conf` | Bootstrap settings: `ServerUrl`, `DeploymentCode` or `EnrollmentToken`, `ProxyUrl`, `LogLevel`. Root only (0600). Written by `enroll` or the install script, not by the package. The token and deployment code are removed from it after enrollment |
| `/Library/EasyPatch/data` | Root only (0700): agent identity and state, logs, the software update ledger, downloaded agent updates |
| `/Library/Logs/EasyPatch/launchd.log` | Anything the daemon prints outside its own log (normally empty) |

The agent refuses to start when it is not root, when macOS is older than 14, or when another
agent process holds `/Library/EasyPatch/data/agent.lock`.

## How it works

**Scans.** `softwareupdate --list` lists what Apple offers the Mac. Output the agent does not
recognise (no network, a catalog error) fails the scan; it is never reported as "no updates".
Each update is identified by its product and version, so the same update is the same row on every
Mac. `softwareupdate` only lists what is missing, so the agent keeps a ledger
(`/Library/EasyPatch/data/softwareupdate-ledger.json`): an update that was listed and then
disappears is reported installed only when `softwareupdate --history` records that version, and
an older version of a product that is no longer listed is reported superseded by the newer one.

**Installations.** For each approved update the agent runs `softwareupdate --download <label>`,
then `softwareupdate --install <label>`, then lists again. The update counts as installed when it
is no longer listed. An update that needs a restart and is still listed counts as installed and
waiting for the restart only when `softwareupdate` said a restart is needed; the console shows it
as pending a restart, and the scan after the restart confirms it. Anything else fails the job item
with `softwareupdate`'s output. On Apple silicon, updates that need a restart fail with
`macos_owner_required` without being attempted (see [Known limitations](#known-limitations)).

**Restarts.** An administrator's restart job runs `shutdown -r now` or `shutdown -r +<minutes>`.
Cancelling a restart during its grace period stops the waiting `shutdown` process.

**Inventory.** `sw_vers`, `sysctl`, `scutil` and `system_profiler SPHardwareDataType` (model,
chip, serial number, hardware UUID, memory, whether the Mac is a virtual machine), and
`profiles status -type enrollment` (whether the Mac is enrolled in MDM).

## Updating the agent

macOS agents update themselves like the others, controlled by the *Agent updates* policy. An
agent is offered only `.pkg` packages of its own architecture, and is never downgraded. The agent
checks the release signature against the key built into it, downloads the package, checks its
size and SHA-256 and installs it with `installer -pkg <package> -target /` in the one-shot launchd
job `com.dhitechnical.easypatch.agent-update`, which keeps running when the package restarts the
daemon. The new agent reads the installer's exit code and completes the job. The package and the
installer output are kept in `/Library/EasyPatch/data/updates` (`install-<version>.log`).

## Command line

```text
Usage: easypatch-agent <command> [options]

  run                       Run the agent (default; used by the com.dhitechnical.easypatch.agent launchd daemon).
  enroll --server <url> (--token-file <path|-> | --deployment-code <code>) [--proxy <url>] [--force] [--no-start]
                            Enroll this computer. A token enrolls immediately; a deployment code
                            creates a request an administrator must approve in the console.
                            The token is read from a file, from standard input (--token-file -)
                            or from EASYPATCH_ENROLLMENT_TOKEN; it is never accepted as an argument.
  status [--json]           Show enrollment and agent status.
  scan [--json]             List the updates this Mac would report (runs softwareupdate --list;
                            installs nothing and does not contact the server).
  inventory [--json]        Show the hardware and macOS details this Mac would report (does not
                            contact the server).
  unenroll [--reason <text>]
                            Notify the server (best effort) and delete the agent identity.
  version                   Print the agent version.
```

The exit codes are those of the Linux agent ([linux-agent.md](linux-agent.md#command-line)).

## Logs

* `/Library/EasyPatch/data/logs/agent.log`: the agent log (rotated). Set `LogLevel=Debug` in
  `/Library/EasyPatch/agent.conf` and restart the daemon
  (`sudo launchctl kickstart -k system/com.dhitechnical.easypatch.agent`) for more detail.
* `/Library/EasyPatch/data/updates/install-<version>.log`: output of the last agent update.
* `/Library/Logs/EasyPatch/launchd.log`: crashes and anything else printed outside the log.
* `sudo launchctl print system/com.dhitechnical.easypatch.agent`: whether the daemon is running.

`softwareupdate` output sent to the server has credentials in URLs removed.

## Uninstalling

From the console: open the endpoint, **More → Uninstall agent…** and type the computer name to
confirm. The agent runs `/Library/EasyPatch/uninstall.sh` in the one-shot launchd job
`com.dhitechnical.easypatch.agent-uninstall` the next time it checks in.

On the Mac:

```sh
sudo /Library/EasyPatch/uninstall.sh
```

The script stops the daemon, runs `easypatch-agent unenroll` (so the server marks the endpoint as
decommissioned when it can be reached), and deletes `/Library/EasyPatch` (including the settings
and the agent identity), the daemon's plist, `/Library/Logs/EasyPatch`, the `/usr/local/bin`
link and the package receipt.

## Troubleshooting

| Symptom | What to check |
|---|---|
| `The agent is not enrolled and has no server URL` in the agent log | The package was installed without enrolling. Run `sudo easypatch-agent enroll` or the install script |
| The Mac does not appear under *Pending Approvals* | `sudo easypatch-agent status`, the agent log; that the Mac can reach the server (`curl -I https://patch.example.com/health/live`) and trusts its certificate |
| Updates shown in the console differ from what you expect | `sudo easypatch-agent scan` shows what the agent reports, without contacting the server |
| An install job item fails with `macos_owner_required` | Expected on Apple silicon for updates that need a restart. Install it in System Settings or with your MDM |
| An install job item fails with `softwareupdate_install_failed` or `softwareupdate_not_installed` | The job's error message (it includes `softwareupdate`'s output) |
| An agent update fails | `/Library/EasyPatch/data/updates/install-<version>.log` |

## Building from source

```sh
scripts/build-macos-packages.sh --version 1.10.0 --arch all
```

The script runs the agent tests, publishes the self-contained agent for osx-x64 and osx-arm64
(the .NET SDK ad-hoc signs it), builds the `.pkg` packages on Linux in a pinned container image
without network access, writes `.sha256` files and signs each package with the release key
(`~/.easypatch/easypatch-release-key.pem`, see
[Building from source](agent-installation.md#building-from-source)). The output is in
`artifacts/macos`. It needs the .NET 10 SDK and Docker; no Mac is needed.
