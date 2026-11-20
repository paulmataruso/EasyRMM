# The EasyPatch agent

The EasyPatch agent is the patching engine's agent on a managed computer:
a Windows service (`EasyPatchAgent`) or a Linux systemd service
(`easypatch-agent`). It reports which updates the computer is missing and
installs the ones its policy or an administrator approves. EasyRMM's own
agent installs and enrolls it, and it reaches the engine through EasyRMM's
TLS edge, on EasyRMM's name. How the engine works is in
[Patching engine](../architecture/patching-engine.md); the console side
is in [Patching](../operations/patching.md).

The agent:

* patches the operating system (Windows Update) or the packages installed
  from the distribution's repositories (apt, dnf), and, on Windows,
  approved applications with winget. It upgrades only what is installed
  and offered by the sources the computer is configured for;
* restarts the computer only for a restart job an administrator created,
  once or through a restart schedule in policy. Installing updates never
  restarts it;
* changes Windows Update policy values only for the groups an
  administrator manages in policy, never the WSUS server settings, and
  puts the original values back when that stops;
* cannot run commands. It carries out a fixed set of jobs: scan, inventory,
  install updates, download updates, remove an update, restart, preset
  messages, agent update and removing its own package;
* makes only outbound HTTPS connections. It needs no inbound port, VPN or
  port forwarding, and works behind NAT.

## Requirements

| | Windows | Linux |
|---|---|---|
| System | Windows 10, Windows 11, Windows Server 2016 or later, 64-bit (x64 or ARM64) | x86_64 or aarch64 with systemd and apt-get or dnf; glibc 2.27 or later |
| Runs as | LocalSystem | root (`UMask=0077`) |
| Network | Outbound HTTPS to EasyRMM's address. For winget, also `github.com` and `release-assets.githubusercontent.com` (otherwise it uses the engine's copy) | Outbound HTTPS to EasyRMM's address; apt and dnf use their own repositories and proxy settings |
| TLS | A certificate Windows trusts, or EasyRMM's own authority given at install | A certificate in the system store, or EasyRMM's own authority given at enrollment |
| .NET | Not needed: the agent is self-contained | Not needed |
| Restart detection on Red Hat | | `dnf needs-restarting` (`dnf-plugins-core` or `dnf-utils`); without it only a newer installed kernel is detected |

Linux distributions:

| Family | Distributions | Package manager | Tested by the project |
|---|---|---|---|
| Debian | Debian 11, 12, 13; Ubuntu 20.04, 22.04, 24.04, 26.04 LTS and interim releases | apt | Debian 12 and 13; Ubuntu 22.04, 24.04, 26.04 and 26.10 |
| Red Hat | RHEL 8, 9, 10, Rocky Linux, AlmaLinux and Oracle Linux 8 and later; CentOS Stream 9 and 10; Fedora | dnf 4 and dnf 5 | Rocky Linux 8 and 9, AlmaLinux 10.2 (x86-64-v2 build), Fedora 45 |

The family comes from `ID` and `ID_LIKE` in `/etc/os-release`. CentOS
Stream publishes no security advisories, so its updates are never
classified as security updates. Not supported: RHEL and CentOS 7, SUSE,
Arch, Alpine, systems without systemd, 32-bit systems.

## Installing it from EasyRMM

EasyRMM installs the EasyPatch agent on Windows and Linux devices that have
none ([ADR-0031](../architecture/adr/0031-easypatch-agent-install.md)):

* **Chosen devices**: in **Patching**, choose devices marked *No EasyPatch
  agent* and **Install EasyPatch agent…**, or **Install EasyPatch agent…**
  on a device's **Patches** tab. Needs `patch.manage`.
* **A whole organization**: **Settings → Patching engine**, Organizations,
  **Install automatically**. Needs `settings.manage`. It is on for new
  organizations. Every minute EasyRMM looks for devices in the organization
  without the agent, new ones included, and installs it; a failed
  automatic install is tried again an hour later, three times in all.

![Installing the EasyPatch agent: the EasyRMM agent receives a signed, device-bound install instruction in its heartbeat answer, downloads the package and checks its SHA-256, and installs it with a single-use token; the EasyPatch agent then enrolls with the patching engine and checks in every minute, all over HTTPS to EasyRMM's address](../images/diagrams/patching-agent-install.svg)

What happens:

1. At its next heartbeat the device's EasyRMM agent receives an
   instruction signed with EasyRMM's job key, bound to the device and valid
   for 15 minutes. It names the engine's address (EasyRMM's own), the
   newest package for the device with its size and SHA-256, a single-use
   enrollment token valid for an hour, and, when EasyRMM uses its own
   certificate authority, that authority.
2. The EasyRMM agent downloads the package over HTTPS and checks its size
   and SHA-256, then installs it:
   * Windows: `msiexec /i <package> /qn /norestart SERVERURL=<EasyRMM's
     address> [SERVERCACERT=<authority>] /l*v <log>`, then `EasyPatch.Agent.exe
     enroll --server <address>` with the token in the
     `EASYPATCH_ENROLLMENT_TOKEN` environment variable;
   * Linux: `apt-get install -y --no-install-recommends <package>` (with
     `apt-get update` and a second try if that fails) or `dnf install -y
     <package>`, then `/opt/easypatch/easypatch-agent enroll --server
     <address> --token-file - [--server-ca <file>]` with the token on
     standard input.

   The token is never on a command line. It is revoked if the install
   fails.
3. The result goes back with the next heartbeat. The EasyPatch agent shows
   up in the device's next inventory, and EasyRMM links the device to its
   endpoint ([Device links](../architecture/patching-engine.md#device-links)).

EasyRMM never installs a second EasyPatch agent, never re-enrolls one
(`--force`) and never upgrades one: the engine updates its own agents
([Updating the agent](#updating-the-agent)). One install runs at a time on
a device, for at most 20 minutes. The states an install goes through, and
what its failures mean, are in
[Installing the EasyPatch agent](../operations/patching.md#installing-the-easypatch-agent).

## How it reaches the engine

The agent's server address is EasyRMM's own. EasyRMM's edge forwards the
agent API and the package downloads (`/api/v1/agents/`,
`/downloads/agent/`, `/downloads/winget/`) to the engine on loopback, and
nothing else of it
([ADR-0039](../architecture/adr/0039-agents-on-easyrmms-name.md)). Every
request after enrollment is signed with the agent's own key
([Request signing](../architecture/patching-engine.md#request-signing)).

* **Certificates.** With a public certificate the agent uses the
  operating system's trust store. When EasyRMM is addressed by IP with its
  own authority (`EASYRMM_TLS_MODE=internal`), EasyRMM gives that
  authority to the agent: the MSI as `SERVERCACERT`, the Linux agent with
  `enroll --server-ca`
  ([ADR-0042](../architecture/adr/0042-agents-trust-easyrmms-authority.md)).
  The agent trusts it for its connection to EasyRMM only, nothing else on
  the computer, and still checks validity, purpose and name. Revocation is
  not checked for that authority. Certificate validation cannot be turned
  off. The agent keeps the authority it was installed with; if it is
  replaced, reinstall the agent. A Linux agent too old for `--server-ca` is
  enrolled without it, and the authority must be in the system store
  first.
* **Proxies.** EasyRMM sets none. On Windows the agent uses the `PROXYURL`
  MSI property or `enroll --proxy`, otherwise `HTTPS_PROXY`/`HTTP_PROXY` or
  the service account's WinINET settings, not WinHTTP (`netsh winhttp`);
  authenticating proxies are answered with the computer account. On Linux
  `enroll --proxy <url>` sets `ProxyUrl` in `/etc/easypatch/agent.conf`;
  proxy credentials are not supported.
* **Clock.** Requests carry a timestamp. The agent learns the server's
  time from each refusal and corrects its offset, so a wrong local clock
  does not stop it.

## Windows

### What is installed

| Item | Where |
|---|---|
| Program | `C:\Program Files\EasyPatch Agent\EasyPatch.Agent.exe` |
| Service | `EasyPatchAgent` ("EasyPatch Agent"), LocalSystem, automatic (delayed) start, restarted 60 seconds after a failure |
| Bootstrap settings | `HKLM\SOFTWARE\EasyPatch\Agent`: `ServerUrl`, `ProxyUrl`, `ServerCaCertificate`, and until enrollment `EnrollmentToken` or `DeploymentCode`; SYSTEM and Administrators only |
| Data | `C:\ProgramData\EasyPatch`, SYSTEM and Administrators only, inheritance off |
| Event source | *EasyPatch Agent* in the Application log |

The service re-applies both access lists at every start and refuses to
start if it cannot. In the data folder:

| Path | Contents |
|---|---|
| `agent.key` | The ECDSA P-256 private key, DPAPI-protected (LocalMachine); never sent or logged |
| `state\agent-state.json` | Enrollment state, held jobs, times, saved Windows Update values |
| `outbox\` | Reports waiting for delivery; they survive restarts and outages |
| `logs\agent.log` | Service log, 10 MB × 10 files |
| `logs\cli.log` | Log of `enroll` and `unenroll` |
| `logs\update-removal.log`, `logs\winget-setup.log`, `logs\uninstall.log` | DISM and installer logs of those jobs |
| `updates\` | Downloaded agent updates and `install-<version>.log` (kept 30 days) |
| `agent.lock` | Keeps a second agent process from running |

### MSI properties

| Property | Description |
|---|---|
| `SERVERURL` | `https://` address of the engine, which is EasyRMM's address. Required on a first install; kept on upgrade. EasyRMM sets it |
| `SERVERCACERT` | An authority (base64 DER) trusted for the connection to the server only. Kept on upgrade. EasyRMM sets it when it uses its own authority |
| `PROXYURL` | An outbound proxy such as `http://proxy.example.com:8080`. Kept on upgrade |
| `ENROLLMENTTOKEN` | An enrollment token; hidden from Windows Installer's property listings, deleted once used. EasyRMM does not use it: it passes the token to `enroll` in the environment instead |
| `DEPLOYMENTCODE` | A deployment code, whose enrollment waits for approval. Not used by EasyRMM |

The installer refuses a first install without an `https://` `SERVERURL`,
or with both `ENROLLMENTTOKEN` and `DEPLOYMENTCODE` (`msiexec` exit code
1603 with the launch condition in the log).

### Command line

From an elevated prompt:

```text
EasyPatch.Agent.exe status [--json]
EasyPatch.Agent.exe enroll --server <url> (--token <token> | --deployment-code <code>) [--proxy <url>] [--force] [--no-start]
EasyPatch.Agent.exe unenroll [--reason <text>]
EasyPatch.Agent.exe version
```

* `status` shows the service, enrollment status, server, endpoint id,
  credential, key fingerprint, last check-in, scan and inventory, held
  jobs and queued reports. `--json` is what EasyRMM's agent reads.
* `enroll` stops the service, writes the bootstrap settings, enrolls and
  starts the service again. On a computer already enrolled with the same
  server it does nothing and exits 0. `--force` tells the old server
  (best effort), deletes the identity and enrolls again. The token can
  come from `EASYPATCH_ENROLLMENT_TOKEN` instead of `--token`.
* `unenroll` tells the server (best effort, 30 seconds), deletes the key,
  state, queued reports and bootstrap settings, and leaves the service
  stopped. The MSI runs it on uninstall.

| Exit code | Meaning |
|---|---|
| 0 | Success (for `enroll`: active, waiting for approval, or already enrolled) |
| 1 | Failure (see `logs\cli.log`) |
| 2 | Invalid arguments or settings |
| 3 | Enrolled with a different server (use `--force`) |
| 4 | The server rejected the token or code |
| 5 | Not elevated |
| 6 | Server unreachable; settings were saved and the service keeps trying |
| 7 | Another agent process could not be stopped |

### Logs and events

`logs\agent.log` rotates at 10 MB and keeps 10 files. Tokens, keys and
signatures are redacted before anything is written. For more detail, set
the string value `HKLM\SOFTWARE\EasyPatch\Agent\LogLevel` to `Debug` and
restart the service; delete it to go back to `Information`.

| Event ID | Meaning |
|---|---|
| 1000 | The service could not start (access lists, elevation, a second instance) |
| 1001 | Enrollment waiting for approval (with the key fingerprint) |
| 1002, 1003 | Enrollment complete; refused or rejected |
| 1004, 1005 | The server revoked the credential (enroll again); credential rotated |
| 1010 | Restarting the computer for a restart job |
| 1011, 1012 | Windows Update settings applied, changed or restored; changed by another policy source, no longer re-applied |
| 1013, 1014, 1015 | Installing an agent update; agent updated (logged by the new version); agent update failed or refused |
| 1016, 1017 | Removing the agent for an uninstall job; uninstall failed |
| 1018, 1019 | winget installed; winget could not be installed |
| 1020, 1021 | An update removed; an update removal failed |

### Tray icon and status window

The service starts the tray (`EasyPatch.Agent.exe tray`) as the signed-in
user in every active session, within about 15 seconds of sign-in, and
again two minutes after it is closed. There is no startup entry. The tray
talks to the service over the named pipe `\\.\pipe\EasyPatchAgent` and
exits when the service stops. Windows 11 puts new icons in the hidden-icons
flyout (**^**) until the user moves them.

* **Icon and menu.** The tooltip shows the agent version and a one-line
  status; the menu shows the activity, the last check-in and whether a
  restart is pending. Preset messages appear as notifications. A restart
  request opens a small window with *Restart now* and, where allowed,
  *Postpone*.
* **Status window** (click the icon): a summary (up to date, updates
  available, restart required, installing, cannot reach the server, and
  so on), connection and update details, the current activity with its
  percentage, **Check in now**, **Check for updates** (a scan; it never
  installs anything) and the newest 200 log entries, first line only and
  redacted again. Both buttons are limited for the whole computer: a
  check-in every 30 seconds, an update check every 5 minutes and not while
  Windows Update is busy.
* **What users cannot do.** Change settings, install or remove anything,
  run commands or stop the agent. The pipe accepts only an answer to the
  current restart request and the three status-window requests, from
  interactive sessions; the session comes from Windows, not the message.
* **Hiding it.** Set **EasyPatch icon** to *Hide* under *Restarts and
  users* in the patch policy. The icon then appears only while a message
  or a restart request is shown, so users cannot open the status window.
  In a session without a tray, messages cannot be shown and countdowns use
  Windows' own shutdown warning.

## Linux

### What the package installs

| Path | Contents |
|---|---|
| `/opt/easypatch/easypatch-agent` | The agent, one self-contained executable |
| `/usr/sbin/easypatch-agent` | A link to it |
| `/usr/lib/systemd/system/easypatch-agent.service` | The service: `Type=notify`, `Restart=always`, `KillMode=mixed`, `UMask=0077`. Enabled and started on install, restarted on upgrade |
| `/etc/needrestart/conf.d/easypatch-agent.conf` | Keeps needrestart from restarting the agent while it installs packages |
| `/etc/easypatch/agent.conf` | Bootstrap settings (`ServerUrl`, `ProxyUrl`, `LogLevel`, and until enrollment the token or code), mode 0600, written by `enroll`, not by the package |
| `/var/lib/easypatch` | Mode 0700: identity and state, logs, package work files, downloaded agent updates |

The agent refuses to start when it is not root, on an unsupported
distribution, or when another agent process holds
`/var/lib/easypatch/agent.lock`. Its private key is encrypted with
`systemd-creds` and the host key on systemd 250 and later (Debian 12 and
later, Ubuntu 24.04, RHEL 9 and later), so a copy of `/var/lib/easypatch`
is useless without `/var/lib/systemd/credential.secret`; otherwise (Ubuntu
22.04, RHEL 8) file permissions protect it. Root can read it either way.

### How it scans and installs

* **Scans** refresh the package lists (`apt-get update`, `dnf makecache`)
  and list upgradable installed packages (`apt-get -s upgrade
  --with-new-pkgs`, `dnf check-update`). Held packages (`apt-mark hold`,
  dnf versionlock) are not offered. An upgrade from a `*-security` suite,
  or covered by a dnf security advisory, is a security update. On dnf the
  agent also reads the advisories' CVEs; on Debian and Ubuntu it reports
  each package's source package for the engine's Debian matching.
* **Installs** run one apt or dnf transaction for the approved packages at
  the exact versions the scan found, in the transient unit
  `easypatch-packages`, so an agent restart does not interrupt it. apt
  removes nothing and keeps locally changed configuration files; rpm
  writes `.rpmnew`. The agent waits up to 30 minutes for the dpkg lock, runs
  `dpkg --configure -a` once after an interrupted dpkg, and tries the
  packages one at a time when the transaction fails. An update counts as
  installed only when the package database shows the new version.
* **The server cannot name a package, version or repository.** It sends
  update ids; names, architectures and versions are validated and passed
  after `--`, without a shell. Credentials in repository URLs are removed
  from output sent to the server.
* **Restarts** are pending when `/run/reboot-required` exists, when `dnf
  needs-restarting -r` says so, or when a newer kernel of the running
  flavour is installed. A restart job runs `shutdown -r +<minutes>
  "<message>"`; cancelling runs `shutdown -c`.
* **History.** Linux has no update history like Windows; the device's
  history stays empty. The agent remembers upgrades it reported for 30
  days and reports them installed once the package database shows them,
  also when they were installed by other means.
* There is no tray, so preset messages, update removal and downloads
  before the window are Windows only.

### Command line

```text
easypatch-agent run                 the service (default)
easypatch-agent enroll --server <url> (--token-file <path|-> | --deployment-code <code>)
                [--proxy <url>] [--server-ca <file>] [--force] [--no-start]
easypatch-agent status [--json]
easypatch-agent scan [--json]       what the agent would report; installs nothing, contacts no server
easypatch-agent unenroll [--reason <text>]
easypatch-agent version
```

`enroll` never takes a token as an argument: it reads it from a file,
from standard input (`--token-file -`) or from
`EASYPATCH_ENROLLMENT_TOKEN`, and removes it from `agent.conf` after
enrollment. The exit codes are those of the Windows agent, with 5 meaning
not root and 7 busy.

### Logs

* `journalctl -u easypatch-agent`: information, warnings and errors.
* `/var/lib/easypatch/logs/agent.log`: 10 MB × 10 files. Set
  `LogLevel=Debug` in `/etc/easypatch/agent.conf` and restart the service
  for more.
* `/var/lib/easypatch/packages/transaction.log`: the last package
  transaction.
* `systemctl status easypatch-packages easypatch-agent-update`: the last
  package transaction and agent update units.

## How the agent works

* **Check-in** every 60 seconds (15 while a job is active), each ±10 %;
  picks up jobs, cancellations, configuration and credential rotation.
* **Scans** every 6 hours, shortly after a restart, at service start when
  the last one is older, after every install job, and on demand.
* **Inventory** daily and on demand: OS edition and build, hardware, disk,
  domain, ESU licence (volume licences), Windows Update service and update
  source; on Linux the distribution, kernel, virtualization, the
  automatic-update tool and Ubuntu Pro.
* **Install jobs**, one at a time, start with a fresh scan, so a repeated
  job never reinstalls anything. Windows installs servicing stack updates
  first and feature updates last, and reports download and install
  percentages. If Windows needs a restart before it can install more, the
  job waits and continues after the restart; with no restart in 30 days it
  fails with `reboot_not_performed`. A scheduled job starts no new update
  after its window closes; an update already installing is never
  interrupted. With install notifications on, signed-in Windows users are
  told when updates install and whether a restart is needed.
* **Windows Update settings** are applied after each check-in when policy
  manages them; the agent reports conflicts with other policy sources and
  stops re-applying a group that conflicts.
* **Customer configuration.** Scans use Windows' own server selection, so
  WSUS, Group Policy and Windows Update for Business apply and are
  reported. Linux scans use the configured repositories.
  `unattended-upgrades` and `dnf-automatic` are reported, never changed.
* **Outages.** Reports are written to disk first and delivered in order
  when the server is back, with exponential backoff and full jitter (up to
  15 minutes), honouring `Retry-After`.

## Updating the agent

The agent updates itself. The patch policy's **Agent updates** setting
(*Restarts and users*) decides how:

* **Automatic** (the default): online agents install the newest signed
  package for their architecture and format within minutes, at most 25 at
  a time. A failed version is tried again after 6 hours, and after three
  failures only when someone asks.
* **Manual**: nothing happens until someone chooses **Update agent…** on
  the device's **Patches** tab, which shows whether the agent can update
  itself and why not.

The packages come with the engine's image, one set per EasyRMM release, and
are listed under **Settings → Patching**, Agent packages. Each has a
`.sig` release signature made by the release workflow; how the release
key is held and checked is in the [code signing policy](../../CODE_SIGNING.md).
Before it downloads anything, the agent checks that the signature's key is
built into it and verifies, that the package is newer and for its
architecture and format, and then that the download has the signed size
and SHA-256. Windows then runs `msiexec /i … /qn /norestart`: Windows
Installer stops the service, replaces the files and starts the new
version, which completes the job; the tray disappears for a few seconds.
Linux runs `apt-get install` or `dnf --disablerepo=* install` in the
transient unit `easypatch-agent-update`. The computer is not restarted,
nobody is asked anything, settings and identity are kept, and agents are
never downgraded.

When an agent cannot update itself, the device's Patches tab says why:
`agent_upgrade_required` (built without a release key),
`release_key_not_trusted` (signed with a key the agent does not carry),
`package_not_signed`, or `agent_up_to_date`. An agent without the right
key is upgraded once by installing a newer package over it (same
`msiexec /i` or `apt-get install`, no properties needed); the identity
and settings are kept and an active job resumes.

## winget

Windows Server 2019 and 2022 and Windows 10 LTSC have no winget, and other
editions may have an old one. Application updates need App Installer
(winget) 1.6 or newer for all users, so the agent installs it when it is
missing or too old, whether or not application updates are on:

1. Three to six minutes after the service starts, then daily, it looks for
   winget 1.6 or newer installed for all users and stops there if it finds
   one; it never updates a working winget.
2. Otherwise it downloads the pinned release (three files, about 315 MB)
   from GitHub, or from the engine when GitHub fails or a file does not
   match. The first time an agent asks, the engine fetches its own copy,
   and the agent tries again 15 minutes later.
3. Every file must have the size and SHA-256 built into the agent. Only
   the dependency packages for the computer's architecture are used.
4. It waits for a running job (at most 2 hours), then installs App
   Installer for all users with `dism.exe /Online
   /Add-ProvisionedAppxPackage … /NoRestart`, which checks Microsoft's
   signatures. The computer is not restarted. The DISM log is
   `logs\winget-setup.log`; event 1018 or 1019 says how it went.

It needs Windows 10 1809 or Windows Server 2019 (build 17763) or later,
x64 or ARM64, and 1.5 GB free on the volume of `C:\ProgramData\EasyPatch`.
On Windows Server 2016 it reports that winget is not supported. Failed
attempts are retried after 30 minutes, 2 hours, 6 hours, then daily. It
cannot be turned off; it does not decide which applications are updated.

## Uninstalling

From EasyRMM, on the device's **Patches** tab, **Stop patching…**
(`patch.manage`): EasyRMM sends the agent an uninstall job and never
installs the agent on that device again until **Allow patching again**.
The agent removes its own package after any running job: `msiexec /x` of
its product on Windows, `apt-get remove easypatch-agent` or `rpm -e
easypatch-agent` (in the transient unit `easypatch-agent-uninstall`) on
Linux. The package's removal step unenrolls it; the endpoint is then
decommissioned and its history kept. A device deleted in EasyRMM, or moved
to another organization, has its agent removed the same way
([Devices that move or are deleted](../operations/patching.md#devices-that-move-or-are-deleted)).

On the computer itself, stop patching in EasyRMM first, or an organization
that installs automatically puts the agent back within minutes. Then:

```powershell
msiexec /x EasyPatchAgent-<version>-x64.msi /qn    # or Settings > Apps
```

```sh
sudo apt-get remove easypatch-agent    # keeps /etc/easypatch and /var/lib/easypatch
sudo apt-get purge easypatch-agent     # also deletes them
sudo dnf remove easypatch-agent        # keeps them: sudo rm -rf /etc/easypatch /var/lib/easypatch
```

Removing the package (not upgrading it) stops the service and runs
`unenroll` first, so the engine marks the endpoint decommissioned when it
can be reached. On Windows the logs in `C:\ProgramData\EasyPatch\logs`
stay for troubleshooting.

## Troubleshooting

Check an agent on the device:

```powershell
& "$env:ProgramFiles\EasyPatch Agent\EasyPatch.Agent.exe" status
```

```sh
sudo /opt/easypatch/easypatch-agent status
journalctl -u easypatch-agent --since "1 hour ago"
```

The device's **Patches** tab says why EasyRMM has not linked a device
([When a device is not linked](../operations/patching.md#when-a-device-is-not-linked)).

| Symptom | Check |
|---|---|
| The install failed | The device's Patches tab gives the reason (installer and enrollment exit codes in words). **Try the install again…** there |
| `status` shows `NotEnrolled`, or enrollment was rejected (exit code 4, event 1003) | The token was used up, expired or revoked before the agent enrolled. EasyRMM leaves an installed agent alone, so remove it on the device ([Uninstalling](#uninstalling)); EasyRMM then installs and enrolls it again, automatically or with **Install EasyPatch agent…** |
| `Revoked` (event 1004), or `credential_revoked` / `endpoint_revoked` | The endpoint was revoked or removed in the engine. Remove the agent on the device, as above |
| `credential_expired` | The computer was off longer than the credential's lifetime (a year by default). Remove the agent on the device, as above |
| "Could not reach the server" | DNS, firewall, proxy, or TLS: the certificate must chain to a root the computer trusts, or to the authority recorded at install |
| `clock_skew` that does not clear | The clock is more than 5 minutes off and keeps drifting. Fix the time source (NTP or domain time) |
| Windows scans fail with `0x8024402C`, `0x80244022` or similar | The update source (Microsoft or WSUS) is unreachable; the error and its meaning are shown on the device |
| Updates you expected are not offered | WSUS approvals, Windows Update for Business deferrals or a target release version apply. The device's Patches tab shows the update source and, under Policy, any Windows Update settings the engine applied |
| Windows Update settings show *Conflict* | Another policy source (usually Group Policy or Intune) set different values. Remove it, or change the patch policy to match |
| No tray icon | Look in the hidden-icons flyout first. Otherwise the icon is hidden by policy, the user signed in seconds ago, or the session is disconnected. If a session has no tray, the agent log says *did not connect to the service* |
| Linux: `The agent is not enrolled and has no server URL` | The package was installed without enrolling. Install again from EasyRMM |
| Linux: updates differ from what you expect | `sudo easypatch-agent scan` shows what the agent reports, without contacting the server |
| Linux: `apt_failed` or `dnf_failed` | The job's message and `/var/lib/easypatch/packages/transaction.log` |
| Linux: a restart is never reported on Red Hat | Install `dnf-plugins-core` (`dnf needs-restarting`) |
| Agent update fails with `update_untrusted_key` or `update_signature_invalid` | The package was signed with a key this agent does not carry, or the `.sig` does not belong to it |
| `update_hash_mismatch` | The downloaded file is not the one that was signed |
| `update_download_failed` | The agent could not download from `/downloads/agent/` (network, proxy) |
| `update_install_failed` | Windows Installer or the package manager failed or rolled back, and the old version still runs: `updates\install-<version>.log` (Windows) or `/var/lib/easypatch/updates/install-<version>.log` |
| Restart job fails with `restart_not_performed` | Windows did not restart within 30 minutes of the request (a user or program cancelled the shutdown), or nobody accepted a prompt without a deadline within 7 days |
| Message job fails with `no_recipients` | Nobody was signed in, or no session had a tray |

winget problems are reported on the agent's application check and in its
log:

| Message | Meaning |
|---|---|
| `winget_not_found`, `winget_too_old` | The agent installs winget itself a few minutes after the service starts; see the next rows if that fails |
| `Could not download … GitHub: … the EasyPatch server: … 503` | The computer cannot reach GitHub and the engine is still fetching its copy; the agent tries again in 15 minutes. If the engine's copy fails too, `easypatch-worker` cannot reach GitHub: allow `github.com` and `release-assets.githubusercontent.com`, or put the three release files in `${EASYRMM_DATA_ROOT}/easypatch/winget/`, readable by user 1654 |
| `… does not match the pinned release` | A proxy or filter changed the download. Nothing was installed |
| `DISM could not install App Installer (exit code …)` | `logs\winget-setup.log` and `C:\Windows\Logs\DISM\dism.log` name the package and the reason |
| `winget needs Windows 10 version 1809 or Windows Server 2019 or later` | Application updates are unavailable on that system |
| An approved application never shows updates | It is installed for one user only (in `AppData`), or winget cannot match it. Run `winget list --id <ID> --exact --source winget` in an elevated prompt |
| `not_verified` | winget exited successfully, but the new version was not listed afterwards; the application may have been running |
| `winget_0x8A150101` | The application was running |
| `winget_0x8A150109`, `winget_0x8A15010A` | The installer needs a restart; the next check after one confirms the upgrade |
| `winget_0x8A150011` or a hash error | The installer did not match its reviewed manifest; the check is never skipped |

## macOS

A macOS agent (a launchd daemon using `softwareupdate`) is experimental
and not released. It has not been used to patch a real Mac. EasyRMM does
not install it and the engine's image carries no macOS package. On Apple
silicon it cannot install updates that need a restart, which includes
every macOS update. To try it on a test Mac you can wipe, build it from
source with `easypatch/scripts/build-macos-packages.sh` (the .NET 10 SDK
and Docker; no Mac needed).

## Building the agent

Released packages are built and signed by EasyRMM's release workflow and
come with the engine's image; most deployments need nothing else. To build
your own (from `easypatch/`):

* Windows MSIs: `pwsh scripts/build-agent.ps1 -Version <version>
  -Architecture x64,arm64 -RequireReleaseKey` on Windows (optionally
  Authenticode-signed), or `scripts/build-msi-linux.sh --version <version>
  --arch all` with Docker (no ICE validation or Authenticode).
* Linux packages: `scripts/build-linux-packages.sh --version <version>
  --arch all` (the .NET 10 SDK and Docker).

The builds read the release key from `~/.easypatch/easypatch-release-key.pem`
(or `EASYPATCH_RELEASE_KEY`, with `EASYPATCH_RELEASE_KEY_PASSWORD` for an
encrypted key) and the public key from
`~/.easypatch/easypatch-release-key.pub.pem` (or
`EASYPATCH_RELEASE_PUBLIC_KEY`); `dotnet run --project
tools/EasyPatch.ReleaseSigner -- generate-key` makes a pair. Agents built
with your key accept only packages signed with it, so they never update to
released packages, and released agents never update to yours.
`scripts/stage-agent-packages.sh` checks a set of signed packages and
stages them for the server image's build. For tests,
`scripts/build-test-agent-packages.sh` builds Linux packages signed with a
throwaway key; such an image must never be published.
