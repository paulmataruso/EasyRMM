# EasyPatch agent: installation and operation

This guide covers the Windows agent. For Linux (Debian, Ubuntu, RHEL and its rebuilds), see
[linux-agent.md](linux-agent.md).

The EasyPatch agent is a Windows service (`EasyPatchAgent`) that reports Windows Update state to
your EasyPatch server and installs the updates an administrator approves. It uses the Windows
Update Agent API that Windows itself uses. The agent:

* **restarts the computer only when an administrator asks for it**, once or through a restart
  schedule set in policy, and warns signed-in users first. Installing updates never restarts
  the computer. It reports when a restart is pending and why: which updates are waiting for
  it, and from agent 1.5.3 also the Windows servicing packages and the files Windows has queued
  for the restart (shown on the endpoint page);
* **changes Windows Update policy only when an administrator configures it** in EasyPatch
  policy, never the WSUS server settings, and puts the original values back when the setting is
  removed or the agent is uninstalled. Otherwise WSUS, Group Policy, Windows Update for Business
  and Intune settings are honored and only reported;
* shows an EasyPatch icon in the notification area of signed-in users, with a status window
  (see [Tray icon](#tray-icon));
* cannot run commands. It executes a fixed set of job types: update scan, inventory refresh,
  install updates, restart, preset messages to signed-in users, agent update and uninstall
  (removing its own package).

## Requirements

| | |
|---|---|
| Operating system | Windows 10, Windows 11, Windows Server 2016 or later, 64-bit (x64 or ARM64) |
| Privileges | Installation and the `enroll`/`unenroll` commands need an administrator; the service runs as LocalSystem |
| Network | Outbound HTTPS (TCP 443 by default) from the endpoint to the EasyPatch server. No inbound ports. To install winget (agent 1.7.0 and later, see [winget](#winget)), also `github.com` and `release-assets.githubusercontent.com`; without them the agent downloads winget from the EasyPatch server instead |
| TLS | The server certificate must be trusted by the Windows certificate store of the computer, or chain to the CA recorded at installation with `SERVERCACERT` (see [Servers with a private certificate authority](#servers-with-a-private-certificate-authority)). Certificate validation cannot be disabled |
| .NET | Not required: the agent is self-contained |

## Choosing an enrollment method

| Method | Use it for | Secret? | Approval |
|---|---|---|---|
| **Enrollment token** (`ENROLLMENTTOKEN`) | Hands-on installs, GPO/Intune deployments where the token is protected | Yes: limited-use, expiring | No, the agent is active immediately |
| **Deployment code** (`DEPLOYMENTCODE`) | RMM scripts and other tokenless mass deployment | No | Yes: each computer appears under *Pending Approvals* until an administrator approves it |

Both are created in the EasyPatch console. The console can also generate the complete
`msiexec` command (tokens) or a PowerShell install script (deployment codes).

## Installing with msiexec

### Enrollment token

```powershell
msiexec /i EasyPatchAgent-1.0.0-x64.msi /qn /norestart `
  SERVERURL=https://patch.example.com `
  ENROLLMENTTOKEN=ept_xxxxxxxxxxxxxxxxxxxxxxxx
```

### Deployment code (tokenless, requires approval)

```powershell
msiexec /i EasyPatchAgent-1.0.0-x64.msi /qn /norestart `
  SERVERURL=https://patch.example.com `
  DEPLOYMENTCODE=EPD-7Q4KPZ2MXR8T3HWN
```

The agent submits an enrollment request with its public key and polls until an administrator
approves or rejects it. Before approving, compare the **key fingerprint** shown in the console
with the one on the computer. The agent prints it on the computer in three places:

* the output of `EasyPatch.Agent.exe status`;
* event 1001 in the Application event log (source *EasyPatch Agent*);
* `C:\ProgramData\EasyPatch\logs\agent.log`.

### MSI properties

| Property | Required | Description |
|---|---|---|
| `SERVERURL` | First install | `https://` URL of the EasyPatch server, for example `https://patch.example.com` or `https://example.com/easypatch`. Remembered on upgrade |
| `ENROLLMENTTOKEN` | One of the two | Enrollment token. Hidden MSI property; see *Protecting the enrollment token*. Deleted by the agent once it has been used |
| `DEPLOYMENTCODE` | One of the two | Deployment code. Deleted by the agent once the request is approved or rejected |
| `PROXYURL` | No | `http://proxy:8080` style URL of an outbound proxy. Remembered on upgrade. Authenticating proxies are contacted with the computer account (Negotiate/NTLM) |
| `SERVERCACERT` | No | A certificate authority certificate (base64 DER) that the agent trusts for its connection to the EasyPatch server only, for servers with a private CA. Set by the install script's *Skip certificate check* option; see [Servers with a private certificate authority](#servers-with-a-private-certificate-authority). Remembered on upgrade |

Without `PROXYURL` the agent uses the `HTTPS_PROXY`/`HTTP_PROXY` environment variables or the
service account's WinINET proxy settings. WinHTTP proxy settings (`netsh winhttp`) are **not**
used, so set `PROXYURL` on networks that require a proxy.

The installer refuses to run without `SERVERURL` on a first installation, with a `SERVERURL`
that does not start with `https://`, or with both `ENROLLMENTTOKEN` and `DEPLOYMENTCODE`.
`msiexec` exit code `1603` with launch-condition text in the log indicates one of these.

### Protecting the enrollment token

Values on an `msiexec` command line are visible to other administrators through the process
list while the installer runs, in the command history of the tool that ran it, and in any
process-creation auditing or endpoint security telemetry. Tokens are therefore single-use and
expire (24 hours by default).

The MSI hides `ENROLLMENTTOKEN` from Windows Installer's property listings and does not echo
registry values into its log, but Microsoft does not document masking for every line of a
verbose (`/l*v`) log. Treat verbose logs of token installs as sensitive.

To keep the token off the `msiexec` command line and out of MSI logs entirely, use a
deployment code (no secret at all), or install with the server URL only and enroll with the
token in an environment variable:

```powershell
msiexec /i EasyPatchAgent-1.0.0-x64.msi /qn /norestart SERVERURL=https://patch.example.com
$env:EASYPATCH_ENROLLMENT_TOKEN = '<token from your secret store>'
& "$env:ProgramFiles\EasyPatch Agent\EasyPatch.Agent.exe" enroll --server https://patch.example.com
Remove-Item Env:\EASYPATCH_ENROLLMENT_TOKEN
```

## What the installer creates

| Item | Location |
|---|---|
| Program | `C:\Program Files\EasyPatch Agent\EasyPatch.Agent.exe` (signed when the build is signed) |
| Service | `EasyPatchAgent` ("EasyPatch Agent"), LocalSystem, automatic (delayed) start, restarts after a failure (60 s) |
| Bootstrap settings | `HKLM\SOFTWARE\EasyPatch\Agent`: `ServerUrl`, `ProxyUrl`, and temporarily `EnrollmentToken` / `DeploymentCode`. ACL: SYSTEM and Administrators only |
| Data | `C:\ProgramData\EasyPatch`. ACL: SYSTEM and Administrators only, inheritance disabled |
| Event log source | *EasyPatch Agent* in the Application log |

The service re-applies both ACLs every time it starts and refuses to start if it cannot.

Data directory layout:

```
C:\ProgramData\EasyPatch\
  agent.key                 ECDSA P-256 private key, DPAPI-protected (LocalMachine scope)
  state\agent-state.json    enrollment state, held jobs, timestamps (written atomically)
  outbox\                   reports waiting for delivery (survive restarts and outages)
  logs\agent.log            service log (10 MB x 10 files)
  logs\cli.log              log of enroll/unenroll commands
  agent.lock                prevents two agent processes from running at once
```

The private key never leaves the computer and is never logged. Only its public key is sent to
the server.

## Command line

Run from an elevated prompt:

```text
EasyPatch.Agent.exe status [--json]
EasyPatch.Agent.exe enroll --server <url> (--token <token> | --deployment-code <code>) [--proxy <url>] [--force] [--no-start]
EasyPatch.Agent.exe unenroll [--reason <text>]
EasyPatch.Agent.exe version
```

* `status` shows the service state, enrollment status, server, endpoint ID, credential, key
  fingerprint, last check-in, scan and inventory times, held jobs and queued reports. `--json`
  prints the same as JSON for RMM monitoring.
* `enroll` stops the service, writes the bootstrap settings, enrolls immediately (printing the
  endpoint ID or the fingerprint of the pending request), then starts the service again.
  * Running it again on a computer that is already enrolled with the same server does nothing
    and exits 0, so RMM scripts can run it repeatedly.
  * `--force` notifies the old server (best effort), deletes the current identity and enrolls
    again. It is required to move a computer to a different server.
  * The token can come from `EASYPATCH_ENROLLMENT_TOKEN` instead of `--token`.
* `unenroll` notifies the server (best effort, 30-second limit), deletes the key, state,
  queued reports and bootstrap settings, and leaves the service stopped. The MSI runs it
  automatically on uninstall.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Success (for `enroll`: active, waiting for approval, or already enrolled) |
| 1 | Failure (see `logs\cli.log`) |
| 2 | Invalid arguments or settings |
| 3 | Already enrolled with a different server (use `--force`) |
| 4 | The server rejected the token or deployment code |
| 5 | Not running elevated |
| 6 | Server unreachable. Settings were saved and the service keeps retrying |
| 7 | Another agent process could not be stopped |

## Example RMM script (deployment code)

```powershell
$ErrorActionPreference = 'Stop'
$server = 'https://patch.example.com'
$msi    = "$env:TEMP\EasyPatchAgent.msi"
Invoke-WebRequest "$server/downloads/agent/EasyPatchAgent-1.0.0-x64.msi" -OutFile $msi -UseBasicParsing
$expected = '<sha256 from the console>'
if ((Get-FileHash $msi -Algorithm SHA256).Hash -ne $expected) { throw 'MSI hash mismatch' }
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart',
     "SERVERURL=$server", 'DEPLOYMENTCODE=EPD-7Q4KPZ2MXR8T3HWN', '/l*v', "`"$env:TEMP\EasyPatchAgent-install.log`"")
if ($p.ExitCode -notin 0, 3010) { throw "msiexec failed with $($p.ExitCode)" }
Start-Sleep -Seconds 20
& "$env:ProgramFiles\EasyPatch Agent\EasyPatch.Agent.exe" status
```

The console generates an equivalent script that also checks the Authenticode signature when
you require it.

## Servers with a private certificate authority

The agent connects only to a server whose certificate it trusts. A server with a public
certificate (the production setup, with ACME) needs nothing more. A server with a private CA,
such as the lab setup with Caddy's internal CA, fails with *Could not establish trust
relationship for the SSL/TLS secure channel* on computers that do not trust that CA. There are
two ways to install agents on such computers:

* **Trust the CA on the computer.** Import the CA's root certificate into *Trusted Root
  Certification Authorities* of the local computer (for example by Group Policy). Every
  program on the computer then trusts that CA.
* **Skip certificate check** in the console's install script dialog (*Deploy →
  Deployment codes → Install script*, Windows tab). The script then:
  1. downloads itself, the server's CA certificate and the MSI **without checking the server
     certificate** (the MSI's SHA-256 is still checked against the value in the script);
  2. reads the CA certificate from `https://<server>/server-ca.crt`, which the lab proxy
     (`Caddyfile.dev`) publishes. It prints its subject and SHA-256 and passes it to the MSI as
     `SERVERCACERT`. If the server publishes no CA certificate, the script warns and installs
     without it;
  3. switches certificate checking back on when it ends.

  The agent then trusts that CA **for its own connection to EasyPatch only**, not for anything
  else on the computer, and still checks every certificate: it accepts a certificate that
  Windows trusts, or one that chains to the recorded CA, is currently valid and matches the
  server name. It does not accept any other certificate.

Because the downloads are not checked, someone who can intercept the connection during the
installation could hand the computer a different script. Use *Skip certificate check* only
on a network you trust, and compare the CA's SHA-256 that the script prints with the one the
server host shows:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml exec caddy cat /data/caddy/pki/authorities/local/root.crt \
  | openssl x509 -outform der | sha256sum
```

Caddy's internal root certificate is valid for 10 years and survives restarts (it is kept in
the `caddy_data` volume). If it is ever replaced, reinstall the agents with the new one
(`SERVERCACERT` on the MSI command line replaces the recorded certificate).

## How the agent works

* **Check-in**: every 60 seconds (±10 % jitter; 15 seconds while a job is active). Picks up
  jobs, cancellations, configuration and credential rotation requests.
* **Scans**: every 6 hours (±10 %), shortly after the computer restarts, at service start when
  the last scan is older than that, after every install job, and on demand. Results and new
  Windows Update history entries are sent to the server. Background scans are skipped while
  another Windows Update operation of the agent is running.
* **Inventory**: daily and on demand. Includes OS edition, version and build, hardware model
  and serial number, disk space, domain membership, ESU licensing (volume licenses only), the
  Windows Update service state and the update source configuration.
* **Install jobs**: one at a time. Each job starts with a fresh scan, so a job that is repeated
  after a crash or restart never reinstalls anything. Servicing stack updates are installed
  first, feature updates last. If Windows needs a restart before it can install more, the job
  waits (state `WaitingForReboot`) and continues after the computer restarts (by a user, an
  administrator, or an EasyPatch restart job). If no restart happens within 30 days the job
  fails with `reboot_not_performed`. When install notifications are on (the default), signed-in
  users are told that updates are being installed, and afterwards whether a restart is needed.
* **Restart jobs**: run without holding up scans. Depending on the mode chosen by the
  administrator, signed-in users see a countdown, or a request to restart that they can
  postpone up to a deadline. If nobody is signed in, the computer restarts at once. The job
  completes only after the agent sees that the computer actually restarted. See
  [architecture.md](architecture.md#restart-jobs).
* **Messages**: preset messages from the console are shown as a notification in every
  signed-in session with a tray. If nobody can see the message, the job fails with
  `no_recipients`.
* **Windows Update settings**: when an administrator configures a group of Windows Update
  settings, the agent applies it after the next check-in and reports whether it was applied,
  or whether another policy source (for example domain Group Policy) changed the values. See
  [architecture.md](architecture.md#windows-update-policy-enforcement).
* **winget** (1.7.0 and later): the agent makes sure App Installer (winget) is installed for
  all users, so [application updates](application-updates.md) work without preparation. See
  [winget](#winget).
* **Agent updates** (1.2.0 and later): the agent installs a newer EasyPatch agent when an
  administrator chooses *Update agent*, or by itself when the *Agent updates* policy is
  *Automatic*. It checks the package's release signature against the key built into it before
  downloading anything. See [Upgrading](#upgrading).
* **Maintenance windows**: a scheduled job does not start new updates after the window closes.
  An update that is already installing is never interrupted.
* **Outages**: reports are written to disk before they are sent and are delivered in order when
  the server is reachable again. Retries use exponential backoff with full jitter (up to 15
  minutes) and honor `Retry-After`.
* **Clock**: requests are signed with a timestamp. The agent measures the server's clock and
  corrects its own offset automatically, so a wrong local clock does not break it.

### winget

Windows Server 2019 and 2022 and Windows 10 LTSC do not include winget, and on other editions it
may be missing or too old. From version 1.7.0 the agent installs it itself when needed:

1. 3 to 6 minutes after the service starts, and then daily, the agent looks for App Installer
   (winget) 1.6 or newer installed for all users. If it finds one, it does nothing else; it
   never updates a working winget.
2. Otherwise it downloads winget **1.29.380** (three files, about 315 MB) from the winget
   GitHub release. A file that cannot be downloaded from GitHub, or that does not match, is
   downloaded from the EasyPatch server instead (`/downloads/winget/…`). The first time an
   agent asks, the server fetches its own copy from GitHub, which can take a few minutes; the
   agent tries again 15 minutes later.
3. Every file must have the size and SHA-256 built into the agent. Nothing is installed from a
   file that does not match, whichever source it came from.
4. Only the dependency packages for the computer's architecture (x64 or ARM64) are taken from
   the dependency archive.
5. While the agent has a job to run, it waits for the job to finish (at most 2 hours).
6. It installs App Installer and its dependencies for all users with Windows' own DISM
   (`dism.exe /Online /Add-ProvisionedAppxPackage … /NoRestart`). Windows checks Microsoft's
   package signatures. The computer is never restarted. The DISM log is `C:\ProgramData\EasyPatch\logs\winget-setup.log`.
7. The downloaded files are deleted. The endpoint's **Overview** tab shows the winget version,
   or why it could not be installed.

Failed attempts are retried after 30 minutes, 2 hours, 6 hours, then daily. Requirements and
limits:

* Windows 10 1809 or Windows Server 2019 (build 17763) or later, x64 or ARM64. On Windows Server
  2016 the agent reports that winget is not supported and downloads nothing.
* 1.5 GB free disk space on the volume of `C:\ProgramData\EasyPatch`.
* The installation cannot be turned off. It does not change which applications are updated:
  that still needs the application updates policy and an approved list.

## Logs and events

`C:\ProgramData\EasyPatch\logs\agent.log` rotates at 10 MB and keeps 10 files. Tokens, keys and
signatures are redacted before anything is written. To collect more detail, set the string
value `HKLM\SOFTWARE\EasyPatch\Agent\LogLevel` to `Debug` and restart the service; delete the
value to return to `Information`.

The Application event log (source *EasyPatch Agent*) receives warnings and errors and the
agent's informational events, including:

| Event ID | Meaning |
|---|---|
| 1000 | The service could not start (data directory or registry ACL, elevation, second instance) |
| 1001 | Enrollment request waiting for approval (includes the key fingerprint) |
| 1002 | Enrollment complete |
| 1003 | Enrollment refused or rejected |
| 1004 | The server revoked the agent's credential. Re-enroll to resume |
| 1005 | Credential rotated |
| 1010 | Restarting the computer for a restart job (warning) |
| 1011 | Windows Update settings applied, changed or restored |
| 1012 | Windows Update settings were changed by another policy source; EasyPatch stopped re-applying them (warning) |
| 1013 | Installing an agent update (the service is about to be restarted by Windows Installer) |
| 1014 | Agent updated (logged by the new version) |
| 1015 | Agent update failed or refused (warning, with the reason) |
| 1016 | Removing the agent for an uninstall job (warning) |
| 1017 | Uninstall job failed (warning, with the reason) |
| 1018 | winget installed for all users |
| 1019 | winget could not be installed (warning, with the reason) |
| 1020 | An update was removed for an update removal job (warning, with how it was removed) |
| 1021 | An update removal job failed (warning, with the reason) |

## Tray icon

The service starts the tray (`EasyPatch.Agent.exe tray`) as the signed-in user in every
active session, within about 15 seconds of sign-in. There is nothing to configure on the
computer and no startup entry: if the tray is closed, the service starts it again after two
minutes. The tray connects to the service over a local named pipe and exits when the service
stops.

Windows 11 puts new notification-area icons in the hidden-icons flyout (the **^** next to the
clock) until the user moves them. To keep it on the taskbar, drag it out of the flyout or turn
it on under *Settings → Personalization → Taskbar → Other system tray icons*.

Hovering over the icon shows the agent version and a one-line status (for example
*EasyPatch Agent 1.5.0 / This computer is up to date*). The right-click menu shows the same
version, the current activity, the last check-in and whether a restart is pending.
Notifications show the preset messages. During a restart request a small window offers
*Restart now* and, where the administrator allowed it, *Postpone*.

### Status window

Clicking the icon (or **Open EasyPatch status** in its menu) opens the status window. Agent
1.5.0 and later have it. From 1.5.1 the window, the menus and the restart prompts follow the
user's Windows app mode (*Settings → Personalization → Colors*), dark or light.

* **Summary.** A colored heading: *up to date*, *N updates available*, *restart required*,
  *checking for updates* or *installing updates*, *can't reach the EasyPatch server*,
  *waiting for approval*, *not enrolled*, or *the EasyPatch service is not responding*. A
  failed update check, or none for three days, is also shown here.
* **Details.** Server connection, last check-in, the server's host name (*Managed by*), the
  last update check and the number of applicable updates it found, the last installation
  (time and number of updates), whether a restart is needed, the current activity (from 1.7.0
  with the percentage, for example *Installing KB5044284 (45%)*), the computer name and the
  agent version.
* **Check in now.** Contacts the server at once, which also delivers waiting results and picks
  up waiting jobs.
* **Check for updates.** Runs an update scan at once. The scan is reported to the server like
  any other and is recorded with the trigger `User`. It never installs anything: the
  administrator's schedules and jobs still decide what is installed and when.
* **Restart options…** appears while a restart request is waiting.
* **Recent activity.** The newest 200 entries of the agent log (information, warnings and
  errors; the first line of each entry only), newest first. It refreshes every 30 seconds while
  the window is open. **Copy** copies the selected entries, or all of them, for a support
  ticket. The full log stays in `C:\ProgramData\EasyPatch\logs`.

The two buttons are limited for the whole computer, not per user: a check-in at most every 30
seconds, and an update check at most every 5 minutes and not while Windows Update is busy
with a scan or an installation. Each request is written to the agent log with the session it
came from. Users cannot change the agent's settings, install or remove anything, run commands
or stop the agent from the tray or the status window.

To hide the icon, set **EasyPatch icon in the notification area** to *Hide* under *User
experience* in the policy for the organization, site, tag or endpoint. The icon then appears
only while a message or a restart request is shown, so users cannot open the status window.
In a session without a tray (for example right after sign-in, before the tray has started)
messages cannot be shown, and restart countdowns use Windows' own shutdown warning instead.

## Upgrading

### Automatic and console updates (agent 1.2.0 and later)

Agents 1.2.0 and later update themselves. To release a new version:

1. Build it with the release key (see [Building from source](#building-from-source)), which
   produces `EasyPatchAgent-<version>-<arch>.msi` and its release signature
   `EasyPatchAgent-<version>-<arch>.msi.sig`.
2. Copy both files to `data/agent-packages` on the server. *Deploy → Agent packages*
   shows the package as **signed** with the key ID. A package without a valid `.sig` is still
   offered for manual download, but agents do not update to it.

Then:

* With the *Agent updates* policy on **Automatic** (the default), online computers install the
  newest signed package for their architecture within a few minutes, at most 25 at a time. A
  failed update is tried again after 6 hours, and after three failures of the same version only
  when an administrator asks.
* With **Manual**, nothing happens until an Operator chooses **Update agent…** on an endpoint
  (*More* menu) or for several endpoints in the endpoint list.

The policy can be set for the whole installation, an organization, a site or a single computer.

During an update the agent checks the release signature against the key built into it, checks
that the package is newer and for its architecture, downloads it from the server, checks its
size and SHA-256, closes the trays, and runs Windows Installer (`msiexec /i … /qn /norestart`).
Windows Installer stops the service, replaces the files and starts the new version, which
completes the job. The computer is not restarted and users are not asked anything; the tray
icon disappears for a few seconds. Agents are never downgraded. The package and the installer
log are kept in `C:\ProgramData\EasyPatch\updates` (the log as `install-<version>.log`; logs
are deleted after 30 days).

The endpoint's overview shows whether its agent can update itself, and why not if it cannot:
`agent_upgrade_required` (older than 1.2.0 or built without a release key),
`release_key_not_trusted` (the package was signed with a key this agent was not built with),
`package_not_signed` or `agent_up_to_date`.

### Installing the MSI

Agents older than 1.2.0, and agents built without a release key, must be upgraded by installing
the newer MSI over the existing one with the same command (no properties needed). This is also
how you move a computer to an agent with a different release key. The server URL and proxy are
kept, the identity in `C:\ProgramData\EasyPatch` is preserved and an active job resumes after
the service restarts. Downgrades are blocked.

An agent that never finished enrolling loses its token or deployment code on upgrade; pass it
again or run `enroll`.

## Uninstalling

From the console (agent 1.6.0 or later): open the endpoint, **More → Uninstall agent…** and type
the computer name to confirm. The agent removes itself the next time it checks in, after any
job it is running, with `msiexec /x` of its own product (nothing else can be removed this
way). The job completes when the agent's uninstaller has unenrolled it; the endpoint is then
shown as decommissioned, its other queued jobs are cancelled and its history is kept (delete
the endpoint if you no longer need it). If the computer is offline, the uninstall waits until
the job expires. If Windows Installer fails, the agent stays installed and reports the job as
failed with the error; the log is `C:\ProgramData\EasyPatch\logs\uninstall.log`.

On the computer:

```powershell
msiexec /x EasyPatchAgent-1.0.0-x64.msi /qn
```

or use *Apps & features*. The uninstaller stops the service, runs `unenroll` (the server marks
the endpoint as decommissioned when it can be reached) and removes the program. Logs in
`C:\ProgramData\EasyPatch\logs` are kept for troubleshooting; delete the folder if you do not
need them.

## Troubleshooting

| Symptom | Check |
|---|---|
| `status` shows `NotEnrolled` and the log says no token or deployment code | Install was done without `ENROLLMENTTOKEN`/`DEPLOYMENTCODE`, or the token was already consumed. Run `enroll` |
| Enrollment rejected (exit code 4, event 1003) | Token expired, revoked or used up, deployment code revoked, or the request was rejected by an administrator. Create a new token or code |
| Stays at `PendingApproval` | Approve the request in the console (*Pending Approvals*). Requests expire after 7 days; the agent then submits a new one |
| `Revoked` (event 1004) | The endpoint was removed or its credential revoked in the console. Re-enroll with `enroll --force` |
| "Could not reach the EasyPatch server" | DNS, firewall, proxy (`PROXYURL`), or TLS: the server certificate must chain to a root trusted by the computer, or to the CA recorded with `SERVERCACERT` (see [Servers with a private certificate authority](#servers-with-a-private-certificate-authority)) |
| Scans fail with `0x8024402C`, `0x80244022` or similar | The Windows Update source (Microsoft or WSUS) is unreachable. The error code and its description are shown in the console |
| Updates not offered that you expected | WSUS approvals, Windows Update for Business deferrals or a target release version apply. The console shows the detected update source, and the endpoint's *Policy* tab shows any Windows Update settings EasyPatch applied |
| No tray icon | On Windows 11, look in the hidden-icons flyout (**^**) first. Otherwise the policy setting *EasyPatch icon in the notification area* is *Hide*, the user signed in less than 15 seconds ago, or the session is a remote session that is disconnected. *Signed-in users* on the endpoint's overview shows how many sessions have a tray. If a session is signed in but has no tray, the agent log says *did not connect to the service*. Agent 1.1.0 had this problem for every user who was not running as administrator; install 1.1.1 or later |
| Windows Update settings show *Conflict* | Another policy source (usually domain Group Policy or Intune) set different values. Remove that policy, or change the EasyPatch setting to match; changing the EasyPatch setting applies it again |
| Agent update failed with `update_untrusted_key` or `update_signature_invalid` | The package was signed with a key this agent was not built with, or the `.sig` file does not belong to the package. Check the key ID under *Deploy → Agent packages*. Agents keep trusting only the keys they were built with; to change keys see [security.md](security.md#agent-release-signing) |
| Agent update failed with `update_hash_mismatch` | The file downloaded from the server is not the one that was signed (it was replaced, rebuilt or truncated). Copy the MSI and its `.sig` from the same build again |
| Agent update failed with `update_install_failed` | Windows Installer failed or rolled back, and the previous version is still running. The job message has the Windows Installer error; the full log is `C:\ProgramData\EasyPatch\updates\install-<version>.log` |
| Agent update failed with `update_download_failed` | The agent could not download the package from `downloads/agent/<file>` (network, proxy, or the file was removed from the server) |
| Restart job failed with `restart_not_performed` | Windows did not restart within 30 minutes of the request, or nobody accepted a prompt without a deadline within 7 days. Check the System event log for shutdowns cancelled by a user or an application |

## Building from source

The MSIs attached to [GitHub Releases](https://github.com/paulmataruso/EasyPatch/releases) are
built and signed by the project's `release` workflow; most installations should use those (see
[installation.md](installation.md#6-offer-agent-packages)). An agent you build with your own
release key accepts only packages signed with that key, so it does not update to official
releases (see [security.md](security.md#agent-release-signing)).

Create the release key once, on the machine that builds the agent (not on the EasyPatch server):

```bash
dotnet run --project tools/EasyPatch.ReleaseSigner -- generate-key
# writes ~/.easypatch/easypatch-release-key.pem (private, keep it safe and backed up)
#    and ~/.easypatch/easypatch-release-key.pub.pem (public, built into the agent)
```

The build scripts build the public key into the agent and write a `.sig` release signature next
to each MSI. Override the locations with `EASYPATCH_RELEASE_PUBLIC_KEY` and
`EASYPATCH_RELEASE_KEY`; set `EASYPATCH_RELEASE_KEY_PASSWORD` to create or use an encrypted
private key. Without the keys the build still succeeds with a warning, but the agent cannot
update itself, and agents will not update to unsigned MSIs. Keep using the same key for later
versions: agents only accept the keys they were built with. See
[security.md](security.md#agent-release-signing).

* Windows: `pwsh scripts/build-agent.ps1 -Version 1.2.0 -Architecture x64,arm64` builds, tests,
  optionally Authenticode-signs, and builds and release-signs the MSIs. `-RequireReleaseKey`
  fails the build when a release key is missing.
* Linux with Docker: `scripts/build-msi-linux.sh --version 1.2.0 --arch all` builds, tests and
  builds the MSIs. It runs the same WiX Toolset 5.0.2 under Wine in a pinned container
  (`agent/Installer/linux/Dockerfile`), with networking disabled during the build. Two things
  are not available on Linux: Windows Installer ICE validation (Wine cannot run it) and
  Authenticode signing. Build packages that must be Authenticode-signed on Windows. Release
  signatures work on Linux.
* Linux/macOS without Docker: `scripts/build-agent.sh --version 1.2.0 --rid all` builds, tests and
  publishes the agent executable only.

On Windows, signing is optional and is configured through environment variables, never
through files in the repository. See `agent/Installer/build-installer.ps1` for `EASYPATCH_SIGN_CERT_THUMBPRINT`,
`EASYPATCH_SIGN_PFX_PATH`/`EASYPATCH_SIGN_PFX_PASSWORD` and `EASYPATCH_SIGN_TIMESTAMP_URL`. Each
MSI is written to `artifacts/installer` together with a `.sha256` file and, with a release key,
a `.sig` file. Copy the MSI and its `.sig` to `data/agent-packages` on the server to offer it for
download and for agent updates. The server computes the SHA-256 itself; the `.sha256` file is
for your own verification. To check packages against a public key:
`dotnet run --project tools/EasyPatch.ReleaseSigner -- verify --public-key <public.pem> <msi>...`.
