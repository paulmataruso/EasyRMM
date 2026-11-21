# Installing the EasyRMM agent

The EasyRMM agent puts a computer under management. It enrolls with a
deployment token, reports in every minute, and installs MeshAgent, the
remote-access agent, from your own server (ADR-0015).

The agent runs on:

* **Windows** 10 and 11, and Windows Server 2016 and later, on x64 and
  ARM64, as a Windows service (ADR-0020);
* **Linux with systemd**, on x86-64, ARM 64-bit, ARMv7 and 32-bit x86.

There is no macOS agent, no MSI package and no DEB or RPM package yet:
computers install with the PowerShell or shell command below.

## Requirements

* **Windows:** an administrator, and Windows PowerShell 5.1 (built into
  Windows 10 and Server 2016 and later).
* **Linux:** root (the installer is run through `sudo`); systemd,
  `sha256sum`, and `curl` or `wget`.
* Outbound HTTPS (443) to the EasyRMM server name, for example
  `rmm.example.com`, and to the MeshCentral name, `mesh.rmm.example.com`.
  Nothing connects to the computer.
* A clock within five minutes of the server's. Signed requests from a
  computer with a wrong clock are refused (`clock_skew`).

## 1. Create a deployment token

In the console, open **Devices → Add devices** (or **Add devices** on a
site's page). Choose the site the computers belong to and, optionally, a
device group; name the token after the rollout; choose when it expires (1 to
90 days) and, optionally, how many devices may use it.

The install command is shown right after the token is created. While the
token can still add devices, **Show install commands** on its row under
**Deployment tokens** shows it again; each time is recorded in the audit log
([ADR-0047](../architecture/adr/0047-tokens-shown-again.md)). Tokens created
before EasyRMM 1.0.0-rc.2 cannot be shown again. Anyone holding the token can
add computers to that site until it expires, reaches its device limit or is
revoked, so revoke it once the rollout is done. Revoking a token does not
affect computers that already enrolled with it.

You need a role with the `enrollment.manage` permission for the site:
Super Administrator, Organization Administrator or Site Administrator.

### One command for every computer: approval tokens

To roll out to many customers with one command (through a GPO, Intune or
another RMM), choose **Wait for approval** instead of a site. The token has
a name, an expiry and an optional device limit, and the install commands
are the same as below. A computer that runs one is not added anywhere yet:
the installer prints a device code and installs the agent, which waits.

```text
Waiting for approval in the EasyRMM console at https://rmm.example.com. Device code: K3QF-7BXA
The agent is running as easyrmm-agent.service.
It finishes enrolling on its own once the device is approved.
```

The computer appears under **Devices → Waiting for approval** (the menu and
the devices tree count waiting devices) with its code, system, address and
token, and any existing device with the same name, which is usually the same
computer reinstalled. Select one or many and **Approve** them into a site
and, optionally, a device group: each becomes a device named after its host
name, and its agent enrolls within a few seconds. **Reject** tells the agent
to stop asking; it idles until it is uninstalled, and installing it again
asks anew. Waiting devices whose agent stopped asking for 7 days are
forgotten, and rejected ones after 30 days.

Approval tokens and waiting devices belong to no organization, so they need
`enrollment.manage` on the whole server (Super Administrator). Revoking an
approval token stops new computers from asking; computers already waiting
can still be approved.

![Enrolling an EasyRMM agent: a deployment token creates the device at once; an approval token makes the agent wait with a device code, asking again with each question held up to 25 seconds, until a super administrator approves it into a site; then the agent fetches MeshAgent through EasyRMM and starts its heartbeat](../images/diagrams/agent-enrollment.svg)

## 2. Install on Windows

The Add devices page shows the command under **Windows**. Open **Windows
PowerShell** as administrator (right-click Start, **Terminal (Admin)** or
**Windows PowerShell (Admin)**) and paste it:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://rmm.example.com/api/agent/v1/install.ps1'))) -Token 'ert_…'
```

The first part turns on TLS 1.2, which Windows PowerShell leaves off on some
systems; the rest downloads `install.ps1` from your server and runs it with
the token. The same command works from an RMM or deployment tool that runs
PowerShell as SYSTEM.

**By IP address.** The command for an address that uses the server's own
certificate authority checks the server's public key itself: it accepts only
a certificate whose key has the SHA-256 shown in the command, downloads the
script, and then turns the check off again. The script does the same for its
own downloads and gives the agent the server's certificate authority to
trust from then on (ADR-0016, ADR-0020). Run it in **Windows PowerShell**
(`powershell.exe`): PowerShell 7 cannot run this check.

`install.ps1`:

1. checks that it runs as an administrator on Windows 10, Windows Server
   2016 or later, on x64 or ARM64;
2. downloads `easyrmm-agent-windows-<arch>.exe` and `SHA256SUMS` from the
   server and refuses a program whose SHA-256 does not match;
3. runs `easyrmm-agent.exe install`, which copies itself to
   `%ProgramFiles%\EasyRMM\Agent`, enrolls the computer and starts the
   **EasyRMM Agent** service;
4. removes its downloads.

Any failure stops it with a message starting `easyrmm:`; the window stays
open. The agent is not code-signed yet; if endpoint protection holds
`easyrmm-agent.exe`, allow it by its SHA-256 from the Add devices page.

## 3. Install on Linux

Choose **Linux** on the Add devices page. On each computer:

```sh
export EASYRMM_TOKEN='ert_…'; curl -fsSL https://rmm.example.com/api/agent/v1/install.sh | sudo --preserve-env=EASYRMM_TOKEN sh; unset EASYRMM_TOKEN
```

Without curl, replace `curl -fsSL` with `wget -qO-`.

The token travels in the environment. `export` is part of the shell, so the
token never appears on a command line, which every user of the computer can
read in the process list and which sudo writes to its log.
`--preserve-env=EASYRMM_TOKEN` keeps it through sudo; a sudo rule that
allows only certain commands may refuse that ("not allowed to preserve the
environment"), and then run the command from a root shell instead (`sudo
-i`, without `sudo` before `sh`). The script still accepts `--token ert_…`
after `sh -s --`, which puts the token on a command line. Like any command,
this one stays in your shell's history: prefer tokens limited in uses and
time, and remove a token once its computers are installed.

**By IP address.** When computers cannot look up the server's name, choose
the server's IP address under **Server address** after creating the token.
That address uses the server's own certificate authority, which the computer
does not trust yet, so the command pins the server's public key instead:

```sh
export EASYRMM_TOKEN='ert_…'; curl -fsSL --insecure --pinnedpubkey 'sha256//…' https://203.0.113.10/api/agent/v1/install.sh | sudo --preserve-env=EASYRMM_TOKEN sh; unset EASYRMM_TOKEN
```

`--insecure` skips only the certificate authority check; curl refuses any
other key. The script then needs curl (wget cannot pin), downloads the
server's certificate authority over the pinned connection, and enrolls the
agent with it, so the agent trusts that authority from then on (ADR-0016).

The script:

1. checks that it runs as root on Linux with systemd;
2. maps the machine's architecture to an agent build;
3. downloads that build and `SHA256SUMS` from the server (HTTPS only when the
   server URL is HTTPS) and refuses a binary whose checksum does not match;
4. installs it as `/usr/local/bin/easyrmm-agent`;
5. runs `easyrmm-agent install`, which enrolls the computer and starts the
   `easyrmm-agent` service.

On both systems the token reaches the agent in the `EASYRMM_TOKEN`
environment variable, not on its command line. It is used once and not
stored.

Within a minute the computer is listed under **Devices** as online. On its
next heartbeat the agent downloads MeshAgent and its settings from the EasyRMM
server and starts it; the device page's **Remote access** row changes from
*Not set up yet* to *Connected* once MeshCentral links it.

### Installing without the script

The binaries are listed with their SHA-256 under **Agent downloads** on the
Add devices page, and served at
`https://rmm.example.com/api/agent/v1/download/<file>` with
`/api/agent/v1/download/SHA256SUMS` alongside.

On Windows, in PowerShell as administrator:

```powershell
(Get-FileHash .\easyrmm-agent-windows-amd64.exe -Algorithm SHA256).Hash   # compare with SHA256SUMS
$env:EASYRMM_TOKEN = 'ert_…'
.\easyrmm-agent-windows-amd64.exe install --server https://rmm.example.com
Remove-Item Env:EASYRMM_TOKEN
```

On Linux:

```sh
curl -fsSLO https://rmm.example.com/api/agent/v1/download/easyrmm-agent-linux-amd64
curl -fsSL https://rmm.example.com/api/agent/v1/download/SHA256SUMS | grep ' easyrmm-agent-linux-amd64$' | sha256sum -c -
sudo install -m 0755 easyrmm-agent-linux-amd64 /usr/local/bin/easyrmm-agent
sudo EASYRMM_TOKEN=ert_… easyrmm-agent install --server https://rmm.example.com
```

If the server's certificate comes from a private certificate authority, add
`--ca-file /path/to/ca.pem`; the agent keeps a copy and trusts it for every
later request. For the server's own authority (IP addresses), download
`/api/agent/v1/ca.pem` and compare its fingerprint with the one on the Add
devices page before using it.

The same certificate is at `/api/agent/v1/easyrmm-ca.crt` in DER, the form
Windows and macOS install directly. Agents need neither: they keep their
own copy. Install it for browsers only on the computers technicians use,
since a computer that trusts it would trust a certificate signed with its
key for any website (ADR-0016). To stop browser warnings on a Windows
computer, right-click the file, choose **Install Certificate**, **Local
Machine**, and **Place all certificates in the following store: Trusted Root
Certification Authorities** (letting Windows pick the store can leave it
where browsers do not trust it). In an administrator PowerShell:

```powershell
Import-Certificate -FilePath .\easyrmm-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
```

## What is installed

On Windows:

| Path | What |
|---|---|
| `%ProgramFiles%\EasyRMM\Agent\easyrmm-agent.exe` | The agent, run by the **EasyRMM Agent** service (`EasyRMMAgent`) as LocalSystem, started automatically and restarted by Windows if it stops |
| `%ProgramData%\EasyRMM\Agent\` | Its state: `agent.json`, `device.key`, `status.json` and `jobs\`, as on Linux. The folder is readable only by SYSTEM and Administrators. The agent checks it before reading it: a folder or file that another account made, or a link, is moved aside as `<name>.untrusted-<time>` and never read |
| `%ProgramData%\EasyRMM\Agent\logs\agent.log` | The agent's log (10 MiB, then `agent.log.1`) |
| `%ProgramFiles%\EasyRMM\MeshAgent\` | MeshAgent, run by the **EasyRMM MeshAgent** service (`EasyRMMMeshAgent`), separate from any other MeshCentral's agent on the computer |

On Linux:

| Path | What |
|---|---|
| `/usr/local/bin/easyrmm-agent` | The agent |
| `/etc/systemd/system/easyrmm-agent.service` | Its service |
| `/var/lib/easyrmm-agent/agent.json` | Server URL, device ID and the server's job-signing public key, pinned at enrollment |
| `/var/lib/easyrmm-agent/device.key` | The device's Ed25519 private key (mode 600). It never leaves the computer; the agent refuses to start if the file is readable by others |
| `/var/lib/easyrmm-agent/status.json` | Last heartbeat, last error, MeshAgent state (read by `easyrmm-agent status`) |
| `/var/lib/easyrmm-agent/jobs/` | Scripts being run (`work/`, removed after each run) and results not yet reported (`journal/`). See [Scripts and jobs](../operations/scripts-and-jobs.md) |
| `/usr/local/lib/easyrmm-agent/meshagent/` | MeshAgent, its settings and database |
| `/etc/systemd/system/easyrmm-meshagent.service` | MeshAgent's service |

## Checking a computer

On Windows, in PowerShell as administrator:

```powershell
& "$env:ProgramFiles\EasyRMM\Agent\easyrmm-agent.exe" status
Get-Service EasyRMMAgent, EasyRMMMeshAgent
Get-Content "$env:ProgramData\EasyRMM\Agent\logs\agent.log" -Tail 50
```

On Linux:

```console
$ sudo easyrmm-agent status
Server:     https://rmm.example.com
Device:     6f1c…
Enrolled:   Sun, 15 Nov 2026 10:02:11 UTC
Service:    active
Heartbeat:  Sun, 15 Nov 2026 10:41:12 UTC
MeshAgent:  installed
Inventory:  sent Sun, 15 Nov 2026 10:02:14 UTC
```

A computer that waits for approval shows its device code instead:

```console
$ sudo easyrmm-agent status
Server:     https://rmm.example.com
Code:       K3QF-7BXA
Waiting:    for approval in the EasyRMM console since Sun, 15 Nov 2026 10:02:11 UTC
Service:    active
```

`journalctl -u easyrmm-agent` shows the agent's log. A failed heartbeat is
retried after 5 seconds, then with a doubling delay up to 5 minutes.

Each heartbeat carries the computer's processor, memory and disk use. The
**Inventory** line is when the agent last sent its hardware and software
list, which it does at start and whenever the list changes (checked every
hour); `not sent: …` gives the reason when an upload failed, and the agent
tries again after 15 minutes. See [Inventory and health](../operations/inventory.md).

| Error | Meaning |
|---|---|
| `token_invalid` | The token is wrong, expired, revoked or used up. Create a new one |
| `key_in_use` | Another device already enrolled with this key. Uninstall and install again |
| `clock_skew` | The computer's clock is more than five minutes off. Fix time synchronization |
| `device_unknown` | The server has no record of this device, for example after restoring an older database backup. Uninstall and enroll again |
| `rate_limited` | Too many enrollments from one address at once; the installer can simply be run again. From an enrolled agent: the device sent far more requests than an agent does (more than about one a second, or an inventory more often than every ten minutes after a few); it backs off and tries again. If it persists, something else may be using the device's key |
| `meshagent_unavailable` | The server cannot reach MeshCentral right now; the agent retries later |
| `enrollment_rejected` | The device was rejected under **Waiting for approval**. Uninstall the agent; installing it again asks anew |
| `too_many_waiting` | 10,000 devices already wait for approval; approve or reject some, and the agent asks again |

## Updating agents

Agents follow the server: when the server ships another agent build (a new
server image, or new files in its agent directory), it updates the agents,
a few at a time (ADR-0027). **Settings → Agent updates** sets how:

* **Automatically** (the default): every agent on another build is updated.
* **When asked**: only agents someone asks for, with **Update agent** on a
  device's page (needs the *edit devices* permission) or **Update … outdated
  agents** on the settings page.
* **Off**: no update starts.

**Devices at once** (default 20) limits how many update at the same time;
the next starts when one comes back with the new build. The page also counts
the agents that are up to date, waiting, updating, failed, or unable to
update themselves.

An agent that is told to update:

1. waits for scripts that are running (up to 10 minutes) and takes no new
   ones;
2. downloads the build from the server, checks its size and SHA-256 against
   the signed instruction, and runs it with `version` to check that it starts;
3. keeps the running build as `easyrmm-agent.old` (`.exe.old` on Windows),
   puts the new one in its place and restarts into it. On Windows the
   service stops with an error and Windows starts it again 10 seconds later;
   the System event log records the stop.

The new build is confirmed when it reaches the server. If it crashes three
times, or cannot reach the server for 10 minutes, the agent puts the
previous build back and reports why; the device's page shows it, the server
tries again after 15 minutes and then after an hour, and after three
attempts marks the update failed until someone asks again. Every update is
in the audit log (`device.agent_update`).

Agents installed before EasyRMM could update them do not report their build
and show **Cannot update itself**: run the install command on the computer
once more, and they update themselves from then on.

To hold a release back, set the mode to **When asked** before upgrading the
server, try it on a few devices, then switch back to **Automatically**.

### Signing the Windows agent

The Windows agent EasyRMM ships carries no Authenticode signature, so
Windows names no publisher for it. You can sign it with your own code
signing certificate, so that Windows and your security tools name your
company (ADR-0049). EasyRMM never holds your key: you sign with the tools
you already use for your certificate (`signtool` with a USB token,
`jsign` or `osslsigncode` with a cloud key such as Azure Key Vault or
DigiCert KeyLocker).

On **Settings → Agent updates** (Super Administrators), under *Signed
Windows builds*:

1. **Download to sign** each Windows build (x86-64 and ARM 64-bit). Sign
   these files, the server's own builds: the server accepts only them.
2. Sign each one, with a timestamp, without changing it otherwise. For
   example, with signtool:

   ```powershell
   signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a easyrmm-agent-windows-amd64.exe
   ```

3. **Upload a signed build**, once for each file.

The server checks that the file is one of its own Windows builds with only
a signature added: its Authenticode digest matches the build's, the
signature covers it and verifies with the signer's certificate, and that
certificate is for code signing. It does not check the certificate's chain:
each Windows computer decides whether it trusts your certificate, so a
certificate from your own certificate authority works where your group
policy trusts it. A refused file says why.

The server then hands out the signed file in place of the unsigned one,
under the same name: the install commands download it, and agents update to
it as to any new build, within the rollout setting. The page shows who
signed each build, its thumbprint, and whether the signature has a
timestamp. Without one, Windows stops trusting the signature when your
certificate expires, and the page warns. Uploading another signature for
the same build replaces it. Uploads and removals are in the audit log.

**After an upgrade** the server's Windows builds are new files, so the
signed ones no longer match them. Until you sign the new builds:

* by default, the server hands out the new release's unsigned build, and
  Windows agents update to it, then to the signed one once you upload it;
* with **Hand out signed Windows builds only** (under *Rollout*), the
  server keeps handing out the newest older signed build, and Windows
  agents stay on it. New installs get it too. Devices show *Waiting for a
  signed build*, and the page says which release they wait for. An
  architecture with no signed build at all has no Windows build handed out
  for it. This setting cannot be turned on before a signed build is
  uploaded, and the last signed build cannot be removed while it is on.
  Agents running an unsigned build are moved to the signed one, even if it
  is of an older version.

The server keeps, for each architecture, the signed build of its own
version and the newest older one, in its database, so backups keep them.
Removing a signed build hands out the release's build again (or, with
*signed builds only*, the older signed one).

## Uninstalling

On Windows, in PowerShell as administrator:

```powershell
& "$env:ProgramFiles\EasyRMM\Agent\easyrmm-agent.exe" uninstall
```

The running program cannot delete itself; Windows removes
`easyrmm-agent.exe` at the next restart, and the command says so.

On Linux:

```sh
sudo easyrmm-agent uninstall
```

This stops and removes both services, MeshAgent and the agent's state. The
device stays listed in the console as offline; its history is kept. To enroll
the computer again, install it with a new token. To take the device out of
the console too, remove it there instead.

## Removing a device

**Remove** on a device's page takes a computer out of EasyRMM with its
agents ([ADR-0050](../architecture/adr/0050-removing-a-device.md)). It
needs the Site Administrator role or above for the device's site.

1. EasyRMM asks the device's agent to uninstall itself. The device shows
   *Removing* until the agent confirms; the page says whether the agent
   has had the instruction yet. An agent gets it with its next heartbeat,
   within a minute while it is online, or when the computer is next on.
2. The agent starts its uninstaller outside its service: a systemd unit
   of its own on Linux (`easyrmm-agent-removal-…`), a separate process on
   Windows. The uninstaller removes the agent's service, MeshAgent, the
   agent's state and its program, and tells EasyRMM.
3. EasyRMM deletes the device, with its alerts, inventory, measurements and
   script history. The audit log keeps what happened. The patching engine
   has the EasyPatch agent uninstall itself, and MeshCentral forgets the
   device.

While the device waits, **Keep the device** cancels the removal. If the
agent cannot remove its service, the device shows why and keeps working;
**Ask again** once that is fixed. **Remove now** or **Remove anyway**
deletes the device at once, without waiting: for a computer that is gone
for good, or one whose agent is from a release before device removal and
cannot follow the instruction (run `easyrmm-agent uninstall` on that one). If a computer
removed this way comes back within 90 days, its agent is told to uninstall
itself then.

A device with no EasyRMM agent, found through MeshCentral, is removed at
once: MeshCentral asks its MeshAgent to uninstall itself and forgets it.

Endpoints only the patching engine has, listed on **Patching → Overview**
under *In the patching engine, with no EasyRMM device*, have **Remove** too:
their EasyPatch agent uninstalls itself when it next checks in, and the
engine stops patching the endpoint after 7 days if it does not.

## Serving the agents

The server hands out the agent builds in its agent directory,
`EASYRMM_AGENT_DIR` (default `/usr/share/easyrmm/agents`). The Docker image
includes the two Windows and four Linux builds there. A server built from
source serves the ones `make build-agents` writes to `bin/agents`:

```sh
make build-agents
EASYRMM_AGENT_DIR=$PWD/bin/agents bin/easyrmm-server serve
```

Files must be named `easyrmm-agent-<os>-<arch>` (`.exe` for Windows). The
server computes their checksums when it starts; a `VERSION` file beside them
names the builds in the console. Agents update to these builds (see
[Updating agents](#updating-agents)).
